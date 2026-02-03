import json
import os
import subprocess
import requests

# === 配置 ===
CONFIG_FILE = "scripts/custom_merge.json"
TEMP_DIR = "temp_custom_merge"
OUT_JSON = "rules/merged-json"
OUT_SRS = "rules/merged-srs"
CORE = "./sb-core"

def download_file(url, local_path):
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        with open(local_path, 'wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        print(f"  [Error] Failed to download {url}: {e}")
        return False

def srs_to_json(srs_path, json_path):
    """使用 Core 將 SRS 反編譯為 JSON"""
    try:
        subprocess.run([CORE, "rule-set", "decompile", "--output", json_path, srs_path], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [Error] Failed to decompile SRS: {e}")
        return False

def extract_rules(file_path, rule_type):
    """讀取 JSON 並提取規則內容 (IP 或 Domain)"""
    content = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for rule in data.get("rules", []):
            # 根據類型提取不同字段
            if rule_type == "geoip":
                for item in rule.get("ip_cidr", []):
                    content.add(item)
            elif rule_type == "geosite":
                # Domain 規則比較複雜，包含 domain, domain_suffix, domain_keyword 等
                # 這裡為了簡單合併，我們假設主要是 domain 和 domain_suffix
                for item in rule.get("domain", []): content.add(f"domain:{item}")
                for item in rule.get("domain_suffix", []): content.add(f"suffix:{item}")
                for item in rule.get("domain_keyword", []): content.add(f"keyword:{item}")
    except Exception as e:
        print(f"  [Error] Failed to read/parse {file_path}: {e}")
    return content

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)

    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(OUT_JSON, exist_ok=True)
    os.makedirs(OUT_SRS, exist_ok=True)

    for task in config.get("merge_tasks", []):
        task_name = task["name"]
        task_type = task["type"]
        sources = task["sources"]
        
        print(f"\n>>> Processing Task: {task_name} ({task_type})")
        merged_content = set()

        for idx, url in enumerate(sources):
            print(f"  - Fetching source {idx+1}...")
            # 判斷副檔名
            is_srs = url.endswith(".srs")
            ext = ".srs" if is_srs else ".json"
            temp_file = os.path.join(TEMP_DIR, f"{task_name}_{idx}{ext}")
            temp_json = os.path.join(TEMP_DIR, f"{task_name}_{idx}.json")

            # 1. 下載
            if download_file(url, temp_file):
                # 2. 如果是 SRS，先轉 JSON
                target_json = temp_file
                if is_srs:
                    if srs_to_json(temp_file, temp_json):
                        target_json = temp_json
                    else:
                        continue # 反編譯失敗，跳過
                
                # 3. 提取並合併 (去重在這個步驟自動完成，因為用了 set)
                items = extract_rules(target_json, task_type)
                merged_content.update(items)
                print(f"    Added {len(items)} rules.")

        # 4. 生成最終結果
        if merged_content:
            final_rules = []
            
            # 根據類型構建最終 JSON 結構
            if task_type == "geoip":
                final_rules.append({"ip_cidr": sorted(list(merged_content))})
            elif task_type == "geosite":
                # 將混合的字符串還原回結構
                d, s, k = [], [], []
                for item in merged_content:
                    if item.startswith("domain:"): d.append(item.split(":", 1)[1])
                    elif item.startswith("suffix:"): s.append(item.split(":", 1)[1])
                    elif item.startswith("keyword:"): k.append(item.split(":", 1)[1])
                
                rule_obj = {}
                if d: rule_obj["domain"] = sorted(d)
                if s: rule_obj["domain_suffix"] = sorted(s)
                if k: rule_obj["domain_keyword"] = sorted(k)
                final_rules.append(rule_obj)

            final_json_data = {"version": 1, "rules": final_rules}
            
            # 寫入 JSON
            final_json_path = os.path.join(OUT_JSON, f"{task_name}.json")
            with open(final_json_path, 'w') as f:
                json.dump(final_json_data, f, indent=2)
            
            # 編譯為 SRS
            final_srs_path = os.path.join(OUT_SRS, f"{task_name}.srs")
            try:
                subprocess.run([CORE, "rule-set", "compile", "--output", final_srs_path, final_json_path], check=True)
                print(f"  [Success] Merged {len(merged_content)} items into {task_name}.srs")
            except Exception as e:
                print(f"  [Error] Compilation failed: {e}")
        else:
            print("  [Warning] No rules found to merge.")

if __name__ == "__main__":
    main()
