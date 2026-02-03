import json
import os
import subprocess
import requests

CONFIG_FILE = "scripts/custom_merge.json"
TEMP_DIR = "temp_custom_merge"
OUT_JSON = "rules/merged-json"
OUT_SRS = "rules/merged-srs"
CORE = "./sb-core"
TARGET_FORMAT_VERSION = 3  

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
    try:
        subprocess.run([CORE, "rule-set", "decompile", "--output", json_path, srs_path], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  [Error] Failed to decompile SRS: {e}")
        return False

def extract_rules(file_path, rule_type):
    content = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for rule in data.get("rules", []):
            if rule_type == "geoip":
                for item in rule.get("ip_cidr", []):
                    content.add(item)
            elif rule_type == "geosite":
                for item in rule.get("domain", []): content.add(f"domain:{item}")
                for item in rule.get("domain_suffix", []): content.add(f"suffix:{item}")
                for item in rule.get("domain_keyword", []): content.add(f"keyword:{item}")
                for item in rule.get("domain_regex", []): content.add(f"regex:{item}")
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
    
    print(f">>> Target Rule-Set Format Version: {TARGET_FORMAT_VERSION}")

    for task in config.get("merge_tasks", []):
        task_name = task["name"]
        task_type = task["type"]
        sources = task["sources"]
        
        print(f"\n>>> Processing Task: {task_name} ({task_type})")
        merged_content = set()

        for idx, url in enumerate(sources):
            print(f"  - Fetching source {idx+1}...")
            is_srs = url.endswith(".srs")
            ext = ".srs" if is_srs else ".json"
            temp_file = os.path.join(TEMP_DIR, f"{task_name}_{idx}{ext}")
            temp_json = os.path.join(TEMP_DIR, f"{task_name}_{idx}.json")

            if download_file(url, temp_file):
                target_json = temp_file
                if is_srs:
                    if srs_to_json(temp_file, temp_json):
                        target_json = temp_json
                    else:
                        continue 
                
                items = extract_rules(target_json, task_type)
                merged_content.update(items)

        if merged_content:
            final_rules = []
            if task_type == "geoip":
                final_rules.append({"ip_cidr": sorted(list(merged_content))})
            elif task_type == "geosite":
                d, s, k, r = [], [], [], []
                for item in merged_content:
                    if item.startswith("domain:"): d.append(item.split(":", 1)[1])
                    elif item.startswith("suffix:"): s.append(item.split(":", 1)[1])
                    elif item.startswith("keyword:"): k.append(item.split(":", 1)[1])
                    elif item.startswith("regex:"): r.append(item.split(":", 1)[1])
                
                rule_obj = {}
                if d: rule_obj["domain"] = sorted(d)
                if s: rule_obj["domain_suffix"] = sorted(s)
                if k: rule_obj["domain_keyword"] = sorted(k)
                if r: rule_obj["domain_regex"] = sorted(r)
                final_rules.append(rule_obj)

            final_json_data = {"version": TARGET_FORMAT_VERSION, "rules": final_rules}
            
            final_json_path = os.path.join(OUT_JSON, f"{task_name}.json")
            with open(final_json_path, 'w') as f:
                json.dump(final_json_data, f, indent=2)
            
            final_srs_path = os.path.join(OUT_SRS, f"{task_name}.srs")
            try:
                subprocess.run([CORE, "rule-set", "compile", "--output", final_srs_path, final_json_path], check=True)
                print(f"  [Success] Generated {task_name} (Format Version: {TARGET_FORMAT_VERSION})")
            except Exception as e:
                print(f"  [Error] Compilation failed: {e}")
        else:
            print("  [Warning] No rules found to merge.")

if __name__ == "__main__":
    main()
