import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
from datetime import datetime

CONFIG_FILE = 'rule-providers.json'
DIR_OUTPUT = 'rules'
MAX_WORKERS = 5
TARGET_FORMAT_VERSION = 4

RULE_MAP = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip', 'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name'
}

class TaskResult:
    def __init__(self, name, status, msg, size="0KB"):
        self.name, self.status, self.msg, self.size = name, status, msg, size

def setup_directories():
    if not os.path.exists(DIR_OUTPUT): os.makedirs(DIR_OUTPUT)

def get_core_version():
    if not os.path.exists("./sing-box"): return "❌ Core Missing"
    try:
        res = subprocess.run(["./sing-box", "version"], capture_output=True, text=True)
        return res.stdout.split('\n')[0].split('version ')[-1].strip()
    except: return "❓ Unknown"

def get_file_size(filepath):
    if not os.path.exists(filepath): return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def download_file(url, filename):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    cmd = ["curl", "-L", "--fail", "--retry", "3", "-A", ua, url, "-o", filename]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except: return False

def optimize_json_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f: data = json.load(f)
        
        data['version'] = TARGET_FORMAT_VERSION
        
        rules = data.get('rules', [])
        modified = True
        total_removed = 0
        
        for rule in rules:
            keys_to_del = []
            for k, v in rule.items():
                if isinstance(v, list):
                    new_v = sorted(list(set(v)))
                    if len(new_v) != len(v): 
                        total_removed += len(v) - len(new_v)
                    rule[k] = new_v
                    if not new_v: keys_to_del.append(k)
            for k in keys_to_del: del rule[k]
            
        with open(filepath, 'w', encoding='utf-8') as f: 
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True, total_removed
    except: return False, 0

def convert_clash_to_json(input_file, output_json):
    rules_dict = {v: set() for v in set(RULE_MAP.values())}
    count = 0
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f: lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '//')): continue
            line = re.split(r'\s*(#|//)', line)[0].strip()
            match = re.search(r'^([A-Z0-9-]+)\s*,\s*([^,]+)', line, re.IGNORECASE)
            if match:
                type_, val = match.group(1).upper(), match.group(2).strip().strip("'\"")
                if type_ in RULE_MAP: rules_dict[RULE_MAP[type_]].add(val); count += 1
        
        if count == 0: return False, "No valid rules"
        final = [{k: sorted(list(v))} for k, v in rules_dict.items() if v]
        with open(output_json, 'w', encoding='utf-8') as f: 
            json.dump({"version": TARGET_FORMAT_VERSION, "rules": final}, f, ensure_ascii=False, indent=2)
        return True, f"Conv {count}"
    except Exception as e: return False, str(e)

def process_single_task(name, url):
    print(f"🔄 [{name}] Processing...")
    tmp = f"temp_{name}"
    f_json = os.path.join(DIR_OUTPUT, f"{name}.json")
    f_srs = os.path.join(DIR_OUTPUT, f"{name}.srs")
    
    if not download_file(url, tmp): return TaskResult(name, "❌", "Download Failed")
    
    json_ready, msg = False, "Unknown"
    try:
        url_l = url.lower()
        if url_l.endswith('.srs'):
            subprocess.run(["./sing-box", "rule-set", "decompile", tmp, "-o", f_json], check=True)
            msg, json_ready = "SRS Rebuilt", True
        elif url_l.endswith('.json'):
            shutil.move(tmp, f_json); msg, json_ready = "JSON Native", True
        elif url_l.endswith('.mrs'):
            return TaskResult(name, "❌", "MRS Not Supported")
        else:
            ok, m = convert_clash_to_json(tmp, f_json)
            if ok: msg, json_ready = "Converted", True
            else: return TaskResult(name, "❌", m)
    except: return TaskResult(name, "❌", "Process Error")
    finally:
        if os.path.exists(tmp): os.remove(tmp)

    if json_ready:
        ok, n = optimize_json_file(f_json)
        if ok: msg += f" (Opt {n})"
        try:
            subprocess.run(["./sing-box", "rule-set", "compile", f_json, "-o", f_srs], check=True)
            return TaskResult(name, "✅", msg, get_file_size(f_srs))
        except: return TaskResult(name, "❌", "Compile Failed")
    return TaskResult(name, "❌", "Logic Error")

def generate_full_readme(core_ver):
    print("📝 Generating README...")
    files = sorted([f for f in os.listdir(DIR_OUTPUT) if f.endswith('.srs')])
    with open(os.path.join(DIR_OUTPUT, "README.md"), 'w', encoding='utf-8') as f:
        f.write(f"# 📦 Sing-box Rule Set Collection\n\n")
        f.write(f"> **Core**: `{core_ver}` | **Updated**: `{datetime.now().strftime('%Y-%m-%d %H:%M')}`\n\n")
        f.write("| Rule Name | SRS (Binary) | Source (JSON) | Size |\n| :--- | :--- | :--- | :--- |\n")
        for srs in files:
            name = srs[:-4]
            json_name = f"{name}.json"
            json_exists = os.path.exists(os.path.join(DIR_OUTPUT, json_name))
            srs_link = f"[{srs}]({srs})"
            json_link = f"[{json_name}]({json_name})" if json_exists else "-"
            size = get_file_size(os.path.join(DIR_OUTPUT, srs))
            f.write(f"| **{name}** | {srs_link} | {json_link} | {size} |\n")

def main():
    setup_directories()
    core_ver = get_core_version()
    
    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    
    tasks = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read().strip()
                if content: tasks = json.loads(content)
        except Exception as e: print(f"⚠️ Config Error: {e}")

    results = []
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_task, n, u): n for n, u in tasks.items()}
            for future in concurrent.futures.as_completed(futures): results.append(future.result())

    if len(sys.argv) > 1 and sys.argv[1] == '--gen-readme':
        generate_full_readme(core_ver)
    elif results and github_step_summary:
        with open(github_step_summary, 'a', encoding='utf-8') as f:
            f.write(f"## 🏭 Report\n- **Core**: `{core_ver}`\n")
            for r in results: f.write(f"- {r.status} {r.name}: {r.msg}\n")
        if all(r.status == "❌" for r in results): sys.exit(1)

if __name__ == "__main__":
    main()
