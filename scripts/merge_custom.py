import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
from datetime import datetime

CONFIG_FILE = 'scripts/custom_merge.json'
DIR_OUTPUT = 'rules'
MAX_WORKERS = 5
TARGET_FORMAT_VERSION = 4

RULE_MAP = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip', 
    'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name'
}

class TaskResult:
    def __init__(self, name, status, msg, size="0KB"):
        self.name, self.status, self.msg, self.size = name, status, msg, size

def setup_directories():
    if not os.path.exists(DIR_OUTPUT): os.makedirs(DIR_OUTPUT)
    d1 = os.path.join(DIR_OUTPUT, "merged-json")
    d2 = os.path.join(DIR_OUTPUT, "merged-srs")
    if not os.path.exists(d1): os.makedirs(d1)
    if not os.path.exists(d2): os.makedirs(d2)

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

def srs_to_json(srs_path, json_path):
    try:
        subprocess.run(["./sb-core", "rule-set", "decompile", "--output", json_path, srs_path], check=True, capture_output=True)
        return True
    except: return False

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

def extract_rules(file_path, task_type):
    content = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f: data = json.load(f)
        for rule in data.get("rules", []):
            if task_type in ["geosite", "mixed"]:
                for x in rule.get("domain", []): content.add(f"domain:{x}")
                for x in rule.get("domain_suffix", []): content.add(f"suffix:{x}")
                for x in rule.get("domain_keyword", []): content.add(f"keyword:{x}")
                for x in rule.get("domain_regex", []): content.add(f"regex:{x}")
            
            if task_type in ["geoip", "mixed"]:
                for x in rule.get("ip_cidr", []): content.add(f"ip:{x}")
                for x in rule.get("source_ip_cidr", []): content.add(f"sip:{x}")
                for x in rule.get("source_port", []): content.add(f"sport:{x}")
                for x in rule.get("port", []): content.add(f"port:{x}")
                for x in rule.get("process_name", []): content.add(f"proc:{x}")

    except Exception as e: print(f"  [Error] Read failed {file_path}: {e}")
    return content

def is_subdomain(child, parent):
    if child == parent: return True
    return child.endswith("." + parent)

def advanced_deduplication(d_list, s_list):
    if not s_list:
        return sorted(list(set(d_list))), []
    
    s_list = sorted(list(set(s_list)), key=len)
    optimized_suffixes = []
    
    for suffix in s_list:
        is_redundant = False
        for parent in optimized_suffixes:
            if is_subdomain(suffix, parent):
                is_redundant = True
                break
        if not is_redundant:
            optimized_suffixes.append(suffix)
    
    d_list = sorted(list(set(d_list)))
    optimized_domains = []
    
    for domain in d_list:
        is_covered = False
        for parent in optimized_suffixes:
            if is_subdomain(domain, parent):
                is_covered = True
                break
        if not is_covered:
            optimized_domains.append(domain)
            
    return optimized_domains, optimized_suffixes

def process_single_task(task):
    name = task["name"]
    type_ = task["type"]
    sources = task["sources"]
    
    print(f"🔄 [{name}] Processing ({type_})...")
    
    merged_content = set()
    temp_dir = "temp_custom_merge"
    os.makedirs(temp_dir, exist_ok=True)

    for idx, url in enumerate(sources):
        is_srs = url.endswith(".srs")
        ext = ".srs" if is_srs else ".json"
        t_file = os.path.join(temp_dir, f"{name}_{idx}{ext}")
        t_json = os.path.join(temp_dir, f"{name}_{idx}.json")
        
        if not download_file(url, t_file): continue
        
        target_json = t_file
        if is_srs:
            if srs_to_json(t_file, t_json): target_json = t_json
            else: continue
        elif not url.endswith('.json'): 
            if convert_clash_to_json(t_file, t_json)[0]: target_json = t_json
            else: continue

        items = extract_rules(target_json, type_)
        merged_content.update(items)

    if not merged_content:
        return TaskResult(name, "❌", "No rules found")

    d, s, k, r = [], [], [], []
    ip, sip, sport, port, proc = [], [], [], [], []

    for item in merged_content:
        val = item.split(":", 1)[1]
        if item.startswith("domain:"): d.append(val)
        elif item.startswith("suffix:"): s.append(val)
        elif item.startswith("keyword:"): k.append(val)
        elif item.startswith("regex:"): r.append(val)
        elif item.startswith("ip:"): ip.append(val)
        elif item.startswith("sip:"): sip.append(val)
        elif item.startswith("sport:"): sport.append(val)
        elif item.startswith("port:"): port.append(val)
        elif item.startswith("proc:"): proc.append(val)

    d, s = advanced_deduplication(d, s)

    rule_obj = {}
    if d: rule_obj["domain"] = sorted(d)
    if s: rule_obj["domain_suffix"] = sorted(s)
    if k: rule_obj["domain_keyword"] = sorted(k)
    if r: rule_obj["domain_regex"] = sorted(r)
    if ip: rule_obj["ip_cidr"] = sorted(ip)
    if sip: rule_obj["source_ip_cidr"] = sorted(sip)
    if sport: rule_obj["source_port"] = sorted(sport)
    if port: rule_obj["port"] = sorted(port)
    if proc: rule_obj["process_name"] = sorted(proc)

    final_json_data = {"version": TARGET_FORMAT_VERSION, "rules": [rule_obj]}
    
    out_json = os.path.join(DIR_OUTPUT, "merged-json", f"{name}.json")
    out_srs = os.path.join(DIR_OUTPUT, "merged-srs", f"{name}.srs")
    
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(final_json_data, f, indent=2)

    try:
        subprocess.run(["./sb-core", "rule-set", "compile", "--output", out_srs, out_json], check=True)
        return TaskResult(name, "✅", f"Merged {len(merged_content)} rules", get_file_size(out_srs))
    except Exception as e:
        return TaskResult(name, "❌", f"Compile Error: {e}")

def main():
    setup_directories()
    core_ver = get_core_version()
    
    tasks = []
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                tasks = data.get("merge_tasks", [])
        except Exception as e: print(f"⚠️ Config Error: {e}")

    results = []
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_task, t): t for t in tasks}
            for future in concurrent.futures.as_completed(futures): results.append(future.result())

    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    if results and github_step_summary:
        with open(github_step_summary, 'a', encoding='utf-8') as f:
            f.write(f"## 🏭 Custom Merge Report\n")
            for r in results: f.write(f"- {r.status} **{r.name}**: {r.msg} ({r.size})\n")
        if any(r.status == "❌" for r in results): sys.exit(1)

if __name__ == "__main__":
    main()
