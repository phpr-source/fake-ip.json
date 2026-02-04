import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
import tldextract
import ipaddress
from collections import defaultdict
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

PREFIX_FOR_SUFFIX = {
    'www', 'api', 'cdn', 'img', 'image', 'static', 'assets', 'media',
    'm', 'mobile', 'h5', 'wap', 'touch',
    'login', 'auth', 'account', 'sso', 'oauth',
    'blog', 'news', 'forum', 'bbs', 'wiki',
    'mail', 'webmail',
    'upload', 'download', 'dl', 'update',
    'video', 'music', 'live', 'stream',
    'ws', 'wss', 'hub',
    'shop', 'store', 'pay', 'checkout', 'mall',
    'dev', 'test', 'beta', 'sandbox', 'uat', 'stage',
    'admin', 'dash', 'dashboard', 'portal', 'console', 'manage',
    'support', 'help', 'doc', 'docs', 'faq',
    'search', 'query', 'geo', 'maps'
}

PREFIX_FOR_DOMAIN = {
    'ns', 'dns',
    'smtp', 'pop', 'pop3', 'imap', 'exchange', 'mx',
    'stun', 'turn',
    'ntp', 'time', 'pool',
    'vpn', 'gw', 'gateway',
    'tracker', 'xmpp',
    'db', 'sql', 'mysql', 'redis', 'mongo', 'oracle'
}

PROTECTED_ROOTS = {
    'github.io', 'githubusercontent.com', 'gitlab.io', 'gitbook.io',
    'vercel.app', 'netlify.app', 'herokuapp.com', 'fly.dev',
    'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'cloudfront.net', 'amazonaws.com', 'googleapis.com', 'elasticbeanstalk.com',
    'azurewebsites.net', 'blob.core.windows.net', 'cloudapp.net',
    'myshopify.com', 'wordpress.com', 'blogspot.com',
    'tumblr.com', 'medium.com', 'wixsite.com', 'squarespace.com',
    'ddns.net', 'dyndns.org', 'no-ip.com', 'duckdns.org',
    'fastly.net', 'b-cdn.net', 'cdn77.org', 'kxcdn.com'
}

RE_NUMERIC = re.compile(r'^\d+$')
RE_HASH_LIKE = re.compile(r'[a-f0-9]{16,}')
RE_VERSION_NODE = re.compile(r'^v\d+')
RE_DOMAIN_FEATURE = re.compile(r'^(ns|dns|db|mx|ntp)\d*$')
RE_VALID_DOMAIN = re.compile(r'^[a-z0-9.-]+$')

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

def extract_rules_with_type(file_path, task_type):
    extracted_data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f: data = json.load(f)
        for rule in data.get("rules", []):
            if task_type in ["geosite", "mixed"]:
                for x in rule.get("domain", []): extracted_data.append((x, "domain"))
                for x in rule.get("domain_suffix", []): extracted_data.append((x, "domain_suffix"))
                for x in rule.get("domain_keyword", []): extracted_data.append((x, "domain_keyword"))
                for x in rule.get("domain_regex", []): extracted_data.append((x, "domain_regex"))
            if task_type in ["geoip", "mixed"]:
                for x in rule.get("ip_cidr", []): extracted_data.append((x, "ip_cidr"))
                for x in rule.get("source_ip_cidr", []): extracted_data.append((x, "source_ip_cidr"))
                for x in rule.get("source_port", []): extracted_data.append((x, "source_port"))
                for x in rule.get("port", []): extracted_data.append((x, "port"))
                for x in rule.get("process_name", []): extracted_data.append((x, "process_name"))
    except Exception as e: print(f"  [Error] Read failed {file_path}: {e}")
    return extracted_data

def is_subdomain(child, parent):
    if child == parent: return True
    return child.endswith("." + parent)

def is_high_entropy(text):
    if not text: return False
    if RE_NUMERIC.match(text): return True
    if RE_HASH_LIKE.search(text): return True
    digit_count = sum(c.isdigit() for c in text)
    if len(text) > 5 and digit_count >= len(text) / 2: return True
    return False

def optimize_ip_cidrs_lossless(cidr_list):
    if not cidr_list: return []
    v4_nets = []
    v6_nets = []
    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except ValueError:
            continue
    v4_merged = ipaddress.collapse_addresses(v4_nets)
    v6_merged = ipaddress.collapse_addresses(v6_nets)
    result = [str(n) for n in v4_merged] + [str(n) for n in v6_merged]
    return result

def clean_domain_string(domain):
    domain = domain.split(':')[0]
    domain = domain.strip().lower()
    domain = re.sub(r'\s+', '', domain)
    if not domain or '..' in domain: return None
    if len(domain) > 253: return None
    if not RE_VALID_DOMAIN.match(domain): return None
    return domain

def sort_ports(port_list):
    def get_start_port(p):
        try:
            if isinstance(p, int): return p
            p_str = str(p)
            if '-' in p_str:
                return int(p_str.split('-')[0])
            return int(p_str)
        except:
            return 0
    return sorted(list(set(port_list)), key=get_start_port)

def evaluate_domain_suggestion(ext):
    subdomain = ext.subdomain
    root = f"{ext.domain}.{ext.suffix}"
    
    if root in PROTECTED_ROOTS:
        if subdomain == 'www': return 'MUST_SUFFIX'
        return 'MUST_DOMAIN'

    if not subdomain: return 'MUST_SUFFIX'
    
    parts = subdomain.split('.')
    head = parts[0].lower()
    
    if is_high_entropy(head): return 'MUST_DOMAIN'

    if head == 'www': return 'MUST_SUFFIX'
    if RE_DOMAIN_FEATURE.match(head): return 'MUST_DOMAIN'
    if head in PREFIX_FOR_SUFFIX: return 'MUST_SUFFIX'
    if head in PREFIX_FOR_DOMAIN: return 'MUST_DOMAIN'
    if 'cdn' in head or 'static' in head: return 'MUST_SUFFIX'
    if RE_VERSION_NODE.match(head): return 'LEAN_DOMAIN'

    return 'NEUTRAL'

def weighted_reclassification(raw_data_list):
    domain_map = defaultdict(lambda: {'votes': list(), 'original_forms': set()})
    others = defaultdict(set)
    extract = tldextract.TLDExtract(include_psl_private_domains=True)
    extract.update()

    for content, original_type in raw_data_list:
        if original_type in ['domain', 'domain_suffix']:
            clean_content = clean_domain_string(content)
            if not clean_content: continue

            ext = extract(clean_content)
            if not ext.suffix or not ext.domain:
                others[original_type].add(clean_content)
                continue
            
            if ext.subdomain == 'www':
                base_domain = f"{ext.domain}.{ext.suffix}"
            elif ext.subdomain:
                base_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
            else:
                base_domain = f"{ext.domain}.{ext.suffix}"
            
            domain_map[base_domain]['votes'].append(original_type)
            domain_map[base_domain]['original_forms'].add(clean_content)
        else:
            others[original_type].add(content)

    final_suffixes = set()
    final_domains = set()

    for domain, info in domain_map.items():
        votes = info['votes']
        ext = extract(domain)
        suggestion = evaluate_domain_suggestion(ext)
        decision = None
        
        if suggestion == 'MUST_SUFFIX':
            decision = 'domain_suffix'
        elif suggestion == 'MUST_DOMAIN':
            decision = 'domain'
        else:
            suffix_votes = votes.count('domain_suffix')
            total_votes = len(votes)
            if suffix_votes > total_votes / 2:
                decision = 'domain_suffix'
            else:
                decision = 'domain'

        if decision == 'domain_suffix':
            final_suffixes.add(domain)
        else:
            final_domains.add(domain)

    sorted_s = sorted(list(final_suffixes), key=len)
    clean_s = []
    for candidate in sorted_s:
        is_redundant = False
        for parent in clean_s:
            if is_subdomain(candidate, parent):
                is_redundant = True
                break
        if not is_redundant:
            clean_s.append(candidate)
            
    clean_d = []
    for domain in sorted(list(final_domains)):
        is_covered = False
        for parent in clean_s:
            if is_subdomain(domain, parent):
                is_covered = True
                break
        if not is_covered:
            clean_d.append(domain)
            
    result_obj = {}
    if clean_d: result_obj["domain"] = sorted(clean_d)
    if clean_s: result_obj["domain_suffix"] = sorted(clean_s)
    
    if 'ip_cidr' in others:
        others['ip_cidr'] = optimize_ip_cidrs_lossless(others['ip_cidr'])
    if 'source_ip_cidr' in others:
        others['source_ip_cidr'] = optimize_ip_cidrs_lossless(others['source_ip_cidr'])

    for type_name, contents in others.items():
        if contents:
            if 'port' in type_name:
                result_obj[type_name] = sort_ports(contents)
            else:
                result_obj[type_name] = sorted(list(set(contents)))
            
    return result_obj

def process_single_task(task):
    name = task["name"]
    type_ = task["type"]
    sources = task["sources"]
    
    print(f"🔄 [{name}] Processing ({type_})...")
    
    raw_data_collection = []
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

        items = extract_rules_with_type(target_json, type_)
        raw_data_collection.extend(items)

    if not raw_data_collection:
        return TaskResult(name, "❌", "No rules found")

    final_rules = weighted_reclassification(raw_data_collection)

    final_json_data = {"version": TARGET_FORMAT_VERSION, "rules": [final_rules]}
    
    out_json = os.path.join(DIR_OUTPUT, "merged-json", f"{name}.json")
    out_srs = os.path.join(DIR_OUTPUT, "merged-srs", f"{name}.srs")
    
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(final_json_data, f, indent=2)

    try:
        subprocess.run(["./sb-core", "rule-set", "compile", "--output", out_srs, out_json], check=True)
        total_count = sum(len(v) for v in final_rules.values())
        return TaskResult(name, "✅", f"Merged {total_count} rules", get_file_size(out_srs))
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
