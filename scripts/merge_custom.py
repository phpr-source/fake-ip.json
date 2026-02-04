import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
import tldextract
import ipaddress
import requests
import logging
import threading
from collections import defaultdict
from typing import List, Dict, Set, Any, Tuple, Optional

CONFIG_FILE = 'scripts/custom_merge.json'
DIR_OUTPUT = 'rules'
MAX_WORKERS = 5
TARGET_FORMAT_VERSION = 4
CORE_BIN = "./sb-core"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

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
    'api', 'cdn', 'img', 'image', 'static', 'assets', 'media',
    'm', 'mobile', 'h5', 'wap', 'touch',
    'login', 'auth', 'account', 'sso', 'oauth',
    'blog', 'news', 'forum', 'bbs', 'wiki',
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

EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)
UPDATE_LOCK = threading.Lock()

class TaskResult:
    def __init__(self, name: str, status: str, msg: str, size: str = "0KB"):
        self.name, self.status, self.msg, self.size = name, status, msg, size

def setup_directories():
    if not os.path.exists(DIR_OUTPUT): os.makedirs(DIR_OUTPUT)
    d1 = os.path.join(DIR_OUTPUT, "merged-json")
    d2 = os.path.join(DIR_OUTPUT, "merged-srs")
    if not os.path.exists(d1): os.makedirs(d1)
    if not os.path.exists(d2): os.makedirs(d2)

def get_core_version() -> str:
    if not os.path.exists(CORE_BIN): return "❌ Core Missing"
    try:
        res = subprocess.run([CORE_BIN, "version"], capture_output=True, text=True)
        return res.stdout.split('\n')[0].split('version ')[-1].strip()
    except Exception: return "❓ Unknown"

def get_file_size(filepath: str) -> str:
    if not os.path.exists(filepath): return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def validate_config(tasks: List[Dict]):
    required = {"name", "type", "sources"}
    for i, task in enumerate(tasks):
        missing = required - task.keys()
        if missing:
            raise ValueError(f"Task #{i} missing keys: {missing}")
        if not isinstance(task["sources"], list):
            raise ValueError(f"Task '{task.get('name')}' sources must be a list")

def clean_orphaned_files(active_tasks: List[Dict]):
    expected_srs = {f"{task['name']}.srs" for task in active_tasks}
    expected_json = {f"{task['name']}.json" for task in active_tasks}
    
    dirs_to_clean = [
        (os.path.join(DIR_OUTPUT, "merged-srs"), expected_srs),
        (os.path.join(DIR_OUTPUT, "merged-json"), expected_json)
    ]
    
    for folder, expected_files in dirs_to_clean:
        if not os.path.exists(folder): continue
        for filename in os.listdir(folder):
            if filename not in expected_files:
                file_path = os.path.join(folder, filename)
                try:
                    os.remove(file_path)
                    logging.info(f"🗑️ Cleaned orphaned file: {filename}")
                except OSError as e:
                    logging.warning(f"Failed to delete {filename}: {e}")

def download_file(url: str, filename: str) -> bool:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        with requests.get(url, headers=headers, stream=True, timeout=15) as r:
            r.raise_for_status()
            with open(filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except requests.exceptions.RequestException as e:
        logging.warning(f"Download failed for {url}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error downloading {url}: {e}")
        return False

def srs_to_json(srs_path: str, json_path: str) -> bool:
    try:
        subprocess.run([CORE_BIN, "rule-set", "decompile", "--output", json_path, srs_path], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"Decompile failed: {e}")
        return False
    except Exception as e:
        logging.warning(f"Unexpected error decompiling: {e}")
        return False

def convert_clash_to_json(input_file: str, output_json: str) -> Tuple[bool, str]:
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
        
        rules_list = []
        for k, v in rules_dict.items():
            if v:
                rules_list.append({k: sorted(list(v))})
        
        with open(output_json, 'w', encoding='utf-8') as f: 
            json.dump({"version": TARGET_FORMAT_VERSION, "rules": rules_list}, f, ensure_ascii=False, indent=2)
        return True, f"Conv {count}"
    except Exception as e: return False, str(e)

def extract_rules_with_type(file_path: str, task_type: str) -> List[Tuple[str, str]]:
    extracted_data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f: data = json.load(f)
        
        raw_rules = data.get("rules", [])
        if isinstance(raw_rules, dict):
            raw_rules = [raw_rules]
            
        for rule_obj in raw_rules:
            if not isinstance(rule_obj, dict): continue
            
            for r_type, content_list in rule_obj.items():
                if not isinstance(content_list, list): continue
                
                if task_type == "geosite" and "ip" in r_type and r_type != "geoip": continue
                if task_type == "geoip" and "domain" in r_type: continue
                
                for item in content_list:
                    extracted_data.append((item, r_type))

    except Exception as e: logging.error(f"Read JSON failed {file_path}: {e}")
    return extracted_data

def is_subdomain(child: str, parent: str) -> bool:
    if child == parent: return True
    return child.endswith("." + parent)

def is_high_entropy(text: str) -> bool:
    if not text: return False
    if RE_NUMERIC.match(text): return True
    if RE_HASH_LIKE.search(text): return True
    digit_count = sum(c.isdigit() for c in text)
    if len(text) > 5 and digit_count >= len(text) / 2: return True
    return False

def optimize_ip_cidrs_lossless(cidr_list: List[str]) -> List[str]:
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
    
    return [str(n) for n in v4_merged] + [str(n) for n in v6_merged]

def clean_domain_string(domain: str) -> Optional[str]:
    domain = domain.split(':')[0]
    domain = domain.strip().lower()
    domain = re.sub(r'\s+', '', domain)
    if not domain or '..' in domain: return None
    if len(domain) > 253: return None
    
    try:
        ipaddress.ip_address(domain)
        return None 
    except ValueError:
        pass

    if not RE_VALID_DOMAIN.match(domain): return None
    return domain

def sort_ports(port_list: List) -> List:
    def get_start_port(p):
        try:
            if isinstance(p, int): return p
            p_str = str(p)
            if '-' in p_str:
                return int(p_str.split('-')[0])
            return int(p_str)
        except Exception:
            return 0
    return sorted(list(set(port_list)), key=get_start_port)

def evaluate_domain_suggestion(ext) -> str:
    subdomain = ext.subdomain
    root = f"{ext.domain}.{ext.suffix}"
    
    if root in PROTECTED_ROOTS:
        if subdomain == 'www': return 'MUST_SUFFIX'
        return 'MUST_DOMAIN'

    if not subdomain: return 'MUST_SUFFIX'
    
    parts = subdomain.split('.')
    head = parts[0].lower()
    
    if is_high_entropy(head): return 'MUST_DOMAIN'
    if head == 'www': return 'LEAN_SUFFIX'

    if RE_DOMAIN_FEATURE.match(head): return 'MUST_DOMAIN'
    if head in PREFIX_FOR_SUFFIX: return 'MUST_SUFFIX'
    if head in PREFIX_FOR_DOMAIN: return 'MUST_DOMAIN'
    if 'cdn' in head or 'static' in head: return 'MUST_SUFFIX'
    if RE_VERSION_NODE.match(head): return 'LEAN_DOMAIN'

    return 'NEUTRAL'

def weighted_reclassification(raw_data_list: List[Tuple[str, str]]) -> Dict[str, List]:
    domain_map = defaultdict(lambda: {'votes': list(), 'original_forms': set()})
    others = defaultdict(set)
    
    for content, original_type in raw_data_list:
        if original_type in ['domain', 'domain_suffix']:
            clean_content = clean_domain_string(content)
            if not clean_content: continue
            
            base_domain = clean_content
            
            domain_map[base_domain]['votes'].append(original_type)
            domain_map[base_domain]['original_forms'].add(clean_content)
        else:
            others[original_type].add(content)

    final_suffixes = set()
    final_domains = set()

    for domain, info in domain_map.items():
        votes = info['votes']
        
        ext = EXTRACTOR(domain)
        
        suggestion = evaluate_domain_suggestion(ext)
        decision = None
        
        if suggestion == 'MUST_SUFFIX':
            decision = 'domain_suffix'
        elif suggestion == 'MUST_DOMAIN':
            decision = 'domain'
        else:
            suffix_votes = votes.count('domain_suffix')
            total_votes = len(votes)
            
            threshold = 0.5
            if suggestion == 'LEAN_SUFFIX': threshold = 0.3
            
            if suffix_votes > total_votes * threshold:
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

def process_single_task(task: Dict) -> TaskResult:
    name = task["name"]
    rule_type = task["type"]
    sources = task["sources"]
    
    logging.info(f"🔄 [{name}] Processing ({rule_type})...")
    
    raw_data_collection = []
    temp_dir = f"temp_{name}"
    os.makedirs(temp_dir, exist_ok=True)

    out_json = os.path.join(DIR_OUTPUT, "merged-json", f"{name}.json")
    out_srs = os.path.join(DIR_OUTPUT, "merged-srs", f"{name}.srs")

    for f_path in [out_json, out_srs]:
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except OSError:
                pass

    try:
        for idx, url in enumerate(sources):
            t_file = os.path.join(temp_dir, f"{name}_{idx}.raw")
            t_json = os.path.join(temp_dir, f"{name}_{idx}.json")
            
            if not download_file(url, t_file): 
                logging.warning(f"  ❌ Source {idx+1} download failed.")
                continue
            
            target_json = t_file
            is_valid_json = False
            
            try:
                with open(t_file, 'r', encoding='utf-8') as f:
                    first_char = f.read(1).strip()
                    if first_char in ['{', '[']:
                        f.seek(0)
                        json.load(f)
                        is_valid_json = True
            except Exception:
                pass

            is_srs = url.endswith(".srs")
            
            if is_srs:
                if srs_to_json(t_file, t_json): target_json = t_json
                else: 
                    logging.warning(f"  ❌ Source {idx+1} SRS decode failed.")
                    continue
            elif is_valid_json:
                pass
            else:
                success, msg = convert_clash_to_json(t_file, t_json)
                if success: 
                    target_json = t_json
                else: 
                    logging.warning(f"  ❌ Source {idx+1} Format Unknown: {msg}")
                    continue

            items = extract_rules_with_type(target_json, rule_type)
            count = len(items)
            logging.info(f"  - Source {idx+1}: {count} rules extracted")
            raw_data_collection.extend(items)

        if not raw_data_collection:
            return TaskResult(name, "❌", "No rules found")

        final_rules_dict = weighted_reclassification(raw_data_collection)
        
        final_rules_list = []
        for k, v in final_rules_dict.items():
            final_rules_list.append({k: v})

        final_json_data = {"version": TARGET_FORMAT_VERSION, "rules": final_rules_list}
        
        with open(out_json, 'w', encoding='utf-8') as f:
            json.dump(final_json_data, f, indent=2)

        try:
            subprocess.run([CORE_BIN, "rule-set", "compile", "--output", out_srs, out_json], 
                           check=True, capture_output=True, text=True)
            total_count = sum(len(v) for v in final_rules_dict.values())
            return TaskResult(name, "✅", f"Merged {total_count} rules", get_file_size(out_srs))
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            logging.error(f"Compile failed for {name}: {err_msg}")
            
            if os.path.exists(out_json):
                try:
                    os.remove(out_json)
                except OSError:
                    pass
            
            return TaskResult(name, "❌", f"Compile Error: {err_msg}")

    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def main():
    setup_directories()
    
    try:
        with UPDATE_LOCK:
            EXTRACTOR.update()
    except Exception as e:
        logging.warning(f"TLD update failed ({e}), using cache")

    core_ver = get_core_version()
    logging.info(f"Core Version: {core_ver}")
    
    if "❌" in core_ver or "❓" in core_ver:
        logging.error("Core binary missing or invalid. Exiting.")
        sys.exit(1)
    
    tasks = []
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                tasks = data.get("merge_tasks", [])
            validate_config(tasks)
        except Exception as e:
            logging.error(f"Config Error: {e}")
            sys.exit(1)

    results = []
    if tasks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_task, t): t for t in tasks}
            for future in concurrent.futures.as_completed(futures): results.append(future.result())
            
        clean_orphaned_files(tasks)

    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    if results and github_step_summary:
        try:
            with open(github_step_summary, 'a', encoding='utf-8') as f:
                f.write(f"## 🏭 Custom Merge Report\n")
                for r in results: f.write(f"- {r.status} **{r.name}**: {r.msg} ({r.size})\n")
        except Exception as e:
            logging.warning(f"Failed to write summary: {e}")
            
    if any(r.status == "❌" for r in results): sys.exit(1)

if __name__ == "__main__":
    main()
