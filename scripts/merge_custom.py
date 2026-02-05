import json
import os
import subprocess
import sys
import concurrent.futures
import re
import shutil
import ipaddress
import requests
import logging
import stat
import time
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any, NamedTuple

try:
    import tldextract
except ImportError:
    tldextract = None

CONFIG_FILE = 'scripts/custom_merge.json'
DIR_OUTPUT = 'rules'
MAX_WORKERS = 4
TARGET_FORMAT_VERSION = 4
CORE_BIN_PATH = os.getenv("SB_CORE_PATH", "./sb-core")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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

ALLOWED_KEYS_GEOSITE = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'process_name'}
ALLOWED_KEYS_GEOIP = {'ip_cidr', 'source_ip_cidr', 'geoip', 'port', 'source_port'}

PREFIX_FOR_SUFFIX = {
    'api', 'cdn', 'img', 'image', 'static', 'assets', 'media', 'm', 'mobile', 
    'login', 'auth', 'account', 'sso', 'upload', 'download', 'video', 'music', 
    'live', 'stream', 'shop', 'pay', 'dev', 'test', 'beta', 'admin', 'geo', 'maps'
}

PREFIX_FOR_DOMAIN = {
    'ns', 'dns', 'smtp', 'pop', 'imap', 'mx', 'vpn', 'db', 'sql', 'mysql'
}

PROTECTED_ROOTS = {
    'github.io', 'githubusercontent.com', 'gitlab.io', 'vercel.app', 'netlify.app',
    'herokuapp.com', 'fly.dev', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'cloudfront.net', 'amazonaws.com', 'googleapis.com', 'azurewebsites.net',
    'wordpress.com', 'blogspot.com', 'medium.com', 'wixsite.com', 'ddns.net', 'no-ip.com'
}

RE_NUMERIC = re.compile(r'^\d+$')
RE_HASH_LIKE = re.compile(r'[a-f0-9]{16,}')
RE_VERSION_NODE = re.compile(r'^v\d+')
RE_DOMAIN_FEATURE = re.compile(r'^(ns|dns|db|mx|ntp)\d*$')
RE_VALID_DOMAIN = re.compile(r'^[a-z0-9._-]+$')
RE_CLASH_LINE = re.compile(r'^\s*-\s*([A-Z0-9-]+)\s*,\s*([^,]+?)(?:,|\s*#|//|$)')
RE_YAML_LIST_ITEM = re.compile(r'^\s*-\s*[\'"]?([^\'"\s#]+)[\'"]?')

try:
    if tldextract:
        EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True, cache_dir=False)
    else:
        EXTRACTOR = None
except Exception:
    EXTRACTOR = None

class TaskResult:
    def __init__(self, name: str, status: str, msg: str, size: str = "0KB"):
        self.name = name
        self.status = status
        self.msg = msg
        self.size = size

class SourceData:
    def __init__(self, url: str, weight: float):
        self.index = -1 
        self.url = url
        self.weight = float(weight)
        self.fingerprints: Set[str] = set() 
        self.raw_rules: List[Tuple[str, str]] = [] 

def setup_environment():
    dirs = [DIR_OUTPUT, os.path.join(DIR_OUTPUT, "merged-json"), os.path.join(DIR_OUTPUT, "merged-srs")]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    if os.path.exists(CORE_BIN_PATH):
        try:
            st = os.stat(CORE_BIN_PATH)
            os.chmod(CORE_BIN_PATH, st.st_mode | stat.S_IEXEC)
        except Exception:
            pass

def cleanup_startup():
    try:
        for item in os.listdir('.'):
            if item.startswith("temp_") and os.path.isdir(item):
                shutil.rmtree(item, ignore_errors=True)
    except Exception:
        pass

def get_core_version() -> str:
    if not os.path.exists(CORE_BIN_PATH):
        return "Core Missing"
    try:
        res = subprocess.run([os.path.abspath(CORE_BIN_PATH), "version"], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            return res.stdout.split('\n')[0].strip()
        return "Exec Failed"
    except Exception:
        return "Unknown"

def get_file_size(filepath: str) -> str:
    if not os.path.exists(filepath): return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def clean_orphaned_files(active_tasks: List[Dict]):
    expected_srs = {f"{task['name']}.srs" for task in active_tasks}
    expected_json = {f"{task['name']}.json" for task in active_tasks}
    folders = [
        (os.path.join(DIR_OUTPUT, "merged-srs"), expected_srs),
        (os.path.join(DIR_OUTPUT, "merged-json"), expected_json)
    ]
    for folder, expected in folders:
        if not os.path.exists(folder): continue
        for filename in os.listdir(folder):
            if filename not in expected:
                try: os.remove(os.path.join(folder, filename))
                except OSError: pass

def validate_config(tasks: List[Dict]):
    required = {"name", "type", "sources"}
    names = set()
    for i, task in enumerate(tasks):
        if not all(k in task for k in required):
            raise ValueError(f"Task #{i} missing required fields")
        if task["name"] in names:
            raise ValueError(f"Duplicate task name: {task['name']}")
        names.add(task["name"])
        if "min_score" not in task:
            task["min_score"] = 1.0
        if "mode" not in task:
            task["mode"] = "strict"

def download_file(url: str, filename: str) -> bool:
    headers = {"User-Agent": USER_AGENT}
    temp_filename = filename + ".tmp"
    for attempt in range(3):
        try:
            with requests.get(url, headers=headers, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(temp_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=16384):
                        f.write(chunk)
            os.replace(temp_filename, filename)
            return True
        except Exception:
            if os.path.exists(temp_filename):
                try: os.remove(temp_filename)
                except: pass
            if attempt < 2: time.sleep(1)
    return False

def srs_to_json(srs_path: str, json_path: str) -> bool:
    try:
        subprocess.run([os.path.abspath(CORE_BIN_PATH), "rule-set", "decompile", "--output", json_path, srs_path], 
                       check=True, capture_output=True, timeout=20)
        return True
    except Exception:
        return False

def convert_clash_to_json(input_file: str, output_json: str) -> Tuple[bool, str]:
    rules_dict = defaultdict(set)
    count = 0
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'): continue
                
                match = RE_CLASH_LINE.match(line)
                if match:
                    rtype, rval = match.groups()
                    rtype = rtype.upper()
                    rval = rval.strip().strip("'\"")
                    if rtype in RULE_MAP:
                        rules_dict[RULE_MAP[rtype]].add(rval)
                        count += 1
                    continue

                list_match = RE_YAML_LIST_ITEM.match(line)
                if list_match:
                    rval = list_match.group(1).strip()
                    if rval.startswith('+.'):
                        rules_dict['domain_suffix'].add(rval[2:])
                        count += 1
                    else:
                        is_ip = False
                        clean_val = rval
                        try:
                            ipaddress.ip_network(rval, strict=False)
                            is_ip = True
                        except ValueError:
                            pass
                        
                        if not is_ip and ':' in rval:
                            parts = rval.split(':')
                            try:
                                ipaddress.ip_network(parts[0], strict=False)
                                is_ip = True
                                clean_val = parts[0]
                            except ValueError:
                                pass
                        elif not is_ip and rval.replace('.', '').isdigit():
                            try:
                                ipaddress.ip_network(rval, strict=False)
                                is_ip = True
                            except ValueError:
                                pass

                        if is_ip:
                            rules_dict['ip_cidr'].add(clean_val)
                            count += 1
                        elif '.' in rval:
                            rules_dict['domain_suffix'].add(rval)
                            count += 1

        if count == 0: return False, "No valid rules parsed"
        final_rules = [{k: sorted(list(v))} for k, v in rules_dict.items()]
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump({"version": TARGET_FORMAT_VERSION, "rules": final_rules}, f, ensure_ascii=False)
        return True, f"Converted {count}"
    except Exception as e:
        return False, str(e)

def normalize_rule(content: str, rtype: str) -> str:
    if rtype in ['domain', 'domain_suffix']:
        domain = content.strip().lower()
        if ':' in domain: domain = domain.split(':')[0]
        
        if domain.startswith('[') and ']' in domain:
             try:
                ip_part = domain[1:domain.index(']')]
                ipaddress.ip_address(ip_part)
                return ""
             except ValueError: pass
             domain = domain[domain.index(']')+1:]
             if domain.startswith(':'): domain = domain[1:]

        if '..' in domain or len(domain) > 253 or not RE_VALID_DOMAIN.match(domain): return ""
        if domain.startswith('.') or domain.endswith('.'): return ""
        return domain
        
    elif rtype in ['ip_cidr', 'source_ip_cidr']:
        try:
            net = ipaddress.ip_network(content, strict=False)
            return str(net)
        except ValueError:
            return ""
            
    return content

def parse_rules_to_source(file_path: str, task_type: str, src_obj: SourceData):
    if task_type == 'geosite': allowed = ALLOWED_KEYS_GEOSITE
    elif task_type == 'geoip': allowed = ALLOWED_KEYS_GEOIP
    else: allowed = ALLOWED_KEYS_GEOSITE | ALLOWED_KEYS_GEOIP
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        raw = data.get("rules", [])
        if isinstance(raw, dict): raw = [raw]
            
        for rule in raw:
            if not isinstance(rule, dict): continue
            for key, val in rule.items():
                if key not in allowed: continue
                mapped = key if key not in ['ip_cidr', 'ip_cidr6'] else 'ip_cidr'
                values = val if isinstance(val, list) else [val]
                for v in values:
                    if v:
                        v_str = str(v)
                        normalized = normalize_rule(v_str, mapped)
                        if not normalized: continue
                        
                        src_obj.raw_rules.append((normalized, mapped))
                        src_obj.fingerprints.add(f"{mapped}:{normalized}")
    except Exception: pass

def is_high_entropy(text: str) -> bool:
    if RE_NUMERIC.match(text) or RE_HASH_LIKE.search(text): return True
    digit_count = sum(c.isdigit() for c in text)
    return len(text) > 5 and digit_count >= len(text) * 0.5

def evaluate_suggestion(ext: Any) -> str:
    if not ext or not ext.domain: return 'NEUTRAL'
    if ext.suffix and ext.suffix in PROTECTED_ROOTS: return 'MUST_DOMAIN'
    root = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain
    if root in PROTECTED_ROOTS:
        return 'MUST_SUFFIX' if subdomain == 'www' else 'MUST_DOMAIN'
    if not subdomain:
        return 'MUST_SUFFIX'
    head = subdomain.split('.')[0].lower()
    if head in PREFIX_FOR_SUFFIX or 'cdn' in head or head == 'www': return 'MUST_SUFFIX'
    if is_high_entropy(head) or head in PREFIX_FOR_DOMAIN or RE_DOMAIN_FEATURE.match(head): return 'MUST_DOMAIN'
    return 'NEUTRAL'

def smart_deduplication(suffixes: Set[str], domains: Set[str]) -> Tuple[List[str], List[str]]:
    sorted_suffixes = sorted(list(suffixes), key=len)
    processed_suffixes = set()
    final_suffixes = []
    
    for s in sorted_suffixes:
        is_covered = False
        parts = s.split('.')
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i+1:])
            if parent in processed_suffixes:
                is_covered = True
                break
        if not is_covered:
            processed_suffixes.add(s)
            final_suffixes.append(s)

    final_domains = []
    for d in sorted(domains):
        is_covered = False
        if d in processed_suffixes:
            is_covered = True
        else:
            parts = d.split('.')
            for i in range(len(parts)):
                parent = ".".join(parts[i:])
                if parent in processed_suffixes:
                    is_covered = True
                    break
        if not is_covered:
            final_domains.append(d)
            
    return final_suffixes, final_domains

def optimize_ip_cidrs(cidrs: List[str]) -> List[str]:
    v4, v6 = [], []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4: v4.append(net)
            else: v6.append(net)
        except ValueError: continue
    return [str(n) for n in ipaddress.collapse_addresses(sorted(v4))] + \
           [str(n) for n in ipaddress.collapse_addresses(sorted(v6))]

def compute_similarity_matrix(sources: List[SourceData]) -> List[List[float]]:
    n = len(sources)
    if n == 0: return []
    matrix = [[0.0] * n for _ in range(n)]
    
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            set_i = sources[i].fingerprints
            set_j = sources[j].fingerprints
            if not set_i or not set_j: continue
            
            intersection = len(set_i.intersection(set_j))
            union = len(set_i.union(set_j))
            
            sim = intersection / union if union > 0 else 0.0
            matrix[i][j] = sim
            matrix[j][i] = sim
            
            if sim > 0.5:
                name_i = os.path.basename(sources[i].url)
                name_j = os.path.basename(sources[j].url)
                logging.info(f"Similarity: {name_i} <-> {name_j} = {sim:.2f}")
                
    return matrix

def process_rules(sources: List[SourceData], min_score: float, mode: str) -> Dict[str, List]:
    sim_matrix = compute_similarity_matrix(sources)
    
    rule_map = defaultdict(list) 
    rule_meta = {} 
    
    is_trust_mode = (mode == 'trust')
    
    for src in sources:
        for content, rtype in src.raw_rules:
            if rtype in ['domain', 'domain_suffix']:
                if not is_trust_mode and is_high_entropy(content): continue
            
            key = f"{rtype}:{content}"
            rule_map[key].append(src.index)
            rule_meta[key] = (content, rtype)

    final_results = defaultdict(list)
    
    for key, src_indices in rule_map.items():
        content, rtype = rule_meta[key]
        
        matched_sources = [sources[i] for i in src_indices]
        matched_sources.sort(key=lambda x: x.weight, reverse=True)
        
        total_score = 0.0
        processed_indices = []
        
        for current_src in matched_sources:
            max_sim = 0.0
            for prev_idx in processed_indices:
                sim = sim_matrix[current_src.index][prev_idx]
                if sim > max_sim:
                    max_sim = sim
            
            marginal_gain = current_src.weight * (1.0 - max_sim)
            total_score += marginal_gain
            processed_indices.append(current_src.index)
            
        if total_score >= min_score:
            final_results[rtype].append(content)

    output = {}
    
    candidate_domains = set(final_results.get('domain', []))
    candidate_suffixes = set(final_results.get('domain_suffix', []))
    final_s, final_d = smart_deduplication(candidate_suffixes, candidate_domains)
    
    if final_d: output['domain'] = final_d
    if final_s: output['domain_suffix'] = final_s
    
    for rtype, items in final_results.items():
        if rtype in ['domain', 'domain_suffix']: continue
        
        if rtype in ['ip_cidr', 'source_ip_cidr']:
            output[rtype] = optimize_ip_cidrs(items)
        elif 'port' in rtype:
            try: items.sort(key=lambda x: int(str(x).split('-')[0]) if str(x).replace('-','').isdigit() else 99999)
            except: items.sort()
            output[rtype] = items
        else:
            items.sort()
            output[rtype] = items
            
    return output

def worker(task: Dict) -> TaskResult:
    name = task['name']
    min_score = float(task.get('min_score', 1.0))
    mode = task.get('mode', 'strict')
    temp_dir = f"temp_{name}"
    out_json = os.path.join(DIR_OUTPUT, "merged-json", f"{name}.json")
    out_srs = os.path.join(DIR_OUTPUT, "merged-srs", f"{name}.srs")
    
    success_flag = False
    os.makedirs(temp_dir, exist_ok=True)
    
    temp_source_list: List[SourceData] = []
    
    try:
        for i, src_conf in enumerate(task['sources']):
            if isinstance(src_conf, str):
                url = src_conf
                weight = 1.0
            else:
                url = src_conf.get('url')
                weight = float(src_conf.get('weight', 1.0))
            
            if not url: continue
            
            src_obj = SourceData(url, weight)
            
            local_file = os.path.join(temp_dir, f"src_{i}.raw")
            if not download_file(url, local_file): continue
                
            json_file = os.path.join(temp_dir, f"src_{i}.json")
            target_file = local_file
            
            is_json = False
            try:
                with open(local_file, 'r', encoding='utf-8') as f:
                    if f.read(1) in ['{', '[']: is_json = True
            except: pass
            
            if url.endswith('.srs'):
                if srs_to_json(local_file, json_file): target_file = json_file
                else: continue
            elif not is_json:
                ok, _ = convert_clash_to_json(local_file, json_file)
                if ok: target_file = json_file
                else: continue
            
            parse_rules_to_source(target_file, task['type'], src_obj)
            
            if src_obj.fingerprints:
                temp_source_list.append(src_obj)
        
        if not temp_source_list:
            return TaskResult(name, "⚠️", "No rules extracted")
            
        for idx, src in enumerate(temp_source_list):
            src.index = idx
            
        merged_data = process_rules(temp_source_list, min_score, mode)
        total_rules = sum(len(v) for v in merged_data.values())
        
        final_list = []
        for key, values in merged_data.items():
            if values: final_list.append({key: values})

        with open(out_json, 'w', encoding='utf-8') as f:
            json.dump({"version": TARGET_FORMAT_VERSION, "rules": final_list}, f, indent=2, ensure_ascii=False)
            
        subprocess.run([os.path.abspath(CORE_BIN_PATH), "rule-set", "compile", "--output", out_srs, out_json], 
                       check=True, capture_output=True, timeout=90)
        
        success_flag = True
        return TaskResult(name, "✅", f"Merged {total_rules}", get_file_size(out_srs))
        
    except Exception as e:
        return TaskResult(name, "❌", str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if not success_flag:
            for f in [out_json, out_srs]:
                if os.path.exists(f): 
                    try: os.remove(f)
                    except: pass

def main():
    setup_environment()
    cleanup_startup()
    
    if EXTRACTOR:
        try: EXTRACTOR.update(fetch_now=False)
        except: pass

    logging.info(f"Core: {get_core_version()}")
    
    tasks = []
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                tasks = json.load(f).get("merge_tasks", [])
            validate_config(tasks)
        except Exception as e:
            logging.error(f"Config Error: {e}")
            sys.exit(1)
    
    if not tasks:
        logging.warning("No tasks found.")
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(worker, t): t for t in tasks}
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
            
    clean_orphaned_files(tasks)

    summary_file = os.getenv('GITHUB_STEP_SUMMARY')
    if summary_file:
        with open(summary_file, 'a', encoding='utf-8') as f:
            f.write("## 🏭 Custom Merge Report\n")
            for r in sorted(results, key=lambda x: x.name):
                f.write(f"- {r.status} **{r.name}**: {r.msg} ({r.size})\n")
    
    for r in results:
        logging.info(f"[{r.name}] {r.status} {r.msg} ({r.size})")

    if any(r.status == "❌" for r in results):
        sys.exit(1)

if __name__ == "__main__":
    main()
