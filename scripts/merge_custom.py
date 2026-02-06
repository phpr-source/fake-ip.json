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
import signal
import tempfile
import math
import gc
from collections import defaultdict
from typing import List, Dict, Set, Tuple
from pathlib import Path
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 優先使用 orjson 提升性能，否則回退到 json
try:
    import orjson
    USE_ORJSON = True
except ImportError:
    orjson = None
    USE_ORJSON = False

# --- 全局配置 ---
CONFIG_FILE = 'scripts/custom_merge.json'
DIR_OUTPUT = Path('rules')
MAX_WORKERS = 4
TARGET_FORMAT_VERSION = 4
CORE_BIN_PATH = os.getenv("SB_CORE_PATH", "./sb-core")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
MAX_DOWNLOAD_SIZE = 512 * 1024 * 1024  # 512MB 限制
MAX_RULES_PER_SOURCE = 5000000

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# 規則類型映射
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

ALLOWED_KEYS_GEOSITE = frozenset({'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'process_name'})
ALLOWED_KEYS_GEOIP = frozenset({'ip_cidr', 'source_ip_cidr', 'geoip', 'port', 'source_port'})

# 基礎設施域名白名單（用於熵值檢測豁免，防止誤殺）
INFRASTRUCTURE_ROOTS = frozenset({
    'amazonaws.com', 'cloudfront.net', 'awsglobalaccelerator.com', 'aws.dev',
    'googleapis.com', 'googleusercontent.com', 'ggpht.com', 'ytimg.com', 'gstatic.com', 'appspot.com', 'google.com',
    'azure.com', 'windows.net', 'trafficmanager.net', 'azureedge.net', 'office.net', 'microsoft.com', 'azurewebsites.net',
    'apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com', 'aaplimg.com',
    'akamaiedge.net', 'akadns.net', 'edgekey.net', 'akamai.net', 'akamaitechnologies.com',
    'cdn.cloudflare.net', 'workers.dev', 'pages.dev', 'cloudflare.com',
    'fastly.net', 'fastlylb.net', 'fastly.com',
    'githubusercontent.com', 'github.io', 'gitlab.io', 'github.com',
    'dropboxusercontent.com', 'dropbox.com',
    'facebook.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com', 'whatsapp.net',
    'twitter.com', 'twimg.com', 't.co', 'x.com',
    'alicdn.com', 'kunlungr.com', 'alipayobjects.com', 'alibaba.com', 'alipay.com',
    'bdstatic.com', 'jomodns.com', 'baidu.com',
    'upaiyun.com', 'upcdn.net',
    'bilivideo.com', 'hdslb.com', 'bilibili.com',
    'douyincdn.com', 'byteimg.com', 'pstatp.com', 'douyin.com', 'tiktokcdn.com',
    'qlogo.cn', 'qpic.cn', 'myqcloud.com', 'gtimg.cn', 'qq.com', 'tencent-cloud.net',
    '126.net', '163.com', 'netease.com',
    'slack-edge.com', 'slack-msgs.com',
    'zoom.us', 'zoom.com'
})

INFRA_SUFFIXES = tuple("." + r for r in INFRASTRUCTURE_ROOTS)

# 正則編譯
RE_NUMERIC = re.compile(r'^\d+$')
RE_HASH_LIKE = re.compile(r'\b[a-f0-9]{32,64}\b')
RE_YAML_LIST_ITEM = re.compile(r'^\s*-\s*[\'"]?([^\'"\s#]+)[\'"]?')
RE_IPV6_BRACKET = re.compile(r'^\[([0-9a-fA-F:]+)\](?::\d+)?$')
RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')

# --- 數據結構 ---

class TaskResult:
    __slots__ = ('name', 'status', 'msg', 'size')
    def __init__(self, name: str, status: str, msg: str, size: str):
        self.name = name
        self.status = status
        self.msg = msg
        self.size = size

class SourceData:
    __slots__ = ('url', 'weight', 'index', 'raw_rules', '_fingerprints')
    def __init__(self, url: str, weight: float, index: int):
        self.url = url
        self.weight = weight
        self.index = index
        self.raw_rules: List[Tuple[str, str]] = []
        self._fingerprints = None
    
    def get_fingerprints(self) -> Set[str]:
        if self._fingerprints is None:
            # 延遲生成指紋，節省內存
            self._fingerprints = {f"{r[1]}:{r[0]}" for r in self.raw_rules}
        return self._fingerprints

# --- 工具函數 ---

def json_dumps(data: dict) -> bytes:
    if USE_ORJSON:
        try:
            return orjson.dumps(data, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
        except Exception:
            pass
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True).encode('utf-8')

def create_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=MAX_WORKERS+1, pool_maxsize=MAX_WORKERS*2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session

def setup_environment():
    dirs = [DIR_OUTPUT, DIR_OUTPUT / "merged-json", DIR_OUTPUT / "merged-srs"]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    core_path = Path(CORE_BIN_PATH).absolute()
    if core_path.exists():
        try:
            os.chmod(core_path, core_path.stat().st_mode | stat.S_IEXEC)
        except OSError:
            pass

def cleanup_startup():
    """清理殘留的臨時文件"""
    try:
        temp_dir = Path(tempfile.gettempdir())
        for item in temp_dir.glob("temp_*"):
             if item.is_dir():
                 shutil.rmtree(item, ignore_errors=True)
        for item in Path('.').iterdir():
            if item.is_dir() and item.name.startswith("temp_"):
                shutil.rmtree(item, ignore_errors=True)
    except OSError:
        pass

def get_file_size(filepath: Path) -> str:
    if not filepath.exists():
        return "0KB"
    size = filepath.stat().st_size
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"

def download_file(session: requests.Session, url: str, filename: Path) -> bool:
    temp = filename.with_suffix('.tmp')
    try:
        with session.get(url, stream=True, timeout=(10, 60), verify=True) as response:
            response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            if 'html' in content_type:
                return False
            
            length_str = response.headers.get('content-length')
            if length_str and length_str.isdigit():
                if int(length_str) > MAX_DOWNLOAD_SIZE:
                    return False
            
            downloaded = 0
            with open(temp, 'wb') as f:
                for chunk in response.iter_content(chunk_size=131072):
                    if chunk:
                        downloaded += len(chunk)
                        if downloaded > MAX_DOWNLOAD_SIZE:
                            return False
                        f.write(chunk)
        
        # 簡單校驗文件頭
        with open(temp, 'rb') as f:
            header = f.read(256).lower()
            if b'<html' in header or b'<!doctype' in header:
                return False

        if filename.exists():
            filename.unlink()
        shutil.move(str(temp), str(filename))
        return True
    except Exception:
        if temp.exists():
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
        return False

def srs_to_json(srs_path: Path, json_path: Path) -> bool:
    try:
        subprocess.run(
            [str(Path(CORE_BIN_PATH).absolute()), "rule-set", "decompile",
             "--output", str(json_path), str(srs_path)],
            check=True, capture_output=True, timeout=60
        )
        return True
    except Exception:
        return False

# --- 歸一化邏輯 ---

@lru_cache(maxsize=65536)
def normalize_domain(content: str) -> str:
    """域名標準化：小寫、去點、IDNA編碼、正則校驗"""
    content = content.strip().lower().strip('.')
    if not content or len(content) > 253: return ""
    
    try:
        # 強制轉為 punycode，保證中文域名匹配準確性
        if any(ord(c) > 127 for c in content):
            encoded = content.encode('idna').decode('ascii')
        else:
            encoded = content
    except UnicodeError:
        return ""

    if ' ' in encoded or '_' in encoded: return ""
    
    # 逐段校驗 RFC 規則
    parts = encoded.split('.')
    for part in parts:
        if not part or len(part) > 63 or part.startswith('-') or part.endswith('-'):
            return ""
        if not RE_DOMAIN_LABEL.match(part):
            return ""
            
    return encoded

@lru_cache(maxsize=16384)
def normalize_ip(content: str) -> str:
    """IP標準化：去括號、補掩碼、校驗有效性"""
    content = content.strip("'\" ").replace(" ", "")
    if not content: return ""
    
    match = RE_IPV6_BRACKET.match(content)
    if match:
        content = match.group(1)
    
    try:
        if '/' not in content:
            content += '/128' if ':' in content else '/32'
        
        net = ipaddress.ip_network(content, strict=False)
        return str(net)
    except ValueError:
        return ""

def parse_line_content(line: str, rules: Dict[str, Set[str]]):
    """解析單行文本規則（兼容 Clash / List）"""
    clean = line.partition('#')[0].partition('//')[0].strip()
    if not clean: return

    # 列表格式
    if clean.startswith('-'):
        m = RE_YAML_LIST_ITEM.match(clean)
        if m:
            rval = m.group(1).strip()
            if rval.startswith('+.'):
                norm = normalize_domain(rval[2:])
                if norm: rules['domain_suffix'].add(norm)
            elif ':' in rval or (rval[0].isdigit() and '.' in rval):
                norm = normalize_ip(rval)
                if norm: rules['ip_cidr'].add(norm)
            else:
                if rval.startswith('.'):
                     norm = normalize_domain(rval[1:])
                     if norm: rules['domain_suffix'].add(norm)
                else:
                     norm = normalize_domain(rval)
                     if norm: rules['domain_suffix'].add(norm)
        return

    # 鍵值對格式
    if ',' in clean:
        parts = [p.strip() for p in clean.split(',')]
        if len(parts) >= 2:
            rtype = parts[0].upper()
            rval = parts[1].strip("'\"")
            
            mapped = RULE_MAP.get(rtype)
            if mapped:
                if mapped in ('domain', 'domain_suffix', 'domain_keyword'):
                    norm = normalize_domain(rval)
                elif mapped in ('ip_cidr', 'source_ip_cidr', 'geoip'):
                    norm = normalize_ip(rval)
                else:
                    norm = rval.strip()
                
                if norm:
                    rules[mapped].add(norm)

def parse_rules_to_source(file_path: Path, task_type: str, src_obj: SourceData):
    """解析文件並填充到 SourceData"""
    allowed = ALLOWED_KEYS_GEOSITE if task_type == 'geosite' else ALLOWED_KEYS_GEOIP if task_type == 'geoip' else ALLOWED_KEYS_GEOSITE | ALLOWED_KEYS_GEOIP
    local_rules = []
    
    try:
        is_json_likely = False
        with open(file_path, 'rb') as f:
            header = f.read(10).strip()
            if header.startswith(b'{') or header.startswith(b'['): 
                is_json_likely = True
            f.seek(0)
            
            if is_json_likely:
                try:
                    if USE_ORJSON:
                        data = orjson.loads(f.read())
                    else:
                        data = json.load(f)
                    
                    raw = data.get("rules", [])
                    if isinstance(raw, dict): raw = [raw]
                    
                    for rule in raw:
                        if not isinstance(rule, dict): continue
                        for key, val in rule.items():
                            if key not in allowed: continue
                            
                            mapped = 'ip_cidr' if key in ('ip_cidr', 'ip_cidr6') else key
                            values = val if isinstance(val, list) else [val]
                            
                            for v in values:
                                v_str = str(v)
                                if mapped in ('domain', 'domain_suffix'):
                                    norm = normalize_domain(v_str)
                                elif mapped in ('ip_cidr', 'source_ip_cidr'):
                                    norm = normalize_ip(v_str)
                                else:
                                    norm = v_str.strip()
                                
                                if norm:
                                    local_rules.append((norm, mapped))
                    
                    src_obj.raw_rules = local_rules
                    return
                except Exception:
                    f.seek(0)
        
        # 文本/YAML 解析
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            temp_rules = defaultdict(set)
            for line in f:
                parse_line_content(line, temp_rules)
            
            for k, v in temp_rules.items():
                if k in allowed:
                    for item in v:
                        local_rules.append((item, k))
        
        src_obj.raw_rules = local_rules

    except Exception as e:
        logger.debug(f"Parse error {file_path}: {e}")

# --- 算法邏輯 ---

def shannon_entropy(text: str) -> float:
    """計算香農熵，識別隨機生成的 DGA 域名"""
    if not text: return 0.0
    length = len(text)
    counts = defaultdict(int)
    for char in text:
        counts[char] += 1
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(text: str) -> bool:
    """判斷是否為高熵（垃圾）域名"""
    if text in INFRASTRUCTURE_ROOTS: return False
    if text.endswith(INFRA_SUFFIXES): return False

    if len(text) >= 32 and RE_HASH_LIKE.search(text): return True
    if RE_NUMERIC.match(text): return True
    
    if len(text) >= 16 and shannon_entropy(text) > 4.8: return True
    return False

def smart_domain_optimization(domains: Set[str], suffixes: Set[str]) -> Tuple[List[str], List[str]]:
    """
    極致域名優化算法 (Reverse String Sort + Linear Scan)
    合併域名與後綴，反轉排序後線性掃描，精準剔除被覆蓋的域名或子後綴。
    """
    if not suffixes and not domains:
        return [], []
    
    # 構建列表：(反轉字符串, 類型優先級, 原始字符串)
    # 類型優先級：0=Suffix, 1=Domain。排序時 Suffix 排在 Domain 前面。
    items = []
    for s in suffixes:
        items.append((s[::-1], 0, s))
    for d in domains:
        items.append((d[::-1], 1, d))
    
    items.sort()
    
    final_suffixes = []
    final_domains = []
    active_cover_rev = None # 當前生效的覆蓋規則（反轉態）
    
    for rev_str, rtype, original in items:
        is_covered = False
        
        if active_cover_rev:
            # 檢查是否被當前覆蓋規則命中
            # 由於已排序，若 rev_str 是 active_cover_rev 的子域名，它必然緊隨其後且以其開頭
            if rev_str.startswith(active_cover_rev):
                # 邊界檢查：完全相等，或後接點號（moc.elgoog 覆蓋 moc.elgoog.liam）
                if len(rev_str) == len(active_cover_rev):
                    is_covered = True
                elif rev_str[len(active_cover_rev)] == '.':
                    is_covered = True
        
        if not is_covered:
            if rtype == 0:
                # 發現新的有效後綴，更新覆蓋規則
                final_suffixes.append(original)
                active_cover_rev = rev_str
            else:
                # 發現未被覆蓋的精確域名
                final_domains.append(original)
                # 精確域名不具備覆蓋能力，不更新 active_cover_rev
                
    return sorted(final_suffixes), sorted(final_domains)

def optimize_ip_cidrs(cidrs: List[str]) -> List[str]:
    """IP CIDR 分桶合併優化"""
    v4_buckets = defaultdict(list)
    v6_buckets = defaultdict(list)
    v4_supernets = []
    v6_supernets = []
    
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4:
                if net.prefixlen < 8:
                    v4_supernets.append(net)
                else:
                    v4_buckets[int(net.network_address) >> 24].append(net)
            else:
                if net.prefixlen < 16:
                    v6_supernets.append(net)
                else:
                    v6_buckets[int(net.network_address) >> 112].append(net)
        except ValueError:
            continue

    final_list = []

    # 處理 IPv4
    collapsed_v4 = []
    for bucket in v4_buckets.values():
        if len(bucket) > 1:
            bucket.sort()
            collapsed_v4.extend(ipaddress.collapse_addresses(bucket))
        else:
            collapsed_v4.extend(bucket)
    
    if v4_supernets:
        all_v4 = v4_supernets + collapsed_v4
        all_v4.sort()
        final_list.extend(str(n) for n in ipaddress.collapse_addresses(all_v4))
    else:
        final_list.extend(str(n) for n in collapsed_v4)

    # 處理 IPv6
    collapsed_v6 = []
    for bucket in v6_buckets.values():
        if len(bucket) > 1:
            bucket.sort()
            collapsed_v6.extend(ipaddress.collapse_addresses(bucket))
        else:
            collapsed_v6.extend(bucket)
            
    if v6_supernets:
        all_v6 = v6_supernets + collapsed_v6
        all_v6.sort()
        final_list.extend(str(n) for n in ipaddress.collapse_addresses(all_v6))
    else:
        final_list.extend(str(n) for n in collapsed_v6)
        
    return final_list

def compute_weights(sources: List[SourceData]) -> Dict[Tuple[str, str], float]:
    """計算權重矩陣（高準確性：去除重複來源的影響）"""
    n = len(sources)
    if n == 0: return {}
    
    # 計算相似度矩陣
    fp_sets = [src.get_fingerprints() for src in sources]
    matrix = [[0.0] * n for _ in range(n)]
    
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            set_i = fp_sets[i]
            set_j = fp_sets[j]
            
            if not set_i or not set_j:
                sim = 0.0
            else:
                intersection = len(set_i & set_j)
                union = len(set_i) + len(set_j) - intersection
                sim = intersection / union if union > 0 else 0.0
            
            matrix[i][j] = matrix[j][i] = sim
    
    # 重要：立即釋放指紋集合內存
    del fp_sets
    gc.collect()

    rule_scores = defaultdict(float)
    
    for i, src in enumerate(sources):
        # 根據與其他源的重疊度降低權重
        overlap_penalty = sum(matrix[i][j] for j in range(n) if i != j)
        adjusted_weight = src.weight / (1.0 + overlap_penalty)
        
        for content, rtype in src.raw_rules:
            rule_scores[(rtype, content)] += adjusted_weight
            
    return rule_scores

def process_rules(sources: List[SourceData], min_score: float, mode: str) -> Dict[str, List]:
    if not sources: return {}
    
    is_trust = (mode == 'trust')
    rule_scores = compute_weights(sources)
    
    final_results = defaultdict(set)
    
    for (rtype, content), score in rule_scores.items():
        # 嚴格模式下過濾高熵域名
        if rtype in ('domain', 'domain_suffix') and not is_trust:
            if is_high_entropy(content):
                continue
        
        if score >= min_score:
            final_results[rtype].add(content)
            
    output = {}
    
    # 域名優化
    doms = final_results.get('domain', set())
    sufs = final_results.get('domain_suffix', set())
    if doms or sufs:
        s, d = smart_domain_optimization(doms, sufs)
        if s: output['domain_suffix'] = s
        if d: output['domain'] = d
    
    # 其他類型處理
    for rtype, items in final_results.items():
        if rtype in ('domain', 'domain_suffix'): continue
        
        lst = list(items)
        if rtype in ('ip_cidr', 'source_ip_cidr'):
            output[rtype] = optimize_ip_cidrs(lst)
        elif 'port' in rtype:
            try:
                lst.sort(key=lambda x: int(str(x).split('-')[0]) if '-' in str(x) else int(x))
            except:
                lst.sort()
            output[rtype] = lst
        else:
            lst.sort()
            output[rtype] = lst
            
    return output

def worker(task: Dict) -> TaskResult:
    name = task['name']
    min_score = float(task.get('min_score', 1.0))
    mode = task.get('mode', 'strict')
    
    out_json = DIR_OUTPUT / "merged-json" / f"{name}.json"
    out_srs = DIR_OUTPUT / "merged-srs" / f"{name}.srs"
    
    # 使用臨時目錄確保安全清理
    with tempfile.TemporaryDirectory(prefix=f"temp_{name}_") as tmpdir:
        tmppath = Path(tmpdir)
        sources = []
        session = create_session()
        
        try:
            for i, conf in enumerate(task['sources']):
                url = conf if isinstance(conf, str) else conf.get('url')
                weight = 1.0 if isinstance(conf, str) else float(conf.get('weight', 1.0))
                
                if not url: continue
                
                src = SourceData(url, weight, i)
                raw_file = tmppath / f"src_{i}.raw"
                
                if not download_file(session, url, raw_file):
                    continue
                
                target_file = raw_file
                
                # 若是 SRS 格式，先反編譯為 JSON
                if url.endswith('.srs'):
                    json_file = tmppath / f"src_{i}.json"
                    if srs_to_json(raw_file, json_file):
                        target_file = json_file
                    else:
                        continue
                
                parse_rules_to_source(target_file, task['type'], src)
                if src.raw_rules:
                    sources.append(src)
                
                # 單個源處理完畢，釋放其原始數據，僅保留必要字段
                del src
                gc.collect()
            
            if not sources:
                return TaskResult(name, "⚠️", "No valid sources", "0KB")
            
            merged = process_rules(sources, min_score, mode)
            
            total_count = sum(len(v) for v in merged.values())
            if total_count == 0:
                return TaskResult(name, "⚠️", "Empty Result", "0KB")
            
            final_data = {
                "version": TARGET_FORMAT_VERSION, 
                "rules": [{k: v} for k, v in merged.items() if v]
            }
            
            with open(out_json, 'wb') as f:
                f.write(json_dumps(final_data))
                
            # 編譯為 SRS
            res = subprocess.run(
                [str(Path(CORE_BIN_PATH).absolute()), "rule-set", "compile", 
                 "--output", str(out_srs), str(out_json)],
                capture_output=True, text=True, timeout=180
            )
            
            if res.returncode != 0:
                return TaskResult(name, "❌", f"Compile: {res.stderr[:100]}", "0KB")
            
            return TaskResult(name, "✅", f"Merged {total_count}", get_file_size(out_srs))
            
        except Exception as e:
            logger.exception(f"Worker Error {name}")
            return TaskResult(name, "❌", str(e)[:100], "0KB")
        finally:
            session.close()
            gc.collect()

def handle_signal(signum, frame):
    sys.exit(1)

def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    setup_environment()
    cleanup_startup()
    
    tasks = []
    if Path(CONFIG_FILE).exists():
        try:
            with open(CONFIG_FILE, 'rb') as f:
                if USE_ORJSON:
                    cfg = orjson.loads(f.read())
                else:
                    cfg = json.load(f)
                tasks = cfg.get("merge_tasks", [])
        except Exception as e:
            logger.error(f"Config Error: {e}")
            sys.exit(1)
            
    if not tasks: return
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(worker, t): t for t in tasks}
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
            
    # GitHub Action 報告
    summary = os.getenv('GITHUB_STEP_SUMMARY')
    if summary:
        try:
            with open(summary, 'a', encoding='utf-8') as f:
                f.write("## 🏭 Custom Merge Report\n| Task | Status | Details | Size |\n|---|---|---|---|\n")
                for r in sorted(results, key=lambda x: x.name):
                    f.write(f"| {r.name} | {r.status} | {r.msg} | {r.size} |\n")
        except OSError:
            pass
            
    for r in results:
        logger.info(f"[{r.name}] {r.status} {r.msg} ({r.size})")
        
    if any(r.status == "❌" for r in results):
        sys.exit(1)

if __name__ == "__main__":
    main()
