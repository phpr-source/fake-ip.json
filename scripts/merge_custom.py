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
import hashlib
import time
import threading
import platform
import multiprocessing
from collections import defaultdict, Counter, deque, OrderedDict
from typing import List, Dict, Set, Tuple, Optional, Any, Union, NamedTuple, Iterator
from pathlib import Path
from functools import lru_cache, wraps
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from enum import Enum, auto
from abc import ABC, abstractmethod
from contextlib import contextmanager

# ==========================================
# 0. 可選依賴處理（v4.4.1 健壯性增強）
# ==========================================

try:
    import orjson
    USE_ORJSON = True
except ImportError:
    orjson = None
    USE_ORJSON = False

try:
    import lmdb
    USE_LMDB = True
except ImportError:
    lmdb = None
    USE_LMDB = False

try:
    import msgpack
    USE_MSGPACK = True
except ImportError:
    msgpack = None
    USE_MSGPACK = False

# v4.4.1: 增強 BLAKE3 導入健壯性（捕獲所有異常）
try:
    from blake3 import blake3
    USE_BLAKE3 = True
except Exception:  # 捕獲 ImportError, OSError, ABI 不兼容等所有異常
    blake3 = None
    USE_BLAKE3 = False
    if platform.system() != 'Windows':  # 僅在非 Windows 平台記錄警告
        logging.getLogger(__name__).debug("BLAKE3 加載失敗，使用 SHA256 回退")

USE_Z3 = False
if platform.system() != 'Windows':
    try:
        from z3 import Solver, Bool, Or, And, Not, sat, Optimize
        USE_Z3 = True
    except ImportError:
        pass

# ==========================================
# 1. 配置與常數（v4.4.1 性能保護）
# ==========================================

CONFIG_FILE = 'scripts/custom_merge.json'
DIR_OUTPUT = Path('rules')
MAX_WORKERS = (os.cpu_count() or 4) * 2
TARGET_FORMAT_VERSION = 4
CORE_BIN_PATH = os.getenv("SB_CORE_PATH", "./sb-core")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
MAX_DOWNLOAD_SIZE = 1024 * 1024 * 1024
INCREMENTAL_MODE = True

# v4.4.1: 新增性能保護閾值
MAX_CIDR_OUTPUT = 10000  # 防止 CIDR 輸出膨脹攻擊
MAX_IP_RANGE_AGGREGATION = 2**24  # /8 大小的閾值，超過則使用激進聚合
LITE_MODE_THRESHOLD = 1000  # 規則數低於此值且無 Z3 時啟用輕量模式

STATE_FORMAT_VERSION = 5
SUPPORTED_STATE_VERSIONS = {4, 5}

class WildcardSemanticsConfig:
    """嚴格偏序集（Strict Poset）配置"""
    WILDCARD_CONTAINS_ROOT = False      
    ROOT_CONTAINS_WILDCARD = True       
    WILDCARD_CONTAINS_SUBWILDCARD = True
    
    @classmethod
    def validate_poset_axioms(cls):
        if cls.WILDCARD_CONTAINS_ROOT and cls.ROOT_CONTAINS_WILDCARD:
            raise ValueError("POSET violation: Antisymmetry broken")

class EntropyLevel(Enum):
    SAFE = auto()
    SUSPICIOUS = auto()
    DGA_LIKELY = auto()
    DGA_CONFIRMED = auto()

RULE_MAP = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name',
    'USER-AGENT': 'user_agent',
    'URL-REGEX': 'url_regex',
    'DOMAIN-WILDCARD': 'domain_wildcard'
}

RE_HASH_LIKE = re.compile(r'\b[a-f0-9]{32,64}\b')
RE_EXCLUSION_PREFIX = re.compile(r'^\s*!')
RE_WILDCARD_DOMAIN = re.compile(r'^\*\.(.+)$')
RE_IPV4_MAPPED_IPV6 = re.compile(r'^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')
RE_DOMAIN_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# ==========================================
# 2. 分級存儲後端（v4.4.1 遷移加固）
# ==========================================

class StorageBackend(ABC):
    @abstractmethod
    def save(self, key: bytes, value: bytes): pass
    @abstractmethod
    def load(self, key: bytes) -> Optional[bytes]: pass
    @abstractmethod
    def close(self): pass

class LMDBBackend(StorageBackend):
    def __init__(self, path: Path):
        self.env = lmdb.open(str(path), map_size=2**30, subdir=False)
    
    def save(self, key: bytes, value: bytes):
        with self.env.begin(write=True) as txn:
            txn.put(key, value)
    
    def load(self, key: bytes) -> Optional[bytes]:
        with self.env.begin() as txn:
            return txn.get(key)
    
    def close(self):
        self.env.close()

class SQLiteBackend(StorageBackend):
    def __init__(self, path: Path):
        import sqlite3
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("CREATE TABLE IF NOT EXISTS state (key BLOB PRIMARY KEY, value BLOB)")
        self.conn.execute("PRAGMA journal_mode=WAL")  # v4.4.1: 提高並發安全性
        self.conn.commit()
    
    def save(self, key: bytes, value: bytes):
        self.conn.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, value))
        self.conn.commit()
    
    def load(self, key: bytes) -> Optional[bytes]:
        cursor = self.conn.execute("SELECT value FROM state WHERE key=?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None
    
    def close(self):
        self.conn.close()

def get_storage_backend(path: Path) -> StorageBackend:
    if USE_LMDB and platform.system() != 'Windows':
        return LMDBBackend(path)
    else:
        logger.info("使用 SQLite 後端（兼容性模式）")
        return SQLiteBackend(path.with_suffix('.sqlite'))

# ==========================================
# 3. 核心數據結構（v4.4.1 性能保護與線程安全）
# ==========================================

class TaskResult(NamedTuple):
    name: str
    status: str
    msg: str
    size: str

class DomainTrie:
    """
    v4.4.1: 讀寫鎖分離優化（讀多寫少場景）
    - 使用 RLock 保證線程安全
    - 保留 LRU 緩存加速讀取
    """
    __slots__ = ('root', '_cache', '_cache_limit', '_lock')
    
    def __init__(self, cache_limit: int = 10000):
        self.root = {}
        self._cache = OrderedDict()
        self._cache_limit = cache_limit
        self._lock = threading.RLock()
    
    def insert(self, domain: str):
        with self._lock:
            node = self.root
            parts = domain.split('.')
            for part in reversed(parts):
                if part not in node:
                    node[part] = {}
                node = node[part]
            node['_end'] = True
            self._cache.clear()
    
    def is_covered(self, domain: str) -> bool:
        with self._lock:
            if domain in self._cache:
                self._cache.move_to_end(domain)
                return self._cache[domain]
            
            node = self.root
            parts = domain.split('.')
            result = False
            
            for part in reversed(parts):
                if '_end' in node:
                    result = True
                    break
                if part not in node:
                    break
                node = node[part]
            else:
                if '_end' in node:
                    result = True
            
            self._cache[domain] = result
            if len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)
            
            return result
    
    def optimize(self) -> List[str]:
        with self._lock:
            results = []
            stack = [('', self.root)]
            while stack:
                current_domain, node = stack.pop()
                if '_end' in node:
                    results.append(current_domain)
                    continue
                for part, child in node.items():
                    if part == '_end': 
                        continue
                    new_domain = f"{part}.{current_domain}" if current_domain else part
                    stack.append((new_domain, child))
            return sorted(results)

class UnifiedIPRangeIndex:
    """
    v4.4.1: 增強型區間合併索引
    - 添加輸出膨脹保護（MAX_CIDR_OUTPUT）
    - 大區間激進聚合策略
    """
    __slots__ = ('v4_ranges', 'v6_ranges', '_sorted', '_lock', '_networks_cache')
    
    def __init__(self):
        self.v4_ranges = []
        self.v6_ranges = []
        self._sorted = False
        self._lock = threading.Lock()
        self._networks_cache = None
    
    def _normalize_mapped(self, cidr: str) -> Optional[Tuple[str, int]]:
        """處理 IPv4-mapped IPv6"""
        if '/' in cidr:
            base, prefix = cidr.split('/')
            prefix = int(prefix)
        else:
            base = cidr
            prefix = None
            
        match = RE_IPV4_MAPPED_IPV6.match(base)
        if match:
            v4_ip = match.group(1)
            if prefix is not None:
                if prefix >= 96:
                    new_prefix = prefix - 96
                    return (f"{v4_ip}/{new_prefix}", 4)
                else:
                    return None
            return (f"{v4_ip}/32", 4)
        return None
    
    def add_cidr(self, cidr: str):
        """添加 CIDR，線程安全"""
        with self._lock:
            try:
                mapped = self._normalize_mapped(cidr)
                if mapped:
                    cidr_str, version = mapped
                    net = ipaddress.ip_network(cidr_str, strict=False)
                else:
                    net = ipaddress.ip_network(cidr, strict=False)
                    version = net.version
                
                start = int(net.network_address)
                end = int(net.broadcast_address)
                
                if version == 4:
                    self.v4_ranges.append((start, end))
                else:
                    self.v6_ranges.append((start, end))
                self._sorted = False
                self._networks_cache = None
            except ValueError:
                pass
    
    def build(self):
        """構建索引：區間排序與合併 O(N log N)"""
        with self._lock:
            if not self._sorted:
                self.v4_ranges = self._merge_intervals(self.v4_ranges)
                self.v6_ranges = self._merge_intervals(self.v6_ranges)
                self._sorted = True
    
    def _merge_intervals(self, intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """合併重疊或相鄰區間"""
        if not intervals:
            return []
        
        intervals.sort(key=lambda x: x[0])
        merged = []
        curr_start, curr_end = intervals[0]
        
        for i in range(1, len(intervals)):
            next_start, next_end = intervals[i]
            if next_start <= curr_end + 1:
                curr_end = max(curr_end, next_end)
            else:
                merged.append((curr_start, curr_end))
                curr_start, curr_end = next_start, next_end
        
        merged.append((curr_start, curr_end))
        return merged
    
    def contains_cidr(self, cidr: str) -> bool:
        """二分查找判斷是否包含 O(log N)"""
        with self._lock:
            if not self._sorted:
                self.build()
            
            try:
                mapped = self._normalize_mapped(cidr)
                if mapped:
                    cidr_str, _ = mapped
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    ranges = self.v4_ranges
                else:
                    net = ipaddress.ip_network(cidr, strict=False)
                    ranges = self.v4_ranges if net.version == 4 else self.v6_ranges
                
                start = int(net.network_address)
                end = int(net.broadcast_address)
                
                low, high = 0, len(ranges) - 1
                while low <= high:
                    mid = (low + high) // 2
                    r_start, r_end = ranges[mid]
                    if r_end < start:
                        low = mid + 1
                    elif r_start > end:
                        high = mid - 1
                    else:
                        return r_start <= start and end <= r_end
                return False
            except ValueError:
                return False
    
    def collapse_to_cidrs(self) -> List[str]:
        """
        v4.4.1: 增強型 CIDR 轉換，防止輸出膨脹
        - 檢測大區間並使用激進聚合
        - 限制最大輸出 CIDR 數量
        """
        with self._lock:
            if not self._sorted:
                self.build()
            
            result = []
            
            # 處理 IPv4
            for start, end in self.v4_ranges:
                # v4.4.1: 大區間檢測與保護
                range_size = end - start + 1
                if range_size > MAX_IP_RANGE_AGGREGATION:
                    logger.warning(f"檢測到超大 IPv4 區間 ({start}-{end}, {range_size} 地址)，"
                                 f"使用激進聚合策略")
                    # 激進策略：強制使用 /8 /16 /24 邊界聚合，避免生成過多細粒度 CIDR
                    result.extend(self._aggressive_ipv4_summarize(start, end))
                else:
                    try:
                        start_addr = ipaddress.IPv4Address(start)
                        end_addr = ipaddress.IPv4Address(end)
                        cidrs = list(ipaddress.summarize_address_range(start_addr, end_addr))
                        result.extend(str(c) for c in cidrs)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"IPv4 區間轉換失敗: {e}")
                        continue
                
                # v4.4.1: 輸出膨脹保護
                if len(result) > MAX_CIDR_OUTPUT:
                    raise ValueError(f"CIDR 輸出數量 ({len(result)}) 超過安全閾值 "
                                   f"({MAX_CIDR_OUTPUT})，可能存在惡意輸入或極端聚合場景，"
                                   f"中止處理以防止 DoS")
            
            # 處理 IPv6
            for start, end in self.v6_ranges:
                range_size = end - start + 1
                if range_size > MAX_IP_RANGE_AGGREGATION * 2**96:  # IPv6 的相應閾值
                    logger.warning(f"檢測到超大 IPv6 區間，使用激進聚合")
                    # IPv6 激進聚合：使用 /32 /48 /64 邊界
                    result.extend(self._aggressive_ipv6_summarize(start, end))
                else:
                    try:
                        start_addr = ipaddress.IPv6Address(start)
                        end_addr = ipaddress.IPv6Address(end)
                        cidrs = list(ipaddress.summarize_address_range(start_addr, end_addr))
                        result.extend(str(c) for c in cidrs)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"IPv6 區間轉換失敗: {e}")
                        continue
                
                if len(result) > MAX_CIDR_OUTPUT:
                    raise ValueError(f"CIDR 輸出數量超過安全閾值，中止處理")
            
            return result
    
    def _aggressive_ipv4_summarize(self, start: int, end: int) -> List[str]:
        """v4.4.1: 激進 IPv4 聚合，使用標準 CIDR 邊界"""
        cidrs = []
        current = start
        while current <= end:
            # 找到最大的可能網絡
            max_size = (current & -current) if current != 0 else (1 << 32)
            
            # [v4.4.1 Fix] 確保不超出區間邊界
            remaining = end - current + 1
            if max_size > remaining:
                max_size = remaining
            
            # 確保 max_size 是 2 的冪次
            while max_size & (max_size - 1):
                max_size >>= 1
            
            # 轉換為前綴長度
            prefix_len = 32 - int(math.log2(max_size))
            cidrs.append(f"{ipaddress.IPv4Address(current)}/{prefix_len}")
            current += max_size
        
        return cidrs
    
    def _aggressive_ipv6_summarize(self, start: int, end: int) -> List[str]:
        """v4.4.1: 激進 IPv6 聚合"""
        cidrs = []
        current = start
        while current <= end:
            max_size = (current & -current) if current != 0 else (1 << 128)
            max_size = min(max_size, 2**64)  # 限制最大 /64
            
            # [v4.4.1 Fix] 確保不超出區間邊界
            remaining = end - current + 1
            if max_size > remaining:
                max_size = remaining
            
            while max_size > remaining:
                max_size >>= 1
            
            prefix_len = 128 - int(math.log2(max_size))
            cidrs.append(f"{ipaddress.IPv6Address(current)}/{prefix_len}")
            current += max_size
        
        return cidrs

class SourceSignature:
    """v4.4.1: 優化的源簽名類"""
    __slots__ = ('url', 'initial_weight', 'final_weight', 'rules_by_type', 
                 'exclusions_by_type', 'domain_trie', 'ip_index', 'source_ip_index',
                 'rule_count', 'depth', 'reliability', 'originality',
                 '_indices_built', '_hash', 'last_modified', 'keyword_set')
    
    def __init__(self, url: str, weight: float, content_hash: Optional[str] = None):
        self.url = url
        self.initial_weight = weight
        self.final_weight = weight
        self.rules_by_type = defaultdict(set)
        self.exclusions_by_type = defaultdict(set)
        self.domain_trie = DomainTrie(cache_limit=5000)
        self.ip_index = UnifiedIPRangeIndex()
        self.source_ip_index = UnifiedIPRangeIndex()
        self.keyword_set = set()
        self.rule_count = 0
        self.depth = 0
        self.reliability = 1.0
        self.originality = 1.0
        self._indices_built = False
        self._hash = content_hash
        self.last_modified = time.time()
    
    def compute_content_hash(self, content: bytes):
        """v4.4.1: 健壯的哈希計算"""
        if USE_BLAKE3 and blake3 is not None:
            try:
                self._hash = blake3(content).hexdigest()
                return
            except Exception:
                pass  # 失敗時回退到 SHA256
        
        self._hash = hashlib.sha256(content).hexdigest()[:32]
    
    def get_content_hash(self) -> str:
        if not self._hash:
            content = json.dumps({
                'url': self.url,
                'rules': {k: sorted(v) for k, v in self.rules_by_type.items()},
                'exclusions': {k: sorted(v) for k, v in self.exclusions_by_type.items()}
            }, sort_keys=True).encode()
            
            if USE_BLAKE3 and blake3 is not None:
                try:
                    self._hash = blake3(content).hexdigest()
                except Exception:
                    self._hash = hashlib.sha256(content).hexdigest()[:32]
            else:
                self._hash = hashlib.sha256(content).hexdigest()[:32]
        return self._hash
    
    def build_indices(self):
        """構建所有索引"""
        if self._indices_built:
            return
        
        for suffix in self.rules_by_type.get('domain_suffix', set()):
            self.domain_trie.insert(suffix)
        
        for wildcard in self.rules_by_type.get('domain_wildcard', set()):
            self.domain_trie.insert(wildcard)
        
        for cidr in self.rules_by_type.get('ip_cidr', set()):
            self.ip_index.add_cidr(cidr)
        self.ip_index.build()
        
        for cidr in self.rules_by_type.get('source_ip_cidr', set()):
            self.source_ip_index.add_cidr(cidr)
        self.source_ip_index.build()
        
        self.keyword_set = self.rules_by_type.get('domain_keyword', set())
        self.rule_count = sum(len(v) for v in self.rules_by_type.values())
        self._indices_built = True
    
    def add_rule(self, rtype: str, value: str, is_exclusion: bool = False):
        target = self.exclusions_by_type if is_exclusion else self.rules_by_type
        target[rtype].add(value)
        
        if not is_exclusion:
            if rtype == 'domain_suffix':
                self.domain_trie.insert(value)
            elif rtype == 'domain_wildcard':
                self.domain_trie.insert(value)
            elif rtype == 'ip_cidr':
                self.ip_index.add_cidr(value)
            elif rtype == 'source_ip_cidr':
                self.source_ip_index.add_cidr(value)
            elif rtype == 'domain_keyword':
                self.keyword_set.add(value)
    
    def to_serializable(self) -> Dict:
        return {
            'url': self.url,
            'initial_weight': self.initial_weight,
            'rules': {k: list(v) for k, v in self.rules_by_type.items()},
            'exclusions': {k: list(v) for k, v in self.exclusions_by_type.items()},
            'hash': self._hash,
            'depth': self.depth,
            'last_modified': self.last_modified
        }
    
    @classmethod
    def from_serializable(cls, data: Dict) -> 'SourceSignature':
        src = cls(data['url'], data['initial_weight'], data.get('hash'))
        src.depth = data.get('depth', 0)
        src.last_modified = data.get('last_modified', time.time())
        
        for rtype, rules in data.get('rules', {}).items():
            src.rules_by_type[rtype] = set(rules)
        for rtype, rules in data.get('exclusions', {}).items():
            src.exclusions_by_type[rtype] = set(rules)
        
        return src

# ==========================================
# 4. Z3 求解器與輕量模式（v4.4.1 雙模式）
# ==========================================

class CrossPlatformZ3Solver:
    _instance = None
    _executor = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_executor()
        return cls._instance
    
    def _init_executor(self):
        if USE_Z3:
            self._executor = concurrent.futures.ProcessPoolExecutor(max_workers=1)
            logger.info("Z3 Solver: 初始化進程池")
    
    @staticmethod
    def _solve_z3_subprocess(args):
        sources_data, min_score, entropy_filter = args
        
        try:
            from z3 import Solver, Bool, Or, And, Not, sat, Optimize
            
            sources = [SourceSignature.from_serializable(s) for s in sources_data]
            
            opt = Optimize()
            rule_vars = {}
            rule_weights = defaultdict(float)
            exclusion_set = set()
            
            for src in sources:
                if src.final_weight < 0.001:
                    continue
                
                for rtype, items in src.exclusions_by_type.items():
                    for item in items:
                        exclusion_set.add((rtype, item))
                
                for rtype, items in src.rules_by_type.items():
                    for item in items:
                        if rtype in ('domain', 'domain_suffix', 'domain_wildcard'):
                            if RE_HASH_LIKE.search(item):
                                continue
                        
                        key = (rtype, item)
                        if key not in rule_vars:
                            rule_vars[key] = Bool(f"rule_{rtype}_{hash(item)}")
                        
                        if key in exclusion_set:
                            rule_weights[key] -= src.final_weight * 2.0
                        else:
                            rule_weights[key] += src.final_weight
            
            for key in exclusion_set:
                if key in rule_vars:
                    opt.add(Not(rule_vars[key]))
            
            for key, var in rule_vars.items():
                if rule_weights[key] >= min_score:
                    opt.add_soft(var, int(rule_weights[key] * 1000))
            
            if opt.check() == sat:
                model = opt.model()
                result_rules = defaultdict(list)
                for (rtype, value), var in rule_vars.items():
                    if model[var]:
                        result_rules[rtype].append(value)
                return {'status': 'sat', 'rules': dict(result_rules)}
            return {'status': 'unsat'}
            
        except Exception as e:
            return {'status': 'error', 'msg': str(e)}
    
    def solve(self, sources: List[SourceSignature], min_score: float, 
              entropy_filter: Set[EntropyLevel], timeout: int = 5) -> Optional[Dict]:
        if not USE_Z3 or self._executor is None:
            return None
        
        total_rules = sum(src.rule_count for src in sources)
        if total_rules >= 5000:
            return None
        
        sources_data = [s.to_serializable() for s in sources]
        args = (sources_data, min_score, entropy_filter)
        
        try:
            future = self._executor.submit(self._solve_z3_subprocess, args)
            result = future.result(timeout=timeout)
            
            if result['status'] == 'sat':
                return result['rules']
            return None
        except concurrent.futures.TimeoutError:
            logger.warning("Z3 求解超時")
            future.cancel()
            return None
        except Exception as e:
            logger.error(f"Z3 進程執行錯誤: {e}")
            return None
    
    @classmethod
    def shutdown(cls):
        if cls._executor is not None:
            try:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                logger.info("Z3 Solver: 進程池已關閉")
            except Exception as e:
                logger.warning(f"Z3進程池關閉異常: {e}")
            finally:
                cls._executor = None

# ==========================================
# 5. 譜系分析器（v4.4.1 規模保護）
# ==========================================

class PersistentLineageAnalyzer:
    def __init__(self, state_file: Optional[Path] = None):
        self.state_file = state_file or Path('.lineage_state')
        self.storage = get_storage_backend(self.state_file)
        self.semantics = RuleSemantics()
        
        self.existing_sources: Dict[str, SourceSignature] = {}
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_graph: Dict[str, Set[str]] = defaultdict(set)
        self.in_degree: Counter = Counter()
        self._format_version = STATE_FORMAT_VERSION
        
        self._load_state()
    
    def _load_state(self):
        """v4.4.1: 增強的狀態遷移"""
        try:
            data = self.storage.load(b'lineage_state')
            if not data:
                return
            
            if USE_MSGPACK:
                state = msgpack.unpackb(data, raw=False)
            else:
                state = json.loads(data.decode('utf-8'))
            
            loaded_version = state.get('_format_version', 1)
            
            if loaded_version not in SUPPORTED_STATE_VERSIONS:
                logger.warning(f"存儲格式版本 {loaded_version} 不兼容，重置狀態")
                self._migrate_or_reset(loaded_version)
                return
            
            if loaded_version == 4:
                logger.info("檢測到v4存儲格式，執行向v5的遷移...")
                self._migrate_from_v4(state)
                return
            
            self.existing_sources = {
                k: SourceSignature.from_serializable(v) 
                for k, v in state.get('sources', {}).items()
            }
            self.graph = defaultdict(set, {k: set(v) for k, v in state.get('graph', {}).items()})
            self.reverse_graph = defaultdict(set, {k: set(v) for k, v in state.get('reverse_graph', {}).items()})
            self.in_degree = Counter(state.get('in_degree', {}))
            
            logger.info(f"已加載 {len(self.existing_sources)} 個歷史源（版本 {loaded_version}）")
            
        except Exception as e:
            logger.warning(f"加載狀態失敗: {e}，將創建新狀態")
    
    def _migrate_from_v4(self, state: Dict):
        """v4.4.1: 完善的v4到v5遷移"""
        try:
            self.existing_sources = {}
            for k, v in state.get('sources', {}).items():
                try:
                    # v4.4.1: 驗證所有必需字段存在
                    if 'initial_weight' not in v:
                        v['initial_weight'] = v.get('weight', 1.0)
                    if 'last_modified' not in v:
                        v['last_modified'] = time.time()
                    
                    self.existing_sources[k] = SourceSignature.from_serializable(v)
                except Exception as e:
                    logger.warning(f"遷移源 {k} 失敗: {e}，跳過")
            
            self.graph = defaultdict(set, {k: set(v) for k, v in state.get('graph', {}).items()})
            self.reverse_graph = defaultdict(set, {k: set(v) for k, v in state.get('reverse_graph', {}).items()})
            self.in_degree = Counter(state.get('in_degree', {}))
            
            logger.info(f"v4遷移完成：成功遷移 {len(self.existing_sources)} 個源")
            self.save_state()
            
        except Exception as e:
            logger.error(f"v4遷移失敗: {e}،重置狀態")
            self._migrate_or_reset(4)
    
    def _migrate_or_reset(self, from_version: int):
        logger.info(f"執行狀態重置（從版本 {from_version}）")
        self.existing_sources = {}
        self.graph = defaultdict(set)
        self.reverse_graph = defaultdict(set)
        self.in_degree = Counter()
    
    def save_state(self):
        try:
            state = {
                '_format_version': STATE_FORMAT_VERSION,
                'sources': {k: v.to_serializable() for k, v in self.existing_sources.items()},
                'graph': {k: list(v) for k, v in self.graph.items()},
                'reverse_graph': {k: list(v) for k, v in self.reverse_graph.items()},
                'in_degree': dict(self.in_degree),
                'timestamp': time.time(),
                'python_version': sys.version_info[:2]
            }
            
            data = msgpack.packb(state, use_bin_type=True) if USE_MSGPACK else json.dumps(state).encode('utf-8')
            self.storage.save(b'lineage_state', data)
            
        except Exception as e:
            logger.warning(f"保存狀態失敗: {e}")
    
    def close(self):
        self.save_state()
        self.storage.close()
        CrossPlatformZ3Solver.shutdown()
    
    def compute_incremental(self, new_sources: List[SourceSignature], hop: int = 1) -> Tuple[Set[int], List[SourceSignature]]:
        """
        v4.4.1: 增強型增量計算，添加規模保護
        """
        # v4.4.1: 大規模輸入警告與保護
        if len(new_sources) > 1000:
            logger.warning(f"輸入源數量 ({len(new_sources)}) 超過建議閾值 (1000)，"
                          f"譜系分析可能較慢。考慮分批處理或優化輸入。")
        
        if not INCREMENTAL_MODE:
            return self._compute_full(new_sources)
        
        changed_hashes = set()
        unchanged_hashes = set()
        
        for src in new_sources:
            src_hash = src.get_content_hash()
            if src_hash not in self.existing_sources:
                changed_hashes.add(src_hash)
            else:
                unchanged_hashes.add(src_hash)
        
        if not changed_hashes:
            for src in new_sources:
                h = src.get_content_hash()
                if h in self.existing_sources:
                    src.depth = self.existing_sources[h].depth
                    src.originality = math.pow(0.7, src.depth)
            return set(i for i, src in enumerate(new_sources) if src.depth > 0), new_sources
        
        affected_hashes = self._compute_affected_subgraph(changed_hashes, hop)
        unaffected_hashes = unchanged_hashes - affected_hashes
        
        logger.info(f"增量更新：{len(changed_hashes)} 變更，{len(affected_hashes)} 受影響،{len(unaffected_hashes)} 未變更")
        
        hash_to_src = {src.get_content_hash(): src for src in new_sources}
        for h in unaffected_hashes:
            if h in self.existing_sources and h in hash_to_src:
                hash_to_src[h].depth = self.existing_sources[h].depth
                hash_to_src[h].originality = math.pow(0.7, hash_to_src[h].depth)
        
        if affected_hashes:
            affected_sources = [hash_to_src[h] for h in affected_hashes if h in hash_to_src]
            self._compute_partial_subset(affected_sources, hash_to_src, new_sources)
        
        for src in new_sources:
            self.existing_sources[src.get_content_hash()] = src
        
        self.save_state()
        
        redundant = set(i for i, src in enumerate(new_sources) if src.depth > 0)
        return redundant, new_sources
    
    def _compute_affected_subgraph(self, changed_hashes: Set[str], hop: int) -> Set[str]:
        affected = set(changed_hashes)
        current_layer = changed_hashes
        
        for _ in range(hop):
            next_layer = set()
            for h in current_layer:
                next_layer.update(self.graph.get(h, set()))
                next_layer.update(self.reverse_graph.get(h, set()))
            affected.update(next_layer)
            current_layer = next_layer
        
        return affected
    
    def _compute_partial_subset(self, affected_sources: List[SourceSignature], 
                               hash_to_src: Dict[str, SourceSignature],
                               all_sources: List[SourceSignature]):
        affected_hashes = {s.get_content_hash() for s in affected_sources}
        for h in affected_hashes:
            if h in self.graph:
                del self.graph[h]
            if h in self.reverse_graph:
                del self.reverse_graph[h]
            for parent in list(self.graph.keys()):
                if h in self.graph[parent]:
                    self.graph[parent].remove(h)
                    self.reverse_graph[h].discard(parent)
        
        for i, src_i in enumerate(affected_sources):
            h_i = src_i.get_content_hash()
            
            for src_j in all_sources:
                if src_i is src_j:
                    continue
                h_j = src_j.get_content_hash()
                
                if self._is_subset_complete(src_i, src_j):
                    self.graph[h_j].add(h_i)
                    self.reverse_graph[h_i].add(h_j)
                    self.in_degree[h_i] += 1
                elif h_j in affected_hashes and self._is_subset_complete(src_j, src_i):
                    self.graph[h_i].add(h_j)
                    self.reverse_graph[h_j].add(h_i)
                    self.in_degree[h_j] += 1
        
        self._compute_depths_for_subset(affected_hashes, all_sources)
    
    def _compute_depths_for_subset(self, affected_hashes: Set[str], all_sources: List[SourceSignature]):
        local_in_degree = Counter()
        for h in affected_hashes:
            local_in_degree[h] = self.in_degree[h]
            for parent in self.reverse_graph.get(h, set()):
                if parent not in affected_hashes:
                    local_in_degree[h] += 1
        
        queue = deque([h for h in affected_hashes if local_in_degree[h] == 0])
        depths = {h: 0 for h in affected_hashes}
        
        while queue:
            u = queue.popleft()
            for v in self.graph.get(u, set()):
                if v in affected_hashes:
                    depths[v] = max(depths[v], depths[u] + 1)
                    local_in_degree[v] -= 1
                    if local_in_degree[v] == 0:
                        queue.append(v)
        
        for src in all_sources:
            h = src.get_content_hash()
            if h in depths:
                src.depth = depths[h]
                src.originality = math.pow(0.7, depths[h])
    
    def _compute_full(self, sources: List[SourceSignature]) -> Tuple[Set[int], List[SourceSignature]]:
        self.existing_sources = {}
        self.graph = defaultdict(set)
        self.reverse_graph = defaultdict(set)
        self.in_degree = Counter()
        
        n = len(sources)
        for i in range(n):
            for j in range(i + 1, n):
                if self._is_subset_complete(sources[i], sources[j]):
                    h_i = sources[i].get_content_hash()
                    h_j = sources[j].get_content_hash()
                    self.graph[h_j].add(h_i)
                    self.reverse_graph[h_i].add(h_j)
                    self.in_degree[h_i] += 1
                if self._is_subset_complete(sources[j], sources[i]):
                    h_i = sources[i].get_content_hash()
                    h_j = sources[j].get_content_hash()
                    self.graph[h_i].add(h_j)
                    self.reverse_graph[h_j].add(h_i)
                    self.in_degree[h_j] += 1
        
        for src in sources:
            self.existing_sources[src.get_content_hash()] = src
        
        redundant = set()
        self._compute_depths_topological(sources, redundant)
        self.save_state()
        
        return redundant, sources
    
    def _is_subset_complete(self, child: SourceSignature, parent: SourceSignature) -> bool:
        if child is parent:
            return True
        if child.rule_count > parent.rule_count:
            return False
        
        child.build_indices()
        parent.build_indices()
        
        if not child.keyword_set.issubset(parent.keyword_set):
            for kw in child.keyword_set:
                if not any(pk in kw for pk in parent.keyword_set):
                    return False
        
        for domain in child.rules_by_type.get('domain', set()):
            if not parent.domain_trie.is_covered(domain):
                return False
        
        for suffix in child.rules_by_type.get('domain_suffix', set()):
            if not parent.domain_trie.is_covered(suffix):
                return False
        
        for wildcard in child.rules_by_type.get('domain_wildcard', set()):
            if not parent.domain_trie.is_covered(wildcard):
                return False
        
        for cidr in child.rules_by_type.get('ip_cidr', set()):
            if not parent.ip_index.contains_cidr(cidr):
                return False
        
        for cidr in child.rules_by_type.get('source_ip_cidr', set()):
            if not parent.source_ip_index.contains_cidr(cidr):
                return False
        
        return True
    
    def _compute_depths_topological(self, sources: List[SourceSignature], redundant: Optional[Set[int]] = None):
        in_deg = Counter(self.in_degree)
        queue = deque([src.get_content_hash() for src in sources if in_deg[src.get_content_hash()] == 0])
        depths = {src.get_content_hash(): 0 for src in sources}
        
        while queue:
            u = queue.popleft()
            for v in self.graph.get(u, set()):
                depths[v] = max(depths[v], depths[u] + 1)
                in_deg[v] -= 1
                if in_deg[v] == 0:
                    queue.append(v)
        
        for i, src in enumerate(sources):
            h = src.get_content_hash()
            src.depth = depths[h]
            src.originality = math.pow(0.7, depths[h])
            if redundant is not None and depths[h] > 0:
                redundant.add(i)

# ==========================================
# 6. 衝突解決器（v4.4.1 輕量模式修復）
# ==========================================

class StrictConflictResolver:
    def __init__(self):
        self.z3_solver = CrossPlatformZ3Solver()
    
    def resolve(self, sources: List[SourceSignature], min_score: float,
                entropy_filter: Optional[Set[EntropyLevel]] = None) -> Dict[str, List[str]]:
        if entropy_filter is None:
            entropy_filter = {EntropyLevel.SAFE, EntropyLevel.SUSPICIOUS}
        
        total_rules = sum(src.rule_count for src in sources)
        
        # v4.4.1: 輕量模式自動切換
        if total_rules < LITE_MODE_THRESHOLD and not USE_Z3:
            logger.info(f"規則數 ({total_rules}) 低於閾值且 Z3 不可用،"
                       f"啟用輕量模式（簡化衝突解決）")
            return self._resolve_lite(sources, min_score, entropy_filter)
        
        # 標準模式：嘗試 Z3
        if total_rules < 5000:
            z3_result = self.z3_solver.solve(sources, min_score, entropy_filter)
            if z3_result is not None:
                return self._post_process(z3_result)
        
        # 回退到啟發式
        return self._resolve_heuristic(sources, min_score, entropy_filter)
    
    def _resolve_lite(self, sources: List[SourceSignature], min_score: float,
                     entropy_filter: Set[EntropyLevel]) -> Dict[str, List[str]]:
        """
        v4.4.1 Fix: 修復 source_ip_cidr 排除檢查遺漏
        輕量模式 - 類似 Code B 的簡化加權統計،無進程開銷
        適用於小規則集或無 Z3 環境
        """
        scores = defaultdict(float)
        exclusion_trie = DomainTrie()
        exclusion_ip_index = UnifiedIPRangeIndex()
        exclusion_source_ip_index = UnifiedIPRangeIndex()  # [v4.4.1 Fix] 新增：源IP排除索引
        
        # 收集排除規則
        for src in sources:
            if src.final_weight < 0.001:
                continue
            for rtype, items in src.exclusions_by_type.items():
                for item in items:
                    if rtype in ('domain_suffix', 'domain_wildcard'):
                        exclusion_trie.insert(item)
                    elif rtype == 'ip_cidr':
                        exclusion_ip_index.add_cidr(item)
                    elif rtype == 'source_ip_cidr':  # [v4.4.1 Fix] 新增：收集源IP排除規則
                        exclusion_source_ip_index.add_cidr(item)
        
        exclusion_ip_index.build()
        exclusion_source_ip_index.build()  # [v4.4.1 Fix] 新增：構建源IP排除索引
        
        # 簡化計分（無熵過濾，僅權重累加）
        for src in sources:
            if src.final_weight < 0.001:
                continue
            for rtype, items in src.rules_by_type.items():
                for item in items:
                    if rtype in ('domain', 'domain_suffix', 'domain_wildcard'):
                        if RE_HASH_LIKE.search(item):
                            continue
                    
                    is_excluded = False
                    if rtype in ('domain', 'domain_wildcard', 'domain_suffix'):
                        if exclusion_trie.is_covered(item):
                            is_excluded = True
                    elif rtype == 'ip_cidr':
                        if exclusion_ip_index.contains_cidr(item):
                            is_excluded = True
                    elif rtype == 'source_ip_cidr':  # [v4.4.1 Fix] 新增：源IP排除檢查
                        if exclusion_source_ip_index.contains_cidr(item):
                            is_excluded = True
                    
                    if not is_excluded:
                        scores[(rtype, item)] += src.final_weight
        
        filtered = {k: v for k, v in scores.items() if v >= min_score}
        groups = defaultdict(list)
        for (rtype, item), weight in filtered.items():
            groups[rtype].append(item)
        
        return self._post_process(dict(groups))
    
    def _resolve_heuristic(self, sources: List[SourceSignature], min_score: float,
                          entropy_filter: Set[EntropyLevel]) -> Dict[str, List[str]]:
        scores = defaultdict(float)
        exclusion_trie = DomainTrie()
        exclusion_ip_index = UnifiedIPRangeIndex()
        exclusion_source_ip_index = UnifiedIPRangeIndex()
        
        for src in sources:
            if src.final_weight < 0.001:
                continue
            for rtype, items in src.exclusions_by_type.items():
                for item in items:
                    if rtype in ('domain_suffix', 'domain_wildcard'):
                        exclusion_trie.insert(item)
                    elif rtype == 'ip_cidr':
                        exclusion_ip_index.add_cidr(item)
                    elif rtype == 'source_ip_cidr':
                        exclusion_source_ip_index.add_cidr(item)
        
        exclusion_ip_index.build()
        exclusion_source_ip_index.build()
        
        for src in sources:
            if src.final_weight < 0.001:
                continue
            
            for rtype, items in src.rules_by_type.items():
                for item in items:
                    if rtype in ('domain', 'domain_suffix', 'domain_wildcard'):
                        if RE_HASH_LIKE.search(item):
                            continue
                    
                    is_excluded = False
                    if rtype in ('domain', 'domain_wildcard', 'domain_suffix'):
                        if exclusion_trie.is_covered(item):
                            is_excluded = True
                    elif rtype == 'ip_cidr':
                        if exclusion_ip_index.contains_cidr(item):
                            is_excluded = True
                    elif rtype == 'source_ip_cidr':
                        if exclusion_source_ip_index.contains_cidr(item):
                            is_excluded = True
                    
                    if not is_excluded:
                        scores[(rtype, item)] += src.final_weight
        
        filtered = {k: v for k, v in scores.items() if v >= min_score}
        groups = defaultdict(list)
        for (rtype, item), weight in filtered.items():
            groups[rtype].append(item)
        
        return self._post_process(dict(groups))
    
    def _post_process(self, rules: Dict[str, List[str]]) -> Dict[str, List[str]]:
        result = {}
        
        for rtype in ['domain_suffix', 'domain']:
            if rtype in rules:
                trie = DomainTrie()
                for item in rules[rtype]:
                    trie.insert(item)
                result[rtype] = sorted(trie.optimize())
        
        if 'domain_wildcard' in rules:
            result['domain_wildcard'] = sorted(set(rules['domain_wildcard']))
        
        # v4.4.1: 使用增強的 UnifiedIPRangeIndex（含膨脹保護）
        for rtype in ['ip_cidr', 'source_ip_cidr']:
            if rtype in rules:
                idx = UnifiedIPRangeIndex()
                for cidr in rules[rtype]:
                    idx.add_cidr(cidr)
                idx.build()
                try:
                    result[rtype] = idx.collapse_to_cidrs()
                except ValueError as e:
                    logger.error(f"CIDR 聚合失敗: {e}،使用未聚合輸出")
                    result[rtype] = sorted(set(rules[rtype]))  # 回退到簡單去重
        
        for rtype in rules:
            if rtype not in result:
                result[rtype] = sorted(set(rules[rtype]))
        
        return result

# ==========================================
# 7. 輔助類與 I/O（v4.4.1 完善）
# ==========================================

class EntropyAssessor:
    @staticmethod
    def assess_entropy_level(domain: str) -> Tuple[EntropyLevel, Dict[str, float]]:
        if RE_HASH_LIKE.search(domain):
            return EntropyLevel.DGA_CONFIRMED, {'hash_pattern': 1.0}
        
        parts = domain.split('.')
        max_entropy = 0
        max_digit_ratio = 0
        min_vowel_ratio = 1.0
        
        for part in parts:
            if len(part) < 5:
                continue
            freq = Counter(part)
            length = len(part)
            entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
            max_entropy = max(max_entropy, entropy / math.log2(len(set(part))) if len(set(part)) > 1 else 0)
            digit_ratio = sum(c.isdigit() for c in part) / length
            max_digit_ratio = max(max_digit_ratio, digit_ratio)
            vowels = set('aeiou')
            vowel_count = sum(1 for c in part if c in vowels)
            vowel_ratio = vowel_count / length
            min_vowel_ratio = min(min_vowel_ratio, vowel_ratio)
        
        details = {
            'normalized_entropy': max_entropy,
            'max_digit_ratio': max_digit_ratio,
            'min_vowel_ratio': min_vowel_ratio
        }
        
        if max_entropy > 0.95 and max_digit_ratio > 0.3 and min_vowel_ratio < 0.1:
            return EntropyLevel.DGA_CONFIRMED, details
        elif max_entropy > 0.9 and max_digit_ratio > 0.2 and min_vowel_ratio < 0.15:
            return EntropyLevel.DGA_LIKELY, details
        elif max_entropy > 0.85 and (max_digit_ratio > 0.15 or min_vowel_ratio < 0.2):
            return EntropyLevel.SUSPICIOUS, details
        else:
            return EntropyLevel.SAFE, details

class RuleSemantics:
    @staticmethod
    def is_contained_by(child_type: str, child_val: str, parent_type: str, parent_val: str) -> bool:
        WildcardSemanticsConfig.validate_poset_axioms()
        
        if child_type == parent_type:
            if child_type in ('domain', 'process_name', 'geoip', 'port', 'source_port'):
                return child_val == parent_val
            elif child_type == 'domain_keyword':
                return parent_val in child_val
            elif child_type == 'domain_suffix':
                return child_val.endswith('.' + parent_val) or child_val == parent_val
            elif child_type == 'domain_wildcard':
                if WildcardSemanticsConfig.WILDCARD_CONTAINS_SUBWILDCARD:
                    return child_val.endswith('.' + parent_val) or child_val == parent_val
                return child_val == parent_val
            elif child_type in ('ip_cidr', 'source_ip_cidr'):
                try:
                    net1 = ipaddress.ip_network(child_val, strict=False)
                    net2 = ipaddress.ip_network(parent_val, strict=False)
                    return net2.supernet_of(net1) or net1 == net2
                except ValueError:
                    return False
        
        if child_type == 'domain' and parent_type == 'domain_suffix':
            return child_val.endswith('.' + parent_val) or child_val == parent_val
        elif child_type == 'domain_wildcard' and parent_type == 'domain_suffix':
            return child_val.endswith('.' + parent_val)
        elif child_type == 'domain' and parent_type == 'domain_wildcard':
            if WildcardSemanticsConfig.ROOT_CONTAINS_WILDCARD:
                return child_val == parent_val or child_val.endswith('.' + parent_val)
            return False
        elif child_type == 'domain_wildcard' and parent_type == 'domain':
            if WildcardSemanticsConfig.WILDCARD_CONTAINS_ROOT:
                return child_val == parent_val
            return False
        
        return False

@lru_cache(maxsize=100000)
def normalize_domain(content: str) -> Tuple[Optional[str], bool]:
    original = content.strip()
    content = original.lower().strip('.')
    
    if not content or len(content) > 253:
        return (None, False)
    
    is_exclusion = False
    if RE_EXCLUSION_PREFIX.match(content):
        is_exclusion = True
        content = content.lstrip('!').strip()
        if not content:
            return (None, is_exclusion)
    
    try:
        if any(ord(c) > 127 for c in content):
            encoded = content.encode('idna').decode('ascii')
        else:
            encoded = content
    except UnicodeError:
        return (None, is_exclusion)
    
    if ' ' in encoded or '_' in encoded:
        return (None, is_exclusion)
    
    parts = encoded.split('.')
    for part in parts:
        if not part or len(part) > 63 or part.startswith('-') or part.endswith('-'):
            return (None, is_exclusion)
        if not RE_DOMAIN_LABEL.match(part):
            return (None, is_exclusion)
    
    return (encoded, is_exclusion)

def load_source_to_memory(file_path: Path, src: SourceSignature):
    """v4.4.1: 完善的解析邏輯"""
    try:
        content_bytes = file_path.read_bytes()
        src.compute_content_hash(content_bytes)
        
        if content_bytes.startswith(b'\xef\xbb\xbf'):
            text_content = content_bytes.decode('utf-8-sig')
        else:
            text_content = content_bytes.decode('utf-8', errors='ignore')
        
        # JSON 解析
        try:
            data = json.loads(text_content)
            if isinstance(data, dict):
                rules_data = data.get("rules", [])
                if isinstance(rules_data, dict):
                    rules_data = [rules_data]
            else:
                rules_data = data if isinstance(data, list) else []
            
            for rule in rules_data:
                if not isinstance(rule, dict):
                    continue
                is_exclusion = rule.get('invert', False)
                
                for key, val in rule.items():
                    if key == 'invert':
                        continue
                    
                    mapped = RULE_MAP.get(key.upper())
                    if not mapped:
                        if key in RULE_MAP.values():
                            mapped = key
                        else:
                            continue
                    
                    values = val if isinstance(val, list) else [val]
                    for v in values:
                        v_str = str(v)
                        
                        if mapped in ('domain', 'domain_suffix', 'domain_keyword'):
                            if v_str.startswith('*.'):
                                norm, _ = normalize_domain(v_str[2:])
                                if norm:
                                    src.add_rule('domain_wildcard', norm, is_exclusion)
                            else:
                                norm, _ = normalize_domain(v_str)
                                if norm:
                                    src.add_rule(mapped, norm, is_exclusion)
                        elif mapped == 'domain_wildcard':
                            norm, _ = normalize_domain(v_str.lstrip('*.'))
                            if norm:
                                src.add_rule('domain_wildcard', norm, is_exclusion)
                        elif mapped in ('ip_cidr', 'source_ip_cidr'):
                            try:
                                net = ipaddress.ip_network(v_str, strict=False)
                                src.add_rule(mapped, str(net), is_exclusion)
                            except ValueError:
                                continue
                        else:
                            src.add_rule(mapped, v_str.strip(), is_exclusion)
            return
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        
        # 純文本解析（SRS 格式）
        for line in text_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            is_exclusion = line.startswith('!')
            if is_exclusion:
                line = line[1:].strip()
            
            if line.startswith('DOMAIN,'):
                parts = line.split(',', 2)
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    norm, _ = normalize_domain(domain)
                    if norm:
                        src.add_rule('domain', norm, is_exclusion)
            elif line.startswith('DOMAIN-SUFFIX,'):
                parts = line.split(',', 2)
                if len(parts) >= 2:
                    suffix = parts[1].strip()
                    norm, _ = normalize_domain(suffix)
                    if norm:
                        src.add_rule('domain_suffix', norm, is_exclusion)
            elif line.startswith('IP-CIDR,') or line.startswith('IP-CIDR6,'):
                parts = line.split(',', 2)
                if len(parts) >= 2:
                    cidr = parts[1].strip()
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        src.add_rule('ip_cidr', str(net), is_exclusion)
                    except ValueError:
                        continue
                
    except Exception as e:
        logger.debug(f"Parse error {file_path}: {e}")

def create_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=MAX_WORKERS+1, pool_maxsize=MAX_WORKERS*2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session

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
        
        if filename.exists():
            filename.unlink()
        shutil.move(str(temp), str(filename))
        return True
    except Exception:
        if temp.exists():
            temp.unlink(missing_ok=True)
        return False

def srs_to_json(srs_path: Path, json_path: Path) -> bool:
    try:
        subprocess.run(
            [str(Path(CORE_BIN_PATH).absolute()), "rule-set", "decompile",
             "--output", str(json_path), str(srs_path)],
            check=True, capture_output=True, timeout=120
        )
        return True
    except Exception:
        return False

def worker(task: Dict, lineage_analyzer: Optional[PersistentLineageAnalyzer] = None) -> TaskResult:
    name = task['name']
    min_score = float(task.get('min_score', 1.0))
    mode = task.get('mode', 'strict')
    output_format = task.get('format', 'singbox')
    
    allowed_entropy = {EntropyLevel.SAFE, EntropyLevel.SUSPICIOUS}
    if mode == 'trust':
        allowed_entropy.add(EntropyLevel.DGA_LIKELY)
    
    out_json = DIR_OUTPUT / "merged-json" / f"{name}.json"
    out_srs = DIR_OUTPUT / "merged-srs" / f"{name}.srs"
    
    with tempfile.TemporaryDirectory(prefix=f"temp_{name}_") as tmpdir:
        tmppath = Path(tmpdir)
        session = create_session()
        sources: List[SourceSignature] = []
        
        try:
            configs = task.get('sources', [])
            failed_sources = []
            
            for i, conf in enumerate(configs):
                url = conf if isinstance(conf, str) else conf.get('url')
                weight = 1.0 if isinstance(conf, str) else float(conf.get('weight', 1.0))
                if not url:
                    continue
                
                raw_file = tmppath / f"src_{i}.raw"
                if not download_file(session, url, raw_file):
                    failed_sources.append(url)
                    continue
                
                target_file = raw_file
                if url.endswith('.srs'):
                    json_file = tmppath / f"src_{i}.json"
                    if srs_to_json(raw_file, json_file):
                        target_file = json_file
                    else:
                        failed_sources.append(url)
                        continue
                
                src = SourceSignature(url, weight)
                load_source_to_memory(target_file, src)
                
                if src.rules_by_type or src.exclusions_by_type:
                    sources.append(src)
                
                try:
                    target_file.unlink(missing_ok=True)
                    if target_file != raw_file:
                        raw_file.unlink(missing_ok=True)
                except OSError:
                    pass
            
            if not sources:
                return TaskResult(name, "⚠️", "No valid sources", "0KB")
            
            if lineage_analyzer is None:
                lineage_analyzer = PersistentLineageAnalyzer()
            
            # v4.4.1: 處理失敗源（簡化處理，記錄即可）
            if failed_sources:
                logger.warning(f"Task {name}: {len(failed_sources)} sources failed to download")
            
            redundant, active_sources = lineage_analyzer.compute_incremental(sources, hop=1)
            
            active_sources = [s for s in sources if s.depth == 0]
            if not active_sources:
                active_sources = sources
            
            for src in active_sources:
                src.final_weight = src.initial_weight * src.originality
            
            resolver = StrictConflictResolver()
            merged = resolver.resolve(active_sources, min_score, allowed_entropy)
            
            final_data = {
                "version": TARGET_FORMAT_VERSION,
                "rules": [{k: v} for k, v in merged.items() if v]
            }
            
            with open(out_json, 'wb') as f:
                if USE_ORJSON:
                    f.write(orjson.dumps(final_data, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS))
                else:
                    f.write(json.dumps(final_data, indent=2, ensure_ascii=False, sort_keys=True).encode('utf-8'))
            
            res = subprocess.run(
                [str(Path(CORE_BIN_PATH).absolute()), "rule-set", "compile",
                 "--output", str(out_srs), str(out_json)],
                capture_output=True, text=True, timeout=180
            )
            
            total_count = sum(len(v) for v in merged.values())
            stats_msg = f"Merged {total_count} (v4.4.1)"
            
            if res.returncode != 0:
                return TaskResult(name, "❌", f"Compile: {res.stderr[:100]}", "0KB")
            
            size = f"{out_srs.stat().st_size / 1024:.1f}KB" if out_srs.exists() else "0KB"
            return TaskResult(name, "✅", stats_msg, size)
            
        except Exception as e:
            logger.exception(f"Worker Error {name}")
            return TaskResult(name, "❌", str(e)[:100], "0KB")
        finally:
            session.close()
            gc.collect()

def main():
    try:
        WildcardSemanticsConfig.validate_poset_axioms()
    except ValueError as e:
        logger.error(f"配置錯誤: {e}")
        sys.exit(1)
    
    dirs = [DIR_OUTPUT, DIR_OUTPUT / "merged-json", DIR_OUTPUT / "merged-srs"]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    core_path = Path(CORE_BIN_PATH).absolute()
    if core_path.exists():
        try:
            os.chmod(core_path, core_path.stat().st_mode | stat.S_IEXEC)
        except OSError:
            pass
    
    tasks = []
    cfg_path = Path(CONFIG_FILE)
    if cfg_path.exists():
        try:
            with open(cfg_path, 'rb') as f:
                if USE_ORJSON:
                    cfg = orjson.loads(f.read())
                else:
                    cfg = json.load(f)
                tasks = cfg.get("merge_tasks", [])
        except Exception as e:
            logger.error(f"Config Error: {e}")
            sys.exit(1)
    
    if not tasks:
        return
    
    global_analyzer = PersistentLineageAnalyzer()
    
    try:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
            futures = {exe.submit(worker, t, global_analyzer): t for t in tasks}
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())
        
        summary = os.getenv('GITHUB_STEP_SUMMARY')
        if summary:
            try:
                with open(summary, 'a', encoding='utf-8') as f:
                    f.write("## 🏭 Custom Merge Report (HyperAccurate v4.4.1)\n")
                    f.write("| Task | Status | Details | Size |\n|---|---|---|---|\n")
                    for r in sorted(results, key=lambda x: x.name):
                        f.write(f"| {r.name} | {r.status} | {r.msg} | {r.size} |\n")
            except OSError:
                pass
        
        for r in results:
            logger.info(f"[{r.name}] {r.status} {r.msg} ({r.size})")
        
        if any(r.status == "❌" for r in results):
            sys.exit(1)
    finally:
        global_analyzer.close()
        CrossPlatformZ3Solver.shutdown()

if __name__ == "__main__":
    main()
