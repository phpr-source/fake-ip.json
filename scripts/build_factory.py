import json
import os
import subprocess
import sys
import concurrent.futures
import time
import re
import shutil

# --- 配置区域 ---
CONFIG_FILE = 'rules.json'
MAX_WORKERS = 5
GITHUB_STEP_SUMMARY = os.getenv('GITHUB_STEP_SUMMARY')

# 输出目录管理
DIR_SRS = "."         # SRS 存放位置 (根目录)
DIR_JSON = "rules_json" # 调试用 JSON 存放位置

# 严格映射表 (Clash/Surge -> Sing-box)
RULE_MAP = {
    'DOMAIN-SUFFIX': 'domain_suffix',
    'HOST-SUFFIX': 'domain_suffix',
    'DOMAIN': 'domain',
    'HOST': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'HOST-KEYWORD': 'domain_keyword',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port',
    'PROCESS-NAME': 'process_name'
}

class TaskResult:
    def __init__(self, name, status, msg, size="0KB"):
        self.name = name
        self.status = status
        self.msg = msg
        self.size = size

def setup_directories():
    """初始化目录"""
    if not os.path.exists(DIR_JSON):
        os.makedirs(DIR_JSON)

def get_core_version():
    core_path = "./sing-box"
    if not os.path.exists(core_path): return "❌ 核心缺失"
    try:
        result = subprocess.run([core_path, "version"], capture_output=True, text=True, check=True)
        return result.stdout.split('\n')[0].split('version ')[-1].strip()
    except: return "❓ 未知版本"

def get_file_size(filepath):
    if not os.path.exists(filepath): return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024: return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def download_file(url, filename):
    # 模拟真实浏览器 UA，防止反爬
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    cmd = ["curl", "-L", "--fail", "--retry", "3", "-A", ua, url, "-o", filename]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

# --- 补回的功能：全局 JSON 深度优化与去重 ---
def optimize_json_file(filepath):
    """
    读取 JSON 文件，对所有规则列表进行去重和排序，并重写文件。
    返回: (是否修改过, 移除的条数)
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        rules = data.get('rules', [])
        total_removed = 0
        modified = False

        for rule in rules:
            for key, val in rule.items():
                if isinstance(val, list):
                    # 使用 set 去重，然后 sorted 排序保证稳定性
                    new_val = sorted(list(set(val)))
                    removed_count = len(val) - len(new_val)
                    
                    if removed_count > 0:
                        rule[key] = new_val
                        total_removed += removed_count
                        modified = True
        
        if modified:
            # 重新写入优化后的 JSON
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True, total_removed
        return False, 0
    except Exception as e:
        print(f"⚠️ 优化 JSON 失败: {e}")
        return False, 0

# --- 核心组件 1: 智能转换器 ---
def convert_clash_to_json(input_file, output_json):
    """正则提取规则 -> 转换为 Sing-box JSON"""
    rules_dict = {v: set() for v in set(RULE_MAP.values())}
    count = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'): continue
            
            # 移除行尾注释
            line = re.split(r'\s*(#|//)', line)[0].strip()

            # 正则匹配: 类型, 值
            match = re.search(r'^([A-Z0-9-]+)\s*,\s*([^,]+)', line, re.IGNORECASE)
            
            if match:
                raw_type = match.group(1).upper()
                value = match.group(2).strip().strip("'\"")
                
                if raw_type in RULE_MAP:
                    sb_type = RULE_MAP[raw_type]
                    rules_dict[sb_type].add(value)
                    count += 1

        if count == 0:
            return False, "无有效规则"

        # 构造 JSON
        final_rules = []
        for k, v in rules_dict.items():
            if v:
                final_rules.append({k: sorted(list(v))})
        
        output_data = {"version": 3, "rules": final_rules}
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        return True, f"转换{count}条"

    except Exception as e:
        return False, f"异常: {str(e)}"

# --- 核心组件 2: 验证与编译流水线 ---
def decompile_srs(input_srs, output_json):
    """反编译 SRS -> JSON"""
    cmd = ["./sing-box", "rule-set", "decompile", input_srs, "-o", output_json]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        if os.path.getsize(output_json) < 10: return False
        return True
    except subprocess.CalledProcessError:
        return False

def compile_json(input_json, output_srs):
    """编译 JSON -> SRS (使用自定义核心)"""
    cmd = ["./sing-box", "rule-set", "compile", input_json, "-o", output_srs]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def process_single_task(name, url):
    print(f"🔄 [{name}] 启动处理...")
    
    temp_download = f"temp_raw_{name}"
    final_json = os.path.join(DIR_JSON, f"{name}.json")
    final_srs = os.path.join(DIR_SRS, f"{name}.srs")
    
    # 1. 下载
    if not download_file(url, temp_download):
        return TaskResult(name, "❌", "下载失败")
    
    url_lower = url.lower()
    process_info = "未知"
    json_ready = False
    
    # 2. 生成标准 JSON (中间态)
    try:
        if url_lower.endswith('.srs'):
            print(f"🛡️ [{name}] 正在验证 SRS 完整性...")
            if decompile_srs(temp_download, final_json):
                process_info = "SRS重构"
                json_ready = True
            else:
                return TaskResult(name, "❌", "SRS反编译失败")
                
        elif url_lower.endswith('.json'):
            shutil.move(temp_download, final_json)
            process_info = "JSON原生"
            json_ready = True
            
        elif url_lower.endswith('.mrs'):
            return TaskResult(name, "❌", "不支持MRS格式")
            
        else:
            print(f"🔧 [{name}] 正在转换规则格式...")
            success, msg = convert_clash_to_json(temp_download, final_json)
            if success:
                process_info = "格式转换"
                json_ready = True
            else:
                return TaskResult(name, "❌", f"解析失败: {msg}")

    except Exception as e:
         return TaskResult(name, "❌", f"处理异常: {str(e)}")
    finally:
        if os.path.exists(temp_download): os.remove(temp_download)

    # 3. 优化与编译 (Gatekeeper)
    if json_ready:
        # --- 补回的步骤：强制执行去重优化 ---
        is_opt, opt_count = optimize_json_file(final_json)
        if is_opt:
            print(f"✨ [{name}] 优化完成: 移除了 {opt_count} 条重复规则")
            process_info += f"(去重{opt_count})"
        # ---------------------------------

        if compile_json(final_json, final_srs):
            size = get_file_size(final_srs)
            print(f"✅ [{name}] 成功: {process_info}")
            return TaskResult(name, "✅", f"{process_info}", size)
        else:
            print(f"❌ [{name}] 编译拒绝(JSON数据不合规)")
            return TaskResult(name, "❌", "编译拒绝(JSON非法)")
            
    return TaskResult(name, "❌", "逻辑未知错误")

def write_summary(results, core_ver):
    if not GITHUB_STEP_SUMMARY: return
    success_cnt = sum(1 for r in results if r.status == "✅")
    fail_cnt = len(results) - success_cnt
    
    with open(GITHUB_STEP_SUMMARY, 'a', encoding='utf-8') as f:
        f.write(f"## 🏭 规则工厂审计报告\n")
        f.write(f"- **构建核心**: `{core_ver}` (reF1nd)\n")
        f.write(f"- **结果统计**: ✅ {success_cnt} | ❌ {fail_cnt}\n")
        f.write(f"> 💡 源码已留存至 `{DIR_JSON}/` (已执行自动去重优化)。\n\n")
        f.write("| 规则名称 | 状态 | 流程详情 | 文件大小 |\n|:---|:---:|:---|:---:|\n")
        for r in results: f.write(f"| **{r.name}** | {r.status} | {r.msg} | {r.size} |\n")

def main():
    print("🚀 启动 Sing-box 全能工厂 (Ultimate Fusion Edition)")
    setup_directories()
    
    core_ver = get_core_version()
    print(f"💎 核心版本: {core_ver}")
    if "❌" in core_ver: sys.exit(1)

    tasks = {}
    if len(sys.argv) == 3:
        tasks[sys.argv[1]] = sys.argv[2]
    elif os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read().strip()
                if content: tasks = json.loads(content)
        except: pass

    if not tasks:
        print("ℹ️ 无任务")
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_task, n, u): n for n, u in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    write_summary(results, core_ver)
    if all(r.status == "❌" for r in results): sys.exit(1)

if __name__ == "__main__":
    main()
