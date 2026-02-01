import json
import os
import subprocess
import sys
import concurrent.futures
import time
import re

# 配置文件
CONFIG_FILE = 'rules.json'
MAX_WORKERS = 5
GITHUB_STEP_SUMMARY = os.getenv('GITHUB_STEP_SUMMARY')

# 严格映射表
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
    # 模拟真实浏览器，防止反爬
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    cmd = ["curl", "-L", "--fail", "--retry", "3", "-A", ua, url, "-o", filename]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

# --- 核心：高精度解析器 ---
def convert_clash_to_json(input_file, output_json):
    """
    使用高精度正则提取规则，忽略策略组、no-resolve标记和行内注释。
    """
    rules_dict = {v: set() for v in set(RULE_MAP.values())} # 使用 set 自动去重
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'): continue
            
            # 1. 移除行尾注释 (例如: DOMAIN,x.com # 这是注释)
            line = re.split(r'\s*(#|//)', line)[0].strip()

            # 2. 高精度正则匹配
            # 匹配模式: (类型), (值), [可选参数...]
            match = re.search(r'^([A-Z0-9-]+)\s*,\s*([^,]+)', line, re.IGNORECASE)
            
            if match:
                raw_type = match.group(1).upper()
                value = match.group(2).strip().strip("'\"") # 去除值的引号和空格
                
                if raw_type in RULE_MAP:
                    sb_type = RULE_MAP[raw_type]
                    rules_dict[sb_type].add(value)

        # 构造 JSON
        final_rules = []
        for k, v in rules_dict.items():
            if v:
                # 排序以保证输出稳定
                final_rules.append({k: sorted(list(v))})
        
        if not final_rules:
            return False

        output_data = {"version": 3, "rules": final_rules}
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        return True

    except Exception as e:
        print(f"⚠️ 转换异常: {e}")
        return False

# --- 核心：验证与编译 ---
def decompile_srs(input_srs, output_json):
    """反编译：验证 SRS 完整性"""
    cmd = ["./sing-box", "rule-set", "decompile", input_srs, "-o", output_json]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def compile_json(input_json, output_srs):
    """编译：生成最终 SRS"""
    cmd = ["./sing-box", "rule-set", "compile", input_json, "-o", output_srs]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def process_single_task(name, url):
    print(f"🔄 [{name}] 启动流水线...")
    
    temp_download = f"temp_raw_{name}"
    temp_json = f"temp_{name}.json"
    target_srs = f"{name}.srs"
    
    # 1. 下载
    if not download_file(url, temp_download):
        return TaskResult(name, "❌", "下载失败")
    
    url_lower = url.lower()
    process_type = "未知"
    
    # 2. 统一转换为 JSON 标准中间态
    json_ready = False
    
    if url_lower.endswith('.srs'):
        # 强制验证：SRS -> JSON
        print(f"🛡️ [{name}] 正在验证 SRS 完整性 (Decompile)...")
        if decompile_srs(temp_download, temp_json):
            process_type = "SRS重构"
            json_ready = True
        else:
            os.remove(temp_download)
            return TaskResult(name, "❌", "SRS验证失败(损坏或版本不符)")
            
    elif url_lower.endswith('.json'):
        # JSON 原生
        os.rename(temp_download, temp_json)
        process_type = "JSON编译"
        json_ready = True
        
    elif url_lower.endswith('.mrs'):
         os.remove(temp_download)
         return TaskResult(name, "❌", "不支持MRS格式")
         
    else:
        # Clash/Surge -> JSON
        print(f"🔧 [{name}] 正在解析文本规则...")
        if convert_clash_to_json(temp_download, temp_json):
            process_type = "格式转换"
            json_ready = True
        else:
            os.remove(temp_download)
            return TaskResult(name, "❌", "解析失败(格式不支持或内容为空)")

    # 3. 最终编译 (Gatekeeper)
    # 这一步是质量控制的核心：必须用你的核心重新编译成功才算通过
    if json_ready:
        if compile_json(temp_json, target_srs):
            size = get_file_size(target_srs)
            
            # 清理中间文件
            if os.path.exists(temp_download): os.remove(temp_download)
            if os.path.exists(temp_json): os.remove(temp_json)
            
            print(f"✅ [{name}] 成功: {process_type}")
            return TaskResult(name, "✅", f"{process_type}+验证", size)
        else:
            print(f"❌ [{name}] 编译被拒绝(JSON数据不合规)")
            if os.path.exists(temp_json): os.remove(temp_json)
            return TaskResult(name, "❌", "编译拒绝(数据校验失败)")
            
    return TaskResult(name, "❌", "未知错误")

def write_summary(results, core_ver):
    if not GITHUB_STEP_SUMMARY: return
    success_cnt = sum(1 for r in results if r.status == "✅")
    fail_cnt = len(results) - success_cnt
    with open(GITHUB_STEP_SUMMARY, 'a', encoding='utf-8') as f:
        f.write(f"## 🏭 规则工厂安全报告\n")
        f.write(f"- **构建核心**: `{core_ver}` (reF1nd)\n")
        f.write(f"- **结果统计**: ✅ {success_cnt} | ❌ {fail_cnt}\n\n")
        f.write("| 规则名称 | 状态 | 安全流程 | 文件大小 |\n|:---|:---:|:---|:---:|\n")
        for r in results: f.write(f"| **{r.name}** | {r.status} | {r.msg} | {r.size} |\n")

def main():
    print("🚀 启动 Sing-box 安全规则工厂 (Secure Edition)")
    
    # 0. 核心检查
    core_ver = get_core_version()
    print(f"💎 核心版本: {core_ver}")
    if "❌" in core_ver: sys.exit(1)

    # 1. 读取任务
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

    # 2. 并发执行
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_task, n, u): n for n, u in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # 3. 输出报告
    write_summary(results, core_ver)
    
    # 4. 如果全失败，报错退出
    if all(r.status == "❌" for r in results): sys.exit(1)

if __name__ == "__main__":
    main()
