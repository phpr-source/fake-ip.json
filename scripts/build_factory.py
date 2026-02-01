import json
import os
import subprocess
import sys
import concurrent.futures
import time

# 配置文件路径
CONFIG_FILE = 'rules.json'
# 并发线程数
MAX_WORKERS = 5
# GitHub Summary 文件路径
GITHUB_STEP_SUMMARY = os.getenv('GITHUB_STEP_SUMMARY')

class TaskResult:
    def __init__(self, name, status, msg, size="0KB"):
        self.name = name
        self.status = status  # ✅ / ❌ / 📦
        self.msg = msg
        self.size = size

def get_core_version():
    """检测核心版本"""
    core_path = "./sing-box"
    if not os.path.exists(core_path):
        return "❌ 核心缺失"
    try:
        result = subprocess.run([core_path, "version"], capture_output=True, text=True, check=True)
        return result.stdout.split('\n')[0].split('version ')[-1].strip()
    except:
        return "❓ 未知版本"

def get_file_size(filepath):
    """获取易读的文件大小"""
    if not os.path.exists(filepath):
        return "0KB"
    size = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"

def optimize_json(filepath):
    """功能：JSON 规则去重"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        rules = data.get('rules', [])
        total_removed = 0
        
        for rule in rules:
            for key, val in rule.items():
                if isinstance(val, list):
                    # 去重并排序
                    new_val = sorted(list(set(val)))
                    removed = len(val) - len(new_val)
                    if removed > 0:
                        rule[key] = new_val
                        total_removed += removed
        
        if total_removed > 0:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
            return True, total_removed
        return False, 0
    except Exception:
        return False, 0

def download_file(url, filename):
    """下载文件 (带 User-Agent 防拦截)"""
    # 模拟浏览器 UA
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    cmd = ["curl", "-L", "--fail", "--retry", "3", "-A", user_agent, url, "-o", filename]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def compile_rule(name, input_file):
    """编译规则"""
    output_file = f"{name}.srs"
    cmd = ["./sing-box", "rule-set", "compile", input_file, "-o", output_file]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True, output_file
    except subprocess.CalledProcessError:
        return False, None

def process_single_task(name, url):
    """处理单个任务的流水线"""
    print(f"🔄 [{name}] 开始处理...")
    start_time = time.time()
    
    is_srs = url.lower().endswith('.srs')
    
    # 1. 下载
    if is_srs:
        target_file = f"{name}.srs"
        if download_file(url, target_file):
            size = get_file_size(target_file)
            print(f"📦 [{name}] 下载完成 (SRS直连)")
            return TaskResult(name, "📦", f"SRS直连 ({size})", size)
        else:
            print(f"❌ [{name}] 下载失败")
            return TaskResult(name, "❌", "下载失败")
    else:
        temp_json = f"temp_{name}.json"
        if download_file(url, temp_json):
            # 2. 优化去重
            is_opt, count = optimize_json(temp_json)
            opt_msg = f" (去重 {count} 条)" if is_opt else ""
            
            # 3. 编译
            success, outfile = compile_rule(name, temp_json)
            
            # 清理临时文件
            if os.path.exists(temp_json):
                os.remove(temp_json)
                
            if success:
                size = get_file_size(outfile)
                print(f"✅ [{name}] 编译成功{opt_msg}")
                return TaskResult(name, "✅", f"编译成功{opt_msg}", size)
            else:
                print(f"❌ [{name}] 编译失败")
                return TaskResult(name, "❌", "编译失败")
        else:
            print(f"❌ [{name}] 下载失败")
            return TaskResult(name, "❌", "下载失败")

def write_summary(results, core_ver):
    """生成 GitHub Job Summary"""
    if not GITHUB_STEP_SUMMARY:
        return

    success_cnt = sum(1 for r in results if r.status in ["✅", "📦"])
    fail_cnt = len(results) - success_cnt
    
    with open(GITHUB_STEP_SUMMARY, 'a', encoding='utf-8') as f:
        f.write(f"## 🏭 规则工厂构建报告\n")
        f.write(f"- **核心版本**: `{core_ver}`\n")
        f.write(f"- **总任务**: {len(results)} | ✅ 成功: {success_cnt} | ❌ 失败: {fail_cnt}\n\n")
        f.write("| 规则名称 | 状态 | 详情 | 文件大小 |\n")
        f.write("| :--- | :---: | :--- | :---: |\n")
        for r in results:
            f.write(f"| **{r.name}** | {r.status} | {r.msg} | {r.size} |\n")

def main():
    print("🚀 启动 Sing-box 规则工厂 (Ultimate Edition)")
    
    # 1. 核心检测
    core_ver = get_core_version()
    print(f"💎 Core Version: {core_ver}")
    if "❌" in core_ver:
        sys.exit(1)

    # 2. 确定任务列表
    tasks = {}
    
    # 手动模式
    if len(sys.argv) == 3:
        tasks[sys.argv[1]] = sys.argv[2]
    # 批量模式
    elif os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    tasks = json.loads(content)
        except Exception as e:
            print(f"❌ 读取配置失败: {e}")
            return
    else:
        print("ℹ️ 无任务可执行")
        return

    if not tasks:
        print("ℹ️ 任务列表为空")
        return

    print(f"🔥 开始处理 {len(tasks)} 个任务 (并发数: {MAX_WORKERS})...\n")
    
    # 3. 并发执行
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_task, name, url): name for name, url in tasks.items()}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # 4. 生成报告
    write_summary(results, core_ver)
    
    # 5. 检查是否全部失败
    if all(r.status == "❌" for r in results):
        sys.exit(1)

if __name__ == "__main__":
    main()
