import json
import os
import subprocess
import sys

# 配置文件路径
CONFIG_FILE = 'rules.json'

def download_file(url, filename):
    """使用 curl 下载文件，带重试机制"""
    print(f"⬇️ 正在下载: {filename} <- {url}")
    try:
        # -L: 跟随跳转, --fail: 报错即停, --retry: 重试
        subprocess.run(["curl", "-L", "--fail", "--retry", "3", url, "-o", filename], check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"❌ 下载失败: {url}")
        return False

def compile_rule(name, input_file):
    """调用当前目录下的 sing-box 进行编译"""
    output_file = f"{name}.srs"
    print(f"🔨 正在编译: {output_file} (使用自定义核心)")
    try:
        # 核心命令：./sing-box rule-set compile 输入文件 -o 输出文件
        subprocess.run(["./sing-box", "rule-set", "compile", input_file, "-o", output_file], check=True)
        print(f"✅ 编译成功: {output_file}")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ 编译失败: {name}")
        return False

def main():
    # 接收命令行参数：python3 build_factory.py [name] [url]
    if len(sys.argv) == 3:
        manual_name = sys.argv[1]
        manual_url = sys.argv[2]
        print(f"🚀 收到手动任务: {manual_name}")
        temp_json = "temp_manual.json"
        if download_file(manual_url, temp_json):
            compile_rule(manual_name, temp_json)
            if os.path.exists(temp_json):
                os.remove(temp_json)
        return

    # 批量任务
    if not os.path.exists(CONFIG_FILE):
        print(f"ℹ️ {CONFIG_FILE} 不存在，跳过批量通用任务。")
        return

    print(f"🚀 开始处理 {CONFIG_FILE} 批量任务...")
    
    # --- 修复点：增加对空文件或格式错误的容错处理 ---
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                print(f"⚠️ {CONFIG_FILE} 是空的，跳过处理。")
                return
            rules = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"❌ {CONFIG_FILE} JSON 格式错误: {e}")
        print("💡 请确保文件内容至少包含一对大括号: {}")
        return
    except Exception as e:
        print(f"❌ 读取 {CONFIG_FILE} 发生未知错误: {e}")
        return
    # ---------------------------------------------

    # 如果 rules 不是字典（例如是个列表 []），也要防一下
    if not isinstance(rules, dict):
        print(f"❌ {CONFIG_FILE} 格式必须是 键值对(字典) 结构。")
        return

    if not rules:
        print(f"ℹ️ {CONFIG_FILE} 内无规则，跳过。")
        return

    for name, url in rules.items():
        print("-" * 30)
        temp_json = f"temp_{name}.json"
        if download_file(url, temp_json):
            compile_rule(name, temp_json)
            if os.path.exists(temp_json):
                os.remove(temp_json)

if __name__ == "__main__":
    main()
