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
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        rules = json.load(f)

    for name, url in rules.items():
        print("-" * 30)
        temp_json = f"temp_{name}.json"
        if download_file(url, temp_json):
            compile_rule(name, temp_json)
            if os.path.exists(temp_json):
                os.remove(temp_json)

if __name__ == "__main__":
    main()
