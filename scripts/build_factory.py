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
    # 1. 检查配置文件是否存在
    if not os.path.exists(CONFIG_FILE):
        print(f"⚠️ 配置文件 {CONFIG_FILE} 不存在，跳过批量构建。")
        return

    # 2. 读取规则列表
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        rules = json.load(f)

    success_count = 0
    fail_count = 0

    # 3. 循环处理每一条规则
    for name, url in rules.items():
        print("-" * 40)
        temp_json = f"temp_{name}.json"
        
        # 下载
        if download_file(url, temp_json):
            # 编译
            if compile_rule(name, temp_json):
                success_count += 1
            else:
                fail_count += 1
            
            # 清理临时下载的 JSON 文件
            if os.path.exists(temp_json):
                os.remove(temp_json)
        else:
            fail_count += 1

    print("=" * 40)
    print(f"📊 汇总: 成功 {success_count} 个, 失败 {fail_count} 个")
    
    # 如果全部失败，非正常退出
    if fail_count > 0 and success_count == 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
