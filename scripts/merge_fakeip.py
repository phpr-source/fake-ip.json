import json
import os
import sys

# 定义文件路径
FILE_S1 = 's1.json'
FILE_S2 = 's2.json'
FILE_S3 = 's3.list'
OUTPUT_JSON = 'fakeip-filter.json'

def main():
    registry = {}
    stats = {'S1': 0, 'S2': 0, 'S3': 0}

    def add_to_reg(val, r_type, src):
        val = val.strip()
        if not val: return
        # 转小写以避免大小写重复 (例如 Google.com 和 google.com)
        # 如果需要保持原始大小写，可以只在 key 中 lower()，value 存原始值
        key = (r_type, val.lower()) 
        
        if key not in registry: 
            registry[key] = {'sources': set(), 'original': val}
        
        registry[key]['sources'].add(src)

    # 1. 处理 S1 (JSON)
    if os.path.exists(FILE_S1):
        print(f"🔄 正在处理 S1: {FILE_S1}...")
        try:
            with open(FILE_S1, 'r', encoding='utf-8') as f:
                d = json.load(f)
                for r in d.get('rules', []):
                    for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                        for v in r.get(k, []): 
                            add_to_reg(v, k, 'S1')
                            stats['S1'] += 1
        except Exception as e:
            print(f"❌ 读取 S1 失败: {e}")

    # 2. 处理 S2 (JSON - 反编译来源)
    if os.path.exists(FILE_S2):
        print(f"🔄 正在处理 S2: {FILE_S2}...")
        try:
            with open(FILE_S2, 'r', encoding='utf-8') as f:
                d = json.load(f)
                for r in d.get('rules', []):
                    for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                        for v in r.get(k, []): 
                            add_to_reg(v, k, 'S2')
                            stats['S2'] += 1
        except Exception as e:
            print(f"❌ 读取 S2 失败: {e}")

    # 3. 处理 S3 (List 纯文本) - 修复：使用 with open
    if os.path.exists(FILE_S3):
        print(f"🔄 正在处理 S3: {FILE_S3}...")
        try:
            with open(FILE_S3, 'r', encoding='utf-8') as f:
                for line in f:
                    l = line.strip()
                    if not l or l.startswith('#'): continue
                    # 简单的格式判断逻辑
                    if l.startswith('.'): 
                        add_to_reg(l.lstrip('.'), 'domain_suffix', 'S3')
                    else: 
                        add_to_reg(l, 'domain', 'S3')
                    stats['S3'] += 1
        except Exception as e:
            print(f"❌ 读取 S3 失败: {e}")

    # ---------------------------------------------------------
    # 核心合并逻辑原理：
    # 规则必须满足：(在 S1 中) OR (同时在 S2 和 S3 中)
    # ---------------------------------------------------------
    final_rules = {'domain': [], 'domain_suffix': [], 'domain_keyword': [], 'domain_regex': []}
    
    kept_by_s1 = 0
    kept_by_consensus = 0

    for key, data in registry.items():
        r_type, _ = key
        sources = data['sources']
        val = data['original']

        if 'S1' in sources:
            final_rules[r_type].append(val)
            kept_by_s1 += 1
        elif 'S2' in sources and 'S3' in sources:
            final_rules[r_type].append(val)
            kept_by_consensus += 1

    total_kept = kept_by_s1 + kept_by_consensus
    print(f"\n📊 统计报告:")
    print(f"  - S1 原始条数: {stats['S1']}")
    print(f"  - S2 原始条数: {stats['S2']}")
    print(f"  - S3 原始条数: {stats['S3']}")
    print(f"  ---------------------------")
    print(f"  - 来源 S1 保留: {kept_by_s1}")
    print(f"  - 来源 共识保留: {kept_by_consensus} (S2 & S3)")
    print(f"  - ✅ 最终输出: {total_kept}\n")

    if total_kept == 0:
        print("⚠️ 警告: 生成的规则集为空！可能下载失败或逻辑错误。")
        # 视情况可选择是否抛出错误中断流程
        # sys.exit(1) 

    # 5. 输出
    output = {'version': 3, 'rules': [{k: sorted(v) for k, v in final_rules.items() if v}]}
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
