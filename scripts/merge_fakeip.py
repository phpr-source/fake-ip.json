import json
import os

# 定义文件路径（与 Workflow 中的下载路径保持一致）
FILE_S1 = 's1.json'
FILE_S2 = 's2.json'
FILE_S3 = 's3.list'
OUTPUT_JSON = 'fakeip-filter.json'

def main():
    registry = {}

    def add_to_reg(val, r_type, src):
        val = val.strip()
        if not val: return
        # 使用 (类型, 值) 作为 Key，但值保持原始大小写
        key = (r_type, val)
        if key not in registry: registry[key] = set()
        registry[key].add(src)

    # 1. 处理 S1 (JSON 格式)
    if os.path.exists(FILE_S1):
        print(f"正在处理 {FILE_S1}...")
        try:
            with open(FILE_S1, 'r') as f:
                d = json.load(f)
                for r in d.get('rules', []):
                    for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                        for v in r.get(k, []): add_to_reg(v, k, 'S1')
        except Exception as e:
            print(f"读取 {FILE_S1} 失败: {e}")

    # 2. 处理 S2 (JSON 格式 - 由 SRS 反编译而来)
    if os.path.exists(FILE_S2):
        print(f"正在处理 {FILE_S2}...")
        try:
            with open(FILE_S2, 'r') as f:
                d = json.load(f)
                for r in d.get('rules', []):
                    for k in ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']:
                        for v in r.get(k, []): add_to_reg(v, k, 'S2')
        except Exception as e:
            print(f"读取 {FILE_S2} 失败: {e}")

    # 3. 处理 S3 (List 纯文本格式)
    if os.path.exists(FILE_S3):
        print(f"正在处理 {FILE_S3}...")
        try:
            for line in open(FILE_S3):
                l = line.strip()
                if not l or l.startswith('#'): continue
                if l.startswith('.'): 
                    add_to_reg(l.lstrip('.'), 'domain_suffix', 'S3')
                else: 
                    add_to_reg(l, 'domain', 'S3')
        except Exception as e:
            print(f"读取 {FILE_S3} 失败: {e}")

    # 4. 合并逻辑：S1 存在 或 (S2 且 S3 存在)
    final_rules = {'domain': [], 'domain_suffix': [], 'domain_keyword': [], 'domain_regex': []}
    count = 0
    for (r_type, val), sources in registry.items():
        if 'S1' in sources or ('S2' in sources and 'S3' in sources):
            final_rules[r_type].append(val)
            count += 1

    print(f"合并完成，共生成 {count} 条规则。")

    # 5. 排序并输出
    output = {'version': 3, 'rules': [{k: sorted(v) for k, v in final_rules.items() if v}]}
    with open(OUTPUT_JSON, 'w') as f:
        json.dump(output, f, indent=2)

if __name__ == "__main__":
    main()
