import os
import json

# 读取 JSON 文件
def load_results(file_path):
    if not os.path.exists(file_path):
        print(f"⚠️ 文件不存在: {file_path}")
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ 无法读取文件 {file_path}: {e}")
        return {}

# 设置文件路径
CODEQL_SAMPLE_PATH = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_scan.json"

# 加载结果
results = load_results(CODEQL_SAMPLE_PATH)

# === 统计每个规则的 examples 数量（降序排序） ===
print("\n=== Examples Count Per Rule (Sorted) ===")
for lang, rules in results.items():
    print(f"[{lang}] Examples Count:")
    sorted_rules = sorted(rules.items(), key=lambda item: len(item[1]["examples"]), reverse=True)
    for rule, data in sorted_rules:
        example_count = len(data["examples"])
        rule_with_root = f"/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/{rule}"
        print(f"  - {rule_with_root}: {example_count} examples")