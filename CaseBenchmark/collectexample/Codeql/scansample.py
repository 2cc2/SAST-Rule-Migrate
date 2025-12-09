import os
import json
import xml.etree.ElementTree as ET

# === 配置 ===
CODEQL_ROOT = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql"
LANGUAGES = ["java", "python", "go", "javascript"]
OUTPUT_JSON = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_examples.json"

def find_files(base_dirs, suffixes):
    """递归查找指定后缀的文件"""
    matched = []
    for base in base_dirs:
        for root, _, files in os.walk(base):
            for f in files:
                if any(f.endswith(suf) for suf in suffixes):
                    matched.append(os.path.join(root, f))
    return matched

def relative_path(path):
    """去掉 CODEQL_ROOT 前缀"""
    if path.startswith(CODEQL_ROOT):
        return path[len(CODEQL_ROOT):].lstrip("/")
    return path

def extract_examples_from_qhelp(file_path):
    """解析 .qhelp 文件中的 <example> 和 <sample> 标签"""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        examples = []
        for example in root.findall(".//example"):
            example_content = {"description": [], "samples": []}
            for child in example:
                if child.tag == "p":  # 提取描述内容
                    example_content["description"].append(child.text.strip() if child.text else "")
                elif child.tag == "sample":  # 提取 <sample> 标签内容
                    src = child.get("src")
                    language = child.get("language")
                    code = child.text.strip() if child.text else None
                    example_content["samples"].append({"src": src, "language": language, "code": code})
            examples.append(example_content)
        return examples
    except Exception as e:
        print(f"⚠️ 无法解析文件 {file_path}: {e}")
        return []

results = {}

for lang in LANGUAGES:
    lang_dir = os.path.join(CODEQL_ROOT, lang, "ql", "src", "Security")
    if not os.path.exists(lang_dir):
        print(f"⚠️ Skip missing language dir: {lang_dir}")
        continue

    all_rule_files = find_files([lang_dir], [".ql"])
    results[lang] = {}

    for rule_file in all_rule_files:
        rule_name = os.path.splitext(os.path.basename(rule_file))[0]
        rule_dir = os.path.dirname(rule_file)
        qhelp_file = os.path.join(rule_dir, f"{rule_name}.qhelp")

        if os.path.exists(qhelp_file):
            # 解析 .qhelp 文件中的 examples
            examples = extract_examples_from_qhelp(qhelp_file)
            results[lang][relative_path(rule_file)] = {
                "qhelp": relative_path(qhelp_file),
                "examples": examples
            }
        else:
            results[lang][relative_path(rule_file)] = {
                "qhelp": None,
                "examples": []
            }

# 写入 JSON
os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# === 统计输出 ===
print("\n=== CodeQL Example Coverage Summary ===")

total_all = 0
with_example_all = 0

for lang, rules in results.items():
    total = len(rules)
    with_example = sum(1 for v in rules.values() if v["examples"])
    coverage = (with_example / total * 100) if total > 0 else 0
    print(f"[{lang}]  Rules: {total:4d}  With example: {with_example:4d}  Coverage: {coverage:.2f}%")

    total_all += total
    with_example_all += with_example

# 总体统计
overall_coverage = (with_example_all / total_all * 100) if total_all > 0 else 0.0

print("\n=== Overall ===")
print(f"Total Rules: {total_all:4d}  With example: {with_example_all:4d}  Coverage: {overall_coverage:.2f}%")

print(f"\n✅ 统计完成，结果写入 {OUTPUT_JSON}")

# === 输出未覆盖的规则 ===
print("\n=== Uncovered Rules ===")
for lang, rules in results.items():
    uncovered_rules = [rule for rule, data in rules.items() if not data["examples"]]
    if uncovered_rules:
        print(f"[{lang}] Uncovered Rules:")
        for rule in uncovered_rules:
            print(f"  - {rule}")