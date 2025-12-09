import os
import yaml
import json
# ERROR_FIX: from src.config import *

# === 配置 ===
# ERROR_FIX: SEMGREP_ROOT = os.path.join(SETTINGS.path.sast, "semgrep-rules")
SEMGREP_ROOT ="/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/semgrep-rules"
OUTPUT_JSON = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/SemgrepSample/semgrep_sample.json"
LANGUAGES = ["python", "javascript", "java", "go", "php"]

def find_certain_files(paths, suffixes, exclude_substrings=None):
    if exclude_substrings is None:
        exclude_substrings = []
    matched_files = []
    for base in paths:
        for root, _, files in os.walk(base):
            for file in files:
                full_path = os.path.join(root, file)
                if any(file.endswith(suffix) for suffix in suffixes):
                    if not any(excl in full_path for excl in exclude_substrings):
                        matched_files.append(full_path)
    return matched_files

def relative_path(path):
    """去掉 SEMGREP_ROOT 前缀"""
    if path.startswith(SEMGREP_ROOT):
        return path[len(SEMGREP_ROOT):].lstrip("/")
    return path

# === 主逻辑 ===
rule_files = find_certain_files(
    [SEMGREP_ROOT],
    [".yaml", ".yml"],
    [".test.", "/template.yaml", "/.pre-commit-config.yaml"],
)

results = {lang: {} for lang in LANGUAGES}

for rule_path in rule_files:
    try:
        with open(rule_path, "r", encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to read {rule_path}: {e}")
        continue

    rules = yaml_data.get("rules", [])
    if not rules:
        continue

    for rule in rules:
        category = rule.get("metadata", {}).get("category", "")
        langs = rule.get("languages", [])
        if not langs:
            continue
        lang = langs[0]

        # 限定安全类 + 支持语言
        if category != "security" or lang not in LANGUAGES:
            continue

        base_name = os.path.splitext(rule_path)[0]
        dir_name = os.path.dirname(rule_path)
        file_prefix = os.path.basename(base_name)
        examples = []

        # ✅ YAML 特例（xxx.test.yaml）
        if lang == "yaml":
            test_file = f"{base_name}.test.yaml"
            if os.path.exists(test_file):
                examples.append(relative_path(test_file))
        else:
            # 其他语言：同名非yaml/yml文件视为example
            for file in os.listdir(dir_name):
                if file.startswith(file_prefix + ".") and not file.endswith((".yaml", ".yml")):
                    examples.append(relative_path(os.path.join(dir_name, file)))

        rel_path = relative_path(rule_path)
        results.setdefault(lang, {})[rel_path] = {"examples": examples}

# === 写入 JSON ===
os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# === 输出统计 ===
print("\n=== Semgrep Example Coverage Summary ===")

total_all = 0
with_example_all = 0

for lang, rules in results.items():
    total = len(rules)
    with_example = sum(1 for v in rules.values() if v["examples"])
    if total == 0:
        continue
    coverage = with_example / total * 100
    print(f"[{lang}]  Rules: {total:4d}  With example: {with_example:4d}  Coverage: {coverage:.2f}%")
    total_all += total
    with_example_all += with_example

# 总体统计
if total_all > 0:
    overall_coverage = with_example_all / total_all * 100
else:
    overall_coverage = 0.0

print("\n=== Overall ===")
print(f"Total Rules: {total_all:4d}  With example: {with_example_all:4d}  Coverage: {overall_coverage:.2f}%")

print(f"\n✅ 统计完成，结果写入 {OUTPUT_JSON}")
