import os
import json
# ERROR_FIX: from scripts.example_collect.utils.filename_match import similarity
from filename_match import similarity

# === 配置 ===
CODEQL_ROOT ="/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql"
LANGUAGES = ["java", "python", "go", "javascript"]
OUTPUT_JSON = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/CodeqlSample/codeql_example.json"
SIMILARITY_THRESHOLD = 0.75

def find_files(base_dirs, suffixes):
    matched = []
    for base in base_dirs:
        for root, _, files in os.walk(base):
            for f in files:
                if any(f.endswith(suf) for suf in suffixes):
                    matched.append(os.path.join(root, f))
    return matched

# TODO: 不能只筛选规则前缀。反例如https://github.com/github/codeql/tree/main/java/ql/src/Security/CWE/CWE-020
def is_example_file(fname, rule_name):
    """判断文件名是否和规则匹配"""
    basename = os.path.basename(fname)
    if basename.lower().startswith("server-crash") and rule_name.lower().startswith("server"):
        pass
    if basename.endswith(".qhelp"):
        return False
    if basename.endswith(".ql"):
        return False
    if basename.startswith(rule_name):
        return True
    if similarity(rule_name, fname) > SIMILARITY_THRESHOLD:
        return True
    if basename.startswith(rule_name + "Good") or basename.startswith(rule_name + "Bad"):
        return True
    return False

def relative_path(path):
    """去掉 CODEQL_ROOT 前缀"""
    if path.startswith(CODEQL_ROOT):
        return path[len(CODEQL_ROOT):].lstrip("/")
    return path

# TODO: 统计good/bad case。
# 情况1：在文件内容中
# 情况2：在文件名中
# 情况3：文件名、文件内容中都没有
def count_good_bad_cases(filepath):
    """统计 example 文件中的 // GOOD 和 // BAD 次数"""
    goodcase = 0
    badcase = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            goodcase = content.count("// GOOD")
            badcase = content.count("// BAD")
    except Exception as e:
        print(f"⚠️  无法读取文件 {filepath}: {e}")
    return goodcase, badcase

results = {}

for lang in LANGUAGES:
    # TODO: experimental未考虑。可以暂时先不考虑。如果只考虑security，则是完备的
    lang_dir = os.path.join(CODEQL_ROOT, lang, "ql", "src", "Security")
    if not os.path.exists(lang_dir):
        print(f"⚠️  Skip missing language dir: {lang_dir}")
        continue

    all_rule_files = find_files([lang_dir], [".ql"])
    results[lang] = {}

    for rule_file in all_rule_files:
        if rule_file.endswith(".qhelp"):
            continue
        rule_name = os.path.splitext(os.path.basename(rule_file))[0]
        rule_dir = os.path.dirname(rule_file)
        examples_dir = os.path.join(rule_dir, "examples")

        # 获取候选 example 文件
        potential_examples = []
        for d in [rule_dir, examples_dir]:
            if os.path.exists(d):
                for f in os.listdir(d):
                    if f.endswith((".java", ".py", ".go", ".js")) and not f.endswith(".qhelp"):
                        potential_examples.append(os.path.join(d, f))

        # 匹配实际 example 文件
        matched_examples = [
            f for f in potential_examples if is_example_file(os.path.basename(f), rule_name)
        ]

        # 去重
        matched_examples = list(dict.fromkeys(matched_examples))
        potential_examples = list(dict.fromkeys(potential_examples))

        # 对匹配到的 example 文件统计 good/bad
        example_entries = []
        for e in matched_examples:
            good, bad = count_good_bad_cases(e)
            example_entries.append({
                "path": relative_path(e),
                "goodcase": good,
                "badcase": bad
            })

        results[lang][relative_path(rule_file)] = {
            "examples": example_entries,
            "potential_examples": [] if matched_examples else [relative_path(e) for e in potential_examples]
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
