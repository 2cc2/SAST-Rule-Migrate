
import os
import json
import csv
import yaml
from b2rscan.llm_wrapper import LLMWrapper

PROJECT_PATH = "sast/codeql"
OUTPUT_DIR = "agent_output"
SUMMARY_JSON = os.path.join(OUTPUT_DIR, "project_structure_summary.json")
RULE_DOC_MD = os.path.join(OUTPUT_DIR, "rule_system_doc.md")
RULE_CSV = os.path.join(OUTPUT_DIR, "sast_rules.csv")

RULE_EXTENSIONS = [".yaml", ".yml", ".json"]
VALID_FIELDS = {"id", "name", "description", "source", "sink", "sanitizers", "pattern", "severity"}

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Phase 1: 项目结构解析
def scan_project_structure(path, depth_limit=3):
    structure = {}

    def helper(p, depth):
        if depth > depth_limit:
            return {}
        children = {}
        for name in os.listdir(p):
            full_path = os.path.join(p, name)
            if os.path.isdir(full_path) and not name.startswith("."):
                children[name] = helper(full_path, depth + 1)
        return children

    return helper(path, 0)

def summarize_directories(structure, base_path):
    llm = LLMWrapper.dashscope()
    summaries = {}
    for root, dirs, _ in os.walk(base_path):
        if "__pycache__" in root or "test" in root:
            continue
        subdirs = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
        if not subdirs:
            continue
        rel_path = os.path.relpath(root, base_path)
        prompt = f"""
                    你是一个静态分析项目理解Agent。

                    目录路径：{rel_path}
                    包含子目录：{subdirs}

                    请判断这个目录在系统中负责什么功能（如规则定义、分析逻辑、配置、插件、报告生成等）。
                    """
        try:
            summary = llm.chat(prompt).strip()
        except Exception as e:
            summary = f"[ERROR] {e}"
        summaries[rel_path] = {
            "subdirs": subdirs,
            "summary": summary
        }
    return summaries

# Phase 2: 问题驱动规则系统文档生成
def generate_rule_system_doc(readme_text, structure_summaries):
    llm = LLMWrapper.dashscope()
    base_context = f"""
以下是该项目的 README 摘要：
{readme_text[:3000]}

---

以下是项目各目录的解释摘要：
""" + "\n".join([
        f"[{path}]: {info['summary']}" for path, info in structure_summaries.items()
    ])

    question = """
        请根据以上内容总结该工具的规则系统设计，包括：
        1. 是否使用规则系统？规则放在哪些目录？
        2. 规则的格式、结构和分类方法
        3. 规则是如何加载并作用于分析流程的
    """
    try:
        answer = llm.chat(base_context + "\n\n" + question)
    except Exception as e:
        answer = f"[ERROR] {e}"

    with open(RULE_DOC_MD, "w", encoding="utf-8") as f:
        f.write("# SAST规则系统文档\n\n")
        f.write(answer)

# Phase 3: 规则文件精准提取
def find_rule_dirs(structure_summaries):
    return [
        path for path, info in structure_summaries.items()
        if any(k in info["summary"].lower() for k in ["规则", "rule", "pattern", "污点", "匹配"])
    ]

def find_rule_files(project_root, rule_dirs):
    rule_files = []
    for rel_dir in rule_dirs:
        abs_dir = os.path.join(project_root, rel_dir)
        for root, _, files in os.walk(abs_dir):
            for file in files:
                if any(file.endswith(ext) for ext in RULE_EXTENSIONS):
                    full_path = os.path.join(root, file)
                    if ".github" in full_path or "workflow" in full_path:
                        continue
                    rule_files.append(full_path)
    return rule_files

def is_likely_rule(data):
    if isinstance(data, dict):
        return len(set(data.keys()) & VALID_FIELDS) >= 2
    elif isinstance(data, list):
        return any(is_likely_rule(d) for d in data if isinstance(d, dict))
    return False

def flatten_rule_info(path, data):
    rules = []
    if isinstance(data, dict):
        data = [data]
    for rule in data:
        if not isinstance(rule, dict):
            continue
        rules.append({
            "file": path,
            "id": rule.get("id") or rule.get("name", ""),
            "description": rule.get("description", "") or rule.get("desc", ""),
            "severity": rule.get("severity", ""),
            "type": rule.get("type", ""),
            "source": str(rule.get("source", "")),
            "sink": str(rule.get("sink", "")),
            "sanitizers": str(rule.get("sanitizers", "")),
        })
    return rules

def extract_rule_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                data = json.load(f)
            else:
                data = yaml.safe_load(f)
        if not is_likely_rule(data):
            return []
        return flatten_rule_info(path, data)
    except Exception:
        return []

def main():
    
    structure = scan_project_structure(PROJECT_PATH)
    print(structure)
    structure_summaries = summarize_directories(structure, PROJECT_PATH)

    readme_path = os.path.join(PROJECT_PATH, "README.md")
    readme_text = open(readme_path, encoding="utf-8").read() if os.path.exists(readme_path) else ""
    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump({
            "readme_summary": readme_text[:3000],
            "structure_summaries": structure_summaries
        }, f, indent=2, ensure_ascii=False)

    print("生成规则系统文档...")
    generate_rule_system_doc(readme_text, structure_summaries)
    

    with open(RULE_DOC_MD, "r") as f:
        content = f.read()
    llm = LLMWrapper.dashscope()
    prompt = content + "结合以上内容，帮我推测该项目的规则文件存储在哪里，不要输出多余内容，只以输出文件位置"
    response = llm.chat(prompt)
    print(response)


    print("🧪 提取规则文件...")
    rule_dirs = find_rule_dirs(structure_summaries)
    rule_files = find_rule_files(PROJECT_PATH, rule_dirs)
    all_rules = []
    for path in rule_files:
        all_rules.extend(extract_rule_file(path))

    with open(RULE_CSV, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "id", "description", "severity", "type", "source", "sink", "sanitizers"])
        writer.writeheader()
        writer.writerows(all_rules)

    print(f"✅ 提取完成：共 {len(all_rules)} 条规则，写入 {RULE_CSV}")

if __name__ == "__main__":
    main()
