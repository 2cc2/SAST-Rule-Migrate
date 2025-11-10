import os, re, json

def extract_codeql_api(repo_path):
    base_dir = repo_path
    print(f"🔍 Extracting CodeQL API from {base_dir}...")
    result = []

    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".ql") or f.endswith(".qll"):
                path = os.path.join(root, f)
                with open(path, encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                
                module = re.findall(r"module\s+([A-Za-z0-9_.:]+)", content)
                imports = re.findall(r"import\s+([A-Za-z0-9_.:]+)", content)
                classes = re.findall(r"class\s+([A-Z][A-Za-z0-9_]*)", content)
                predicates = re.findall(r"predicate\s+([a-zA-Z0-9_]+)", content)
                docs = re.findall(r"/\*\*(.*?)\*/", content, re.S)
                
                # 提取查询逻辑
                from_statements = re.findall(r"from\s+.*", content)
                where_statements = re.findall(r"where\s+.*", content)
                select_statements = re.findall(r"select\s+.*", content)

                result.append({
                    "file": path,
                    "module": module[0] if module else None,
                    "imports": imports,
                    "classes": classes,
                    "predicates": predicates,
                    "doc": docs[0].strip() if docs else "",
                    "from_statements": from_statements,
                    "where_statements": where_statements,
                    "select_statements": select_statements
                })
    
    # 按文件名的字典序排序
    result.sort(key=lambda x: x["file"])

    with open("codeql_79_index.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"✅ Extracted {len(result)} files")

# 调用函数
# extract_codeql_api("/home/cbb/codeql/java/ql/lib/semmle/")
extract_codeql_api("/home/cbb/codeql/java/ql/src/Security/CWE/CWE-079/")
