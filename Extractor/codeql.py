import os, re, json

def extract_codeql_api(repo_path, lang="python"):
    base_dir = repo_path
    print(f"🔍 Extracting CodeQL API from {base_dir}...")
    result = []

    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".ql"):
                path = os.path.join(root, f)
                with open(path, encoding="utf-8", errors="ignore") as fp:
                    content = fp.read()
                
                module = re.findall(r"module\s+([A-Za-z0-9_.:]+)", content)
                imports = re.findall(r"import\s+([A-Za-z0-9_.:]+)", content)
                classes = re.findall(r"class\s+([A-Z][A-Za-z0-9_]*)", content)
                predicates = re.findall(r"predicate\s+([a-zA-Z0-9_]+)", content)
                docs = re.findall(r"/\*\*(.*?)\*/", content, re.S)
                
                result.append({
                    "file": path,
                    "module": module[0] if module else None,
                    "imports": imports,
                    "classes": classes,
                    "predicates": predicates,
                    "doc": docs[0].strip() if docs else ""
                })
    
    # 按文件名的字典序排序
    result.sort(key=lambda x: x["file"])

    with open("codeql_ql_java.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"✅ Extracted {len(result)} files")

extract_codeql_api("/home/cbb/codeql/java/ql", "python")