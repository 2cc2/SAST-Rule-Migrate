import os
import json
import re

def scan_codeql_files_tree(base_path):
    """
    Scan the given directory for .ql and .qll files and organize them in a tree structure.

    Args:
        base_path (str): The base directory to scan.

    Returns:
        dict: A tree-like structure representing the directory and files.
    """
    tree = {}
    for root, dirs, files in os.walk(base_path):
        # Get the relative path from the base path
        rel_path = os.path.relpath(root, base_path)
        if rel_path == ".":
            rel_path = ""

        # Navigate to the correct level in the tree
        current_level = tree
        for part in rel_path.split(os.sep):
            if part:
                current_level = current_level.setdefault(part, {})

        # Add files to the current level
        for file in files:
            # if file.endswith(".ql") or file.endswith(".qll"):
            file_path = os.path.join(root, file)
            current_level[file] = file_path
    return tree

def parse_imports_from_content(content):
    """从文件内容中提取 import 模块名"""
    imports = re.findall(r"import\s+([\w.]+)", content)
    from_imports = re.findall(r"from\s+([\w.]+)\s+import", content)
    return imports + from_imports

def scan_codeql_files_tree_with_imports(base_path):
    """
    扫描目录并提取文件中的import语句，仅关注.qll和.ql文件

    Args:
        base_path (str): 要扫描的目录路径

    Returns:
        dict: 包含文件路径和import语句的树状结构
    """
    tree = {}
    for root, dirs, files in os.walk(base_path):
        rel_path = os.path.relpath(root, base_path)
        if rel_path == ".":
            rel_path = ""

        current_level = tree
        for part in rel_path.split(os.sep):
            if part:
                current_level = current_level.setdefault(part, {})

        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".ql") or file.endswith(".qll"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        imports = parse_imports_from_content(content)
                        current_level[file] = {
                            "path": file_path,
                            "imports": imports
                        }
                except Exception as e:
                    current_level[file] = {
                        "path": file_path,
                        "imports": [f"Error: {str(e)}"]
                    }
            else:
                current_level[file] = {
                    "path": file_path,
                }

    return tree

def main():
    base_path = "/home/cbb/codeql/"
    output_file = "/home/cbb/Pretools/codeql_files_tree_with_imports.json"

    # 扫描CodeQL文件夹并提取import语句
    codeql_files_tree = scan_codeql_files_tree_with_imports(base_path)

    # 保存结果到JSON文件
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(codeql_files_tree, json_file, indent=4, ensure_ascii=False)

    print(f"CodeQL文件已扫描并提取import语句，结果保存在 {output_file}")

if __name__ == "__main__":
    main()