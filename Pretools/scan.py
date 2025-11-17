import os
import json
import re

def parse_imports_from_content(content):
    """从文件内容中提取 import 和 module 模块名"""
    imports = re.findall(r"import\s+([\w.]+)", content)
    from_imports = re.findall(r"from\s+([\w.]+)\s+import", content)
    modules = re.findall(r"module\s+([A-Za-z0-9_.:]+)", content)
    return {
        "imports": imports + from_imports,
        "modules": modules
    }

def scan_codeql_files_tree_with_imports(base_path):
    """
    扫描目录并提取文件中的 import 和 module 语句，仅关注 .qll 和 .ql 文件

    Args:
        base_path (str): 要扫描的目录路径

    Returns:
        dict: 包含文件路径和 import/module 语句的树状结构
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
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        parsed_data = parse_imports_from_content(content)
                        current_level[file] = {
                            "path": file_path,
                            "imports": parsed_data["imports"],
                            "modules": parsed_data["modules"]
                        }
                except Exception as e:
                    current_level[file] = {
                        "path": file_path,
                        "imports": [f"Error: {str(e)}"],
                        "modules": [f"Error: {str(e)}"]
                    }
            else:
                current_level[file] = {
                    "path": file_path,
                }

    return tree

def create_module_to_filepath_mapping(tree):
    """
    从扫描结果中创建 module 到 filepath 的映射

    Args:
        tree (dict): 扫描结果的树状结构

    Returns:
        dict: module 到 filepath 的映射
    """
    module_to_filepath = {}

    def traverse_tree(subtree):
        for key, value in subtree.items():
            if isinstance(value, dict):
                if "path" in value and "modules" in value:
                    for module in value["modules"]:
                        module_to_filepath[module] = value["path"]
                else:
                    traverse_tree(value)

    traverse_tree(tree)
    return module_to_filepath

def main():
    base_path = "/home/cbb/codeql/"
    output_file = "/home/cbb/SAST-Rule-Migrate/Pretools/module_to_filepath.json"

    # 扫描 CodeQL 文件夹并提取 import 和 module 语句
    codeql_files_tree = scan_codeql_files_tree_with_imports(base_path)

    # 创建 module 到 filepath 的映射
    module_to_filepath = create_module_to_filepath_mapping(codeql_files_tree)

    # 保存结果到 JSON 文件
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(module_to_filepath, json_file, indent=4, ensure_ascii=False)

    print(f"module 到 filepath 的映射已生成，结果保存在 {output_file}")

if __name__ == "__main__":
    main()