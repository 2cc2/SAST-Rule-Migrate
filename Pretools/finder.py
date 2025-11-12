import json
import os
from tqdm import tqdm

def resolve_import_path(module_name, base_path):
    """根据模块名查找实际文件路径 (.ql 或 .qll)，采用就近原则"""
    rel_path = module_name.replace('.', '/')
    closest_match = None
    closest_depth = float('inf')

    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file in [rel_path + ".ql", rel_path + ".qll"]:
                current_depth = root.count(os.sep)
                if current_depth < closest_depth:
                    closest_match = os.path.join(root, file)
                    closest_depth = current_depth

    return closest_match

def find_import_filepaths(json_file, base_path, output_file):
    """为JSON中的每个import模块找到filepath并更新结构"""
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 仅处理前五个顶层节点
    top_keys = list(data.keys())[:25]
    limited_data = {key: data[key] for key in top_keys}

    def process_node(node):
        if isinstance(node, dict):
            if "imports" in node and "path" in node:
                updated_imports = {}
                for imp in tqdm(node["imports"], desc=f"Processing imports for {node['path']}"):
                    updated_imports[imp] = resolve_import_path(imp, base_path)
                node["imports"] = updated_imports
            else:
                for key, value in node.items():
                    process_node(value)
        elif isinstance(node, list):
            for item in node:
                process_node(item)

    process_node(limited_data)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(limited_data, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    json_file = "/home/cbb/Pretools/codeql_files_tree_with_imports.json"
    base_path = "/home/cbb/codeql/"
    output_file = "/home/cbb/Pretools/codeql_files_tree_with_imports_resolved25.json"

    find_import_filepaths(json_file, base_path, output_file)
    print(f"Resolved import filepaths saved to {output_file}")