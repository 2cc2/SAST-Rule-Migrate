import os
import re
import json
import networkx as nx
from pyvis.network import Network

def parse_imports_from_content(content):
    """从文件内容中提取 import 模块名"""
    return re.findall(r"import\s+([\w.]+)", content)

def load_module_mapping(json_path):
    """加载模块映射的 JSON 文件"""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            module_mapping = json.load(f)
    except Exception as e:
        print(f"[⚠️] 无法加载模块映射文件: {json_path} ({e})")
        module_mapping = {}
    return module_mapping

def resolve_import_path(module_name, all_files, module_mapping=None):
    """根据模块名查找实际文件路径 (.ql 或 .qll)"""
    if all_files is None:
        raise ValueError("all_files 参数未正确初始化，不能为 None")
    
    rel_path = module_name.replace('.', '/')
    for ext in [".ql", ".qll"]:
        module_path = rel_path + ext
        for file in all_files:
            if module_path in file:
                return file

    if module_mapping and module_name in module_mapping:
        resolved_path = module_mapping[module_name]
        exclude = ["images", "test", ".github", ".git", "change-notes", "swift", "cpp", "csharp", "ruby", "kotlin", "scala", "rust", "actions", "javascript", "python", "go", "php"]
        if resolved_path and not any(excluded in resolved_path for excluded in exclude):    
            return resolved_path
    return None

def find_context(file_path, base_path, visited=None, G=None, parent_module=None, level=0, missed_modules=None, all_files=None, module_mapping=None):
    """
    递归解析文件及其 import 树。
    构建 NetworkX 图对象。
    节点：完整文件路径
    边：当前文件 → 被导入模块
    """
    if visited is None:
        visited = set()
    if G is None:
        G = nx.DiGraph()
    if missed_modules is None:
        missed_modules = []
    if file_path in visited:
        return G, missed_modules
    visited.add(file_path)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[⚠️] 无法读取文件: {file_path} ({e})")
        return G, missed_modules
    current_module = os.path.relpath(file_path, base_path)
    print("  " * level + f"📄 {current_module}  |  {file_path} |")
    if parent_module:
        G.add_edge(parent_module, current_module)
    imports = parse_imports_from_content(content)
    for module_name in imports:
        resolved_path = resolve_import_path(module_name, all_files, module_mapping)
        if resolved_path:
            target_node = os.path.relpath(resolved_path, base_path)
            G.add_edge(current_module, target_node)
            base_dir = os.path.dirname(resolved_path)
            find_context(resolved_path, base_dir, visited, G, current_module, level + 1, missed_modules, all_files, module_mapping)
        else:
            print("  " * level + f"[⚠️] 未找到模块: {module_name} | import by {current_module}")
            missed_modules.append(module_name)
    return G, missed_modules

def visualize_dependency_graph(G, output_html="/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/KDB/XSS.html"):
    """使用 PyVis 生成交互式可视化 HTML 文件，并标记入度和出度最多的点"""
    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff", font_color="black")
    net.from_nx(G)
    in_degree_max_node = max(G.in_degree, key=lambda x: x[1])[0] if G.in_degree else None
    out_degree_max_node = max(G.out_degree, key=lambda x: x[1])[0] if G.out_degree else None
    for node in net.nodes:
        node["shape"] = "dot"
        node["size"] = 12
        node["color"] = "#8ecae6"
        if node["id"] == in_degree_max_node:
            node["color"] = "#ff0000"
            node["title"] = f"{node['id']} (入度最多)"
        if node["id"] == out_degree_max_node:
            node["color"] = "#ff0000"
            node["title"] = f"{node['id']} (出度最多)"
    net.toggle_physics(False)
    net.set_options("""
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "hubsize"
        }
      },
      "physics": {
        "enabled": false
      }
    }
    """)
    net.write_html(output_html)
    print(f"\n✅ 依赖图已生成: {output_html}")

def save_graph_to_json(G, output_path="XSS.json"):
    """将 NetworkX 图保存为 JSON 格式"""
    data = {
        "nodes": list(G.nodes),
        "edges": [{"source": u, "target": v} for u, v in G.edges]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ 图数据已保存为: {output_path}")

def save_missed_modules_to_json(missed_modules, output_path="/home/cbb/SAST-Rule-Migrate/Pretools/missed_modules.json"):
    """将未找到的模块保存为 JSON 文件"""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(missed_modules, f, ensure_ascii=False, indent=2)
    print(f"✅ 未找到的模块已保存为: {output_path}")

def print_in_out_degree_table(G):
    """打印入度和出度的表格"""
    print("\n📊 入度和出度表:")
    print(f"{'节点':<50}{'入度':<10}{'出度':<10}")
    print("-" * 70)
    for node in G.nodes:
        in_degree = G.in_degree(node)
        out_degree = G.out_degree(node)
        print(f"{node:<50}{in_degree:<10}{out_degree:<10}")

def main():
    entry_file = "/home/cbb/codeql/java/ql/lib/semmle/code/java/dataflow/ApiSources.qll"
    base_path = "/home/cbb/codeql/"
    print(f"开始解析入口文件: {entry_file}\n")
    visited = set()
    missed_modules = []
    codeqllist = []
    include = ["java", "shared"]
    exclude = ["images", "test", ".github", ".git", "change-notes", "swift", "cpp", "csharp", "ruby", "kotlin", "scala", "rust", "actions", "javascript", "python", "go", "php"]
    for root, dirs, files in os.walk("/home/cbb/codeql/"):
        for file in files:
            if file.endswith(".ql") or file.endswith(".qll"):
                full_path = os.path.join(root, file)
                if any(keyword in full_path for keyword in include) and not any(keyword in full_path for keyword in exclude):
                    codeqllist.append(full_path)
    codeql_list_path = "/home/cbb/SAST-Rule-Migrate/Pretools/codeql_list.txt"
    module_mapping_path = "/home/cbb/SAST-Rule-Migrate/Pretools/module_to_filepath.json"
    with open(codeql_list_path, "w", encoding="utf-8") as f:
        f.write("\n".join(codeqllist))
    print(f"📁 共收集 .ql 和 .qll 文件数: {len(codeqllist)}")
    module_mapping = load_module_mapping(module_mapping_path)
    # print(module_mapping)
    # print(f"📁 共加载模块映射数: {len(module_mapping)}")
    # path=resolve_import_path("PathGraph", codeqllist, module_mapping)
    # print(path)
    G, missed_modules = find_context(entry_file, base_path, visited, missed_modules=missed_modules, all_files=codeqllist, module_mapping=module_mapping)
    print(f"\n📁 共解析文件数: {len(visited)}")
    print(f"❌ 未找到的模块数: {len(missed_modules)}")
    save_missed_modules_to_json(missed_modules)
    visualize_dependency_graph(G)
    save_graph_to_json(G)

if __name__ == "__main__":
    main()