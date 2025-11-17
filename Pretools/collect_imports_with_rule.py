import os
import re
import json
import networkx as nx
from pyvis.network import Network

def parse_imports_from_content(content):
    """从文件内容中提取 import 模块名"""
    return re.findall(r"import\s+([\w.]+)", content)

def resolve_import_path(module_name, base_path):
    """根据模块名查找实际文件路径 (.ql 或 .qll)"""
    rel_path = module_name.replace('.', '/')
    for ext in [".ql", ".qll"]:
        module_path = os.path.join(base_path, rel_path + ext)
        if os.path.exists(module_path):
            return module_path
    return None

def find_context(file_path, base_path, visited=None, G=None, parent_module=None, level=0, missed_modules=None):
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

    current_module = os.path.relpath(file_path, base_path)  # 使用相对路径作为模块标识
    print("  " * level + f"📄 {current_module}  |  {file_path} |")
    if parent_module:
        G.add_edge(parent_module, current_module)

    imports = parse_imports_from_content(content)
    for module_name in imports:
        # if module_name.startswith("java.") or module_name == "java":
        #     continue
        # elif module_name.startswith("semmle"):
        #     base_path = "/home/cbb/codeql/java/ql/lib"
    
        # elif module_name.startswith("codeql.util"):
        #     base_path = "/home/cbb/codeql/shared/util/"
        # elif module_name.startswith("codeql.ssa"):
        #     base_path = "/home/cbb/codeql/shared/ssa/"
        # elif module_name.startswith("codeql.controlflow.BasicBlock"):
        #     base_path = "/home/cbb/codeql/shared/controlflow/"
        # elif module_name.startswith("codeql.threatmodels.ThreatModels"):
        #     base_path = "/home/cbb/codeql/shared/threat-models/"
        # # elif module_name.startswith("FlowSummaryImpl"):
        # #     base_path = "/home/cbb/codeql/java/ql/lib/semmle/code/java/dataflow/internal/FlowSummaryImpl.qll"
        # elif module_name.startswith("codeql"):
        #     base_path = "/home/cbb/codeql"
        # 绝对路径
        if "." in module_name:
         
            if module_name.startswith("semmle"):
                base_path = "/home/cbb/codeql/java/ql/lib"
            elif module_name.startswith("codeql.util"):
                base_path = "/home/cbb/codeql/shared/util/"
            elif module_name.startswith("codeql.ssa"):
                base_path = "/home/cbb/codeql/shared/ssa/"
            elif module_name.startswith("codeql.controlflow.BasicBlock"):
                base_path = "/home/cbb/codeql/shared/controlflow/"
            elif module_name.startswith("codeql.threatmodels.ThreatModels"):
                base_path = "/home/cbb/codeql/shared/threat-models/"
            elif module_name.startswith("codeql.dataflow.internal"):
                base_path = "/home/cbb/codeql/shared/dataflow/"
                base_path = "/home/cbb/codeql/java/ql/lib/semmle/code/java/dataflow/internal/SsaImpl.qll"

        # elif module_name.startswith("codeql"):
        #     base_path = "/home/cbb/codeql"
        # 相对路径
        elif module_name.startswith("java.") or module_name == "java":
                base_path = "/home/cbb/codeql/java/ql/lib"
        else:
            base_path = os.path.dirname(file_path)

        resolved_path = resolve_import_path(module_name, base_path)
        if resolved_path:
            target_node = module_name.replace('.', '/') + ".qll"  # 使用模块路径作为标识
            G.add_edge(current_module, target_node)
            base_dir = os.path.dirname(resolved_path)
            find_context(resolved_path, base_dir, visited, G, current_module, level + 1, missed_modules)
        else:
            print("  " * level + f"[⚠️] 未找到模块: {module_name} | import by {current_module}")
            missed_modules.append(module_name)

    return G, missed_modules

def visualize_dependency_graph(G, output_html="/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/KDB/XSS.html"):
    """使用 PyVis 生成交互式可视化 HTML 文件，并标记入度和出度最多的点"""
    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff", font_color="black")
    net.from_nx(G)

    # 计算入度和出度最多的节点
    in_degree_max_node = max(G.in_degree, key=lambda x: x[1])[0] if G.in_degree else None
    out_degree_max_node = max(G.out_degree, key=lambda x: x[1])[0] if G.out_degree else None

    for node in net.nodes:
        node["shape"] = "dot"
        node["size"] = 12
        node["color"] = "#8ecae6"  # 默认颜色

        # 标记入度最多的节点为红色
        if node["id"] == in_degree_max_node:
            node["color"] = "#ff0000"  # 红色
            node["title"] = f"{node['id']} (入度最多)"

        # 标记出度最多的节点为红色
        if node["id"] == out_degree_max_node:
            node["color"] = "#ff0000"  # 红色
            node["title"] = f"{node['id']} (出度最多)"

    net.toggle_physics(False)
    net.options.physics = {
        "enabled": False
    }
    # 使用固定布局（层次结构布局）
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
    # 写入 HTML 文件
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

def save_missed_modules_to_json(missed_modules, output_path="/home/cbb/Pretools/missed_modules.json"):
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
    entry_file = "/home/cbb/codeql/java/ql/src/Security/CWE/CWE-079/XSS.ql"
    base_path = "/home/cbb/codeql/"

    print(f"开始解析入口文件: {entry_file}\n")
    visited = set()
    missed_modules = []
    G, missed_modules = find_context(entry_file, base_path, visited, missed_modules=missed_modules)

    print(f"\n📁 共解析文件数: {len(visited)}")
    print(f"❌ 未找到的模块数: {len(missed_modules)}")
    save_missed_modules_to_json(missed_modules)
    visualize_dependency_graph(G)
    save_graph_to_json(G)
    # print_in_out_degree_table(G)  # 打印入度和出度表

if __name__ == "__main__":
    main()