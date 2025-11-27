import os
import re
import json
import csv
import networkx as nx
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_imports_from_content(content):
    return re.findall(r"import\s+([\w.]+)", content)

def resolve_import_path(module_name, base_path):
    rel_path = module_name.replace('.', '/')
    for ext in [".ql", ".qll"]:
        module_path = os.path.join(base_path, rel_path + ext)
        if os.path.exists(module_path):
            return module_path
    return None

def find_context(file_path, base_path, visited=None, G=None, parent_module=None, level=0):
    """ 递归解析文件的依赖关系 """
    if visited is None:
        visited = set()
    if G is None:
        G = nx.DiGraph()

    if file_path in visited:
        return G
    visited.add(file_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[⚠️] 无法读取文件: {file_path} ({e})")
        return G

    current_module = os.path.relpath(file_path, base_path)
    print("  " * level + f"📄 {current_module}")
    if parent_module:
        G.add_edge(parent_module, current_module)

    imports = parse_imports_from_content(content)
    for module_name in imports:
        resolved_path = resolve_import_path(module_name, base_path)
        target_node = module_name.replace('.', '/') + ".qll"
        G.add_edge(current_module, target_node)

        if resolved_path:
            print("  " * level + f"├─ {module_name}")
            find_context(resolved_path, base_path, visited, G, current_module, level + 1)
        else:
            print("  " * level + f"[⚠️] 未找到模块: {module_name}")

    return G

def save_graph_to_json(G, output_path="SQL.json"):
    data = {
        "nodes": list(G.nodes),
        "edges": [{"source": u, "target": v} for u, v in G.edges]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ 图数据已保存为 JSON: {output_path}")

def save_degree_csv(G, output_path="degree.csv"):
    """保存每个节点的入度和出度为一个 CSV 文件（先按入度降序，再按出度降序排序）"""
    degree_data = [(node, G.in_degree(node), G.out_degree(node)) for node in G.nodes]
    degree_data.sort(key=lambda x: (x[1], x[2]), reverse=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["节点", "入度", "出度"])
        writer.writerows(degree_data)
    print(f"✅ 节点入度出度信息已按入度、出度降序排序并保存为 CSV: {output_path}")

def print_in_out_degree_table(G):
    print("\n📊 入度和出度表:")
    print(f"{'节点':<50}{'入度':<10}{'出度':<10}")
    print("-" * 70)
    for node in G.nodes:
        print(f"{node:<50}{G.in_degree(node):<10}{G.out_degree(node):<10}")

def collect_files_in_directory(base_dir, file_exts=[".ql", ".qll"]):
    """递归获取指定文件夹下的所有符合扩展名的文件"""
    files = []
    for root, dirs, files_in_dir in os.walk(base_dir):
        for file in files_in_dir:
            if any(file.endswith(ext) for ext in file_exts):
                files.append(os.path.join(root, file))
    return files

def process_file(entry_file, base_path):
    """处理单个文件，返回文件的图"""
    visited = set()
    G = find_context(entry_file, base_path, visited)
    return G

def process_all_files(base_dir, base_path):
    """使用线程池处理目录下的所有 .ql 和 .qll 文件"""
    all_files = collect_files_in_directory(base_dir)
    all_graph = nx.DiGraph()

    # 使用线程池并行处理每个文件
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_file, entry_file, base_path): entry_file for entry_file in all_files}
        
        for future in as_completed(futures):
            file = futures[future]
            try:
                G = future.result()
                print(f"文件 {file} 处理完成")
                # 合并图
                all_graph = nx.compose(all_graph, G)
            except Exception as e:
                print(f"[⚠️] 处理文件 {file} 时出错: {e}")

    return all_graph

def save_summary_csv(G, output_path="summary.csv"):
    """保存所有文件的入度和出度汇总到一个 CSV 文件"""
    summary_data = [(node, G.in_degree(node), G.out_degree(node)) for node in G.nodes]
    summary_data.sort(key=lambda x: (x[1], x[2]), reverse=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["节点", "入度", "出度"])
        writer.writerows(summary_data)
    print(f"✅ 所有文件的入度出度信息已保存为汇总 CSV: {output_path}")

def main():
    base_dir = "/home/cbb/codeql/java/ql/src/Security/CWE"  # 根目录
    base_path = "/home/cbb/codeql/java/ql/lib"  # 库路径

    print(f"开始处理目录: {base_dir}\n")
    
    # 处理所有文件
    G = process_all_files(base_dir, base_path)

    print(f"\n📁 共解析文件数: {len(G.nodes)}")
    
    save_graph_to_json(G, "full_dependency_graph.json")
    save_degree_csv(G, "full_degree.csv")
    print_in_out_degree_table(G)
    save_summary_csv(G, "full_summary.csv")

if __name__ == "__main__":
    main()
