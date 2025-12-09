import os
import re
import json
import networkx as nx
import csv
from pyvis.network import Network
def read_csv(file_path):
    """读取 CSV 文件并返回相对路径列表"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # 跳过表头
            return [row[0] for row in reader if row]
    except Exception as e:
        print(f"❌ 无法读取 CSV 文件：{file_path}\n错误：{e}")
        return []
# def parse_imports_from_content(content):
#     """从文件内容中提取 import 模块名"""
#     return re.findall(r"import\s+([\w.]+)", content)

def parse_imports_from_content(content):
    """从文件内容中提取 import 模块名，忽略注释"""
    # 去掉多行注释 /* ... */
    content_no_block_comments = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    # 去掉单行注释 //
    content_no_comments = re.sub(r"//.*", "", content_no_block_comments)
    # 匹配 import 语句
    imports = re.findall(r"\bimport\s+([\w.]+)", content_no_comments)
    return imports

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
        if resolved_path:    
            return resolved_path
    return None

def find_context(
    file_path,
    base_path,
    visited=None,
    G=None,
    parent_module=None,
    level=0,
    missed_modules=None,
    all_files=None,
    module_mapping=None,
    max_depth=None  # 新增参数：最大深度
):
    """
    递归解析 QL / QLL 文件的 import 关系，构建 NetworkX 有向图。

    优化内容：
    - 在开始任何逻辑前优先判断 file_path 是否在 all_files 中
    - 修复 base_path 不应在递归中不断改变的问题
    - 结构更简单、可维护
    """

    # ---------- 0. 初始化结构 ----------
    if visited is None:
        visited = set()
    if G is None:
        G = nx.DiGraph()
    if missed_modules is None:
        missed_modules = []
    if all_files is None:
        raise ValueError("❌ all_files 不能为空，必须提供用于解析 import 的文件列表")

    # ---------- 1. 文件存在性判断 ----------
    if file_path not in all_files:
        print(f"[⛔] 跳过：文件不在 all_files 列表中 → {file_path}")
        return G, missed_modules

    # ---------- 2. 避免重复解析 ----------
    if file_path in visited:
        return G, missed_modules
    visited.add(file_path)

    # ---------- 3. 深度限制 ----------
    if max_depth is not None and level > max_depth:
        return G, missed_modules
    
    # ---------- 4. 读取文件 ----------
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[⚠️] 无法读取文件: {file_path} ({e})")
        return G, missed_modules

    # 当前模块的相对路径（以 base_path 为根）
    current_module = os.path.relpath(file_path, base_path)
    print("  " * level + f"📄 {current_module}  |  {file_path} |")
    # ---------- 5. 如果有父模块，则记录依赖边 ----------
    if parent_module:
        G.add_edge(parent_module, current_module)

    # ---------- 6. 解析 imports ----------
    imports = parse_imports_from_content(content)

    for module_name in imports:

        # 如果模块名是 "python"，跳过解析
        if module_name == "python":
            print("  " * level + f"[跳过] 模块名为 'python'，不解析 | import by {current_module}")
            continue
        if module_name == "java":
            print("  " * level + f"[跳过] 模块名为 'java'，不解析 | import by {current_module}")
            continue
        # ---------- 6.1 解析 import 到文件路径 ----------
        resolved_path = resolve_import_path(module_name, all_files, module_mapping)

        if resolved_path:
            # 找到模块
            target_node = os.path.relpath(resolved_path, base_path)
            G.add_edge(current_module, target_node)

            # ---------- 6.2 递归解析 ----------
            find_context(
                resolved_path,
                base_path,        # ⚠ base_path 固定，不改变
                visited,
                G,
                current_module,
                level + 1,
                missed_modules,
                all_files,
                module_mapping,
                max_depth  # 传递最大深度
            )

        else:
            # 未找到模块
            print("  " * level + f"[⚠️] 未找到模块: {module_name} | import by {current_module}")
            missed_modules.append((current_module, module_name))

    return G, missed_modules

def save_missed_modules_to_json(missed_modules, output_path="/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/missed_modules.json", file_path=None):
    """将未找到的模块保存为 JSON 文件"""
    data = {
        "file_path": file_path,
        "missed_modules": missed_modules
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ 未找到的模块已保存为: {output_path}")

def save_graph_to_json(G, output_path="graphy.json", file_path=None):
    """将 NetworkX 图保存为 JSON 格式"""
    data = {
        "file_path": file_path,
        "nodes": list(G.nodes),
        "edges": [{"source": u, "target": v} for u, v in G.edges]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"✅ 图数据已保存为: {output_path}")

if __name__ == "__main__":
    main()