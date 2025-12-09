import os
import sys
import csv
import networkx as nx
import json
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(project_root)

from agent.llm_client import LLMBot, Model
from collect import (
    find_context,
    resolve_import_path,
    load_module_mapping,
    save_missed_modules_to_json,
    read_csv,
    save_graph_to_json
)




if __name__ == "__main__":
    llm = LLMBot(
        system_prompt="You are a skilled vulnerability detection rule designer.",
        model="deepseek-v3",
    )

    language="java"
    # entry_dir = "/home/cbb/codeql/python/ql/src/Security/CWE-020/CookieInjection.ql"
    entry_dir = "/home/cbb/codeql/java/ql/src/Security/CWE/CWE-089/SqlTainted.ql"
    base_path = "/home/cbb/codeql/"
    print(f"开始解析入口目录: {entry_dir}\n")

    # ---------- 1. 读取 CSV 文件列表 ----------
    python_list_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/filelist/{language}.csv"
    shared_list_path="/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/filelist/shared.csv"
    relative_paths = read_csv(python_list_path)
    shared_list=read_csv(shared_list_path)
    relative_paths=relative_paths+shared_list
    base_dir = "/home/cbb/"
    absolute_paths = [os.path.join(base_dir, rel_path) for rel_path in relative_paths]

    # ---------- 2. 加载模块映射 ----------
    module_mapping_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/module_mappings/{language}_module_to_filepath.json"
    module_mapping = load_module_mapping(module_mapping_path)
    shared_path="/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/CodeqlPaser/module_mappings/shared_module_to_filepath.json"
    shared_mapping = load_module_mapping(shared_path)
    module_mapping.update(shared_mapping)  # 合并 shared_mapping
    print(f"📁 共加载模块映射数: {len(module_mapping)}\n")

    # ---------- 3. 遍历入口目录获取所有文件 ----------
    file_path = entry_dir
    # print(f"📄 找到入口目录下 {len(all_entry_files)} 个 QL/QLL 文件\n")

    # ---------- 4. 初始化 visited / missed_modules / Graph ----------
    visited = set()
    missed_modules = []
    G = nx.DiGraph()
    max_depth=1
    print(f"解析文件: {file_path}")
    G, missed_modules = find_context(
            file_path=file_path,
            base_path=base_path,
            visited=visited,
            G=G,
            missed_modules=missed_modules,
            all_files=absolute_paths,
            module_mapping=module_mapping,
            max_depth=max_depth
        )
    missed_modules = list(set(missed_modules))
    # ---------- 6. 保存结果 ----------
    print(f"\n📁 共解析文件数: {len(visited)}")
    print(visited)
    print(f"❌ 未找到的模块数: {len(missed_modules)}")
    # TAG:将图G和visited的代码给大模型让大模型返回组合好的结果
        # 为每个文件单独保存解析结果
    missed_modules_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{os.path.basename(file_path)}_missed.json"
    graph_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{os.path.basename(file_path)}_graph.json"

        # 确保目录存在
    os.makedirs(os.path.dirname(missed_modules_path), exist_ok=True)
    os.makedirs(os.path.dirname(graph_path), exist_ok=True)

    save_missed_modules_to_json(missed_modules, output_path=missed_modules_path,file_path=file_path)
    save_graph_to_json(G, output_path=graph_path,file_path=file_path)

    print(f"📁 文件 {file_path} 的未找到模块已保存到 {missed_modules_path}")
    print(f"📁 文件 {file_path} 的图数据已保存到 {graph_path}")

    # TAG: 将图 G 和 visited 的数据组合并返回给大模型
    # 1. 提取图的节点和边信息
    graph_data = {
        "nodes": list(G.nodes),
        "edges": [{"source": u, "target": v} for u, v in G.edges]
    }

    # 读取每个 visited 文件的内容并存储到 result_data
    visited_files_content = {}
    for file in visited:
        try:
            with open(file, "r", encoding="utf-8") as f:
                visited_files_content[file] = f.read()
        except Exception as e:
            print(f"[⚠️] 无法读取文件: {file} ({e})")

    # 2. 组合结果数据
    result_data = {
        "visited_files": list(visited),
        "graph": graph_data,
        "file_contents": visited_files_content  # 添加文件内容
    }

    # 3. 将结果保存为 JSON 文件
    result_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{os.path.basename(file_path)}_result{max_depth}.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)

    print(f"📁 文件 {file_path} 的组合结果已保存到 {result_path}")


