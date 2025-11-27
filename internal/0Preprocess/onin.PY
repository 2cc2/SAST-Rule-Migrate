import json
import os
from collections import defaultdict
language="java"
# 文件夹路径
dir_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{language}_graphs/"

# 保存统计结果的路径
output_path = f"/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/{language}_graphs_common_with_degrees.json"

# 初始化结果
all_nodes = []
all_edges = []

# 遍历目录下所有 JSON 文件
for filename in os.listdir(dir_path):
    if filename.endswith(".json"):
        file_path = os.path.join(dir_path, filename)
        
        # 读取 JSON 文件
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        # 提取 nodes 和 edges
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        
        # 将所有文件的 nodes 和 edges 添加到列表
        all_nodes.append(set(nodes))
        all_edges.append(set((edge["source"], edge["target"]) for edge in edges))

# 计算所有文件的 nodes 和 edges 的交集
common_nodes = set.intersection(*all_nodes) if all_nodes else set()
common_edges = set.intersection(*all_edges) if all_edges else set()

# 统计入度和出度
degree_stats = {node: {"in_degree": 0, "out_degree": 0} for node in common_nodes}
for edge in common_edges:
    source, target = edge
    if source in degree_stats:
        degree_stats[source]["out_degree"] += 1
    if target in degree_stats:
        degree_stats[target]["in_degree"] += 1

# 排序 degree_stats
sorted_degree_stats = sorted(degree_stats.items(), key=lambda x: (x[1]["in_degree"], -x[1]["out_degree"]))

# 保存结果到 JSON 文件
common_data = {
    "common_nodes": list(common_nodes),
    "common_edges": [{"source": edge[0], "target": edge[1]} for edge in common_edges],
    "degree_stats": {node: stats for node, stats in sorted_degree_stats}
}

with open(output_path, "w", encoding="utf-8") as output_file:
    json.dump(common_data, output_file, indent=4, ensure_ascii=False)

print(f"相同部分及排序后的入度出度统计已保存到 {output_path}")

# 去除各文件中不属于 common 的部分
filtered_files = []

for filename in os.listdir(dir_path):
    if filename.endswith(".json"):
        file_path = os.path.join(dir_path, filename)
        
        # 读取 JSON 文件
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        # 提取 nodes 和 edges
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        
        # 过滤掉不在 common_nodes 和 common_edges 中的内容
        filtered_nodes = [node for node in nodes if node not in common_nodes]
        filtered_edges = [edge for edge in edges if (edge["source"], edge["target"]) not in common_edges]
        
        # 保存过滤后的内容
        filtered_files.append({
            "file_path": file_path,
            "filtered_nodes": filtered_nodes,
            "filtered_edges": filtered_edges
        })

# 保存过滤结果到 JSON 文件
filtered_output_path = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/python_graphs_filtered.json"
with open(filtered_output_path, "w", encoding="utf-8") as output_file:
    json.dump(filtered_files, output_file, indent=4, ensure_ascii=False)

print(f"过滤后的文件内容已保存到 {filtered_output_path}")