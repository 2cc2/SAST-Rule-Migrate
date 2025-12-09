import json
from pyvis.network import Network
from collections import defaultdict
import os


def bfs_by_depth(graph, start_node_id, max_depth=3):
    """
    BFS 按“层数”做扩展（不会断边）
    返回：related_nodes, related_edges
    """
    visited = set()
    queue = [(start_node_id, 0)]  # (node, depth)

    related_nodes = set()
    related_edges = set()

    while queue:
        current, depth = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)
        related_nodes.add(current)

        # 深度限制
        if depth >= max_depth:
            continue

        # 遍历邻居
        for neighbor in graph[current]:
            related_edges.add((current, neighbor))
            queue.append((neighbor, depth + 1))

    return related_nodes, related_edges


def visualize_bfs_graph(json_file, output_html="graph_bfs.html", start_node=None, max_depth=3):
    # 读取 JSON
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    # 构建邻接表
    graph = defaultdict(list)
    for edge in edges:
        graph[edge["source"]].append(edge["target"])

    if start_node not in nodes:
        print(f"起始节点 {start_node} 不在图中！")
        return

    # BFS（按深度）
    related_nodes, related_edges = bfs_by_depth(graph, start_node, max_depth=max_depth)

    # 创建 pyvis 图
    net = Network(
        height="1500px",
        width="2400px",
        directed=True,
        bgcolor="#ffffff",
        font_color="black",
        layout=True  # 启用层次布局
    )
    net.toggle_physics(False)

    # 设置树状布局
    net.repulsion(node_distance=200, central_gravity=0.0, spring_length=100, spring_strength=0.05)

    # 为每一层设置颜色
    depth_colors = ["#FF5733", "#33FF57", "#3357FF", "#F3FF33", "#FF33A8"]  # 可扩展颜色列表

    # 计算每个节点的深度
    node_depths = {start_node: 0}
    for src, dst in related_edges:
        if src in node_depths:
            node_depths[dst] = node_depths[src] + 1

    # 添加节点（显示文件名 + hover 显示路径）
    for node in related_nodes:
        node_depth = node_depths.get(node, 0)
        color = depth_colors[node_depth % len(depth_colors)]  # 循环使用颜色

        net.add_node(
            node,
            label=os.path.basename(node),
            title=node,
            color=color
        )

    # 添加边（确保双方节点都存在）
    for src, dst in related_edges:
        if src in related_nodes and dst in related_nodes:
            net.add_edge(src, dst)

    # 输出 HTML（避免模板报错）
    net.write_html(output_html, notebook=False)
    print(f"BFS（深度={max_depth}）可视化完成：{output_html}")


# 示例运行
if __name__ == "__main__":
    json_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/python_graphs/CookieInjection.ql_graph.json"
    output_html = "CookieInjection_bfs_graph.html"
    start_node = "python/ql/src/Security/CWE-020/CookieInjection.ql"

    visualize_bfs_graph(
        json_file,
        output_html,
        start_node=start_node,
        max_depth=3
    )
