import json
from pyvis.network import Network
from collections import defaultdict
import os


def bfs_by_depth(graph, start_node_id, max_depth=3):
    visited = set()
    queue = [(start_node_id, 0)]
    related_nodes = set()
    related_edges = set()

    while queue:
        current, depth = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)
        related_nodes.add(current)

        if depth >= max_depth:
            continue

        for neighbor in graph[current]:
            related_edges.add((current, neighbor))
            queue.append((neighbor, depth + 1))

    return related_nodes, related_edges


def dfs_by_depth(graph, start_node_id, max_depth=3):
    visited = set()
    stack = [(start_node_id, 0)]
    related_nodes = set()
    related_edges = set()

    while stack:
        current, depth = stack.pop()

        if current in visited:
            continue

        visited.add(current)
        related_nodes.add(current)

        if depth >= max_depth:
            continue

        for neighbor in graph[current]:
            related_edges.add((current, neighbor))
            stack.append((neighbor, depth + 1))

    return related_nodes, related_edges


def compute_node_depths(start_node, related_edges):
    node_depths = {start_node: 0}
    changed = True

    # 多轮传播，递归计算每个节点的最小深度
    while changed:
        changed = False
        for src, dst in related_edges:
            if src in node_depths:
                expected_depth = node_depths[src] + 1
                if dst not in node_depths or expected_depth < node_depths[dst]:
                    node_depths[dst] = expected_depth
                    changed = True

    return node_depths


def visualize_graph(json_file, output_html, start_node,
                    by="bfs", max_depth=3):

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes = data["nodes"]
    edges = data["edges"]

    graph = defaultdict(list)
    for edge in edges:
        graph[edge["source"]].append(edge["target"])

    if start_node not in nodes:
        print(f"起始节点 {start_node} 不在图中！")
        return

    # 跳过特定节点
    skip_nodes = {"python/ql/lib/python.qll"}

    # BFS 或 DFS
    if by == "bfs":
        related_nodes, related_edges = bfs_by_depth(graph, start_node, max_depth)
    else:
        related_nodes, related_edges = dfs_by_depth(graph, start_node, max_depth)

    # 移除需要跳过的节点
    related_nodes = {node for node in related_nodes if node not in skip_nodes}
    related_edges = {(src, dst) for src, dst in related_edges if src not in skip_nodes and dst not in skip_nodes}

    # 计算节点深度
    node_depths = compute_node_depths(start_node, related_edges)

    # 创建图
    net = Network(
        height="1500px",
        width="2400px",
        directed=True,
        bgcolor="#ffffff",
        font_color="black",
        layout=True
    )
    net.toggle_physics(False)

    # 树状布局
    net.set_options('''
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "levelSeparation": 300,
          "nodeSpacing": 600,
          "treeSpacing": 500,
          "direction": "LR",
          "sortMethod": "directed"
        }
      }
    }
    ''')

    # 不再按层上色：全部统一颜色
    for node in related_nodes:
        net.add_node(
            node,
            label=os.path.basename(node),
            title=node,
            level=node_depths.get(node, 0)   # 关键：严格控制层高度
        )

    # 边
    for src, dst in related_edges:
        if src in related_nodes and dst in related_nodes:
            net.add_edge(src, dst)

    net.write_html(output_html, notebook=False)
    print(f"{by.upper()}（深度={max_depth}）层级可视化完成：{output_html}")


# 示例运行：只使用 BFS
if __name__ == "__main__":
    json_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/python_graphs/CookieInjection.ql_graph.json"
    output_html = "CookieInjection_layers_graph.html"
    start_node = "python/ql/src/Security/CWE-020/CookieInjection.ql"
    # start_node="python/ql/lib/semmle/python/Frameworks.qll"
    # start_node = "python/ql/lib/semmle/python/Concepts.qll"

    visualize_graph(
        json_file,
        output_html,
        start_node=start_node,
        by="dfs",       # 可改为 "dfs"
        max_depth=7
    )
