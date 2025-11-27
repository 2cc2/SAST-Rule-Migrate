from pyvis.network import Network
import networkx as nx
import json
import logging

def bfs(graph, start_node_id, max_depth=1):
    """
    使用广度优先搜索（BFS）遍历图，找到所有与起始节点相关的节点和边。
    可设置最大迭代深度（max_depth）。
    """
    visited = set()
    queue = [(start_node_id, 0)]  # 队列中存储 (节点, 当前深度)
    related_nodes = set()
    related_edges = set()

    while queue:
        current, depth = queue.pop(0)
        if current not in visited:
            visited.add(current)
            related_nodes.add(current)

            # 如果设置了最大深度且当前深度达到限制，则跳过
            if max_depth is not None and depth >= max_depth:
                continue

            for neighbor in graph.neighbors(current):
                related_edges.add((current, neighbor))
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

    return related_nodes, related_edges

def visualize_related_graph(graph_json_path: str, start_node_id: int, out_html: str = "graph.html", max_depth=1):
    """
    Visualize the related subgraph from the start node (N0) using PyVis (interactive web visualization).
    可设置最大迭代深度（max_depth）。
    """
    logging.info(f"Loading graph from {graph_json_path}")
    with open(graph_json_path, "r", encoding="utf-8") as f:
        graph = json.load(f)

    nodes = graph["nodes"]
    edges = graph["edges"]

    G = nx.DiGraph()

    # 添加所有节点到图中
    node_ids = {n["id"]: n for n in nodes}
    for n in nodes:
        label = f"{n['type']}: {n['name']}"
        title = f"<b>{n['type']}</b><br>{n.get('file', '')}<br><pre>{(n.get('doc') or '')[:500]}</pre>"
        color = {
            "class": "#90CAF9",
            "predicate": "#A5D6A7",
            "import": "#FFE082",
            "module": "#FFAB91"
        }.get(n["type"], "#E0E0E0")
        G.add_node(n["id"], label=label, title=title, color=color)

    # 添加所有边到图中
    for e in edges:
        G.add_edge(e["from"], e["to"], title=e.get("type", "related"))

    # 使用BFS算法提取与N0相关的节点和边
    related_nodes, related_edges = bfs(G, start_node_id, max_depth=max_depth)

    # 创建新的子图
    subgraph = G.subgraph(related_nodes)

    # 可视化
    net = Network(height="800px", width="100%", directed=True, notebook=False)
    net.from_nx(subgraph)
    net.toggle_physics(True)
    net.show(out_html, notebook=False)
    logging.info(f"Graph visualization written to {out_html}")

# 调用可视化函数
graph_json_path = "XSS_graph.json" 
start_node_id = "N0"  # N0的ID，选择起始节点
out_html = "XSS_graph_related_visualized.html"  # 输出的 HTML 可视化文件路径

# 调用可视化函数
visualize_related_graph(graph_json_path, start_node_id, out_html)
