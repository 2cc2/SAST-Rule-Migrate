import json
from pyvis.network import Network

def visualize_graph(json_file, output_html="graph.html"):
    # 加载 JSON 数据
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    # 创建 pyvis 网络图
    net = Network(
        height="100%",
        width="100%",
        directed=True,
        bgcolor="#ffffff",
        font_color="black"
    )
    net.toggle_physics(False)  # 关闭物理效果以提高稳定性

    # 添加节点
    for node in nodes:
        net.add_node(
            node,
            label=node,  # 节点标签
            title=node   # 鼠标悬停显示完整信息
        )

    # 添加边
    for edge in edges:
        net.add_edge(edge["source"], edge["target"])

    # 输出 HTML 文件
    net.show(output_html, notebook=False)
    print(f"可视化完成，结果已保存到 {output_html}")

# 使用示例
if __name__ == "__main__":
    json_file = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/python_graphs/CookieInjection.ql_graph.json"
    output_html = "CookieInjection_graph.html"
    visualize_graph(json_file, output_html)