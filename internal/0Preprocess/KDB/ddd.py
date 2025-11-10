import json

def load_nodes(file_path):
    """加载 JSON 文件中的节点"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return set(data.get("nodes", []))
    except Exception as e:
        print(f"无法加载文件 {file_path}: {e}")
        return set()

def compare_graphs(file1, file2):
    """比较两个图的节点"""
    nodes1 = load_nodes(file1)
    nodes2 = load_nodes(file2)

    common_nodes = nodes1 & nodes2
    only_in_file1 = nodes1 - nodes2
    only_in_file2 = nodes2 - nodes1

    print(f"两个图共有 {len(common_nodes)} 个相同的节点:")
    for node in common_nodes:
        print(f"- {node}")

    print(f"\n仅在 {file1} 中的节点 ({len(only_in_file1)}):")
    for node in only_in_file1:
        print(f"- {node}")

    print(f"\n仅在 {file2} 中的节点 ({len(only_in_file2)}):")
    for node in only_in_file2:
        print(f"- {node}")

if __name__ == "__main__":
    # 替换为实际的文件路径
    file1 = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/KDB/XSS.json"
    file2 = "/home/cbb/SAST-Rule-Migrate/internal/0Preprocess/KDB/graphSQL.json"
    compare_graphs(file1, file2)