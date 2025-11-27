import os
import re
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple

def safe_mkdir(p: str):
    os.makedirs(p, exist_ok=True)

def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

RE_KEEP = {
    "import": re.compile(r"^\s*import\s+([a-zA-Z0-9_.:]+)", re.M),
    "class": re.compile(r"^\s*class\s+([A-Za-z0-9_]+)(?:\s+extends\s+([A-Za-z0-9_.:]+))?", re.M),
    "predicate": re.compile(r"^\s*predicate\s+([A-Za-z0-9_]+)\s*\((.*?)\)", re.M | re.S),
    "function": re.compile(r"^\s*(?:predicate|function)\s+([A-Za-z0-9_]+)\s*\(", re.M)
}

def extract_top_comments(text: str, max_chars: int = 1000) -> str:
    """
    Extract leading doc comment blocks (/** ... */) or markdown front matter.
    """
    m = re.search(r"/\*\*(.*?)\*/", text, re.S)
    if m:
        s = m.group(1)
        return re.sub(r"\s+\*", "\n", s).strip()[:max_chars]
    m2 = re.search(r"^#.*\n(.{0,%d})" % max_chars, text, re.S)
    if m2:
        return m2.group(0).strip()
    return text.strip()[:max_chars]

def parse_codeql_dir(src_dir: str, out_graph_path: str):
    src = Path(src_dir)
    nodes = []
    edges = []
    node_id_counter = 0
    id_for = {}
    import_file_paths = set()
    missing_files = set()

    def _make_node(nodetype, name, file=None, snippet=None, doc=None, extra=None):
        nonlocal node_id_counter
        key = (nodetype, name, file)
        if key in id_for:
            return id_for[key]
        nid = f"N{node_id_counter}"
        node_id_counter += 1
        node = {
            "id": nid,
            "type": nodetype,
            "name": name,
            "file": file,
            "snippet": snippet or "",
            "doc": doc or "",
        }
        if extra:
            node.update(extra)
        nodes.append(node)
        id_for[key] = nid
        return nid

    
    def resolve_import_path(base_dir: str, imp_name: str, file_list: List[str]) -> str:
   
        parts = imp_name.split(".")
        relative_path = "/".join(parts) + ".qll"

    # 遍历文件列表，检查相对路径是否匹配
        for file in file_list:
            if relative_path in file:
                return file
    # 如果未找到匹配的文件，返回一个错误或警告
        return os.path.join(base_dir, relative_path)  # 返回预期路径，尽管文件可能不存在

    def parse_file(file_path: str):
        """解析单个文件并提取信息"""
        try:
            text = read_text_file(file_path)
        except FileNotFoundError:
            print(f"[⚠️ Missing] {file_path}")
            missing_files.add(file_path)  # 使用 set 来避免重复记录
            return

        rel = file_path
        module_id = _make_node(
            "module", rel, file=rel,
            snippet=(text if len(text) > 0 else ""),
            doc=extract_top_comments(text)
        )
        all_files = []
        for root, _, files in os.walk("/home/cbb/codeql/java/ql/lib"):
            for file in files:
                if file.endswith(('.qll', '.ql')):  # 只关心 .qll 和 .ql 文件
                    all_files.append(os.path.join(root, file))
        # 解析导入
        for m in RE_KEEP["import"].findall(text):
            imp = m.strip()
            imp_file = resolve_import_path("/home/cbb/codeql/java/ql/lib", imp,all_files)

            print(f"Resolving import: {imp_file}")
            
            if imp_file not in import_file_paths:
                import_file_paths.add(imp_file)
                try:
                    parse_file(imp_file)  # 递归解析导入的文件
                except Exception as e:
                    print(f"[⚠️ Import parse failed] {imp_file} -> {e}")
                    missing_files.add(imp_file)
            imp_id = _make_node("import", imp)
            edges.append({"from": module_id, "to": imp_id, "type": "imports"})

        # 类与继承
        for cname, extends in RE_KEEP["class"].findall(text):
            cid = _make_node("class", cname, file=rel, doc=extract_top_comments(text))
            edges.append({"from": module_id, "to": cid, "type": "defines"})
            if extends:
                ext_id = _make_node("class", extends)
                edges.append({"from": cid, "to": ext_id, "type": "extends"})

        # 谓词
        for pname, params in RE_KEEP["predicate"].findall(text):
            pid = _make_node(
                "predicate", pname, file=rel,
                snippet=text[:400],
                doc=extract_top_comments(text),
                extra={"params": params.strip()}
            )
            edges.append({"from": module_id, "to": pid, "type": "defines"})

    # 开始解析
    for p in src.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".qll", ".ql"}:
            parse_file(str(p))

    graph = {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "source_dir": str(src_dir),
            "file_count": len(nodes),
            "generated_at": time.time(),
            "missing_files": list(missing_files),  # 记录缺失文件
        },
    }

    # 保存图谱数据
    with open(out_graph_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)

    logging.info(
        f"Parsed {len(nodes)} nodes, {len(edges)} edges, "
        f"missing {len(missing_files)} imports. Graph saved to {out_graph_path}"
    )
    print(f"[✅ Done] Missing imports: {len(missing_files)} recorded.")
    print(missing_files)
    return out_graph_path


def main():
    # 设定要解析的源代码目录和输出的图谱文件路径
    src_dir = "/home/cbb/codeql/java/ql/src/Security/CWE/CWE-079/"  # 你的源码路径
    out_graph_path = "XSS_graph.json"  # 输出的图谱文件路径

    # 调用 `parse_codeql_dir` 来解析源码目录，并生成图谱文件
    parse_codeql_dir(src_dir, out_graph_path)

    # 输出解析后的图谱文件路径
    print(f"Graph has been saved to {out_graph_path}")


if __name__ == "__main__":
    main()
