#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
codeql_kg_pipeline.py

Pipeline:
  - clone repo or fetch via GitHub API
  - parse ql/qll/md → produce graph.json { nodes: [...], edges: [...] }
  - import into Neo4j
  - embed node textual descriptions and build Faiss index
"""

import os
import re
import json
import time
import shutil
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# Neo4j
from neo4j import GraphDatabase

# OpenAI embeddings (example). You can replace with other providers.
import openai
import numpy as np
import faiss

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ---------------------------
# Utilities
# ---------------------------
def safe_mkdir(p: str):
    os.makedirs(p, exist_ok=True)

def read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

# ---------------------------
# Step 1: clone/update repo (simple using git CLI or GitHub API)
# ---------------------------
def clone_repo(repo: str, branch: str = "main", target: str = "./codeql_repo"):
    """
    repo: like "github/codeql"
    """
    target = Path(target)
    if target.exists():
        logging.info(f"Target {target} exists — attempting git pull")
        # try to pull
        try:
            import subprocess
            subprocess.run(["git", "-C", str(target), "fetch", "--all"], check=True)
            subprocess.run(["git", "-C", str(target), "checkout", branch], check=True)
            subprocess.run(["git", "-C", str(target), "pull", "origin", branch], check=True)
            return str(target)
        except Exception as e:
            logging.warning(f"Git pull failed: {e}. Will attempt clone to temp.")
            temp = target.parent / (target.name + "_tmp")
            if temp.exists():
                shutil.rmtree(temp)
            subprocess.run(["git", "clone", "--branch", branch, f"https://github.com/{repo}.git", str(temp)], check=True)
            if target.exists():
                shutil.rmtree(target)
            temp.rename(target)
            return str(target)
    else:
        logging.info(f"Cloning https://github.com/{repo}.git → {target}")
        import subprocess
        subprocess.run(["git", "clone", "--branch", branch, f"https://github.com/{repo}.git", str(target)], check=True)
        return str(target)

# ---------------------------
# Step 2: parse repository for .qll .ql .md files and extract API info
# ---------------------------
RE_KEEP = {
    "import": re.compile(r"^\s*import\s+([a-zA-Z0-9_.:]+)", re.M),
    "class": re.compile(r"^\s*class\s+([A-Za-z0-9_]+)(?:\s+extends\s+([A-Za-z0-9_.:]+))?", re.M),
    "predicate": re.compile(r"^\s*predicate\s+([A-Za-z0-9_]+)\s*\((.*?)\)", re.M | re.S),
    "function": re.compile(r"^\s*(?:predicate|function)\s+([A-Za-z0-9_]+)\s*\(", re.M)
}

def extract_top_comments(text: str, max_chars: int = 1000) -> str:
    """
    try to extract leading doc comment blocks (/** ... */) or markdown front matter
    """
    # ql-style comment: /** ... */
    m = re.search(r"/\*\*(.*?)\*/", text, re.S)
    if m:
        s = m.group(1)
        return re.sub(r"\s+\*", "\n", s).strip()[:max_chars]
    # markdown header
    m2 = re.search(r"^#.*\n(.{0,%d})" % max_chars, text, re.S)
    if m2:
        return m2.group(0).strip()
    # fallback: first 300 chars
    return text.strip()[:max_chars]

def parse_codeql_dir(src_dir: str, out_graph_path: str):
    """
    Walk src_dir and parse files. Produce graph.json:
    {
      nodes: [{ id, type, name, file, snippet, doc }],
      edges: [{ from, to, type }]
    }
    Node types: module(file), class, predicate, docpage
    Edge types: imports, extends, defines, calls (best-effort)
    """
    src = Path(src_dir)
    nodes = []
    edges = []
    node_id_counter = 0
    id_for = {}  # mapping (type,name,maybefile) -> id

    def _make_node(nodetype, name, file=None, snippet=None, doc=None, extra=None):
        nonlocal node_id_counter
        key = (nodetype, name, file)
        if key in id_for:
            return id_for[key]
        nid = f"N{node_id_counter}"
        node_id_counter += 1
        node = {"id": nid, "type": nodetype, "name": name, "file": file, "snippet": snippet or "", "doc": doc or ""}
        if extra:
            node.update(extra)
        nodes.append(node)
        id_for[key] = nid
        return nid

    # walk files
    file_count = 0
    for p in src.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".qll", ".ql"}:
            file_count += 1
            text = read_text_file(str(p))
            rel = str(p.relative_to(src_dir))
            module_id = _make_node("module", rel, file=rel, snippet=(text[:800] if len(text)>0 else ""), doc=extract_top_comments(text))
            # imports
            for m in RE_KEEP["import"].findall(text):
                imp = m.strip()
                # create import node
                imp_id = _make_node("import", imp)
                edges.append({"from": module_id, "to": imp_id, "type": "imports"})
            # classes
            for c in RE_KEEP["class"].findall(text):
                cname = c[0]
                extends = c[1] if c[1] else None
                cid = _make_node("class", cname, file=rel, doc=extract_top_comments(text))
                edges.append({"from": module_id, "to": cid, "type": "defines"})
                if extends:
                    # create extends node if not exists
                    ext_id = _make_node("class", extends)
                    edges.append({"from": cid, "to": ext_id, "type": "extends"})
            # predicates
            for ptn in RE_KEEP["predicate"].findall(text):
                pname = ptn[0]
                params = ptn[1].strip()
                pid = _make_node("predicate", pname, file=rel, snippet=text[:400], doc=extract_top_comments(text), extra={"params": params})
                edges.append({"from": module_id, "to": pid, "type": "defines"})
            # best-effort: calls (predicate calling other predicates) using simple pattern
            for call in re.findall(r"([A-Za-z0-9_]+)\s*\(", text):
                # if call matches a known predicate name, link
                # we will build calls later once predicate names collected
                pass

    # OPTIONAL: second pass to detect calls inside predicate bodies (best-effort)
    # Build a name set of predicates
    predicate_names = {n["name"] for n in nodes if n["type"] == "predicate"}
    # second pass to find calls
    for node in nodes:
        if node["type"] == "predicate" and node.get("file"):
            file_path = Path(src_dir) / node["file"]
            try:
                txt = read_text_file(str(file_path))
            except Exception:
                continue
            # find functions called inside definition (naive)
            body_snippet = txt  # could narrow to the predicate body with better parsing
            calls = set(re.findall(r"\b([A-Za-z0-9_]+)\s*\(", body_snippet))
            for c in calls:
                if c in predicate_names and c != node["name"]:
                    # find target id
                    tid = id_for.get(("predicate", c, None))
                    if not tid:
                        # try any file
                        tid = next((v for k,v in id_for.items() if k[0]=="predicate" and k[1]==c), None)
                    if tid:
                        edges.append({"from": node["id"], "to": tid, "type": "calls"})
    graph = {"nodes": nodes, "edges": edges, "metadata": {"source_dir": str(src_dir), "file_count": file_count, "generated_at": time.time()}}
    # write out
    with open(out_graph_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)
    logging.info(f"Parsed {file_count} files -> graph saved to {out_graph_path} (nodes={len(nodes)}, edges={len(edges)})")
    return out_graph_path

# ---------------------------
# Step 3: Import into Neo4j
# ---------------------------
def neo4j_import(graph_json_path: str, neo4j_uri: str, user: str, password: str, batch: int = 200):
    logging.info("Connecting to Neo4j...")
    driver = GraphDatabase.driver(neo4j_uri, auth=(user, password))
    graph = json.load(open(graph_json_path, "r", encoding="utf-8"))
    nodes = graph["nodes"]
    edges = graph["edges"]
    logging.info(f"Importing {len(nodes)} nodes and {len(edges)} edges into Neo4j")
    with driver.session() as session:
        # create constraints (id uniqueness)
        try:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE")
        except Exception as e:
            logging.debug(f"Constraint creation may have failed: {e}")
        # create nodes in batches
        for i in range(0, len(nodes), batch):
            batch_nodes = nodes[i:i+batch]
            tx = session.begin_transaction()
            for n in batch_nodes:
                # each node as :Entity with labels by type
                labels = ":" + n["type"].capitalize() if n.get("type") else ""
                props = {k: v for k, v in n.items() if k not in {"id", "type"}}
                # build cypher
                cypher = f"MERGE (e:Entity{labels} {{ id: $id }}) SET e += $props"
                tx.run(cypher, id=n["id"], props=props)
            tx.commit()
        # create edges
        for i in range(0, len(edges), batch):
            batch_edges = edges[i:i+batch]
            tx = session.begin_transaction()
            for e in batch_edges:
                cypher = """
                        MATCH (a:Entity {id:$from_id}), (b:Entity {id:$to_id})
                        MERGE (a)-[r:REL {type:$rel_type}]->(b)
                        SET r.count = coalesce(r.count,0) + 1
                        """
                tx.run(
                        cypher,
                        from_id=e["from"],
                        to_id=e["to"],
                        rel_type=e.get("type", "related")
                    )
            tx.commit()
    driver.close()
    logging.info("Neo4j import finished.")

# ---------------------------
# Step 4: Embeddings + Faiss index
# ---------------------------
def default_node_text(node: Dict[str,Any]) -> str:
    parts = [f"TYPE: {node.get('type')}", f"NAME: {node.get('name')}"]
    if node.get("file"):
        parts.append(f"FILE: {node.get('file')}")
    doc = node.get("doc") or ""
    if doc:
        parts.append("DOC: " + doc.strip())
    snippet = node.get("snippet") or ""
    if snippet:
        parts.append("SNIPPET: " + snippet.strip()[:500])
    # include params if predicate
    if node.get("params"):
        parts.append("PARAMS: " + node.get("params"))
    return "\n".join(parts)

def embed_nodes_and_build_faiss(graph_json_path: str, out_dir: str, openai_model: str = "text-embedding-3-large", batch_size: int = 32):
    """
    For each node produce a textual description, get embedding, store metadata and build Faiss index.
    """
    graph = json.load(open(graph_json_path, "r", encoding="utf-8"))
    nodes = graph["nodes"]
    texts = [default_node_text(n) for n in nodes]
    ids = [n["id"] for n in nodes]

    # set OpenAI key from env
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not set in environment")
    openai.api_key = openai_api_key

    # create output dirs
    safe_mkdir(out_dir)
    meta_dir = Path(out_dir) / "meta"
    safe_mkdir(str(meta_dir))

    # embeddings list
    all_embs = []
    # batch call OpenAI embeddings
    for i in tqdm(range(0, len(texts), batch_size), desc="Embedding batches"):
        batch_texts = texts[i:i+batch_size]
        # NOTE: using OpenAI python lib -- adjust if using another provider
        resp = openai.Embedding.create(model=openai_model, input=batch_texts)
        batch_emb = [r["embedding"] for r in resp["data"]]
        all_embs.extend(batch_emb)
        time.sleep(0.1)  # gentle

    dim = len(all_embs[0])
    # build Faiss index
    index = faiss.IndexFlatL2(dim)
    arr = np.array(all_embs).astype('float32')
    index.add(arr)
    faiss.write_index(index, os.path.join(out_dir, "faiss.index"))

    # save metadata mapping
    mapping = {"ids": ids, "texts": texts}
    with open(os.path.join(out_dir, "mapping.json"), "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False)
    logging.info(f"Built Faiss index with {len(ids)} vectors (dim={dim}) at {out_dir}")

# ---------------------------
# Step 5: Simple retrieval helper
# ---------------------------
def retrieve_similar(query: str, faiss_index_path: str, mapping_json: str, top_k: int = 5, openai_model: str = "text-embedding-3-large"):
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    openai.api_key = openai_api_key
    qemb = openai.Embedding.create(model=openai_model, input=[query])["data"][0]["embedding"]
    idx = faiss.read_index(faiss_index_path)
    D, I = idx.search(np.array([qemb]).astype('float32'), top_k)
    mapping = json.load(open(mapping_json, "r", encoding="utf-8"))
    results = []
    for dist, idxi in zip(D[0], I[0]):
        if idxi < 0:
            continue
        results.append({"id": mapping["ids"][idxi], "text": mapping["texts"][idxi], "score": float(dist)})
    return results
# ---------------------------
# Step 6: Visualization
# ---------------------------
from pyvis.network import Network
import networkx as nx

def visualize_graph(graph_json_path: str, out_html: str = "graph.html", max_nodes: int = 800):
    """
    Visualize the graph.json using PyVis (interactive web visualization)
    """
    logging.info(f"Loading graph from {graph_json_path}")
    with open(graph_json_path, "r", encoding="utf-8") as f:
        graph = json.load(f)

    nodes = graph["nodes"]
    edges = graph["edges"]

    # Reduce size for visualization if too big
    if len(nodes) > max_nodes:
        logging.warning(f"Graph too large ({len(nodes)} nodes) — only displaying first {max_nodes}")
        nodes = nodes[:max_nodes]
        node_ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["from"] in node_ids and e["to"] in node_ids]

    G = nx.DiGraph()

    # Add nodes
    for n in nodes:
        label = f"{n['type']}: {n['name']}"
        title = f"<b>{n['type']}</b><br>{n.get('file','')}<br><pre>{(n.get('doc') or '')[:500]}</pre>"
        color = {
            "class": "#90CAF9",
            "predicate": "#A5D6A7",
            "import": "#FFE082",
            "module": "#FFAB91"
        }.get(n["type"], "#E0E0E0")
        G.add_node(n["id"], label=label, title=title, color=color)

    # Add edges
    for e in edges:
        G.add_edge(e["from"], e["to"], title=e.get("type","related"))

    net = Network(height="800px", width="100%", directed=True, notebook=False)
    net.from_nx(G)
    net.toggle_physics(True)
    net.show(out_html, notebook=False)
    logging.info(f"Graph visualization written to {out_html}")
# ---------------------------
# CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="CodeQL Java API Knowledge Graph Pipeline")
    sub = parser.add_subparsers(dest="cmd")

    p_clone = sub.add_parser("clone")
    p_clone.add_argument("--repo", default="github/codeql")
    p_clone.add_argument("--branch", default="main")
    p_clone.add_argument("--target", default="./codeql_repo")

    p_parse = sub.add_parser("parse")
    p_parse.add_argument("--src", required=True)
    p_parse.add_argument("--out", default="graph.json")

    p_neo = sub.add_parser("neo4j_import")
    p_neo.add_argument("--graph", required=True)
    p_neo.add_argument("--uri", default=os.environ.get("NEO4J_URI"))
    p_neo.add_argument("--user", default=os.environ.get("NEO4J_USER"))
    p_neo.add_argument("--password", default=os.environ.get("NEO4J_PASS"))

    p_embed = sub.add_parser("embed")
    p_embed.add_argument("--graph", required=True)
    p_embed.add_argument("--out_dir", default="./embeddings")
    p_embed.add_argument("--model", default="text-embedding-3-large")

    p_query = sub.add_parser("serve_query")
    p_query.add_argument("--index", required=True)
    p_query.add_argument("--mapping", required=True)
    p_query.add_argument("--q", required=True)

    p_vis = sub.add_parser("visualize")
    p_vis.add_argument("--graph", required=True)
    p_vis.add_argument("--out", default="graph.html")

    args = parser.parse_args()
    if args.cmd == "clone":
        clone_repo(args.repo, args.branch, args.target)
    elif args.cmd == "parse":
        parse_codeql_dir(args.src, args.out)
    elif args.cmd == "neo4j_import":
        if not args.uri or not args.user or not args.password:
            raise RuntimeError("NEO4J_URI/NEO4J_USER/NEO4J_PASS must be provided as args or env vars")
        neo4j_import(args.graph, args.uri, args.user, args.password)
    elif args.cmd == "embed":
        embed_nodes_and_build_faiss(args.graph, args.out_dir, openai_model=args.model)
    elif args.cmd == "serve_query":
        res = retrieve_similar(args.q, args.index, args.mapping)
        print(json.dumps(res, indent=2, ensure_ascii=False))
    elif args.cmd == "visualize":
        visualize_graph(args.graph, args.out)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()