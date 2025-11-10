# CodeQL Java API Knowledge-Graph Pipeline
一个完整的 Python 管线：从 `github/codeql` 仓库抓取 Java 标准库与文档 → 解析 `.qll/.ql/.md` 提取 API 节点与关系 → 将图谱导入 Neo4j → 为每个节点生成向量并建立本地 Faiss 向量索引以供 RAG/检索使用。

## 功能概览
- `clone`：克隆 / 更新官方 CodeQL 仓库（仅指定路径子目录）
- `parse`：解析指定目录下的 `.qll`, `.ql`, `.md` 文件，抽取模块、类、predicate、imports、注释示例，输出 `graph.json`
- `neo4j_import`：把 `graph.json` 导入 Neo4j（创建节点与关系）
- `embed`：为图谱节点生成文本描述并调用 embedding API，保存 embeddings 与建立 Faiss 索引
- `serve_query`（辅助）：基于向量检索的简易查询示例（可扩展为后端服务）

---

## 要求（Environment / 安装）
推荐创建虚拟环境并安装依赖：

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install requests pygments neo4j openai faiss-cpu tqdm python-dotenv bs4
```

（注：如需替换 OpenAI 嵌入，可改用其他提供者；`faiss-cpu` 在某些平台要用 `pip install faiss-cpu`）

需要设置环境变量（或在 `.env` 文件中）：
- `NEO4J_URI`（例如 `bolt://localhost:7687`）
- `NEO4J_USER`
- `NEO4J_PASS`
- `OPENAI_API_KEY` （或其它 embedding 提供商的密钥）

---

## 使用说明（高层）
```bash
# 克隆 repo（或更新）
python codeql_kg_pipeline.py clone --repo github/codeql --branch main --target ./codeql_repo

# 解析 Java 库（ql/lib、ql/doc、ql/src）
python codeql_kg_pipeline.py parse --src /home/cbb/.codeql/packages/codeql --out graph.json

# 将图谱导入 Neo4j
python codeql_kg_pipeline.py neo4j_import --graph graph.json

# 为每个图谱节点生成 embedding 并建立 Faiss 索引
python codeql_kg_pipeline.py embed --graph graph.json --out_dir ./embeddings --model text-embedding-3-large
```



## 说明、改进与扩展建议

1. **解析器改进**  
   我给出的是“轻量正则”解析器，能快速抽取类/谓词/导入。为了更精确建议：
   - 用自定义 QL 解析器（更复杂）或把 `.qll` 预处理成 token 再精确抽取 predicate body；
   - 使用 `pyparsing`、antlr 等来写一个简易 QL 语法解析器。

2. **Neo4j 模式设计**  
   目前脚本将所有实体当作 `:Entity`，并按 `type` 添加标签（如 `:Entity:Predicate`）。在生产环境建议设计更细的 Node/Rel schema（例如 `:Module`, `:Class`, `:Predicate`），并加入 `module_name`, `signature`, `example` 等属性以便查询。

3. **Embedding 提供商**  
   我用 `openai.Embedding.create` 举例（`text-embedding-3-large`），你可替换成你自己的嵌入 API（或本地模型）。若需要对大规模节点做 embedding，建议分批并用并行请求和退避策略。

4. **向量库选择**  
   我用 Faiss 做示例（CPU 版本）；生产可选 Milvus、Weaviate、Chroma 等，取决于可扩展性和部署需求。

5. **安全与凭据**  
   把凭据放在 `.env` 或 CI secrets，脚本中不应明文保存。

6. **后续：构建 RAG Prompt**  
   - 检索 top-K 节点后用模板生成 prompt（把检索到的 node texts 作为上下文），交由 LLM 生成规则草案或审查现有规则。

---

## 最后
我已经把完整管线脚本给出，并包含 CLI 子命令：`clone` / `parse` / `neo4j_import` / `embed` / `serve_query`。  
如果你愿意，我可以继续：
- 把解析器升级为更精确的 QL AST 提取器（提取 predicate body、返回类型、示例、注释）；
- 提供 Neo4j import 的 Cypher schema（清晰的 labels/properties/indices）；
- 增加一个小型 Flask/FastAPI 服务，供 Agent 在生成规则时做 RAG 查询和引用文档片段。

你想先让我把解析器增强（更精确地抽取 predicate body / parameters / examples）还是把 Neo4j schema 优化并输出具体 Cypher？