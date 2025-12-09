import os
import json
import re
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(project_root)
from agent.llm_client import LLM

# 配置路径和模板
BASE_DIR = "/home/cbb/codeql/java/ql/src/Security/"
OUTPUT_FILE = "codeql_java_summary.json"

TEMPLATE = """
<input>
以下是一段 CodeQL 代码：
{code}
</input>
<task>
请你分析这段代码并完成以下任务：
1. 提取并总结该代码所涉及的 API 信息，包括：
   - 模块名（module）：代码所属的模块名称。
   - 导入的模块（imported modules）：代码中显式导入的模块。
   - 类名（classes）：代码中定义的类名称。
   - 谓词名（predicates）：代码中定义的谓词名称。
   - 相关的注释文档（comments）：代码中与模块、类、谓词相关的注释内容。
2. 分析 `from ... where` 查询语句，提取其中不同属性的变量及其使用的函数，并按属性归类。属性与函数的关系应明确标注。
3. 提取代码中涉及的安全相关标签及其联系：
   - `source`：标记为数据来源的代码片段。
   - `sink`：标记为数据流终点的代码片段。
   - `propagation`：标记为数据流传播的代码片段。
   - `sanitizer`：标记为数据清理的代码片段。
   - `link`：描述上述标签与导入模块及函数的关系，格式为：
     `标签::导入模块名::函数名`。
4. 按以下 JSON 格式输出总结结果：
</task>
<output>
请将总结结果以 JSON 格式输出，不要包含多余内容：
```json
{{
    "file": "<文件名>",
    "module": "<模块名>",
    "imports": ["导入模块1", "导入模块2"],
    "classes": ["类名1", "类名2"],
    "predicates": ["谓词名1", "谓词名2"],
    "doc": "<一句话总结规则功能，检测能力>",
    "from_where_usage": {{
        "属性1": ["函数1", "函数2"],
        "属性2": ["函数3"]
    }},
    "source": "<code>",
    "sink": "<code>",
    "propagation": "<code>",
    "sanitizer": "<code>",
    "link": [
        "sourcetag::导入模块名::函数名",
        "sinktag::导入模块名::函数名",
        "propagationtag::导入模块名::函数名",
        "sanitizertag::导入模块名::函数名"
    ],
    "tags": RULE（规则文件）|LIB（库文件）|ABSTRACT（抽象基类）,
    "summary": "<文件内容|如果是规则文件，则总结如何检测漏洞的，明确如何进行污点分析。|如果是库文件，则总结该库文件提供了哪些功能。>"
}}
    </output>
    """

llm = LLM(
    system_prompt="你擅长总结工具的语法规则",
    model="deepseek-v3",
    verbose=True
)

def process_file(path: str) -> dict:
    """
    处理单个文件，调用 LLM 并解析响应。
    """
    try:
        # 读取文件内容
        with open(path, encoding="utf-8", errors="ignore") as fp:
            content = fp.read()
        # 构建 prompt
        prompt = TEMPLATE.format(code=content, preserve_context=False)
        print(f"\n🧩 正在处理文件：{path}")
        # 调用 LLM
        response = llm.Summary(prompt=prompt, max_tokens=3000)
        # 解析 LLM 响应
        return parse_llm_response(response, path)
    except Exception as e:
        print(f"❌ 处理文件出错：{path}\n错误：{e}")
        return None

def parse_llm_response(response: str, path: str) -> dict:
    """
    解析 LLM 响应为 JSON 格式。
    """
    try:
        # 提取 JSON 代码块
        matches = re.findall(r"```json\n(.*?)```", response, re.DOTALL)
        if matches:
            response_json = matches[0].strip()
            parsed_response = json.loads(response_json)
            parsed_response["file"] = path
            print(f"✅ 已解析：{path}")
            return parsed_response
        else:
            print(f"⚠️ 未找到 JSON 代码块：{path}")
            return None
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON 解析失败：{path}\n错误：{e}")
        print(f"原始输出：\n{response[:300]}...")
        return None

def extract_codeql_api():
    """
    遍历目录，提取 CodeQL API 信息。
    """
    result = []
    file_count = 0
    for root, _, files in os.walk(BASE_DIR):
        for f in files:
            if f.endswith(".ql"):
                path = os.path.join(root, f)
                file_count += 1
                parsed_response = process_file(path)
                if parsed_response:
                    result.append(parsed_response)
    if not result:
        print("⚠️ 没有成功提取任何文件。请检查 LLM 响应格式。")
        return
    # 按文件名排序
    result.sort(key=lambda x: x.get("file", ""))
    # 保存结果到 JSON 文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n✅ 提取完成，共处理 {file_count} 个文件，成功解析 {len(result)} 个。结果已保存到 {OUTPUT_FILE}")

if __name__ == "__main__":
    extract_codeql_api()