import os
import json
import glob
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Callable, Tuple, Union
from pathlib import Path

from b2rscan.llm_wrapper import LLMWrapper  # 你已有的封装
# 如果你有正式的 CodeQLRuleParser / IRConverter，后面可无缝换上

# -----------------------------
# xCPG-IR 简化版 JSON Schema（可按你的正式定义替换/扩展）
# -----------------------------
XCPG_IR_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["id", "name", "description", "severity", "sources", "sinks", "sanitizers", "validators"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "source": {"type": "string"},
            "pattern": {"type": "string"},
            "sources": {"type": "array", "items": {"type": "string"}},
            "sinks": {"type": "array", "items": {"type": "string"}},
            "sanitizers": {"type": "array", "items": {"type": "string"}},
            "validators": {"type": "array", "items": {"type": "string"}},
            "meta": {"type": "object"}
        },
        "additionalProperties": True
    }
}

# -----------------------------
# Tool 抽象与注册表
# -----------------------------
class ToolError(Exception):
    pass

@dataclass
class ToolResult:
    ok: bool
    content: Any
    error: Optional[str] = None

class Tool:
    name: str
    description: str

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        if tool.name in self._tools:
            raise ValueError(f"Tool {tool.name} already registered")
        self._tools[tool.name] = tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise ToolError(f"Unknown tool: {name}")
        return self._tools[name]

    def tool_specs_for_prompt(self) -> str:
        """
        给 LLM 的 tools 目录：名称 + 入参 + 返回。
        这里为简化，使用自然语言说明。你也可切换到函数调用/JSON模式。
        """
        lines = []
        for t in self._tools.values():
            lines.append(f"- {t.name}: {t.description}")
        return "\n".join(lines)

# -----------------------------
# 基础工具实现
# -----------------------------
class ListDirTool(Tool):
    name = "list_dir"
    description = "List files/directories under a path. Args: path:str, depth:int=2, include_hidden:bool=False"

    def run(self, **kwargs) -> ToolResult:
        path = Path(kwargs.get("path", ".")).resolve()
        depth = int(kwargs.get("depth", 2))
        include_hidden = bool(kwargs.get("include_hidden", False))
        if not path.exists():
            return ToolResult(False, None, f"path not found: {path}")

        res = []
        base_depth = len(path.parts)
        for p in path.rglob("*"):
            if not include_hidden and any(part.startswith(".") for part in p.parts):
                continue
            if len(p.parts) - base_depth <= depth:
                res.append(str(p))
        return ToolResult(True, res)

class ReadFileTool(Tool):
    name = "read_file"
    description = "Read a text file. Args: path:str, max_bytes:int=200000"

    def run(self, **kwargs) -> ToolResult:
        path = Path(kwargs.get("path", "")).resolve()
        max_bytes = int(kwargs.get("max_bytes", 200000))
        if not path.exists() or not path.is_file():
            return ToolResult(False, None, f"file not found: {path}")
        data = path.read_bytes()[:max_bytes]
        try:
            return ToolResult(True, data.decode("utf-8", errors="replace"))
        except Exception as e:
            return ToolResult(False, None, f"decode error: {e}")

class GlobSearchTool(Tool):
    name = "glob_search"
    description = "Find files by glob patterns. Args: root:str, patterns:List[str]"

    def run(self, **kwargs) -> ToolResult:
        root = Path(kwargs.get("root", ".")).resolve()
        patterns: List[str] = kwargs.get("patterns", ["**/*.yml", "**/*.yaml", "**/*.json", "**/*.ql"])
        if not root.exists():
            return ToolResult(False, None, f"root not found: {root}")
        results = set()
        for pat in patterns:
            for p in root.glob(pat):
                if p.is_file():
                    results.add(str(p))
        return ToolResult(True, sorted(results))

# -----------------------------
# 轻量规则解析工具（示例/可替换）
# -----------------------------
import yaml

class ParseSemgrepYAMLTool(Tool):
    name = "parse_semgrep_yaml"
    description = "Parse a Semgrep YAML rule file and extract rules. Args: path:str"

    def run(self, **kwargs) -> ToolResult:
        path = Path(kwargs.get("path", "")).resolve()
        if not path.exists():
            return ToolResult(False, None, f"file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules = data.get("rules", [])
            extracted = []
            for r in rules:
                rid = r.get("id") or r.get("rule", str(uuid.uuid4()))
                name = r.get("message", "")[:80] or r.get("id", "semgrep-rule")
                sev = (r.get("severity") or "medium").lower()
                patterns = r.get("patterns") or r.get("pattern") or ""
                # 极简抽取 sources/sinks（真实实现请根据 pattern-eq / pattern-sources 等完善）
                sources, sinks = [], []
                if "pattern-sources" in r:
                    sources = [str(x) for x in r["pattern-sources"]]
                if "pattern-sinks" in r:
                    sinks = [str(x) for x in r["pattern-sinks"]]
                extracted.append({
                    "id": str(rid),
                    "name": name,
                    "description": r.get("message", ""),
                    "severity": sev if sev in ["low","medium","high","critical"] else "medium",
                    "source": "semgrep",
                    "pattern": json.dumps(patterns) if isinstance(patterns, (list, dict)) else str(patterns),
                    "sources": sources,
                    "sinks": sinks,
                    "sanitizers": [],
                    "validators": [],
                    "meta": {"file": str(path)}
                })
            return ToolResult(True, extracted)
        except Exception as e:
            return ToolResult(False, None, f"semgrep parse error: {e}")

class ParseCodeQLQueryTool(Tool):
    name = "parse_codeql_ql"
    description = "Heuristically parse a CodeQL .ql file for basic metadata. Args: path:str"

    def run(self, **kwargs) -> ToolResult:
        """
        这里只做极简启发式解析：
        - 从注释和 select/where 附近抽 name/description/severity
        - 真实项目请替换为 CodeQL 官方解析或你已有的解析器
        """
        path = Path(kwargs.get("path", "")).resolve()
        if not path.exists():
            return ToolResult(False, None, f"file not found: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        # 简单启发：注释中的 @id @name @kind @severity
        rid = None
        name = None
        sev = "medium"
        desc = ""
        for line in text.splitlines():
            L = line.strip()
            if "@id" in L:
                rid = L.split("@id",1)[1].strip(": ").strip()
            if "@name" in L:
                name = L.split("@name",1)[1].strip(": ").strip()
            if "@kind" in L or "@problem.severity" in L or "@severity" in L:
                # 抓一个可能的枚举
                token = L.split()[-1].strip(": ").strip().lower()
                if token in ["low","medium","high","critical"]:
                    sev = token
            if L.startswith("//") and "@description" in L or "Description:" in L:
                desc = L.split(":",1)[1].strip()
        if not rid:
            rid = f"ql-{uuid.uuid4().hex[:8]}"
        if not name:
            name = rid
        return ToolResult(True, [{
            "id": rid,
            "name": name,
            "description": desc or f"CodeQL rule extracted from {path.name}",
            "severity": sev,
            "source": "codeql",
            "pattern": "heuristic-parsed-ql",
            "sources": [],
            "sinks": [],
            "sanitizers": [],
            "validators": [],
            "meta": {"file": str(path)}
        }])

# -----------------------------
# IR 映射 & Schema 校验 & 合并
# -----------------------------
class MapToXCPGIRTool(Tool):
    name = "map_to_xcpg_ir"
    description = "Map raw rule dict(s) to xCPG-IR fields and normalize. Args: rules:List[Dict]"

    def run(self, **kwargs) -> ToolResult:
        rules = kwargs.get("rules", [])
        mapped = []
        for r in rules:
            mapped.append({
                "id": str(r.get("id") or uuid.uuid4()),
                "name": str(r.get("name") or "Rule"),
                "description": str(r.get("description") or ""),
                "severity": r.get("severity") if r.get("severity") in ["low","medium","high","critical"] else "medium",
                "source": r.get("source") or "unknown",
                "pattern": r.get("pattern") or "",
                "sources": list(dict.fromkeys(r.get("sources") or [])),
                "sinks": list(dict.fromkeys(r.get("sinks") or [])),
                "sanitizers": list(dict.fromkeys(r.get("sanitizers") or [])),
                "validators": list(dict.fromkeys(r.get("validators") or [])),
                "meta": r.get("meta") or {}
            })
        return ToolResult(True, mapped)

class ValidateJSONSchemaTool(Tool):
    name = "validate_json_schema"
    description = "Validate a JSON array against xCPG-IR schema. Args: data:List[Dict]"

    def run(self, **kwargs) -> ToolResult:
        try:
            data = kwargs.get("data", [])
            # 极简校验（可换成 jsonschema 库）
            if not isinstance(data, list):
                return ToolResult(False, None, "not a list")
            for i, item in enumerate(data):
                for req in ["id","name","description","severity","sources","sinks","sanitizers","validators"]:
                    if req not in item:
                        return ToolResult(False, None, f"item[{i}] missing '{req}'")
                if item["severity"] not in ["low","medium","high","critical"]:
                    return ToolResult(False, None, f"item[{i}] invalid severity")
            return ToolResult(True, "ok")
        except Exception as e:
            return ToolResult(False, None, f"schema validate error: {e}")

class MergeDedupRulesTool(Tool):
    name = "merge_dedup_rules"
    description = "Merge and deduplicate rules by id or (name,source). Args: rules:List[Dict]"

    def run(self, **kwargs) -> ToolResult:
        rules: List[Dict[str, Any]] = kwargs.get("rules", [])
        seen: Dict[str, Dict[str, Any]] = {}
        for r in rules:
            key = r.get("id") or f"{r.get('name')}::{r.get('source')}"
            if key not in seen:
                seen[key] = r
            else:
                # 简单合并：集合并集
                for k in ["sources", "sinks", "sanitizers", "validators"]:
                    a = seen[key].get(k, [])
                    b = r.get(k, [])
                    seen[key][k] = list(dict.fromkeys((a or []) + (b or [])))
                # pattern/description 保留更长的
                if len(str(r.get("description",""))) > len(str(seen[key].get("description",""))):
                    seen[key]["description"] = r.get("description","")
                if len(str(r.get("pattern",""))) > len(str(seen[key].get("pattern",""))):
                    seen[key]["pattern"] = r.get("pattern","")
        return ToolResult(True, list(seen.values()))

# -----------------------------
# ReAct Agent 实现
# -----------------------------
class ReActAgent:
    """
    约定 LLM 单轮输出 JSON，如：
    {
      "thought": "We should scan repo for yaml and ql",
      "action": "glob_search",
      "action_input": {"root": "...", "patterns": ["**/*.yml","**/*.yaml","**/*.ql"]}
    }
    若要结束：
    {
      "thought": "We have final rules",
      "action": "finish",
      "action_input": {"result": [ ... xCPG-IR array ... ]}
    }
    """
    SYSTEM_PROMPT = """You are a senior security rule extraction agent using the ReAct pattern.
You'll reason step-by-step and decide which TOOL to call next, or FINISH with final JSON.

TOOLS you can use:
{tool_specs}

OUTPUT FORMAT (strict JSON, no extra text):
{{
  "thought": "your brief reasoning",
  "action": "<one of tool names or 'finish'>",
  "action_input": {{ ... }}
}}

Guidelines:
- Start by exploring repository structure, then locate rule files, then parse, map to xCPG-IR, merge & validate.
- Prefer small, targeted reads over huge files.
- Always produce valid JSON. No markdown, no commentary outside JSON.
"""

    def __init__(
        self,
        llm: LLMWrapper,
        tools: ToolRegistry,
        max_steps: int = 12,
        reflexion: bool = True
    ):
        self.llm = llm
        self.tools = tools
        self.max_steps = max_steps
        self.reflexion = reflexion
        self.trace: List[Dict[str, Any]] = []

    def _compose_prompt(self, user_task: str, scratch: str) -> str:
        return self.SYSTEM_PROMPT.format(tool_specs=self.tools.tool_specs_for_prompt()) + "\n" + \
            f"\nUSER TASK:\n{user_task}\n\n" + \
            ("SCRATCHPAD (previous thoughts/actions/observations):\n" + scratch if scratch else "")

    def run(self, user_task: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        scratch = ""
        final_rules: List[Dict[str, Any]] = []
        for step in range(1, self.max_steps + 1):
            prompt = self._compose_prompt(user_task, scratch)
            raw = self.llm.infer(prompt)
            # 容错：若不是 JSON，尝试截取 JSON 片段
            try:
                first_brace = raw.find("{")
                last_brace = raw.rfind("}")
                action_obj = json.loads(raw[first_brace:last_brace+1])
            except Exception as e:
                action_obj = {
                    "thought": "LLM returned non-JSON; fallback to finish with no result",
                    "action": "finish",
                    "action_input": {"result": []}
                }

            thought = action_obj.get("thought", "")
            action = action_obj.get("action", "")
            action_input = action_obj.get("action_input", {})

            if action == "finish":
                result = action_input.get("result", [])
                final_rules = result if isinstance(result, list) else []
                self.trace.append({
                    "step": step, "thought": thought, "action": action,
                    "input": action_input, "observation": f"Finished with {len(final_rules)} rules"
                })
                break

            if not self.tools.has(action):
                obs = f"Unknown tool: {action}"
                self.trace.append({
                    "step": step, "thought": thought, "action": action,
                    "input": action_input, "observation": obs
                })
                scratch += f"\nTHOUGHT: {thought}\nACTION: {action}\nOBSERVATION: {obs}\n"
                continue

            tool = self.tools.get(action)
            result = tool.run(**action_input)
            obs = result.content if result.ok else f"ERROR: {result.error}"

            # 将 observation 截断，避免 prompt 过大
            obs_str = obs if isinstance(obs, str) else json.dumps(obs)[:8000]
            self.trace.append({
                "step": step, "thought": thought, "action": action,
                "input": action_input, "observation": obs_str
            })
            scratch += f"\nTHOUGHT: {thought}\nACTION: {action}\nOBSERVATION: {obs_str}\n"

        return final_rules, self.trace

# -----------------------------
# 你的 RuleExtractor → 使用 ReActAgent
# -----------------------------
class RuleExtractor:
    def __init__(self, config_path: Optional[str] = None):
        self.llm_client = LLMWrapper("dashscope")
        self.tools = ToolRegistry()
        # 注册工具
        self.tools.register(ListDirTool())
        self.tools.register(ReadFileTool())
        self.tools.register(GlobSearchTool())
        self.tools.register(ParseSemgrepYAMLTool())
        self.tools.register(ParseCodeQLQueryTool())
        self.tools.register(MapToXCPGIRTool())
        self.tools.register(ValidateJSONSchemaTool())
        self.tools.register(MergeDedupRulesTool())

        self.agent = ReActAgent(self.llm_client, self.tools, max_steps=12)

    def _post_validate_and_fix(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # 规范化 + 去重 + 校验
        mapped = self.tools.get("map_to_xcpg_ir").run(rules=rules)
        if not mapped.ok:
            raise ToolError(mapped.error or "map_to_xcpg_ir failed")

        merged = self.tools.get("merge_dedup_rules").run(rules=mapped.content)
        if not merged.ok:
            raise ToolError(merged.error or "merge_dedup_rules failed")

        valid = self.tools.get("validate_json_schema").run(data=merged.content)
        if not valid.ok:
            # 最小修复：不合规的 severity 统一成 medium；缺字段补空
            fixed = []
            for r in merged.content:
                r.setdefault("description", "")
                r.setdefault("sources", [])
                r.setdefault("sinks", [])
                r.setdefault("sanitizers", [])
                r.setdefault("validators", [])
                if r.get("severity") not in ["low","medium","high","critical"]:
                    r["severity"] = "medium"
                fixed.append(r)
            # 再校验一次
            valid2 = self.tools.get("validate_json_schema").run(data=fixed)
            if not valid2.ok:
                raise ToolError(valid2.error or "schema validate failed")
            return fixed
        return merged.content

    def extract_rules(self, sast_tool: str, source_path: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        if options is None:
            options = {}

        # 用户任务指令（给 ReAct）
        user_task = f"""
Goal: Extract security rules from the repository and convert them to xCPG-IR.

Context:
- SAST tool: {sast_tool}
- Repo path: {Path(source_path).resolve()}
- Hints:
  * Common rule locations: rules/, queries/, patterns/, detections/
  * File types: .yml, .yaml, .json (Semgrep), .ql (CodeQL)
  * For Semgrep: parse YAML -> id/name/message/severity/patterns/(sources|sinks)
  * For CodeQL: heuristically parse .ql headers/comments for id/name/severity/description

Plan:
1) Explore repo (list_dir, glob_search)
2) For each candidate file: read_file -> parse_semgrep_yaml or parse_codeql_ql
3) Map to xCPG-IR (map_to_xcpg_ir)
4) Merge & dedup (merge_dedup_rules)
5) Validate (validate_json_schema)
6) FINISH with JSON array

Output:
- FINISH only when you have a JSON array of xCPG-IR rules (no extra text).
- Keep each step concise, always return strict JSON with fields [thought, action, action_input].
Options: {json.dumps(options, ensure_ascii=False)}
"""

        # 运行 ReAct
        react_rules, trace = self.agent.run(user_task)

        # 容错：若 LLM 没有 finish 出结果或结果为空，降级为“脚手架直线流程”
        if not react_rules:
            # 兜底：直接扫描 + 尝试解析
            glob_res = self.tools.get("glob_search").run(
                root=source_path,
                patterns=["**/*.yml", "**/*.yaml", "**/*.json", "**/*.ql"]
            )
            candidates = glob_res.content if glob_res.ok else []
            raw_rules: List[Dict[str, Any]] = []
            for f in candidates:
                if f.endswith((".yml", ".yaml")):
                    pr = self.tools.get("parse_semgrep_yaml").run(path=f)
                    if pr.ok and isinstance(pr.content, list):
                        raw_rules.extend(pr.content)
                elif f.endswith(".ql"):
                    pr = self.tools.get("parse_codeql_ql").run(path=f)
                    if pr.ok and isinstance(pr.content, list):
                        raw_rules.extend(pr.content)
            react_rules = raw_rules

        # 统一后处理（Schema 校验 + 去重）
        rules = self._post_validate_and_fix(react_rules)

        # 可选：打印一份简短 trace，便于调试
        # for t in trace[-3:]:
        #     print(f"[step {t['step']}] {t['thought']} -> {t['action']} :: obs(len)={len(str(t['observation']))}")

        return rules

# -----------------------------
# Demo
# -----------------------------
if __name__ == "__main__":
    extractor = RuleExtractor()
    rules = extractor.extract_rules("codeql", "sast/codeql")
    print(json.dumps(rules, ensure_ascii=False, indent=2))
