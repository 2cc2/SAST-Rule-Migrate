import os
import json
import glob
import time
import uuid
import logging
import hashlib
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Callable, Tuple, Union
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler

from b2rscan.llm_wrapper import LLMWrapper
import yaml

# =========================
# Logging Utilities
# =========================
class JsonLineFormatter(logging.Formatter):
    def __init__(self, default_extra: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.default_extra = default_extra or {}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Merge extras
        if hasattr(record, "extra"):
            extras = getattr(record, "extra")
            if isinstance(extras, dict):
                payload.update(extras)
        # Attach default
        payload.update(self.default_extra)
        # Exception info
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def _mk_logger(name: str, log_dir: str = "logs") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    # Avoid duplicate handlers if reimported
    if logger.handlers:
        return logger

    # Console (human-friendly)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, log_level, logging.INFO))
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(ch)

    # JSONL file (machine-friendly)
    fh = RotatingFileHandler(
        filename=os.path.join(log_dir, f"agent-{datetime.utcnow().strftime('%Y%m%d')}.jsonl"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)  # always detailed in file
    fh.setFormatter(JsonLineFormatter())
    logger.addHandler(fh)

    logger.propagate = False
    return logger

LOGGER = _mk_logger("react-agent")

def log_json(level: int, msg: str, **extra):
    LOGGER.log(level, msg, extra={"extra": extra})

def sha1_short(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:10]

# =========================
# xCPG-IR Schema (same as before)
# =========================
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

# =========================
# Tool infra (same as before, with logging added)
# =========================
class ToolError(Exception):
    pass

@dataclass
class ToolResult:
    ok: bool
    content: Any
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None

class Tool:
    name: str
    description: str
    observation_trunc: int = 4000  # truncate long observations in logs

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError

    def _log_call(self, ok: bool, start_ts: float, call_id: str, run_id: str, **data):
        elapsed_ms = int((time.time() - start_ts) * 1000)
        obs = data.get("observation")
        if isinstance(obs, (dict, list)):
            obs_preview = json.dumps(obs, ensure_ascii=False)[: self.observation_trunc]
        else:
            obs_preview = str(obs)[: self.observation_trunc]
        log_json(
            logging.DEBUG if ok else logging.WARNING,
            f"tool.{self.name}.end",
            run_id=run_id,
            tool_call_id=call_id,
            ok=ok,
            elapsed_ms=elapsed_ms,
            input=data.get("input"),
            observation_preview=obs_preview,
            error=data.get("error")
        )

    def __call__(self, *, run_id: str, **kwargs) -> ToolResult:
        call_id = uuid.uuid4().hex[:8]
        start = time.time()
        log_json(logging.DEBUG, f"tool.{self.name}.start", run_id=run_id, tool_call_id=call_id, input=kwargs)
        try:
            res = self.run(**kwargs)
            # attach elapsed for upstream
            res.elapsed_ms = int((time.time() - start) * 1000)
            self._log_call(True, start, call_id, run_id, input=kwargs, observation=res.content)
            return res
        except Exception as e:
            self._log_call(False, start, call_id, run_id, input=kwargs, observation=None, error=str(e))
            return ToolResult(False, None, f"{self.name} error: {e}", elapsed_ms=int((time.time() - start) * 1000))

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
        lines = [f"- {t.name}: {t.description}" for t in self._tools.values()]
        return "\n".join(lines)

# =========================
# Tools (same as before)
# =========================
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
        path = Path(kwargs.get("path", "")).resolve()
        if not path.exists():
            return ToolResult(False, None, f"file not found: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        rid = None; name = None; sev = "medium"; desc = ""
        for line in text.splitlines():
            L = line.strip()
            if "@id" in L:
                rid = L.split("@id",1)[1].strip(": ").strip()
            if "@name" in L:
                name = L.split("@name",1)[1].strip(": ").strip()
            if "@kind" in L or "@problem.severity" in L or "@severity" in L:
                token = L.split()[-1].strip(": ").strip().lower()
                if token in ["low","medium","high","critical"]:
                    sev = token
            if (L.startswith("//") and "@description" in L) or ("Description:" in L):
                desc = L.split(":",1)[1].strip()
        if not rid: rid = f"ql-{uuid.uuid4().hex[:8]}"
        if not name: name = rid
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
        data = kwargs.get("data", [])
        if not isinstance(data, list):
            return ToolResult(False, None, "not a list")
        for i, item in enumerate(data):
            for req in ["id","name","description","severity","sources","sinks","sanitizers","validators"]:
                if req not in item:
                    return ToolResult(False, None, f"item[{i}] missing '{req}'")
            if item["severity"] not in ["low","medium","high","critical"]:
                return ToolResult(False, None, f"item[{i}] invalid severity")
        return ToolResult(True, "ok")

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
                for k in ["sources", "sinks", "sanitizers", "validators"]:
                    a = seen[key].get(k, [])
                    b = r.get(k, [])
                    seen[key][k] = list(dict.fromkeys((a or []) + (b or [])))
                if len(str(r.get("description",""))) > len(str(seen[key].get("description",""))):
                    seen[key]["description"] = r.get("description","")
                if len(str(r.get("pattern",""))) > len(str(seen[key].get("pattern",""))):
                    seen[key]["pattern"] = r.get("pattern","")
        return ToolResult(True, list(seen.values()))

# =========================
# ReAct Agent (with logging)
# =========================
class ReActAgent:
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
    def __init__(self, llm: LLMWrapper, tools: ToolRegistry, max_steps: int = 12):
        self.llm = llm
        self.tools = tools
        self.max_steps = max_steps
        self.trace: List[Dict[str, Any]] = []

    def _compose_prompt(self, user_task: str, scratch: str) -> str:
        return self.SYSTEM_PROMPT.format(tool_specs=self.tools.tool_specs_for_prompt()) + "\n" + \
            f"\nUSER TASK:\n{user_task}\n\n" + \
            ("SCRATCHPAD (previous thoughts/actions/observations):\n" + scratch if scratch else "")

    def run(self, run_id: str, user_task: str, observation_trunc: int = 4000) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        scratch = ""
        final_rules: List[Dict[str, Any]] = []

        log_json(logging.INFO, "react.start", run_id=run_id, task_hash=sha1_short(user_task), max_steps=self.max_steps)

        for step in range(1, self.max_steps + 1):
            t0 = time.time()
            prompt = self._compose_prompt(user_task, scratch)
            raw = self.llm.infer(prompt)
            dur_ms = int((time.time() - t0) * 1000)
            log_json(logging.DEBUG, "llm.step_raw", run_id=run_id, step=step, elapsed_ms=dur_ms,
                     prompt_chars=len(prompt), response_preview=str(raw)[:observation_trunc])

            # Try to parse JSON
            try:
                first_brace = raw.find("{"); last_brace = raw.rfind("}")
                action_obj = json.loads(raw[first_brace:last_brace+1])
            except Exception as e:
                log_json(logging.WARNING, "llm.parse_error", run_id=run_id, step=step, error=str(e))
                action_obj = {
                    "thought": "LLM returned non-JSON; fallback to finish with no result",
                    "action": "finish",
                    "action_input": {"result": []}
                }

            thought = action_obj.get("thought", "")
            action = action_obj.get("action", "")
            action_input = action_obj.get("action_input", {})

            log_json(logging.INFO, "react.decision", run_id=run_id, step=step, action=action,
                     action_input=action_input, thought_preview=thought[:200])

            if action == "finish":
                result = action_input.get("result", [])
                final_rules = result if isinstance(result, list) else []
                self.trace.append({
                    "step": step,
                    "thought": thought,
                    "action": action,
                    "input": action_input,
                    "observation": f"Finished with {len(final_rules)} rules"
                })
                log_json(logging.INFO, "react.finish", run_id=run_id, step=step, rules=len(final_rules))
                break

            if not self.tools.has(action):
                obs = f"Unknown tool: {action}"
                self.trace.append({
                    "step": step, "thought": thought, "action": action,
                    "input": action_input, "observation": obs
                })
                scratch += f"\nTHOUGHT: {thought}\nACTION: {action}\nOBSERVATION: {obs}\n"
                log_json(logging.WARNING, "react.unknown_tool", run_id=run_id, step=step, action=action)
                continue

            tool = self.tools.get(action)
            res = tool(run_id=run_id, **action_input)
            obs = res.content if res.ok else f"ERROR: {res.error}"
            obs_preview = json.dumps(obs, ensure_ascii=False) if isinstance(obs, (dict, list)) else str(obs)
            obs_preview = obs_preview[:observation_trunc]

            self.trace.append({
                "step": step, "thought": thought, "action": action,
                "input": action_input, "observation": obs_preview, "elapsed_ms": res.elapsed_ms
            })
            scratch += f"\nTHOUGHT: {thought}\nACTION: {action}\nOBSERVATION: {obs_preview}\n"

        log_json(logging.INFO, "react.end", run_id=run_id, steps=len(self.trace))
        return final_rules, self.trace

# =========================
# RuleExtractor (logs added)
# =========================
class RuleExtractor:
    def __init__(self, config_path: Optional[str] = None):
        self.llm_client = LLMWrapper("dashscope")
        self.tools = ToolRegistry()
        self.tools.register(ListDirTool())
        self.tools.register(ReadFileTool())
        self.tools.register(GlobSearchTool())
        self.tools.register(ParseSemgrepYAMLTool())
        self.tools.register(ParseCodeQLQueryTool())
        self.tools.register(MapToXCPGIRTool())
        self.tools.register(ValidateJSONSchemaTool())
        self.tools.register(MergeDedupRulesTool())
        self.agent = ReActAgent(self.llm_client, self.tools, max_steps=12)

    def _post_validate_and_fix(self, run_id: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        log_json(logging.INFO, "post.process.start", run_id=run_id, count=len(rules))
        mapped = self.tools.get("map_to_xcpg_ir")(run_id=run_id, rules=rules)
        if not mapped.ok:
            log_json(logging.ERROR, "post.map.error", run_id=run_id, error=mapped.error)
            raise ToolError(mapped.error or "map_to_xcpg_ir failed")

        merged = self.tools.get("merge_dedup_rules")(run_id=run_id, rules=mapped.content)
        if not merged.ok:
            log_json(logging.ERROR, "post.merge.error", run_id=run_id, error=merged.error)
            raise ToolError(merged.error or "merge_dedup_rules failed")

        valid = self.tools.get("validate_json_schema")(run_id=run_id, data=merged.content)
        if not valid.ok:
            log_json(logging.WARNING, "post.validate.fixup", run_id=run_id, reason=valid.error)
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
            # Re-validate
            valid2 = self.tools.get("validate_json_schema")(run_id=run_id, data=fixed)
            if not valid2.ok:
                log_json(logging.ERROR, "post.validate.error", run_id=run_id, error=valid2.error)
                raise ToolError(valid2.error or "schema validate failed")
            log_json(logging.INFO, "post.process.ok", run_id=run_id, final=len(fixed))
            return fixed

        log_json(logging.INFO, "post.process.ok", run_id=run_id, final=len(merged.content))
        return merged.content

    def extract_rules(self, sast_tool: str, source_path: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        if options is None:
            options = {}

        run_id = uuid.uuid4().hex[:12]
        repo_abs = str(Path(source_path).resolve())
        log_json(logging.INFO, "extract.start", run_id=run_id, sast_tool=sast_tool, repo=repo_abs, options=options)

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

        react_rules, trace = self.agent.run(run_id=run_id, user_task=user_task)

        if not react_rules:
            log_json(logging.WARNING, "extract.react_empty_fallback", run_id=run_id)
            glob_res = self.tools.get("glob_search")(run_id=run_id, root=source_path,
                                                     patterns=["**/*.yml", "**/*.yaml", "**/*.json", "**/*.ql"])
            candidates = glob_res.content if glob_res.ok else []
            raw_rules: List[Dict[str, Any]] = []
            for f in candidates:
                if f.endswith((".yml", ".yaml")):
                    pr = self.tools.get("parse_semgrep_yaml")(run_id=run_id, path=f)
                    if pr.ok and isinstance(pr.content, list):
                        raw_rules.extend(pr.content)
                elif f.endswith(".ql"):
                    pr = self.tools.get("parse_codeql_ql")(run_id=run_id, path=f)
                    if pr.ok and isinstance(pr.content, list):
                        raw_rules.extend(pr.content)
            react_rules = raw_rules

        rules = self._post_validate_and_fix(run_id, react_rules)
        log_json(logging.INFO, "extract.end", run_id=run_id, rules=len(rules), repo=repo_abs)

        return rules

# =========================
# Demo
# =========================
if __name__ == "__main__":
    extractor = RuleExtractor()
    rules = extractor.extract_rules("codeql", "sast/codeql")
    print(json.dumps(rules, ensure_ascii=False, indent=2))