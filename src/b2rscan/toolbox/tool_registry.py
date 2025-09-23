from typing import Dict, List, Any, Optional
from dataclasses import dataclass

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