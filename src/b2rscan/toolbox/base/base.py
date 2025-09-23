from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import logging
import time
import uuid
import json


class ToolError(Exception):
    """Tool execution error"""
    pass


@dataclass
class ToolResult:
    """Tool execution result"""
    ok: bool
    content: Any
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None


class Tool:
    """Base class for all tools"""
    name: str = ""
    description: str = ""
    observation_trunc: int = 4000  # truncate long observations in logs

    def __init__(self) -> None:
        pass

    def run(self, **kwargs) -> ToolResult:
        raise NotImplementedError

    def _log_call(self, ok: bool, start_ts: float, call_id: str, run_id: str, **data):
        elapsed_ms = int((time.time() - start_ts) * 1000)
        obs = data.get("observation")
        if isinstance(obs, (dict, list)):
            obs_preview = json.dumps(obs, ensure_ascii=False)[: self.observation_trunc]
        else:
            obs_preview = str(obs)[: self.observation_trunc]
        # 简化日志记录，避免依赖不存在的log_json函数
        logging.debug(f"tool.{self.name}.end - run_id: {run_id}, tool_call_id: {call_id}, ok: {ok}, "
                      f"elapsed_ms: {elapsed_ms}, input: {data.get('input')}, "
                      f"observation_preview: {obs_preview}, error: {data.get('error')}")

    def __call__(self, *, run_id: str = "", **kwargs) -> ToolResult:
        call_id = uuid.uuid4().hex[:8]
        start = time.time()
        logging.debug(f"tool.{self.name}.start - run_id: {run_id}, tool_call_id: {call_id}, input: {kwargs}")
        try:
            res = self.run(**kwargs)
            # attach elapsed for upstream
            res.elapsed_ms = int((time.time() - start) * 1000)
            self._log_call(True, start, call_id, run_id, input=kwargs, observation=res.content)
            return res
        except Exception as e:
            self._log_call(False, start, call_id, run_id, input=kwargs, observation=None, error=str(e))
            return ToolResult(False, None, f"{self.name} error: {e}", elapsed_ms=int((time.time() - start) * 1000))