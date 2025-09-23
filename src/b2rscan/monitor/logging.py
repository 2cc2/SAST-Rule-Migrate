import json
import logging
from typing import Any, Dict, Optional
from datetime import datetime
from logging.handlers import RotatingFileHandler

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