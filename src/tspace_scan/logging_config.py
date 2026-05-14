from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .paths import default_log_path


def configure_logging(level: int = logging.INFO) -> None:
    log_path = default_log_path()
    root = logging.getLogger()
    if any(isinstance(handler, RotatingFileHandler) for handler in root.handlers):
        return
    root.setLevel(level)
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(handler)
