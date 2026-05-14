from __future__ import annotations

import os
import sys
from pathlib import Path


APP_DIR_NAME = "T-SpaceScan"


def project_root() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return project_root() / "data"


def default_rules_path() -> Path:
    return data_dir() / "license_rules.json"


def app_data_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    root = Path(local) if local else project_root()
    path = root / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_database_path() -> Path:
    return app_data_dir() / "tspace_scan.db"


def default_export_dir() -> Path:
    path = app_data_dir() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_log_dir() -> Path:
    path = app_data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_log_path() -> Path:
    return default_log_dir() / "tspace_scan.log"
