from __future__ import annotations

import os
import re
from pathlib import Path

from .filesystem_scanner import enrich_item_from_filesystem
from .models import SoftwareItem

try:
    import winreg
except ImportError:  # pragma: no cover - Windows-only scanner
    winreg = None  # type: ignore[assignment]


UNINSTALL_LOCATIONS = (
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "system-wide"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "system-wide"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "user-only"),
)


def scan_registry() -> list[SoftwareItem]:
    if winreg is None:
        return []

    results: list[SoftwareItem] = []
    for hive_name, subkey, install_type in UNINSTALL_LOCATIONS:
        hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
        try:
            root = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        except OSError:
            continue
        with root:
            try:
                total, _, _ = winreg.QueryInfoKey(root)
            except OSError:
                continue
            for index in range(total):
                try:
                    child_name = winreg.EnumKey(root, index)
                    child = winreg.OpenKey(root, child_name, 0, winreg.KEY_READ)
                except OSError:
                    continue
                with child:
                    item = _software_from_key(child, f"{hive_name}\\{subkey}\\{child_name}", install_type)
                    if item:
                        results.append(enrich_item_from_filesystem(item))
    return _deduplicate(results)


def _software_from_key(key, registry_key: str, install_type: str) -> SoftwareItem | None:
    name = _read_value(key, "DisplayName")
    if not name or _looks_like_system_component(key):
        return None
    publisher = _read_value(key, "Publisher")
    install_location = _read_value(key, "InstallLocation")
    display_icon = _read_value(key, "DisplayIcon")
    exe = _executable_from_icon(display_icon)
    if not install_location and exe:
        install_location = str(Path(exe).parent)
    estimated_size = _to_int(_read_value(key, "EstimatedSize"))
    item = SoftwareItem(
        name=name,
        publisher=publisher,
        version=_read_value(key, "DisplayVersion"),
        install_date=_normalize_install_date(_read_value(key, "InstallDate")),
        install_location=install_location,
        executable_path=exe,
        website=_read_value(key, "URLInfoAbout") or _read_value(key, "HelpLink"),
        estimated_size_kb=estimated_size,
        install_type=install_type,
        source="registry",
        registry_key=registry_key,
        uninstall_string=_read_value(key, "UninstallString"),
    )
    return item


def _read_value(key, name: str) -> str:
    try:
        value, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return ""
    if value is None:
        return ""
    return str(value).strip()


def _looks_like_system_component(key) -> bool:
    system_component = _read_value(key, "SystemComponent")
    release_type = _read_value(key, "ReleaseType").lower()
    parent_key = _read_value(key, "ParentKeyName")
    return system_component == "1" or bool(parent_key) or release_type in {"security update", "update rollup"}


def _normalize_install_date(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    if re.fullmatch(r"\d{8}", value):
        return f"{value[0:4]}-{value[4:6]}-{value[6:8]}"
    return value


def _executable_from_icon(display_icon: str) -> str:
    if not display_icon:
        return ""
    value = os.path.expandvars(display_icon.strip().strip('"'))
    if "," in value and value.rsplit(",", 1)[-1].strip().lstrip("-").isdigit():
        value = value.rsplit(",", 1)[0].strip().strip('"')
    if value.lower().endswith(".exe") and Path(value).exists():
        return value
    return ""


def _to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _deduplicate(items: list[SoftwareItem]) -> list[SoftwareItem]:
    seen: dict[str, SoftwareItem] = {}
    for item in items:
        key = item.stable_key()
        if key in seen:
            existing = seen[key]
            existing.related_paths = sorted(set(existing.related_paths + item.related_paths))
            existing.license_files = sorted(set(existing.license_files + item.license_files))
            if not existing.executable_path:
                existing.executable_path = item.executable_path
            continue
        seen[key] = item
    return list(seen.values())
