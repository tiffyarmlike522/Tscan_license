from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .models import SoftwareItem


LICENSE_FILE_NAMES = {
    "license",
    "license.txt",
    "license.md",
    "copying",
    "copying.txt",
    "eula",
    "eula.txt",
    "notice",
    "notice.txt",
}

EXECUTABLE_EXTENSIONS = {".exe", ".com", ".bat", ".cmd"}

SHORTCUT_NOISE_TOKENS = (
    "uninstall",
    "readme",
    "help",
    "documentation",
    "release notes",
    "license",
    "updater",
    "update",
    "task manager",
    "task scheduler",
    "control panel",
    "command prompt",
    "powershell",
    "run",
    "services",
    "event viewer",
)

GENERIC_SHORTCUT_NAMES = {
    "programs",
    "microsoft",
    "google",
    "openai",
    "windows",
}

FOLDER_NOISE_NAMES = {
    "common files",
    "windowsapps",
    "windows sidebar",
    "microsoft shared",
    "internet explorer",
    "reference assemblies",
    "uninstall information",
    "package cache",
    "temp",
    "tmp",
    "cache",
    "logs",
}


def existing_program_roots() -> list[Path]:
    candidates = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("APPDATA"),
    ]
    roots: list[Path] = []
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists() and path.is_dir() and path not in roots:
            roots.append(path)
    return roots


def existing_start_menu_roots() -> list[Path]:
    candidates = [
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs",
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs",
    ]
    roots: list[Path] = []
    for path in candidates:
        if path.exists() and path.is_dir() and path not in roots:
            roots.append(path)
    return roots


def scan_start_menu_shortcuts(max_items: int = 500) -> list[SoftwareItem]:
    """Collect Start Menu shortcuts as inventory hints.

    The MVP intentionally avoids COM/pywin32 dependencies, so it records the
    shortcut path but does not resolve the target executable.
    """
    items: list[SoftwareItem] = []
    for root in existing_start_menu_roots():
        count = 0
        try:
            shortcuts = sorted(root.rglob("*.lnk"), key=lambda p: p.name.lower())
        except OSError:
            continue
        for shortcut in shortcuts:
            if count >= max_items:
                break
            count += 1
            name = shortcut.stem
            if not name or name.strip().lower() in GENERIC_SHORTCUT_NAMES or _is_noisy_shortcut(name, shortcut):
                continue
            install_type = "user-only" if "appdata" in str(root).lower() else "system-wide"
            items.append(
                SoftwareItem(
                    name=name,
                    install_location=str(shortcut.parent),
                    install_type=install_type,
                    source="shortcut",
                    related_paths=[str(shortcut)],
                )
            )
    return items


def scan_program_directories(max_items_per_root: int = 300) -> list[SoftwareItem]:
    """Return top-level app folders that may not have uninstall registry entries."""
    items: list[SoftwareItem] = []
    for root in existing_program_roots():
        count = 0
        try:
            children = sorted(root.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for child in children:
            if count >= max_items_per_root:
                break
            if not child.is_dir() or child.name.startswith(".") or child.name.strip().lower() in FOLDER_NOISE_NAMES:
                continue
            exe = find_primary_executable(child)
            if not exe:
                continue
            count += 1
            install_type = "user-only" if str(root).lower().find("appdata") >= 0 else "system-wide"
            items.append(
                SoftwareItem(
                    name=child.name,
                    install_location=str(child),
                    executable_path=str(exe),
                    install_type=install_type,
                    source="filesystem",
                    related_paths=[str(child), str(exe)],
                    estimated_size_kb=estimate_directory_size_kb(child, max_files=500),
                    license_files=[str(path) for path in find_license_files(child, max_files=200)],
                )
            )
    return items


def _is_noisy_shortcut(name: str, shortcut: Path) -> bool:
    text = " ".join([name, str(shortcut.parent)]).lower()
    if any(token in text for token in SHORTCUT_NOISE_TOKENS):
        return True
    if "windows tools" in text or "administrative tools" in text:
        return True
    if "\\chrome apps" in text or "chrome apps" in text:
        return True
    return False


def enrich_item_from_filesystem(item: SoftwareItem) -> SoftwareItem:
    install_path = Path(item.install_location) if item.install_location else None
    if install_path and install_path.exists() and install_path.is_dir():
        if not item.executable_path:
            exe = find_primary_executable(install_path)
            if exe:
                item.executable_path = str(exe)
        if item.estimated_size_kb <= 0:
            item.estimated_size_kb = estimate_directory_size_kb(install_path, max_files=1000)
        if not item.license_files:
            item.license_files = [str(path) for path in find_license_files(install_path, max_files=300)]
        add_related_path(item, str(install_path))
    if item.executable_path:
        add_related_path(item, item.executable_path)
    return item


def add_related_path(item: SoftwareItem, path: str) -> None:
    if path and path not in item.related_paths:
        item.related_paths.append(path)


def find_primary_executable(folder: Path, max_files: int = 250) -> Path | None:
    if not folder.exists() or not folder.is_dir():
        return None
    preferred = []
    fallback = []
    scanned = 0
    try:
        for current, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in {"cache", "temp", "tmp", "logs"}]
            depth = Path(current).relative_to(folder).parts
            if len(depth) > 2:
                dirs[:] = []
            for file_name in files:
                scanned += 1
                if scanned > max_files:
                    break
                candidate = Path(current) / file_name
                if candidate.suffix.lower() not in EXECUTABLE_EXTENSIONS:
                    continue
                lowered = candidate.stem.lower()
                if folder.name.lower().replace(" ", "") in lowered.replace(" ", ""):
                    preferred.append(candidate)
                else:
                    fallback.append(candidate)
            if scanned > max_files:
                break
    except OSError:
        return None
    if preferred:
        return sorted(preferred, key=lambda p: len(str(p)))[0]
    if fallback:
        return sorted(fallback, key=lambda p: len(str(p)))[0]
    return None


def find_license_files(folder: Path, max_files: int = 300) -> list[Path]:
    matches: list[Path] = []
    scanned = 0
    try:
        for current, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in {"cache", "temp", "tmp", "node_modules"}]
            if len(Path(current).relative_to(folder).parts) > 2:
                dirs[:] = []
            for file_name in files:
                scanned += 1
                if scanned > max_files:
                    return matches
                if file_name.lower() in LICENSE_FILE_NAMES:
                    matches.append(Path(current) / file_name)
    except OSError:
        return matches
    return matches


def estimate_directory_size_kb(folder: Path, max_files: int = 1000) -> int:
    total = 0
    scanned = 0
    try:
        for current, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in {"cache", "temp", "tmp"}]
            for file_name in files:
                scanned += 1
                if scanned > max_files:
                    return total // 1024
                try:
                    total += (Path(current) / file_name).stat().st_size
                except OSError:
                    continue
    except OSError:
        return total // 1024
    return total // 1024


def read_text_samples(paths: Iterable[str], max_chars_per_file: int = 12000) -> str:
    chunks: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:max_chars_per_file]
        except OSError:
            continue
        chunks.append(text)
    return "\n".join(chunks)


def iter_files_limited(folder: str, max_files: int = 600) -> Iterable[Path]:
    root = Path(folder)
    if not root.exists() or not root.is_dir():
        return []

    def generator() -> Iterable[Path]:
        scanned = 0
        try:
            for current, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d.lower() not in {"cache", "temp", "tmp", "logs"}]
                if len(Path(current).relative_to(root).parts) > 3:
                    dirs[:] = []
                for file_name in files:
                    scanned += 1
                    if scanned > max_files:
                        return
                    yield Path(current) / file_name
        except OSError:
            return

    return generator()
