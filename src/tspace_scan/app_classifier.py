from __future__ import annotations

from .models import SoftwareItem


NOISE_KEYWORDS = (
    "uninstall",
    "readme",
    "release notes",
    "documentation",
    "help",
    "updater",
    "update assistant",
    "maintenance service",
    "compatibility mode",
    "task scheduler",
    "task manager",
    "control panel",
    "command prompt",
    "powershell",
    "tools for desktop apps",
    "tools for uwp apps",
)


def classify_app(item: SoftwareItem) -> SoftwareItem:
    text = " ".join([item.name, item.publisher, item.install_location, item.executable_path]).lower()

    if _contains(text, NOISE_KEYWORDS) or item.source == "shortcut" and _looks_like_windows_tool(text):
        return _set(item, "Updater/Uninstaller", "Noise/Helper", False, True, "Helper, shortcut, updater, or system utility.")

    if _contains(text, ("microsoft office", "microsoft 365", "office 365", "word", "excel", "powerpoint", "outlook", "visio", "project")):
        return _set(item, "Office/Productivity", "License relevant", True, False, "Office/productivity software is commonly license managed.")
    if _contains(text, ("foxit", "acrobat", "adobe reader", "pdf-xchange", "nitro pdf", "wondershare pdfelement")):
        return _set(item, "PDF/Document", "Work apps", True, False, "PDF/document software is commonly used for work and may require license review.")
    if _contains(text, ("photoshop", "illustrator", "premiere", "after effects", "lightroom", "coreldraw", "affinity", "canva")):
        return _set(item, "Creative", "License relevant", True, False, "Creative software is commonly commercial/subscription-based.")
    if _contains(text, ("autocad", "autodesk", "revit", "inventor", "solidworks", "sketchup", "archicad", "catia")):
        return _set(item, "CAD/Engineering", "License relevant", True, False, "CAD/engineering software is high-value license managed software.")
    if _contains(text, ("vmware workstation", "virtualbox", "hyper-v", "parallels")):
        return _set(item, "Virtualization", "License relevant", True, False, "Virtualization tools may require commercial license review.")
    if _contains(text, ("anydesk", "ultraviewer", "teamviewer", "rustdesk", "remote desktop")):
        return _set(item, "Remote Access", "Work apps", True, False, "Remote access software should be reviewed for policy and license compliance.")

    if _contains(text, ("python", "node.js", "nodejs", "npm", "bun", "java", "jdk", "jre", ".net", "runtime", "redistributable", "windows sdk", "postgresql", "wsl")):
        return _set(item, "Runtime/Framework", "Developer/Runtime", False, False, "Runtime/developer dependency; tracked separately from primary license-risk apps.")
    if _contains(text, ("visual studio", "vscode", "visual studio code", "git", "github desktop", "github cli", "docker", "jetbrains", "pycharm", "webstorm", "intellij", "kiro", "windsurf", "opencode")):
        return _set(item, "Developer Tool", "Developer/Runtime", True, False, "Developer tooling; license relevance depends on edition.")
    if _contains(text, ("nvidia", "amd software", "intel driver", "realtek", "logitech", "synaptics", "driver", "geforce")):
        return _set(item, "Driver/Hardware", "Driver/Hardware", False, False, "Driver or hardware utility; tracked separately from application license risk.")
    if _contains(text, ("microsoft edge", "google chrome", "firefox", "brave", "opera", "vivaldi")):
        return _set(item, "Browser", "Free/Open-source", False, False, "Browser/freeware class; normally low license-review priority.")
    if _contains(text, ("telegram", "viber", "zalo", "slack", "discord", "zoom", "teams", "skype")):
        return _set(item, "Communication", "Freemium/Conditional", False, False, "Communication app; usually freeware/freemium unless enterprise edition.")
    if _contains(text, ("vlc", "k-lite", "spotify", "obs studio")):
        return _set(item, "Media", "Free/Open-source", False, False, "Media/freeware or open-source software.")
    if _contains(text, ("7-zip", "winrar", "bandizip", "winzip")):
        return _set(item, "Archive/Utility", "Work apps", True, False, "Archive utility; some products are commercial/trialware.")
    if _contains(text, ("windows defender", "windows mail", "windows media player", "windows photo viewer", "windows kits")):
        return _set(item, "System Tool", "System/Windows", False, True, "Windows built-in or SDK/system component.")
    if _contains(text, ("defender", "antivirus", "malwarebytes", "eset", "kaspersky", "bitdefender", "crowdstrike")):
        return _set(item, "Security", "Work apps", True, False, "Security software may be enterprise licensed.")
    if _contains(text, ("bluestacks", "capcut", "camo studio")):
        return _set(item, "Media", "Freemium/Conditional", False, False, "Consumer/freemium application; tracked separately from business license risk.")
    if _contains(text, ("ricoh", "device software manager")):
        return _set(item, "Driver/Hardware", "Driver/Hardware", False, False, "Hardware vendor utility; tracked separately from business license risk.")
    if _contains(text, ("xbox", "steam", "epic games", "riot client", "battle.net")):
        return _set(item, "Gaming", "Freemium/Conditional", False, False, "Gaming/consumer software; generally outside business license-risk focus.")
    if _contains(text, ("windows", "microsoft corporation")) and item.source == "shortcut":
        return _set(item, "System Tool", "System/Windows", False, True, "Windows shortcut or system tool.")

    if item.license_type in {"Paid software", "Trial software", "Subscription-based"}:
        return _set(item, "Unknown", "License relevant", True, False, "Commercial/trial license classification makes this license relevant.")
    if item.license_type in {"Freeware", "Open-source software", "Freemium"}:
        group = "Freemium/Conditional" if item.license_type == "Freemium" else "Free/Open-source"
        return _set(item, "Unknown", group, False, False, "Free/open-source/freemium classification lowers license-review priority.")

    return _set(item, "Unknown", "Unknown", True, False, "No reliable app category rule matched.")


def should_drop_from_default_scan(item: SoftwareItem) -> bool:
    text = " ".join([item.name, item.publisher, item.install_location]).lower()
    if item.is_noise:
        return True
    if item.source == "shortcut" and _contains(text, NOISE_KEYWORDS):
        return True
    return False


def _set(
    item: SoftwareItem,
    category: str,
    group: str,
    license_relevant: bool,
    is_noise: bool,
    reason: str,
) -> SoftwareItem:
    item.app_category = category
    item.app_group = group
    item.is_license_relevant = license_relevant
    item.is_noise = is_noise
    item.app_classification_reason = reason
    return item


def _contains(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _looks_like_windows_tool(value: str) -> bool:
    return _contains(
        value,
        (
            "windows tools",
            "administrative tools",
            "system32",
            "windows\\start menu",
            "control panel",
            "event viewer",
            "services",
        ),
    )
