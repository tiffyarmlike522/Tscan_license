from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


LICENSE_TYPES = (
    "Freeware",
    "Paid software",
    "Trial software",
    "Open-source software",
    "Freemium",
    "Subscription-based",
    "Unknown",
)

RISK_LEVELS = ("Low Risk", "Medium Risk", "High Risk", "Critical Risk")

APP_GROUPS = (
    "License relevant",
    "Work apps",
    "Free/Open-source",
    "Freemium/Conditional",
    "Developer/Runtime",
    "Driver/Hardware",
    "System/Windows",
    "Noise/Helper",
    "Unknown",
)

APP_CATEGORIES = (
    "Office/Productivity",
    "PDF/Document",
    "Creative",
    "CAD/Engineering",
    "Browser",
    "Communication",
    "Developer Tool",
    "Runtime/Framework",
    "Driver/Hardware",
    "System Tool",
    "Updater/Uninstaller",
    "Remote Access",
    "Virtualization",
    "Media",
    "Archive/Utility",
    "Security",
    "Gaming",
    "Unknown",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class DigitalSignatureInfo:
    status: str = "NotChecked"
    status_message: str = ""
    subject: str = ""
    issuer: str = ""
    thumbprint: str = ""
    checked_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RiskFinding:
    signal: str
    reason: str
    path: str = ""
    level: str = "Low Risk"
    confidence: int = 30
    score_delta: int = 5
    recommendation: str = (
        "Review this signal with the software owner and verify license evidence "
        "from official records."
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SoftwareItem:
    name: str
    publisher: str = ""
    version: str = ""
    install_date: str = ""
    install_location: str = ""
    executable_path: str = ""
    website: str = ""
    estimated_size_kb: int = 0
    install_type: str = "unknown"
    source: str = "registry"
    registry_key: str = ""
    uninstall_string: str = ""
    related_paths: list[str] = field(default_factory=list)
    license_files: list[str] = field(default_factory=list)
    app_category: str = "Unknown"
    app_group: str = "Unknown"
    is_license_relevant: bool = True
    is_noise: bool = False
    app_classification_reason: str = ""
    license_type: str = "Unknown"
    license_confidence: int = 0
    license_explanation: str = "No reliable license signal was found."
    signature: DigitalSignatureInfo = field(default_factory=DigitalSignatureInfo)
    risk_score: int = 0
    risk_level: str = "Low Risk"
    risk_findings: list[RiskFinding] = field(default_factory=list)

    def stable_key(self) -> str:
        bits = [
            self.name.strip().lower(),
            self.publisher.strip().lower(),
            self.version.strip().lower(),
            self.install_location.strip().lower(),
        ]
        return "|".join(bits)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signature"] = self.signature.to_dict()
        data["risk_findings"] = [finding.to_dict() for finding in self.risk_findings]
        return data


@dataclass(slots=True)
class ScanSession:
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str = ""
    computer_name: str = ""
    user_name: str = ""
    os_version: str = ""
    total_items: int = 0
    total_findings: int = 0
    summary_json: str = ""


@dataclass(slots=True)
class PolicyRule:
    id: int = 0
    match_type: str = "name"
    pattern: str = ""
    reason: str = ""
    risk_level: str = "High Risk"
    created_by: str = ""
    created_at: str = ""


@dataclass(slots=True)
class ScanComparison:
    old_session_id: int
    new_session_id: int
    added: list[SoftwareItem] = field(default_factory=list)
    removed: list[SoftwareItem] = field(default_factory=list)
    changed: list[tuple[SoftwareItem, SoftwareItem, list[str]]] = field(default_factory=list)
