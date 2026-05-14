from __future__ import annotations

from pathlib import Path

from .filesystem_scanner import iter_files_limited
from .models import PolicyRule, RiskFinding, SoftwareItem


HIGH_SIGNAL_KEYWORDS = ("crack", "keygen", "activator", "preactivated", "license bypass")
MEDIUM_SIGNAL_KEYWORDS = ("patch", "loader", "kms", "repack", "modified installer", "serial")
COMMERCIAL_PUBLISHERS = ("adobe", "autodesk", "corel", "microsoft", "jetbrains", "oracle", "vmware")
ACTIVATION_HOST_TOKENS = ("activate", "activation", "license", "licensing", "adobe", "autodesk", "corel")


class RiskAnalyzer:
    def __init__(self, whitelist: set[str] | list[PolicyRule] | None = None, blacklist: list[PolicyRule] | None = None) -> None:
        self.whitelist: set[str] = set()
        self.whitelist_rules: list[PolicyRule] = []
        for value in whitelist or []:
            if isinstance(value, PolicyRule):
                self.whitelist_rules.append(value)
            else:
                self.whitelist.add(str(value).lower())
        self.blacklist = blacklist or []

    def analyze(self, item: SoftwareItem) -> SoftwareItem:
        findings: list[RiskFinding] = []
        normalized_name = item.name.lower()
        normalized_publisher = item.publisher.lower()

        if self._is_whitelisted(item, normalized_name):
            item.risk_score = 0
            item.risk_level = "Low Risk"
            item.risk_findings = [
                RiskFinding(
                    signal="whitelist",
                    reason="Software is explicitly marked as safe by local policy.",
                    confidence=80,
                    score_delta=0,
                    recommendation="Keep periodic review of whitelist entries.",
                )
            ]
            return item

        findings.extend(self._blacklist_findings(item))
        findings.extend(self._keyword_findings(item))
        findings.extend(self._publisher_findings(item, normalized_publisher))
        findings.extend(self._signature_findings(item, normalized_name, normalized_publisher))
        findings.extend(self._hosts_findings(item))
        findings.extend(self._commercial_license_findings(item, normalized_name, normalized_publisher))

        score = min(100, sum(f.score_delta for f in findings))
        item.risk_score = score
        item.risk_level = risk_level_from_score(score)
        item.risk_findings = findings
        return item

    def _is_whitelisted(self, item: SoftwareItem, normalized_name: str) -> bool:
        return (
            item.stable_key().lower() in self.whitelist
            or normalized_name in self.whitelist
            or any(_policy_matches(rule, item) for rule in self.whitelist_rules)
        )

    def _blacklist_findings(self, item: SoftwareItem) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for rule in self.blacklist:
            if not _policy_matches(rule, item):
                continue
            score_delta = 85 if rule.risk_level == "Critical Risk" else 60 if rule.risk_level == "High Risk" else 35
            findings.append(
                RiskFinding(
                    signal="blacklist_policy",
                    reason=rule.reason or f"Matched blacklist policy: {rule.pattern}",
                    path=item.install_location or item.executable_path or item.registry_key,
                    level=rule.risk_level,
                    confidence=90,
                    score_delta=score_delta,
                    recommendation="Review this software against local IT policy and remove or approve only through a documented exception.",
                )
            )
        return findings

    def _keyword_findings(self, item: SoftwareItem) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        paths_to_check = list(item.related_paths)
        if item.install_location:
            paths_to_check.append(item.install_location)
        if item.executable_path:
            paths_to_check.append(item.executable_path)

        for raw in paths_to_check:
            lowered = raw.lower()
            for keyword in HIGH_SIGNAL_KEYWORDS:
                if keyword in lowered:
                    findings.append(_keyword_finding(keyword, raw, high=True))
            for keyword in MEDIUM_SIGNAL_KEYWORDS:
                if self._should_consider_medium_keyword(item, raw, keyword):
                    findings.append(_keyword_finding(keyword, raw, high=False))

        if item.install_location and item.app_group in {"License relevant", "Work apps"}:
            for path in iter_files_limited(item.install_location, max_files=600):
                lowered = str(path).lower()
                for keyword in HIGH_SIGNAL_KEYWORDS:
                    if keyword in lowered:
                        findings.append(_keyword_finding(keyword, str(path), high=True))
                for keyword in MEDIUM_SIGNAL_KEYWORDS:
                    if self._should_consider_medium_keyword(item, str(path), keyword):
                        findings.append(_keyword_finding(keyword, str(path), high=False))
        return _cap_findings(_unique_findings(findings))

    def _should_consider_medium_keyword(self, item: SoftwareItem, path: str, keyword: str) -> bool:
        if item.is_noise:
            return False
        commercial_context = (
            item.app_group in {"License relevant", "Work apps"}
            and item.license_type in {"Paid software", "Subscription-based", "Trial software", "Unknown"}
        )
        if not commercial_context:
            return False
        lowered = path.lower()
        if keyword not in lowered:
            return False
        filename = Path(path).name.lower()
        suspicious_neighbors = ("crack", "keygen", "activat", "license", "licence", "bypass", "kms")
        if keyword == "serial":
            return any(token in filename for token in suspicious_neighbors) or filename in {"serial.txt", "serials.txt"}
        if keyword in {"loader", "patch"}:
            return any(token in filename for token in suspicious_neighbors) or filename.endswith((".exe", ".cmd", ".bat"))
        if keyword == "repack":
            return item.license_type in {"Paid software", "Subscription-based", "Trial software"}
        return True

    def _publisher_findings(self, item: SoftwareItem, publisher: str) -> list[RiskFinding]:
        if publisher:
            return []
        if item.license_type in {"Paid software", "Subscription-based", "Trial software"}:
            return [
                RiskFinding(
                    signal="missing_publisher",
                    reason="Publisher metadata is missing for software classified as commercial/trial.",
                    path=item.install_location or item.registry_key,
                    level="Low Risk",
                    confidence=35,
                    score_delta=8,
                    recommendation="Verify publisher and source from procurement or official vendor records.",
                )
            ]
        return []

    def _signature_findings(self, item: SoftwareItem, name: str, publisher: str) -> list[RiskFinding]:
        if not item.executable_path:
            return []
        commercial = item.license_type in {"Paid software", "Subscription-based", "Trial software"}
        known_commercial = any(token in publisher or token in name for token in COMMERCIAL_PUBLISHERS)
        if not commercial and not known_commercial:
            return []

        findings: list[RiskFinding] = []
        status = item.signature.status
        status_lower = status.lower()
        if status_lower in {"hashmismatch", "nottrusted", "notvalid", "unknownerror"}:
            findings.append(
                RiskFinding(
                    signal="invalid_digital_signature",
                    reason=f"Executable signature status is '{status}', which requires review for commercial software.",
                    path=item.executable_path,
                    level="High Risk",
                    confidence=75,
                    score_delta=25,
                    recommendation="Verify the executable from official vendor media and reinstall from a trusted source if needed.",
                )
            )
        elif status_lower in {"notsigned"}:
            findings.append(
                RiskFinding(
                    signal="unsigned_commercial_executable",
                    reason="Executable is not digitally signed while the software appears commercial or trial-based.",
                    path=item.executable_path,
                    level="Medium Risk",
                    confidence=45,
                    score_delta=12,
                    recommendation="Confirm whether this vendor normally signs releases before treating it as a compliance issue.",
                )
            )
        elif status_lower == "valid" and publisher and item.signature.subject:
            publisher_tokens = {token for token in publisher.replace(",", " ").replace(".", " ").lower().split() if len(token) >= 4}
            subject = item.signature.subject.lower()
            if publisher_tokens and not any(token in subject for token in publisher_tokens):
                findings.append(
                    RiskFinding(
                        signal="publisher_signature_mismatch",
                        reason="Registry publisher does not appear to match the digital signature subject.",
                        path=item.executable_path,
                        level="Medium Risk",
                        confidence=55,
                        score_delta=18,
                        recommendation="Verify publisher identity against official vendor installer metadata.",
                    )
                )
        return findings

    def _hosts_findings(self, item: SoftwareItem) -> list[RiskFinding]:
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
        if not hosts_path.exists():
            return []
        try:
            lines = hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return []
        vendor_tokens = _vendor_tokens(item)
        if not vendor_tokens:
            return []
        findings: list[RiskFinding] = []
        for line in lines:
            clean = line.strip().lower()
            if not clean or clean.startswith("#"):
                continue
            if not (clean.startswith("127.") or clean.startswith("0.0.0.0")):
                continue
            if any(token in clean for token in vendor_tokens) and any(token in clean for token in ACTIVATION_HOST_TOKENS):
                findings.append(
                    RiskFinding(
                        signal="hosts_activation_block",
                        reason="Hosts file appears to block vendor activation/licensing endpoints.",
                        path=str(hosts_path),
                        level="High Risk",
                        confidence=70,
                        score_delta=30,
                        recommendation="Review the hosts entry with IT/security and restore official vendor connectivity if unauthorized.",
                    )
                )
        return _unique_findings(findings)

    def _commercial_license_findings(self, item: SoftwareItem, name: str, publisher: str) -> list[RiskFinding]:
        if item.is_noise or not item.is_license_relevant or item.app_group not in {"License relevant", "Work apps"}:
            return []
        commercial = item.license_type in {"Paid software", "Subscription-based"}
        known_commercial = any(token in publisher or token in name for token in COMMERCIAL_PUBLISHERS)
        if not commercial and not known_commercial:
            return []
        if item.license_confidence < 68 and item.app_category not in {"Creative", "CAD/Engineering", "Office/Productivity"}:
            return []
        if item.app_category not in {"Creative", "CAD/Engineering", "Office/Productivity", "PDF/Document", "Virtualization"}:
            return []
        if item.license_files:
            return []
        return [
            RiskFinding(
                signal="license_evidence_missing",
                reason="Commercial software was detected but no local license/EULA evidence file was found by the MVP scanner.",
                path=item.install_location or item.registry_key,
                level="Low Risk",
                confidence=25,
                score_delta=5,
                recommendation="Check legitimate purchase, subscription, tenant, or license-management records before taking action.",
            )
        ]


def risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "Critical Risk"
    if score >= 60:
        return "High Risk"
    if score >= 30:
        return "Medium Risk"
    return "Low Risk"


def _keyword_finding(keyword: str, path: str, high: bool) -> RiskFinding:
    if high:
        return RiskFinding(
            signal=f"suspicious_keyword:{keyword}",
            reason=f"Path or file name contains the high-risk keyword '{keyword}'.",
            path=path,
            level="High Risk",
            confidence=75,
            score_delta=28,
            recommendation="Quarantine only according to company policy; verify source and license with the software owner.",
        )
    return RiskFinding(
        signal=f"suspicious_keyword:{keyword}",
        reason=f"Path or file name contains the review keyword '{keyword}'. This can be legitimate in some products.",
        path=path,
        level="Medium Risk",
        confidence=45,
        score_delta=12,
        recommendation="Review context carefully; do not treat this as proof of unauthorized software by itself.",
    )


def _vendor_tokens(item: SoftwareItem) -> set[str]:
    tokens = set()
    for value in (item.publisher, item.name):
        for token in value.lower().replace(",", " ").replace(".", " ").split():
            if len(token) >= 4:
                tokens.add(token)
    return tokens


def _unique_findings(findings: list[RiskFinding]) -> list[RiskFinding]:
    seen: set[tuple[str, str]] = set()
    unique: list[RiskFinding] = []
    for finding in findings:
        key = (finding.signal, finding.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _cap_findings(findings: list[RiskFinding], per_signal_limit: int = 3) -> list[RiskFinding]:
    counts: dict[str, int] = {}
    capped: list[RiskFinding] = []
    for finding in findings:
        counts[finding.signal] = counts.get(finding.signal, 0) + 1
        if counts[finding.signal] <= per_signal_limit:
            capped.append(finding)
    return capped


def _policy_matches(rule: PolicyRule, item: SoftwareItem) -> bool:
    pattern = rule.pattern.strip().lower()
    if not pattern:
        return False
    fields = {
        "name": item.name,
        "publisher": item.publisher,
        "path": " ".join([item.install_location, item.executable_path]),
        "stable_key": item.stable_key(),
    }
    value = fields.get(rule.match_type, " ".join(fields.values()))
    return pattern in value.lower()
