from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .filesystem_scanner import read_text_samples
from .models import SoftwareItem
from .paths import default_rules_path


class LicenseClassifier:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or default_rules_path()
        self.rules = self._load_rules(self.rules_path)

    def classify(self, item: SoftwareItem, user_override: str = "") -> SoftwareItem:
        candidates: list[tuple[str, int, str]] = []
        if user_override:
            candidates.append((user_override, 100, "User override from whitelist/policy database."))

        name = item.name.lower()
        publisher = item.publisher.lower()

        for rule in self.rules.get("known_software", []):
            if _contains_any(name, rule.get("name_contains", [])):
                candidates.append(
                    (
                        rule["license_type"],
                        int(rule.get("confidence", 75)),
                        f"Matched offline software rule: {rule.get('explanation', rule['license_type'])}",
                    )
                )

        for rule in self.rules.get("publisher_rules", []):
            if publisher and _contains_any(publisher, rule.get("publisher_contains", [])):
                candidates.append(
                    (
                        rule["license_type"],
                        int(rule.get("confidence", 65)),
                        f"Matched publisher rule for '{item.publisher}'.",
                    )
                )

        keyword_result = self._classify_by_name_keywords(name)
        if keyword_result:
            candidates.append(keyword_result)

        license_text = read_text_samples(item.license_files).lower()
        if license_text:
            candidates.extend(self._classify_by_license_text(license_text))

        if item.website and any(token in item.website.lower() for token in ("github.com", "gitlab.com", "sourceforge.net")):
            candidates.append(("Open-source software", 60, "Project website points to a common source hosting platform."))

        if not candidates:
            item.license_type = "Unknown"
            item.license_confidence = 0
            item.license_explanation = "No reliable metadata, publisher, rule, or license file signal was found."
            return item

        best = sorted(candidates, key=lambda x: x[1], reverse=True)[0]
        if best[1] < 45:
            item.license_type = "Unknown"
            item.license_confidence = best[1]
            item.license_explanation = f"Weak signal only: {best[2]}"
        else:
            item.license_type = best[0]
            item.license_confidence = min(best[1], 100)
            item.license_explanation = best[2]
        return item

    def _classify_by_name_keywords(self, name: str) -> tuple[str, int, str] | None:
        if any(token in name for token in (" trial", "demo", "evaluation")):
            return ("Trial software", 70, "Name contains trial/evaluation wording.")
        if any(token in name for token in ("community", "free edition", "express")):
            return ("Freemium", 58, "Name suggests a free/community tier.")
        if any(token in name for token in ("open source", "oss")):
            return ("Open-source software", 65, "Name contains open-source wording.")
        return None

    def _classify_by_license_text(self, text: str) -> list[tuple[str, int, str]]:
        results: list[tuple[str, int, str]] = []
        for rule in self.rules.get("license_text_rules", []):
            if _contains_any(text, rule.get("contains", [])):
                results.append(
                    (
                        rule["license_type"],
                        int(rule.get("confidence", 70)),
                        f"Matched license file text rule: {rule.get('explanation', rule['license_type'])}",
                    )
                )
        return results

    @staticmethod
    def _load_rules(path: Path) -> dict[str, Any]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"known_software": [], "publisher_rules": [], "license_text_rules": []}


def _contains_any(value: str, needles: list[str]) -> bool:
    return any(needle.lower() in value for needle in needles)
