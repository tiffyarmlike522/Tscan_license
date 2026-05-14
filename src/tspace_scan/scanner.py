from __future__ import annotations

import logging

from .app_classifier import classify_app, should_drop_from_default_scan
from .filesystem_scanner import enrich_item_from_filesystem, scan_program_directories, scan_start_menu_shortcuts
from .license_classifier import LicenseClassifier
from .models import SoftwareItem
from .registry_scanner import scan_registry
from .risk_analyzer import RiskAnalyzer
from .signature_verifier import SignatureVerifier


LOGGER = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(
        self,
        classifier: LicenseClassifier | None = None,
        analyzer: RiskAnalyzer | None = None,
        signature_verifier: SignatureVerifier | None = None,
        verify_signatures: bool = True,
        max_signature_workers: int = 4,
    ) -> None:
        self.classifier = classifier or LicenseClassifier()
        self.analyzer = analyzer or RiskAnalyzer()
        self.signature_verifier = signature_verifier or SignatureVerifier()
        self.verify_signatures = verify_signatures
        self.max_signature_workers = max(1, max_signature_workers)

    def scan(self, include_filesystem_discovery: bool = True, include_noise: bool = False) -> list[SoftwareItem]:
        LOGGER.info("Starting software scan")
        items = scan_registry()
        if include_filesystem_discovery:
            items = self._merge(items, scan_program_directories())
            items = self._merge(items, scan_start_menu_shortcuts())

        for item in items:
            enrich_item_from_filesystem(item)
            self.classifier.classify(item)
            classify_app(item)

        if not include_noise:
            before = len(items)
            items = [item for item in items if not should_drop_from_default_scan(item)]
            LOGGER.info("Filtered %s noisy helper/system entries", before - len(items))

        if self.verify_signatures:
            self._verify_signatures(items)

        processed: list[SoftwareItem] = []
        for item in items:
            self.analyzer.analyze(item)
            processed.append(item)
        LOGGER.info("Completed software scan with %s items", len(processed))
        return sorted(processed, key=lambda x: x.name.lower())

    def _verify_signatures(self, items: list[SoftwareItem]) -> None:
        executable_items = [item for item in items if item.executable_path and item.is_license_relevant]
        if not executable_items:
            return
        results = self.signature_verifier.verify_many([item.executable_path for item in executable_items])
        for item in executable_items:
            item.signature = results.get(item.executable_path, item.signature)

    @staticmethod
    def _merge(primary: list[SoftwareItem], discovered: list[SoftwareItem]) -> list[SoftwareItem]:
        by_key = {item.stable_key(): item for item in primary}
        existing_names = {item.name.strip().lower() for item in primary}
        for item in discovered:
            if item.name.strip().lower() in existing_names:
                continue
            by_key[item.stable_key()] = item
            existing_names.add(item.name.strip().lower())
        return list(by_key.values())
