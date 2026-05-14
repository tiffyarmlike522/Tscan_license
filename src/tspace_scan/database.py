from __future__ import annotations

import json
import os
import platform
import sqlite3
from pathlib import Path

from .models import DigitalSignatureInfo, PolicyRule, RiskFinding, ScanComparison, ScanSession, SoftwareItem, utc_now_iso
from .paths import default_database_path


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    computer_name TEXT,
    user_name TEXT,
    os_version TEXT,
    total_items INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS software_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_session_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    publisher TEXT,
    version TEXT,
    install_date TEXT,
    install_location TEXT,
    executable_path TEXT,
    website TEXT,
    estimated_size_kb INTEGER NOT NULL DEFAULT 0,
    install_type TEXT,
    source TEXT,
    registry_key TEXT,
    uninstall_string TEXT,
    related_paths_json TEXT NOT NULL DEFAULT '[]',
    license_files_json TEXT NOT NULL DEFAULT '[]',
    app_category TEXT NOT NULL DEFAULT 'Unknown',
    app_group TEXT NOT NULL DEFAULT 'Unknown',
    is_license_relevant INTEGER NOT NULL DEFAULT 1,
    is_noise INTEGER NOT NULL DEFAULT 0,
    app_classification_reason TEXT,
    license_type TEXT NOT NULL DEFAULT 'Unknown',
    license_confidence INTEGER NOT NULL DEFAULT 0,
    license_explanation TEXT,
    signature_status TEXT NOT NULL DEFAULT 'NotChecked',
    signature_status_message TEXT,
    signature_subject TEXT,
    signature_issuer TEXT,
    signature_thumbprint TEXT,
    signature_checked_at TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'Low Risk',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    software_item_id INTEGER NOT NULL,
    signal TEXT NOT NULL,
    reason TEXT NOT NULL,
    path TEXT,
    level TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0,
    score_delta INTEGER NOT NULL DEFAULT 0,
    recommendation TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (software_item_id) REFERENCES software_items(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS license_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    match_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    license_type TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    explanation TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS publisher_database (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_name TEXT NOT NULL UNIQUE,
    canonical_name TEXT,
    default_license_type TEXT,
    website TEXT,
    trust_level TEXT NOT NULL DEFAULT 'unknown',
    notes TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    reason TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    risk_level TEXT NOT NULL DEFAULT 'High Risk',
    reason TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_software_session ON software_items(scan_session_id);
CREATE INDEX IF NOT EXISTS idx_software_name ON software_items(name);
CREATE INDEX IF NOT EXISTS idx_software_publisher ON software_items(publisher);
CREATE INDEX IF NOT EXISTS idx_software_license ON software_items(license_type);
CREATE INDEX IF NOT EXISTS idx_software_risk ON software_items(risk_level, risk_score);
CREATE INDEX IF NOT EXISTS idx_findings_software ON risk_findings(software_item_id);
CREATE INDEX IF NOT EXISTS idx_findings_signal ON risk_findings(signal);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON license_rules(enabled, match_type);
CREATE INDEX IF NOT EXISTS idx_whitelist_match ON whitelist(match_type, pattern);
CREATE INDEX IF NOT EXISTS idx_blacklist_match ON blacklist(match_type, pattern);
"""


class LocalDatabase:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript(SCHEMA_SQL)
        self._migrate_schema()
        self._create_post_migration_indexes()
        self.connection.commit()

    def _migrate_schema(self) -> None:
        software_columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(software_items)").fetchall()
        }
        migrations = {
            "signature_status": "ALTER TABLE software_items ADD COLUMN signature_status TEXT NOT NULL DEFAULT 'NotChecked'",
            "signature_status_message": "ALTER TABLE software_items ADD COLUMN signature_status_message TEXT",
            "signature_subject": "ALTER TABLE software_items ADD COLUMN signature_subject TEXT",
            "signature_issuer": "ALTER TABLE software_items ADD COLUMN signature_issuer TEXT",
            "signature_thumbprint": "ALTER TABLE software_items ADD COLUMN signature_thumbprint TEXT",
            "signature_checked_at": "ALTER TABLE software_items ADD COLUMN signature_checked_at TEXT",
            "app_category": "ALTER TABLE software_items ADD COLUMN app_category TEXT NOT NULL DEFAULT 'Unknown'",
            "app_group": "ALTER TABLE software_items ADD COLUMN app_group TEXT NOT NULL DEFAULT 'Unknown'",
            "is_license_relevant": "ALTER TABLE software_items ADD COLUMN is_license_relevant INTEGER NOT NULL DEFAULT 1",
            "is_noise": "ALTER TABLE software_items ADD COLUMN is_noise INTEGER NOT NULL DEFAULT 0",
            "app_classification_reason": "ALTER TABLE software_items ADD COLUMN app_classification_reason TEXT",
        }
        for column, statement in migrations.items():
            if column not in software_columns:
                self.connection.execute(statement)

    def _create_post_migration_indexes(self) -> None:
        self.connection.execute("CREATE INDEX IF NOT EXISTS idx_software_group ON software_items(app_group, app_category)")
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_software_relevance ON software_items(is_license_relevant, is_noise)"
        )

    def save_scan(self, items: list[SoftwareItem]) -> int:
        session = ScanSession(
            completed_at=utc_now_iso(),
            computer_name=platform.node(),
            user_name=os.environ.get("USERNAME") or os.environ.get("USER") or "",
            os_version=platform.platform(),
            total_items=len(items),
            total_findings=sum(len(item.risk_findings) for item in items),
            summary_json=json.dumps(_summary(items), ensure_ascii=False),
        )
        cursor = self.connection.cursor()
        cursor.execute(
            """
            INSERT INTO scan_sessions (
                started_at, completed_at, computer_name, user_name, os_version,
                total_items, total_findings, summary_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.started_at,
                session.completed_at,
                session.computer_name,
                session.user_name,
                session.os_version,
                session.total_items,
                session.total_findings,
                session.summary_json,
            ),
        )
        session_id = int(cursor.lastrowid)
        for item in items:
            software_id = self._insert_item(cursor, session_id, item)
            for finding in item.risk_findings:
                cursor.execute(
                    """
                    INSERT INTO risk_findings (
                        software_item_id, signal, reason, path, level, confidence,
                        score_delta, recommendation, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        software_id,
                        finding.signal,
                        finding.reason,
                        finding.path,
                        finding.level,
                        finding.confidence,
                        finding.score_delta,
                        finding.recommendation,
                        utc_now_iso(),
                    ),
                )
        self.connection.commit()
        return session_id

    def add_whitelist(self, pattern: str, match_type: str = "name", reason: str = "Marked safe in UI") -> None:
        self.connection.execute(
            "INSERT INTO whitelist(match_type, pattern, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
            (match_type, pattern, reason, os.environ.get("USERNAME", ""), utc_now_iso()),
        )
        self.connection.commit()

    def load_whitelist_patterns(self) -> set[str]:
        rows = self.connection.execute("SELECT pattern FROM whitelist").fetchall()
        return {str(row["pattern"]).lower() for row in rows}

    def list_whitelist(self) -> list[PolicyRule]:
        rows = self.connection.execute(
            "SELECT id, match_type, pattern, reason, created_by, created_at FROM whitelist ORDER BY created_at DESC"
        ).fetchall()
        return [
            PolicyRule(
                id=int(row["id"]),
                match_type=row["match_type"],
                pattern=row["pattern"],
                reason=row["reason"] or "",
                created_by=row["created_by"] or "",
                created_at=row["created_at"] or "",
            )
            for row in rows
        ]

    def add_blacklist(
        self,
        pattern: str,
        match_type: str = "name",
        risk_level: str = "High Risk",
        reason: str = "Blocked by local policy",
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO blacklist(match_type, pattern, risk_level, reason, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (match_type, pattern, risk_level, reason, os.environ.get("USERNAME", ""), utc_now_iso()),
        )
        self.connection.commit()

    def list_blacklist(self) -> list[PolicyRule]:
        rows = self.connection.execute(
            """
            SELECT id, match_type, pattern, risk_level, reason, created_by, created_at
            FROM blacklist
            ORDER BY created_at DESC
            """
        ).fetchall()
        return [
            PolicyRule(
                id=int(row["id"]),
                match_type=row["match_type"],
                pattern=row["pattern"],
                risk_level=row["risk_level"] or "High Risk",
                reason=row["reason"] or "",
                created_by=row["created_by"] or "",
                created_at=row["created_at"] or "",
            )
            for row in rows
        ]

    def delete_policy(self, table: str, policy_id: int) -> None:
        if table not in {"whitelist", "blacklist"}:
            raise ValueError("Unsupported policy table")
        self.connection.execute(f"DELETE FROM {table} WHERE id = ?", (policy_id,))
        self.connection.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.connection.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.connection.execute(
            """
            INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, utc_now_iso()),
        )
        self.connection.commit()

    def list_scan_sessions(self, limit: int = 200) -> list[dict[str, object]]:
        rows = self.connection.execute(
            """
            SELECT id, started_at, completed_at, computer_name, user_name, os_version,
                   total_items, total_findings, summary_json
            FROM scan_sessions
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def load_items_for_session(self, session_id: int) -> list[SoftwareItem]:
        rows = self.connection.execute(
            "SELECT * FROM software_items WHERE scan_session_id = ? ORDER BY lower(name)",
            (session_id,),
        ).fetchall()
        items = [self._item_from_row(row) for row in rows]
        if not items:
            return []
        item_by_id = {int(row["id"]): item for row, item in zip(rows, items)}
        placeholders = ",".join("?" for _ in item_by_id)
        finding_rows = self.connection.execute(
            f"SELECT * FROM risk_findings WHERE software_item_id IN ({placeholders}) ORDER BY id",
            tuple(item_by_id),
        ).fetchall()
        for row in finding_rows:
            item = item_by_id.get(int(row["software_item_id"]))
            if not item:
                continue
            item.risk_findings.append(
                RiskFinding(
                    signal=row["signal"],
                    reason=row["reason"],
                    path=row["path"] or "",
                    level=row["level"],
                    confidence=int(row["confidence"] or 0),
                    score_delta=int(row["score_delta"] or 0),
                    recommendation=row["recommendation"] or "",
                )
            )
        return items

    def compare_sessions(self, old_session_id: int, new_session_id: int) -> ScanComparison:
        old_items = self.load_items_for_session(old_session_id)
        new_items = self.load_items_for_session(new_session_id)
        old_by_key = {_comparison_key(item): item for item in old_items}
        new_by_key = {_comparison_key(item): item for item in new_items}
        added = [new_by_key[key] for key in sorted(new_by_key.keys() - old_by_key.keys())]
        removed = [old_by_key[key] for key in sorted(old_by_key.keys() - new_by_key.keys())]
        changed: list[tuple[SoftwareItem, SoftwareItem, list[str]]] = []
        for key in sorted(old_by_key.keys() & new_by_key.keys()):
            old_item = old_by_key[key]
            new_item = new_by_key[key]
            fields = []
            for field in ("version", "license_type", "app_group", "risk_score", "risk_level", "install_location", "signature_status"):
                old_value = _field_value(old_item, field)
                new_value = _field_value(new_item, field)
                if old_value != new_value:
                    fields.append(field)
            if fields:
                changed.append((old_item, new_item, fields))
        return ScanComparison(old_session_id=old_session_id, new_session_id=new_session_id, added=added, removed=removed, changed=changed)

    def _insert_item(self, cursor: sqlite3.Cursor, session_id: int, item: SoftwareItem) -> int:
        cursor.execute(
            """
            INSERT INTO software_items (
                scan_session_id, name, publisher, version, install_date, install_location,
                executable_path, website, estimated_size_kb, install_type, source,
                registry_key, uninstall_string, related_paths_json, license_files_json,
                app_category, app_group, is_license_relevant, is_noise, app_classification_reason,
                license_type, license_confidence, license_explanation,
                signature_status, signature_status_message, signature_subject,
                signature_issuer, signature_thumbprint, signature_checked_at,
                risk_score, risk_level, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                item.name,
                item.publisher,
                item.version,
                item.install_date,
                item.install_location,
                item.executable_path,
                item.website,
                item.estimated_size_kb,
                item.install_type,
                item.source,
                item.registry_key,
                item.uninstall_string,
                json.dumps(item.related_paths, ensure_ascii=False),
                json.dumps(item.license_files, ensure_ascii=False),
                item.app_category,
                item.app_group,
                1 if item.is_license_relevant else 0,
                1 if item.is_noise else 0,
                item.app_classification_reason,
                item.license_type,
                item.license_confidence,
                item.license_explanation,
                item.signature.status,
                item.signature.status_message,
                item.signature.subject,
                item.signature.issuer,
                item.signature.thumbprint,
                item.signature.checked_at,
                item.risk_score,
                item.risk_level,
                utc_now_iso(),
            ),
        )
        return int(cursor.lastrowid)

    def _item_from_row(self, row: sqlite3.Row) -> SoftwareItem:
        def loads_list(value: str | None) -> list[str]:
            if not value:
                return []
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                return []
            return [str(item) for item in data] if isinstance(data, list) else []

        return SoftwareItem(
            name=row["name"],
            publisher=row["publisher"] or "",
            version=row["version"] or "",
            install_date=row["install_date"] or "",
            install_location=row["install_location"] or "",
            executable_path=row["executable_path"] or "",
            website=row["website"] or "",
            estimated_size_kb=int(row["estimated_size_kb"] or 0),
            install_type=row["install_type"] or "unknown",
            source=row["source"] or "",
            registry_key=row["registry_key"] or "",
            uninstall_string=row["uninstall_string"] or "",
            related_paths=loads_list(row["related_paths_json"]),
            license_files=loads_list(row["license_files_json"]),
            app_category=row["app_category"] or "Unknown",
            app_group=row["app_group"] or "Unknown",
            is_license_relevant=bool(row["is_license_relevant"]),
            is_noise=bool(row["is_noise"]),
            app_classification_reason=row["app_classification_reason"] or "",
            license_type=row["license_type"] or "Unknown",
            license_confidence=int(row["license_confidence"] or 0),
            license_explanation=row["license_explanation"] or "",
            signature=DigitalSignatureInfo(
                status=row["signature_status"] or "NotChecked",
                status_message=row["signature_status_message"] or "",
                subject=row["signature_subject"] or "",
                issuer=row["signature_issuer"] or "",
                thumbprint=row["signature_thumbprint"] or "",
                checked_at=row["signature_checked_at"] or "",
            ),
            risk_score=int(row["risk_score"] or 0),
            risk_level=row["risk_level"] or "Low Risk",
        )


def _summary(items: list[SoftwareItem]) -> dict[str, int]:
    summary: dict[str, int] = {
        "total": len(items),
        "findings": sum(len(item.risk_findings) for item in items),
    }
    for item in items:
        summary[item.license_type] = summary.get(item.license_type, 0) + 1
        summary[item.risk_level] = summary.get(item.risk_level, 0) + 1
        summary[item.app_group] = summary.get(item.app_group, 0) + 1
        summary[item.app_category] = summary.get(item.app_category, 0) + 1
    return summary


def _comparison_key(item: SoftwareItem) -> str:
    publisher = item.publisher.strip().lower()
    name = item.name.strip().lower()
    path = item.install_location.strip().lower()
    if publisher:
        return f"{publisher}|{name}"
    return f"{name}|{path}"


def _field_value(item: SoftwareItem, field: str) -> object:
    if field == "signature_status":
        return item.signature.status
    return getattr(item, field)
