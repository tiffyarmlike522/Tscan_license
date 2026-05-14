from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from .models import DigitalSignatureInfo, utc_now_iso


LOGGER = logging.getLogger(__name__)


class SignatureVerifier:
    def __init__(self, timeout_seconds: int = 8) -> None:
        self.timeout_seconds = timeout_seconds
        self._cache: dict[str, DigitalSignatureInfo] = {}

    def verify(self, executable_path: str) -> DigitalSignatureInfo:
        if not executable_path:
            return DigitalSignatureInfo(status="NotChecked", status_message="No executable path was available.")
        path = Path(executable_path)
        if not path.exists() or not path.is_file():
            return DigitalSignatureInfo(status="NotFound", status_message="Executable file was not found.", checked_at=utc_now_iso())

        cache_key = str(path).lower()
        if cache_key in self._cache:
            return self._cache[cache_key]

        script = (
            "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "& { param([string]$Target) "
            "$sig = Get-AuthenticodeSignature -LiteralPath $Target; "
            "[PSCustomObject]@{"
            "Status=$sig.Status.ToString();"
            "StatusMessage=$sig.StatusMessage;"
            "Subject=if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' };"
            "Issuer=if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { '' };"
            "Thumbprint=if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { '' }"
            "} | ConvertTo-Json -Compress }"
        )
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                    str(path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                creationflags=_creation_flags(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOGGER.warning("Signature check failed for %s: %s", path, exc)
            info = DigitalSignatureInfo(
                status="CheckFailed",
                status_message=str(exc),
                checked_at=utc_now_iso(),
            )
            self._cache[cache_key] = info
            return info

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout).strip()
            info = DigitalSignatureInfo(status="CheckFailed", status_message=message, checked_at=utc_now_iso())
            self._cache[cache_key] = info
            return info

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            info = DigitalSignatureInfo(
                status="CheckFailed",
                status_message="PowerShell returned an unreadable signature payload.",
                checked_at=utc_now_iso(),
            )
            self._cache[cache_key] = info
            return info

        info = DigitalSignatureInfo(
            status=str(payload.get("Status") or "Unknown"),
            status_message=str(payload.get("StatusMessage") or ""),
            subject=str(payload.get("Subject") or ""),
            issuer=str(payload.get("Issuer") or ""),
            thumbprint=str(payload.get("Thumbprint") or ""),
            checked_at=utc_now_iso(),
        )
        self._cache[cache_key] = info
        return info

    def verify_many(self, executable_paths: list[str]) -> dict[str, DigitalSignatureInfo]:
        unique_paths = []
        results: dict[str, DigitalSignatureInfo] = {}
        for raw_path in executable_paths:
            if not raw_path:
                continue
            path = Path(raw_path)
            cache_key = str(path).lower()
            if cache_key in self._cache:
                results[str(path)] = self._cache[cache_key]
                continue
            if not path.exists() or not path.is_file():
                info = DigitalSignatureInfo(
                    status="NotFound",
                    status_message="Executable file was not found.",
                    checked_at=utc_now_iso(),
                )
                self._cache[cache_key] = info
                results[str(path)] = info
                continue
            unique_paths.append(str(path))

        if not unique_paths:
            return results

        script = (
            "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "$ErrorActionPreference = 'SilentlyContinue'; "
            "$json = [Console]::In.ReadToEnd(); "
            "$paths = $json | ConvertFrom-Json; "
            "$rows = foreach ($Target in $paths) { "
            "try { "
            "$sig = Get-AuthenticodeSignature -LiteralPath $Target; "
            "[PSCustomObject]@{"
            "Path=$Target;"
            "Status=$sig.Status.ToString();"
            "StatusMessage=$sig.StatusMessage;"
            "Subject=if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' };"
            "Issuer=if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { '' };"
            "Thumbprint=if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { '' }"
            "} "
            "} catch { "
            "[PSCustomObject]@{Path=$Target;Status='CheckFailed';StatusMessage=$_.Exception.Message;Subject='';Issuer='';Thumbprint=''} "
            "} "
            "}; "
            "$rows | ConvertTo-Json -Compress"
        )
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                input=json.dumps(unique_paths),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(self.timeout_seconds, min(90, 4 + len(unique_paths) * 2)),
                check=False,
                creationflags=_creation_flags(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            LOGGER.warning("Batch signature check failed: %s", exc)
            for raw_path in unique_paths:
                info = DigitalSignatureInfo(status="CheckFailed", status_message=str(exc), checked_at=utc_now_iso())
                self._cache[raw_path.lower()] = info
                results[raw_path] = info
            return results

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout).strip()
            for raw_path in unique_paths:
                info = DigitalSignatureInfo(status="CheckFailed", status_message=message, checked_at=utc_now_iso())
                self._cache[raw_path.lower()] = info
                results[raw_path] = info
            return results

        try:
            payload = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError:
            payload = []
        if isinstance(payload, dict):
            payload = [payload]

        rows_by_path = {str(row.get("Path", "")): row for row in payload if isinstance(row, dict)}
        for raw_path in unique_paths:
            row = rows_by_path.get(raw_path)
            if not row:
                info = DigitalSignatureInfo(
                    status="CheckFailed",
                    status_message="PowerShell did not return a signature result for this path.",
                    checked_at=utc_now_iso(),
                )
            else:
                info = DigitalSignatureInfo(
                    status=str(row.get("Status") or "Unknown"),
                    status_message=str(row.get("StatusMessage") or ""),
                    subject=str(row.get("Subject") or ""),
                    issuer=str(row.get("Issuer") or ""),
                    thumbprint=str(row.get("Thumbprint") or ""),
                    checked_at=utc_now_iso(),
                )
            self._cache[raw_path.lower()] = info
            results[raw_path] = info
        return results


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
