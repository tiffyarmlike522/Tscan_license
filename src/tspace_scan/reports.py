from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from .models import SoftwareItem, utc_now_iso
from .paths import default_export_dir


REPORT_COLUMNS = [
    "name",
    "publisher",
    "version",
    "install_date",
    "install_location",
    "executable_path",
    "website",
    "estimated_size_kb",
    "install_type",
    "app_group",
    "app_category",
    "is_license_relevant",
    "license_type",
    "license_confidence",
    "signature_status",
    "signature_subject",
    "risk_score",
    "risk_level",
    "risk_findings",
]


def default_report_path(extension: str) -> Path:
    timestamp = utc_now_iso().replace(":", "").replace("+0000", "Z").replace("+00:00", "Z")
    return default_export_dir() / f"software_scan_{timestamp}.{extension}"


def export_csv(items: list[SoftwareItem], path: Path | None = None) -> Path:
    target = path or default_report_path("csv")
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        for item in items:
            row = item.to_dict()
            row["signature_status"] = item.signature.status
            row["signature_subject"] = item.signature.subject
            row["risk_findings"] = " | ".join(f"{f.signal}: {f.reason}" for f in item.risk_findings)
            writer.writerow({column: row.get(column, "") for column in REPORT_COLUMNS})
    return target


def export_json(items: list[SoftwareItem], path: Path | None = None) -> Path:
    target = path or default_report_path("json")
    payload = {
        "generated_at": utc_now_iso(),
        "items": [item.to_dict() for item in items],
        "summary": summarize(items),
        "manager_summary": (
            "This report inventories installed software, license classification signals, "
            "and license-compliance risk indicators. Findings are risk signals, not proof "
            "of unauthorized use."
        ),
    }
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def export_xlsx(items: list[SoftwareItem], path: Path | None = None) -> Path:
    target = path or default_report_path("xlsx")
    rows = [REPORT_COLUMNS]
    for item in items:
        rows.append(
            [
                item.name,
                item.publisher,
                item.version,
                item.install_date,
                item.install_location,
                item.executable_path,
                item.website,
                str(item.estimated_size_kb),
                item.install_type,
                item.app_group,
                item.app_category,
                "yes" if item.is_license_relevant else "no",
                item.license_type,
                str(item.license_confidence),
                item.signature.status,
                item.signature.subject,
                str(item.risk_score),
                item.risk_level,
                " | ".join(f"{finding.signal}: {finding.reason}" for finding in item.risk_findings),
            ]
        )
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as workbook:
        workbook.writestr("[Content_Types].xml", _xlsx_content_types())
        workbook.writestr("_rels/.rels", _xlsx_root_rels())
        workbook.writestr("xl/workbook.xml", _xlsx_workbook())
        workbook.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_rels())
        workbook.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet(rows))
    return target


def export_pdf(items: list[SoftwareItem], path: Path | None = None) -> Path:
    target = path or default_report_path("pdf")
    lines = [
        "T-Space License Risk Scanner Report",
        f"Generated at: {utc_now_iso()}",
        "",
        "Manager summary:",
        "This report inventories installed software, license classification signals, and license-compliance risk indicators.",
        "Findings are indicators, not proof of unauthorized use.",
        "",
        "Summary:",
    ]
    summary = summarize(items)
    for key, value in sorted(summary.items()):
        lines.append(f"- {key}: {value}")
    lines.extend(["", "Software inventory:"])
    for item in items:
        lines.append(
            f"{item.name} | {item.publisher or '-'} | {item.version or '-'} | "
            f"{item.app_group}/{item.app_category} | {item.license_type} {item.license_confidence}/100 | "
            f"Risk {item.risk_score}/100 {item.risk_level}"
        )
        if item.signature.status != "NotChecked":
            lines.append(f"  Signature: {item.signature.status} {item.signature.subject}")
        for finding in item.risk_findings[:3]:
            lines.append(f"  Finding: {finding.signal} - {finding.reason}")
    target.write_bytes(_simple_pdf(lines))
    return target


def summarize(items: list[SoftwareItem]) -> dict[str, int]:
    summary: dict[str, int] = {"total": len(items), "risk_findings": 0}
    for item in items:
        summary[item.license_type] = summary.get(item.license_type, 0) + 1
        summary[item.risk_level] = summary.get(item.risk_level, 0) + 1
        summary[item.app_group] = summary.get(item.app_group, 0) + 1
        summary["risk_findings"] += len(item.risk_findings)
    return summary


def _xlsx_content_types() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""


def _xlsx_root_rels() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""


def _xlsx_workbook() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Software Inventory" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""


def _xlsx_workbook_rels() -> str:
    return """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""


def _xlsx_sheet(rows: list[list[str]]) -> str:
    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for column_index, value in enumerate(row, start=1):
            ref = f"{_column_letter(column_index)}{row_index}"
            text = escape(str(value or ""))
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>')
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData>'
        "</worksheet>"
    )


def _column_letter(index: int) -> str:
    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _simple_pdf(lines: list[str]) -> bytes:
    pages = [lines[index : index + 46] for index in range(0, len(lines), 46)] or [[]]
    font_object_id = 3 + len(pages) * 2
    ordered: dict[int, bytes] = {1: b"<< /Type /Catalog /Pages 2 0 R >>"}
    page_refs = [f"{3 + index * 2} 0 R" for index in range(len(pages))]
    ordered[2] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode("ascii")
    for index, page in enumerate(pages):
        page_id = 3 + index * 2
        content_id = page_id + 1
        stream = _pdf_page_stream(page)
        ordered[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_object_id} 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        ordered[content_id] = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
    ordered[font_object_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for object_id in sorted(ordered):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(ordered[object_id])
        output.extend(b"\nendobj\n")
    xref_at = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _pdf_page_stream(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "50 760 Td"]
    for line in lines:
        commands.append(f"({_pdf_escape(line[:120])}) Tj")
        commands.append("0 -15 Td")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
