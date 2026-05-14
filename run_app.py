from __future__ import annotations

import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tspace_scan.database import LocalDatabase  # noqa: E402
from tspace_scan.reports import export_pdf, export_xlsx  # noqa: E402
from tspace_scan.scanner import ScannerEngine  # noqa: E402
from tspace_scan.ui import main  # noqa: E402


def smoke_test() -> int:
    temp_dir = Path(tempfile.gettempdir())
    db_path = temp_dir / "tspace_scan_exe_smoke.db"
    pdf_path = temp_dir / "tspace_scan_exe_smoke.pdf"
    xlsx_path = temp_dir / "tspace_scan_exe_smoke.xlsx"
    for path in (db_path, pdf_path, xlsx_path):
        path.unlink(missing_ok=True)
    items = ScannerEngine(verify_signatures=False).scan(include_filesystem_discovery=False)
    db = LocalDatabase(db_path)
    session_id = db.save_scan(items[:5])
    loaded = db.load_items_for_session(session_id)
    export_pdf(loaded, pdf_path)
    export_xlsx(loaded, xlsx_path)
    ok = bool(items) and bool(loaded) and pdf_path.exists() and xlsx_path.exists()
    db.connection.close()
    for path in (db_path, pdf_path, xlsx_path):
        path.unlink(missing_ok=True)
    print(f"smoke_test={'OK' if ok else 'FAILED'} items={len(items)} loaded={len(loaded)}")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--smoke-test" in sys.argv:
        raise SystemExit(smoke_test())
    main()
