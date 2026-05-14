from __future__ import annotations

import logging
import queue
import threading
import webbrowser
from pathlib import Path
from tkinter import BOTH, DISABLED, END, LEFT, NORMAL, RIGHT, WORD, X, BooleanVar, Canvas, StringVar, Text, Tk, messagebox
from tkinter import filedialog, ttk

from .database import LocalDatabase
from .license_classifier import LicenseClassifier
from .logging_config import configure_logging
from .models import APP_CATEGORIES, APP_GROUPS, LICENSE_TYPES, RISK_LEVELS, PolicyRule, SoftwareItem
from .paths import default_log_path
from .reports import export_csv, export_json, export_pdf, export_xlsx, summarize
from .risk_analyzer import RiskAnalyzer
from .scanner import ScannerEngine


LOGGER = logging.getLogger(__name__)


class TSpaceScanApp:
    def __init__(self) -> None:
        configure_logging()
        self.root = Tk()
        self.root.title("T-Space License Risk Scanner Professional")
        self.root.geometry("1500x900")
        self.root.minsize(1180, 720)
        self.root.option_add("*Font", "{Segoe UI} 9")

        self.db = LocalDatabase()
        self.items: list[SoftwareItem] = []
        self.filtered: list[SoftwareItem] = []
        self.selected_item: SoftwareItem | None = None
        self.sessions: list[dict[str, object]] = []
        self.sort_column = "name"
        self.sort_reverse = False
        self.queue: queue.Queue[tuple[str, object]] = queue.Queue()

        self.search_text = StringVar()
        self.license_filter = StringVar(value="All")
        self.risk_filter = StringVar(value="All")
        saved_group_filter = self.db.get_setting("default_group_filter", "All")
        if saved_group_filter == "Consumer/Free":
            saved_group_filter = "Free/Open-source"
        if saved_group_filter == "License relevant":
            saved_group_filter = "All"
        self.group_filter = StringVar(value=saved_group_filter if saved_group_filter in ("All",) + APP_GROUPS else "All")
        self.category_filter = StringVar(value="All")
        self.status_text = StringVar(value="Ready")
        self.scan_phase = 0
        self.scan_animation_job: str | None = None
        self.is_scanning = False
        self.theme = StringVar(value=self.db.get_setting("theme", "Light"))
        self.verify_signatures = BooleanVar(value=self.db.get_setting("verify_signatures", "1") == "1")
        self.include_noise = BooleanVar(value=self.db.get_setting("include_noise", "0") == "1")
        self.history_old_session = StringVar()
        self.history_new_session = StringVar()
        self.policy_pattern = StringVar()
        self.policy_match_type = StringVar(value="name")
        self.blacklist_risk_level = StringVar(value="High Risk")

        self._configure_style()
        self._build_ui()
        self.refresh_history()
        self.refresh_policy_lists()
        self.root.after(150, self._drain_queue)
        LOGGER.info("Application started")

    def run(self) -> None:
        self.root.mainloop()

    def _configure_style(self) -> None:
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_theme()

    def _apply_theme(self) -> None:
        dark = self.theme.get() == "Dark"
        self.colors = {
            "bg": "#0f172a" if dark else "#f4f7fb",
            "header": "#111827" if dark else "#ffffff",
            "panel": "#1f2937" if dark else "#ffffff",
            "panel_soft": "#172033" if dark else "#eef4ff",
            "text": "#f8fafc" if dark else "#101828",
            "muted": "#a7b0c0" if dark else "#667085",
            "border": "#334155" if dark else "#d0d8e5",
            "tree": "#111827" if dark else "#ffffff",
            "tree_alt": "#182338" if dark else "#f8fbff",
            "accent": "#60a5fa" if dark else "#1d4ed8",
            "accent_soft": "#1e3a8a" if dark else "#dbeafe",
            "good": "#34d399" if dark else "#059669",
            "warn": "#fbbf24" if dark else "#d97706",
            "danger": "#f87171" if dark else "#dc2626",
        }
        self.root.configure(background=self.colors["bg"])
        self.style.configure(".", background=self.colors["bg"], foreground=self.colors["text"], fieldbackground=self.colors["panel"])
        self.style.configure("TFrame", background=self.colors["bg"])
        self.style.configure("Header.TFrame", background=self.colors["header"])
        self.style.configure("Panel.TFrame", background=self.colors["panel"], relief="solid", borderwidth=1)
        self.style.configure("Filter.TFrame", background=self.colors["panel"], relief="solid", borderwidth=1)
        self.style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        self.style.configure("HeaderTitle.TLabel", background=self.colors["header"], foreground=self.colors["text"], font=("Segoe UI", 15, "bold"))
        self.style.configure("HeaderSub.TLabel", background=self.colors["header"], foreground=self.colors["muted"], font=("Segoe UI", 9))
        self.style.configure("Muted.TLabel", foreground=self.colors["muted"], background=self.colors["bg"])
        self.style.configure("Metric.TLabel", font=("Segoe UI", 17, "bold"), foreground=self.colors["text"], background=self.colors["panel"])
        self.style.configure("MetricName.TLabel", foreground=self.colors["muted"], background=self.colors["panel"])
        self.style.configure("PanelTitle.TLabel", font=("Segoe UI", 14, "bold"), foreground=self.colors["text"], background=self.colors["panel"])
        self.style.configure("TButton", padding=(12, 7), font=("Segoe UI", 9))
        self.style.configure("Accent.TButton", padding=(14, 8), font=("Segoe UI", 9, "bold"))
        self.style.configure("TCheckbutton", background=self.colors["header"], foreground=self.colors["text"])
        self.style.configure("Horizontal.TProgressbar", troughcolor=self.colors["panel_soft"], background=self.colors["accent"])
        self.style.configure("Treeview", rowheight=30, background=self.colors["tree"], fieldbackground=self.colors["tree"], foreground=self.colors["text"], borderwidth=0)
        self.style.configure("Treeview.Heading", background=self.colors["panel_soft"], foreground=self.colors["text"], font=("Segoe UI", 9, "bold"), padding=(6, 7))
        self.style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI", 9))
        self.style.map("Treeview", background=[("selected", self.colors["accent"])])
        if hasattr(self, "tree"):
            self._configure_tree_tags()
        if hasattr(self, "detail_text"):
            self._configure_detail_text()
        if hasattr(self, "license_chart"):
            self._render_metrics()
            self._render_charts()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=(18, 14), style="Header.TFrame")
        top.pack(fill=X)
        title_box = ttk.Frame(top, style="Header.TFrame")
        title_box.pack(side=LEFT, padx=(0, 20))
        ttk.Label(title_box, text="T-Space Scan", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Software inventory and license risk dashboard", style="HeaderSub.TLabel").pack(anchor="w")
        self.scan_button = ttk.Button(top, text="Scan", command=self.start_scan, style="Accent.TButton")
        self.scan_button.pack(side=LEFT)
        for label, extension in (("CSV", "csv"), ("JSON", "json"), ("PDF", "pdf"), ("Excel", "xlsx")):
            ttk.Button(top, text=f"Export {label}", command=lambda ext=extension: self.export_report(ext)).pack(side=LEFT, padx=(8, 0))
        ttk.Checkbutton(top, text="Digital signatures", variable=self.verify_signatures, command=self.save_settings).pack(side=LEFT, padx=(14, 0))
        self.scan_progress = ttk.Progressbar(top, mode="indeterminate", length=180)
        self.scan_progress.pack(side=LEFT, padx=(12, 0))
        ttk.Label(top, textvariable=self.status_text, style="Muted.TLabel").pack(side=RIGHT)

        body = ttk.PanedWindow(self.root, orient="horizontal")
        body.pack(fill=BOTH, expand=True, padx=18, pady=(14, 18))

        main = ttk.Frame(body)
        detail_panel = ttk.Frame(body, width=420)
        body.add(main, weight=5)
        body.add(detail_panel, weight=2)

        self.tabs = ttk.Notebook(main)
        self.tabs.pack(fill=BOTH, expand=True)
        self.dashboard_tab = ttk.Frame(self.tabs, padding=12)
        self.history_tab = ttk.Frame(self.tabs, padding=12)
        self.compare_tab = ttk.Frame(self.tabs, padding=12)
        self.settings_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.history_tab, text="Scan history")
        self.tabs.add(self.compare_tab, text="Compare")
        self.tabs.add(self.settings_tab, text="Settings")

        self._build_dashboard_tab()
        self._build_history_tab()
        self._build_compare_tab()
        self._build_settings_tab()
        self._build_detail_panel(detail_panel)
        self._render_metrics()
        self._render_charts()

    def _build_dashboard_tab(self) -> None:
        self.metrics_frame = ttk.Frame(self.dashboard_tab)
        self.metrics_frame.pack(fill=X, pady=(0, 12))

        charts = ttk.Frame(self.dashboard_tab)
        charts.pack(fill=X, pady=(0, 12))
        self.license_chart = Canvas(charts, height=178, background=self.colors["panel"], highlightthickness=1, highlightbackground=self.colors["border"])
        self.risk_chart = Canvas(charts, height=178, background=self.colors["panel"], highlightthickness=1, highlightbackground=self.colors["border"])
        self.license_chart.pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self.risk_chart.pack(side=LEFT, fill=X, expand=True)

        filters = ttk.Frame(self.dashboard_tab, padding=(12, 10), style="Filter.TFrame")
        filters.pack(fill=X, pady=(0, 10))
        ttk.Label(filters, text="Search").pack(side=LEFT)
        search = ttk.Entry(filters, textvariable=self.search_text, width=34)
        search.pack(side=LEFT, padx=(6, 12))
        search.bind("<KeyRelease>", lambda _event: self.apply_filters())
        ttk.Label(filters, text="License").pack(side=LEFT)
        license_combo = ttk.Combobox(filters, textvariable=self.license_filter, values=("All",) + LICENSE_TYPES, width=20, state="readonly")
        license_combo.pack(side=LEFT, padx=(6, 12))
        license_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_filters())
        ttk.Label(filters, text="Risk").pack(side=LEFT)
        risk_combo = ttk.Combobox(filters, textvariable=self.risk_filter, values=("All",) + RISK_LEVELS, width=16, state="readonly")
        risk_combo.pack(side=LEFT, padx=(6, 12))
        risk_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_filters())
        ttk.Label(filters, text="Group").pack(side=LEFT)
        group_combo = ttk.Combobox(filters, textvariable=self.group_filter, values=("All",) + APP_GROUPS, width=18, state="readonly")
        group_combo.pack(side=LEFT, padx=(6, 12))
        group_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_filters())
        ttk.Label(filters, text="Category").pack(side=LEFT)
        category_combo = ttk.Combobox(filters, textvariable=self.category_filter, values=("All",) + APP_CATEGORIES, width=18, state="readonly")
        category_combo.pack(side=LEFT, padx=(6, 0))
        category_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_filters())

        columns = (
            "name",
            "publisher",
            "version",
            "license_priority",
            "license_type",
            "license_confidence",
            "app_group",
            "app_category",
            "signature_status",
            "risk_score",
            "risk_level",
            "install_type",
        )
        self.tree = ttk.Treeview(self.dashboard_tab, columns=columns, show="headings")
        self._configure_tree_tags()
        headings = {
            "name": "Software",
            "publisher": "Publisher",
            "version": "Version",
            "license_priority": "Priority",
            "license_type": "License",
            "license_confidence": "Conf.",
            "app_group": "Group",
            "app_category": "Category",
            "signature_status": "Signature",
            "risk_score": "Risk",
            "risk_level": "Risk level",
            "install_type": "Install",
        }
        widths = {
            "name": 230,
            "publisher": 170,
            "version": 90,
            "license_priority": 94,
            "license_type": 140,
            "license_confidence": 64,
            "app_group": 130,
            "app_category": 130,
            "signature_status": 90,
            "risk_score": 64,
            "risk_level": 105,
            "install_type": 90,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column], command=lambda c=column: self.sort_by(c))
            self.tree.column(column, width=widths[column], anchor="w", stretch=column not in {"license_confidence", "risk_score"})
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

    def _build_history_tab(self) -> None:
        toolbar = ttk.Frame(self.history_tab)
        toolbar.pack(fill=X, pady=(0, 8))
        ttk.Button(toolbar, text="Refresh", command=self.refresh_history).pack(side=LEFT)
        ttk.Button(toolbar, text="Load selected session", command=self.load_selected_history).pack(side=LEFT, padx=(8, 0))

        columns = ("id", "completed_at", "computer_name", "user_name", "total_items", "total_findings")
        self.history_tree = ttk.Treeview(self.history_tab, columns=columns, show="headings")
        for column, label, width in (
            ("id", "ID", 70),
            ("completed_at", "Completed", 180),
            ("computer_name", "Computer", 150),
            ("user_name", "User", 120),
            ("total_items", "Items", 80),
            ("total_findings", "Findings", 90),
        ):
            self.history_tree.heading(column, text=label)
            self.history_tree.column(column, width=width, anchor="w")
        self.history_tree.pack(fill=BOTH, expand=True)

    def _build_compare_tab(self) -> None:
        toolbar = ttk.Frame(self.compare_tab)
        toolbar.pack(fill=X, pady=(0, 8))
        ttk.Label(toolbar, text="Old").pack(side=LEFT)
        self.old_session_combo = ttk.Combobox(toolbar, textvariable=self.history_old_session, width=28, state="readonly")
        self.old_session_combo.pack(side=LEFT, padx=(6, 12))
        ttk.Label(toolbar, text="New").pack(side=LEFT)
        self.new_session_combo = ttk.Combobox(toolbar, textvariable=self.history_new_session, width=28, state="readonly")
        self.new_session_combo.pack(side=LEFT, padx=(6, 12))
        ttk.Button(toolbar, text="Compare", command=self.compare_sessions).pack(side=LEFT)

        self.compare_summary = ttk.Label(self.compare_tab, text="Select two scan sessions to compare.", style="Muted.TLabel")
        self.compare_summary.pack(anchor="w", pady=(0, 8))
        columns = ("change", "name", "publisher", "old_version", "new_version", "details")
        self.compare_tree = ttk.Treeview(self.compare_tab, columns=columns, show="headings")
        for column, label, width in (
            ("change", "Change", 90),
            ("name", "Software", 220),
            ("publisher", "Publisher", 170),
            ("old_version", "Old version", 110),
            ("new_version", "New version", 110),
            ("details", "Details", 300),
        ):
            self.compare_tree.heading(column, text=label)
            self.compare_tree.column(column, width=width, anchor="w")
        self.compare_tree.pack(fill=BOTH, expand=True)

    def _build_settings_tab(self) -> None:
        general = ttk.Frame(self.settings_tab)
        general.pack(fill=X, pady=(0, 12))
        ttk.Label(general, text="Theme").pack(side=LEFT)
        theme_combo = ttk.Combobox(general, textvariable=self.theme, values=("Light", "Dark"), width=12, state="readonly")
        theme_combo.pack(side=LEFT, padx=(6, 16))
        theme_combo.bind("<<ComboboxSelected>>", lambda _event: self.save_settings())
        ttk.Checkbutton(general, text="Verify digital signatures during scan", variable=self.verify_signatures, command=self.save_settings).pack(side=LEFT)
        ttk.Checkbutton(general, text="Include helper/system noise", variable=self.include_noise, command=self.save_settings).pack(side=LEFT, padx=(14, 0))
        ttk.Label(general, text="Default view").pack(side=LEFT, padx=(14, 0))
        default_group_combo = ttk.Combobox(general, textvariable=self.group_filter, values=("All",) + APP_GROUPS, width=18, state="readonly")
        default_group_combo.pack(side=LEFT, padx=(6, 0))
        default_group_combo.bind("<<ComboboxSelected>>", lambda _event: self.save_settings())
        ttk.Label(general, text=f"Log: {default_log_path()}", style="Muted.TLabel").pack(side=RIGHT)

        policy_form = ttk.Frame(self.settings_tab)
        policy_form.pack(fill=X, pady=(0, 8))
        ttk.Label(policy_form, text="Pattern").pack(side=LEFT)
        ttk.Entry(policy_form, textvariable=self.policy_pattern, width=30).pack(side=LEFT, padx=(6, 8))
        ttk.Label(policy_form, text="Match").pack(side=LEFT)
        ttk.Combobox(policy_form, textvariable=self.policy_match_type, values=("name", "publisher", "path", "stable_key"), width=12, state="readonly").pack(side=LEFT, padx=(6, 8))
        ttk.Label(policy_form, text="Blacklist level").pack(side=LEFT)
        ttk.Combobox(policy_form, textvariable=self.blacklist_risk_level, values=RISK_LEVELS, width=14, state="readonly").pack(side=LEFT, padx=(6, 8))
        ttk.Button(policy_form, text="Add whitelist", command=self.add_whitelist).pack(side=LEFT, padx=(8, 0))
        ttk.Button(policy_form, text="Add blacklist", command=self.add_blacklist).pack(side=LEFT, padx=(8, 0))

        policy_panes = ttk.PanedWindow(self.settings_tab, orient="horizontal")
        policy_panes.pack(fill=BOTH, expand=True)
        whitelist_frame = ttk.Frame(policy_panes)
        blacklist_frame = ttk.Frame(policy_panes)
        policy_panes.add(whitelist_frame, weight=1)
        policy_panes.add(blacklist_frame, weight=1)

        ttk.Label(whitelist_frame, text="Whitelist", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.whitelist_tree = self._policy_tree(whitelist_frame)
        ttk.Button(whitelist_frame, text="Delete selected", command=lambda: self.delete_selected_policy("whitelist")).pack(anchor="w", pady=(8, 0))

        ttk.Label(blacklist_frame, text="Blacklist", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.blacklist_tree = self._policy_tree(blacklist_frame, include_level=True)
        ttk.Button(blacklist_frame, text="Delete selected", command=lambda: self.delete_selected_policy("blacklist")).pack(anchor="w", pady=(8, 0))

    def _policy_tree(self, parent: ttk.Frame, include_level: bool = False) -> ttk.Treeview:
        columns = ("id", "match_type", "pattern", "risk_level", "reason") if include_level else ("id", "match_type", "pattern", "reason")
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
        for column in columns:
            tree.heading(column, text=column.replace("_", " ").title())
            tree.column(column, width=120 if column != "reason" else 220, anchor="w")
        tree.pack(fill=BOTH, expand=True, pady=(6, 0))
        return tree

    def _build_detail_panel(self, parent: ttk.Frame) -> None:
        panel = ttk.Frame(parent, padding=(12, 10), style="Panel.TFrame")
        panel.pack(fill=BOTH, expand=True)
        ttk.Label(panel, text="Software detail", style="PanelTitle.TLabel").pack(anchor="w")
        self.detail_text = Text(panel, wrap=WORD, height=26, relief="flat", borderwidth=0, padx=10, pady=10)
        self._configure_detail_text()
        self.detail_text.pack(fill=BOTH, expand=True, pady=(10, 10))
        actions = ttk.Frame(parent)
        actions.pack(fill=X, pady=(10, 0))
        ttk.Button(actions, text="Open website", command=self.open_website).pack(side=LEFT)
        ttk.Button(actions, text="Mark safe", command=self.mark_safe).pack(side=LEFT, padx=(8, 0))
        ttk.Button(actions, text="Blacklist", command=self.blacklist_selected).pack(side=LEFT, padx=(8, 0))

    def _configure_detail_text(self) -> None:
        self.detail_text.configure(
            background=self.colors["panel"],
            foreground=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent"],
            font=("Segoe UI", 9),
            state=DISABLED,
        )
        self.detail_text.tag_configure("title", font=("Segoe UI", 13, "bold"), foreground=self.colors["text"])
        self.detail_text.tag_configure("label", font=("Segoe UI", 9, "bold"), foreground=self.colors["muted"])
        self.detail_text.tag_configure("value", foreground=self.colors["text"])
        self.detail_text.tag_configure("good", foreground=self.colors["good"])
        self.detail_text.tag_configure("warn", foreground=self.colors["warn"])
        self.detail_text.tag_configure("danger", foreground=self.colors["danger"])

    def start_scan(self) -> None:
        if self.is_scanning:
            return
        self._start_scan_animation()
        self.tree.delete(*self.tree.get_children())
        self._clear_detail()
        verify_signatures = self.verify_signatures.get()
        include_noise = self.include_noise.get()
        thread = threading.Thread(target=self._scan_worker, args=(verify_signatures, include_noise), daemon=True)
        thread.start()

    def _scan_worker(self, verify_signatures: bool, include_noise: bool) -> None:
        try:
            db = LocalDatabase()
            whitelist = db.list_whitelist()
            blacklist = db.list_blacklist()
            engine = ScannerEngine(
                LicenseClassifier(),
                RiskAnalyzer(whitelist=whitelist, blacklist=blacklist),
                verify_signatures=verify_signatures,
            )
            items = engine.scan(include_filesystem_discovery=True, include_noise=include_noise)
            session_id = db.save_scan(items)
            self.queue.put(("scan_complete", (items, session_id)))
        except Exception as exc:  # noqa: BLE001 - UI boundary must report unexpected scanner failures
            LOGGER.exception("Scan failed")
            self.queue.put(("error", str(exc)))

    def _drain_queue(self) -> None:
        try:
            while True:
                event, payload = self.queue.get_nowait()
                if event == "scan_complete":
                    items, session_id = payload  # type: ignore[misc]
                    self.items = list(items)
                    self._stop_scan_animation()
                    self.status_text.set(f"Scan complete. Session #{session_id}. {len(self.items)} items.")
                    self.refresh_history()
                    self.apply_filters()
                elif event == "error":
                    self._stop_scan_animation()
                    self.status_text.set("Scan failed")
                    messagebox.showerror("Scan failed", str(payload))
        except queue.Empty:
            pass
        self.root.after(150, self._drain_queue)

    def _start_scan_animation(self) -> None:
        self.is_scanning = True
        self.scan_phase = 0
        self.scan_button.configure(state="disabled")
        self.scan_progress.start(12)
        self._tick_scan_animation()

    def _tick_scan_animation(self) -> None:
        if not self.is_scanning:
            return
        frames = (
            "Scanning registry...",
            "Reading installed apps...",
            "Classifying licenses...",
            "Checking risk signals...",
            "Building dashboard...",
        )
        dots = "." * ((self.scan_phase % 3) + 1)
        self.status_text.set(f"{frames[self.scan_phase % len(frames)]}{dots}")
        self.scan_phase += 1
        self.scan_animation_job = self.root.after(650, self._tick_scan_animation)

    def _stop_scan_animation(self) -> None:
        self.is_scanning = False
        self.scan_progress.stop()
        self.scan_button.configure(state="normal")
        if self.scan_animation_job:
            try:
                self.root.after_cancel(self.scan_animation_job)
            except Exception:  # noqa: BLE001 - Tk can invalidate callbacks during shutdown
                pass
            self.scan_animation_job = None

    def apply_filters(self) -> None:
        query = self.search_text.get().strip().lower()
        license_filter = self.license_filter.get()
        risk_filter = self.risk_filter.get()
        group_filter = self.group_filter.get()
        category_filter = self.category_filter.get()
        filtered = []
        for item in self.items:
            text = " ".join(
                [
                    item.name,
                    item.publisher,
                    item.version,
                    item.install_location,
                    item.signature.status,
                    item.app_group,
                    item.app_category,
                ]
            ).lower()
            if query and query not in text:
                continue
            if license_filter != "All" and item.license_type != license_filter:
                continue
            if risk_filter != "All" and item.risk_level != risk_filter:
                continue
            if group_filter != "All" and item.app_group != group_filter:
                continue
            if category_filter != "All" and item.app_category != category_filter:
                continue
            filtered.append(item)
        self.filtered = sorted(filtered, key=lambda x: str(self._sort_value(x, self.sort_column)).lower(), reverse=self.sort_reverse)
        self._populate_tree()
        self._render_metrics()
        self._render_charts()

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        self.apply_filters()

    def _sort_value(self, item: SoftwareItem, column: str) -> object:
        if column == "signature_status":
            return item.signature.status
        if column == "license_priority":
            return license_priority(item)
        return getattr(item, column)

    def _populate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.filtered):
            priority = license_priority(item)
            tags = ["odd" if index % 2 else "even", _priority_tag(priority)]
            self.tree.insert(
                "",
                END,
                iid=str(index),
                values=(
                    item.name,
                    item.publisher,
                    item.version,
                    license_priority(item),
                    item.license_type,
                    item.license_confidence,
                    item.app_group,
                    item.app_category,
                    item.signature.status,
                    item.risk_score,
                    item.risk_level,
                    item.install_type,
                ),
                tags=tuple(tags),
            )

    def show_detail(self, _event: object | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if index >= len(self.filtered):
            return
        self.selected_item = self.filtered[index]
        self.render_detail(self.selected_item)

    def render_detail(self, item: SoftwareItem) -> None:
        self._clear_detail()
        self._detail_insert(f"{item.name}\n", "title")
        self._detail_insert(f"{item.publisher or 'Unknown publisher'}\n\n", "value")
        rows = [
            ("Publisher", item.publisher),
            ("Version", item.version),
            ("Install date", item.install_date),
            ("Install path", item.install_location),
            ("Executable", item.executable_path),
            ("Website", item.website),
            ("Install type", item.install_type),
            ("Group", item.app_group),
            ("Category", item.app_category),
            ("Priority", license_priority(item)),
            ("License relevant", "Yes" if item.is_license_relevant else "No"),
            ("App note", item.app_classification_reason),
            ("License", f"{item.license_type} ({item.license_confidence}/100)"),
            ("License note", item.license_explanation),
            ("Signature", item.signature.status),
            ("Signature subject", item.signature.subject),
            ("Signature issuer", item.signature.issuer),
            ("Signature checked", item.signature.checked_at),
            ("Risk", f"{item.risk_level} ({item.risk_score}/100)"),
        ]
        for field, value in rows:
            self._detail_insert_pair(field, value or "-")
        self._detail_insert("\nFindings\n", "label")
        if not item.risk_findings:
            self._detail_insert("No risk findings for the current rule set.\n", "good")
        for index, finding in enumerate(item.risk_findings, start=1):
            tag = "danger" if finding.level in {"High Risk", "Critical Risk"} else "warn" if finding.level == "Medium Risk" else "value"
            self._detail_insert(f"{index}. {finding.signal}\n", "label")
            self._detail_insert(f"   {finding.level}: {finding.reason}\n", tag)
            if finding.path:
                self._detail_insert(f"   Path: {finding.path}\n", "value")
            self._detail_insert(f"   Confidence: {finding.confidence}/100\n", "value")
            self._detail_insert(f"   Recommendation: {finding.recommendation}\n\n", "value")
        self.detail_text.configure(state=DISABLED)

    def _detail_insert_pair(self, label: str, value: str) -> None:
        self._detail_insert(f"{label}: ", "label")
        self._detail_insert(f"{value}\n", _value_tag(label, value))

    def _detail_insert(self, text: str, tag: str) -> None:
        self.detail_text.configure(state=NORMAL)
        self.detail_text.insert(END, text, tag)

    def refresh_history(self) -> None:
        self.sessions = self.db.list_scan_sessions()
        self.history_tree.delete(*self.history_tree.get_children())
        labels = []
        for session in self.sessions:
            label = f"#{session['id']} {session.get('completed_at') or session.get('started_at')}"
            labels.append(label)
            self.history_tree.insert(
                "",
                END,
                iid=str(session["id"]),
                values=(
                    session["id"],
                    session.get("completed_at") or "-",
                    session.get("computer_name") or "-",
                    session.get("user_name") or "-",
                    session.get("total_items") or 0,
                    session.get("total_findings") or 0,
                ),
            )
        self.old_session_combo["values"] = labels
        self.new_session_combo["values"] = labels
        if len(labels) >= 2:
            self.history_new_session.set(labels[0])
            self.history_old_session.set(labels[1])
        elif labels:
            self.history_new_session.set(labels[0])

    def load_selected_history(self) -> None:
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showinfo("No session", "Select a scan session first.")
            return
        session_id = int(selection[0])
        self.items = self.db.load_items_for_session(session_id)
        self.status_text.set(f"Loaded session #{session_id}. {len(self.items)} items.")
        self.tabs.select(self.dashboard_tab)
        self.apply_filters()

    def compare_sessions(self) -> None:
        old_id = _session_id_from_label(self.history_old_session.get())
        new_id = _session_id_from_label(self.history_new_session.get())
        if not old_id or not new_id or old_id == new_id:
            messagebox.showinfo("Compare sessions", "Select two different scan sessions.")
            return
        comparison = self.db.compare_sessions(old_id, new_id)
        self.compare_tree.delete(*self.compare_tree.get_children())
        for item in comparison.added:
            self.compare_tree.insert("", END, values=("Added", item.name, item.publisher, "-", item.version, item.install_location))
        for item in comparison.removed:
            self.compare_tree.insert("", END, values=("Removed", item.name, item.publisher, item.version, "-", item.install_location))
        for old_item, new_item, fields in comparison.changed:
            self.compare_tree.insert(
                "",
                END,
                values=("Changed", new_item.name, new_item.publisher, old_item.version, new_item.version, ", ".join(fields)),
            )
        self.compare_summary.configure(
            text=(
                f"Old #{old_id} vs New #{new_id}: "
                f"{len(comparison.added)} added, {len(comparison.removed)} removed, {len(comparison.changed)} changed."
            )
        )

    def refresh_policy_lists(self) -> None:
        self._fill_policy_tree(self.whitelist_tree, self.db.list_whitelist())
        self._fill_policy_tree(self.blacklist_tree, self.db.list_blacklist(), include_level=True)

    def _fill_policy_tree(self, tree: ttk.Treeview, rules: list[PolicyRule], include_level: bool = False) -> None:
        tree.delete(*tree.get_children())
        for rule in rules:
            values = (rule.id, rule.match_type, rule.pattern, rule.risk_level, rule.reason) if include_level else (
                rule.id,
                rule.match_type,
                rule.pattern,
                rule.reason,
            )
            tree.insert("", END, iid=str(rule.id), values=values)

    def add_whitelist(self) -> None:
        pattern = self.policy_pattern.get().strip()
        if not pattern:
            return
        self.db.add_whitelist(pattern, self.policy_match_type.get(), "Added from Settings")
        self.policy_pattern.set("")
        self.refresh_policy_lists()

    def add_blacklist(self) -> None:
        pattern = self.policy_pattern.get().strip()
        if not pattern:
            return
        self.db.add_blacklist(pattern, self.policy_match_type.get(), self.blacklist_risk_level.get(), "Added from Settings")
        self.policy_pattern.set("")
        self.refresh_policy_lists()

    def delete_selected_policy(self, table: str) -> None:
        tree = self.whitelist_tree if table == "whitelist" else self.blacklist_tree
        selection = tree.selection()
        if not selection:
            return
        self.db.delete_policy(table, int(selection[0]))
        self.refresh_policy_lists()

    def open_website(self) -> None:
        if not self.selected_item or not self.selected_item.website:
            messagebox.showinfo("No website", "No official website was found in registry metadata.")
            return
        webbrowser.open(self.selected_item.website)

    def mark_safe(self) -> None:
        if not self.selected_item:
            return
        self.db.add_whitelist(self.selected_item.name)
        self.refresh_policy_lists()
        messagebox.showinfo("Marked safe", "The selected software name was added to the local whitelist.")

    def blacklist_selected(self) -> None:
        if not self.selected_item:
            return
        self.db.add_blacklist(self.selected_item.name, "name", "High Risk", "Blacklisted from software detail")
        self.refresh_policy_lists()
        messagebox.showinfo("Blacklisted", "The selected software name was added to the local blacklist.")

    def export_report(self, extension: str) -> None:
        if not self.items:
            messagebox.showinfo("No data", "Run or load a scan before exporting a report.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{extension}",
            filetypes=[(extension.upper(), f"*.{extension}")],
            initialfile=f"software_scan.{extension}",
        )
        if not path:
            return
        target = Path(path)
        exporters = {
            "csv": export_csv,
            "json": export_json,
            "pdf": export_pdf,
            "xlsx": export_xlsx,
        }
        exporters[extension](self.items, target)
        self.status_text.set(f"Exported {target}")
        LOGGER.info("Exported report %s", target)

    def save_settings(self) -> None:
        self.db.set_setting("theme", self.theme.get())
        self.db.set_setting("verify_signatures", "1" if self.verify_signatures.get() else "0")
        self.db.set_setting("include_noise", "1" if self.include_noise.get() else "0")
        self.db.set_setting("default_group_filter", self.group_filter.get())
        self._apply_theme()
        self.apply_filters()

    def _render_metrics(self) -> None:
        for child in self.metrics_frame.winfo_children():
            child.destroy()
        all_summary = summarize(self.items)
        visible_summary = summarize(self.filtered)
        metrics = [
            ("Installed", all_summary.get("total", 0)),
            ("Visible", visible_summary.get("total", 0)),
            ("Free", all_summary.get("Freeware", 0)),
            ("Open-source", all_summary.get("Open-source software", 0)),
            ("Freemium", all_summary.get("Freemium", 0)),
            ("Review", all_summary.get("License relevant", 0) + all_summary.get("Work apps", 0)),
            ("Unknown", all_summary.get("Unknown", 0)),
            ("Findings", all_summary.get("risk_findings", 0)),
        ]
        palette = [self.colors["accent"], self.colors["muted"], self.colors["good"], "#0891b2", self.colors["warn"], "#7c3aed", self.colors["danger"], "#64748b"]
        for index, (label, value) in enumerate(metrics):
            frame = ttk.Frame(self.metrics_frame, padding=(10, 8), style="Panel.TFrame")
            frame.pack(side=LEFT, fill=X, expand=True, padx=(0, 8))
            strip = Canvas(frame, height=3, highlightthickness=0, background=self.colors["panel"])
            strip.pack(fill=X, pady=(0, 6))
            strip.create_rectangle(0, 0, 800, 3, fill=palette[index % len(palette)], outline="")
            ttk.Label(frame, text=str(value), style="Metric.TLabel").pack(anchor="w")
            ttk.Label(frame, text=label, style="MetricName.TLabel").pack(anchor="w")

    def _render_charts(self) -> None:
        license_counts = {license_type: 0 for license_type in LICENSE_TYPES}
        risk_counts = {risk_level: 0 for risk_level in RISK_LEVELS}
        for item in self.filtered:
            license_counts[item.license_type] = license_counts.get(item.license_type, 0) + 1
            risk_counts[item.risk_level] = risk_counts.get(item.risk_level, 0) + 1
        self._draw_bar_chart(self.license_chart, license_counts, "License classification")
        self._draw_bar_chart(self.risk_chart, risk_counts, "Risk levels")

    def _draw_bar_chart(self, canvas: Canvas, values: dict[str, int], title: str) -> None:
        canvas.configure(background=self.colors["panel"], highlightbackground=self.colors["border"])
        canvas.delete("all")
        width = max(canvas.winfo_width(), 420)
        canvas.create_text(14, 12, anchor="nw", text=title, font=("Segoe UI", 10, "bold"), fill=self.colors["text"])
        max_value = max(values.values()) if values else 1
        x = 14
        y = 44
        palette = [self.colors["accent"], self.colors["good"], self.colors["warn"], "#7c3aed", self.colors["danger"], "#64748b", "#0891b2"]
        for index, (label, value) in enumerate(values.items()):
            bar_width = int((width - 210) * (value / max_value)) if max_value else 0
            canvas.create_rectangle(x, y, width - 150, y + 12, fill=self.colors["panel_soft"], outline="")
            if value:
                canvas.create_rectangle(x, y, x + max(bar_width, 3), y + 12, fill=palette[index % len(palette)], outline="")
            canvas.create_text(width - 140, y - 2, anchor="nw", text=f"{label}: {value}", font=("Segoe UI", 8), fill=self.colors["muted"])
            y += 19

    def _clear_detail(self) -> None:
        self.detail_text.configure(state=NORMAL)
        self.detail_text.delete("1.0", END)
        self.detail_text.configure(state=DISABLED)

    def _configure_tree_tags(self) -> None:
        self.tree.tag_configure("even", background=self.colors["tree"])
        self.tree.tag_configure("odd", background=self.colors["tree_alt"])
        self.tree.tag_configure("priority_review_now", foreground=self.colors["danger"])
        self.tree.tag_configure("priority_review", foreground=self.colors["warn"])
        self.tree.tag_configure("priority_no_action", foreground=self.colors["good"])
        self.tree.tag_configure("priority_default", foreground=self.colors["text"])


def _session_id_from_label(label: str) -> int:
    if not label.startswith("#"):
        return 0
    try:
        return int(label.split(" ", 1)[0].lstrip("#"))
    except ValueError:
        return 0


def license_priority(item: SoftwareItem) -> str:
    if item.risk_score >= 60 or item.risk_level in {"High Risk", "Critical Risk"}:
        return "Review now"
    if item.app_group in {"License relevant", "Work apps"} or item.license_type in {
        "Paid software",
        "Trial software",
        "Subscription-based",
    }:
        return "Review"
    if item.license_type in {"Freeware", "Open-source software"}:
        return "No action"
    if item.license_type == "Freemium":
        return "Track terms"
    if item.app_group in {"Developer/Runtime", "Driver/Hardware", "System/Windows"}:
        return "Inventory"
    return "Identify"


def _priority_tag(priority: str) -> str:
    if priority == "Review now":
        return "priority_review_now"
    if priority == "Review":
        return "priority_review"
    if priority == "No action":
        return "priority_no_action"
    return "priority_default"


def _value_tag(label: str, value: str) -> str:
    if label == "Risk" and ("High" in value or "Critical" in value):
        return "danger"
    if label == "Risk" and "Medium" in value:
        return "warn"
    if label == "Priority" and value == "No action":
        return "good"
    if label == "Priority" and value in {"Review", "Review now"}:
        return "warn" if value == "Review" else "danger"
    if label == "Signature" and value == "Valid":
        return "good"
    return "value"


def main() -> None:
    TSpaceScanApp().run()
