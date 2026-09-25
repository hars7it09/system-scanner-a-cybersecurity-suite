    # main.py - System Security Scanner (Desktop) with USB info
import customtkinter as ctk  # type: ignore
from tkinter import messagebox, filedialog
import threading, time, os, csv
from modules import (  # type: ignore
    port_scanner,
    password_policy,
    wifi_info,
    usb_info,
    report_generator,
    log_storage,
    firewall_info,
    firewall_scanner,
    malware_scanner,
    threat_alert,
    network_discovery,
    honeypot,
    scan_scheduler,
    threat_timeline,
    auth,
    tamper,
    protected_folders,
    settings_manager,
    decoy_mode,
)
from modules.report_generator import format_usb_events  # type: ignore

# ── Apply persisted settings before any window is created ─────────────────
_startup_cfg = settings_manager.load()
ctk.set_appearance_mode(_startup_cfg.get("ui", {}).get("appearance_mode", "Dark"))
ctk.set_default_color_theme(_startup_cfg.get("ui", {}).get("color_theme", "blue"))

# ── Design tokens ─────────────────────────────────────────────────────────
FONT_TITLE   = ("Segoe UI", 22, "bold")
FONT_HEADING = ("Segoe UI", 14, "bold")
FONT_SUBHEAD = ("Segoe UI", 12)
FONT_BODY    = ("Segoe UI", 11)
FONT_MONO    = ("Consolas", 14)
FONT_SMALL   = ("Segoe UI", 10)
FONT_NAV     = ("Segoe UI", 12, "bold")

COLOR_SIDEBAR   = "#0f172a"   # very dark navy
COLOR_HEADER    = "#1e293b"   # dark slate
COLOR_CARD      = "#1e293b"   # card bg
COLOR_ACCENT    = "#3b82f6"   # blue
COLOR_ACCENT2   = "#0ea5e9"   # sky
COLOR_SUCCESS   = "#22c55e"   # green
COLOR_WARNING   = "#f59e0b"   # amber
COLOR_DANGER    = "#ef4444"   # red
COLOR_TEXT_DIM  = "#94a3b8"   # muted
COLOR_NAV_HOVER = "#1e3a5f"

# Simple tooltip class
class ToolTip:
    _delay_ms = 500
    _offset_x = 10
    _offset_y = 5
    _instances = set() 

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip: ctk.CTkToplevel | None = None
        self._after_id = None
        ToolTip._instances.add(self)
        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)
        widget.bind("<Destroy>", self._on_widget_destroy)

    def _on_enter(self, event=None):
        self._cancel_schedule()
        self._after_id = self.widget.after(self._delay_ms, self._show_tooltip)

    def _on_leave(self, event=None):
        self._cancel_schedule()
        self._hide_tooltip()

    def _on_widget_destroy(self, event=None):
        self._cancel_schedule()
        self._hide_tooltip()

    def _cancel_schedule(self):
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show_tooltip(self):
        self._after_id = None
        if self.tooltip is not None:
            return
        try:
            root = self.widget.winfo_toplevel()
            # Position below widget (works for any widget; no bbox)
            x = self.widget.winfo_rootx() + self._offset_x
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + self._offset_y
            self.tooltip = ctk.CTkToplevel(root)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            label = ctk.CTkLabel(self.tooltip, text=self.text)
            label.pack(padx=6, pady=4)
            self.tooltip.bind("<Leave>", self._on_leave)
            self.tooltip.update_idletasks()
        except Exception:
            self._hide_tooltip()

    def _hide_tooltip(self, event=None):
        if self.tooltip is not None:
            try:
                self.tooltip.unbind("<Leave>")
                self.tooltip.destroy()
            except Exception:
                pass
            self.tooltip = None

    @classmethod
    def hide_all(cls):
        for tt in list(cls._instances):
            try:
                tt._hide_tooltip()
            except Exception:
                pass

class SystemScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced System Security Scanner")
        self.root.geometry("1260x780")
        self.root.minsize(1000, 680)
        self.root.configure(fg_color=COLOR_SIDEBAR)

        # ── State variables ────────────────────────────────────────────────
        self.scan_results: dict = {}
        self.usb_log        = []
        self.scanning       = False
        self.wifi_log       = []
        self.wifi_scanning  = False
        self.last_scan_time: str | None = None
        self.device_count   = 0
        self.status_var     = ctk.StringVar(value="System Ready")
        self._active_nav: str | None = None   # currently highlighted nav button
        log_storage.init_log_file()

        # ── Authentication & Self-Protection ──────────────────────────────
        self.auth_manager = auth.AuthManager()
        self.tamper_monitor = tamper.TamperMonitor(
            on_alert=self._on_tamper_alert,
            check_interval=120,
        )

        # ── Decoy Mode (deception-based security) ─────────────────────────
        self._decoy_active = False                          # UI-level flag
        self._decoy_failed_streak = 0                       # consecutive fails
        self.decoy_manager = decoy_mode.DecoyManager(
            camera_enabled=True,
        )
        self._decoy_container: ctk.CTkFrame | None = None   # type: ignore[assignment]

        # ── Widget attribute declarations (for static type checkers) ──────
        # Header & Navigation
        self._clock_lbl: ctk.CTkLabel = None                # type: ignore[assignment]
        self._status_pill: ctk.CTkLabel = None              # type: ignore[assignment]
        
        # Dashboard Components
        self.security_score_lbl: ctk.CTkLabel = None        # type: ignore[assignment]
        self.security_score_desc: ctk.CTkLabel = None       # type: ignore[assignment]
        self.full_scan_btn: ctk.CTkButton = None            # type: ignore[assignment]
        
        
        # Body / sidebar
        self._sidebar: ctk.CTkFrame = None                  # type: ignore[assignment]
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._content: ctk.CTkFrame = None                  # type: ignore[assignment]
        self._panels: dict[str, ctk.CTkFrame] = {}

        # Tab aliases (assigned in _build_body)
        self.port_tab: ctk.CTkFrame = None                  # type: ignore[assignment]
        self.password_tab: ctk.CTkFrame = None              # type: ignore[assignment]
        self.wifi_tab: ctk.CTkFrame = None                  # type: ignore[assignment]
        self.usb_tab: ctk.CTkFrame = None                   # type: ignore[assignment]
        self.firewall_tab: ctk.CTkFrame = None              # type: ignore[assignment]
        self.malware_tab: ctk.CTkFrame = None               # type: ignore[assignment]
        self.logs_tab: ctk.CTkFrame = None                  # type: ignore[assignment]
        self.report_tab: ctk.CTkFrame = None                # type: ignore[assignment]
        self.settings_tab: ctk.CTkFrame = None              # type: ignore[assignment]

        # Status bar
        self.progress: ctk.CTkProgressBar = None            # type: ignore[assignment]

        # Port scanner tab widgets
        self.host_entry: ctk.CTkEntry = None                # type: ignore[assignment]
        self.port_entry: ctk.CTkEntry = None                # type: ignore[assignment]
        self.port_timeout_entry: ctk.CTkEntry = None        # type: ignore[assignment]
        self.port_workers_entry: ctk.CTkEntry = None        # type: ignore[assignment]
        self.scan_button: ctk.CTkButton = None              # type: ignore[assignment]
        self.result_box: ctk.CTkTextbox = None              # type: ignore[assignment]

        # Password policy tab widgets
        self.policy_box: ctk.CTkTextbox = None              # type: ignore[assignment]
        self.fetch_button: ctk.CTkButton = None             # type: ignore[assignment]

        # Wi-Fi tab widgets
        self.wifi_box: ctk.CTkTextbox = None                # type: ignore[assignment]
        self.wifi_button: ctk.CTkButton = None              # type: ignore[assignment]
        self.start_wifi_scan_button: ctk.CTkButton = None   # type: ignore[assignment]
        self.stop_wifi_scan_button: ctk.CTkButton = None    # type: ignore[assignment]

        # USB tab widgets
        self.device_count_label: ctk.CTkLabel = None        # type: ignore[assignment]
        self.last_scan_label: ctk.CTkLabel = None           # type: ignore[assignment]
        self.usb_box: ctk.CTkTextbox = None                 # type: ignore[assignment]
        self.usb_button: ctk.CTkButton = None               # type: ignore[assignment]
        self.detailed_var: ctk.BooleanVar = None             # type: ignore[assignment]
        self.detailed_check: ctk.CTkCheckBox = None         # type: ignore[assignment]
        self.scan_interval_entry: ctk.CTkEntry = None       # type: ignore[assignment]
        self.start_scan_button: ctk.CTkButton = None        # type: ignore[assignment]
        self.stop_scan_button: ctk.CTkButton = None         # type: ignore[assignment]

        # Firewall tab widgets
        self.fw_probe_entry: ctk.CTkEntry = None            # type: ignore[assignment]
        self.fw_maxrules_entry: ctk.CTkEntry = None         # type: ignore[assignment]
        self.fw_status_label: ctk.CTkLabel = None           # type: ignore[assignment]
        self.firewall_box: ctk.CTkTextbox = None            # type: ignore[assignment]
        self.firewall_button: ctk.CTkButton = None          # type: ignore[assignment]
        self.fw_open_log_btn: ctk.CTkButton = None          # type: ignore[assignment]

        # Malware tab widgets
        self.malware_path_entry: ctk.CTkEntry = None        # type: ignore[assignment]
        self.malware_path_button: ctk.CTkButton = None      # type: ignore[assignment]
        self.malware_box: ctk.CTkTextbox = None             # type: ignore[assignment]
        self.malware_button: ctk.CTkButton = None           # type: ignore[assignment]
        self.malware_status_label: ctk.CTkLabel = None      # type: ignore[assignment]
        self.malware_wl_button: ctk.CTkButton = None        # type: ignore[assignment]
        self.malware_log_button: ctk.CTkButton = None       # type: ignore[assignment]

        # Logs tab widgets
        self.log_filter_var: ctk.StringVar = None           # type: ignore[assignment]
        self.risk_filter_var: ctk.StringVar = None          # type: ignore[assignment]
        self.logs_count_label: ctk.CTkLabel = None          # type: ignore[assignment]
        self.logs_box: ctk.CTkTextbox = None                # type: ignore[assignment]

        # Report tab widgets
        self.report_button: ctk.CTkButton = None            # type: ignore[assignment]
        self.report_status: ctk.CTkLabel = None             # type: ignore[assignment]

        # Settings tab widgets
        self.default_timeout_entry: ctk.CTkEntry = None     # type: ignore[assignment]
        self.theme_var: ctk.StringVar = None                # type: ignore[assignment]

        # Threat alert widgets
        self.alerts_tab: ctk.CTkFrame = None                # type: ignore[assignment]
        self._alert_bell: ctk.CTkButton = None              # type: ignore[assignment]
        self._alert_badge: ctk.CTkLabel = None              # type: ignore[assignment]
        self._alert_total_lbl: ctk.CTkLabel = None          # type: ignore[assignment]
        self._alert_recent_lbl: ctk.CTkLabel = None         # type: ignore[assignment]

        # Network discovery tab widgets
        self.network_tab: ctk.CTkFrame = None               # type: ignore[assignment]
        self.net_subnet_entry: ctk.CTkEntry = None          # type: ignore[assignment]
        self.net_timeout_entry: ctk.CTkEntry = None         # type: ignore[assignment]
        self.net_workers_entry: ctk.CTkEntry = None         # type: ignore[assignment]
        self.net_scan_button: ctk.CTkButton = None          # type: ignore[assignment]
        self.net_result_box: ctk.CTkTextbox = None          # type: ignore[assignment]
        self.net_device_count_lbl: ctk.CTkLabel = None      # type: ignore[assignment]
        self.net_known_lbl: ctk.CTkLabel = None             # type: ignore[assignment]
        self.net_unknown_lbl: ctk.CTkLabel = None           # type: ignore[assignment]
        self.net_method_lbl: ctk.CTkLabel = None            # type: ignore[assignment]

        # Startup analyzer tab widgets
        self.startup_tab: ctk.CTkFrame = None               # type: ignore[assignment]
        self.startup_result_box: ctk.CTkTextbox = None      # type: ignore[assignment]
        self.startup_scan_btn: ctk.CTkButton = None         # type: ignore[assignment]
        self.startup_total_lbl: ctk.CTkLabel = None         # type: ignore[assignment]
        self.startup_high_lbl: ctk.CTkLabel = None          # type: ignore[assignment]
        self.startup_med_lbl: ctk.CTkLabel = None           # type: ignore[assignment]

        # Honeypot tab widgets
        self.honeypot_tab: ctk.CTkFrame = None              # type: ignore[assignment]
        self.honeypot_box: ctk.CTkTextbox = None            # type: ignore[assignment]
        self.honeypot_deploy_btn: ctk.CTkButton = None      # type: ignore[assignment]
        self.honeypot_check_btn: ctk.CTkButton = None       # type: ignore[assignment]
        self.honeypot_remove_btn: ctk.CTkButton = None      # type: ignore[assignment]
        self.honeypot_status_lbl: ctk.CTkLabel = None       # type: ignore[assignment]
        self.honeypot_monitor: honeypot.HoneypotMonitor = None  # type: ignore[assignment]
        self._hp_camera_var: ctk.BooleanVar = None          # type: ignore[assignment]
        self._hp_camera_switch: ctk.CTkSwitch = None        # type: ignore[assignment]
        self._hp_camera_status: ctk.CTkLabel = None         # type: ignore[assignment]
        self._hp_watchdog_lbl: ctk.CTkLabel = None          # type: ignore[assignment]

        # Scheduler tab widgets
        self.scheduler_tab: ctk.CTkFrame = None             # type: ignore[assignment]
        self.scheduler_box: ctk.CTkTextbox = None           # type: ignore[assignment]
        self.scheduler_toggle_btn: ctk.CTkButton = None     # type: ignore[assignment]
        self.scheduler_status_lbl: ctk.CTkLabel = None      # type: ignore[assignment]
        self.scheduler_interval_var: ctk.StringVar = None    # type: ignore[assignment]
        self.scheduler_engine: scan_scheduler.ScanScheduler = None  # type: ignore[assignment]

        # Threat Timeline tab widgets
        self.timeline_tab: ctk.CTkFrame = None              # type: ignore[assignment]
        self.timeline_box: ctk.CTkTextbox = None            # type: ignore[assignment]
        self.timeline_filter_var: ctk.StringVar = None      # type: ignore[assignment]
        self.timeline_stats_lbl: ctk.CTkLabel = None        # type: ignore[assignment]
        self._tl_stat_boxes: dict[str, ctk.CTkLabel] = {}
        self._scheduler_module_vars: dict[str, ctk.BooleanVar] = {}

        # Protected Folders tab widgets
        self.protected_tab: ctk.CTkFrame = None              # type: ignore[assignment]
        self.pf_box: ctk.CTkTextbox = None                   # type: ignore[assignment]
        self.pf_list_frame: ctk.CTkScrollableFrame = None    # type: ignore[assignment]
        self.pf_status_lbl: ctk.CTkLabel = None              # type: ignore[assignment]
        self.pf_camera_var: ctk.BooleanVar = None            # type: ignore[assignment]
        self.pf_camera_switch: ctk.CTkSwitch = None          # type: ignore[assignment]
        self.pf_camera_status: ctk.CTkLabel = None           # type: ignore[assignment]
        self.pf_watchdog_lbl: ctk.CTkLabel = None            # type: ignore[assignment]
        self.pf_monitor: protected_folders.ProtectedFolderMonitor = None  # type: ignore[assignment]

        # ── Smart Threat Alert Manager ────────────────────────────────────
        self.alert_manager = threat_alert.ThreatAlertManager(
            root, log_fn=log_storage.log_event,
        )
        self.alert_manager.on_alert_callback = self._update_alert_badge

        # ── Build the three-zone layout ────────────────────────────────────
        self._build_header()
        self._build_body()      # sidebar + content area
        self._build_statusbar()

        # ── Initialize background services BEFORE tab setup ───────────────
        # (setup_scheduler_tab needs self.scheduler_engine.config)
        self.honeypot_monitor = honeypot.HoneypotMonitor(
            interval_seconds=60,
            on_alert=self._on_honeypot_alert,
        )

        self.pf_monitor = protected_folders.ProtectedFolderMonitor(
            on_alert=self._on_protected_folder_alert,
            camera_enabled=protected_folders.get_camera_enabled(),
        )

        self.scheduler_engine = scan_scheduler.ScanScheduler()
        self.scheduler_engine.set_scan_callback(self._scheduled_scan_callback)
        self.scheduler_engine.set_on_complete(self._on_scheduled_scan_complete)

        # ── Populate every content panel ──────────────────────────────────
        self.setup_port_tab()
        self.setup_password_tab()
        self.setup_wifi_tab()
        self.setup_usb_tab()
        self.setup_firewall_tab()
        self.setup_malware_tab()
        self.setup_logs_tab()
        self.setup_report_tab()
        self.setup_settings_tab()
        self.setup_alerts_tab()
        self.setup_network_tab()
        self.setup_startup_tab()
        self.setup_protected_tab()
        self.setup_honeypot_tab()
        self.setup_scheduler_tab()
        self.setup_timeline_tab()
        self.setup_process_tab()

        # ── Start background services ─────────────────────────────────────
        self.honeypot_monitor.start()
        self.pf_monitor.start()
        if self.scheduler_engine.config.get("enabled", False):
            self.scheduler_engine.start()
        self.tamper_monitor.start()

        # Show the dashboard (home) view by default
        self._show_panel("dashboard")

        # ── Show login dialog after window renders ────────────────────────
        self.root.after(300, self._show_login_dialog)

        # ── Hidden admin bypass: Ctrl+Shift+F12 exits decoy mode ──────────
        self.root.bind("<Control-Shift-F12>", self._admin_escape_decoy)

    # ══════════════════════════════════════════════════════════════════════
    #  LAYOUT BUILDERS
    # ══════════════════════════════════════════════════════════════════════

    def _build_header(self):
        """Top header bar: logo, title, live clock."""
        hdr = ctk.CTkFrame(self.root, height=64, fg_color=COLOR_HEADER, corner_radius=0)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # Left – branding
        brand = ctk.CTkFrame(hdr, fg_color="transparent")
        brand.pack(side="left", padx=20, pady=8)
        ctk.CTkLabel(brand, text="🛡", font=("Segoe UI", 28)).pack(side="left", padx=(0, 8))
        txt_col = ctk.CTkFrame(brand, fg_color="transparent")
        txt_col.pack(side="left")
        ctk.CTkLabel(txt_col, text="Advanced System Security Scanner",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(txt_col, text="Real-time monitoring & threat analysis",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Right – alert bell + live clock + status pill
        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right", padx=20)

        # Alert bell button with badge
        bell_frame = ctk.CTkFrame(right, fg_color="transparent")
        bell_frame.pack(anchor="e", pady=(0, 2))
        self._alert_bell = ctk.CTkButton(
            bell_frame, text="🔔", width=36, height=32,
            font=("Segoe UI", 18), fg_color="transparent",
            hover_color=COLOR_NAV_HOVER, text_color="white",
            corner_radius=8,
            command=lambda: self._show_panel("alerts"),
        )
        self._alert_bell.pack(side="left")
        self._alert_badge = ctk.CTkLabel(
            bell_frame, text="", width=22, height=18,
            font=("Segoe UI", 9, "bold"),
            fg_color=COLOR_DANGER, text_color="white",
            corner_radius=9,
        )
        # Badge hidden initially (no alerts yet)
        self._alert_badge.pack(side="left", padx=(0, 6))
        self._alert_badge.pack_forget()

        self._clock_lbl = ctk.CTkLabel(right, text="", font=FONT_BODY,
                                       text_color=COLOR_TEXT_DIM)
        self._clock_lbl.pack(anchor="e")
        self._status_pill = ctk.CTkLabel(
            right, text="● LIVE", font=("Segoe UI", 11, "bold"),
            text_color=COLOR_SUCCESS)
        self._status_pill.pack(anchor="e")
        self._tick_clock()

    def _tick_clock(self):
        """Update the header clock every second."""
        self._clock_lbl.configure(
            text=time.strftime("%A, %d %b %Y   %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    def _build_body(self):
        """Horizontal split: sidebar (fixed 210 px) + scrollable content pane."""
        body = ctk.CTkFrame(self.root, fg_color=COLOR_SIDEBAR, corner_radius=0)
        body.pack(fill="both", expand=True)

        # ── Sidebar ───────────────────────────────────────────────────────
        self._sidebar = ctk.CTkFrame(body, width=210, fg_color=COLOR_SIDEBAR,
                                     corner_radius=0)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        ctk.CTkLabel(self._sidebar, text="NAVIGATION",
                     font=("Segoe UI", 9, "bold"),
                     text_color=COLOR_TEXT_DIM).pack(pady=(14, 4), padx=16, anchor="w")

        # Scrollable container for nav buttons (handles overflow)
        nav_scroll = ctk.CTkScrollableFrame(
            self._sidebar, fg_color=COLOR_SIDEBAR,
            scrollbar_button_color="#334155",
            scrollbar_button_hover_color=COLOR_ACCENT,
        )
        nav_scroll.pack(fill="both", expand=True, padx=0, pady=0)

        # Nav items: (label, icon, panel_key)
        nav_items = [
            ("Dashboard",         "🏠",  "dashboard"),
            ("Port Scanner",      "🔍",  "port"),
            ("Network Discovery", "🌐",  "network"),
            ("Password Policy",   "🔐",  "password"),
            ("Wi-Fi Info",        "📶",  "wifi"),
            ("USB Devices",       "💾",  "usb"),
            ("Firewall Scan",     "🛡️",  "firewall"),
            ("Malware Detection", "🧬",  "malware"),
            ("Startup Analyzer",  "🚀",  "startup"),
            ("Process Monitor",   "🔬",  "processes"),
            ("Protected Folders", "🔒",  "protected"),
            ("Honeypot Monitor",  "🎯",  "honeypot"),
            ("Scan Scheduler",    "⏰",  "scheduler"),
            ("Threat Timeline",   "📈",  "timeline"),
            ("Security Logs",     "📋",  "logs"),
            ("Threat Alerts",     "🔔",  "alerts"),
            ("Generate Report",   "📄",  "report"),
            ("Settings",          "⚙️",  "settings"),
        ]
        self._nav_buttons = {}
        for label, icon, key in nav_items:
            btn = ctk.CTkButton(
                nav_scroll,
                text=f"  {icon}  {label}",
                anchor="w",
                font=FONT_NAV,
                height=36,
                corner_radius=8,
                fg_color="transparent",
                hover_color=COLOR_NAV_HOVER,
                text_color="white",
                command=lambda k=key: self._show_panel(k),
            )
            btn.pack(fill="x", padx=8, pady=1)
            self._nav_buttons[key] = btn

        # Version footer (below the scrollable area)
        ctk.CTkFrame(self._sidebar, height=1, fg_color="#334155").pack(
            fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(self._sidebar, text="v1.0.0  |  Windows",
                     font=("Segoe UI", 9),
                     text_color=COLOR_TEXT_DIM).pack(padx=16, pady=(0, 8), anchor="w")

        # ── Content pane ──────────────────────────────────────────────────
        self._content = ctk.CTkFrame(body, fg_color="#0f1a2e", corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        # Stacked frames — one per nav panel
        self._panels: dict[str, ctk.CTkFrame] = {}
        for key in ["dashboard", "port", "network", "password", "wifi", "usb",
                    "firewall", "malware", "startup", "processes", "protected",
                    "honeypot", "scheduler",
                    "timeline", "logs", "alerts", "report", "settings"]:
            panel = ctk.CTkFrame(self._content, fg_color="#0f1a2e", corner_radius=0)
            self._panels[key] = panel

        # Map the old tab attributes to new panel frames
        # (setup_*_tab methods do  frame = self.port_tab  etc.)
        self.port_tab      = self._panels["port"]
        self.password_tab  = self._panels["password"]
        self.wifi_tab      = self._panels["wifi"]
        self.usb_tab       = self._panels["usb"]
        self.firewall_tab  = self._panels["firewall"]
        self.malware_tab   = self._panels["malware"]
        self.logs_tab      = self._panels["logs"]
        self.report_tab    = self._panels["report"]
        self.settings_tab  = self._panels["settings"]
        self.alerts_tab    = self._panels["alerts"]
        self.network_tab   = self._panels["network"]
        self.startup_tab   = self._panels["startup"]
        self.protected_tab = self._panels["protected"]
        self.honeypot_tab  = self._panels["honeypot"]
        self.scheduler_tab = self._panels["scheduler"]
        self.timeline_tab  = self._panels["timeline"]
        self.process_tab   = self._panels["processes"]

        # Build the dashboard panel separately
        self._build_dashboard_panel(self._panels["dashboard"])

    def _build_statusbar(self):
        """Bottom status bar with status text + progress bar."""
        bar = ctk.CTkFrame(self.root, height=36, fg_color=COLOR_HEADER, corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        ctk.CTkLabel(bar, textvariable=self.status_var,
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(
            side="left", padx=16, pady=8)
        self.progress = ctk.CTkProgressBar(bar, orientation="horizontal",
                                           width=220, height=8)
        self.progress.pack(side="right", padx=16, pady=12)
        self.progress.set(0)

    # ── Panel switcher ─────────────────────────────────────────────────────
    def _show_panel(self, key: str):
        """Hide all panels, show the requested one, highlight the nav button."""
        for panel in self._panels.values():
            panel.place_forget()
        self._panels[key].place(x=0, y=0, relwidth=1, relheight=1)

        # Highlight active nav button
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(fg_color=COLOR_ACCENT)
            else:
                btn.configure(fg_color="transparent")
        self._active_nav = key

    # ── Dashboard (home) panel ─────────────────────────────────────────────
    def _build_dashboard_panel(self, frame: ctk.CTkFrame):
        """A summary home screen with scan-category cards."""
        # Top section: Title, Full System Scan, Security Score
        top_frame = ctk.CTkFrame(frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=28, pady=(28, 4))
        
        # Left: Title and subtitle
        title_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        title_frame.pack(side="left")
        ctk.CTkLabel(title_frame, text="Security Dashboard",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(title_frame,
                     text="Run individual scans or an automated full system scan.",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(anchor="w")
                     
        # Right: Security Score & Full Scan
        score_frame = ctk.CTkFrame(top_frame, fg_color=COLOR_CARD, corner_radius=8, border_width=1, border_color="#334155")
        score_frame.pack(side="right", padx=(20, 0))
        
        self.security_score_lbl = ctk.CTkLabel(score_frame, text="--", font=("Segoe UI", 32, "bold"), text_color=COLOR_TEXT_DIM)
        self.security_score_lbl.pack(side="left", padx=(16, 8), pady=10)
        
        desc_frame = ctk.CTkFrame(score_frame, fg_color="transparent")
        desc_frame.pack(side="left", padx=(0, 16), pady=10)
        ctk.CTkLabel(desc_frame, text="System Security Score", font=FONT_HEADING, text_color="white").pack(anchor="w")
        self.security_score_desc = ctk.CTkLabel(desc_frame, text="Waiting for scans...", font=FONT_SMALL, text_color=COLOR_TEXT_DIM)
        self.security_score_desc.pack(anchor="w")
        
        self.full_scan_btn = ctk.CTkButton(top_frame, text="🛡️ Run Full System Scan", font=FONT_HEADING,
                                         fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER, height=40,
                                         command=self.run_full_system_scan)
        self.full_scan_btn.pack(side="right", padx=(20, 0))

        # Cards grid
        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=24, pady=20)

        cards = [
            ("🔍", "Port Scanner",       "Detect open & risky TCP ports",          "port",     COLOR_ACCENT),
            ("🔐", "Password Policy",    "Audit Windows password requirements",   "password", "#7c3aed"),
            ("📶", "Wi-Fi Info",         "Inspect wireless security settings",     "wifi",     "#0891b2"),
            ("💾", "USB Devices",        "Monitor USB connection events",          "usb",      "#d97706"),
            ("🛡️", "Firewall Scan",      "Analyse rules & open-port exposure",     "firewall", "#dc2626"),
            ("🧬", "Malware Detection",  "Heuristic process & file inspection",    "malware",  "#16a34a"),
            ("🔬", "Process Monitor",   "Detect hidden & suspicious processes",   "processes","#a855f7"),
            ("🔒", "Protected Folders",  "Monitor confidential files & folders",   "protected","#e11d48"),
            ("📋", "Security Logs",      "View & filter all recorded events",      "logs",     "#475569"),
            ("📄", "Generate Report",    "Export full scan results to DOCX",      "report",   "#0f766e"),
        ]

        cols = 4
        for i, (icon, title, desc, panel_key, accent) in enumerate(cards):
            row, col = divmod(i, cols)
            card = ctk.CTkFrame(grid, fg_color=COLOR_CARD,
                                corner_radius=14, border_width=1,
                                border_color="#334155")
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            grid.grid_rowconfigure(row, weight=1)
            grid.grid_columnconfigure(col, weight=1)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=18, pady=16)

            ctk.CTkLabel(inner, text=icon, font=("Segoe UI", 28)).pack(anchor="w")
            ctk.CTkLabel(inner, text=title, font=FONT_HEADING,
                         text_color="white").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(inner, text=desc, font=FONT_SMALL,
                         text_color=COLOR_TEXT_DIM, wraplength=200,
                         justify="left").pack(anchor="w")
            ctk.CTkButton(
                inner, text="Open →",
                font=FONT_SMALL, height=32, corner_radius=8,
                fg_color=accent, hover_color=COLOR_NAV_HOVER,
                command=lambda k=panel_key: self._show_panel(k),
            ).pack(anchor="w", pady=(12, 0))

    def update_security_score(self):
        """Calculate and update the system security score (0-100)."""
        if not hasattr(self, 'security_score_lbl') or not self.security_score_lbl.winfo_exists():
            return
            
        score = 100
        desc: list[str] = []
        
        # Firewall impact
        fw = self.scan_results.get("firewall_scanner", {})
        if fw and fw.get("status") == "ok":
            if not fw.get("profile_active", True):
                score -= 20
                desc.append("Firewall disabled")
            open_p = fw.get("open_ports", 0)
            if open_p > 10:
                score -= 10
                desc.append("Many external ports")
                
        # Malware impact
        mw = self.scan_results.get("malware", {})
        if mw and mw.get("status") == "ok":
            m_sum = mw.get("summary", {})
            hi = m_sum.get("suspicious_files", 0) + m_sum.get("suspicious_processes", 0) + m_sum.get("suspicious_startup_entries", 0)
            if hi > 0:
                score -= min(40, hi * 10)
                desc.append(f"{hi} malicious items")

        # Network intruders
        nw = self.scan_results.get("network_discovery", {})
        if nw and nw.get("status") == "ok":
            intruders = len(nw.get("summary", {}).get("new_intruders", []))
            if intruders > 0:
                score -= min(20, intruders * 10)
                desc.append(f"{intruders} intruders")
                
        # Port scan
        pt = self.scan_results.get("port_scan", {})
        if pt and pt.get("status") == "ok":
            open_p = sum(1 for v in pt.get("results", {}).values() if v)
            if open_p > 5:
                score -= min(10, open_p * 2)
                desc.append(f"{open_p} open ports")
                
        score = max(0, min(100, score))
        
        color = COLOR_SUCCESS
        if score < 60:
            color = COLOR_DANGER
        elif score < 85:
            color = COLOR_WARNING
            
        self.security_score_lbl.configure(text=f"{score}", text_color=color)
        
        desc_text = ", ".join(desc) if desc else "System secure"
        if not self.scan_results:
            desc_text = "Waiting for scans..."
            self.security_score_lbl.configure(text="--", text_color=COLOR_TEXT_DIM)
            
        self.security_score_desc.configure(text=desc_text)

    def _print_threat(self, threat_id: str, detail: str, output_func):
        """Helper to print a professional threat explanation to a specific console."""
        try:
            from modules import threat_explainer, log_storage  # type: ignore
            info = threat_explainer.analyze_threat(threat_id, detail)
            tag = info.get("color", "orange")
            output_func(f"\n  {info['icon']} Threat Analysis: {info['name']}\n", tag)
            output_func(f"      Risk Level : {info['risk']}\n", tag)
            output_func(f"      Details    : {info['explanation']}\n", "dim")
            output_func(f"      Action     : {info['action']}\n\n", "white")
            
            # Log the generated explanation
            log_storage.log_event("Threat Info", f"{info['name']} - {info['action']}", info['risk'])
        except Exception:
            pass

    def run_full_system_scan(self):
        """Trigger sequential run of core security modules."""
        self.full_scan_btn.configure(state="disabled", text="Scanning...")
        self.status_var.set("Running Full System Scan...")
        self.progress.set(0.1)
        
        def _scan_thread():
            try:
                # 1. Malware
                self.status_var.set("Full Scan [1/4]: Malware Heuristics...")
                import modules.malware_scanner as malware_scanner  # type: ignore
                self.scan_results["malware"] = malware_scanner.basic_malware_scan()
                self.root.after(0, self.update_security_score)
                self.progress.set(0.3)
                
                # 2. Firewall
                self.status_var.set("Full Scan [2/4]: Windows Firewall...")
                import modules.firewall_scanner as firewall_scanner  # type: ignore
                self.scan_results["firewall_scanner"] = firewall_scanner.scan_firewall()
                self.root.after(0, self.update_security_score)
                self.progress.set(0.6)
                
                # 3. Network Discovery
                self.status_var.set("Full Scan [3/4]: Network Discovery...")
                import modules.network_discovery as network_discovery  # type: ignore
                self.scan_results["network_discovery"] = network_discovery.discover_devices()
                self.root.after(0, self.update_security_score)
                self.progress.set(0.8)
                
                # 4. Startup Analyzer
                self.status_var.set("Full Scan [4/4]: Startup Programs...")
                import modules.startup_analyzer as startup_analyzer  # type: ignore
                self.scan_results["startup_analyzer"] = startup_analyzer.scan_startup_programs()
                self.root.after(0, self.update_security_score)
                self.progress.set(1.0)
                
                # Finalize
                self.root.after(0, lambda: self.full_scan_btn.configure(state="normal", text="🛡️ Run Full System Scan"))
                self.root.after(0, lambda: self.status_var.set("Full System Scan Complete"))
                self.root.after(0, lambda: self.alert_manager.trigger(
                    "System Scan Complete", 
                    f"All critical modules evaluated. Score: {self.security_score_lbl.cget('text')}/100", 
                    "Low"
                ))
            except Exception as e:
                self.root.after(0, lambda: self.full_scan_btn.configure(state="normal", text="🛡️ Run Full System Scan"))
                self.root.after(0, lambda: self.status_var.set(f"Scan failed: {e}"))
            
        threading.Thread(target=_scan_thread, daemon=True).start()

    # ── Shared section-card helper used by setup_*_tab methods ─────────────
    def _make_card(self, parent, title: str, icon: str = "") -> ctk.CTkFrame:
        """Return a styled card frame with a labelled header."""
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD,
                            corner_radius=12, border_width=1,
                            border_color="#334155")
        card.pack(fill="x", padx=18, pady=(0, 12))
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(hdr, text=f"{icon}  {title}".strip(),
                     font=FONT_HEADING, text_color="white").pack(anchor="w")
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 12))
        return body

    # ── Console output helpers ───────────────────────────────────────────────
    def _cwrite(self, box: ctk.CTkTextbox, text: str, tag: str = "") -> None:
        """
        Write `text` to a CTkTextbox console and auto-scroll to the bottom.
        The box must be in 'normal' state before calling.

        Args:
            box:  The CTkTextbox widget to write into.
            text: The string to append (include '\\n' as needed).
            tag:  Optional colour tag name — "red", "green", "orange", or "".
        """
        try:
            if tag:
                box.insert("end", text, tag)
            else:
                box.insert("end", text)
            box.see("end")          # always scroll to newest line
        except Exception:
            pass  # widget may have been destroyed

    def _cclear(self, box: ctk.CTkTextbox) -> None:
        """
        Clear a CTkTextbox console and prepare it for new output.
        Leaves the box in 'normal' (editable) state so _cwrite can follow.
        """
        box.configure(state="normal")
        box.delete("1.0", "end")

    def _make_console(self, parent: ctk.CTkFrame) -> ctk.CTkTextbox:
        """
        Create and pack a styled, scrollable console CTkTextbox inside `parent`.
        Returns the widget, ready for use with _cwrite / _cclear.

        Usage:
            self.my_box = self._make_console(frame)
        """
        box = ctk.CTkTextbox(
            parent,
            font=FONT_MONO,
            wrap="none",                # horizontal scroll — real console feel
            fg_color="#0d1b2a",         # deep navy background
            text_color="#e2e8f0",       # near-white readable text
            border_width=1,
            border_color="#334155",
            activate_scrollbars=True,
        )
        box.pack(padx=10, pady=8, fill="both", expand=True)
        # Standard colour tags for risk-based colouring
        box.tag_config("red",    foreground="#f87171")   # bright red
        box.tag_config("green",  foreground="#4ade80")   # bright green
        box.tag_config("orange", foreground="#fb923c")   # amber
        box.tag_config("cyan",   foreground="#22d3ee")   # cyan
        box.tag_config("dim",    foreground="#64748b")   # muted slate
        box.tag_config("white",  foreground="#f8fafc")   # near-white
        box.configure(state="disabled")  # read-only until a scan runs
        return box

    # PORT TAB
    def setup_port_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.port_tab
        ctk.CTkLabel(_page, text="🔍 Port Scanner",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Detect open and risky TCP ports on any host",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="🔍 Port Scanner", font=FONT_HEADING).pack(anchor="w")

        input_frame = ctk.CTkFrame(frame)
        input_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(input_frame, text="Target IP or Hostname:").grid(row=0, column=0, sticky="w", pady=5)
        self.host_entry = ctk.CTkEntry(input_frame, width=200)
        self.host_entry.grid(row=0, column=1, pady=5, padx=5)
        ToolTip(self.host_entry, "Enter the IP address or hostname to scan (default: 127.0.0.1)")

        ctk.CTkLabel(input_frame, text="Port Range (e.g., 1-1024 or 22,80,443):").grid(row=1, column=0, sticky="w", pady=5)
        self.port_entry = ctk.CTkEntry(input_frame, width=200)
        self.port_entry.grid(row=1, column=1, pady=5, padx=5)
        ToolTip(self.port_entry, "Specify ports as range (start-end) or comma-separated list (default: 1-1024)")

        ctk.CTkLabel(input_frame, text="Timeout (s):").grid(row=2, column=0, sticky="w", pady=5)
        self.port_timeout_entry = ctk.CTkEntry(input_frame, width=80)
        self.port_timeout_entry.insert(0, "0.5")
        self.port_timeout_entry.grid(row=2, column=1, sticky="w", pady=5, padx=5)
        ToolTip(self.port_timeout_entry, "Connection timeout per port (seconds)")

        ctk.CTkLabel(input_frame, text="Max Threads:").grid(row=3, column=0, sticky="w", pady=5)
        self.port_workers_entry = ctk.CTkEntry(input_frame, width=80)
        self.port_workers_entry.insert(0, "200")
        self.port_workers_entry.grid(row=3, column=1, sticky="w", pady=5, padx=5)
        ToolTip(self.port_workers_entry, "Maximum parallel connections while scanning")

        # Preset buttons
        preset_frame = ctk.CTkFrame(frame)
        preset_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(preset_frame, text="Presets:").pack(side="left", padx=5)
        quick_btn = ctk.CTkButton(preset_frame, text="Quick (Top 100)", width=110,
                                  command=self.set_quick_ports)
        quick_btn.pack(side="left", padx=4)
        ToolTip(quick_btn, "Scan a curated set of the most common 100 ports")
        full_btn = ctk.CTkButton(preset_frame, text="Full (1-1024)", width=110,
                                 command=self.set_full_ports)
        full_btn.pack(side="left", padx=4)
        ToolTip(full_btn, "Scan all well-known ports 1–1024")

        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10)
        self.scan_button = ctk.CTkButton(button_frame, text="🚀 Start Scan", command=self.start_port_scan, height=38)
        self.scan_button.pack(side="left", padx=5)
        ToolTip(self.scan_button, "Start the port scanning process")

        self.result_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#0d1b2a",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155")
        self.result_box.pack(padx=10, pady=5, fill="both", expand=True)
        # Configure text tags for colors
        self.result_box.tag_config("red", foreground="red")
        self.result_box.tag_config("green", foreground="green")
        self.result_box.tag_config("orange", foreground="orange")

    def set_quick_ports(self):
        # Common top ports (subset)
        ports = "20,21,22,23,25,53,80,110,139,143,443,445,3389,5432,3306,5900"
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, ports)

    def set_full_ports(self):
        self.port_entry.delete(0, "end")
        self.port_entry.insert(0, "1-1024")

    def start_port_scan(self):
        host = self.host_entry.get().strip() or "127.0.0.1"
        port_range = self.port_entry.get().strip() or "1-1024"
        try:
            timeout = float(self.port_timeout_entry.get().strip() or "0.5")
        except Exception:
            timeout = 0.5
        try:
            max_workers = int(self.port_workers_entry.get().strip() or "200")
        except Exception:
            max_workers = 200
        self.result_box.configure(state='normal')
        self.result_box.delete("1.0", "end")
        self.result_box.insert("end", f"Scanning {host} ...\n")
        self.result_box.see("end")
        self.result_box.configure(state='disabled')
        self.scan_button.configure(state=ctk.DISABLED)
        self.status_var.set("Scanning ports...")
        self.progress.set(0)
        def run():
            ports = []
            for token in port_range.split(","):
                token = token.strip()
                if "-" in token:
                    a,b = token.split("-")
                    ports.extend(range(int(a), int(b)+1))
                elif token:
                    ports.append(int(token))
            total_ports = len(ports)
            res = port_scanner.scan_ports(host, ports, max_workers=max_workers, timeout=timeout)
            self.scan_results["port_scan"] = res
            self.result_box.configure(state='normal')
            if res.get("status") != "ok":
                # Host resolution / other error
                self.result_box.insert("end", "Error: ", "red")
                self.result_box.see("end")
                self.result_box.insert("end", f"{res.get('error', 'Unknown error')}\n", "red")
                self.result_box.see("end")
            else:
                # Detailed per-port results
                for i, (p, open_) in enumerate(sorted(res["results"].items())):
                    if open_:
                        self.result_box.insert("end", f"Port {p}: ", tags="red")
                        self.result_box.see("end")
                        self.result_box.insert("end", "OPEN\n", tags="red")
                        self.result_box.see("end")
                    elif total_ports <= 2:
                        self.result_box.insert("end", f"Port {p}: ", tags="green")
                        self.result_box.see("end")
                        self.result_box.insert("end", "CLOSED\n", tags="green")
                        self.result_box.see("end")
                    if total_ports:
                        self.progress.set((i + 1) / total_ports)
                        self.root.update_idletasks()

                # Risk summary
                overall = res.get("overall_risk", "Unknown")
                score = res.get("score", 0)
                high_open = res.get("high_risk_open", 0)
                med_open = res.get("medium_risk_open", 0)
                low_open = res.get("low_risk_open", 0)

                if overall == "High":
                    tag = "red"
                elif overall == "Low":
                    tag = "green"
                else:
                    tag = "orange"

                self.result_box.insert("end", "\nSummary:\n")
                self.result_box.see("end")
                self.result_box.insert("end", "Overall exposure: ", tag)
                self.result_box.see("end")
                self.result_box.insert("end", f"{overall}\n", tag)
                self.result_box.see("end")
                self.result_box.insert("end", f"Security score: {score}/100\n")
                self.result_box.see("end")
                self.result_box.insert("end", f"High-risk open ports: {high_open}\n", "red" if high_open else "green")
                self.result_box.see("end")
                self.result_box.insert("end", f"Medium-risk open ports: {med_open}\n", "orange" if med_open else "green")
                self.result_box.see("end")
                self.result_box.insert("end", f"Low-risk open ports: {low_open}\n\n", "green")
                self.result_box.see("end")

                # Log to security log if any open ports
                open_ports = res.get("open_ports") or []
                if open_ports:
                    risk_for_log = "High" if overall == "High" else "Medium"
                    msg = (
                        f"Port scan on {host}: {overall} exposure, score {score}/100, "
                        f"high={high_open}, medium={med_open}, low={low_open}"
                    )
                    log_storage.log_event("Port", msg, risk_for_log)
                    self.alert_manager.trigger("Port", msg, risk_for_log)

            self.result_box.insert("end", f"\nScan completed in {res.get('time')}s\n")
            self.result_box.see("end")
            self.result_box.configure(state='disabled')
            self.scan_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")
            self.progress.set(0)
        threading.Thread(target=run, daemon=True).start()

    # PASSWORD TAB
    def setup_password_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.password_tab
        ctk.CTkLabel(_page, text="🔐 Password Policy",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Audit the system's password complexity requirements",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="🔐 Password Policy", font=FONT_HEADING).pack(anchor="w")

        ctk.CTkLabel(frame, text="System Password Policy (fetched from OS)", font=FONT_BODY).pack(pady=8)
        self.policy_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#0d1b2a",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155")
        self.policy_box.pack(padx=10, pady=5, fill="both", expand=True)
        # Configure text tags for colors
        self.policy_box.tag_config("red", foreground="red")
        self.policy_box.tag_config("green", foreground="green")
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)
        self.fetch_button = ctk.CTkButton(button_frame, text="🔍 Fetch Password Policy", command=self.fetch_policy, height=38)
        self.fetch_button.pack(side="left", padx=5)
        ToolTip(self.fetch_button, "Retrieve the current password policy settings from the system")

    def fetch_policy(self):
        self.policy_box.configure(state='normal')
        self.policy_box.delete("1.0", "end")
        self.policy_box.configure(state='disabled')
        self.fetch_button.configure(state=ctk.DISABLED)
        self.status_var.set("Fetching password policy...")
        def run():
            res = password_policy.get_password_policy()
            self.scan_results["password_policy"] = res
            self.policy_box.configure(state='normal')
            self.policy_box.insert("end", f"Check: {res.get('check')}\n")
            self.policy_box.see("end")
            status = res.get('status')
            if status.lower() == 'good':
                self.policy_box.insert("end", f"Status: {status}", tags="green")
                self.policy_box.see("end")
            elif status.lower() == 'bad':
                self.policy_box.insert("end", f"Status: {status}", tags="red")
                self.policy_box.see("end")
            else:
                self.policy_box.insert("end", f"Status: {status}")
                self.policy_box.see("end")
            self.policy_box.insert("end", "\n\n")
            self.policy_box.see("end")
            self.policy_box.insert("end", res.get('detail'))
            self.policy_box.see("end")
            self.policy_box.configure(state='disabled')
            self.fetch_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")
        threading.Thread(target=run, daemon=True).start()

    # WIFI TAB
    def setup_wifi_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.wifi_tab
        ctk.CTkLabel(_page, text="📶 Wi-Fi Info",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Inspect connected wireless network security settings",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="📶 Wi-Fi Info", font=FONT_HEADING).pack(anchor="w")

        ctk.CTkLabel(frame, text="Connected Wi‑Fi Device Info", font=FONT_BODY).pack(pady=8)
        self.wifi_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#0d1b2a",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155")
        self.wifi_box.pack(padx=10, pady=5, fill="both", expand=True)
        # Configure text tags for colors
        self.wifi_box.tag_config("red", foreground="red")
        self.wifi_box.tag_config("green", foreground="green")
        self.wifi_box.tag_config("orange", foreground="orange")
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)
        self.wifi_button = ctk.CTkButton(button_frame, text="📡 Fetch Wi‑Fi Info", command=self.fetch_wifi, height=38)
        self.wifi_button.pack(side="left", padx=5)
        ToolTip(self.wifi_button, "Retrieve current Wi-Fi connection details")
        self.start_wifi_scan_button = ctk.CTkButton(button_frame, text="▶️ Start Scanning", command=self.start_wifi_scan, height=38)
        self.start_wifi_scan_button.pack(side="left", padx=5)
        ToolTip(self.start_wifi_scan_button, "Continuously monitor Wi-Fi connections")
        self.stop_wifi_scan_button = ctk.CTkButton(button_frame, text="⏹️ Stop Scanning", command=self.stop_wifi_scan, state=ctk.DISABLED, height=38)
        self.stop_wifi_scan_button.pack(side="left", padx=5)
        ToolTip(self.stop_wifi_scan_button, "Stop the continuous Wi-Fi scanning")

    def fetch_wifi(self):
        self.wifi_box.configure(state='normal')
        self.wifi_box.delete("1.0", "end")
        self.wifi_box.configure(state='disabled')
        self.wifi_button.configure(state=ctk.DISABLED)
        self.status_var.set("Fetching Wi-Fi info...")
        def run():
            info = wifi_info.get_wifi_info()
            self.scan_results['wifi_info'] = info
            self.wifi_box.configure(state='normal')
            if info.get('status') == 'ok':
                detail = info.get('detail', {}) or {}
                assessment = wifi_info.assess_wifi_security(detail)

                # Overall status
                self.wifi_box.insert("end", "Status: ", tags="green")
                self.wifi_box.see("end")
                self.wifi_box.insert("end", "ok\n\n", tags="green")
                self.wifi_box.see("end")

                # Summary line with score and risk
                ssid = assessment.get("ssid") or "Unknown"
                security = assessment.get("security") or "Unknown"
                risk = assessment.get("risk_level") or "Unknown"
                score = assessment.get("score", 0)
                network_type = assessment.get("network_type", "Unknown")

                self.wifi_box.insert("end", f"Current SSID: {ssid}\n")
                self.wifi_box.see("end")
                self.wifi_box.insert("end", f"Security: {security}\n")
                self.wifi_box.see("end")
                self.wifi_box.insert("end", f"Network type: {network_type}\n")
                self.wifi_box.see("end")

                # Risk with color coding
                if risk == "High":
                    tag = "red"
                elif risk == "Low":
                    tag = "green"
                else:
                    tag = "orange"
                self.wifi_box.insert("end", "Risk level: ", tag)
                self.wifi_box.see("end")
                self.wifi_box.insert("end", f"{risk}\n", tag)
                self.wifi_box.see("end")

                self.wifi_box.insert("end", f"Security score: {score}/100\n\n")
                self.wifi_box.see("end")

                # Warnings (weak password / public network hints, etc.)
                warnings = assessment.get("warnings") or []
                if warnings:
                    self.wifi_box.insert("end", "Warnings:\n", "red")
                    self.wifi_box.see("end")
                    for w in warnings:
                        self.wifi_box.insert("end", f"- {w}\n")
                        self.wifi_box.see("end")
                    self.wifi_box.insert("end", "\n")
                    self.wifi_box.see("end")

                # Raw detail dump for advanced users
                if detail:
                    self.wifi_box.insert("end", "Raw Wi‑Fi details:\n")
                    self.wifi_box.see("end")
                    for k, v in detail.items():
                        self.wifi_box.insert("end", f"{k}: {v}\n")
                        self.wifi_box.see("end")
            else:
                self.wifi_box.insert("end", "Status: ", tags="red")
                self.wifi_box.see("end")
                self.wifi_box.insert("end", "error\n\n", tags="red")
                self.wifi_box.see("end")
                self.wifi_box.insert("end", info.get('detail'))
                self.wifi_box.see("end")
            self.wifi_box.configure(state='disabled')
            self.wifi_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")
        threading.Thread(target=run, daemon=True).start()

    def start_wifi_scan(self):
        if self.wifi_scanning:
            return
        self.wifi_scanning = True
        self.start_wifi_scan_button.configure(state=ctk.DISABLED)
        self.stop_wifi_scan_button.configure(state=ctk.NORMAL)
        self.wifi_log = []
        self.update_wifi_display()
        self.status_var.set("Scanning Wi-Fi continuously...")
        threading.Thread(target=self.wifi_scan_loop, daemon=True).start()

    def stop_wifi_scan(self):
        self.wifi_scanning = False
        self.start_wifi_scan_button.configure(state=ctk.NORMAL)
        self.stop_wifi_scan_button.configure(state=ctk.DISABLED)
        self.status_var.set("Ready")

    def wifi_scan_loop(self):
        previous_ssid = None
        while self.wifi_scanning:
            info = wifi_info.get_wifi_info()
            if info.get('status') == 'ok':
                detail = info.get('detail', {}) or {}
                assessment = wifi_info.assess_wifi_security(detail)
                current_ssid = assessment.get("ssid")
                security = assessment.get("security")
                risk = assessment.get("risk_level", "Medium")
                if current_ssid and current_ssid != previous_ssid:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.wifi_log.append(f"{timestamp}: Connected to - {current_ssid} (Security: {security})")
                    # Persist Wi-Fi connection with security level
                    try:
                        wifi_info.record_wifi_snapshot(current_ssid, security, event="connected", source="scan_loop")
                    except Exception:
                        pass
                    # Log WiFi connection change (risk based on assessment)
                    log_storage.log_event("WiFi", f"WiFi network changed to: {current_ssid} (Security: {security})", risk)
                    self.alert_manager.trigger("WiFi", f"Network changed to: {current_ssid} (Security: {security})", risk)
                    previous_ssid = current_ssid
            self.update_wifi_display()
            time.sleep(5)  # Scan every 5 seconds

    def update_wifi_display(self):
        self.wifi_box.configure(state='normal')
        self.wifi_box.delete("1.0", "end")
        if self.wifi_log:
            self.wifi_box.insert("end", "Wi-Fi Connection Log:\n")
            self.wifi_box.see("end")
            for entry in self.wifi_log:
                self.wifi_box.insert("end", f"{entry}\n")
                self.wifi_box.see("end")
        else:
            self.wifi_box.insert("end", "No Wi-Fi connections detected yet.\n")
            self.wifi_box.see("end")
        self.wifi_box.configure(state='disabled')

    # USB TAB
    def setup_usb_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.usb_tab
        ctk.CTkLabel(_page, text="💾 USB Devices",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Monitor USB device connections and history",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="💾 USB Devices", font=FONT_HEADING).pack(anchor="w")

        ctk.CTkLabel(frame, text="Connected USB Devices (External Only)", font=FONT_BODY).pack(pady=8)
        info_frame = ctk.CTkFrame(frame)
        info_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(info_frame, text="Device Count:").grid(row=0, column=0, sticky="w")
        self.device_count_label = ctk.CTkLabel(info_frame, text="0")
        self.device_count_label.grid(row=0, column=1, sticky="w", padx=5)
        ctk.CTkLabel(info_frame, text="Last Scan:").grid(row=0, column=2, sticky="w", padx=10)
        self.last_scan_label = ctk.CTkLabel(info_frame, text="Never")
        self.last_scan_label.grid(row=0, column=3, sticky="w")

        self.usb_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#0d1b2a",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155")
        self.usb_box.pack(padx=10, pady=5, fill="both", expand=True)
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)
        self.usb_button = ctk.CTkButton(button_frame, text="🔌 Fetch USB Info", command=self.fetch_usb, height=38)
        self.usb_button.pack(side="left", padx=5)
        ToolTip(self.usb_button, "Retrieve current USB device information")
        self.detailed_var = ctk.BooleanVar()
        self.detailed_check = ctk.CTkCheckBox(button_frame, text="Detailed View", variable=self.detailed_var)
        self.detailed_check.pack(side="left", padx=5)
        ToolTip(self.detailed_check, "Show detailed device info (if available)")
        ctk.CTkLabel(button_frame, text="Scan Interval (s):").pack(side="left", padx=5)
        self.scan_interval_entry = ctk.CTkEntry(button_frame, width=80)
        self.scan_interval_entry.insert(0, "5")
        self.scan_interval_entry.pack(side="left", padx=5)
        ToolTip(self.scan_interval_entry, "Interval for continuous scanning (seconds)")
        self.start_scan_button = ctk.CTkButton(button_frame, text="▶️ Start Scanning", command=self.start_usb_scan, height=38)
        self.start_scan_button.pack(side="left", padx=5)
        ToolTip(self.start_scan_button, "Continuously monitor USB devices")
        self.stop_scan_button = ctk.CTkButton(button_frame, text="⏹️ Stop Scanning", command=self.stop_usb_scan, state=ctk.DISABLED, height=38)
        self.stop_scan_button.pack(side="left", padx=5)
        ToolTip(self.stop_scan_button, "Stop the continuous USB scanning")

    def fetch_usb(self):
        self.usb_box.configure(state='normal')
        self.usb_box.delete("1.0", "end")
        self.usb_box.configure(state='disabled')
        self.usb_button.configure(state=ctk.DISABLED)
        self.status_var.set("Fetching USB info...")
        def run():
            info = usb_info.get_usb_info()
            self.scan_results['usb_info'] = info
            self.last_scan_time = time.strftime("%H:%M:%S")
            self.last_scan_label.configure(text=self.last_scan_time)
            self.usb_box.configure(state='normal')
            if info.get('status') == 'ok':
                self.usb_box.insert("end", "Status: ", tags="green")
                self.usb_box.see("end")
                self.usb_box.insert("end", "ok\n\n", tags="green")
                self.usb_box.see("end")
                internal_devs = info.get('internal_devices', [])
                external_devs = info.get('external_devices', [])
                total_devices = len(internal_devs) + len(external_devs)
                self.device_count = total_devices
                self.device_count_label.configure(text=str(self.device_count))

                # Display internal devices
                self.usb_box.insert("end", 'Internal USB devices:\n')
                self.usb_box.see("end")
                if internal_devs:
                    for d in internal_devs:
                        self.usb_box.insert("end", f"- {d}\n")
                        self.usb_box.see("end")
                else:
                    self.usb_box.insert("end", "None found.\n")
                    self.usb_box.see("end")

                self.usb_box.insert("end", "\n")
                self.usb_box.see("end")

                # Display external devices
                self.usb_box.insert("end", 'External USB devices:\n')
                self.usb_box.see("end")
                if external_devs:
                    for d in external_devs:
                        self.usb_box.insert("end", f"- {d}\n")
                        self.usb_box.see("end")
                    # Log external USB device detection
                    log_storage.log_event("USB", f"External device detected: {', '.join(external_devs)}", "Medium")
                    self.alert_manager.trigger("USB", f"External device detected: {', '.join(external_devs)}", "Medium")
                    # Record snapshot in USB history
                    usb_info.record_usb_snapshot(external_devs)
                else:
                    self.usb_box.insert("end", "None found.\n")
                    self.usb_box.see("end")

                times = info.get('times_hint', '') or ''
                if times and times != 'none':
                    formatted_events = format_usb_events(times)
                    if formatted_events:
                        self.usb_box.insert("end", '\nRecent USB Connection Events:\n')
                        self.usb_box.see("end")
                        for event in formatted_events:
                            self.usb_box.insert("end", f"- {event}\n")
                            self.usb_box.see("end")
                    else:
                        self.usb_box.insert("end", '\nNo recent USB connection events found.\n')
                        self.usb_box.see("end")
            else:
                self.usb_box.insert("end", "Status: ", tags="red")
                self.usb_box.see("end")
                self.usb_box.insert("end", "error\n\n", tags="red")
                self.usb_box.see("end")
                self.usb_box.insert("end", info.get('detail','No info'))
                self.usb_box.see("end")
            self.usb_box.configure(state='disabled')
            self.usb_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")
        threading.Thread(target=run, daemon=True).start()

    def start_usb_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.start_scan_button.configure(state=ctk.DISABLED)
        self.stop_scan_button.configure(state=ctk.NORMAL)
        self.usb_log = []
        self.update_usb_display()
        self.status_var.set("Scanning USB continuously...")
        threading.Thread(target=self.usb_scan_loop, daemon=True).start()

    def stop_usb_scan(self):
        self.scanning = False
        self.start_scan_button.configure(state=ctk.NORMAL)
        self.stop_scan_button.configure(state=ctk.DISABLED)
        self.status_var.set("Ready")

    def usb_scan_loop(self):
        previous_devices = set()
        while self.scanning:
            try:
                interval = int(self.scan_interval_entry.get()) if self.scan_interval_entry.get().isdigit() else 5
            except:
                interval = 5
            info = usb_info.get_usb_info()
            if info.get('status') == 'ok':
                external_devices = info.get('external_devices', [])
                internal_devices = info.get('internal_devices', [])
                current_devices = set(external_devices + internal_devices)
                new_devices = current_devices - previous_devices  # type: ignore[operator]
                if new_devices:
                    usb_info.record_usb_snapshot(list(new_devices))
                for dev in new_devices:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.usb_log.append(f"{timestamp}: Connected - {dev}")
                    # Log new USB device detection
                    is_external = dev in external_devices
                    risk_level = "Medium" if is_external else "Low"
                    log_storage.log_event("USB", f"USB device connected: {dev} ({'External' if is_external else 'Internal'})", risk_level)
                    self.alert_manager.trigger("USB", f"USB device connected: {dev} ({'External' if is_external else 'Internal'})", risk_level)
                previous_devices = current_devices
            self.update_usb_display()
            time.sleep(interval)

    def update_usb_display(self):
        self.usb_box.configure(state='normal')
        self.usb_box.delete("1.0", "end")
        if self.usb_log:
            self.usb_box.insert("end", "USB Connection Log:\n")
            self.usb_box.see("end")
            for entry in self.usb_log:
                self.usb_box.insert("end", f"{entry}\n")
                self.usb_box.see("end")
        else:
            self.usb_box.insert("end", "No new USB connections detected yet.\n")
            self.usb_box.see("end")
        self.usb_box.configure(state='disabled')

    # FIREWALL TAB  (enhanced — uses firewall_scanner module)
    def setup_firewall_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.firewall_tab
        ctk.CTkLabel(_page, text="🛡️ Firewall Scan",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Advanced firewall rule analysis and port exposure",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Header ──────────────────────────────────────────────────────────
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(
            header_frame,
            text="🛡️ Advanced Firewall Security Scanner",
            font=FONT_HEADING,
        ).pack(anchor="w")
        ctk.CTkLabel(
            header_frame,
            text="Checks firewall state (netsh), profile config, inbound rules & open ports",
            font=FONT_SMALL,
        ).pack(anchor="w", pady=(0, 4))

        # ── Controls row ────────────────────────────────────────────────────
        ctrl_frame = ctk.CTkFrame(frame)
        ctrl_frame.pack(pady=4, padx=10, fill="x")

        ctk.CTkLabel(ctrl_frame, text="Probe Host (port scan):").grid(
            row=0, column=0, sticky="w", padx=5, pady=4
        )
        self.fw_probe_entry = ctk.CTkEntry(ctrl_frame, width=145)
        self.fw_probe_entry.insert(0, "127.0.0.1")
        self.fw_probe_entry.grid(row=0, column=1, sticky="w", padx=5, pady=4)
        ToolTip(
            self.fw_probe_entry,
            "IP / hostname to probe for open sensitive ports (leave as 127.0.0.1 for localhost)",
        )

        ctk.CTkLabel(ctrl_frame, text="Max Rules to Inspect:").grid(
            row=0, column=2, sticky="w", padx=10, pady=4
        )
        self.fw_maxrules_entry = ctk.CTkEntry(ctrl_frame, width=60)
        self.fw_maxrules_entry.insert(0, "500")
        self.fw_maxrules_entry.grid(row=0, column=3, sticky="w", padx=5, pady=4)
        ToolTip(self.fw_maxrules_entry, "Maximum number of inbound rules to inspect (default 500)")

        # ── Live status label ────────────────────────────────────────────────
        self.fw_status_label = ctk.CTkLabel(
            frame, text="", font=FONT_SMALL, text_color=COLOR_TEXT_DIM
        )
        self.fw_status_label.pack(anchor="w", padx=12, pady=(0, 4))

        # ── Console output box (full-height, dark terminal style) ────────────
        self.firewall_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#060d18",        # very deep navy — terminal black
            text_color="#e2e8f0",
            border_width=1,
            border_color="#1e3a5f",
            activate_scrollbars=True,
        )
        self.firewall_box.pack(padx=10, pady=(0, 8), fill="both", expand=True)
        # ── Colour tags ──────────────────────────────────────────────────────
        self.firewall_box.tag_config("red",    foreground="#f87171")  # High risk
        self.firewall_box.tag_config("green",  foreground="#4ade80")  # Safe / OK
        self.firewall_box.tag_config("orange", foreground="#fb923c")  # Medium risk
        self.firewall_box.tag_config("cyan",   foreground="#38bdf8")  # Section headers
        self.firewall_box.tag_config("dim",    foreground="#64748b")  # Muted text
        self.firewall_box.tag_config("white",  foreground="#f1f5f9")  # Bright labels
        self.firewall_box.configure(state="disabled")

        # ── Buttons ──────────────────────────────────────────────────────────
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)

        self.firewall_button = ctk.CTkButton(
            button_frame,
            text="🔎 Run Full Firewall Scan",
            command=self.fetch_firewall,)
        self.firewall_button.pack(side="left", padx=5)
        ToolTip(
            self.firewall_button,
            "Run all firewall checks: profile status, inbound rules, open-port probe",
        )

        self.fw_open_log_btn = ctk.CTkButton(
            button_frame,
            text="📄 Open Firewall Log",
            width=140,
            command=self._open_firewall_log,)
        self.fw_open_log_btn.pack(side="left", padx=5)
        ToolTip(self.fw_open_log_btn, "Open the firewall_scan_log.csv file in the default application")

    # ── Open the firewall CSV log externally ─────────────────────────────
    def _open_firewall_log(self):
        import os, subprocess
        log_path = os.path.join("logs", "firewall_scan_log.csv")
        if os.path.exists(log_path):
            try:
                os.startfile(log_path)  # type: ignore[attr-defined]  # Windows-only API
            except Exception as e:
                messagebox.showerror("Firewall Log", f"Cannot open log file:\n{e}")
        else:
            messagebox.showinfo("Firewall Log", "No firewall log found yet. Run a scan first.")

    # ── Section divider helper ───────────────────────────────────────────────
    def _fw_divider(self, title: str) -> None:
        """Insert a styled section divider into the firewall console."""
        sep = "─" * 64
        box = self.firewall_box
        box.insert("end", f"\n{sep}\n", "dim")
        box.insert("end", f"  {title}\n", "cyan")
        box.insert("end", f"{sep}\n", "dim")
        box.see("end")

    # ── Main scan handler ────────────────────────────────────────────────────
    def fetch_firewall(self):
        """Kick off the full firewall scan in a background thread."""
        box = self.firewall_box
        self._cclear(box)                           # clear + leave in normal state
        self.firewall_button.configure(state=ctk.DISABLED)
        self.fw_open_log_btn.configure(state=ctk.DISABLED)
        self.status_var.set("Running advanced firewall scan…")

        probe_host = self.fw_probe_entry.get().strip() or "127.0.0.1"
        try:
            max_rules = int(self.fw_maxrules_entry.get().strip())
        except Exception:
            max_rules = 500

        def _step(msg: str) -> None:
            """Update live step label safely from any thread."""
            self.root.after(0, lambda: self.fw_status_label.configure(text=msg))

        def _w(text: str, tag: str = "") -> None:
            """Write coloured text to firewall_box and scroll to bottom."""
            self._cwrite(box, text, tag)

        def run() -> None:
            # ── Banner ───────────────────────────────────────────────────────
            _step("  ⏳  Running full firewall scan…")
            _w("  ╔══════════════════════════════════════════════════════════╗\n", "cyan")
            _w("  ║   Advanced System Security Scanner — Firewall Module    ║\n", "cyan")
            _w("  ╚══════════════════════════════════════════════════════════╝\n", "cyan")
            _w(f"  Scan started : {time.strftime('%Y-%m-%d  %H:%M:%S')}\n", "dim")
            _w(f"  Probe host   : {probe_host}    Max rules : {max_rules}\n\n", "dim")

            # ── Run the engine ───────────────────────────────────────────────
            report = firewall_scanner.run_firewall_scan(
                probe_host=probe_host,
                max_rules=max_rules,
                save_csv=True,
            )
            self.scan_results["firewall"] = report
            status = report.get("status", "error")

            if status == "unsupported":
                _w("  ⚠  Firewall scan is only supported on Windows.\n", "orange")
                box.configure(state="disabled")
                self.firewall_button.configure(state=ctk.NORMAL)
                self.fw_open_log_btn.configure(state=ctk.NORMAL)
                self.status_var.set("Ready"); _step(""); return

            if status == "error":
                _w("  ❌  Firewall scan error:\n", "red")
                _w(f"  {report.get('error', 'Unknown error')}\n", "red")
                box.configure(state="disabled")
                self.firewall_button.configure(state=ctk.NORMAL)
                self.fw_open_log_btn.configure(state=ctk.NORMAL)
                self.status_var.set("Ready"); _step(""); return

            # ── Aggregate summary ────────────────────────────────────────────
            overall_risk = report.get("overall_risk", "Unknown")
            score        = report.get("score", 0)
            scan_time    = report.get("scan_time", "")
            high_rules   = report.get("high_risk_rules",  0)
            med_rules    = report.get("medium_risk_rules", 0)
            high_ports   = report.get("high_risk_ports",  0)
            med_ports    = report.get("medium_risk_ports", 0)
            csv_saved    = report.get("csv_saved", False)

            risk_tag = (
                "red"    if overall_risk == "High" else
                "green"  if overall_risk == "Low"  else
                "orange"
            )
            # Score bar (10 chars)
            filled = round(score / 10)
            bar    = "█" * filled + "░" * (10 - filled)

            _w("  Overall Risk   :  ", "white"); _w(f"{overall_risk}\n", risk_tag)
            _w(f"  Security Score :  [{bar}]  {score}/100\n", risk_tag)
            _w(f"  Scan Time      :  {scan_time}\n", "dim")
            _w(f"  Risky Rules    →  High: {high_rules}   Medium: {med_rules}\n",
               "red" if high_rules else ("orange" if med_rules else "green"))
            _w(f"  Open Ports     →  High: {high_ports}   Medium: {med_ports}\n",
               "red" if high_ports else ("orange" if med_ports else "green"))
            _w(f"  Log saved      :  {'Yes ✔' if csv_saved else 'No'}"
               "  (logs/firewall_scan_log.csv)\n",
               "green" if csv_saved else "dim")

            # ── Section 1: Profile on/off (netsh) ───────────────────────────
            _step("  ⏳  Section 1 — profile state…")
            self._fw_divider("1. Firewall Profile Status  —  netsh advfirewall")
            profiles = report.get("profiles") or []
            if profiles:
                for p in profiles:
                    en  = p.get("enabled")
                    tag = "green" if en else "red"
                    ico = "[ON] " if en else "[OFF]"
                    _w(f"  {ico}  ", tag)
                    _w(p.get("finding", "") + "\n", tag)
                    if not en:
                        self._print_threat("firewall_disabled", p.get("Name", ""), _w)
            else:
                _w("  Could not retrieve profile status via netsh.\n", "orange")

            # ── Section 2: Profile config (PowerShell) ──────────────────────
            _step("  ⏳  Section 2 — profile configuration…")
            self._fw_divider("2. Profile Configuration  —  Get-NetFirewallProfile")
            profile_details = report.get("profile_details") or []
            if profile_details:
                for pd in profile_details:
                    name     = pd.get("Name", "Unknown")
                    enabled  = pd.get("Enabled", False)
                    inbound  = pd.get("DefaultInboundAction",  "Unknown")
                    outbound = pd.get("DefaultOutboundAction", "Unknown")
                    rl       = pd.get("risk_level", "Low")
                    tag      = "red" if rl == "High" else ("orange" if rl == "Medium" else "green")
                    badge    = "ENABLED " if enabled else "DISABLED"
                    _w(f"  [{badge}]  {name}\n", tag)
                    _w(f"    Inbound  default  :  {inbound}\n",
                       "orange" if inbound.lower() == "allow" else "dim")
                    _w(f"    Outbound default  :  {outbound}\n", "dim")
                    for v in pd.get("vulnerabilities", []):
                        ico = "  ⚠  " if rl in ("High", "Medium") else "  ✔  "
                        _w(ico + v + "\n", tag)
                    _w("\n")
            else:
                _w("  Could not retrieve profile details via PowerShell.\n", "orange")

            # ── Section 3: Open port probe ───────────────────────────────────
            _step(f"  ⏳  Section 3 — open-port probe on {probe_host}…")
            self._fw_divider(f"3. Open Sensitive Port Probe  —  host: {probe_host}")
            open_ports = report.get("open_ports") or []
            if open_ports:
                _w(f"  {'PORT':<8} {'SERVICE':<36} RISK\n", "dim")
                _w(f"  {'─'*8} {'─'*36} {'─'*6}\n", "dim")
                for op in open_ports:
                    rl   = op.get("risk_level", "Medium")
                    tag  = "red" if rl == "High" else "orange"
                    pn   = str(op.get("port", "?"))
                    svc  = op.get("service", "Unknown")[:34]
                    _w(f"  {pn:<8} {svc:<36} ", "white")
                    _w(f"{rl}\n", tag)
                    if rl in ("High", "Medium"):
                        tid = "open_port_generic"
                        if pn == "21": tid = "open_port_ftp"
                        elif pn == "23": tid = "open_port_telnet"
                        elif pn == "3389": tid = "open_port_rdp"
                        self._print_threat(tid, f"Port {pn}", _w)
                _w(f"\n  ⚠  {len(open_ports)} sensitive port(s) open. "
                   "Restrict access via firewall rules.\n", "orange")
            else:
                _w(f"  ✔  No sensitive ports open on {probe_host}.\n", "green")

            # ── Section 4: Risky inbound rules ──────────────────────────────
            _step("  ⏳  Section 4 — risky inbound rules…")
            self._fw_divider(
                f"4. Risky Inbound Rules  —  {high_rules} High   {med_rules} Medium"
            )
            risky_rules = report.get("risky_rules") or []
            if risky_rules:
                shown = risky_rules[:30]  # type: ignore[index]
                _w(f"  Showing {len(shown)} of {len(risky_rules)} risky rule(s):\n\n", "dim")
                for r in shown:
                    rl   = r.get("risk_level", "Medium")
                    tag  = "red" if rl == "High" else "orange"
                    name = r.get("name",     "Unnamed")
                    pf   = r.get("profile",  "All")
                    pt   = r.get("port",     "Any")
                    pr   = r.get("protocol", "Any")
                    rm   = r.get("remote",   "Any")
                    _w("  [", "dim"); _w(f"{rl:6s}", tag); _w(f"]  {name}\n", "white")
                    _w(f"    Profile={pf}  Port={pt}  Protocol={pr}  Remote={rm}\n", "dim")
                    for reason in r.get("reasons", []):
                        _w(f"    • {reason}\n", tag)
                    if rl in ("High", "Medium"):
                        self._print_threat("risky_rule", name, _w)
                    _w("\n")
            else:
                _w("  ✔  No medium/high-risk inbound rules detected.\n", "green")

            # ── Section 5: Warnings ──────────────────────────────────────────
            _step("  ⏳  Section 5 — recommendations…")
            self._fw_divider("5. Warnings & Recommendations")
            for w in (report.get("warnings") or []):
                is_ok = w.startswith("No critical")
                _w(("  ✔  " if is_ok else "  ⚠  ") + w + "\n",
                   "green" if is_ok else "orange")

            # ── Footer ───────────────────────────────────────────────────────
            _w(f"\n  Scan complete at {time.strftime('%H:%M:%S')}. "
               "Results saved to logs/firewall_scan_log.csv\n", "dim")
            _w(f"  {'═'*62}\n", "dim")

            # Log to shared security log
            risk_for_log = (
                "High"   if high_rules or high_ports else
                "Medium" if med_rules  or med_ports  else
                "Low"
            )
            log_storage.log_event(
                "Firewall",
                f"Firewall Scan: {overall_risk} risk, score {score}/100, "
                f"rules H={high_rules} M={med_rules}, ports H={high_ports} M={med_ports}",
                risk_for_log,
            )
            self.alert_manager.trigger(
                "Firewall",
                f"Firewall scan: {overall_risk} risk (score {score}/100). "
                f"High-risk rules: {high_rules}, open ports: {high_ports}",
                risk_for_log,
            )
            _step("")
            box.configure(state="disabled")
            self.firewall_button.configure(state=ctk.NORMAL)
            self.fw_open_log_btn.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")

        threading.Thread(target=run, daemon=True).start()




    # MALWARE TAB
    def setup_malware_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.malware_tab
        ctk.CTkLabel(_page, text="🧬 Malware Detection",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Professional heuristic malware scanner with smart detection",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Header ──────────────────────────────────────────────────────────
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="🧬 Advanced Malware Heuristic Scanner",
                     font=FONT_HEADING).pack(anchor="w")
        ctk.CTkLabel(
            header_frame,
            text="Multi-factor detection: hash signatures, keyword analysis, location checks, "
                 "hidden file flags.\nWhitelisted directories are automatically excluded to "
                 "minimise false positives.",
            font=FONT_SMALL,
            justify="left",
        ).pack(anchor="w", pady=(0, 4))

        # ── Custom path scan controls ────────────────────────────────────────
        path_frame = ctk.CTkFrame(frame)
        path_frame.pack(pady=4, padx=10, fill="x")
        ctk.CTkLabel(path_frame, text="Custom Folder Scan:").grid(
            row=0, column=0, sticky="w", padx=5, pady=4)
        self.malware_path_entry = ctk.CTkEntry(path_frame, width=300,
            placeholder_text="Enter folder or file path …")
        self.malware_path_entry.grid(row=0, column=1, sticky="w", padx=5, pady=4)
        ToolTip(self.malware_path_entry,
                "Enter a folder or file path to scan for malware indicators")
        self.malware_path_button = ctk.CTkButton(
            path_frame, text="🔍 Scan Path", width=110,
            command=self.fetch_malware_path, height=36)
        self.malware_path_button.grid(row=0, column=2, sticky="w", padx=5, pady=4)
        ToolTip(self.malware_path_button,
                "Scan the specified folder or file for suspicious items")

        # ── Live status label ────────────────────────────────────────────────
        self.malware_status_label = ctk.CTkLabel(
            frame, text="", font=FONT_SMALL, text_color=COLOR_TEXT_DIM)
        self.malware_status_label.pack(anchor="w", padx=12, pady=(0, 4))

        # ── Console output box ───────────────────────────────────────────────
        self.malware_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#060d18",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#1e3a5f",
            activate_scrollbars=True)
        self.malware_box.pack(padx=10, pady=(0, 8), fill="both", expand=True)
        # Colour tags
        self.malware_box.tag_config("red",    foreground="#f87171")
        self.malware_box.tag_config("green",  foreground="#4ade80")
        self.malware_box.tag_config("orange", foreground="#fb923c")
        self.malware_box.tag_config("cyan",   foreground="#38bdf8")
        self.malware_box.tag_config("dim",    foreground="#64748b")
        self.malware_box.tag_config("white",  foreground="#f1f5f9")
        self.malware_box.configure(state="disabled")

        # ── Buttons ──────────────────────────────────────────────────────────
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)
        self.malware_button = ctk.CTkButton(
            button_frame, text="🧪 Full System Scan",
            command=self.fetch_malware, height=38)
        self.malware_button.pack(side="left", padx=5)
        ToolTip(self.malware_button,
                "Scan Downloads, Desktop, Documents & Temp folders + check processes & startup items")

        self.malware_wl_button = ctk.CTkButton(
            button_frame, text="🛡️ Manage Whitelist",
            width=150, command=self._manage_malware_whitelist, height=38)
        self.malware_wl_button.pack(side="left", padx=5)
        ToolTip(self.malware_wl_button,
                "Add safe directories to the whitelist to prevent false positives")

        self.malware_log_button = ctk.CTkButton(
            button_frame, text="📄 Open Log",
            width=110, command=self._open_malware_log, height=38)
        self.malware_log_button.pack(side="left", padx=5)
        ToolTip(self.malware_log_button,
                "Open the malware_scan_log.csv file")

    # ── Malware log opener ───────────────────────────────────────────────────
    def _open_malware_log(self):
        log_path = os.path.join("logs", "malware_scan_log.csv")
        if os.path.exists(log_path):
            try:
                os.startfile(log_path)  # type: ignore[attr-defined]
            except Exception as e:
                messagebox.showerror("Malware Log", f"Cannot open log:\n{e}")
        else:
            messagebox.showinfo("Malware Log",
                                "No malware log found yet. Run a scan first.")

    # ── Whitelist manager dialog ─────────────────────────────────────────────
    def _manage_malware_whitelist(self):
        wl = malware_scanner.get_whitelist()
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Malware Scanner — Whitelist")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="🛡️ Whitelisted Directories",
                     font=FONT_HEADING).pack(pady=(12, 4))
        ctk.CTkLabel(dialog,
                     text="Files in these directories are automatically marked SAFE.",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(pady=(0, 8))

        wl_box = ctk.CTkTextbox(dialog, font=FONT_MONO, fg_color="#0d1b2a",
                                text_color="#e2e8f0", wrap="word")
        wl_box.pack(padx=12, pady=4, fill="both", expand=True)
        for p in wl:
            wl_box.insert("end", f"{p}\n")
        wl_box.configure(state="disabled")

        add_frame = ctk.CTkFrame(dialog)
        add_frame.pack(pady=8, padx=12, fill="x")
        add_entry = ctk.CTkEntry(add_frame, width=400,
                                 placeholder_text="Enter directory path to whitelist …")
        add_entry.pack(side="left", padx=5, fill="x", expand=True)

        def _add():
            path = (add_entry.get() or "").strip()
            if path and os.path.exists(path):
                malware_scanner.add_whitelist_path(path)
                wl_box.configure(state="normal")
                wl_box.insert("end", f"{os.path.abspath(path).lower()}\n")
                wl_box.configure(state="disabled")
                add_entry.delete(0, "end")
                messagebox.showinfo("Whitelist", f"Added: {path}")
            else:
                messagebox.showerror("Whitelist", "Invalid or non-existent path.")

        ctk.CTkButton(add_frame, text="➕ Add", width=80,
                      command=_add).pack(side="left", padx=5)

    # ── Console helper for malware tab ───────────────────────────────────────
    def _mw(self, text, tag=""):
        """Write to malware_box and scroll."""
        box = self.malware_box
        box.configure(state="normal")
        if tag:
            box.insert("end", text, tag)
        else:
            box.insert("end", text)
        box.see("end")

    def _mw_divider(self, title):
        sep = "─" * 64
        self._mw(f"\n{sep}\n", "dim")
        self._mw(f"  {title}\n", "cyan")
        self._mw(f"{sep}\n", "dim")

    # ── Full System Scan ─────────────────────────────────────────────────────
    def fetch_malware(self):
        box = self.malware_box
        self._cclear(box)
        self.malware_button.configure(state=ctk.DISABLED)
        self.malware_path_button.configure(state=ctk.DISABLED)
        self.status_var.set("Running advanced malware scan…")

        def _step(msg):
            self.root.after(0, lambda: self.malware_status_label.configure(text=msg))

        def _progress(count, fp):
            name = os.path.basename(fp)[:35]
            self.root.after(0, lambda: self.malware_status_label.configure(
                text=f"  ⏳ Scanned {count} files… {name}"))

        def run():
            # ── Banner ────────────────────────────────────────────────────
            _step("  ⏳  Running full malware scan…")
            self._mw("  ╔══════════════════════════════════════════════════════════╗\n", "cyan")
            self._mw("  ║   Advanced Malware Scanner — Full System Scan           ║\n", "cyan")
            self._mw("  ╚══════════════════════════════════════════════════════════╝\n", "cyan")
            self._mw(f"  Scan started : {time.strftime('%Y-%m-%d  %H:%M:%S')}\n", "dim")
            self._mw(f"  Mode         : Full System Scan (Downloads, Desktop, Documents, Temp)\n\n", "dim")

            info = malware_scanner.basic_malware_scan(progress_callback=_progress)
            self.scan_results["malware"] = info

            status = info.get("status")
            if status == "unsupported":
                self._mw("  ⚠  Malware scan is only supported on Windows.\n", "orange")
                box.configure(state="disabled")
                self.malware_button.configure(state=ctk.NORMAL)
                self.malware_path_button.configure(state=ctk.NORMAL)
                self.status_var.set("Ready"); _step(""); return

            if status == "error":
                self._mw("  ❌  Malware scan error:\n", "red")
                self._mw(f"  {info.get('detail', 'Unknown error')}\n", "red")
                box.configure(state="disabled")
                self.malware_button.configure(state=ctk.NORMAL)
                self.malware_path_button.configure(state=ctk.NORMAL)
                self.status_var.set("Ready"); _step(""); return

            # ── Summary ──────────────────────────────────────────────────
            summary = info.get("summary") or {}
            findings = info.get("findings") or {}
            overall_risk = summary.get("overall_risk", "Unknown")
            score = summary.get("score", 0)
            sp = summary.get("suspicious_processes", 0)
            ss = summary.get("suspicious_startup_entries", 0)
            sf = summary.get("suspicious_files", 0)
            hrf = summary.get("high_risk_files", 0)
            dirs_scanned = summary.get("directories_scanned", [])

            risk_tag = (
                "red"    if overall_risk == "High" else
                "green"  if overall_risk == "Low"  else
                "orange"
            )
            filled = round(float(score) / 10.0)
            bar = "█" * filled + "░" * (10 - filled)

            self._mw("  Overall Risk   :  ", "white")
            self._mw(f"{overall_risk}\n", risk_tag)
            self._mw(f"  Security Score :  [{bar}]  {score}/100\n", risk_tag)
            self._mw(f"  Dirs Scanned   :  {len(dirs_scanned)}\n", "dim")
            self._mw(f"  Suspicious processes      :  {sp}\n",
                     "red" if sp else "green")
            self._mw(f"  Suspicious startup items  :  {ss}\n",
                     "orange" if ss else "green")
            self._mw(f"  Suspicious files          :  {sf}\n",
                     "orange" if sf else "green")
            self._mw(f"  HIGH RISK files           :  {hrf}\n",
                     "red" if hrf else "green")

            # ── Section 1: Processes ─────────────────────────────────────
            _step("  Processing results…")
            procs = findings.get("processes") or []
            self._mw_divider("1. Suspicious Processes")
            if procs:
                for p in procs[:30]: # type: ignore[index]
                    rl = p.get("risk_level", "Medium")
                    tag = "red" if rl == "High" else "orange"
                    self._mw(f"  [{rl:6s}]  ", tag)
                    self._mw(f"{p.get('name', '?')} (PID {p.get('pid', '?')})\n", "white")
                    path = p.get("path") or ""
                    if path:
                        self._mw(f"    Path: {path}\n", "dim")
                    for r in p.get("reasons") or []:
                        self._mw(f"    • {r}\n", tag)
                    self._mw("\n")
                    if rl == "High":
                        self._print_threat("suspicious_process", p.get("name", ""),
                                           lambda m, t="": self._mw(m, t))
            else:
                self._mw("  ✔  No suspicious processes detected.\n", "green")

            # ── Section 2: Startup Items ─────────────────────────────────
            startups = findings.get("startup") or []
            self._mw_divider("2. Suspicious Startup Entries")
            if startups:
                for s in startups[:30]: # type: ignore[index]
                    rl = s.get("risk_level", "Medium")
                    tag = "red" if rl == "High" else "orange"
                    self._mw(f"  [{rl:6s}]  ", tag)
                    self._mw(f"{s.get('name', 'Unnamed')}\n", "white")
                    cmd = s.get("command") or ""
                    loc = s.get("location") or ""
                    if cmd:
                        self._mw(f"    Command : {cmd}\n", "dim")
                    if loc:
                        self._mw(f"    Location: {loc}\n", "dim")
                    for r in s.get("reasons") or []:
                        self._mw(f"    • {r}\n", tag)
                    self._mw("\n")
                    if rl == "High":
                        self._print_threat("suspicious_startup", s.get("name", ""),
                                           lambda m, t="": self._mw(m, t))
            else:
                self._mw("  ✔  No suspicious startup entries detected.\n", "green")

            # ── Section 3: Flagged Files ─────────────────────────────────
            files = findings.get("files") or []
            self._mw_divider(f"3. Flagged Files  ({len(files)} total)")
            if files:
                self._mw(f"  {'FILE':<30} {'TYPE':<8} {'RISK':<12} SCORE\n", "dim")
                self._mw(f"  {'─'*30} {'─'*8} {'─'*12} {'─'*5}\n", "dim")
                for f in files[:50]: # type: ignore[index]
                    cls = f.get("classification", "SUSPICIOUS")
                    fscore = f.get("score", 0)
                    fname = f.get("file_name", os.path.basename(f.get("path", "")))
                    ftype = f.get("file_type", "?")
                    tag = "red" if cls == "HIGH RISK" else "orange"

                    display_name = fname[:28] if len(fname) > 28 else fname
                    self._mw(f"  {display_name:<30} ", "white")
                    self._mw(f"{ftype:<8} ", "dim")
                    self._mw(f"{cls:<12} ", tag)
                    self._mw(f"{fscore}\n")

                    self._mw(f"    Path: {f.get('path', '')}\n", "dim")
                    for r in f.get("reasons") or []:
                        self._mw(f"    • {r}\n", tag)
                    self._mw("\n")

                    if cls == "HIGH RISK":
                        self._print_threat("malicious_file", f.get("path", ""),
                                           lambda m, t="": self._mw(m, t))

                if len(files) > 50:
                    self._mw(f"  ... and {len(files)-50} more in log.\n", "dim")
            else:
                self._mw("  ✔  No suspicious files detected. Your system looks clean!\n", "green")

            # ── Footer ───────────────────────────────────────────────────
            self._mw(f"\n  Scan complete at {time.strftime('%H:%M:%S')}.\n", "dim")
            self._mw("  Results saved to logs/malware_scan_log.csv\n", "dim")
            self._mw(f"  {'═'*62}\n", "dim")

            # Log to shared security log
            if sp or ss or sf:
                risk_for_log = "High" if overall_risk == "High" else "Medium"
                msg = (
                    f"Malware scan: {overall_risk} risk, score {score}/100, "
                    f"processes={sp}, startup={ss}, files={sf}"
                )
                log_storage.log_event("Malware", msg, risk_for_log)
                self.alert_manager.trigger("Malware", msg, risk_for_log)

            _step("")
            box.configure(state="disabled")
            self.malware_button.configure(state=ctk.NORMAL)
            self.malware_path_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")

        threading.Thread(target=run, daemon=True).start()

    # ── Custom Path Scan ─────────────────────────────────────────────────────
    def fetch_malware_path(self):
        target = (self.malware_path_entry.get() or "").strip()
        if not target:
            messagebox.showerror("Malware Scan",
                                 "Please enter a folder or file path to scan.")
            return

        box = self.malware_box
        self._cclear(box)
        self.malware_path_button.configure(state=ctk.DISABLED)
        self.malware_button.configure(state=ctk.DISABLED)
        self.status_var.set(f"Scanning path: {target} …")

        def _progress(count, fp):
            name = os.path.basename(fp)[:35]
            self.root.after(0, lambda: self.malware_status_label.configure(
                text=f"  ⏳ Scanned {count} files… {name}"))

        def run():
            self._mw("  ╔══════════════════════════════════════════════════════════╗\n", "cyan")
            self._mw("  ║   Advanced Malware Scanner — Custom Path Scan           ║\n", "cyan")
            self._mw("  ╚══════════════════════════════════════════════════════════╝\n", "cyan")
            self._mw(f"  Target : {target}\n", "dim")
            self._mw(f"  Started: {time.strftime('%Y-%m-%d  %H:%M:%S')}\n\n", "dim")

            info = malware_scanner.scan_path(target, progress_callback=_progress)
            self.scan_results["malware_path"] = info

            status = info.get("status")
            if status == "ok":
                summary  = info.get("summary") or {}
                findings = (info.get("findings") or {}).get("files") or []
                overall_risk = summary.get("overall_risk", "Unknown")
                score        = summary.get("score", 0)
                high_c       = summary.get("high_risk", 0)
                susp_c       = summary.get("suspicious", 0)
                total_c      = summary.get("suspicious_files", 0)
                target_res   = summary.get("target", target)

                risk_tag = (
                    "red"    if overall_risk == "High" else
                    "green"  if overall_risk == "Low"  else
                    "orange"
                )
                filled = round(float(score) / 10.0)
                bar = "█" * filled + "░" * (10 - filled)

                self._mw("  Overall Risk   :  ", "white")
                self._mw(f"{overall_risk}\n", risk_tag)
                self._mw(f"  Security Score :  [{bar}]  {score}/100\n", risk_tag)
                self._mw(f"  HIGH RISK      :  {high_c}\n",
                         "red" if high_c else "green")
                self._mw(f"  SUSPICIOUS     :  {susp_c}\n",
                         "orange" if susp_c else "green")

                if findings:
                    self._mw_divider(f"Flagged Files  ({total_c} total)")
                    self._mw(f"  {'FILE':<30} {'TYPE':<8} {'RISK':<12} SCORE\n", "dim")
                    self._mw(f"  {'─'*30} {'─'*8} {'─'*12} {'─'*5}\n", "dim")
                    for f in findings[:100]: # type: ignore[index]
                        cls = f.get("classification", "SUSPICIOUS")
                        fscore = f.get("score", 0)
                        fname = f.get("file_name", os.path.basename(f.get("path", "")))
                        ftype = f.get("file_type", "?")
                        tag = "red" if cls == "HIGH RISK" else "orange"

                        display_name = fname[:28] if len(fname) > 28 else fname
                        self._mw(f"  {display_name:<30} ", "white")
                        self._mw(f"{ftype:<8} ", "dim")
                        self._mw(f"{cls:<12} ", tag)
                        self._mw(f"{fscore}\n")

                        self._mw(f"    Path: {f.get('path', '')}\n", "dim")
                        for r in f.get("reasons") or []:
                            self._mw(f"    • {r}\n", tag)
                        self._mw("\n")

                        if cls == "HIGH RISK":
                            self._print_threat("malicious_file", f.get("path", ""),
                                               lambda m, t="": self._mw(m, t))
                    if len(findings) > 100:
                        self._mw(f"  ... and {len(findings)-100} more. "
                                 "Check logs/malware_scan_log.csv\n", "dim")
                else:
                    self._mw("\n  ✔  No suspicious files detected. Path looks clean!\n", "green")

                self._mw(f"\n  Scan complete at {time.strftime('%H:%M:%S')}.\n", "dim")
                self._mw(f"  {'═'*62}\n", "dim")

                risk_for_log = ("High" if overall_risk == "High"
                                else "Medium" if total_c else "Low")
                log_storage.log_event("Malware",
                    f"Path scan '{target_res}': {overall_risk} risk, "
                    f"score {score}/100, HIGH={high_c}, SUSP={susp_c}",
                    risk_for_log)
                self.alert_manager.trigger("Malware",
                    f"Path scan '{target_res}': {overall_risk} risk, "
                    f"HIGH={high_c}, SUSP={susp_c}",
                    risk_for_log)
            else:
                self._mw("  ❌  Custom path scan error:\n", "red")
                self._mw(f"  {info.get('detail', 'Unknown error')}\n", "red")

            self.malware_status_label.configure(text="")
            box.configure(state="disabled")
            self.malware_path_button.configure(state=ctk.NORMAL)
            self.malware_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")

        threading.Thread(target=run, daemon=True).start()


    # LOGS TAB
    def setup_logs_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.logs_tab
        ctk.CTkLabel(_page, text="📋 Security Logs",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="View, filter and export all recorded security events",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="📋 Security Logs", font=FONT_HEADING).pack(anchor="w")

        # Filter and control frame
        control_frame = ctk.CTkFrame(frame)
        control_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(control_frame, text="Filter by Module:", font=FONT_BODY).grid(row=0, column=0, sticky="w", padx=5)
        self.log_filter_var = ctk.StringVar(value="All")
        filter_combo = ctk.CTkComboBox(control_frame, variable=self.log_filter_var, 
                                       values=["All", "USB", "WiFi", "Port", "Firewall", "Malware", "Password"],
                                       command=self.refresh_logs_display, height=36)
        filter_combo.grid(row=0, column=1, sticky="w", padx=5)

        ctk.CTkLabel(control_frame, text="Filter by Risk:", font=FONT_BODY).grid(row=0, column=2, sticky="w", padx=5)
        self.risk_filter_var = ctk.StringVar(value="All")
        risk_combo = ctk.CTkComboBox(control_frame, variable=self.risk_filter_var, 
                                     values=["All", "Low", "Medium", "High"],
                                     command=self.refresh_logs_display, height=36)
        risk_combo.grid(row=0, column=3, sticky="w", padx=5)

        # Stats frame
        stats_frame = ctk.CTkFrame(frame)
        stats_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(stats_frame, text="Total Logs:", font=FONT_SMALL).grid(row=0, column=0, sticky="w")
        self.logs_count_label = ctk.CTkLabel(stats_frame, text="0", font=FONT_SMALL)
        self.logs_count_label.grid(row=0, column=1, sticky="w", padx=5)

        # Logs display
        self.logs_box = ctk.CTkTextbox(
            frame,
            font=FONT_MONO,
            wrap="none",
            fg_color="#0d1b2a",
            text_color="#e2e8f0",
            border_width=1,
            border_color="#334155")
        self.logs_box.pack(padx=10, pady=5, fill="both", expand=True)

        # Buttons frame
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10, padx=10, fill="x")
        
        refresh_button = ctk.CTkButton(button_frame, text="🔄 Refresh", command=self.refresh_logs_display, height=38)
        refresh_button.pack(side="left", padx=5)
        ToolTip(refresh_button, "Refresh the logs display")

        export_button = ctk.CTkButton(button_frame, text="💾 Export as CSV", command=self.export_logs_csv, height=38)
        export_button.pack(side="left", padx=5)
        ToolTip(export_button, "Export logs to a CSV file")

        clear_button = ctk.CTkButton(button_frame, text="🗑️ Clear All Logs", command=self.clear_all_logs, height=38)
        clear_button.pack(side="left", padx=5)
        ToolTip(clear_button, "Clear all security logs (cannot be undone)")

        # Initial display
        self.refresh_logs_display()

    def refresh_logs_display(self):
        """Refresh and display logs with current filters."""
        all_logs = log_storage.get_all_logs()
        module_filter = self.log_filter_var.get()
        risk_filter = self.risk_filter_var.get()

        # Apply filters
        filtered_logs = all_logs
        if module_filter != "All":
            filtered_logs = [log for log in filtered_logs if log.get('Module', '') == module_filter]
        if risk_filter != "All":
            filtered_logs = [log for log in filtered_logs if log.get('Risk Level', '') == risk_filter]

        # Update display
        self.logs_box.configure(state='normal')
        self.logs_box.delete("1.0", "end")

        if not filtered_logs:
            self.logs_box.insert("end", "No logs found with current filters.\n")
            self.logs_box.see("end")
        else:
            # Header
            header = f"{'Date':<12} {'Time':<10} {'Module':<12} {'Event':<40} {'Risk':<8}\n"
            header += "-" * 82 + "\n"
            self.logs_box.insert("end", header)
            self.logs_box.see("end")

            # Color tags for risk levels
            self.logs_box.tag_config("Low", foreground="green")
            self.logs_box.tag_config("Medium", foreground="orange")
            self.logs_box.tag_config("High", foreground="red")

            # Logs
            for log in filtered_logs:
                date = log.get('Date', 'N/A')
                time_str = log.get('Time', 'N/A')
                module = log.get('Module', 'N/A')
                event = log.get('Event Description', 'N/A')[:35]  # Truncate long events
                risk = log.get('Risk Level', 'N/A')

                line = f"{date:<12} {time_str:<10} {module:<12} {event:<40} "
                self.logs_box.insert("end", line)
                self.logs_box.see("end")
                self.logs_box.insert("end", risk + "\n", risk)
                self.logs_box.see("end")

        self.logs_box.configure(state='disabled')
        self.logs_count_label.configure(text=str(len(filtered_logs)))

    def export_logs_csv(self):
        """Export logs to a new CSV file."""
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            export_filename = os.path.join("reports", f"logs_export_{timestamp}.csv")
            
            logs = log_storage.get_all_logs()
            if not logs:
                messagebox.showinfo("Export Logs", "No logs to export.")
                return

            # Write to CSV
            os.makedirs("reports", exist_ok=True)
            with open(export_filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["Date", "Time", "Module", "Event Description", "Risk Level"])
                writer.writeheader()
                writer.writerows(logs)

            messagebox.showinfo("Export Logs", f"Logs exported to: {export_filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs: {e}")

    def clear_all_logs(self):
        """Clear all logs after confirmation."""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all security logs? This cannot be undone."):
            if log_storage.clear_logs():
                messagebox.showinfo("Logs Cleared", "All security logs have been cleared.")
                self.refresh_logs_display()
            else:
                messagebox.showerror("Error", "Failed to clear logs.")

    # REPORT TAB
    def setup_report_tab(self):
        # ── Page shell: title banner + scrollable body ──────────────────
        _page = self.report_tab
        ctk.CTkLabel(_page, text="📄 Generate Report",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page, text="Export a full DOCX report of all scan results",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))
        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="📄 Generate Report", font=FONT_HEADING).pack(anchor="w")

        ctk.CTkLabel(frame, text="Generate System Scan Report", font=FONT_BODY).pack(pady=10)
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=6)
        self.report_button = ctk.CTkButton(button_frame, text="📝 Generate DOCX Report", command=self.generate_report, height=38)
        self.report_button.pack(side="left", padx=5)
        ToolTip(self.report_button, "Create a DOCX report of all scan results")
        ctk.CTkLabel(frame, text="Optional: Create PDF (requires docx2pdf on Windows)", font=FONT_SMALL).pack(pady=4)
        self.report_status = ctk.CTkLabel(frame, text="", font=FONT_SMALL)
        self.report_status.pack(pady=6)

    def generate_report(self):
        self.report_button.configure(state=ctk.DISABLED)
        self.status_var.set("Generating report...")
        def run():
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = os.path.join("reports", f"report_{timestamp}.docx")
            report_generator.create_report(self.scan_results, filename)
            self.report_status.configure(text=f"Report saved as {filename}")
            messagebox.showinfo("Report", f"Report saved: {filename}")
            self.report_button.configure(state=ctk.NORMAL)
            self.status_var.set("Ready")
        threading.Thread(target=run, daemon=True).start()

    # SETTINGS TAB
    # ══════════════════════════════════════════════════════════════════════
    #  SETTINGS PANEL  –  Professional Control Centre
    # ══════════════════════════════════════════════════════════════════════

    def setup_settings_tab(self):
        """Build the full settings control panel with category tabs."""
        from modules import settings_manager  # type: ignore

        _page = self.settings_tab

        # ── Load current settings ──────────────────────────────────────
        _cfg = settings_manager.load()

        # ── Page header ────────────────────────────────────────────────
        hdr_row = ctk.CTkFrame(_page, fg_color="transparent")
        hdr_row.pack(fill="x", padx=24, pady=(22, 0))

        txt_col = ctk.CTkFrame(hdr_row, fg_color="transparent")
        txt_col.pack(side="left")
        ctk.CTkLabel(txt_col, text="⚙️  Control Panel",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(txt_col,
                     text="Centralised application settings — changes are saved to .logs/app_settings.json",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Apply & Reset buttons (top-right)
        btn_row = ctk.CTkFrame(hdr_row, fg_color="transparent")
        btn_row.pack(side="right")
        reset_btn = ctk.CTkButton(
            btn_row, text="↺ Defaults", width=110, height=34,
            fg_color="#334155", hover_color="#475569",
            command=self._settings_reset_defaults,
        )
        reset_btn.pack(side="left", padx=(0, 8))
        apply_btn = ctk.CTkButton(
            btn_row, text="💾 Apply & Save", width=130, height=34,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self._settings_apply_and_save,
        )
        apply_btn.pack(side="left")

        # Thin divider
        ctk.CTkFrame(_page, height=1, fg_color="#334155").pack(
            fill="x", padx=24, pady=(10, 0))

        # ── Category TabView ───────────────────────────────────────────
        self._settings_tabview = ctk.CTkTabview(
            _page,
            fg_color="#0f1a2e",
            segmented_button_fg_color="#1e293b",
            segmented_button_selected_color=COLOR_ACCENT,
            segmented_button_selected_hover_color=COLOR_NAV_HOVER,
            segmented_button_unselected_color="#1e293b",
            segmented_button_unselected_hover_color="#334155",
            text_color="white",
            corner_radius=10,
        )
        self._settings_tabview.pack(fill="both", expand=True,
                                    padx=20, pady=(8, 12))

        for tab_name in ("🖥️  UI", "🔒  Security", "📷  Camera",
                         "🗂️  Protected Files", "🔑  Authentication",
                         "📋  Logging"):
            self._settings_tabview.add(tab_name)

        # ── 1. UI Settings ─────────────────────────────────────────────
        self._build_settings_ui_tab(
            self._settings_tabview.tab("🖥️  UI"), _cfg)

        # ── 2. Security Settings ───────────────────────────────────────
        self._build_settings_security_tab(
            self._settings_tabview.tab("🔒  Security"), _cfg)

        # ── 3. Camera Settings ─────────────────────────────────────────
        self._build_settings_camera_tab(
            self._settings_tabview.tab("📷  Camera"), _cfg)

        # ── 4. Protected Files ─────────────────────────────────────────
        self._build_settings_protected_tab(
            self._settings_tabview.tab("🗂️  Protected Files"), _cfg)

        # ── 5. Authentication Settings ─────────────────────────────────
        self._build_settings_auth_tab(
            self._settings_tabview.tab("🔑  Authentication"), _cfg)

        # ── 6. Logging Settings ────────────────────────────────────────
        self._build_settings_logging_tab(
            self._settings_tabview.tab("📋  Logging"), _cfg)

    # ── Settings sub-builders ──────────────────────────────────────────

    def _settings_row(self, parent, label: str, tooltip: str = ""):
        """Return (row_frame, label_widget) for a two-column settings row."""
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", pady=5)
        lbl = ctk.CTkLabel(row, text=label, font=FONT_BODY,
                            text_color="white", anchor="w", width=220)
        lbl.pack(side="left")
        if tooltip:
            ToolTip(lbl, tooltip)
        return row

    def _settings_section(self, parent, title: str, icon: str = ""):
        """Section header inside a tab."""
        sf = ctk.CTkFrame(parent, fg_color=COLOR_CARD,
                          corner_radius=10, border_width=1,
                          border_color="#334155")
        sf.pack(fill="x", padx=4, pady=(0, 14))
        hdr = ctk.CTkFrame(sf, fg_color="transparent")
        hdr.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(hdr,
                     text=f"{icon}  {title}".strip(),
                     font=FONT_HEADING, text_color="white").pack(anchor="w")
        body = ctk.CTkFrame(sf, fg_color="transparent")
        body.pack(fill="x", padx=14, pady=(0, 12))
        return body

    # -- 1. UI tab --------------------------------------------------------
    def _build_settings_ui_tab(self, tab, cfg: dict):
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent",
                                        scrollbar_button_color="#334155")
        scroll.pack(fill="both", expand=True)

        # Appearance section
        sec = self._settings_section(scroll, "Appearance", "🎨")

        row = self._settings_row(sec, "Appearance Mode",
                                 "Dark / Light / System")
        self._ui_appearance_var = ctk.StringVar(
            value=cfg.get("ui", {}).get("appearance_mode", "Dark"))
        ctk.CTkOptionMenu(
            row, variable=self._ui_appearance_var,
            values=["Dark", "Light", "System"],
            width=170, height=32,
        ).pack(side="left")

        row = self._settings_row(sec, "Color Accent Theme",
                                 "Blue / Green / Dark-Blue")
        self._ui_color_theme_var = ctk.StringVar(
            value=cfg.get("ui", {}).get("color_theme", "blue"))
        ctk.CTkOptionMenu(
            row, variable=self._ui_color_theme_var,
            values=["blue", "green", "dark-blue"],
            width=170, height=32,
        ).pack(side="left")
        ctk.CTkLabel(row,
                     text="⚠ Color theme change requires restart",
                     font=FONT_SMALL, text_color=COLOR_WARNING).pack(
            side="left", padx=10)

        # Typography section
        sec2 = self._settings_section(scroll, "Typography", "🔤")

        row = self._settings_row(sec2, "Font Family",
                                 "Font used across the UI")
        self._ui_font_family_var = ctk.StringVar(
            value=cfg.get("ui", {}).get("font_family", "Segoe UI"))
        ctk.CTkOptionMenu(
            row, variable=self._ui_font_family_var,
            values=["Segoe UI", "Arial", "Consolas", "Calibri", "Verdana"],
            width=170, height=32,
        ).pack(side="left")

        row = self._settings_row(sec2, "Body Font Size (pt)",
                                 "Size of the main body text")
        self._ui_font_size_var = ctk.IntVar(
            value=cfg.get("ui", {}).get("font_size", 11))
        ctk.CTkSlider(
            row, from_=9, to=16, number_of_steps=7,
            variable=self._ui_font_size_var, width=160,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, textvariable=self._ui_font_size_var,
                     font=FONT_BODY, text_color=COLOR_ACCENT,
                     width=24).pack(side="left")

    # -- 2. Security tab --------------------------------------------------
    def _build_settings_security_tab(self, tab, cfg: dict):
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent",
                                        scrollbar_button_color="#334155")
        scroll.pack(fill="both", expand=True)

        sec = self._settings_section(scroll, "Intrusion Detection", "🛡️")
        sec_cfg = cfg.get("security", {})

        row = self._settings_row(sec, "Intrusion Evidence Capture",
                                 "Take webcam photos when intrusion detected")
        self._sec_capture_var = ctk.BooleanVar(
            value=sec_cfg.get("intrusion_capture_enabled", True))
        ctk.CTkSwitch(row, text="", variable=self._sec_capture_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        row = self._settings_row(sec, "Tamper Detection",
                                 "Monitor app files for unauthorized changes")
        self._sec_tamper_var = ctk.BooleanVar(
            value=sec_cfg.get("tamper_detection_enabled", True))
        ctk.CTkSwitch(row, text="", variable=self._sec_tamper_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        sec2 = self._settings_section(scroll, "Access Control", "🔐")

        row = self._settings_row(sec2, "Require Login on Startup",
                                 "Prompt for dynamic password when app opens")
        self._sec_auth_var = ctk.BooleanVar(
            value=sec_cfg.get("auth_enabled", True))
        ctk.CTkSwitch(row, text="", variable=self._sec_auth_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        row = self._settings_row(sec2, "Enable Account Lockout",
                                 "Lock after 3 failed login attempts")
        self._sec_lockout_var = ctk.BooleanVar(
            value=sec_cfg.get("lockout_enabled", True))
        ctk.CTkSwitch(row, text="", variable=self._sec_lockout_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

    # -- 3. Camera tab ----------------------------------------------------
    def _build_settings_camera_tab(self, tab, cfg: dict):
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent",
                                        scrollbar_button_color="#334155")
        scroll.pack(fill="both", expand=True)

        cam_cfg = cfg.get("camera", {})
        sec = self._settings_section(scroll, "Evidence Capture Control", "📷")

        row = self._settings_row(sec, "Max Captures per Event",
                                 "Maximum webcam snapshots per intrusion event")
        self._cam_max_var = ctk.IntVar(
            value=cam_cfg.get("max_captures", 2))
        ctk.CTkSlider(
            row, from_=1, to=10, number_of_steps=9,
            variable=self._cam_max_var, width=160,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, textvariable=self._cam_max_var,
                     font=FONT_BODY, text_color=COLOR_ACCENT,
                     width=24).pack(side="left")

        row = self._settings_row(sec, "Cooldown Between Events (s)",
                                 "Minimum seconds before next capture sequence")
        self._cam_cooldown_var = ctk.IntVar(
            value=cam_cfg.get("cooldown_seconds", 30))
        ctk.CTkSlider(
            row, from_=5, to=300, number_of_steps=59,
            variable=self._cam_cooldown_var, width=160,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, textvariable=self._cam_cooldown_var,
                     font=FONT_BODY, text_color=COLOR_ACCENT,
                     width=36).pack(side="left")

        sec2 = self._settings_section(scroll, "Camera Usage Scope", "🎯")

        row = self._settings_row(sec2, "Enable for Honeypot Monitor",
                                 "Camera captures on honeypot file access")
        self._cam_honeypot_var = ctk.BooleanVar(
            value=cam_cfg.get("honeypot_camera", False))
        ctk.CTkSwitch(row, text="", variable=self._cam_honeypot_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        row = self._settings_row(sec2, "Enable for Protected Folders",
                                 "Camera captures on protected path access")
        self._cam_protected_var = ctk.BooleanVar(
            value=cam_cfg.get("protected_camera", False))
        ctk.CTkSwitch(row, text="", variable=self._cam_protected_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

    # -- 4. Protected Files tab -------------------------------------------
    def _build_settings_protected_tab(self, tab, cfg: dict):
        """Path management UI that mirrors changes to protected_folders module."""
        outer = ctk.CTkFrame(tab, fg_color="transparent")
        outer.pack(fill="both", expand=True)

        # Add-path input row
        add_row = ctk.CTkFrame(outer, fg_color=COLOR_CARD,
                               corner_radius=10, border_width=1,
                               border_color="#334155")
        add_row.pack(fill="x", padx=4, pady=(0, 10))
        inner = ctk.CTkFrame(add_row, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(inner, text="🗂️  Monitored Paths",
                     font=FONT_HEADING, text_color="white").pack(
            anchor="w", pady=(0, 8))

        entry_row = ctk.CTkFrame(inner, fg_color="transparent")
        entry_row.pack(fill="x")
        self._prot_path_entry = ctk.CTkEntry(
            entry_row, placeholder_text="Paste a file or folder path…",
            height=34, font=FONT_BODY)
        self._prot_path_entry.pack(side="left", fill="x", expand=True,
                                   padx=(0, 8))

        browse_btn = ctk.CTkButton(
            entry_row, text="📁 Browse", width=90, height=34,
            fg_color="#334155", hover_color="#475569",
            command=self._settings_browse_path,
        )
        browse_btn.pack(side="left", padx=(0, 6))

        add_path_btn = ctk.CTkButton(
            entry_row, text="➕ Add", width=80, height=34,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self._settings_add_path,
        )
        add_path_btn.pack(side="left")

        # Scrollable list of existing paths
        list_card = ctk.CTkFrame(outer, fg_color=COLOR_CARD,
                                 corner_radius=10, border_width=1,
                                 border_color="#334155")
        list_card.pack(fill="both", expand=True, padx=4)
        ctk.CTkLabel(list_card, text="Currently Monitored",
                     font=FONT_SUBHEAD, text_color=COLOR_TEXT_DIM).pack(
            anchor="w", padx=14, pady=(10, 4))

        self._prot_list_frame = ctk.CTkScrollableFrame(
            list_card, fg_color="transparent",
            scrollbar_button_color="#334155",
            scrollbar_button_hover_color=COLOR_ACCENT,
        )
        self._prot_list_frame.pack(fill="both", expand=True,
                                   padx=10, pady=(0, 10))
        self._settings_refresh_path_list()

    def _settings_browse_path(self):
        path = filedialog.askdirectory(title="Select folder to protect")
        if not path:
            path = filedialog.askopenfilename(title="Select file to protect")
        if path:
            self._prot_path_entry.delete(0, "end")
            self._prot_path_entry.insert(0, path)

    def _settings_add_path(self):
        from modules import protected_folders  # type: ignore
        path = self._prot_path_entry.get().strip()
        if not path:
            messagebox.showwarning("Settings", "Please enter or browse for a path.")
            return
        result = protected_folders.add_protected_path(path)
        if result["status"] == "ok":
            self._prot_path_entry.delete(0, "end")
            self._settings_refresh_path_list()
            # Reload the monitor so it picks up the new path
            try:
                self.pf_monitor.reload()
            except Exception:
                pass
            self.status_var.set(f"Protected: {result['message']}")
        elif result["status"] == "duplicate":
            messagebox.showinfo("Settings", result["message"])
        else:
            messagebox.showerror("Settings", result["message"])

    def _settings_remove_path(self, path: str):
        from modules import protected_folders  # type: ignore
        result = protected_folders.remove_protected_path(path)
        if result["status"] == "ok":
            self._settings_refresh_path_list()
            try:
                self.pf_monitor.reload()
            except Exception:
                pass
            self.status_var.set(f"Removed: {result['message']}")
        else:
            messagebox.showerror("Settings", result["message"])

    def _settings_refresh_path_list(self):
        from modules import protected_folders  # type: ignore
        # Clear existing
        for w in self._prot_list_frame.winfo_children():
            w.destroy()

        paths = protected_folders.get_protected_paths()
        if not paths:
            ctk.CTkLabel(
                self._prot_list_frame,
                text="No paths monitored yet — add one above.",
                font=FONT_BODY, text_color=COLOR_TEXT_DIM,
            ).pack(anchor="w", pady=8)
            return

        for entry in paths:
            p = entry.get("path", "")
            ptype = entry.get("type", "file")
            icon = "📁" if ptype == "folder" else "📄"
            row = ctk.CTkFrame(self._prot_list_frame,
                               fg_color="#1e293b", corner_radius=6)
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=f"{icon}  {p}",
                         font=FONT_SMALL, text_color="white",
                         anchor="w").pack(side="left", padx=10,
                                          pady=6, fill="x", expand=True)
            ctk.CTkButton(
                row, text="✕", width=28, height=26,
                fg_color=COLOR_DANGER, hover_color="#991b1b",
                font=("Segoe UI", 11, "bold"),
                command=lambda _p=p: self._settings_remove_path(_p),
            ).pack(side="right", padx=6, pady=4)

    # -- 5. Authentication tab --------------------------------------------
    def _build_settings_auth_tab(self, tab, cfg: dict):
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent",
                                        scrollbar_button_color="#334155")
        scroll.pack(fill="both", expand=True)

        auth_cfg = cfg.get("auth", {})
        sec = self._settings_section(scroll, "Login Behaviour", "🔑")

        row = self._settings_row(sec, "Show Password Format Hint",
                                 "Display time-format hint in login dialog")
        self._auth_hint_var = ctk.BooleanVar(
            value=auth_cfg.get("dynamic_password_hint", True))
        ctk.CTkSwitch(row, text="", variable=self._auth_hint_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        row = self._settings_row(sec, "OTP / Two-Factor (Reserved)",
                                 "Future: one-time-password second factor")
        self._auth_otp_var = ctk.BooleanVar(
            value=auth_cfg.get("otp_enabled", False))
        sw = ctk.CTkSwitch(row, text="", variable=self._auth_otp_var,
                           onvalue=True, offvalue=False,
                           progress_color=COLOR_ACCENT)
        sw.configure(state="disabled")
        sw.pack(side="left")
        ctk.CTkLabel(row, text="(Coming soon)", font=FONT_SMALL,
                     text_color=COLOR_TEXT_DIM).pack(side="left", padx=8)

        # Change password section
        sec2 = self._settings_section(scroll, "Change Base Password", "🔄")
        ctk.CTkLabel(sec2,
                     text="Dynamic password = base_password + HHMM (24 h or 12 h format)",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(
            anchor="w", pady=(0, 8))

        cp_grid = ctk.CTkFrame(sec2, fg_color="transparent")
        cp_grid.pack(fill="x")

        ctk.CTkLabel(cp_grid, text="Current Password:",
                     font=FONT_BODY, width=180).grid(
            row=0, column=0, sticky="w", pady=4)
        self._auth_cur_pass = ctk.CTkEntry(
            cp_grid, show="•", width=220, height=32)
        self._auth_cur_pass.grid(row=0, column=1, padx=8, pady=4, sticky="w")

        ctk.CTkLabel(cp_grid, text="New Password:",
                     font=FONT_BODY, width=180).grid(
            row=1, column=0, sticky="w", pady=4)
        self._auth_new_pass = ctk.CTkEntry(
            cp_grid, show="•", width=220, height=32)
        self._auth_new_pass.grid(row=1, column=1, padx=8, pady=4, sticky="w")

        ctk.CTkLabel(cp_grid, text="Confirm New Password:",
                     font=FONT_BODY, width=180).grid(
            row=2, column=0, sticky="w", pady=4)
        self._auth_conf_pass = ctk.CTkEntry(
            cp_grid, show="•", width=220, height=32)
        self._auth_conf_pass.grid(row=2, column=1, padx=8, pady=4, sticky="w")

        self._auth_pass_status = ctk.CTkLabel(
            sec2, text="", font=FONT_SMALL, text_color=COLOR_TEXT_DIM)
        self._auth_pass_status.pack(anchor="w", pady=(4, 0))

        ctk.CTkButton(
            sec2, text="🔄 Change Password", height=34,
            fg_color=COLOR_WARNING, hover_color="#b45309",
            text_color="black",
            command=self._settings_change_password,
        ).pack(anchor="w", pady=(8, 0))

    def _settings_change_password(self):
        cur  = self._auth_cur_pass.get()
        new  = self._auth_new_pass.get()
        conf = self._auth_conf_pass.get()
        if new != conf:
            self._auth_pass_status.configure(
                text="❌ New passwords do not match.", text_color=COLOR_DANGER)
            return
        result = self.auth_manager.change_pin(cur, new)
        if result["success"]:
            self._auth_pass_status.configure(
                text="✅ " + result["message"], text_color=COLOR_SUCCESS)
            self._auth_cur_pass.delete(0, "end")
            self._auth_new_pass.delete(0, "end")
            self._auth_conf_pass.delete(0, "end")
        else:
            self._auth_pass_status.configure(
                text="❌ " + result["message"], text_color=COLOR_DANGER)

    # -- 6. Logging tab ---------------------------------------------------
    def _build_settings_logging_tab(self, tab, cfg: dict):
        scroll = ctk.CTkScrollableFrame(tab, fg_color="transparent",
                                        scrollbar_button_color="#334155")
        scroll.pack(fill="both", expand=True)

        log_cfg = cfg.get("logging", {})
        sec = self._settings_section(scroll, "Log Level & Volume", "📋")

        row = self._settings_row(sec, "Log Level",
                                 "Verbosity of entries written to log")
        self._log_level_var = ctk.StringVar(
            value=log_cfg.get("log_level", "INFO"))
        ctk.CTkOptionMenu(
            row, variable=self._log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            width=150, height=32,
        ).pack(side="left")

        row = self._settings_row(sec, "Max Log Rows (before rotation)",
                                 "Old rows are dropped when limit is reached")
        self._log_max_var = ctk.IntVar(
            value=log_cfg.get("max_log_lines", 1000))
        ctk.CTkSlider(
            row, from_=100, to=5000, number_of_steps=49,
            variable=self._log_max_var, width=160,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, textvariable=self._log_max_var,
                     font=FONT_BODY, text_color=COLOR_ACCENT,
                     width=48).pack(side="left")

        sec2 = self._settings_section(scroll, "Export Options", "📤")

        row = self._settings_row(sec2, "Auto-Export on Exit",
                                 "Automatically save logs when app closes")
        self._log_auto_export_var = ctk.BooleanVar(
            value=log_cfg.get("auto_export", False))
        ctk.CTkSwitch(row, text="", variable=self._log_auto_export_var,
                      onvalue=True, offvalue=False,
                      progress_color=COLOR_ACCENT).pack(side="left")

        row = self._settings_row(sec2, "Export Format",
                                 "File format for exported logs")
        self._log_format_var = ctk.StringVar(
            value=log_cfg.get("export_format", "CSV"))
        ctk.CTkOptionMenu(
            row, variable=self._log_format_var,
            values=["CSV", "JSON"],
            width=120, height=32,
        ).pack(side="left")

        # Export now button
        export_now_btn = ctk.CTkButton(
            sec2, text="📤 Export Logs Now", height=34,
            fg_color="#0f766e", hover_color="#0d5c57",
            command=self._settings_export_logs_now,
        )
        export_now_btn.pack(anchor="w", pady=(10, 0))

        # Scan section
        sec3 = self._settings_section(scroll, "Scan Defaults", "⚡")

        row = self._settings_row(sec3, "Default Operation Timeout (s)",
                                 "Used for port scanning and network probes")
        self._scan_timeout_var = ctk.IntVar(
            value=cfg.get("scan", {}).get("default_timeout", 5))
        ctk.CTkSlider(
            row, from_=1, to=60, number_of_steps=59,
            variable=self._scan_timeout_var, width=160,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, textvariable=self._scan_timeout_var,
                     font=FONT_BODY, text_color=COLOR_ACCENT,
                     width=30).pack(side="left")

        # Compatibility alias expected by older callers
        self.default_timeout_entry = self._scan_timeout_var

    def _settings_export_logs_now(self):
        """Export CSV logs to a user-chosen path."""
        fmt = self._log_format_var.get() if hasattr(self, "_log_format_var") else "CSV"
        ext = ".json" if fmt == "JSON" else ".csv"
        dest = filedialog.asksaveasfilename(
            title="Export Security Logs",
            defaultextension=ext,
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"),
                       ("All files", "*.*")],
        )
        if not dest:
            return
        try:
            logs = log_storage.get_all_logs()
            if fmt == "JSON":
                import json
                with open(dest, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=2)
            else:
                logs_for_csv = log_storage.get_logs_for_report()
                with open(dest, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Date", "Time", "Module",
                                     "Event Description", "Risk Level"])
                    writer.writerows(logs_for_csv)
            self.status_var.set(f"Logs exported → {os.path.basename(dest)}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    # ── Apply / Reset ──────────────────────────────────────────────────────

    def _settings_apply_and_save(self):
        """Collect UI state, apply live changes, and persist to JSON."""
        from modules import settings_manager  # type: ignore

        # Guard: tab-view may not exist yet (shouldn't happen, but safe)
        if not hasattr(self, "_ui_appearance_var"):
            messagebox.showerror("Settings", "Settings not initialised yet.")
            return

        new_cfg: dict = {
            "ui": {
                "appearance_mode":  self._ui_appearance_var.get(),
                "color_theme":      self._ui_color_theme_var.get(),
                "font_size":        self._ui_font_size_var.get(),
                "font_family":      self._ui_font_family_var.get(),
            },
            "security": {
                "intrusion_capture_enabled": self._sec_capture_var.get(),
                "tamper_detection_enabled":  self._sec_tamper_var.get(),
                "auth_enabled":              self._sec_auth_var.get(),
                "lockout_enabled":           self._sec_lockout_var.get(),
            },
            "camera": {
                "max_captures":       self._cam_max_var.get(),
                "cooldown_seconds":   self._cam_cooldown_var.get(),
                "honeypot_camera":    self._cam_honeypot_var.get(),
                "protected_camera":   self._cam_protected_var.get(),
            },
            "auth": {
                "dynamic_password_hint": self._auth_hint_var.get(),
                "otp_enabled":           self._auth_otp_var.get(),
            },
            "logging": {
                "log_level":      self._log_level_var.get(),
                "max_log_lines":  self._log_max_var.get(),
                "auto_export":    self._log_auto_export_var.get(),
                "export_format":  self._log_format_var.get(),
            },
            "scan": {
                "default_timeout": self._scan_timeout_var.get(),
            },
        }

        # ── Apply live changes that take effect without restart ────────
        # 1. Appearance mode (works immediately in customtkinter)
        mode = new_cfg["ui"]["appearance_mode"]
        ctk.set_appearance_mode(mode)

        # 2. Camera settings → propagate to running monitors
        try:
            self.honeypot_monitor.set_camera_enabled(
                new_cfg["camera"]["honeypot_camera"])
            self.pf_monitor.set_camera_enabled(
                new_cfg["camera"]["protected_camera"])
        except Exception:
            pass

        # 3. Persist to disk
        if settings_manager.save(new_cfg):
            self.status_var.set("✅ Settings saved successfully.")
            messagebox.showinfo(
                "Settings Applied",
                "Settings saved.\n\n"
                "Note: Color accent theme and font changes "
                "require an application restart to take full effect.",
            )
        else:
            messagebox.showerror("Settings Error",
                                 "Failed to write settings file.")

    def _settings_reset_defaults(self):
        """Reset all settings to built-in defaults."""
        from modules import settings_manager  # type: ignore
        if not messagebox.askyesno(
                "Reset to Defaults",
                "This will reset ALL settings to their built-in defaults.\n\n"
                "Continue?"):
            return
        settings_manager.reset_to_defaults()
        # Rebuild the tab so widgets reflect new values
        for w in self.settings_tab.winfo_children():
            w.destroy()
        self.setup_settings_tab()
        self.status_var.set("Settings reset to defaults.")

    # ══════════════════════════════════════════════════════════════════════
    #  NETWORK DEVICE DISCOVERY TAB
    # ══════════════════════════════════════════════════════════════════════
    def setup_network_tab(self):
        """Build the Network Device Discovery panel."""
        _page = self.network_tab
        ctk.CTkLabel(_page, text="🌐 Network Device Discovery",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Scan your local network to identify connected devices",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Header card ───────────────────────────────────────────────────
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="🌐 Network Scanner",
                     font=FONT_HEADING).pack(anchor="w")
        ctk.CTkLabel(header_frame,
                     text="ARP sweep + ping probe to discover devices on your LAN",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(
            anchor="w", pady=(0, 4))

        # ── Network info cards row ────────────────────────────────────────
        info_row = ctk.CTkFrame(frame, fg_color="transparent")
        info_row.pack(fill="x", padx=10, pady=6)

        # Get live network info for display
        try:
            _net = network_discovery._get_local_network_info()
        except Exception:
            _net = {"self_ip": "N/A", "gateway": "N/A", "subnet": "N/A"}

        for idx, (lbl, val, icon) in enumerate([
            ("Your IP", _net.get("self_ip", "N/A"), "💻"),
            ("Gateway", _net.get("gateway", "N/A"), "🌐"),
            ("Subnet",  _net.get("subnet", "N/A"),  "📡"),
        ]):
            card = ctk.CTkFrame(info_row, fg_color=COLOR_CARD, corner_radius=10)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ctk.CTkLabel(card, text=f"  {icon}  {lbl}",
                         font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(
                anchor="w", padx=10, pady=(8, 0))
            ctk.CTkLabel(card, text=f"  {val}",
                         font=(FONT_HEADING[0], FONT_HEADING[1]),
                         text_color="white").pack(anchor="w", padx=10, pady=(0, 8))

        # ── Configuration inputs ──────────────────────────────────────────
        input_frame = ctk.CTkFrame(frame)
        input_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(input_frame,
                     text="Subnet (CIDR, auto-detected):").grid(
            row=0, column=0, sticky="w", pady=5, padx=8)
        self.net_subnet_entry = ctk.CTkEntry(input_frame, width=200,
            placeholder_text="e.g. 192.168.1.0/24")
        self.net_subnet_entry.grid(row=0, column=1, pady=5, padx=5)
        if _net.get("subnet"):
            self.net_subnet_entry.insert(0, _net["subnet"])
        ToolTip(self.net_subnet_entry,
                "Leave blank for auto-detection, or specify a custom CIDR subnet")

        ctk.CTkLabel(input_frame,
                     text="Ping Timeout (ms):").grid(
            row=1, column=0, sticky="w", pady=5, padx=8)
        self.net_timeout_entry = ctk.CTkEntry(input_frame, width=80)
        self.net_timeout_entry.insert(0, "500")
        self.net_timeout_entry.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        ToolTip(self.net_timeout_entry,
                "Timeout for each ping probe in milliseconds")

        ctk.CTkLabel(input_frame,
                     text="Max Parallel Probes:").grid(
            row=2, column=0, sticky="w", pady=5, padx=8)
        self.net_workers_entry = ctk.CTkEntry(input_frame, width=80)
        self.net_workers_entry.insert(0, "64")
        self.net_workers_entry.grid(row=2, column=1, sticky="w", pady=5, padx=5)
        ToolTip(self.net_workers_entry,
                "Number of simultaneous ping probes (higher = faster, more load)")

        # ── Buttons ───────────────────────────────────────────────────────
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(pady=10)
        self.net_scan_button = ctk.CTkButton(
            button_frame, text="🚀 Discover Devices",
            command=self.start_network_scan, height=42,
            font=("Segoe UI", 13, "bold"))
        self.net_scan_button.pack(side="left", padx=5)
        ToolTip(self.net_scan_button,
                "Start scanning the local network for connected devices")

        # ── Live stats row ────────────────────────────────────────────────
        stats_row = ctk.CTkFrame(frame, fg_color="transparent")
        stats_row.pack(fill="x", padx=10, pady=4)

        for lbl_text, attr_name, color in [
            ("Devices Found:", "net_device_count_lbl", COLOR_ACCENT),
            ("Known:", "net_known_lbl", COLOR_SUCCESS),
            ("Unknown:", "net_unknown_lbl", COLOR_DANGER),
            ("Method:", "net_method_lbl", COLOR_ACCENT2),
        ]:
            ctk.CTkLabel(stats_row, text=lbl_text,
                         font=FONT_SMALL).pack(side="left", padx=(8, 2))
            lbl = ctk.CTkLabel(stats_row, text="—",
                               font=FONT_SMALL, text_color=color)
            lbl.pack(side="left", padx=(0, 12))
            setattr(self, attr_name, lbl)

        # ── Results console ───────────────────────────────────────────────
        self.net_result_box = ctk.CTkTextbox(
            frame, font=("Consolas", 12), wrap="none",
            fg_color="#060d18", text_color="#e2e8f0",
            border_width=1, border_color="#334155",
            height=400)
        self.net_result_box.pack(padx=10, pady=8, fill="both", expand=True)
        # Colour tags
        self.net_result_box.tag_config("red",    foreground="#f87171")
        self.net_result_box.tag_config("green",  foreground="#4ade80")
        self.net_result_box.tag_config("orange", foreground="#fbbf24")
        self.net_result_box.tag_config("cyan",   foreground="#38bdf8")
        self.net_result_box.tag_config("dim",    foreground="#64748b")
        self.net_result_box.tag_config("bold_green", foreground="#22c55e")
        self.net_result_box.tag_config("bold_red",   foreground="#ef4444")

        # Initial message
        self.net_result_box.insert("end",
            "  Ready to scan. Press  🚀 Discover Devices  to begin.\n", "dim")
        self.net_result_box.configure(state="disabled")

    def start_network_scan(self):
        """Launch the network discovery scan in a background thread."""
        # Read user inputs
        subnet = self.net_subnet_entry.get().strip() or None
        try:
            timeout_ms = int(self.net_timeout_entry.get().strip() or "500")
        except ValueError:
            timeout_ms = 500
        try:
            max_workers = int(self.net_workers_entry.get().strip() or "64")
        except ValueError:
            max_workers = 64

        # Prepare the console
        self.net_result_box.configure(state="normal")
        self.net_result_box.delete("1.0", "end")
        self.net_result_box.insert("end",
            "  🌐 Network Device Discovery\n", "cyan")
        self.net_result_box.insert("end",
            f"  {'═'*72}\n\n", "dim")
        self.net_result_box.insert("end",
            f"  Scanning subnet: {subnet or 'auto-detect'}\n", "dim")
        self.net_result_box.insert("end",
            f"  Ping timeout: {timeout_ms} ms  |  Threads: {max_workers}\n", "dim")
        self.net_result_box.insert("end",
            "  Sending probes... please wait.\n\n", "dim")
        self.net_result_box.see("end")

        self.net_scan_button.configure(state="disabled")
        self.status_var.set("Scanning network...")
        self.progress.set(0)

        def _progress(current, total):
            """Update progress bar from any thread."""
            try:
                frac = current / total if total else 0
                self.progress.set(frac)
                self.root.update_idletasks()
            except Exception:
                pass

        def _run():
            import modules.network_discovery as network_discovery  # type: ignore
            result = network_discovery.discover_devices(
                subnet=subnet,
                ping_timeout_ms=timeout_ms,
                max_workers=max_workers,
                progress_callback=_progress,
            )

            box = self.net_result_box
            box.configure(state="normal")

            if result.get("status") == "error":
                box.insert("end", f"  ❌ ERROR: {result.get('error')}\n", "red")
                box.see("end")
                box.configure(state="disabled")
                self.net_scan_button.configure(state="normal")
                self.status_var.set("Network scan failed")
                self.progress.set(0)
                return

            devices = result.get("devices", [])
            summary = result.get("summary", {})
            scan_time = result.get("scan_time", 0)
            method = result.get("scan_method", "N/A")
            net_info = result.get("network", {})

            # ── Network info header ───────────────────────────────────────
            box.insert("end", "  NETWORK INFORMATION\n", "cyan")
            box.insert("end", f"  {'─'*90}\n", "dim")
            box.insert("end",
                f"  Your IP    : {net_info.get('self_ip', 'N/A')}\n")
            box.insert("end",
                f"  Gateway    : {net_info.get('gateway', 'N/A')}\n")
            box.insert("end",
                f"  Subnet     : {net_info.get('subnet', 'N/A')}\n")
            box.insert("end",
                f"  Scan method: {method}\n")
            scapy_tag = "green" if summary.get("scapy_available") else "orange"
            box.insert("end",
                f"  Scapy      : {'Available ✓' if summary.get('scapy_available') else 'Not installed (using ping fallback)'}\n",
                scapy_tag)
            box.insert("end", "\n")

            # ── Device table (with Device Type + Risk columns) ────────────
            box.insert("end", "  DISCOVERED DEVICES\n", "cyan")
            box.insert("end", f"  {'─'*90}\n", "dim")
            box.insert("end",
                f"  {'#':<4} {'IP ADDRESS':<17} {'MAC ADDRESS':<20} "
                f"{'VENDOR':<18} {'DEVICE TYPE':<18} {'RISK':<6} "
                f"{'STATUS':<10} HOSTNAME\n", "cyan")
            box.insert("end", f"  {'─'*90}\n", "dim")

            # Device-type icons for visual clarity
            _type_icons = {
                "Mobile Hotspot / Router": "🌐", "Router/AP": "📡",
                "Access Point": "📡", "This Computer": "💻",
                "Laptop/Desktop": "🖥️", "Mobile/Laptop": "📱",
                "Mobile Device": "📱", "Smart Device": "🏠",
                "IoT Device": "🔌", "IoT / SBC": "🔌",
                "Gaming Console": "🎮", "Smart TV": "📺",
                "Printer": "🖨️", "NAS/Server": "🗄️",
                "IP Camera": "📷", "Virtual Machine": "☁️",
                "Virtual/Container": "☁️", "Network Device": "🔗",
            }

            unknown_count = 0
            high_risk_count = 0
            for i, dev in enumerate(devices, 1):
                status = dev.get("status", "Unknown")
                ip = dev.get("ip", "N/A")
                mac = dev.get("mac", "N/A")
                vendor = dev.get("vendor", "Unknown")
                hostname = dev.get("hostname", "N/A")
                device_type = dev.get("device_type", "Unknown")
                risk_level = dev.get("risk_level", "Low")

                # Risk indicator symbol
                if risk_level == "High":
                    risk_icon = "🔴"
                    high_risk_count += 1 # type: ignore
                elif risk_level == "Medium":
                    risk_icon = "🟡"
                else:
                    risk_icon = "🟢"

                # Choose row colour tag based on risk + status
                if status == "Router":
                    tag = "cyan"
                elif status == "Self":
                    tag = "bold_green"
                elif risk_level == "High":
                    tag = "bold_red"
                    unknown_count += 1 # type: ignore
                elif risk_level == "Medium":
                    tag = "orange"
                elif status == "Known":
                    tag = "green"
                else:
                    tag = "green"

                # Type icon
                type_icon = _type_icons.get(device_type, "❓")

                line = (
                    f"  {type_icon} {i:<3} {ip:<17} {mac:<20} "
                    f"{vendor:<18} {device_type:<18} {risk_icon:<5} "
                    f"[{status:<8}] {hostname}\n"
                )
                box.insert("end", line, tag)
                if risk_level == "High":
                    if device_type == "⚠ Potential Intruder (New)":
                        self._print_threat("new_intruder", mac, lambda m, t="": box.insert("end", m, t))
                    elif status == "Unknown":
                        self._print_threat("unknown_device", mac, lambda m, t="": box.insert("end", m, t))

            box.insert("end", f"\n  {'─'*90}\n", "dim")

            # ── Device type distribution ──────────────────────────────────
            type_counts = summary.get("device_types", {})
            if type_counts:
                box.insert("end", "\n  DEVICE TYPE DISTRIBUTION\n", "cyan")
                box.insert("end", f"  {'─'*90}\n", "dim")
                for dtype, count in sorted(type_counts.items(),
                                           key=lambda x: -x[1]):
                    dtype_icon = _type_icons.get(dtype, "❓")
                    bar_len = min(count * 3, 30)
                    bar = "█" * bar_len
                    box.insert("end",
                        f"  {dtype_icon} {dtype:<22} {count:>3}  ", "dim")
                    # Colour the bar based on device type risk
                    bar_tag = "bold_red" if "Unknown" in dtype else "cyan"
                    box.insert("end", f"{bar}\n", bar_tag)

            # ── Summary footer ────────────────────────────────────────────
            box.insert("end", f"\n  {'─'*90}\n", "dim")
            box.insert("end", "\n  SCAN SUMMARY\n", "cyan")
            box.insert("end", f"  {'─'*90}\n", "dim")
            box.insert("end",
                f"  Total devices : {summary.get('device_count', 0)}\n")
            box.insert("end",
                f"  Known         : {summary.get('known', 0)}\n", "green")
            box.insert("end",
                f"  Unknown       : {summary.get('unknown', 0)}\n",
                "bold_red" if summary.get('unknown', 0) > 0 else "green")
            box.insert("end",
                f"  High risk     : {summary.get('high_risk', 0)}\n",
                "bold_red" if summary.get('high_risk', 0) > 0 else "green")
            box.insert("end",
                f"  Medium risk   : {summary.get('medium_risk', 0)}\n",
                "orange" if summary.get('medium_risk', 0) > 0 else "green")
            if summary.get("vendors"):
                box.insert("end",
                    f"  Vendors       : {', '.join(summary['vendors'])}\n", "dim")
            box.insert("end",
                f"  Scan time     : {scan_time}s\n", "dim")

            # Unknown device warning
            if unknown_count > 0 or high_risk_count > 0:
                box.insert("end",
                    f"\n  🔴 {unknown_count} HIGH-RISK / UNIDENTIFIED device(s) "
                    "detected on your network!\n", "bold_red")
                box.insert("end",
                    "  These could be unauthorized or rogue devices. "
                    "Verify their MAC addresses and investigate.\n", "orange")
                box.insert("end",
                    "  Recommended: Check your router's connected device "
                    "list and block any unrecognized entries.\n", "dim")

            # Network isolation / Hotspot warning
            if summary.get("device_count", 0) <= 2:
                box.insert("end",
                    f"\n  ℹ️ Note: Only {summary.get('device_count', 0)} "
                    "device(s) discovered.\n", "cyan")
                box.insert("end",
                    "  Some devices may not be visible due to network "
                    "isolation, AP isolation (common on public WiFi and "
                    "mobile hotspots), or strict client firewalls.\n", "dim")

            box.insert("end", f"\n  {'═'*90}\n", "dim")
            box.insert("end",
                "  Scan complete.\n", "dim")
            box.see("end")
            box.configure(state="disabled")

            # ── Update stats labels ───────────────────────────────────────
            self.net_device_count_lbl.configure(
                text=str(summary.get("device_count", 0)))
            self.net_known_lbl.configure(
                text=str(summary.get("known", 0)))
            self.net_unknown_lbl.configure(
                text=str(summary.get("unknown", 0)))
            self.net_method_lbl.configure(text=method)

            # ── Log events + trigger alerts ───────────────────────────────
            risk = "High" if high_risk_count > 2 else (
                "Medium" if high_risk_count > 0 else "Low")
            log_storage.log_event(
                "Network",
                f"Discovered {summary.get('device_count', 0)} devices "
                f"({summary.get('known', 0)} known, "
                f"{summary.get('unknown', 0)} unknown, "
                f"{summary.get('high_risk', 0)} high-risk)",
                risk)
            self.alert_manager.trigger(
                "Network",
                f"Network scan: {summary.get('device_count', 0)} devices, "
                f"{high_risk_count} high-risk, "
                f"{summary.get('unknown', 0)} unknown",
                risk)

            # Log individual high-risk devices
            for dev in devices:
                if dev.get("risk_level") == "High":
                    log_storage.log_event(
                        "Network",
                        f"⚠ Unidentified device: {dev['ip']} "
                        f"(MAC: {dev['mac']}, Type: {dev['device_type']})",
                        "High")

            # Store results for report generation
            self.scan_results["network_discovery"] = result

            self.net_scan_button.configure(state="normal")
            self.status_var.set("Network scan complete")
            self.progress.set(1.0)
            self.root.after(0, self.update_security_score)

            # Fire alerts for intruders
            intruders = summary.get("new_intruders", [])
            for intr in intruders:
                mac_lbl = intr.get("mac", "Unknown MAC")
                ip_lbl = intr.get("ip", "Unknown IP")
                self.root.after(0, lambda m=mac_lbl, i=ip_lbl: self.alert_manager.trigger(
                    "Network Intruder Detected",
                    f"New unknown device joined the network.\nMAC: {m}\nIP: {i}",
                    "High"
                ))

        threading.Thread(target=_run, daemon=True).start()


    # ══════════════════════════════════════════════════════════════════════
    #  STARTUP ANALYZER TAB
    # ══════════════════════════════════════════════════════════════════════
    def setup_startup_tab(self):
        """Builds the UI for the Startup Analyzer module."""
        frame = self.startup_tab

        # Header
        hdr = ctk.CTkFrame(frame, fg_color="transparent")
        hdr.pack(fill="x", padx=28, pady=(28, 12))
        ctk.CTkLabel(hdr, text="Startup Analyzer", font=FONT_TITLE,
                     text_color="white").pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Detect and analyze programs configured to run automatically at system boot.",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Controls & Live Stats row
        ctrl_bar = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=8)
        ctrl_bar.pack(fill="x", padx=28, pady=(0, 16))

        # Button
        self.startup_scan_btn = ctk.CTkButton(
            ctrl_bar, text="Scan Startup Programs  🚀", font=FONT_HEADING,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self.start_startup_scan, width=200, height=40
        )
        self.startup_scan_btn.pack(side="left", padx=16, pady=16)

        # Stats
        stats_frame = ctk.CTkFrame(ctrl_bar, fg_color="transparent")
        stats_frame.pack(side="right", padx=16)

        def make_stat(parent, label_text):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(side="left", padx=12)
            ctk.CTkLabel(f, text=label_text, font=("Segoe UI", 11),
                         text_color=COLOR_TEXT_DIM).pack()
            val_lbl = ctk.CTkLabel(f, text="--", font=("Segoe UI", 18, "bold"))
            val_lbl.pack()
            return val_lbl

        self.startup_total_lbl = make_stat(stats_frame, "Total Entries")
        self.startup_high_lbl = make_stat(stats_frame, "High Risk")
        self.startup_med_lbl = make_stat(stats_frame, "Medium Risk")
        
        self.startup_high_lbl.configure(text_color=COLOR_DANGER)
        self.startup_med_lbl.configure(text_color=COLOR_WARNING)

        # Results Console
        res_frame = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=8)
        res_frame.pack(fill="both", expand=True, padx=28, pady=(0, 28))

        ctk.CTkLabel(res_frame, text="ANALYSIS REPORT",
                     font=("Segoe UI", 11, "bold"), text_color=COLOR_TEXT_DIM)\
            .pack(anchor="w", padx=16, pady=(12, 0))

        self.startup_result_box = ctk.CTkTextbox(
            res_frame, font=FONT_MONO, fg_color="#0b1221", text_color="#e2e8f0",
            wrap="none"
        )
        self.startup_result_box.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        # Setup text tags
        box = self.startup_result_box
        box.tag_config("cyan", foreground="#22d3ee")
        box.tag_config("green", foreground="#4ade80")
        box.tag_config("bold_green", foreground="#22c55e")
        box.tag_config("orange", foreground="#fbbf24")
        box.tag_config("bold_red", foreground="#ef4444")
        box.tag_config("dim", foreground="#64748b")
        
        box.insert("end", "  Ready to analyze system startup paths.\n", "dim")
        box.insert("end", "  Click 'Scan Startup Programs' to begin.\n", "dim")
        box.configure(state="disabled")

    def start_startup_scan(self):
        """Initiates the startup scan in a background thread."""
        self.startup_scan_btn.configure(state="disabled")
        self.status_var.set("Scanning startup entries...")
        self.progress.set(0.2)

        box = self.startup_result_box
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", "  [INIT] Gathering startup entries...\n", "dim")
        box.configure(state="disabled")

        def _run():
            import modules.startup_analyzer as startup_analyzer  # type: ignore
            self.progress.set(0.5)
            result = startup_analyzer.scan_startup_programs()
            
            self.root.after(0, self._render_startup_results, result)

        threading.Thread(target=_run, daemon=True).start()

    def _render_startup_results(self, result: dict):
        """Prepares and displays startup entries with risk classification."""
        box = self.startup_result_box
        box.configure(state="normal")
        box.delete("1.0", "end")

        if result.get("status") == "error":
            box.insert("end", f"  ❌ ERROR: {result.get('error')}\n", "bold_red")
            box.configure(state="disabled")
            self.startup_scan_btn.configure(state="normal")
            self.status_var.set("Startup scan failed")
            self.progress.set(0)
            return

        entries = result.get("entries", [])
        summary = result.get("summary", {})

        box.insert("end", "  STARTUP ENTRIES DISCOVERED\n", "cyan")
        box.insert("end", f"  {'─'*110}\n", "dim")
        box.insert("end",
            f"  {'#':<4} {'NAME':<20} {'PUBLISHER':<25} {'RISK':<6} {'STATUS':<9} {'PATH/SOURCE'}\n", "cyan")
        box.insert("end", f"  {'─'*110}\n", "dim")

        for i, ent in enumerate(entries, 1):
            name = (ent['name'][:17] + '...') if len(ent['name']) > 20 else ent['name']
            publisher = (ent['publisher'][:22] + '...') if len(ent['publisher']) > 25 else ent['publisher']
            risk = ent['risk_level']
            status = ent['status']
            path = ent['path']
            
            # Formatting
            if risk == "High":
                risk_icon = "🔴"
                tag = "bold_red"
            elif risk == "Medium":
                risk_icon = "🟡"
                tag = "orange"
            else:
                risk_icon = "🟢"
                tag = "green"
                
            box.insert("end", 
                f"  {i:<4} {name:<20} {publisher:<25} {risk_icon:<6} {status:<9} ", "dim")
            box.insert("end", f"{path}\n", tag)
            
            # Print reason if not Low
            if risk in ("High", "Medium"):
                box.insert("end", f"       └─ ⚠ {ent['risk_reason']}\n", tag)
                
            # Print source dim
            box.insert("end", f"       └─ Source: {ent['source']}\n", "dim")

        box.insert("end", f"\n  {'─'*110}\n", "dim")
        box.insert("end", "\n  SCAN SUMMARY\n", "cyan")
        box.insert("end", f"  {'─'*110}\n", "dim")
        box.insert("end", f"  Total Entries : {summary.get('total', 0)}\n")
        box.insert("end", f"  Low Risk      : {summary.get('low_risk', 0)}\n", "green")
        
        med_tag = "orange" if summary.get('medium_risk', 0) > 0 else "green"
        box.insert("end", f"  Medium Risk   : {summary.get('medium_risk', 0)}\n", med_tag)
        
        high_tag = "bold_red" if summary.get('high_risk', 0) > 0 else "green"
        box.insert("end", f"  High Risk     : {summary.get('high_risk', 0)}\n", high_tag)
        
        if summary.get('high_risk', 0) > 0:
            box.insert("end", "\n  🔴 HIGH RISK DETECTED: Review suspicious entries above.\n", "bold_red")

        box.insert("end", f"\n  {'═'*110}\n", "dim")
        box.insert("end", "  Scan complete.\n", "dim")
        box.see("end")
        box.configure(state="disabled")

        # Update stats
        self.startup_total_lbl.configure(text=str(summary.get("total", 0)))
        self.startup_high_lbl.configure(text=str(summary.get("high_risk", 0)))
        self.startup_med_lbl.configure(text=str(summary.get("medium_risk", 0)))

        # ── Log events + trigger alerts ───────────────────────────────
        high_risk_count = summary.get('high_risk', 0)
        risk_overall = "High" if high_risk_count > 0 else ("Medium" if summary.get('medium_risk', 0) > 0 else "Low")
        
        log_storage.log_event(
            "Startup",
            f"Scanned {summary.get('total', 0)} startups. "
            f"Found {high_risk_count} high-risk, {summary.get('medium_risk', 0)} medium-risk.",
            risk_overall)
            
        if risk_overall in ("High", "Medium"):
            self.alert_manager.trigger(
                "Startup Integrity",
                f"Startup Scan: Found {high_risk_count} high-risk entries and {summary.get('medium_risk', 0)} medium-risk entries.",
                risk_overall)

        # Store for report
        self.scan_results["startup_analyzer"] = result

        self.startup_scan_btn.configure(state="normal")
        self.status_var.set("Startup scan complete")
        self.progress.set(1.0)



    # ══════════════════════════════════════════════════════════════════════
    #  THREAT ALERTS TAB
    # ══════════════════════════════════════════════════════════════════════
    def setup_alerts_tab(self):
        """Build the Threat Alerts history panel."""
        _page = self.alerts_tab
        ctk.CTkLabel(_page, text="🔔 Threat Alerts",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Real-time threat notifications and alert history",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # Header card
        header_frame = ctk.CTkFrame(frame)
        header_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(header_frame, text="🔔 Smart Threat Alert Console",
                     font=FONT_HEADING).pack(anchor="w")
        ctk.CTkLabel(header_frame,
                     text="All security alerts from scans, monitors and heuristic engines",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(anchor="w", pady=(0, 4))

        # Stats row
        stats_frame = ctk.CTkFrame(frame)
        stats_frame.pack(pady=4, padx=10, fill="x")
        ctk.CTkLabel(stats_frame, text="Total Alerts:",
                     font=FONT_SMALL).pack(side="left", padx=5)
        self._alert_total_lbl = ctk.CTkLabel(
            stats_frame, text="0", font=FONT_SMALL,
            text_color=COLOR_ACCENT2)
        self._alert_total_lbl.pack(side="left", padx=(0, 20))

        ctk.CTkLabel(stats_frame, text="Recent (60 s):",
                     font=FONT_SMALL).pack(side="left", padx=5)
        self._alert_recent_lbl = ctk.CTkLabel(
            stats_frame, text="0", font=FONT_SMALL,
            text_color=COLOR_WARNING)
        self._alert_recent_lbl.pack(side="left")

        # History console (built by the alert manager)
        self.alert_manager.build_history_widget(frame)

        # Buttons
        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(pady=8)
        refresh_btn = ctk.CTkButton(
            btn_frame, text="🔄 Refresh", height=38,
            command=self._refresh_alerts_panel)
        refresh_btn.pack(side="left", padx=5)
        ToolTip(refresh_btn, "Reload the alert history list")

        test_btn = ctk.CTkButton(
            btn_frame, text="🧪 Test Alert", height=38,
            fg_color="#475569", hover_color=COLOR_NAV_HOVER,
            command=lambda: self.alert_manager.trigger(
                "System", "This is a test alert to verify notifications.", "Medium"))
        test_btn.pack(side="left", padx=5)
        ToolTip(test_btn, "Fire a test alert to preview the notification popup")

    def _refresh_alerts_panel(self):
        """Update the alerts history console and stat labels."""
        self.alert_manager.refresh_history_widget()
        total = len(self.alert_manager.history)
        recent = self.alert_manager.unread_count
        if hasattr(self, "_alert_total_lbl"):
            self._alert_total_lbl.configure(text=str(total))
        if hasattr(self, "_alert_recent_lbl"):
            self._alert_recent_lbl.configure(text=str(recent))

    def _update_alert_badge(self):
        """Callback fired by alert_manager after each new alert."""
        count = self.alert_manager.unread_count
        if count > 0:
            self._alert_badge.configure(text=str(count))
            self._alert_badge.pack(side="left", padx=(0, 6))
        else:
            self._alert_badge.pack_forget()
        # Also refresh the alerts panel stats if it's visible
        self._refresh_alerts_panel()

    # ══════════════════════════════════════════════════════════════════════
    #  AUTHENTICATION & SELF-PROTECTION
    # ══════════════════════════════════════════════════════════════════════

    def _show_login_dialog(self):
        """Show dynamic time-based Admin-Only Authentication dialog on startup.
        After 3 consecutive failed attempts, activates Decoy Mode instead of
        locking out — the intruder is silently redirected to a fake interface."""
        self._decoy_failed_streak = 0  # reset streak for each dialog open

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Admin Authentication Required")
        dialog.geometry("420x380")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(fg_color="#0f172a")

        # Center on screen
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - 210
        y = (dialog.winfo_screenheight() // 2) - 190
        dialog.geometry(f"+{x}+{y}")

        # Header
        ctk.CTkLabel(dialog, text="🔒", font=("Segoe UI", 48)).pack(pady=(24, 4))
        ctk.CTkLabel(dialog, text="Restricted Access", font=FONT_HEADING, text_color="white").pack()
        ctk.CTkLabel(dialog, text="Please enter your authentication token to proceed.",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(pady=(4, 16))

        # Password Entry
        pass_var = ctk.StringVar()
        pass_entry = ctk.CTkEntry(
            dialog, textvariable=pass_var, show="•",
            width=260, height=40, font=FONT_BODY,
            placeholder_text="Password",
            justify="center",
        )
        pass_entry.pack(pady=4)
        pass_entry.focus_set()

        # Status label
        status_lbl = ctk.CTkLabel(dialog, text="", font=FONT_SMALL, text_color=COLOR_DANGER)
        status_lbl.pack(pady=4)

        # Attempts display
        attempts_lbl = ctk.CTkLabel(
            dialog,
            text=f"Attempts remaining: {self.auth_manager.attempts_remaining}",
            font=FONT_SMALL, text_color=COLOR_TEXT_DIM)
        attempts_lbl.pack()

        def _attempt_login(event=None):
            pwd = pass_var.get().strip()
            if not pwd:
                status_lbl.configure(text="Please enter the password", text_color=COLOR_WARNING)
                return

            result = self.auth_manager.authenticate(pwd)

            if result["success"]:
                # ── Genuine successful login ───────────────────────────
                self._decoy_failed_streak = 0
                status_lbl.configure(text=result["message"], text_color=COLOR_SUCCESS)
                self.status_var.set("Authenticated as ADMIN")
                self.root.after(500, dialog.destroy)
            else:
                # ── Failed attempt — check if we should trigger decoy ─
                self._decoy_failed_streak += 1

                if self._decoy_failed_streak >= decoy_mode.FAILED_THRESHOLD:
                    # ── DECOY ACTIVATION: fake "success" ──────────────
                    status_lbl.configure(
                        text="Access Granted", text_color=COLOR_SUCCESS)
                    pass_entry.configure(state="disabled")
                    login_btn.configure(state="disabled")
                    self.root.after(800, lambda: self._activate_decoy_mode(dialog))
                    return

                # Normal failure UI
                status_lbl.configure(text=result["message"], text_color=COLOR_DANGER)
                attempts_lbl.configure(
                    text=f"Attempts remaining: "
                         f"{max(0, decoy_mode.FAILED_THRESHOLD - self._decoy_failed_streak)}")
                pass_var.set("")
                pass_entry.focus_set()

        login_btn = ctk.CTkButton(
            dialog, text="Login", height=38,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=_attempt_login)
        login_btn.pack(pady=12)

        pass_entry.bind("<Return>", _attempt_login)

        ctk.CTkLabel(dialog, text="Authorized Personnel Only",
                     font=("Segoe UI", 9), text_color="#475569").pack(pady=(8, 0))

        def _on_close():
            if not self.auth_manager.is_authenticated and not self._decoy_active:
                self.root.destroy()

        dialog.protocol("WM_DELETE_WINDOW", _on_close)

    # ══════════════════════════════════════════════════════════════════════
    #  DECOY MODE  —  Fake Interface System
    # ══════════════════════════════════════════════════════════════════════

    def _activate_decoy_mode(self, login_dialog: ctk.CTkToplevel | None = None):
        """Silently switch the entire UI into the decoy (fake) interface."""
        # Activate the backend manager (starts logging + evidence capture)
        self.decoy_manager.activate()
        self._decoy_active = True

        # Close the (real) login dialog
        if login_dialog:
            try:
                login_dialog.destroy()
            except Exception:
                pass

        # Log activation in the real security log too
        try:
            log_storage.log_event(
                "Decoy Mode",
                f"Decoy activated — session {self.decoy_manager.session_id}",
                "High",
            )
        except Exception:
            pass

        # Hide the REAL UI (sidebar, content, header stay but we overlay)
        self._build_decoy_interface()

    def _build_decoy_interface(self):
        """Build a full-screen overlay with a convincing fake dashboard.
        Every button click and navigation action is logged to the
        decoy activity file for forensic review."""
        fake_data = decoy_mode.generate_fake_scan_results()
        fake_logs = decoy_mode.generate_fake_logs(25)
        fake_timeline = decoy_mode.generate_fake_timeline(15)

        # ── Full-window overlay (sits on top of the real UI) ──────────
        overlay = ctk.CTkFrame(self.root, fg_color=COLOR_SIDEBAR, corner_radius=0)
        overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self._decoy_container = overlay

        # ── Header bar ────────────────────────────────────────────────
        hdr = ctk.CTkFrame(overlay, height=64, fg_color=COLOR_HEADER, corner_radius=0)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        brand = ctk.CTkFrame(hdr, fg_color="transparent")
        brand.pack(side="left", padx=20, pady=8)
        ctk.CTkLabel(brand, text="🛡", font=("Segoe UI", 28)).pack(side="left", padx=(0, 8))
        txt = ctk.CTkFrame(brand, fg_color="transparent")
        txt.pack(side="left")
        ctk.CTkLabel(txt, text="Advanced System Security Scanner",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(txt, text="Real-time monitoring & threat analysis",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Right side — clock + status
        right = ctk.CTkFrame(hdr, fg_color="transparent")
        right.pack(side="right", padx=20)
        self._decoy_clock = ctk.CTkLabel(right, text="", font=FONT_BODY,
                                         text_color=COLOR_TEXT_DIM)
        self._decoy_clock.pack(anchor="e")
        ctk.CTkLabel(right, text="● LIVE", font=("Segoe UI", 11, "bold"),
                     text_color=COLOR_SUCCESS).pack(anchor="e")
        self._tick_decoy_clock()

        # ── Body: sidebar + content ───────────────────────────────────
        body = ctk.CTkFrame(overlay, fg_color=COLOR_SIDEBAR, corner_radius=0)
        body.pack(fill="both", expand=True)

        # Sidebar
        sidebar = ctk.CTkFrame(body, width=210, fg_color=COLOR_SIDEBAR, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="NAVIGATION",
                     font=("Segoe UI", 9, "bold"),
                     text_color=COLOR_TEXT_DIM).pack(pady=(14, 4), padx=16, anchor="w")

        nav_scroll = ctk.CTkScrollableFrame(
            sidebar, fg_color=COLOR_SIDEBAR,
            scrollbar_button_color="#334155",
            scrollbar_button_hover_color=COLOR_ACCENT,
        )
        nav_scroll.pack(fill="both", expand=True)

        decoy_nav_items = [
            ("Dashboard",         "🏠",  "dcoy_dash"),
            ("Port Scanner",      "🔍",  "dcoy_ports"),
            ("Network Discovery", "🌐",  "dcoy_net"),
            ("Password Policy",   "🔐",  "dcoy_pass"),
            ("Wi-Fi Info",        "📶",  "dcoy_wifi"),
            ("USB Devices",       "💾",  "dcoy_usb"),
            ("Firewall Scan",     "🛡️",  "dcoy_fw"),
            ("Malware Detection", "🧬",  "dcoy_mal"),
            ("Security Logs",     "📋",  "dcoy_logs"),
            ("Generate Report",   "📄",  "dcoy_rpt"),
            ("Settings",          "⚙️",  "dcoy_set"),
        ]
        self._decoy_nav_btns: dict[str, ctk.CTkButton] = {}
        for label, icon, key in decoy_nav_items:
            btn = ctk.CTkButton(
                nav_scroll,
                text=f"  {icon}  {label}",
                anchor="w", font=FONT_NAV, height=36,
                corner_radius=8, fg_color="transparent",
                hover_color=COLOR_NAV_HOVER, text_color="white",
                command=lambda k=key, l=label: self._decoy_nav(k, l),
            )
            btn.pack(fill="x", padx=8, pady=1)
            self._decoy_nav_btns[key] = btn

        # Version footer
        ctk.CTkFrame(sidebar, height=1, fg_color="#334155").pack(
            fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(sidebar, text="v1.0.0  |  Windows",
                     font=("Segoe UI", 9),
                     text_color=COLOR_TEXT_DIM).pack(padx=16, pady=(0, 8), anchor="w")

        # ── Content area ──────────────────────────────────────────────
        content = ctk.CTkFrame(body, fg_color="#0f1a2e", corner_radius=0)
        content.pack(side="left", fill="both", expand=True)

        # Stacked frames for each "page"
        self._decoy_panels: dict[str, ctk.CTkFrame] = {}
        for key in [k for _, _, k in decoy_nav_items]:
            pnl = ctk.CTkFrame(content, fg_color="#0f1a2e", corner_radius=0)
            self._decoy_panels[key] = pnl

        # ── Build fake pages ──────────────────────────────────────────
        self._build_decoy_dashboard(self._decoy_panels["dcoy_dash"], fake_data)
        self._build_decoy_scan_page(self._decoy_panels["dcoy_ports"], "Port Scanner", "🔍",
                                    f"Open Ports: {fake_data['ports']['open_ports']}  |  Risky: {fake_data['ports']['risky_ports']}")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_net"], "Network Discovery", "🌐",
                                    f"Devices: {fake_data['network']['devices_found']}  |  Unknown: {fake_data['network']['unknown_devices']}  |  Subnet: {fake_data['network']['subnet']}")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_pass"], "Password Policy", "🔐",
                                    "All policies compliant  |  Min length: 8  |  Complexity: Enabled")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_wifi"], "Wi-Fi Info", "📶",
                                    "SSID: HomeNetwork  |  Security: WPA3  |  Signal: 92%")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_usb"], "USB Devices", "💾",
                                    "Connected: 2  |  Mass Storage: 1  |  HID: 1")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_fw"], "Firewall Scan", "🛡️",
                                    f"Status: {fake_data['firewall']['status']}  |  Rules: {fake_data['firewall']['rules_count']}  |  Blocked today: {fake_data['firewall']['blocked_today']}")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_mal"], "Malware Detection", "🧬",
                                    f"Status: {fake_data['malware']['status']}  |  Scanned: {fake_data['malware']['files_scanned']}  |  Threats: {fake_data['malware']['threats_found']}")
        self._build_decoy_logs_page(self._decoy_panels["dcoy_logs"], fake_logs)
        self._build_decoy_scan_page(self._decoy_panels["dcoy_rpt"], "Report Generator", "📄",
                                    "Last report: Never  |  Format: DOCX")
        self._build_decoy_scan_page(self._decoy_panels["dcoy_set"], "Settings", "⚙️",
                                    "Appearance: Dark  |  Theme: Blue  |  Font: Segoe UI")

        # ── Status bar ────────────────────────────────────────────────
        sbar = ctk.CTkFrame(overlay, height=36, fg_color=COLOR_HEADER, corner_radius=0)
        sbar.pack(fill="x", side="bottom")
        sbar.pack_propagate(False)
        ctk.CTkLabel(sbar, text="System Ready",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(
            side="left", padx=16, pady=8)
        pb = ctk.CTkProgressBar(sbar, width=220, height=8)
        pb.pack(side="right", padx=16, pady=12)
        pb.set(0)

        # Show dashboard by default
        self._decoy_show_panel("dcoy_dash", "Dashboard")

    # ── Decoy navigation helpers ──────────────────────────────────────────

    def _decoy_nav(self, key: str, label: str):
        """Switch decoy panel and log the navigation action."""
        self.decoy_manager.log_action("NAVIGATION", f"Navigated to {label}",
                                      {"panel": key})
        self._decoy_show_panel(key, label)

    def _decoy_show_panel(self, key: str, label: str = ""):
        for pnl in self._decoy_panels.values():
            pnl.place_forget()
        self._decoy_panels[key].place(x=0, y=0, relwidth=1, relheight=1)
        # Highlight nav button
        for k, btn in self._decoy_nav_btns.items():
            btn.configure(fg_color=COLOR_ACCENT if k == key else "transparent")

    def _tick_decoy_clock(self):
        """Update the decoy header clock."""
        if not self._decoy_active:
            return
        try:
            self._decoy_clock.configure(
                text=time.strftime("%A, %d %b %Y   %H:%M:%S"))
        except Exception:
            return
        self.root.after(1000, self._tick_decoy_clock)

    # ── Decoy page builders ──────────────────────────────────────────────

    def _build_decoy_dashboard(self, frame: ctk.CTkFrame, data: dict):
        """Fake dashboard with dummy security score and module cards."""
        # Top section
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=28, pady=(28, 4))

        title_fr = ctk.CTkFrame(top, fg_color="transparent")
        title_fr.pack(side="left")
        ctk.CTkLabel(title_fr, text="Security Dashboard",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(title_fr,
                     text="Run individual scans or an automated full system scan.",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Score card
        score_fr = ctk.CTkFrame(top, fg_color=COLOR_CARD, corner_radius=8,
                                border_width=1, border_color="#334155")
        score_fr.pack(side="right", padx=(20, 0))

        score = data["security_score"]
        sc_color = COLOR_SUCCESS if score >= 80 else (COLOR_WARNING if score >= 60 else COLOR_DANGER)
        ctk.CTkLabel(score_fr, text=str(score),
                     font=("Segoe UI", 32, "bold"),
                     text_color=sc_color).pack(side="left", padx=(16, 8), pady=10)

        desc_fr = ctk.CTkFrame(score_fr, fg_color="transparent")
        desc_fr.pack(side="left", padx=(0, 16), pady=10)
        ctk.CTkLabel(desc_fr, text="System Security Score",
                     font=FONT_HEADING, text_color="white").pack(anchor="w")
        ctk.CTkLabel(desc_fr, text="System secure",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # Fake "Full Scan" button
        def _fake_full_scan():
            self.decoy_manager.log_action(
                "BUTTON", "Clicked 'Run Full System Scan'", {})

        ctk.CTkButton(
            top, text="🛡️ Run Full System Scan", font=FONT_HEADING,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER, height=40,
            command=_fake_full_scan,
        ).pack(side="right", padx=(20, 0))

        # Cards grid
        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=24, pady=20)

        cards = [
            ("🔍", "Port Scanner",       f"Open: {data['ports']['open_ports']}  |  Risky: {data['ports']['risky_ports']}", "dcoy_ports",  COLOR_ACCENT),
            ("🔐", "Password Policy",    "All policies compliant",                                                          "dcoy_pass",  "#7c3aed"),
            ("📶", "Wi-Fi Info",         "WPA3  |  Signal 92%",                                                              "dcoy_wifi",  "#0891b2"),
            ("💾", "USB Devices",        "2 connected  |  All authorized",                                                   "dcoy_usb",   "#d97706"),
            ("🛡️", "Firewall Scan",      f"Active  |  {data['firewall']['rules_count']} rules",                               "dcoy_fw",    "#dc2626"),
            ("🧬", "Malware Detection",  f"Clean  |  {data['malware']['files_scanned']} files scanned",                       "dcoy_mal",   "#16a34a"),
            ("📋", "Security Logs",      "All events normal",                                                                "dcoy_logs",  "#475569"),
            ("📄", "Generate Report",    "Export scan results to DOCX",                                                      "dcoy_rpt",   "#0f766e"),
        ]

        cols = 4
        for i, (icon, title, desc, panel_key, accent) in enumerate(cards):
            row, col = divmod(i, cols)
            card = ctk.CTkFrame(grid, fg_color=COLOR_CARD,
                                corner_radius=14, border_width=1,
                                border_color="#334155")
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            grid.grid_rowconfigure(row, weight=1)
            grid.grid_columnconfigure(col, weight=1)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=18, pady=16)

            ctk.CTkLabel(inner, text=icon, font=("Segoe UI", 28)).pack(anchor="w")
            ctk.CTkLabel(inner, text=title, font=FONT_HEADING,
                         text_color="white").pack(anchor="w", pady=(6, 2))
            ctk.CTkLabel(inner, text=desc, font=FONT_SMALL,
                         text_color=COLOR_TEXT_DIM, wraplength=200,
                         justify="left").pack(anchor="w")
            ctk.CTkButton(
                inner, text="Open →",
                font=FONT_SMALL, height=32, corner_radius=8,
                fg_color=accent, hover_color=COLOR_NAV_HOVER,
                command=lambda k=panel_key, t=title: (
                    self.decoy_manager.log_action("BUTTON", f"Open → {t}", {"panel": k}),
                    self._decoy_show_panel(k, t),
                ),
            ).pack(anchor="w", pady=(12, 0))

    def _build_decoy_scan_page(self, frame: ctk.CTkFrame, title: str,
                                icon: str, summary: str):
        """Generic decoy module page with a fake 'Run Scan' button."""
        ctk.CTkLabel(frame, text=f"{icon}  {title}",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(frame, text="Module status and last scan results",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        # Summary card
        card = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=12,
                            border_width=1, border_color="#334155")
        card.pack(fill="x", padx=18, pady=(0, 12))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(inner, text="Results Summary",
                     font=FONT_HEADING, text_color="white").pack(anchor="w")
        ctk.CTkLabel(inner, text=summary,
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            anchor="w", pady=(4, 0))

        # Fake scan button (logs the action)
        def _fake_scan():
            self.decoy_manager.log_action(
                "BUTTON", f"Clicked 'Run Scan' on {title}",
                {"module": title})

        ctk.CTkButton(
            frame, text=f"🔍 Run {title}", height=38,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=_fake_scan,
        ).pack(padx=24, anchor="w", pady=(4, 12))

        # Fake console output
        box = ctk.CTkTextbox(
            frame, font=FONT_MONO, wrap="none",
            fg_color="#0d1b2a", text_color="#e2e8f0",
            border_width=1, border_color="#334155",
        )
        box.pack(padx=18, pady=8, fill="both", expand=True)
        box.tag_config("green", foreground="#4ade80")
        box.tag_config("dim",   foreground="#64748b")
        box.tag_config("cyan",  foreground="#22d3ee")
        box.insert("end", f"\n  === {title.upper()} RESULTS ===\n\n", "cyan")
        box.insert("end", f"  {summary}\n\n", "green")
        box.insert("end", f"  Last scan: {time.strftime('%Y-%m-%d %H:%M:%S')}\n", "dim")
        box.insert("end", "  Status: Complete\n", "green")
        box.insert("end", "  No threats detected.\n\n", "green")
        box.configure(state="disabled")

    def _build_decoy_logs_page(self, frame: ctk.CTkFrame, fake_logs: list):
        """Decoy logs page with convincing dummy log entries."""
        ctk.CTkLabel(frame, text="📋  Security Logs",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(frame, text=f"Showing {len(fake_logs)} recent events",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        box = ctk.CTkTextbox(
            frame, font=FONT_MONO, wrap="none",
            fg_color="#0d1b2a", text_color="#e2e8f0",
            border_width=1, border_color="#334155",
        )
        box.pack(padx=18, pady=8, fill="both", expand=True)
        box.tag_config("green",  foreground="#4ade80")
        box.tag_config("orange", foreground="#fb923c")
        box.tag_config("dim",    foreground="#64748b")
        box.tag_config("cyan",   foreground="#22d3ee")

        box.insert("end", "\n  === SECURITY EVENT LOG ===\n\n", "cyan")
        box.insert("end", f"  {'Date':<12} {'Time':<10} {'Module':<20} {'Risk':<8} Event\n", "dim")
        box.insert("end", f"  {'─'*80}\n", "dim")

        for entry in fake_logs:
            risk  = entry.get("Risk", "Low")
            color = "green" if risk == "Low" else "orange"
            box.insert(
                "end",
                f"  {entry['Date']:<12} {entry['Time']:<10} "
                f"{entry['Module']:<20} ",
                "dim",
            )
            box.insert("end", f"{risk:<8} ", color)
            box.insert("end", f"{entry['Event']}\n")

        box.configure(state="disabled")

    # ── Admin override to escape Decoy Mode ──────────────────────────────

    def _admin_escape_decoy(self, event=None):
        """Hidden admin bypass: Ctrl+Shift+F12 opens a real login prompt
        to escape decoy mode and return to the genuine application."""
        if not self._decoy_active:
            return

        # Build a small admin re-auth dialog
        escape_dlg = ctk.CTkToplevel(self.root)
        escape_dlg.title("Admin Override")
        escape_dlg.geometry("380x240")
        escape_dlg.resizable(False, False)
        escape_dlg.transient(self.root)
        escape_dlg.grab_set()
        escape_dlg.configure(fg_color="#0f172a")

        escape_dlg.update_idletasks()
        x = (escape_dlg.winfo_screenwidth() // 2) - 190
        y = (escape_dlg.winfo_screenheight() // 2) - 120
        escape_dlg.geometry(f"+{x}+{y}")

        ctk.CTkLabel(escape_dlg, text="🔑  Admin Override",
                     font=FONT_HEADING, text_color="white").pack(pady=(20, 4))
        ctk.CTkLabel(escape_dlg,
                     text="Enter your real admin password to exit Decoy Mode.",
                     font=FONT_SMALL, text_color=COLOR_TEXT_DIM).pack(pady=(0, 12))

        esc_pass_var = ctk.StringVar()
        esc_entry = ctk.CTkEntry(
            escape_dlg, textvariable=esc_pass_var, show="•",
            width=240, height=36, font=FONT_BODY,
            placeholder_text="Admin password + HHMM",
            justify="center",
        )
        esc_entry.pack(pady=4)
        esc_entry.focus_set()

        esc_status = ctk.CTkLabel(escape_dlg, text="", font=FONT_SMALL,
                                  text_color=COLOR_DANGER)
        esc_status.pack(pady=4)

        def _try_escape(event=None):
            pwd = esc_pass_var.get().strip()
            if not pwd:
                return
            # Reset auth manager state so it doesn't carry over lockout
            self.auth_manager._failed_attempts = 0
            self.auth_manager._lockout_until = 0.0
            result = self.auth_manager.authenticate(pwd)
            if result["success"]:
                esc_status.configure(text="✅ Access restored",
                                     text_color=COLOR_SUCCESS)
                # Deactivate decoy
                deactivation = self.decoy_manager.deactivate()
                self._decoy_active = False
                self._decoy_failed_streak = 0

                # Log for real
                try:
                    log_storage.log_event(
                        "Decoy Mode",
                        f"Decoy deactivated — {deactivation.get('actions_logged', 0)} actions logged",
                        "High",
                    )
                except Exception:
                    pass

                # Destroy the fake overlay and re-show the real UI
                self.root.after(600, lambda: self._exit_decoy(escape_dlg))
            else:
                esc_status.configure(text="Wrong password",
                                     text_color=COLOR_DANGER)
                esc_pass_var.set("")

        esc_entry.bind("<Return>", _try_escape)
        ctk.CTkButton(
            escape_dlg, text="Authenticate", height=34,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=_try_escape,
        ).pack(pady=8)

    def _exit_decoy(self, escape_dlg: ctk.CTkToplevel | None = None):
        """Tear down the decoy overlay and reveal the real application."""
        if escape_dlg:
            try:
                escape_dlg.destroy()
            except Exception:
                pass

        if self._decoy_container:
            try:
                self._decoy_container.destroy()
            except Exception:
                pass
            self._decoy_container = None

        # Ensure the real dashboard is showing
        self.status_var.set("Authenticated as ADMIN — Decoy mode exited")
        self._show_panel("dashboard")

    def _require_admin(self, action_key: str) -> bool:
        """
        Check if current user is authorized for a protected action.
        Shows a re-authentication dialog if not admin.

        Returns True if authorized, False otherwise.
        """
        result = self.auth_manager.authorize_action(action_key)
        if result["authorized"]:
            return True

        # Show access denied message
        messagebox.showwarning(
            "Access Denied",
            f"{result['message']}\n\n"
            f"Action: {result['action_name']}",
        )
        return False

    def _on_tamper_alert(self, alert: dict):
        """
        Callback from tamper detection monitor.
        Silently logs tampering — no popup to preserve stealth.
        """
        alert_type = alert.get("type", "tamper_detected")
        timestamp = alert.get("timestamp", "")

        # Silent alert history entry
        def _silent_log():
            if alert_type == "integrity_check_failed":
                modified = alert.get("modified", 0)
                deleted = alert.get("deleted", 0)
                msg = (f"Integrity check: {modified} modified, "
                       f"{deleted} deleted files")
            else:
                filename = alert.get("filename", "unknown")
                action = alert.get("action", "Unknown")
                msg = f"Tamper: {filename} was {action}"

            self.alert_manager.trigger("Tamper Detection", msg, "High", silent=True)

        self.root.after(0, _silent_log)

        # Log to threat timeline
        threat_timeline.add_event(
            "system",
            "Tamper Detection Alert",
            f"Protected file tampered at {timestamp}",
            threat_timeline.SEVERITY_HIGH,
            "tamper",
        )

    # ══════════════════════════════════════════════════════════════════════
    #  PROTECTED FOLDERS TAB
    # ══════════════════════════════════════════════════════════════════════

    def setup_protected_tab(self):
        """Build the Protected Folder Monitoring & Evidence Capture tab."""
        _page = self.protected_tab
        ctk.CTkLabel(_page, text="\ud83d\udd12 Protected Folder Monitoring",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Monitor your confidential files & folders for "
                          "unauthorized access with optional evidence capture",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Status card ──────────────────────────────────────────────────
        status_card = self._make_card(frame, "Monitoring Status", "\ud83d\udee1\ufe0f")

        stat_row = ctk.CTkFrame(status_card, fg_color="transparent")
        stat_row.pack(fill="x", pady=(4, 8))

        path_count = len(protected_folders.get_protected_paths())
        self.pf_status_lbl = ctk.CTkLabel(
            stat_row,
            text=(f"Monitoring {path_count} protected path(s)"
                  if path_count > 0
                  else "No paths protected yet"),
            font=FONT_BODY,
            text_color=(COLOR_SUCCESS if path_count > 0
                        else COLOR_TEXT_DIM))
        self.pf_status_lbl.pack(side="left", padx=8)

        # Real-time watchdog status indicator
        try:
            from watchdog.observers import Observer as _WDTest  # type: ignore
            _wd_ok = True
        except ImportError:
            _wd_ok = False
        self.pf_watchdog_lbl = ctk.CTkLabel(
            stat_row,
            text=("\u25cf Real-time Monitor: Active"
                  if _wd_ok
                  else "\u25cb Watchdog not installed — polling only"),
            font=FONT_SMALL,
            text_color=(COLOR_SUCCESS if _wd_ok else COLOR_WARNING))
        self.pf_watchdog_lbl.pack(side="right", padx=8)

        # ── Camera Evidence Toggle card ──────────────────────────────────
        cam_card = self._make_card(frame,
                                   "Intrusion Evidence Capture", "\ud83d\udcf7")

        cam_row = ctk.CTkFrame(cam_card, fg_color="transparent")
        cam_row.pack(fill="x", pady=(2, 6))

        ctk.CTkLabel(cam_row,
                     text="Webcam Capture on Intrusion:",
                     font=FONT_BODY).pack(side="left", padx=4)

        self.pf_camera_var = ctk.BooleanVar(
            value=protected_folders.get_camera_enabled())
        self.pf_camera_switch = ctk.CTkSwitch(
            cam_row,
            text="",
            variable=self.pf_camera_var,
            onvalue=True, offvalue=False,
            command=self._pf_toggle_camera,
            width=48,
        )
        self.pf_camera_switch.pack(side="left", padx=8)

        cam_state = protected_folders.get_camera_enabled()
        self.pf_camera_status = ctk.CTkLabel(
            cam_row,
            text=(f"ON \u2014 Max {protected_folders.DEFAULT_MAX_CAPTURES} "
                  f"images, {protected_folders.DEFAULT_COOLDOWN_SECONDS}s "
                  f"cooldown" if cam_state else "OFF"),
            font=FONT_SMALL,
            text_color=(COLOR_SUCCESS if cam_state else COLOR_TEXT_DIM))
        self.pf_camera_status.pack(side="left", padx=4)

        # Camera availability info
        cam_avail = honeypot.is_camera_available()
        cam_info = ("\u2713 Camera detected — ready for evidence capture"
                    if cam_avail
                    else "\u2717 No camera detected (install opencv-python "
                         "and connect a webcam)")
        ctk.CTkLabel(cam_card,
                     text=cam_info,
                     font=FONT_SMALL,
                     text_color=(COLOR_SUCCESS if cam_avail
                                 else COLOR_TEXT_DIM)).pack(
            anchor="w", padx=4, pady=(0, 4))

        ctk.CTkLabel(cam_card,
                     text="\u26a0 Camera activates ONLY during intrusion "
                          "events — max 2 images, then 30s cooldown",
                     font=FONT_SMALL,
                     text_color=COLOR_TEXT_DIM).pack(
            anchor="w", padx=4, pady=(0, 4))

        # ── Add Folder/File buttons ──────────────────────────────────────
        add_card = self._make_card(frame,
                                   "Add Protected Paths", "\u2795")

        btn_row = ctk.CTkFrame(add_card, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 8))

        add_folder_btn = ctk.CTkButton(
            btn_row, text="\ud83d\udcc1 Add Protected Folder", height=38,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self._pf_add_folder)
        add_folder_btn.pack(side="left", padx=5)
        ToolTip(add_folder_btn,
                "Select a folder to monitor for unauthorized access")

        add_file_btn = ctk.CTkButton(
            btn_row, text="\ud83d\udcc4 Add Protected File", height=38,
            fg_color="#7c3aed", hover_color=COLOR_NAV_HOVER,
            command=self._pf_add_file)
        add_file_btn.pack(side="left", padx=5)
        ToolTip(add_file_btn,
                "Select a specific file to monitor for unauthorized access")

        view_evidence_btn = ctk.CTkButton(
            btn_row, text="\ud83d\udcc2 View Evidence", height=38,
            fg_color="#0891b2", hover_color=COLOR_NAV_HOVER,
            command=self._pf_view_evidence)
        view_evidence_btn.pack(side="left", padx=5)
        ToolTip(view_evidence_btn,
                "Open the evidence captures folder in File Explorer")

        clear_log_btn = ctk.CTkButton(
            btn_row, text="\ud83d\uddd1\ufe0f Clear Event Log", height=38,
            fg_color=COLOR_DANGER, hover_color="#991b1b",
            command=self._pf_clear_logs)
        clear_log_btn.pack(side="left", padx=5)
        ToolTip(clear_log_btn,
                "Delete all intrusion event logs (requires admin)")

        # ── Protected items list ─────────────────────────────────────────
        list_card = self._make_card(frame,
                                    "Protected Items", "\ud83d\udcdd")
        self.pf_list_frame = ctk.CTkScrollableFrame(
            list_card, fg_color="#0d1b2a", height=180,
            corner_radius=8,
            scrollbar_button_color="#334155",
            scrollbar_button_hover_color=COLOR_ACCENT)
        self.pf_list_frame.pack(fill="x", padx=4, pady=4)
        self._pf_refresh_list()

        # ── Intrusion Detection Console ──────────────────────────────────
        console_card = self._make_card(frame,
                                       "Intrusion Detection Console", "\ud83d\udcbb")
        self.pf_box = self._make_console(console_card)

        # Show existing events
        self._pf_show_recent_events()

    # ── Protected Folder helper methods ──────────────────────────────────

    def _pf_toggle_camera(self):
        """Toggle webcam evidence capture ON/OFF."""
        enabled = self.pf_camera_var.get()
        self.pf_monitor.set_camera_enabled(enabled)
        if enabled:
            self.pf_camera_status.configure(
                text=(f"ON \u2014 Max "
                      f"{protected_folders.DEFAULT_MAX_CAPTURES} images, "
                      f"{protected_folders.DEFAULT_COOLDOWN_SECONDS}s "
                      f"cooldown"),
                text_color=COLOR_SUCCESS)
        else:
            self.pf_camera_status.configure(
                text="OFF", text_color=COLOR_TEXT_DIM)

    def _pf_add_folder(self):
        """Open folder dialog and add selected folder to protection."""
        folder = filedialog.askdirectory(
            title="Select Folder to Protect")
        if not folder:
            return
        self._pf_add_path(folder)

    def _pf_add_file(self):
        """Open file dialog and add selected file to protection."""
        filepath = filedialog.askopenfilename(
            title="Select File to Protect",
            filetypes=[("All Files", "*.*")])
        if not filepath:
            return
        self._pf_add_path(filepath)

    def _pf_add_path(self, path: str):
        """Add a path to the protected list and refresh UI."""
        result = protected_folders.add_protected_path(path)
        status = result.get("status", "error")
        message = result.get("message", "")

        if status == "ok":
            self.status_var.set(f"\u2713 {message}")
            # Reload the watchdog observer to include new path
            self.pf_monitor.reload()
        elif status == "duplicate":
            self.status_var.set(f"\u26a0 {message}")
        else:
            self.status_var.set(f"\u2717 {message}")

        self._pf_refresh_list()
        self._pf_update_status()

        # Log to console
        if self.pf_box is not None:
            box = self.pf_box
            box.configure(state="normal")
            if status == "ok":
                entry = result.get("entry", {})
                ptype = entry.get("type", "file")
                self._cwrite(box,
                    f"\n  \u2705 Added protected {ptype}: "
                    f"{os.path.basename(path)}\n", "green")
                self._cwrite(box,
                    f"     Path: {path}\n", "dim")
            elif status == "duplicate":
                self._cwrite(box,
                    f"\n  \u26a0 Already protected: "
                    f"{os.path.basename(path)}\n", "orange")
            else:
                self._cwrite(box,
                    f"\n  \u2717 Error: {message}\n", "red")
            box.configure(state="disabled")

    def _pf_remove_path(self, path: str):
        """Remove a path from protection (requires admin auth)."""
        if not self._require_admin("change_settings"):
            return
        result = protected_folders.remove_protected_path(path)
        if result.get("status") == "ok":
            self.status_var.set(f"\u2713 {result['message']}")
            self.pf_monitor.reload()
        else:
            self.status_var.set(f"\u2717 {result.get('message', 'Error')}")
        self._pf_refresh_list()
        self._pf_update_status()

    def _pf_view_evidence(self):
        """Open the evidence captures folder."""
        evidence_dir = honeypot.EVIDENCE_DIR
        os.makedirs(evidence_dir, exist_ok=True)
        try:
            os.startfile(evidence_dir)  # type: ignore[attr-defined]
        except Exception:
            self.status_var.set(f"Evidence folder: {evidence_dir}")

    def _pf_clear_logs(self):
        """Clear all intrusion event logs (requires admin)."""
        if not self._require_admin("delete_logs"):
            return
        protected_folders.clear_events()
        if self.pf_box is not None:
            self._cclear(self.pf_box)
            self._cwrite(self.pf_box,
                "\n  Event log cleared.\n", "dim")
            self.pf_box.configure(state="disabled")
        self.status_var.set("Protected folder event log cleared")

    def _pf_refresh_list(self):
        """Rebuild the protected items list UI."""
        if self.pf_list_frame is None:
            return

        # Clear existing items
        for w in self.pf_list_frame.winfo_children():
            w.destroy()

        paths = protected_folders.get_protected_paths()

        if not paths:
            ctk.CTkLabel(
                self.pf_list_frame,
                text="  No protected files or folders. "
                     "Click 'Add Protected Folder' or "
                     "'Add Protected File' to get started.",
                font=FONT_SMALL,
                text_color=COLOR_TEXT_DIM,
                wraplength=600,
                justify="left",
            ).pack(anchor="w", padx=8, pady=8)
            return

        for entry in paths:
            if not isinstance(entry, dict):
                continue
            row = ctk.CTkFrame(self.pf_list_frame,
                               fg_color="#1e293b",
                               corner_radius=8)
            row.pack(fill="x", padx=4, pady=2)

            ptype = entry.get("type", "file")
            icon = "\ud83d\udcc1" if ptype == "folder" else "\ud83d\udcc4"
            label = entry.get("label", os.path.basename(
                entry.get("path", "")))

            ctk.CTkLabel(
                row, text=f"  {icon}  {label}",
                font=FONT_BODY, text_color="white",
                anchor="w",
            ).pack(side="left", padx=(8, 4), pady=6)

            # Path info
            path_text = entry.get("path", "")
            if len(path_text) > 60:
                path_text = "..." + path_text[-57:]
            ctk.CTkLabel(
                row, text=path_text,
                font=FONT_SMALL, text_color=COLOR_TEXT_DIM,
                anchor="w",
            ).pack(side="left", padx=4, pady=6, expand=True, fill="x")

            # Type badge
            badge_color = "#0891b2" if ptype == "folder" else "#7c3aed"
            ctk.CTkLabel(
                row, text=ptype.upper(),
                font=(FONT_SMALL[0], 9, "bold"),
                fg_color=badge_color,
                corner_radius=4,
                text_color="white",
                width=55, height=22,
            ).pack(side="left", padx=4, pady=6)

            # Added date
            added = entry.get("added_at", "")[:10]
            if added:
                ctk.CTkLabel(
                    row, text=added,
                    font=FONT_SMALL,
                    text_color=COLOR_TEXT_DIM,
                ).pack(side="left", padx=4, pady=6)

            # Remove button (triggers admin auth)
            epath = entry.get("path", "")
            remove_btn = ctk.CTkButton(
                row, text="\u2716", width=30, height=28,
                fg_color=COLOR_DANGER, hover_color="#991b1b",
                font=(FONT_SMALL[0], 12, "bold"),
                corner_radius=6,
                command=lambda p=epath: self._pf_remove_path(p),
            )
            remove_btn.pack(side="right", padx=6, pady=4)
            ToolTip(remove_btn, "Remove from protection (requires admin)")

    def _pf_update_status(self):
        """Update the monitoring status label."""
        paths = protected_folders.get_protected_paths()
        count = len(paths)
        if count > 0:
            folders = sum(
                1 for p in paths
                if isinstance(p, dict) and p.get("type") == "folder"
            )
            files = count - folders
            parts = []
            if folders:
                parts.append(f"{folders} folder(s)")
            if files:
                parts.append(f"{files} file(s)")
            text = f"Monitoring {', '.join(parts)}"
            color = COLOR_SUCCESS
        else:
            text = "No paths protected yet"
            color = COLOR_TEXT_DIM

        if self.pf_status_lbl is not None:
            self.pf_status_lbl.configure(text=text, text_color=color)

    def _pf_show_recent_events(self):
        """Display recent events in the console on tab load."""
        if self.pf_box is None:
            return
        events = protected_folders.get_events()
        box = self.pf_box
        self._cclear(box)

        if not events:
            self._cwrite(box,
                "\n  No intrusion events recorded yet.\n"
                "  Protected paths will be monitored in real-time.\n",
                "dim")
            box.configure(state="disabled")
            return

        self._cwrite(box,
            "\n  === RECENT INTRUSION EVENTS ===\n\n", "cyan")

        # Show last 20 events
        recent = events[-20:]
        for evt in reversed(recent):
            ts = evt.get("timestamp", "")[:19]
            fname = evt.get("filename", "unknown")
            action = evt.get("action", "Unknown")
            severity = evt.get("severity", "HIGH")

            sev_tag = "red" if severity in ("HIGH", "CRITICAL") else "orange"
            self._cwrite(box,
                f"  [{ts}]  ", "dim")
            self._cwrite(box,
                f"\u26a0 {action}: ", sev_tag)
            self._cwrite(box,
                f"{fname}\n", "")

            ev_imgs = evt.get("evidence_images", [])
            if ev_imgs:
                for img in ev_imgs:
                    self._cwrite(box,
                        f"    \ud83d\udcf7 Evidence: "
                        f"{img.get('filename', '')}\n", "orange")

        total = len(events)
        self._cwrite(box,
            f"\n  Total events: {total}  |  "
            f"Showing last {len(recent)}\n", "dim")
        box.configure(state="disabled")

    def _on_protected_folder_alert(self, alert: dict):
        """
        Callback from protected folder monitor (watchdog or polling).

        SILENT MODE — no popup. Intrusion evidence is captured covertly.
        """
        filename = alert.get("filename", "unknown")
        action = alert.get("action", "Unknown")
        evidence_images = alert.get("evidence_images", [])
        cooldown = alert.get("cooldown_active", False)
        cooldown_secs = alert.get("cooldown_remaining", 0)

        # ── 1. Silent alert history ──────────────────────────────────────
        msg = f"Protected file/folder was {action}! Possible intrusion."
        if evidence_images:
            msg += (f" {len(evidence_images)} evidence image(s) "
                    f"captured.")
        elif cooldown:
            msg += f" Cooldown active ({cooldown_secs}s)."

        def _silent_log():
            self.alert_manager.trigger(f"Protected: {filename}", msg, "High", silent=True)

        self.root.after(0, _silent_log)

        # ── 2. Console log ───────────────────────────────────────────────
        def _log_to_console():
            if self.pf_box is None:
                return
            try:
                box = self.pf_box
                box.configure(state="normal")
                self._cwrite(box,
                    f"\n  \u26a0 UNAUTHORIZED ACCESS DETECTED "
                    f"[{alert.get('time', '')}]  \u26a0\n", "red")
                self._cwrite(box,
                    f"    File    : {filename}\n", "red")
                self._cwrite(box,
                    f"    Action  : {action}\n", "orange")
                self._cwrite(box,
                    f"    Path    : {alert.get('path', '')}\n", "dim")
                self._cwrite(box,
                    f"    Time    : "
                    f"{alert.get('timestamp', '')[:19]}\n", "dim")

                # Evidence capture status
                if evidence_images:
                    for img in evidence_images:
                        idx = img.get("index", "?")
                        path = img.get("image_path", "")
                        self._cwrite(box,
                            f"    \ud83d\udcf7 Image {idx}: {path}\n", "orange")
                    self._cwrite(box,
                        "    Capture complete.\n", "green")
                elif cooldown:
                    self._cwrite(box,
                        f"    Capture: Cooldown active "
                        f"({cooldown_secs}s remaining)\n", "dim")
                else:
                    self._cwrite(box,
                        "    Capture: Camera OFF "
                        "(enable to capture)\n", "dim")

                box.configure(state="disabled")
            except Exception:
                pass  # widget destroyed or app closing

        self.root.after(0, _log_to_console)

        # ── 3. Threat timeline ───────────────────────────────────────────
        threat_timeline.add_event(
            "system",
            f"Protected File Alert: {filename}",
            f"Unauthorized {action} detected",
            threat_timeline.SEVERITY_HIGH,
            "protected_folders",
        )

    # ══════════════════════════════════════════════════════════════════════
    #  HONEYPOT MONITOR TAB
    # ══════════════════════════════════════════════════════════════════════

    def setup_honeypot_tab(self):
        """Build the Honeypot Intrusion Detection & Evidence Capture tab."""
        _page = self.honeypot_tab
        ctk.CTkLabel(_page, text="\ud83c\udfaf Honeypot Intrusion Detection",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Deploy decoy files with real-time monitoring "
                          "& optional webcam evidence capture",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Status card ──────────────────────────────────────────────────
        status_card = self._make_card(frame, "System Status", "\ud83d\udee1\ufe0f")

        stat_row = ctk.CTkFrame(status_card, fg_color="transparent")
        stat_row.pack(fill="x", pady=(4, 8))

        self.honeypot_status_lbl = ctk.CTkLabel(
            stat_row, text="Status: Not checked yet",
            font=FONT_BODY, text_color=COLOR_TEXT_DIM)
        self.honeypot_status_lbl.pack(side="left", padx=8)

        # Real-time watchdog status
        self._hp_watchdog_lbl = ctk.CTkLabel(
            stat_row,
            text=("\u25cf Real-time Monitor: Active"
                  if honeypot._WATCHDOG_AVAILABLE
                  else "\u25cb Watchdog not installed"),
            font=FONT_SMALL,
            text_color=(COLOR_SUCCESS if honeypot._WATCHDOG_AVAILABLE
                        else COLOR_WARNING))
        self._hp_watchdog_lbl.pack(side="right", padx=8)

        # ── Camera Evidence Toggle card ──────────────────────────────────
        cam_card = self._make_card(frame, "Intrusion Evidence Capture", "\ud83d\udcf7")

        cam_row = ctk.CTkFrame(cam_card, fg_color="transparent")
        cam_row.pack(fill="x", pady=(2, 6))

        ctk.CTkLabel(cam_row,
                     text="Webcam Capture on Intrusion:",
                     font=FONT_BODY).pack(side="left", padx=4)

        self._hp_camera_var = ctk.BooleanVar(value=False)
        self._hp_camera_switch = ctk.CTkSwitch(
            cam_row,
            text="",
            variable=self._hp_camera_var,
            onvalue=True, offvalue=False,
            command=self._toggle_camera_capture,
            width=48,
        )
        self._hp_camera_switch.pack(side="left", padx=8)

        self._hp_camera_status = ctk.CTkLabel(
            cam_row, text="OFF", font=FONT_SMALL,
            text_color=COLOR_TEXT_DIM)
        self._hp_camera_status.pack(side="left", padx=4)

        # Camera availability check
        cam_avail = honeypot.is_camera_available()
        cam_info_text = (
            "\u2713 Camera detected — ready for evidence capture"
            if cam_avail
            else "\u2717 No camera detected (install opencv-python "
                 "and connect a webcam)")
        cam_info_color = COLOR_SUCCESS if cam_avail else COLOR_TEXT_DIM
        ctk.CTkLabel(cam_card,
                     text=cam_info_text,
                     font=FONT_SMALL,
                     text_color=cam_info_color).pack(
            anchor="w", padx=4, pady=(0, 4))

        ctk.CTkLabel(cam_card,
                     text="\u26a0 Camera activates ONLY during intrusion "
                          "events — no continuous access",
                     font=FONT_SMALL,
                     text_color=COLOR_TEXT_DIM).pack(
            anchor="w", padx=4, pady=(0, 4))

        # ── Control buttons ──────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=18, pady=(0, 8))

        self.honeypot_deploy_btn = ctk.CTkButton(
            btn_frame, text="\ud83c\udfaf Deploy Honeypots", height=38,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self._deploy_honeypots)
        self.honeypot_deploy_btn.pack(side="left", padx=5)
        ToolTip(self.honeypot_deploy_btn,
                "Create hidden decoy files in Documents and Desktop")

        self.honeypot_check_btn = ctk.CTkButton(
            btn_frame, text="\ud83d\udd0d Check Integrity", height=38,
            fg_color="#0891b2", hover_color=COLOR_NAV_HOVER,
            command=self._check_honeypots)
        self.honeypot_check_btn.pack(side="left", padx=5)
        ToolTip(self.honeypot_check_btn,
                "Verify all honeypot files for tampering")

        self.honeypot_remove_btn = ctk.CTkButton(
            btn_frame, text="\ud83d\uddd1\ufe0f Remove All", height=38,
            fg_color=COLOR_DANGER, hover_color="#991b1b",
            command=self._remove_honeypots)
        self.honeypot_remove_btn.pack(side="left", padx=5)
        ToolTip(self.honeypot_remove_btn,
                "Delete all deployed honeypot files and clear registry")

        view_evidence_btn = ctk.CTkButton(
            btn_frame, text="\ud83d\udcc2 View Evidence", height=38,
            fg_color="#7c3aed", hover_color=COLOR_NAV_HOVER,
            command=self._view_evidence_folder)
        view_evidence_btn.pack(side="left", padx=5)
        ToolTip(view_evidence_btn,
                "Open the evidence captures folder in File Explorer")

        # ── Console output ───────────────────────────────────────────────
        console_card = self._make_card(frame,
                                       "Intrusion Detection Console", "\ud83d\udcbb")
        self.honeypot_box = self._make_console(console_card)

    def _toggle_camera_capture(self):
        """Toggle webcam evidence capture ON/OFF."""
        enabled = self._hp_camera_var.get()
        self.honeypot_monitor.set_camera_enabled(enabled)
        if enabled:
            self._hp_camera_status.configure(
                text=f"ON \u2014 Max {honeypot.DEFAULT_MAX_CAPTURES} images, "
                     f"{honeypot.DEFAULT_COOLDOWN_SECONDS}s cooldown",
                text_color=COLOR_SUCCESS)
        else:
            self._hp_camera_status.configure(
                text="OFF",
                text_color=COLOR_TEXT_DIM)

    def _view_evidence_folder(self):
        """Open the secure evidence captures folder in File Explorer."""
        evidence_dir = honeypot.EVIDENCE_DIR
        os.makedirs(evidence_dir, exist_ok=True)
        try:
            os.startfile(evidence_dir)  # type: ignore[attr-defined]
        except Exception:
            self.status_var.set(f"Evidence folder: {evidence_dir}")

    def _deploy_honeypots(self):
        """Deploy honeypot files and restart real-time monitoring."""
        self.honeypot_deploy_btn.configure(state="disabled",
                                           text="Deploying...")
        self._cclear(self.honeypot_box)

        def _worker():
            result = honeypot.deploy_honeypots()
            # Reload the watchdog observer to watch new files
            self.honeypot_monitor.reload()
            self.root.after(0, lambda: self._show_honeypot_result(
                    result, "deploy"))

        threading.Thread(target=_worker, daemon=True).start()

    def _check_honeypots(self):
        """Check honeypot integrity."""
        self.honeypot_check_btn.configure(state="disabled",
                                          text="Checking...")
        self._cclear(self.honeypot_box)

        def _worker():
            result = honeypot.get_honeypot_status()
            self.root.after(0, lambda: self._show_honeypot_result(
                    result, "check"))

        threading.Thread(target=_worker, daemon=True).start()

    def _remove_honeypots(self):
        """Remove all honeypot files (requires admin)."""
        if not self._require_admin("remove_honeypots"):
            return
        self._cclear(self.honeypot_box)

        def _worker():
            result = honeypot.remove_honeypots()
            # Reload the watchdog (nothing to watch now)
            self.honeypot_monitor.reload()
            self.root.after(0, lambda: self._show_honeypot_result(
                    result, "remove"))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_honeypot_result(self, result: dict, action: str):
        """Display honeypot operation results in the console."""
        self.honeypot_deploy_btn.configure(
            state="normal", text="\ud83c\udfaf Deploy Honeypots")
        self.honeypot_check_btn.configure(
            state="normal", text="\ud83d\udd0d Check Integrity")

        box = self.honeypot_box
        self._cclear(box)

        if action == "deploy":
            self._cwrite(box,
                "\n  === HONEYPOT DEPLOYMENT REPORT ===\n\n", "cyan")
            deployed = result.get("deployed", [])
            skipped = result.get("skipped", [])
            errors = result.get("errors", [])
            total = result.get("total_active", 0)

            if deployed:
                self._cwrite(box, f"  Deployed {len(deployed)} new "
                             f"honeypot file(s):\n", "green")
                for d in deployed:
                    self._cwrite(box,
                        f"    + {os.path.basename(d['path'])}\n", "green")
                    self._cwrite(box,
                        f"      Path: {d['path']}\n", "dim")
            if skipped:
                self._cwrite(box, f"\n  Skipped {len(skipped)} "
                             f"(already deployed):\n", "orange")
                for s in skipped:
                    self._cwrite(box,
                        f"    - {os.path.basename(s)}\n", "dim")
            if errors:
                self._cwrite(box, "\n  Errors:\n", "red")
                for e in errors:
                    self._cwrite(box, f"    ! {e}\n", "red")

            self._cwrite(box,
                f"\n  Total active honeypots: {total}\n", "cyan")
            cam_state = "ON" if self._hp_camera_var.get() else "OFF"
            self._cwrite(box,
                f"  Camera evidence capture: {cam_state}\n", "dim")
            self._cwrite(box,
                "  Real-time watchdog monitoring: ACTIVE\n\n", "green")
            self.honeypot_status_lbl.configure(
                text=f"Active Honeypots: {total} | "
                     f"Monitoring: Real-time",
                text_color=COLOR_SUCCESS)

            # Log to timeline
            threat_timeline.add_event(
                threat_timeline.EVENT_HONEYPOT,
                "Honeypots Deployed",
                f"{len(deployed)} decoy files deployed, "
                f"watchdog monitoring active",
                threat_timeline.SEVERITY_LOW,
                "honeypot",
            )

        elif action == "check":
            self._cwrite(box,
                "\n  === HONEYPOT INTEGRITY CHECK ===\n\n", "cyan")
            hps = result.get("honeypots", [])
            alerts = result.get("alerts", [])
            intact = result.get("intact", 0)
            tampered = result.get("tampered", 0)

            if not hps:
                self._cwrite(box,
                    "  No honeypots deployed yet. Click 'Deploy "
                    "Honeypots' first.\n", "orange")
            else:
                self._cwrite(box,
                    f"  {'FILE':<32} {'STATE':<12} DEPLOYED\n", "dim")
                self._cwrite(box,
                    f"  {'-'*32} {'-'*12} {'-'*19}\n", "dim")
                for h in hps:
                    state = h.get("state", "unknown")
                    tag = ("green" if state == "intact"
                           else "red" if state == "deleted"
                           else "orange")
                    self._cwrite(box,
                        f"  {h['filename']:<32} ", "")
                    self._cwrite(box,
                        f"{state.upper():<12} ", tag)
                    self._cwrite(box,
                        f"{h.get('deployed_at', '')[:19]}\n", "dim")

                self._cwrite(box,
                    f"\n  Summary: {intact} intact, "
                    f"{tampered} tampered\n",
                    "green" if tampered == 0 else "red")

            if alerts:
                self._cwrite(box,
                    "\n  >> ALERT: TAMPERING DETECTED! <<\n", "red")
                for a in alerts:
                    self._cwrite(box,
                        f"  ! {a['filename']} was {a['state']}\n", "red")
                    evidence = a.get("evidence_image")
                    if evidence:
                        self._cwrite(box,
                            f"    Evidence: {evidence}\n", "orange")
                    # Log to timeline
                    threat_timeline.log_honeypot_event(
                        a["filename"], a["state"])

            status_text = (
                f"Intact: {intact} | Tampered: {tampered}"
                if hps else "No honeypots deployed")
            color = (COLOR_SUCCESS if tampered == 0
                     else COLOR_DANGER)
            self.honeypot_status_lbl.configure(
                text=status_text, text_color=color)

        elif action == "remove":
            self._cwrite(box,
                "\n  === HONEYPOT REMOVAL ===\n\n", "cyan")
            removed = result.get("removed", [])
            errors = result.get("errors", [])

            if removed:
                self._cwrite(box,
                    f"  Removed {len(removed)} honeypot file(s):\n",
                    "green")
                for r in removed:
                    self._cwrite(box,
                        f"    - {os.path.basename(r)}\n", "dim")
            else:
                self._cwrite(box, "  No honeypots to remove.\n", "dim")

            if errors:
                self._cwrite(box, "\n  Errors:\n", "red")
                for e in errors:
                    self._cwrite(box, f"    ! {e}\n", "red")

            self.honeypot_status_lbl.configure(
                text="No honeypots deployed",
                text_color=COLOR_TEXT_DIM)

        box.configure(state="disabled")

    def _on_honeypot_alert(self, alert: dict):
        """
        Callback from honeypot real-time monitor (watchdog or polling).

        SILENT MODE — no popup. Intrusion evidence is captured covertly.
        Uses controlled capture: max 2 images per event, 30s cooldown.
        """
        filename = alert.get("filename", "unknown")
        action = alert.get("action", alert.get("state", "tampered"))
        evidence_images = alert.get("evidence_images", [])
        cooldown = alert.get("cooldown_active", False)
        cooldown_secs = alert.get("cooldown_remaining", 0)

        # ── 1. Silent alert history (NO popup) ───────────────────────────
        msg = f"Decoy file was {action}! Possible intrusion."
        if evidence_images:
            msg += f" {len(evidence_images)} evidence image(s) captured."
        elif cooldown:
            msg += f" Cooldown active ({cooldown_secs}s)."

        def _silent_log():
            self.alert_manager.trigger(f"Honeypot: {filename}", msg, "High", silent=True)

        self.root.after(0, _silent_log)

        # ── 2. Console log (only visible if tab is open) ─────────────────
        def _log_to_console():
            if not hasattr(self, 'honeypot_box') or self.honeypot_box is None:
                return
            try:
                box = self.honeypot_box
                box.configure(state="normal")
                self._cwrite(box,
                    f"\n  \u26a0 INTRUSION DETECTED [{alert.get('time', '')}]  "
                    f"\u26a0\n", "red")
                self._cwrite(box,
                    f"    File    : {filename}\n", "red")
                self._cwrite(box,
                    f"    Action  : {action}\n", "orange")
                self._cwrite(box,
                    f"    Time    : {alert.get('timestamp', '')[:19]}\n", "dim")

                # Evidence capture status
                if evidence_images:
                    for img in evidence_images:
                        idx = img.get("index", "?")
                        path = img.get("image_path", "")
                        self._cwrite(box,
                            f"    \ud83d\udcf7 Image {idx}: {path}\n", "orange")
                    self._cwrite(box,
                        "    Capture complete.\n", "green")
                elif cooldown:
                    self._cwrite(box,
                        f"    Capture: Cooldown active ({cooldown_secs}s "
                        f"remaining)\n", "dim")
                else:
                    self._cwrite(box,
                        "    Capture: Camera OFF (enable to capture)\n", "dim")

                box.configure(state="disabled")
            except Exception:
                pass  # widget destroyed or app closing

        self.root.after(0, _log_to_console)

        # ── 3. Threat timeline (persistent, silent) ──────────────────────
        threat_timeline.log_honeypot_event(filename, action)

    # ══════════════════════════════════════════════════════════════════════
    #  SCAN SCHEDULER TAB
    # ══════════════════════════════════════════════════════════════════════

    def setup_scheduler_tab(self):
        """Build the Scan Scheduler tab."""
        _page = self.scheduler_tab
        ctk.CTkLabel(_page, text="\u23f0 Scan Scheduler",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Schedule automatic security scans at regular "
                          "intervals",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Configuration card ───────────────────────────────────────────
        config_card = self._make_card(frame, "Schedule Configuration", "\u2699\ufe0f")

        # Status label
        self.scheduler_status_lbl = ctk.CTkLabel(
            config_card,
            text="\u25cf Scheduler: Inactive",
            font=FONT_HEADING, text_color=COLOR_TEXT_DIM)
        self.scheduler_status_lbl.pack(anchor="w", padx=4, pady=(4, 8))

        # Interval selection
        interval_frame = ctk.CTkFrame(config_card, fg_color="transparent")
        interval_frame.pack(fill="x", pady=4)
        ctk.CTkLabel(interval_frame, text="Scan Interval:",
                     font=FONT_BODY).pack(side="left", padx=4)

        labels = [p[0] for p in scan_scheduler.INTERVAL_PRESETS]
        cfg = self.scheduler_engine.config if hasattr(self, 'scheduler_engine') and self.scheduler_engine else scan_scheduler.get_schedule()
        current = cfg.get("interval_label", "Every 1 hour")

        self.scheduler_interval_var = ctk.StringVar(value=current)
        interval_menu = ctk.CTkOptionMenu(
            interval_frame,
            values=labels,
            variable=self.scheduler_interval_var,
            width=200,
            command=self._on_scheduler_interval_change)
        interval_menu.pack(side="left", padx=8)
        ToolTip(interval_menu, "How often to run automatic scans")

        # Module checkboxes
        modules_frame = ctk.CTkFrame(config_card, fg_color="transparent")
        modules_frame.pack(fill="x", pady=(8, 4))
        ctk.CTkLabel(modules_frame, text="Modules to scan:",
                     font=FONT_BODY).pack(anchor="w", padx=4, pady=(0, 4))

        active_modules = cfg.get("modules", ["malware", "firewall"])
        self._scheduler_module_vars: dict[str, ctk.BooleanVar] = {}
        for mod_key, mod_label in scan_scheduler.AVAILABLE_MODULES:
            var = ctk.BooleanVar(value=(mod_key in active_modules))
            self._scheduler_module_vars[mod_key] = var
            ctk.CTkCheckBox(
                modules_frame, text=mod_label, variable=var,
                font=FONT_BODY, onvalue=True, offvalue=False,
                command=self._on_scheduler_module_change,
            ).pack(anchor="w", padx=16, pady=2)

        # Control buttons
        btn_frame = ctk.CTkFrame(config_card, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(8, 4))

        is_enabled = cfg.get("enabled", False)
        self.scheduler_toggle_btn = ctk.CTkButton(
            btn_frame,
            text=("\u23f9 Stop Scheduler" if is_enabled
                  else "\u25b6\ufe0f Start Scheduler"),
            height=40, width=180,
            fg_color=(COLOR_DANGER if is_enabled else COLOR_SUCCESS),
            hover_color=COLOR_NAV_HOVER,
            font=FONT_HEADING,
            command=self._toggle_scheduler)
        self.scheduler_toggle_btn.pack(side="left", padx=5)

        run_now_btn = ctk.CTkButton(
            btn_frame, text="\u26a1 Run Now", height=40,
            fg_color="#7c3aed", hover_color=COLOR_NAV_HOVER,
            command=self._scheduler_run_now)
        run_now_btn.pack(side="left", padx=5)
        ToolTip(run_now_btn,
                "Execute a scan immediately with the selected modules")

        # ── History card ─────────────────────────────────────────────────
        history_card = self._make_card(frame, "Scan History", "\ud83d\udccb")
        self.scheduler_box = self._make_console(history_card)

        # Load initial state
        self._refresh_scheduler_status()
        self._refresh_scheduler_history()

    def _on_scheduler_interval_change(self, new_label: str):
        """Update the scheduler interval."""
        for label, seconds in scan_scheduler.INTERVAL_PRESETS:
            if label == new_label:
                self.scheduler_engine.update_config(
                    interval_seconds=seconds,
                    interval_label=label)
                break

    def _on_scheduler_module_change(self):
        """Update the scheduler's active modules."""
        modules = [k for k, v in self._scheduler_module_vars.items()
                   if v.get()]
        self.scheduler_engine.update_config(modules=modules)

    def _toggle_scheduler(self):
        """Start or stop the scan scheduler."""
        if self.scheduler_engine.is_running:
            self.scheduler_engine.stop()
            self.scheduler_toggle_btn.configure(
                text="\u25b6\ufe0f Start Scheduler",
                fg_color=COLOR_SUCCESS)
            self.scheduler_status_lbl.configure(
                text="\u25cf Scheduler: Inactive",
                text_color=COLOR_TEXT_DIM)
            self.status_var.set("Scan Scheduler stopped")
        else:
            # Save current settings
            modules = [k for k, v in self._scheduler_module_vars.items()
                       if v.get()]
            interval_label = self.scheduler_interval_var.get()
            interval_secs = 3600
            for label, secs in scan_scheduler.INTERVAL_PRESETS:
                if label == interval_label:
                    interval_secs = secs
                    break

            self.scheduler_engine.update_config(
                enabled=True,
                interval_seconds=interval_secs,
                interval_label=interval_label,
                modules=modules)
            self.scheduler_engine.start()

            self.scheduler_toggle_btn.configure(
                text="\u23f9 Stop Scheduler",
                fg_color=COLOR_DANGER)
            self.scheduler_status_lbl.configure(
                text=f"\u25cf Scheduler: Active ({interval_label})",
                text_color=COLOR_SUCCESS)
            self.status_var.set(
                f"Scan Scheduler started ({interval_label})")

    def _scheduler_run_now(self):
        """Execute a scheduled scan immediately."""
        modules = [k for k, v in self._scheduler_module_vars.items()
                   if v.get()]
        if not modules:
            self.status_var.set("No modules selected for scan")
            return

        self.status_var.set("Running scheduled scan now...")

        def _worker():
            try:
                result = self._scheduled_scan_callback(modules)
                entry = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "modules": modules,
                    "status": "ok",
                    "duration_seconds": 0,
                    "run_number": 0,
                }
                self.root.after(0, lambda: self._on_scheduled_scan_complete(entry))
            except Exception as e:
                self.root.after(0, lambda: self.status_var.set(
                    f"Scan failed: {e}"))

        threading.Thread(target=_worker, daemon=True).start()

    def _scheduled_scan_callback(self, modules: list) -> dict:  # type: ignore[type-arg]
        """Execute the actual scan modules. Called by the scheduler."""
        results = {}

        if "malware" in modules:
            self.root.after(0, lambda: self.status_var.set(
                "Scheduled: Malware scan..."))
            results["malware"] = malware_scanner.basic_malware_scan()
            self.scan_results["malware"] = results["malware"]
            self.root.after(0, self.update_security_score)

        if "firewall" in modules:
            self.root.after(0, lambda: self.status_var.set(
                "Scheduled: Firewall scan..."))
            results["firewall"] = firewall_scanner.scan_firewall()
            self.scan_results["firewall_scanner"] = results["firewall"]
            self.root.after(0, self.update_security_score)

        if "network" in modules:
            self.root.after(0, lambda: self.status_var.set(
                "Scheduled: Network discovery..."))
            results["network"] = network_discovery.discover_devices()
            self.scan_results["network_discovery"] = results["network"]
            self.root.after(0, self.update_security_score)

        if "startup" in modules:
            self.root.after(0, lambda: self.status_var.set(
                "Scheduled: Startup analyzer..."))
            from modules import startup_analyzer  # type: ignore
            results["startup"] = startup_analyzer.scan_startup_programs()
            self.scan_results["startup_analyzer"] = results["startup"]
            self.root.after(0, self.update_security_score)

        return results

    def _on_scheduled_scan_complete(self, entry: dict):
        """Callback after a scheduled scan finishes."""
        modules = entry.get("modules", [])
        duration = entry.get("duration_seconds", 0)
        self.status_var.set(
            f"Scheduled scan complete ({', '.join(modules)}) "
            f"in {duration}s")
        self._refresh_scheduler_history()
        self.update_security_score()

        # Log to threat timeline
        threat_timeline.log_scan_event(
            "Scheduled Scan",
            f"Modules: {', '.join(modules)} | Duration: {duration}s")

        # Trigger alert
        self.alert_manager.trigger(
            "Scheduled Scan Complete",
            f"Scanned: {', '.join(modules)}",
            "Low")

    def _refresh_scheduler_status(self):
        """Update the scheduler status label."""
        cfg = self.scheduler_engine.config
        if cfg.get("enabled", False):
            label = cfg.get("interval_label", "Every 1 hour")
            runs = cfg.get("runs_completed", 0)
            self.scheduler_status_lbl.configure(
                text=f"\u25cf Scheduler: Active ({label}) | "
                     f"Runs: {runs}",
                text_color=COLOR_SUCCESS)
            self.scheduler_toggle_btn.configure(
                text="\u23f9 Stop Scheduler",
                fg_color=COLOR_DANGER)
        else:
            self.scheduler_status_lbl.configure(
                text="\u25cf Scheduler: Inactive",
                text_color=COLOR_TEXT_DIM)
            self.scheduler_toggle_btn.configure(
                text="\u25b6\ufe0f Start Scheduler",
                fg_color=COLOR_SUCCESS)

    def _refresh_scheduler_history(self):
        """Refresh the scan history console."""
        history = scan_scheduler.get_history()
        box = self.scheduler_box
        self._cclear(box)

        if not history:
            self._cwrite(box,
                "\n  No scheduled scans have been executed yet.\n",
                "dim")
        else:
            self._cwrite(box,
                "\n  === SCHEDULED SCAN HISTORY ===\n\n", "cyan")
            self._cwrite(box,
                f"  {'#':<5} {'TIMESTAMP':<22} {'MODULES':<35} "
                f"{'STATUS':<8} DURATION\n", "dim")
            self._cwrite(box,
                f"  {'-'*5} {'-'*22} {'-'*35} {'-'*8} "
                f"{'-'*8}\n", "dim")

            for entry in reversed(history[-50:]):  # type: ignore[index]
                num = entry.get("run_number", 0)
                ts = entry.get("timestamp", "")[:19]
                mods = ", ".join(entry.get("modules", []))
                status = entry.get("status", "?")
                dur = entry.get("duration_seconds", 0)
                tag = "green" if status == "ok" else "red"

                self._cwrite(box,
                    f"  {num:<5} {ts:<22} {mods:<35} ", "")
                self._cwrite(box, f"{status.upper():<8} ", tag)
                self._cwrite(box, f"{dur}s\n", "dim")

        box.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════════
    #  THREAT TIMELINE TAB
    # ══════════════════════════════════════════════════════════════════════

    def setup_timeline_tab(self):
        """Build the Threat Timeline tab."""
        _page = self.timeline_tab
        ctk.CTkLabel(_page, text="\ud83d\udcc8 Threat Timeline",
                     font=FONT_TITLE, text_color="white").pack(
            pady=(22, 2), padx=24, anchor="w")
        ctk.CTkLabel(_page,
                     text="Chronological history of all security events "
                          "and threats",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(
            padx=24, anchor="w", pady=(0, 12))

        _scroll = ctk.CTkScrollableFrame(_page, fg_color="#0f1a2e",
                                         scrollbar_button_color="#334155",
                                         scrollbar_button_hover_color=COLOR_ACCENT)
        _scroll.pack(fill="both", expand=True, padx=0, pady=0)
        frame = _scroll

        # ── Statistics card ──────────────────────────────────────────────
        stats_card = self._make_card(frame, "Timeline Statistics", "\ud83d\udcca")

        stat_row = ctk.CTkFrame(stats_card, fg_color="transparent")
        stat_row.pack(fill="x", pady=4)

        self.timeline_stats_lbl = ctk.CTkLabel(
            stat_row, text="Loading statistics...",
            font=FONT_BODY, text_color=COLOR_TEXT_DIM)
        self.timeline_stats_lbl.pack(anchor="w", padx=4)

        # Stat boxes row
        self._tl_stat_boxes: dict[str, ctk.CTkLabel] = {}
        box_row = ctk.CTkFrame(stats_card, fg_color="transparent")
        box_row.pack(fill="x", pady=(4, 8))

        for label, key, color in [
            ("Last 24h", "24h", COLOR_ACCENT),
            ("Last 7d", "7d", COLOR_WARNING),
            ("Last 30d", "30d", "#7c3aed"),
            ("Total", "total", COLOR_TEXT_DIM),
        ]:
            mini = ctk.CTkFrame(box_row, fg_color=COLOR_CARD,
                                corner_radius=8, border_width=1,
                                border_color="#334155")
            mini.pack(side="left", padx=6, pady=2, expand=True,
                      fill="x")
            val_lbl = ctk.CTkLabel(mini, text="--",
                                    font=("Segoe UI", 22, "bold"),
                                    text_color=color)
            val_lbl.pack(pady=(8, 0))
            ctk.CTkLabel(mini, text=label, font=FONT_SMALL,
                         text_color=COLOR_TEXT_DIM).pack(pady=(0, 8))
            self._tl_stat_boxes[key] = val_lbl

        # ── Controls row ─────────────────────────────────────────────────
        ctrl_frame = ctk.CTkFrame(frame, fg_color="transparent")
        ctrl_frame.pack(fill="x", padx=18, pady=(0, 8))

        ctk.CTkLabel(ctrl_frame, text="Filter:",
                     font=FONT_BODY).pack(side="left", padx=4)

        filter_options = [
            "All Events", "Malware", "Firewall", "Network",
            "Honeypot", "Port", "Startup", "Scan", "System",
        ]
        self.timeline_filter_var = ctk.StringVar(value="All Events")
        filter_menu = ctk.CTkOptionMenu(
            ctrl_frame, values=filter_options,
            variable=self.timeline_filter_var, width=160,
            command=lambda _: self._refresh_timeline())
        filter_menu.pack(side="left", padx=8)

        refresh_btn = ctk.CTkButton(
            ctrl_frame, text="\ud83d\udd04 Refresh", height=32,
            fg_color="#475569", hover_color=COLOR_NAV_HOVER,
            command=self._refresh_timeline)
        refresh_btn.pack(side="left", padx=5)

        clear_btn = ctk.CTkButton(
            ctrl_frame, text="\ud83d\uddd1\ufe0f Clear", height=32,
            fg_color=COLOR_DANGER, hover_color="#991b1b",
            command=self._clear_timeline)
        clear_btn.pack(side="left", padx=5)

        # ── Timeline console ─────────────────────────────────────────────
        timeline_card = self._make_card(frame, "Event History", "\ud83d\uddd3\ufe0f")
        self.timeline_box = self._make_console(timeline_card)

        # Load initial data
        self._refresh_timeline()

    def _refresh_timeline(self):
        """Refresh the timeline display with current filter."""
        # Determine filter
        filter_val = self.timeline_filter_var.get()
        event_type = None
        if filter_val != "All Events":
            type_map = {
                "Malware": threat_timeline.EVENT_MALWARE,
                "Firewall": threat_timeline.EVENT_FIREWALL,
                "Network": threat_timeline.EVENT_NETWORK,
                "Honeypot": threat_timeline.EVENT_HONEYPOT,
                "Port": threat_timeline.EVENT_PORT,
                "Startup": threat_timeline.EVENT_STARTUP,
                "Scan": threat_timeline.EVENT_SCAN,
                "System": threat_timeline.EVENT_SYSTEM,
            }
            event_type = type_map.get(filter_val)

        events = threat_timeline.get_timeline(
            limit=200, event_type=event_type)
        stats = threat_timeline.get_statistics()

        # Update statistics
        self._tl_stat_boxes["24h"].configure(
            text=str(stats.get("last_24h", 0)))
        self._tl_stat_boxes["7d"].configure(
            text=str(stats.get("last_7d", 0)))
        self._tl_stat_boxes["30d"].configure(
            text=str(stats.get("last_30d", 0)))
        self._tl_stat_boxes["total"].configure(
            text=str(stats.get("total_events", 0)))

        trend = stats.get("trend", "stable")
        trend_icon = (
            "Trend: Increasing" if trend == "increasing"
            else "Trend: Decreasing" if trend == "decreasing"
            else "Trend: Stable")
        trend_color = (
            COLOR_DANGER if trend == "increasing"
            else COLOR_SUCCESS if trend == "decreasing"
            else COLOR_TEXT_DIM)
        self.timeline_stats_lbl.configure(
            text=f"Total: {stats.get('total_events', 0)} events | "
                 f"{trend_icon}",
            text_color=trend_color)

        # Render timeline
        box = self.timeline_box
        self._cclear(box)

        if not events:
            self._cwrite(box,
                "\n  No events recorded yet.\n\n"
                "  Events will appear here as you run scans, "
                "detect threats,\n"
                "  and monitor honeypots.\n", "dim")
        else:
            self._cwrite(box,
                "\n  === THREAT TIMELINE ===\n\n", "cyan")

            current_date = ""
            for evt in events:
                # Date header
                evt_date = evt.get("date", "")
                if evt_date != current_date:
                    current_date = evt_date
                    self._cwrite(box,
                        f"\n  --- {current_date} "
                        f"{'- ' * 25}\n\n", "cyan")

                evt_time = evt.get("time", "??:??:??")
                severity = evt.get("severity", "Low")
                title = evt.get("title", "Unknown")
                desc = evt.get("description", "")
                etype = evt.get("type", "system")

                sev_tag = (
                    "red" if severity in ("High", "Critical")
                    else "orange" if severity == "Medium"
                    else "green")

                type_icons = {
                    "malware": "[MAL]",
                    "firewall": "[FW] ",
                    "network": "[NET]",
                    "honeypot": "[HP] ",
                    "port": "[PRT]",
                    "startup": "[STR]",
                    "scan": "[SCN]",
                    "system": "[SYS]",
                }
                icon = type_icons.get(etype, "[???]")

                self._cwrite(box,
                    f"  {evt_time}  ", "dim")
                self._cwrite(box,
                    f"{icon} ", "cyan")
                self._cwrite(box,
                    f"[{severity:8s}] ", sev_tag)
                self._cwrite(box, f"{title}\n", "")

                if desc:
                    self._cwrite(box,
                        f"            {desc}\n", "dim")

        box.configure(state="disabled")

    def _clear_timeline(self):
        """Clear all timeline events."""
        threat_timeline.clear_timeline()
        self._refresh_timeline()
        self.status_var.set("Threat timeline cleared")

    # ══════════════════════════════════════════════════════════════════════
    #  PROCESS MONITOR TAB
    # ══════════════════════════════════════════════════════════════════════

    def setup_process_tab(self):
        """Build the Hidden Suspicious Process Detector UI."""
        frame = self.process_tab

        # ── Header ──────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(frame, fg_color="transparent")
        hdr.pack(fill="x", padx=28, pady=(28, 12))
        ctk.CTkLabel(hdr, text="🔬  Process Monitor",
                     font=FONT_TITLE, text_color="white").pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text="Scan running processes and detect hidden or suspicious activity via heuristic analysis.",
                     font=FONT_BODY, text_color=COLOR_TEXT_DIM).pack(anchor="w")

        # ── Controls bar ────────────────────────────────────────────────────
        ctrl_bar = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=8)
        ctrl_bar.pack(fill="x", padx=28, pady=(0, 10))

        left_ctrl = ctk.CTkFrame(ctrl_bar, fg_color="transparent")
        left_ctrl.pack(side="left", padx=16, pady=12)

        self._proc_scan_btn = ctk.CTkButton(
            left_ctrl, text="🔬 Scan Processes", font=FONT_HEADING,
            fg_color=COLOR_ACCENT, hover_color=COLOR_NAV_HOVER,
            command=self._proc_start_scan, width=200, height=40,
        )
        self._proc_scan_btn.pack(side="left", padx=(0, 12))
        ToolTip(self._proc_scan_btn, "Scan all running processes")

        # Filter
        self._proc_filter_var = ctk.StringVar(value="All")
        ctk.CTkLabel(left_ctrl, text="Filter:", font=FONT_BODY,
                     text_color=COLOR_TEXT_DIM).pack(side="left", padx=(12, 4))
        filter_menu = ctk.CTkOptionMenu(
            left_ctrl, variable=self._proc_filter_var,
            values=["All", "Suspicious Only", "High Risk Only"],
            width=160, height=32,
            command=lambda _: self._proc_apply_filter(),
        )
        filter_menu.pack(side="left")
        ToolTip(filter_menu, "Filter displayed processes by risk level")

        # Stats (right side)
        stats_frame = ctk.CTkFrame(ctrl_bar, fg_color="transparent")
        stats_frame.pack(side="right", padx=16, pady=12)

        def _make_stat(parent, label_text):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.pack(side="left", padx=12)
            ctk.CTkLabel(f, text=label_text, font=("Segoe UI", 10),
                         text_color=COLOR_TEXT_DIM).pack()
            val = ctk.CTkLabel(f, text="--", font=("Segoe UI", 18, "bold"))
            val.pack()
            return val

        self._proc_total_lbl = _make_stat(stats_frame, "Total")
        self._proc_high_lbl  = _make_stat(stats_frame, "High")
        self._proc_med_lbl   = _make_stat(stats_frame, "Medium")
        self._proc_low_lbl   = _make_stat(stats_frame, "Low")

        self._proc_high_lbl.configure(text_color=COLOR_DANGER)
        self._proc_med_lbl.configure(text_color=COLOR_WARNING)
        self._proc_low_lbl.configure(text_color=COLOR_SUCCESS)

        # ── Results console ────────────────────────────────────────────────
        res_frame = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=8)
        res_frame.pack(fill="both", expand=True, padx=28, pady=(0, 10))

        ctk.CTkLabel(res_frame, text="PROCESS ANALYSIS",
                     font=("Segoe UI", 11, "bold"),
                     text_color=COLOR_TEXT_DIM).pack(anchor="w", padx=16, pady=(12, 0))

        self._proc_result_box = ctk.CTkTextbox(
            res_frame, font=FONT_MONO, fg_color="#0b1221",
            text_color="#e2e8f0", wrap="none",
        )
        self._proc_result_box.pack(fill="both", expand=True, padx=16, pady=(8, 10))

        box = self._proc_result_box
        box.tag_config("cyan",       foreground="#22d3ee")
        box.tag_config("green",      foreground="#4ade80")
        box.tag_config("bold_green", foreground="#22c55e")
        box.tag_config("orange",     foreground="#fbbf24")
        box.tag_config("bold_red",   foreground="#ef4444")
        box.tag_config("dim",        foreground="#64748b")
        box.tag_config("purple",     foreground="#c084fc")
        box.tag_config("white",      foreground="#f8fafc")

        box.insert("end", "  Ready to scan running processes.\n", "dim")
        box.insert("end", "  Click  \u2018\ud83d\udd2c Scan Processes\u2019  to analyse running system activity.\n", "dim")
        box.configure(state="disabled")

        # ── Action bar (bottom) ─────────────────────────────────────────────
        act_bar = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=8)
        act_bar.pack(fill="x", padx=28, pady=(0, 16))
        inner = ctk.CTkFrame(act_bar, fg_color="transparent")
        inner.pack(padx=16, pady=10)

        ctk.CTkLabel(inner, text="Quick Actions:", font=FONT_BODY,
                     text_color=COLOR_TEXT_DIM).pack(side="left", padx=(0, 12))

        # PID entry for targeted actions
        ctk.CTkLabel(inner, text="PID:", font=FONT_BODY,
                     text_color=COLOR_TEXT_DIM).pack(side="left", padx=(0, 4))
        self._proc_pid_entry = ctk.CTkEntry(
            inner, placeholder_text="e.g. 1234",
            width=90, height=32, font=FONT_BODY)
        self._proc_pid_entry.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            inner, text="📝 Details", height=32, width=100,
            fg_color="#334155", hover_color="#475569",
            command=self._proc_show_details,
        ).pack(side="left", padx=4)
        ToolTip(self._proc_pid_entry, "Enter a PID and use the action buttons")

        ctk.CTkButton(
            inner, text="✅ Trust", height=32, width=90,
            fg_color="#0f766e", hover_color="#0d5c57",
            command=self._proc_trust_pid,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            inner, text="⚠️ Terminate", height=32, width=110,
            fg_color=COLOR_DANGER, hover_color="#991b1b",
            command=self._proc_terminate_pid,
        ).pack(side="left", padx=4)

        # Store the last scan result for filtering / actions
        self._proc_last_result: dict = {}

    # ── Process scan lifecycle ────────────────────────────────────────────

    def _proc_start_scan(self):
        """Launch process scan in a background thread."""
        from modules import process_monitor  # type: ignore

        self._proc_scan_btn.configure(state="disabled")
        self.status_var.set("Scanning running processes…")
        self.progress.set(0.15)

        box = self._proc_result_box
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", "  [INIT] Enumerating running processes…\n", "dim")
        box.insert("end", "  [INFO] Measuring CPU usage (0.5 s interval)…\n", "dim")
        box.configure(state="disabled")

        def _run():
            self.progress.set(0.4)
            result = process_monitor.scan_processes(include_low_risk=True)
            self.root.after(0, self._proc_render_results, result)

        threading.Thread(target=_run, daemon=True).start()

    def _proc_render_results(self, result: dict):
        """Render the full scan outcome into the console."""
        self._proc_last_result = result

        box = self._proc_result_box
        box.configure(state="normal")
        box.delete("1.0", "end")

        if result.get("status") == "error":
            box.insert("end", f"  \u274c ERROR: {result.get('error')}\n", "bold_red")
            box.configure(state="disabled")
            self._proc_scan_btn.configure(state="normal")
            self.status_var.set("Process scan failed")
            self.progress.set(0)
            return

        procs = result.get("processes", [])
        summary = result.get("summary", {})

        # Apply current filter
        procs = self._proc_filter_list(procs)

        # ── Header row ───────────────────────────────────────────────
        box.insert("end", "  HIDDEN & SUSPICIOUS PROCESS DETECTOR\n", "cyan")
        box.insert("end", f"  Scanned at: {summary.get('scan_time', 'N/A')}\n", "dim")
        box.insert("end", f"  {'\u2500'*120}\n", "dim")
        box.insert("end",
            f"  {'#':<5} {'PROCESS NAME':<24} {'PID':<8} {'CPU%':<8} "
            f"{'MEM(MB)':<10} {'RISK':<8} {'SCORE':<7} REASON\n", "cyan")
        box.insert("end", f"  {'\u2500'*120}\n", "dim")

        # ── Process rows ─────────────────────────────────────────────
        for i, p in enumerate(procs, 1):
            name    = p["name"]
            disp    = (name[:21] + "\u2026") if len(name) > 22 else name
            risk    = p["risk_level"]
            reasons = p.get("risk_reasons", [])

            if risk == "High":
                icon, tag = "\ud83d\udd34", "bold_red"
            elif risk == "Medium":
                icon, tag = "\ud83d\udfe1", "orange"
            else:
                icon, tag = "\ud83d\udfe2", "green"

            main_reason = reasons[0] if reasons else "\u2014"

            box.insert("end",
                f"  {i:<5} {disp:<24} {p['pid']:<8} "
                f"{p['cpu_percent']:<8.1f} {p['memory_mb']:<10.1f} ", "dim")
            box.insert("end", f"{icon} {risk:<6} ", tag)
            box.insert("end", f"{p['risk_score']:<7} ", "purple")
            box.insert("end", f"{main_reason}\n", tag)

            # Additional reasons (indented)
            for reason in reasons[1:]:
                box.insert("end",
                    f"{'':>60}\u251c\u2500 {reason}\n", tag)

            # Path (dim)
            if p.get("exe_path"):
                path_display = p["exe_path"]
                if len(path_display) > 80:
                    path_display = "\u2026" + path_display[-77:]
                box.insert("end",
                    f"{'':>8}\u2514\u2500 Path: {path_display}\n", "dim")

        # ── Summary ─────────────────────────────────────────────────
        box.insert("end", f"\n  {'\u2500'*120}\n", "dim")
        box.insert("end", "\n  SCAN SUMMARY\n", "cyan")
        box.insert("end", f"  {'\u2500'*120}\n", "dim")
        box.insert("end", f"  Total Processes : {summary.get('total', 0)}\n", "white")
        box.insert("end", f"  Low Risk        : {summary.get('low', 0)}\n", "green")

        med_tag = "orange" if summary.get('medium', 0) > 0 else "green"
        box.insert("end", f"  Medium Risk     : {summary.get('medium', 0)}\n", med_tag)

        high_tag = "bold_red" if summary.get('high', 0) > 0 else "green"
        box.insert("end", f"  High Risk       : {summary.get('high', 0)}\n", high_tag)

        if summary.get('high', 0) > 0:
            box.insert("end",
                "\n  \ud83d\udd34 HIGH-RISK PROCESSES DETECTED \u2014 review entries above.\n", "bold_red")
            box.insert("end",
                "  Use the PID field below to view details, trust, or terminate.\n", "dim")

        box.insert("end", f"\n  {'\u2550'*120}\n", "dim")
        box.insert("end", "  Scan complete.\n", "dim")
        box.see("1.0")
        box.configure(state="disabled")

        # Update stat labels
        self._proc_total_lbl.configure(text=str(summary.get("total", 0)))
        self._proc_high_lbl.configure(text=str(summary.get("high", 0)))
        self._proc_med_lbl.configure(text=str(summary.get("medium", 0)))
        self._proc_low_lbl.configure(text=str(summary.get("low", 0)))

        # ── Log + alert ───────────────────────────────────────────────
        n_high = summary.get("high", 0)
        n_med  = summary.get("medium", 0)
        risk_overall = "High" if n_high > 0 else ("Medium" if n_med > 0 else "Low")

        log_storage.log_event(
            "Process Monitor",
            f"Scanned {summary.get('total', 0)} processes. "
            f"Found {n_high} high-risk, {n_med} medium-risk.",
            risk_overall)

        if risk_overall in ("High", "Medium"):
            self.alert_manager.trigger(
                "Process Monitor",
                f"Detected {n_high} high-risk and {n_med} medium-risk running processes.",
                risk_overall)

        # Store for report
        self.scan_results["process_monitor"] = result

        self._proc_scan_btn.configure(state="normal")
        self.status_var.set("Process scan complete")
        self.progress.set(1.0)

    # ── Filter helper ────────────────────────────────────────────────────

    def _proc_filter_list(self, procs: list) -> list:
        filt = self._proc_filter_var.get()
        if filt == "Suspicious Only":
            return [p for p in procs if p["risk_level"] in ("Medium", "High")]
        elif filt == "High Risk Only":
            return [p for p in procs if p["risk_level"] == "High"]
        return procs

    def _proc_apply_filter(self):
        """Re-render with the last scan data."""
        if self._proc_last_result:
            self._proc_render_results(self._proc_last_result)

    # ── Action handlers ──────────────────────────────────────────────────

    def _proc_get_pid(self) -> int | None:
        """Read PID from the entry field."""
        txt = self._proc_pid_entry.get().strip()
        if not txt:
            messagebox.showwarning("Process Monitor", "Enter a PID first.")
            return None
        try:
            return int(txt)
        except ValueError:
            messagebox.showerror("Process Monitor", f"'{txt}' is not a valid PID.")
            return None

    def _proc_find_by_pid(self, pid: int) -> dict | None:
        procs = self._proc_last_result.get("processes", [])
        for p in procs:
            if p["pid"] == pid:
                return p
        return None

    def _proc_show_details(self):
        """Show full info about a process in a popup."""
        pid = self._proc_get_pid()
        if pid is None:
            return
        proc = self._proc_find_by_pid(pid)
        if not proc:
            messagebox.showinfo("Process Monitor",
                                f"PID {pid} was not found in the last scan.")
            return

        # Build detail popup
        dlg = ctk.CTkToplevel(self.root)
        dlg.title(f"Process Details \u2014 PID {pid}")
        dlg.geometry("520x480")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.configure(fg_color="#0f172a")
        dlg.update_idletasks()
        x = (dlg.winfo_screenwidth() // 2) - 260
        y = (dlg.winfo_screenheight() // 2) - 240
        dlg.geometry(f"+{x}+{y}")

        risk = proc["risk_level"]
        r_color = COLOR_DANGER if risk == "High" else (
            COLOR_WARNING if risk == "Medium" else COLOR_SUCCESS)

        ctk.CTkLabel(dlg, text=f"\ud83d\udd2c  {proc['name']}",
                     font=FONT_TITLE, text_color="white").pack(pady=(16, 4))
        ctk.CTkLabel(dlg, text=f"Risk: {risk}  (score {proc['risk_score']})",
                     font=FONT_HEADING, text_color=r_color).pack()

        # Info card
        card = ctk.CTkFrame(dlg, fg_color=COLOR_CARD, corner_radius=10,
                            border_width=1, border_color="#334155")
        card.pack(fill="x", padx=20, pady=12)

        details = [
            ("PID",        str(proc["pid"])),
            ("CPU",        f"{proc['cpu_percent']}%"),
            ("Memory",     f"{proc['memory_mb']:.1f} MB"),
            ("User",       proc.get("username", "\u2014")),
            ("Status",     proc.get("status", "\u2014")),
            ("Parent",     f"{proc.get('parent_name', '\u2014')} (PID {proc.get('parent_pid', '\u2014')})"),
            ("Path",       proc.get("exe_path", "\u2014")),
            ("Trusted",    "\u2705 Yes" if proc.get("is_trusted") else "\u274c No"),
        ]

        for label, value in details:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(row, text=f"{label}:", font=FONT_BODY,
                         text_color=COLOR_TEXT_DIM, width=80,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=FONT_BODY,
                         text_color="white", anchor="w",
                         wraplength=350).pack(side="left", fill="x", expand=True)

        # Reasons
        if proc.get("risk_reasons"):
            ctk.CTkLabel(dlg, text="Detection Reasons",
                         font=FONT_HEADING, text_color="white").pack(
                anchor="w", padx=24, pady=(8, 4))
            reason_box = ctk.CTkTextbox(
                dlg, font=FONT_BODY, fg_color="#0b1221",
                text_color="#e2e8f0", height=100, wrap="word",
            )
            reason_box.pack(fill="x", padx=24, pady=(0, 12))
            for r in proc["risk_reasons"]:
                reason_box.insert("end", f"\u2022 {r}\n")
            reason_box.configure(state="disabled")

        ctk.CTkButton(
            dlg, text="Close", height=34,
            fg_color="#334155", hover_color="#475569",
            command=dlg.destroy,
        ).pack(pady=(0, 12))

    def _proc_trust_pid(self):
        """Add a process name to the whitelist."""
        from modules import process_monitor  # type: ignore
        pid = self._proc_get_pid()
        if pid is None:
            return
        proc = self._proc_find_by_pid(pid)
        if not proc:
            messagebox.showinfo("Process Monitor",
                                f"PID {pid} not in last scan.")
            return
        process_monitor.add_to_whitelist(proc["name"])
        messagebox.showinfo("Process Monitor",
                            f"'{proc['name']}' added to trusted list.\n"
                            f"Re-scan to update results.")
        self.status_var.set(f"Trusted: {proc['name']}")

    def _proc_terminate_pid(self):
        """Terminate a process by PID (with confirmation)."""
        from modules import process_monitor  # type: ignore
        pid = self._proc_get_pid()
        if pid is None:
            return
        proc = self._proc_find_by_pid(pid)
        name = proc["name"] if proc else f"PID {pid}"

        if not messagebox.askyesno(
                "Terminate Process",
                f"Are you sure you want to terminate:\n\n"
                f"  {name}  (PID {pid})\n\n"
                f"This cannot be undone."):
            return

        result = process_monitor.terminate_process(pid)
        if result["success"]:
            messagebox.showinfo("Process Monitor", result["message"])
            log_storage.log_event(
                "Process Monitor",
                f"Terminated: {name} (PID {pid})",
                "High")
        else:
            messagebox.showerror("Process Monitor", result["message"])

        self.status_var.set(result["message"])


if __name__ == '__main__':
    root = ctk.CTk()
    app = SystemScannerApp(root)

    def on_closing():
        # Hide all tooltips first so they don't stay on screen after close
        ToolTip.hide_all()
        # Stop background monitors gracefully
        try:
            app.pf_monitor.stop()
        except Exception:
            pass
        try:
            app.honeypot_monitor.stop()
        except Exception:
            pass
        try:
            app.tamper_monitor.stop()
        except Exception:
            pass
        try:
            for child in root.winfo_children():
                if isinstance(child, ctk.CTkToplevel):
                    try:
                        child.destroy()  # type: ignore[union-attr]
                    except Exception:
                        pass
        except Exception:
            pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
