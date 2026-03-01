# gui.py
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from PyQt5.QtCore import QProcess, QTimer, Qt, QStandardPaths
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QFormLayout, QGroupBox,
    QMessageBox, QSplitter, QTabWidget,
    QCheckBox, QComboBox, QFileDialog, QSpinBox, QScrollArea
)

from blocknet_client import BlockNetClient


# ----------------------------- PyInstaller-safe paths -----------------------------

def app_data_dir(app_name: str = "BlockNetGUI") -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    p = Path(base) / app_name
    p.mkdir(parents=True, exist_ok=True)
    return p


def resource_path(rel: str) -> Path:
    """
    Find files in dev mode or when frozen by PyInstaller.
    Looks in:
      - sys._MEIPASS (PyInstaller extraction dir)
      - folder next to the frozen exe
      - folder next to this script
    """
    candidates = []

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / rel)
        candidates.append(Path(meipass) / Path(rel).name)

    exe_dir = Path(sys.executable).resolve().parent
    candidates.append(exe_dir / rel)
    candidates.append(exe_dir / Path(rel).name)

    script_dir = Path(__file__).resolve().parent
    candidates.append(script_dir / rel)
    candidates.append(script_dir / Path(rel).name)

    for c in candidates:
        if c.exists():
            return c

    return script_dir / rel


CFG_PATH = app_data_dir() / "blocknet_gui_config.json"

# try both names
BIN_EXE = resource_path("BlockNet.exe")
if not BIN_EXE.exists():
    BIN_EXE = resource_path("blocknet.exe")


# ----------------------------- Dark theme ----------------------------------------

def apply_dark_theme(app: QApplication) -> None:
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.WindowText, QColor(230, 230, 230))
    palette.setColor(QPalette.Base, QColor(18, 18, 18))
    palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
    palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
    palette.setColor(QPalette.Text, QColor(230, 230, 230))
    palette.setColor(QPalette.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ButtonText, QColor(230, 230, 230))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(90, 170, 255))
    palette.setColor(QPalette.Highlight, QColor(60, 120, 200))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    app.setStyleSheet("""
        QGroupBox {
            border: 1px solid #3a3a3a;
            border-radius: 8px;
            margin-top: 10px;
            padding: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px 0 6px;
            color: #dcdcdc;
        }
        QLineEdit, QPlainTextEdit {
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 6px;
            background: #121212;
            selection-background-color: #3c78c8;
        }
        QPushButton {
            border: 1px solid #4a4a4a;
            border-radius: 8px;
            padding: 8px 10px;
            background: #2d2d2d;
        }
        QPushButton:hover { background: #333333; }
        QPushButton:pressed { background: #1f1f1f; }
        QPushButton:disabled {
            color: #777;
            border-color: #333;
            background: #262626;
        }
        QTabWidget::pane {
            border: 1px solid #3a3a3a;
            border-radius: 8px;
            top: -1px;
        }
        QTabBar::tab {
            background: #2b2b2b;
            border: 1px solid #3a3a3a;
            padding: 8px 12px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 2px;
        }
        QTabBar::tab:selected { background: #1f1f1f; }

        QLabel#StatusPill {
            border-radius: 10px;
            padding: 4px 10px;
            font-weight: 600;
        }

        QSplitter::handle { background: #3a3a3a; }
        QSplitter::handle:horizontal {
            width: 10px;
            margin-left: 2px;
            margin-right: 2px;
            border-radius: 5px;
        }
        QSplitter::handle:vertical {
            height: 10px;
            margin-top: 2px;
            margin-bottom: 2px;
            border-radius: 5px;
            }
    """)


# ----------------------------- GUI helpers ---------------------------------------

def _default_spool_dir() -> str:
    tmp = os.environ.get("TEMP") or os.environ.get("TMP") or str(app_data_dir())
    return str(Path(tmp) / "blocknet_spool")


def _hbox(*widgets: QWidget) -> QWidget:
    w = QWidget()
    l = QHBoxLayout(w)
    l.setContentsMargins(0, 0, 0, 0)
    l.setSpacing(6)
    for x in widgets:
        l.addWidget(x)
    l.addStretch(1)
    return w


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _maybe_json_value(text: str) -> Any:
    """
    If it parses as JSON -> return JSON value.
    Otherwise -> return string.
    """
    t = (text or "").strip()
    if not t:
        return ""
    if t.startswith("{") or t.startswith("[") or t in ("true", "false", "null") or t[0].isdigit() or t[0] == "-":
        try:
            return json.loads(t)
        except Exception:
            return t
    return t


# ----------------------------- GUI -----------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BlockNet Control Panel")

        # Used to keep multi-line log chunks routed consistently
        self._last_ctx: Optional[str] = None  # "proxy" | "gateway" | None

        # process
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.SeparateChannels)
        self.proc.readyReadStandardOutput.connect(self._read_stdout)
        self.proc.readyReadStandardError.connect(self._read_stderr)
        self.proc.errorOccurred.connect(self._on_proc_error)
        self.proc.finished.connect(self._on_finished)

        # periodic stats
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._poll_stats)

        # debounced config save
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(350)
        self.save_timer.timeout.connect(self._save_cfg)

        # fonts
        self.mono = QFont("Consolas")
        self.mono.setStyleHint(QFont.Monospace)
        self.mono.setPointSize(10)

        # root
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        header = QHBoxLayout()
        title = QLabel("BlockNet")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)

        self.status_pill = QLabel("STOPPED")
        self.status_pill.setObjectName("StatusPill")

        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(self.status_pill)
        root.addLayout(header)

        # MAIN splitter: left controls + right outputs (drag handle)
        self.main_split = QSplitter(Qt.Horizontal)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.setHandleWidth(10)
        root.addWidget(self.main_split, 1)

        # LEFT: tabs
        self.left_tabs = QTabWidget()
        self.left_tabs.setMinimumWidth(420)
        self.main_split.addWidget(self.left_tabs)

        # RIGHT: output tabs
        self.right_tabs = QTabWidget()
        self.main_split.addWidget(self.right_tabs)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        # ---------------- Left Tabs ----------------
        self._build_left_server_tab()
        self._build_left_proxy_tab()
        self._build_left_gateway_tab()
        self._build_left_storage_tab()
        self._build_left_api_config_tab()

        # ---------------- Right Tabs ----------------
        self._build_right_output_tabs()
        self._build_right_api_tabs()

        self.statusBar().showMessage("Ready")

        # load config
        self._load_cfg()
        self._sync_relay_from_host_port()
        self._wire_autosave()

        self.main_split.splitterMoved.connect(lambda *_: self._schedule_save())

    # ---------------- Build: Left Tabs ----------------

    def _wrap_scroll(self, inner: QWidget) -> QWidget:
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setFrameShape(QScrollArea.NoFrame)
        sc.setWidget(inner)
        return sc

    def _build_left_server_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("Connection / Server")
        fl = QFormLayout(gb)

        self.ed_host = QLineEdit("127.0.0.1")
        self.ed_port = QLineEdit("38888")
        self.ed_relay = QLineEdit("127.0.0.1:38888")
        self.ed_token = QLineEdit("")
        self.ed_token.setEchoMode(QLineEdit.Password)
        self.ed_spool = QLineEdit(_default_spool_dir())

        # NEW: thread count for blocknet.exe
        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(0, 4096)
        self.sp_threads.setValue(0)  # 0 = use BlockNet default/auto
        self.ed_threads_flag = QLineEdit("--threads")
        self.ed_threads_flag.setPlaceholderText("e.g. --threads or -t (leave default if unsure)")

        self.ed_server_extra = QLineEdit("")
        self.ed_server_extra.setPlaceholderText('extra args (optional), e.g. --log-level info')

        fl.addRow("Listen host", self.ed_host)
        fl.addRow("Listen port", self.ed_port)
        fl.addRow("Relay (host:port)", self.ed_relay)
        fl.addRow("Token", self.ed_token)
        fl.addRow("Spool dir", self.ed_spool)
        fl.addRow("Threads (0=auto)", self.sp_threads)
        fl.addRow("Threads flag", self.ed_threads_flag)
        fl.addRow("Server extra", self.ed_server_extra)

        btn_row = QHBoxLayout()
        self.btn_gen = QPushButton("Generate Token")
        self.btn_start = QPushButton("Start")
        self.btn_stop = QPushButton("Stop")
        btn_row.addWidget(self.btn_gen)
        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        fl.addRow(btn_row)

        btn_row2 = QHBoxLayout()
        self.btn_stats = QPushButton("Fetch Stats")
        self.btn_clear_out = QPushButton("Clear Output")
        self.btn_clear_log = QPushButton("Clear Console")
        btn_row2.addWidget(self.btn_stats)
        btn_row2.addWidget(self.btn_clear_out)
        btn_row2.addWidget(self.btn_clear_log)
        fl.addRow(btn_row2)

        self.btn_gen.clicked.connect(self._gen_token)
        self.btn_start.clicked.connect(self._start_server)
        self.btn_stop.clicked.connect(self._stop_server)
        self.btn_stats.clicked.connect(self._poll_stats)

        lay.addWidget(gb)

        # Quick status strip
        gb2 = QGroupBox("Quick Actions")
        l2 = QVBoxLayout(gb2)
        self.btn_api_ping = QPushButton("API: /v1/ping")
        self.btn_rx_status = QPushButton("API: RandomX status")
        self.btn_web_test = QPushButton("API: Web fetch (example.com)")
        l2.addWidget(self.btn_api_ping)
        l2.addWidget(self.btn_rx_status)
        l2.addWidget(self.btn_web_test)
        lay.addWidget(gb2)

        self.btn_api_ping.clicked.connect(self._do_api_ping)
        self.btn_rx_status.clicked.connect(self._do_randomx_status)
        self.btn_web_test.clicked.connect(self._do_web_example)

        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Server")

        self._set_running(False)

    def _build_left_proxy_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb_proxy = QGroupBox("TLS Proxy (optional)")
        pfl = QFormLayout(gb_proxy)

        self.cb_proxy = QCheckBox("Enable proxy (HTTPS -> backend HTTP)")
        self.cb_proxy.setChecked(False)

        self.ed_proxy_listen = QLineEdit("0.0.0.0:443")
        self.ed_proxy_backend = QLineEdit("")
        self.ed_proxy_cert = QLineEdit("")
        self.ed_proxy_key = QLineEdit("")
        self.btn_proxy_cert = QPushButton("Browse…")
        self.btn_proxy_key = QPushButton("Browse…")

        self.ed_proxy_inject = QLineEdit("")
        self.ed_proxy_allow = QLineEdit("")

        self.cmb_proxy_log = QComboBox()
        self.cmb_proxy_log.addItems(["none", "basic", "verbose"])
        self.cmb_proxy_log.setCurrentText("basic")

        pfl.addRow(self.cb_proxy)
        pfl.addRow("Proxy listen (host:port)", self.ed_proxy_listen)
        pfl.addRow("Proxy backend (host:port)", self.ed_proxy_backend)
        pfl.addRow("Proxy cert (.pem)", _hbox(self.ed_proxy_cert, self.btn_proxy_cert))
        pfl.addRow("Proxy key (.pem)", _hbox(self.ed_proxy_key, self.btn_proxy_key))
        pfl.addRow("Proxy inject token", self.ed_proxy_inject)
        pfl.addRow("Proxy allow list", self.ed_proxy_allow)
        pfl.addRow("Proxy log", self.cmb_proxy_log)

        self.btn_proxy_cert.clicked.connect(lambda: self._browse_file_into(self.ed_proxy_cert))
        self.btn_proxy_key.clicked.connect(lambda: self._browse_file_into(self.ed_proxy_key))

        lay.addWidget(gb_proxy)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Proxy")

    def _build_left_gateway_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb_gateway = QGroupBox("Edge Gateway (optional)")
        gfl = QFormLayout(gb_gateway)

        self.cb_gateway = QCheckBox("Enable gateway (HTTPS -> backend + sinkhole rules)")
        self.cb_gateway.setChecked(False)

        self.ed_gateway_listen = QLineEdit("0.0.0.0:443")
        self.ed_gateway_backend = QLineEdit("")
        self.ed_gateway_cert = QLineEdit("")
        self.ed_gateway_key = QLineEdit("")
        self.btn_gateway_cert = QPushButton("Browse…")
        self.btn_gateway_key = QPushButton("Browse…")

        self.ed_gateway_allow = QLineEdit("")
        self.cmb_gateway_log = QComboBox()
        self.cmb_gateway_log.addItems(["none", "basic", "verbose"])
        self.cmb_gateway_log.setCurrentText("basic")

        self.ed_gateway_extra = QLineEdit("")
        self.ed_gateway_extra.setPlaceholderText('extra args (optional), e.g. --gateway-sinkhole-file "rules.txt"')

        gfl.addRow(self.cb_gateway)
        gfl.addRow("Gateway listen (host:port)", self.ed_gateway_listen)
        gfl.addRow("Gateway backend (host:port)", self.ed_gateway_backend)
        gfl.addRow("Gateway cert (.pem)", _hbox(self.ed_gateway_cert, self.btn_gateway_cert))
        gfl.addRow("Gateway key (.pem)", _hbox(self.ed_gateway_key, self.btn_gateway_key))
        gfl.addRow("Gateway allow list", self.ed_gateway_allow)
        gfl.addRow("Gateway log", self.cmb_gateway_log)
        gfl.addRow("Gateway extra", self.ed_gateway_extra)

        self.btn_gateway_cert.clicked.connect(lambda: self._browse_file_into(self.ed_gateway_cert))
        self.btn_gateway_key.clicked.connect(lambda: self._browse_file_into(self.ed_gateway_key))

        lay.addWidget(gb_gateway)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Gateway")

    def _build_left_storage_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb_io = QGroupBox("Quick Put / Get")
        io = QFormLayout(gb_io)

        self.ed_key = QLineEdit("greeting")
        self.ed_mime = QLineEdit("text/plain")
        self.ed_put = QLineEdit("hello world")
        self.ed_get = QLineEdit("greeting")

        io.addRow("Key", self.ed_key)
        io.addRow("MIME", self.ed_mime)
        io.addRow("Put text", self.ed_put)
        io.addRow("Get (key or obj_...)", self.ed_get)

        io_btns = QHBoxLayout()
        self.btn_put = QPushButton("PUT")
        self.btn_get = QPushButton("GET")
        io_btns.addWidget(self.btn_put)
        io_btns.addWidget(self.btn_get)
        io.addRow(io_btns)

        self.btn_put.clicked.connect(self._do_put)
        self.btn_get.clicked.connect(self._do_get)

        lay.addWidget(gb_io)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Storage")

    def _build_left_api_config_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        # Core API toggles
        gb = QGroupBox("API Modules (server flags)")
        fl = QFormLayout(gb)

        self.cb_api = QCheckBox("Enable API module (--api on)")
        self.cb_api.setChecked(True)
        self.ed_api_prefix = QLineEdit("/v1")

        self.cb_api_media = QCheckBox("Enable Media API (--api-media on)")
        self.cb_api_media.setChecked(True)

        self.cb_api_randomx = QCheckBox("Enable RandomX API (--api-randomx on)")
        self.cb_api_randomx.setChecked(True)
        self.ed_randomx_dll = QLineEdit(r".\randomx-dll.dll")
        self.btn_randomx_dll = QPushButton("Browse…")

        self.cb_api_web = QCheckBox("Enable Web API (--api-web on)")
        self.cb_api_web.setChecked(True)

        self.cb_api_p2pool = QCheckBox("Enable P2Pool API (--api-p2pool on)")
        self.cb_api_p2pool.setChecked(False)

        # NEW: extra args passed only when p2pool api enabled
        self.ed_p2pool_extra = QLineEdit("")
        self.ed_p2pool_extra.setPlaceholderText("extra p2pool args (optional), passed to BlockNet when --api-p2pool on")

        fl.addRow(self.cb_api)
        fl.addRow("API prefix", self.ed_api_prefix)
        fl.addRow(self.cb_api_media)
        fl.addRow(self.cb_api_randomx)
        fl.addRow("RandomX DLL", _hbox(self.ed_randomx_dll, self.btn_randomx_dll))
        fl.addRow(self.cb_api_web)
        fl.addRow(self.cb_api_p2pool)
        fl.addRow("P2Pool extra", self.ed_p2pool_extra)

        self.btn_randomx_dll.clicked.connect(lambda: self._browse_file_into(self.ed_randomx_dll))

        lay.addWidget(gb)

        # Web API safety tuning
        gbw = QGroupBox("Web API Safety / Limits")
        wfl = QFormLayout(gbw)

        self.cb_web_block_private = QCheckBox("Block private hosts (localhost, .local/.lan, private IPv4)")
        self.cb_web_block_private.setChecked(True)

        self.cb_web_allow_http = QCheckBox("Allow http://")
        self.cb_web_allow_http.setChecked(True)

        self.cb_web_allow_https = QCheckBox("Allow https:// (requires OpenSSL build)")
        self.cb_web_allow_https.setChecked(True)

        self.sp_web_timeout = QSpinBox()
        self.sp_web_timeout.setRange(1000, 60000)
        self.sp_web_timeout.setSingleStep(500)
        self.sp_web_timeout.setValue(8000)

        self.sp_web_max_page_kb = QSpinBox()
        self.sp_web_max_page_kb.setRange(8, 4096)
        self.sp_web_max_page_kb.setValue(256)

        self.sp_web_max_scripts = QSpinBox()
        self.sp_web_max_scripts.setRange(0, 256)
        self.sp_web_max_scripts.setValue(32)

        self.ed_web_ua = QLineEdit("BlockNetWeb/1.0")

        wfl.addRow(self.cb_web_block_private)
        wfl.addRow(self.cb_web_allow_http)
        wfl.addRow(self.cb_web_allow_https)
        wfl.addRow("Timeout (ms)", self.sp_web_timeout)
        wfl.addRow("Max page (KB)", self.sp_web_max_page_kb)
        wfl.addRow("Max scripts", self.sp_web_max_scripts)
        wfl.addRow("User-Agent", self.ed_web_ua)

        lay.addWidget(gbw)

        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "API Config")

    # ---------------- Build: Right Tabs ----------------

    def _build_right_output_tabs(self) -> None:
        # Output
        out_tab = QWidget()
        out_l = QVBoxLayout(out_tab)
        self.txt_out = QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(self.mono)
        out_l.addWidget(self.txt_out)
        self.right_tabs.addTab(out_tab, "Output")

        # Server Console
        log_tab = QWidget()
        log_l = QVBoxLayout(log_tab)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(self.mono)
        log_l.addWidget(self.txt_log)
        self.right_tabs.addTab(log_tab, "Server Console")

        # Proxy
        proxy_tab = QWidget()
        proxy_l = QVBoxLayout(proxy_tab)
        self.txt_proxy = QPlainTextEdit()
        self.txt_proxy.setReadOnly(True)
        self.txt_proxy.setFont(self.mono)
        proxy_l.addWidget(self.txt_proxy)
        self.right_tabs.addTab(proxy_tab, "Proxy")

        # Gateway
        gateway_tab = QWidget()
        gateway_l = QVBoxLayout(gateway_tab)
        self.txt_gateway = QPlainTextEdit()
        self.txt_gateway.setReadOnly(True)
        self.txt_gateway.setFont(self.mono)
        gateway_l.addWidget(self.txt_gateway)
        self.right_tabs.addTab(gateway_tab, "Gateway")

        # bind clear buttons now that editors exist
        self.btn_clear_out.clicked.connect(lambda: self.txt_out.setPlainText(""))
        self.btn_clear_log.clicked.connect(lambda: self.txt_log.setPlainText(""))

    def _build_right_api_tabs(self) -> None:
        self.right_tabs.addTab(self._tab_texttovec(), "API: TextToVec")
        self.right_tabs.addTab(self._tab_vectortext(), "API: VectorText")
        self.right_tabs.addTab(self._tab_web(), "API: Web")
        self.right_tabs.addTab(self._tab_media(), "API: Media")
        self.right_tabs.addTab(self._tab_randomx(), "API: RandomX")
        self.right_tabs.addTab(self._tab_p2pool(), "API: P2Pool")

    def _mk_api_out(self) -> QPlainTextEdit:
        w = QPlainTextEdit()
        w.setReadOnly(True)
        w.setFont(self.mono)
        return w

    def _tab_texttovec(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("POST /v1/texttovec")
        fl = QFormLayout(gb)

        self.ttv_text = QPlainTextEdit()
        self.ttv_text.setFont(self.mono)
        self.ttv_text.setPlainText("hello from blocknet")

        self.ttv_dim = QSpinBox()
        self.ttv_dim.setRange(1, 32768)
        self.ttv_dim.setValue(1024)

        self.ttv_norm = QCheckBox("normalize")
        self.ttv_norm.setChecked(True)

        self.ttv_outfmt = QComboBox()
        self.ttv_outfmt.addItems(["b64f32", "list"])
        self.ttv_outfmt.setCurrentText("b64f32")

        self.btn_ttv = QPushButton("Run texttovec")
        self.btn_ttv.clicked.connect(self._do_texttovec)

        fl.addRow("text", self.ttv_text)
        fl.addRow("dim", self.ttv_dim)
        fl.addRow(self.ttv_norm)
        fl.addRow("output", self.ttv_outfmt)
        fl.addRow(self.btn_ttv)

        lay.addWidget(gb)
        self.ttv_out = self._mk_api_out()
        lay.addWidget(self.ttv_out, 1)
        return tab

    def _tab_vectortext(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("POST /v1/vectortext")
        fl = QFormLayout(gb)

        self.vtxt_prompt = QPlainTextEdit()
        self.vtxt_prompt.setFont(self.mono)
        self.vtxt_prompt.setPlainText("Write a short response that uses the payload and the vector top dims.")

        self.vtxt_payload = QPlainTextEdit()
        self.vtxt_payload.setFont(self.mono)
        self.vtxt_payload.setPlainText("payload goes here")

        self.vtxt_key = QLineEdit("")
        self.vtxt_lexicon_key = QLineEdit("")
        self.vtxt_context_key = QLineEdit("")

        self.vtxt_idf = QLineEdit("")
        self.vtxt_tokens = QLineEdit("")

        self.vtxt_lexicon_inline = QPlainTextEdit()
        self.vtxt_lexicon_inline.setFont(self.mono)
        self.vtxt_lexicon_inline.setPlaceholderText("optional lexicon (string or JSON)")

        self.vtxt_context_inline = QPlainTextEdit()
        self.vtxt_context_inline.setFont(self.mono)
        self.vtxt_context_inline.setPlaceholderText("optional context (string or JSON)")

        self.vtxt_vector_json = QPlainTextEdit()
        self.vtxt_vector_json.setFont(self.mono)
        self.vtxt_vector_json.setPlainText("[0.1, -0.2, 0.33, 0.04]")

        self.vtxt_vector_b64 = QLineEdit("")
        self.vtxt_vector_b64.setPlaceholderText("optional vector_b64f32 (overrides vector list if set)")

        self.vtxt_max_tokens = QSpinBox()
        self.vtxt_max_tokens.setRange(1, 2000)
        self.vtxt_max_tokens.setValue(160)

        self.vtxt_topk = QSpinBox()
        self.vtxt_topk.setRange(1, 256)
        self.vtxt_topk.setValue(16)

        self.vtxt_seed = QLineEdit("0")
        self.vtxt_seed.setPlaceholderText("0 or string/number seed")

        self.btn_vtxt = QPushButton("Run vectortext")
        self.btn_vtxt.clicked.connect(self._do_vectortext)

        fl.addRow("prompt (required)", self.vtxt_prompt)
        fl.addRow("payload", self.vtxt_payload)
        fl.addRow("key", self.vtxt_key)
        fl.addRow("lexicon_key", self.vtxt_lexicon_key)
        fl.addRow("context_key", self.vtxt_context_key)
        fl.addRow("idf (optional)", self.vtxt_idf)
        fl.addRow("tokens (optional)", self.vtxt_tokens)
        fl.addRow("lexicon (inline)", self.vtxt_lexicon_inline)
        fl.addRow("context (inline)", self.vtxt_context_inline)
        fl.addRow("vector (JSON list)", self.vtxt_vector_json)
        fl.addRow("vector_b64f32", self.vtxt_vector_b64)
        fl.addRow("max_tokens", self.vtxt_max_tokens)
        fl.addRow("topk", self.vtxt_topk)
        fl.addRow("seed", self.vtxt_seed)
        fl.addRow(self.btn_vtxt)

        lay.addWidget(gb)
        self.vtxt_out = self._mk_api_out()
        lay.addWidget(self.vtxt_out, 1)
        return tab

    def _tab_web(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        # ---------------- /web/fetch ----------------
        gb1 = QGroupBox("POST /v1/web/fetch")
        fl1 = QFormLayout(gb1)

        self.web_url = QLineEdit("https://example.com")
        self.web_mode = QComboBox()
        self.web_mode.addItems(["html", "text"])
        self.web_include_js = QCheckBox("include_js (also fetch external JS bodies)")
        self.web_include_js.setChecked(False)

        self.web_max_kb = QSpinBox()
        self.web_max_kb.setRange(8, 4096)
        self.web_max_kb.setValue(256)

        self.web_max_scripts = QSpinBox()
        self.web_max_scripts.setRange(0, 256)
        self.web_max_scripts.setValue(32)

        self.btn_web_fetch = QPushButton("Run web/fetch")
        self.btn_web_fetch.clicked.connect(self._do_web_fetch)

        fl1.addRow("url", self.web_url)
        fl1.addRow("mode", self.web_mode)
        fl1.addRow(self.web_include_js)
        fl1.addRow("max_bytes (KB)", self.web_max_kb)
        fl1.addRow("max_scripts", self.web_max_scripts)
        fl1.addRow(self.btn_web_fetch)

        # ---------------- /web/js ----------------
        gb2 = QGroupBox("POST /v1/web/js")
        fl2 = QFormLayout(gb2)

        self.webjs_url = QLineEdit("https://example.com")
        self.webjs_fetch_bodies = QCheckBox("fetch_bodies (download each JS body)")
        self.webjs_fetch_bodies.setChecked(True)

        self.webjs_max_scripts = QSpinBox()
        self.webjs_max_scripts.setRange(0, 256)
        self.webjs_max_scripts.setValue(16)

        self.btn_web_js = QPushButton("Run web/js")
        self.btn_web_js.clicked.connect(self._do_web_js)

        fl2.addRow("url", self.webjs_url)
        fl2.addRow(self.webjs_fetch_bodies)
        fl2.addRow("max_scripts", self.webjs_max_scripts)
        fl2.addRow(self.btn_web_js)

        # ---------------- /web/links ----------------
        gb3 = QGroupBox("POST /v1/web/links")
        fl3 = QFormLayout(gb3)

        self.weblinks_url = QLineEdit("https://example.com")
        self.weblinks_filter = QComboBox()
        self.weblinks_filter.addItems(["all", "same-origin", "external-only"])
        self.weblinks_filter.setCurrentText("all")

        self.weblinks_max = QSpinBox()
        self.weblinks_max.setRange(1, 8192)
        self.weblinks_max.setValue(512)

        self.btn_web_links = QPushButton("Run web/links")
        self.btn_web_links.clicked.connect(self._do_web_links)

        fl3.addRow("url", self.weblinks_url)
        fl3.addRow("filter", self.weblinks_filter)
        fl3.addRow("max_links", self.weblinks_max)
        fl3.addRow(self.btn_web_links)

        # ---------------- /web/rss_find ----------------
        gb4 = QGroupBox("POST /v1/web/rss_find")
        fl4 = QFormLayout(gb4)

        self.webrss_url = QLineEdit("https://example.com")
        self.webrss_max = QSpinBox()
        self.webrss_max.setRange(1, 512)
        self.webrss_max.setValue(64)

        self.btn_web_rss = QPushButton("Run web/rss_find")
        self.btn_web_rss.clicked.connect(self._do_web_rss_find)

        fl4.addRow("url", self.webrss_url)
        fl4.addRow("max_feeds", self.webrss_max)
        fl4.addRow(self.btn_web_rss)

        lay.addWidget(gb1)
        lay.addWidget(gb2)
        lay.addWidget(gb3)
        lay.addWidget(gb4)

        self.web_out = self._mk_api_out()
        lay.addWidget(self.web_out, 1)
        return tab

    def _tab_media(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        # ImageToVec
        gbi = QGroupBox("POST /v1/imagetovec")
        fli = QFormLayout(gbi)

        self.img_path = QLineEdit("")
        self.btn_img_browse = QPushButton("Browse…")
        self.btn_img_browse.clicked.connect(
            lambda: self._browse_file_into(
                self.img_path,
                filter_str="Images (*.png *.jpg *.jpeg *.webp *.bmp *.gif);;All files (*.*)"
            )
        )

        self.img_dim = QSpinBox()
        self.img_dim.setRange(1, 32768)
        self.img_dim.setValue(1024)

        self.img_norm = QCheckBox("normalize")
        self.img_norm.setChecked(True)

        self.img_outfmt = QComboBox()
        self.img_outfmt.addItems(["b64f32", "list"])
        self.img_outfmt.setCurrentText("b64f32")

        self.btn_imagetovec = QPushButton("Run imagetovec")
        self.btn_imagetovec.clicked.connect(self._do_imagetovec)

        fli.addRow("image file", _hbox(self.img_path, self.btn_img_browse))
        fli.addRow("dim", self.img_dim)
        fli.addRow(self.img_norm)
        fli.addRow("output", self.img_outfmt)
        fli.addRow(self.btn_imagetovec)

        # VideoToVec
        gbv = QGroupBox("POST /v1/videotovec")
        flv = QFormLayout(gbv)

        self.vid_path = QLineEdit("")
        self.btn_vid_browse = QPushButton("Browse…")
        self.btn_vid_browse.clicked.connect(
            lambda: self._browse_file_into(
                self.vid_path,
                filter_str="Videos (*.mp4 *.mkv *.webm *.mov *.avi);;All files (*.*)"
            )
        )

        self.vid_dim = QSpinBox()
        self.vid_dim.setRange(1, 32768)
        self.vid_dim.setValue(1024)

        self.vid_norm = QCheckBox("normalize")
        self.vid_norm.setChecked(True)

        self.vid_outfmt = QComboBox()
        self.vid_outfmt.addItems(["b64f32", "list"])
        self.vid_outfmt.setCurrentText("b64f32")

        self.vid_max_frames = QSpinBox()
        self.vid_max_frames.setRange(1, 5000)
        self.vid_max_frames.setValue(256)

        self.btn_videotovec = QPushButton("Run videotovec")
        self.btn_videotovec.clicked.connect(self._do_videotovec)

        flv.addRow("video file", _hbox(self.vid_path, self.btn_vid_browse))
        flv.addRow("dim", self.vid_dim)
        flv.addRow(self.vid_norm)
        flv.addRow("output", self.vid_outfmt)
        flv.addRow("max_frames", self.vid_max_frames)
        flv.addRow(self.btn_videotovec)

        lay.addWidget(gbi)
        lay.addWidget(gbv)

        self.media_out = self._mk_api_out()
        lay.addWidget(self.media_out, 1)
        return tab

    def _tab_randomx(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb1 = QGroupBox("GET /v1/randomx/status")
        l1 = QVBoxLayout(gb1)
        self.btn_rxstat = QPushButton("Fetch RandomX status")
        self.btn_rxstat.clicked.connect(self._do_randomx_status)
        l1.addWidget(self.btn_rxstat)

        gb2 = QGroupBox("POST /v1/randomx/hash")
        fl = QFormLayout(gb2)

        self.rx_seed_hex = QLineEdit("")
        self.rx_data_mode = QComboBox()
        self.rx_data_mode.addItems(["data_b64", "data_hex"])
        self.rx_data_mode.setCurrentText("data_b64")
        self.rx_data = QPlainTextEdit()
        self.rx_data.setFont(self.mono)
        self.rx_data.setPlainText("")

        self.btn_rxhash = QPushButton("Compute RandomX hash")
        self.btn_rxhash.clicked.connect(self._do_randomx_hash)

        fl.addRow("seed_hex", self.rx_seed_hex)
        fl.addRow("data mode", self.rx_data_mode)
        fl.addRow("data", self.rx_data)
        fl.addRow(self.btn_rxhash)

        # Batch hashing
        gb3 = QGroupBox("POST /v1/randomx/hash_batch")
        flb = QFormLayout(gb3)

        self.rx_batch_items = QPlainTextEdit()
        self.rx_batch_items.setFont(self.mono)
        self.rx_batch_items.setPlainText(json.dumps([
            {"data_hex": "00"},
            {"data_hex": "ff"}
        ], indent=2))

        self.btn_rxhash_batch = QPushButton("Compute RandomX hash batch")
        self.btn_rxhash_batch.clicked.connect(self._do_randomx_hash_batch)

        flb.addRow("items (JSON array OR full body object)", self.rx_batch_items)
        flb.addRow(self.btn_rxhash_batch)

        lay.addWidget(gb1)
        lay.addWidget(gb2)
        lay.addWidget(gb3)

        self.rx_out = self._mk_api_out()
        lay.addWidget(self.rx_out, 1)
        return tab

    def _tab_p2pool(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        # NEW: open params patch (UI + optional body)
        gb0 = QGroupBox("Open session params (optional)")
        fl0 = QFormLayout(gb0)

        self.p2_open_host = QLineEdit("")
        self.p2_open_wallet = QLineEdit("")
        self.p2_open_rig = QLineEdit("")
        self.p2_open_threads = QSpinBox()
        self.p2_open_threads.setRange(0, 4096)
        self.p2_open_threads.setValue(0)

        self.p2_open_extra_json = QPlainTextEdit()
        self.p2_open_extra_json.setFont(self.mono)
        self.p2_open_extra_json.setPlaceholderText('Optional JSON object merged into /p2pool/open body, e.g. {"mini": true}')

        fl0.addRow("host (optional)", self.p2_open_host)
        fl0.addRow("wallet (optional)", self.p2_open_wallet)
        fl0.addRow("rig_id (optional)", self.p2_open_rig)
        fl0.addRow("threads (0=default)", self.p2_open_threads)
        fl0.addRow("extra JSON (object)", self.p2_open_extra_json)

        gb = QGroupBox("P2Pool API (session-based)")
        fl = QFormLayout(gb)

        self.p2_session = QLineEdit("")
        self.btn_p2_open = QPushButton("Open session")
        self.btn_p2_job = QPushButton("Get job")
        self.btn_p2_poll = QPushButton("Poll logs")
        self.btn_p2_close = QPushButton("Close session")

        self.p2_poll_max = QSpinBox()
        self.p2_poll_max.setRange(1, 256)
        self.p2_poll_max.setValue(32)

        self.btn_p2_open.clicked.connect(self._do_p2pool_open)
        self.btn_p2_job.clicked.connect(self._do_p2pool_job)
        self.btn_p2_poll.clicked.connect(self._do_p2pool_poll)
        self.btn_p2_close.clicked.connect(self._do_p2pool_close)

        fl.addRow("session", self.p2_session)
        fl.addRow(_hbox(self.btn_p2_open, self.btn_p2_job, self.btn_p2_poll, self.btn_p2_close))
        fl.addRow("poll max_msgs", self.p2_poll_max)

        gb2 = QGroupBox("Submit share (POST /v1/p2pool/submit)")
        fl2 = QFormLayout(gb2)

        self.p2_submit_json = QPlainTextEdit()
        self.p2_submit_json.setFont(self.mono)
        self.p2_submit_json.setPlainText(json.dumps({
            "session": "",
            "line": "submit ...",
        }, indent=2))

        self.btn_p2_submit = QPushButton("Submit")
        self.btn_p2_submit.clicked.connect(self._do_p2pool_submit)

        fl2.addRow("payload (JSON)", self.p2_submit_json)
        fl2.addRow(self.btn_p2_submit)

        lay.addWidget(gb0)
        lay.addWidget(gb)
        lay.addWidget(gb2)

        self.p2_out = self._mk_api_out()
        lay.addWidget(self.p2_out, 1)
        return tab

    # ---------------- helpers ----------------

    def _schedule_save(self) -> None:
        self.save_timer.start()

    def _set_running(self, running: bool) -> None:
        if running:
            self.status_pill.setText("RUNNING")
            self.status_pill.setStyleSheet("background:#1f4d2e; color:#eaffea;")
        else:
            self.status_pill.setText("STOPPED")
            self.status_pill.setStyleSheet("background:#4a1f1f; color:#ffecec;")

        if hasattr(self, "btn_start") and hasattr(self, "btn_stop"):
            self.btn_start.setDisabled(running)
            self.btn_stop.setDisabled(not running)

    def _client(self) -> BlockNetClient:
        return BlockNetClient(self.ed_relay.text().strip(), self.ed_token.text().strip())

    def _append_plain(self, w: QPlainTextEdit, s: str, *, prefix: str = "") -> None:
        s = (s or "").replace("\r\n", "\n").replace("\r", "\n")
        for line in s.split("\n"):
            if line == "":
                continue
            w.appendPlainText(prefix + line)

        MAX_BLOCKS = 4000
        doc = w.document()
        if doc.blockCount() > MAX_BLOCKS:
            cursor = w.textCursor()
            cursor.movePosition(cursor.Start)
            for _ in range(doc.blockCount() - MAX_BLOCKS):
                cursor.select(cursor.LineUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()

    def _append_json(self, w: QPlainTextEdit, obj: Any) -> None:
        try:
            s = json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception:
            s = str(obj)
        self._append_plain(w, s)

    def _sync_relay_from_host_port(self) -> None:
        host = self.ed_host.text().strip() or "127.0.0.1"
        port = self.ed_port.text().strip() or "38888"
        self.ed_relay.setText(f"{host}:{port}")

    def _wire_autosave(self) -> None:
        edits = [
            self.ed_host, self.ed_port, self.ed_relay, self.ed_token, self.ed_spool,
            self.ed_threads_flag,  # NEW
            self.ed_server_extra,

            self.ed_proxy_listen, self.ed_proxy_backend, self.ed_proxy_cert, self.ed_proxy_key,
            self.ed_proxy_inject, self.ed_proxy_allow,

            self.ed_gateway_listen, self.ed_gateway_backend, self.ed_gateway_cert, self.ed_gateway_key,
            self.ed_gateway_allow, self.ed_gateway_extra,

            self.ed_key, self.ed_mime, self.ed_put, self.ed_get,

            self.ed_api_prefix, self.ed_randomx_dll, self.ed_web_ua,
            self.ed_p2pool_extra,  # NEW
        ]
        for e in edits:
            e.textChanged.connect(self._schedule_save)

        self.ed_host.textChanged.connect(self._sync_relay_from_host_port)
        self.ed_port.textChanged.connect(self._sync_relay_from_host_port)

        self.sp_threads.valueChanged.connect(self._schedule_save)  # NEW

        for cb in (
            self.cb_proxy, self.cb_gateway,
            self.cb_api, self.cb_api_media, self.cb_api_randomx, self.cb_api_web, self.cb_api_p2pool,
            self.cb_web_block_private, self.cb_web_allow_http, self.cb_web_allow_https
        ):
            cb.stateChanged.connect(self._schedule_save)

        for cmb in (self.cmb_proxy_log, self.cmb_gateway_log):
            cmb.currentTextChanged.connect(self._schedule_save)

        for sp in (self.sp_web_timeout, self.sp_web_max_page_kb, self.sp_web_max_scripts):
            sp.valueChanged.connect(self._schedule_save)

        # NEW: persist p2pool open defaults
        self.p2_open_host.textChanged.connect(self._schedule_save)
        self.p2_open_wallet.textChanged.connect(self._schedule_save)
        self.p2_open_rig.textChanged.connect(self._schedule_save)
        self.p2_open_threads.valueChanged.connect(self._schedule_save)
        self.p2_open_extra_json.textChanged.connect(self._schedule_save)

    def _browse_file_into(self, edit: QLineEdit, filter_str: str = "All files (*.*)") -> None:
        start_dir = str(Path.home())
        cur = edit.text().strip()
        if cur:
            try:
                p = Path(cur)
                if p.exists():
                    start_dir = str(p.parent)
            except Exception:
                pass

        path, _ = QFileDialog.getOpenFileName(self, "Select file", start_dir, filter_str)
        if path:
            edit.setText(path)
            self._schedule_save()

    def _resolve_cert_key_path(self, s: str) -> str:
        s = (s or "").strip()
        if not s:
            return ""
        try:
            p = Path(s)
            if p.is_absolute() and p.exists():
                return str(p)
            if p.exists():
                return str(p.resolve())
        except Exception:
            pass

        try:
            rp = resource_path(s)
            if rp.exists():
                return str(rp)
            rp2 = resource_path(Path(s).name)
            if rp2.exists():
                return str(rp2)
        except Exception:
            pass

        return s

    def _split_extra_args(self, s: str) -> list:
        s = (s or "").strip()
        if not s:
            return []
        out = []
        cur = []
        in_q = False
        qch = ""
        for ch in s:
            if in_q:
                if ch == qch:
                    in_q = False
                    qch = ""
                else:
                    cur.append(ch)
            else:
                if ch in ("'", '"'):
                    in_q = True
                    qch = ch
                elif ch.isspace():
                    if cur:
                        out.append("".join(cur))
                        cur = []
                else:
                    cur.append(ch)
        if cur:
            out.append("".join(cur))
        return out

    def _append_threads_args(self, args: list, threads: int, flag_str: str) -> None:
        """
        Add the thread count CLI args in a robust way.

        - If flag_str is "--threads" or "-t" => add ["--threads", "N"]
        - If flag_str contains spaces => split and append, then append N
        - If flag_str is like "--threads=" => append "--threads=N"
        - If flag_str is like "--threads=8" => append as-is (and ignore threads spinner)
        """
        if threads <= 0:
            return

        fs = (flag_str or "").strip()
        if not fs:
            fs = "--threads"

        toks = self._split_extra_args(fs)
        if not toks:
            toks = ["--threads"]

        # If user provided --flag=value already, trust it
        if len(toks) == 1 and "=" in toks[0]:
            k, v = toks[0].split("=", 1)
            if v.strip() == "":
                args.append(f"{k}={threads}")
            else:
                args.append(toks[0])
            return

        args.extend(toks)
        args.append(str(threads))

    # -------- stdout/stderr routing --------

    def _classify_line(self, line: str) -> Tuple[bool, bool, Optional[str], str]:
        raw = line
        low = raw.strip().lower()
        lstripped = raw.lstrip()
        low_ls = lstripped.lower()

        if low_ls.startswith("[proxy]") or low_ls.startswith("proxy:") or low_ls.startswith("tlsproxy") or low_ls.startswith("tls proxy"):
            cleaned = lstripped
            for pfx in ("[proxy]", "proxy:", "tlsproxy", "tls proxy"):
                if cleaned.lower().startswith(pfx):
                    cleaned = cleaned[len(pfx):].lstrip()
                    break
            return True, False, "proxy", cleaned

        if low_ls.startswith("[gateway]") or low_ls.startswith("gateway:") or low_ls.startswith("edge gateway") or low_ls.startswith("edge-gateway"):
            cleaned = lstripped
            for pfx in ("[gateway]", "gateway:", "edge gateway", "edge-gateway"):
                if cleaned.lower().startswith(pfx):
                    cleaned = cleaned[len(pfx):].lstrip()
                    break
            return False, True, "gateway", cleaned

        is_proxy = ("[proxy]" in low) or ("tls proxy" in low) or ("tlsproxy" in low) or ("proxy:" in low)
        is_gateway = ("[gateway]" in low) or ("edge gateway" in low) or ("edge-gateway" in low) or ("gateway:" in low)

        ctx: Optional[str] = None
        if is_proxy and not is_gateway:
            ctx = "proxy"
        elif is_gateway and not is_proxy:
            ctx = "gateway"

        return is_proxy, is_gateway, ctx, raw.strip("\r\n")

    def _route_process_text(self, text: str, *, is_stderr: bool) -> None:
        if not text:
            return

        if is_stderr:
            self._append_plain(self.txt_log, text, prefix="[stderr] ")
            self._append_plain(self.txt_out, text, prefix="[stderr] ")
        else:
            self._append_plain(self.txt_log, text)
            self._append_plain(self.txt_out, text, prefix="[server] ")

        t = text.replace("\r\n", "\n").replace("\r", "\n")
        for raw_line in t.split("\n"):
            if not raw_line.strip():
                continue

            is_proxy, is_gateway, ctx, cleaned = self._classify_line(raw_line)

            if (raw_line.startswith(" ") or raw_line.startswith("\t")) and not (is_proxy or is_gateway) and self._last_ctx:
                ctx = self._last_ctx
                is_proxy = (ctx == "proxy")
                is_gateway = (ctx == "gateway")

            if ctx:
                self._last_ctx = ctx

            if is_proxy and not is_gateway:
                self._append_plain(self.txt_proxy, cleaned, prefix="[stderr] " if is_stderr else "")
            elif is_gateway and not is_proxy:
                self._append_plain(self.txt_gateway, cleaned, prefix="[stderr] " if is_stderr else "")
            elif is_proxy and is_gateway:
                self._append_plain(self.txt_proxy, cleaned, prefix="[stderr] " if is_stderr else "")
                self._append_plain(self.txt_gateway, cleaned, prefix="[stderr] " if is_stderr else "")

    def _read_stdout(self) -> None:
        data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if data.strip():
            self._route_process_text(data, is_stderr=False)

    def _read_stderr(self) -> None:
        data = bytes(self.proc.readAllStandardError()).decode("utf-8", errors="replace")
        if data.strip():
            self._route_process_text(data, is_stderr=True)

    def _on_proc_error(self, err) -> None:
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
            self._append_plain(w, f"[gui] process error: {err}")
        self._set_running(False)
        self.timer.stop()

    def _on_finished(self) -> None:
        self.timer.stop()
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
            self._append_plain(w, "[gui] server process exited")
        self._set_running(False)

    # -------- actions --------

    def _gen_token(self) -> None:
        tok = "dev-" + secrets.token_hex(16)
        self.ed_token.setText(tok)
        self._schedule_save()

    def _start_server(self) -> None:
        self._save_cfg()

        if not BIN_EXE.exists():
            QMessageBox.critical(
                self,
                "Missing BlockNet executable",
                f"Not found:\n{BIN_EXE}\n\nPlace BlockNet.exe next to gui.py (or bundle it with PyInstaller)."
            )
            return

        if self.proc.state() != QProcess.NotRunning:
            QMessageBox.information(self, "Already running", "Server is already running.")
            return

        relay = self.ed_relay.text().strip()
        spool = self.ed_spool.text().strip()
        token = self.ed_token.text().strip()

        args = ["serve", "--listen", relay, "--spool", spool]

        # NEW: threads
        th = int(self.sp_threads.value())
        if th > 0:
            self._append_threads_args(args, th, self.ed_threads_flag.text())

        if token:
            args += ["--token", token]

        # API flags
        if self.cb_api.isChecked():
            prefix = self.ed_api_prefix.text().strip() or "/v1"
            args += ["--api", "on", "--api-prefix", prefix]
            if self.cb_api_media.isChecked():
                args += ["--api-media", "on"]
            if self.cb_api_randomx.isChecked():
                args += ["--api-randomx", "on"]
                dll = self.ed_randomx_dll.text().strip()
                if dll:
                    args += ["--api-randomx-dll", dll]
            if self.cb_api_web.isChecked():
                args += ["--api-web", "on"]
                # optional web knobs if your server supports them
                args += ["--api-web-block-private", "on" if self.cb_web_block_private.isChecked() else "off"]
                args += ["--api-web-allow-http", "on" if self.cb_web_allow_http.isChecked() else "off"]
                args += ["--api-web-allow-https", "on" if self.cb_web_allow_https.isChecked() else "off"]
                args += ["--api-web-timeout-ms", str(self.sp_web_timeout.value())]
                args += ["--api-web-max-page-bytes", str(self.sp_web_max_page_kb.value() * 1024)]
                args += ["--api-web-max-scripts", str(self.sp_web_max_scripts.value())]
                ua = self.ed_web_ua.text().strip()
                if ua:
                    args += ["--api-web-ua", ua]
            if self.cb_api_p2pool.isChecked():
                args += ["--api-p2pool", "on"]
                args += self._split_extra_args(self.ed_p2pool_extra.text())

        # Proxy/Gateway
        proxy_on = bool(self.cb_proxy.isChecked())
        gateway_on = bool(self.cb_gateway.isChecked())

        if proxy_on and gateway_on:
            pl = self.ed_proxy_listen.text().strip()
            gl = self.ed_gateway_listen.text().strip()
            if pl and gl and pl == gl:
                QMessageBox.critical(
                    self,
                    "Port conflict",
                    "Proxy and Gateway are both enabled but listen on the same address.\n\n"
                    f"proxy listen = {pl}\n"
                    f"gateway listen = {gl}\n\n"
                    "They can't both bind the same port. Change one (e.g. 443 vs 4443) or disable one."
                )
                return

        if proxy_on:
            args += ["--proxy", "on"]
            pl = self.ed_proxy_listen.text().strip()
            pb = self.ed_proxy_backend.text().strip()
            if pl:
                args += ["--proxy-listen", pl]
            if pb:
                args += ["--proxy-backend", pb]

            pc = self._resolve_cert_key_path(self.ed_proxy_cert.text())
            pk = self._resolve_cert_key_path(self.ed_proxy_key.text())
            if pc and pk:
                args += ["--proxy-cert", pc, "--proxy-key", pk]

            inject = self.ed_proxy_inject.text().strip()
            if inject:
                args += ["--proxy-inject-token", inject]

            allow = self.ed_proxy_allow.text().strip()
            if allow:
                args += ["--proxy-allow", allow]

            logv = self.cmb_proxy_log.currentText().strip()
            if logv:
                args += ["--proxy-log", logv]

        if gateway_on:
            args += ["--gateway", "on"]
            gl = self.ed_gateway_listen.text().strip()
            gb = self.ed_gateway_backend.text().strip()
            if gl:
                args += ["--gateway-listen", gl]
            if gb:
                args += ["--gateway-backend", gb]

            gc = self._resolve_cert_key_path(self.ed_gateway_cert.text())
            gk = self._resolve_cert_key_path(self.ed_gateway_key.text())
            if gc and gk:
                args += ["--gateway-cert", gc, "--gateway-key", gk]

            gallow = self.ed_gateway_allow.text().strip()
            if gallow:
                args += ["--gateway-allow", gallow]

            glog = self.cmb_gateway_log.currentText().strip()
            if glog:
                args += ["--gateway-log", glog]

            args += self._split_extra_args(self.ed_gateway_extra.text())

        # Server extra args
        args += self._split_extra_args(self.ed_server_extra.text())

        # Reset context routing when starting fresh
        self._last_ctx = None

        cmdline = f"{BIN_EXE} " + " ".join(args)
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
            self._append_plain(w, f"[gui] starting: {cmdline}")

        self.proc.setProgram(str(BIN_EXE))
        self.proc.setArguments(args)
        self.proc.setWorkingDirectory(str(app_data_dir()))
        self.proc.start()

        if not self.proc.waitForStarted(2500):
            QMessageBox.critical(self, "Failed to start", "BlockNet did not start. See console for details.")
            self._set_running(False)
            return

        self._set_running(True)
        self.timer.start()

    def _stop_server(self) -> None:
        self._save_cfg()

        if self.proc.state() == QProcess.NotRunning:
            return

        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
            self._append_plain(w, "[gui] stopping server...")

        self.proc.terminate()
        if not self.proc.waitForFinished(2000):
            for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
                self._append_plain(w, "[gui] force kill")
            self.proc.kill()

        self.timer.stop()
        self._set_running(False)

    def _poll_stats(self) -> None:
        try:
            j = self._client().stats()
            self._append_json(self.txt_out, j)
            self.statusBar().showMessage("Stats updated")
        except Exception as e:
            self._append_plain(self.txt_out, f"stats error: {e}")
            self.statusBar().showMessage("Stats error")

    def _do_put(self) -> None:
        try:
            key = self.ed_key.text().strip()
            mime = self.ed_mime.text().strip() or "text/plain"
            text = self.ed_put.text()
            j = self._client().put(text.encode("utf-8"), key=key, mime=mime)
            self._append_json(self.txt_out, j)
            self.statusBar().showMessage("PUT ok" if j.get("ok") else "PUT failed")
        except Exception as e:
            self._append_plain(self.txt_out, f"put error: {e}")
            self.statusBar().showMessage("PUT error")

    def _do_get(self) -> None:
        s = self.ed_get.text().strip()
        if not s:
            return
        try:
            cli = self._client()
            if s.startswith("obj_"):
                status, hdrs, data = cli.get_ref(s)
            else:
                status, hdrs, data = cli.get_key(s)

            ctype = hdrs.get("Content-Type") or hdrs.get("content-type") or ""
            self._append_plain(self.txt_out, f"status={status} content-type={ctype}")

            try:
                self._append_plain(self.txt_out, data.decode("utf-8", errors="replace"))
            except Exception:
                self._append_plain(self.txt_out, f"<{len(data)} bytes>")

            self.statusBar().showMessage("GET ok" if status == 200 else f"GET status={status}")
        except Exception as e:
            self._append_plain(self.txt_out, f"get error: {e}")
            self.statusBar().showMessage("GET error")

    # ---------------- API actions ----------------

    def _api_prefix(self) -> str:
        return (self.ed_api_prefix.text().strip() or "/v1")

    def _do_api_ping(self) -> None:
        try:
            j = self._client().api_ping(prefix=self._api_prefix())
            self._append_json(self.txt_out, j)
        except Exception as e:
            self._append_plain(self.txt_out, f"api ping error: {e}")

    def _do_texttovec(self) -> None:
        try:
            text = self.ttv_text.toPlainText()
            dim = int(self.ttv_dim.value())
            normalize = bool(self.ttv_norm.isChecked())
            outfmt = self.ttv_outfmt.currentText().strip()
            j = self._client().api_texttovec(text, dim=dim, normalize=normalize, output=outfmt, prefix=self._api_prefix())
            self.ttv_out.setPlainText("")
            self._append_json(self.ttv_out, j)
        except Exception as e:
            self._append_plain(self.ttv_out, f"texttovec error: {e}")

    def _do_vectortext(self) -> None:
        try:
            prompt = self.vtxt_prompt.toPlainText().strip()
            payload = self.vtxt_payload.toPlainText()

            body: Dict[str, Any] = {
                "prompt": prompt,
                "payload": payload,
                "key": self.vtxt_key.text().strip(),
                "lexicon_key": self.vtxt_lexicon_key.text().strip(),
                "context_key": self.vtxt_context_key.text().strip(),
                "max_tokens": int(self.vtxt_max_tokens.value()),
                "topk": int(self.vtxt_topk.value()),
            }

            idf_txt = self.vtxt_idf.text().strip()
            if idf_txt:
                body["idf"] = _maybe_json_value(idf_txt)
            tok_txt = self.vtxt_tokens.text().strip()
            if tok_txt:
                body["tokens"] = _maybe_json_value(tok_txt)

            lex_inline = self.vtxt_lexicon_inline.toPlainText().strip()
            if lex_inline:
                body["lexicon"] = _maybe_json_value(lex_inline)
            ctx_inline = self.vtxt_context_inline.toPlainText().strip()
            if ctx_inline:
                body["context"] = _maybe_json_value(ctx_inline)

            vb64 = self.vtxt_vector_b64.text().strip()
            if vb64:
                body["vector_b64f32"] = vb64
            else:
                vtxt = self.vtxt_vector_json.toPlainText().strip()
                try:
                    v = json.loads(vtxt) if vtxt else []
                except Exception:
                    raise ValueError("vector JSON is invalid")
                if not isinstance(v, list):
                    raise ValueError("vector must be a JSON list")
                body["vector"] = v

            seed_txt = self.vtxt_seed.text().strip()
            if seed_txt:
                body["seed"] = _maybe_json_value(seed_txt)

            j = self._client().api_vectortext(body, prefix=self._api_prefix())
            self.vtxt_out.setPlainText("")
            self._append_json(self.vtxt_out, j)
        except Exception as e:
            self._append_plain(self.vtxt_out, f"vectortext error: {e}")

    def _do_web_fetch(self) -> None:
        try:
            body = {
                "url": self.web_url.text().strip(),
                "mode": self.web_mode.currentText().strip(),
                "include_js": bool(self.web_include_js.isChecked()),
                "max_bytes": int(self.web_max_kb.value()) * 1024,
                "max_scripts": int(self.web_max_scripts.value()),
            }
            j = self._client().api_web_fetch(body, prefix=self._api_prefix())
            self.web_out.setPlainText("")
            self._append_json(self.web_out, j)
        except Exception as e:
            self._append_plain(self.web_out, f"web/fetch error: {e}")

    def _do_web_js(self) -> None:
        try:
            body = {
                "url": self.webjs_url.text().strip(),
                "fetch_bodies": bool(self.webjs_fetch_bodies.isChecked()),
                "max_scripts": int(self.webjs_max_scripts.value()),
            }
            j = self._client().api_web_js(body, prefix=self._api_prefix())
            self.web_out.setPlainText("")
            self._append_json(self.web_out, j)
        except Exception as e:
            self._append_plain(self.web_out, f"web/js error: {e}")

    def _do_web_links(self) -> None:
        try:
            filt = self.weblinks_filter.currentText().strip().lower()

            body: Dict[str, Any] = {
                "url": self.weblinks_url.text().strip(),
                "max_links": int(self.weblinks_max.value()),
            }

            # These flags are what your C++ route should read.
            if filt == "same-origin":
                body["same_origin"] = True
            elif filt == "external-only":
                body["external_only"] = True

            j = self._client().api_web_links(body, prefix=self._api_prefix())
            self.web_out.setPlainText("")
            self._append_json(self.web_out, j)
        except Exception as e:
            self._append_plain(self.web_out, f"web/links error: {e}")

    def _do_web_rss_find(self) -> None:
        try:
            body = {
                "url": self.webrss_url.text().strip(),
                "max_feeds": int(self.webrss_max.value()),
            }
            j = self._client().api_web_rss_find(body, prefix=self._api_prefix())
            self.web_out.setPlainText("")
            self._append_json(self.web_out, j)
        except Exception as e:
            self._append_plain(self.web_out, f"web/rss_find error: {e}")

    def _do_imagetovec(self) -> None:
        try:
            p = self.img_path.text().strip()
            if not p:
                raise ValueError("select an image file")
            b = Path(p).read_bytes()
            body = {
                "image_b64": base64.b64encode(b).decode("ascii"),
                "dim": int(self.img_dim.value()),
                "normalize": bool(self.img_norm.isChecked()),
                "output": self.img_outfmt.currentText().strip(),
            }
            j = self._client().api_imagetovec(body, prefix=self._api_prefix())
            self.media_out.setPlainText("")
            self._append_json(self.media_out, j)
        except Exception as e:
            self._append_plain(self.media_out, f"imagetovec error: {e}")

    def _do_videotovec(self) -> None:
        try:
            p = self.vid_path.text().strip()
            if not p:
                raise ValueError("select a video file")
            b = Path(p).read_bytes()
            body = {
                "video_b64": base64.b64encode(b).decode("ascii"),
                "dim": int(self.vid_dim.value()),
                "normalize": bool(self.vid_norm.isChecked()),
                "output": self.vid_outfmt.currentText().strip(),
                "max_frames": int(self.vid_max_frames.value()),
            }
            j = self._client().api_videotovec(body, prefix=self._api_prefix())
            self.media_out.setPlainText("")
            self._append_json(self.media_out, j)
        except Exception as e:
            self._append_plain(self.media_out, f"videotovec error: {e}")

    def _do_randomx_status(self) -> None:
        try:
            j = self._client().api_randomx_status(prefix=self._api_prefix())
            self.rx_out.setPlainText("")
            self._append_json(self.rx_out, j)
            self._append_json(self.txt_out, j)
        except Exception as e:
            self._append_plain(self.rx_out, f"randomx status error: {e}")

    def _do_randomx_hash(self) -> None:
        try:
            seed_hex = self.rx_seed_hex.text().strip()
            if not seed_hex:
                raise ValueError("seed_hex required")

            mode = self.rx_data_mode.currentText().strip()
            data = self.rx_data.toPlainText().strip()
            if not data:
                raise ValueError("data required")

            body: Dict[str, Any] = {"seed_hex": seed_hex}
            if mode == "data_hex":
                body["data_hex"] = data
            else:
                body["data_b64"] = data

            j = self._client().api_randomx_hash(body, prefix=self._api_prefix())
            self.rx_out.setPlainText("")
            self._append_json(self.rx_out, j)
        except Exception as e:
            self._append_plain(self.rx_out, f"randomx hash error: {e}")

    def _do_randomx_hash_batch(self) -> None:
        try:
            seed_hex = self.rx_seed_hex.text().strip()
            if not seed_hex:
                raise ValueError("seed_hex required")

            raw = (self.rx_batch_items.toPlainText() or "").strip()
            if not raw:
                raise ValueError("items JSON required")

            parsed = json.loads(raw)

            # allow either: JSON array => items, or JSON object => full body
            if isinstance(parsed, list):
                body: Dict[str, Any] = {"seed_hex": seed_hex, "items": parsed}
            elif isinstance(parsed, dict):
                body = dict(parsed)
                body.setdefault("seed_hex", seed_hex)
                if "items" not in body or not isinstance(body["items"], list):
                    raise ValueError("body must include items[] (JSON array)")
            else:
                raise ValueError("JSON must be an array (items) or object (full body)")

            j = self._client().api_randomx_hash_batch(body, prefix=self._api_prefix())
            self.rx_out.setPlainText("")
            self._append_json(self.rx_out, j)
        except Exception as e:
            self._append_plain(self.rx_out, f"randomx hash_batch error: {e}")

    def _do_web_example(self) -> None:
        self.web_url.setText("https://example.com")
        self.web_mode.setCurrentText("text")
        self.web_include_js.setChecked(False)
        self._do_web_fetch()

    # P2Pool
    def _do_p2pool_open(self) -> None:
        try:
            # Build optional open params body (patch)
            body: Dict[str, Any] = {}

            host = self.p2_open_host.text().strip()
            wallet = self.p2_open_wallet.text().strip()
            rig = self.p2_open_rig.text().strip()
            th = int(self.p2_open_threads.value())
            if host:
                body["host"] = host
            if wallet:
                body["wallet"] = wallet
            if rig:
                body["rig_id"] = rig
            if th > 0:
                body["threads"] = th

            raw_extra = (self.p2_open_extra_json.toPlainText() or "").strip()
            if raw_extra:
                extra = json.loads(raw_extra)
                if not isinstance(extra, dict):
                    raise ValueError("extra JSON must be an object")
                body.update(extra)

            cli = self._client()
            # Try calling with a body if your BlockNetClient supports it; otherwise fall back.
            try:
                j = cli.api_p2pool_open(body, prefix=self._api_prefix()) if body else cli.api_p2pool_open(prefix=self._api_prefix())
            except TypeError:
                j = cli.api_p2pool_open(prefix=self._api_prefix())

            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
            sess = (j.get("session") or j.get("id") or "")
            if sess:
                self.p2_session.setText(str(sess))
        except Exception as e:
            self._append_plain(self.p2_out, f"p2pool open error: {e}")

    def _do_p2pool_job(self) -> None:
        try:
            sess = self.p2_session.text().strip()
            if not sess:
                raise ValueError("session required")
            j = self._client().api_p2pool_job(sess, prefix=self._api_prefix())
            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
        except Exception as e:
            self._append_plain(self.p2_out, f"p2pool job error: {e}")

    def _do_p2pool_poll(self) -> None:
        try:
            sess = self.p2_session.text().strip()
            if not sess:
                raise ValueError("session required")
            j = self._client().api_p2pool_poll(sess, max_msgs=int(self.p2_poll_max.value()), prefix=self._api_prefix())
            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
        except Exception as e:
            self._append_plain(self.p2_out, f"p2pool poll error: {e}")

    def _do_p2pool_submit(self) -> None:
        try:
            raw = self.p2_submit_json.toPlainText().strip()
            body = json.loads(raw) if raw else {}
            if not isinstance(body, dict):
                raise ValueError("submit payload must be a JSON object")

            # auto-fill session if empty
            if not body.get("session"):
                sess = self.p2_session.text().strip()
                if sess:
                    body["session"] = sess

            j = self._client().api_p2pool_submit(body, prefix=self._api_prefix())
            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
        except Exception as e:
            self._append_plain(self.p2_out, f"p2pool submit error: {e}")

    def _do_p2pool_close(self) -> None:
        try:
            sess = self.p2_session.text().strip()
            if not sess:
                raise ValueError("session required")
            j = self._client().api_p2pool_close(sess, prefix=self._api_prefix())
            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
        except Exception as e:
            self._append_plain(self.p2_out, f"p2pool close error: {e}")

    # -------- config persistence --------

    def closeEvent(self, ev) -> None:
        self._save_cfg()
        self._stop_server()
        super().closeEvent(ev)

    def _load_cfg(self) -> None:
        if not CFG_PATH.exists():
            self.main_split.setSizes([480, 980])
            return

        try:
            j = json.loads(CFG_PATH.read_text(encoding="utf-8"))

            self.ed_relay.setText(j.get("relay", self.ed_relay.text()))
            self.ed_token.setText(j.get("token", self.ed_token.text()))
            self.ed_spool.setText(j.get("spool", self.ed_spool.text()))
            self.ed_host.setText(j.get("host", self.ed_host.text()))
            self.ed_port.setText(j.get("port", self.ed_port.text()))
            self.ed_server_extra.setText(j.get("server_extra", self.ed_server_extra.text()))

            # NEW: threads
            try:
                self.sp_threads.setValue(int(j.get("threads", self.sp_threads.value())))
            except Exception:
                pass
            self.ed_threads_flag.setText(j.get("threads_flag", self.ed_threads_flag.text()))

            self.cb_proxy.setChecked(bool(j.get("proxy_enabled", False)))
            self.ed_proxy_listen.setText(j.get("proxy_listen", self.ed_proxy_listen.text()))
            self.ed_proxy_backend.setText(j.get("proxy_backend", self.ed_proxy_backend.text()))
            self.ed_proxy_cert.setText(j.get("proxy_cert", self.ed_proxy_cert.text()))
            self.ed_proxy_key.setText(j.get("proxy_key", self.ed_proxy_key.text()))
            self.ed_proxy_inject.setText(j.get("proxy_inject", self.ed_proxy_inject.text()))
            self.ed_proxy_allow.setText(j.get("proxy_allow", self.ed_proxy_allow.text()))
            try:
                self.cmb_proxy_log.setCurrentText(j.get("proxy_log", self.cmb_proxy_log.currentText()))
            except Exception:
                pass

            self.cb_gateway.setChecked(bool(j.get("gateway_enabled", False)))
            self.ed_gateway_listen.setText(j.get("gateway_listen", self.ed_gateway_listen.text()))
            self.ed_gateway_backend.setText(j.get("gateway_backend", self.ed_gateway_backend.text()))
            self.ed_gateway_cert.setText(j.get("gateway_cert", self.ed_gateway_cert.text()))
            self.ed_gateway_key.setText(j.get("gateway_key", self.ed_gateway_key.text()))
            self.ed_gateway_allow.setText(j.get("gateway_allow", self.ed_gateway_allow.text()))
            self.ed_gateway_extra.setText(j.get("gateway_extra", self.ed_gateway_extra.text()))
            try:
                self.cmb_gateway_log.setCurrentText(j.get("gateway_log", self.cmb_gateway_log.currentText()))
            except Exception:
                pass

            # API config
            self.cb_api.setChecked(bool(j.get("api_enabled", True)))
            self.ed_api_prefix.setText(j.get("api_prefix", self.ed_api_prefix.text()))
            self.cb_api_media.setChecked(bool(j.get("api_media", True)))
            self.cb_api_randomx.setChecked(bool(j.get("api_randomx", True)))
            self.cb_api_web.setChecked(bool(j.get("api_web", True)))
            self.cb_api_p2pool.setChecked(bool(j.get("api_p2pool", False)))
            self.ed_randomx_dll.setText(j.get("randomx_dll", self.ed_randomx_dll.text()))
            self.ed_p2pool_extra.setText(j.get("p2pool_extra", self.ed_p2pool_extra.text()))

            self.cb_web_block_private.setChecked(bool(j.get("web_block_private", True)))
            self.cb_web_allow_http.setChecked(bool(j.get("web_allow_http", True)))
            self.cb_web_allow_https.setChecked(bool(j.get("web_allow_https", True)))
            self.sp_web_timeout.setValue(int(j.get("web_timeout", self.sp_web_timeout.value())))
            self.sp_web_max_page_kb.setValue(int(j.get("web_max_page_kb", self.sp_web_max_page_kb.value())))
            self.sp_web_max_scripts.setValue(int(j.get("web_max_scripts", self.sp_web_max_scripts.value())))
            self.ed_web_ua.setText(j.get("web_ua", self.ed_web_ua.text()))

            # NEW: p2pool open defaults
            self.p2_open_host.setText(j.get("p2_open_host", self.p2_open_host.text()))
            self.p2_open_wallet.setText(j.get("p2_open_wallet", self.p2_open_wallet.text()))
            self.p2_open_rig.setText(j.get("p2_open_rig", self.p2_open_rig.text()))
            try:
                self.p2_open_threads.setValue(int(j.get("p2_open_threads", self.p2_open_threads.value())))
            except Exception:
                pass
            self.p2_open_extra_json.setPlainText(j.get("p2_open_extra_json", self.p2_open_extra_json.toPlainText()))

            # splitter state
            try:
                s = j.get("main_split_state", "")
                if s:
                    self.main_split.restoreState(_b64d(s))
                else:
                    self.main_split.setSizes([480, 980])
            except Exception:
                self.main_split.setSizes([480, 980])

            # last selected tabs
            try:
                self.left_tabs.setCurrentIndex(int(j.get("left_tab", 0)))
            except Exception:
                pass
            try:
                self.right_tabs.setCurrentIndex(int(j.get("right_tab", 0)))
            except Exception:
                pass

        except Exception:
            self.main_split.setSizes([480, 980])

    def _save_cfg(self) -> None:
        try:
            j = {
                "relay": self.ed_relay.text().strip(),
                "token": self.ed_token.text().strip(),
                "spool": self.ed_spool.text().strip(),
                "host": self.ed_host.text().strip(),
                "port": self.ed_port.text().strip(),
                "server_extra": self.ed_server_extra.text().strip(),

                # NEW: threads
                "threads": int(self.sp_threads.value()),
                "threads_flag": self.ed_threads_flag.text().strip(),

                "proxy_enabled": bool(self.cb_proxy.isChecked()),
                "proxy_listen": self.ed_proxy_listen.text().strip(),
                "proxy_backend": self.ed_proxy_backend.text().strip(),
                "proxy_cert": self.ed_proxy_cert.text().strip(),
                "proxy_key": self.ed_proxy_key.text().strip(),
                "proxy_inject": self.ed_proxy_inject.text().strip(),
                "proxy_allow": self.ed_proxy_allow.text().strip(),
                "proxy_log": self.cmb_proxy_log.currentText().strip(),

                "gateway_enabled": bool(self.cb_gateway.isChecked()),
                "gateway_listen": self.ed_gateway_listen.text().strip(),
                "gateway_backend": self.ed_gateway_backend.text().strip(),
                "gateway_cert": self.ed_gateway_cert.text().strip(),
                "gateway_key": self.ed_gateway_key.text().strip(),
                "gateway_allow": self.ed_gateway_allow.text().strip(),
                "gateway_log": self.cmb_gateway_log.currentText().strip(),
                "gateway_extra": self.ed_gateway_extra.text().strip(),

                "api_enabled": bool(self.cb_api.isChecked()),
                "api_prefix": self.ed_api_prefix.text().strip(),
                "api_media": bool(self.cb_api_media.isChecked()),
                "api_randomx": bool(self.cb_api_randomx.isChecked()),
                "api_web": bool(self.cb_api_web.isChecked()),
                "api_p2pool": bool(self.cb_api_p2pool.isChecked()),
                "randomx_dll": self.ed_randomx_dll.text().strip(),
                "p2pool_extra": self.ed_p2pool_extra.text().strip(),

                "web_block_private": bool(self.cb_web_block_private.isChecked()),
                "web_allow_http": bool(self.cb_web_allow_http.isChecked()),
                "web_allow_https": bool(self.cb_web_allow_https.isChecked()),
                "web_timeout": int(self.sp_web_timeout.value()),
                "web_max_page_kb": int(self.sp_web_max_page_kb.value()),
                "web_max_scripts": int(self.sp_web_max_scripts.value()),
                "web_ua": self.ed_web_ua.text().strip(),

                # NEW: p2pool open defaults
                "p2_open_host": self.p2_open_host.text().strip(),
                "p2_open_wallet": self.p2_open_wallet.text().strip(),
                "p2_open_rig": self.p2_open_rig.text().strip(),
                "p2_open_threads": int(self.p2_open_threads.value()),
                "p2_open_extra_json": self.p2_open_extra_json.toPlainText(),

                "main_split_state": _b64e(bytes(self.main_split.saveState())),
                "left_tab": int(self.left_tabs.currentIndex()),
                "right_tab": int(self.right_tabs.currentIndex()),
            }
            CFG_PATH.write_text(json.dumps(j, indent=2), encoding="utf-8")
        except Exception:
            pass


def main() -> int:
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    w = MainWindow()
    w.resize(1350, 880)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())