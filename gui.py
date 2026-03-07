# gui.py
from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import sys
import http.client
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from PyQt5.QtCore import QProcess, QTimer, Qt, QStandardPaths

try:
    from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile  # type: ignore
    from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor  # type: ignore
    from PyQt5.QtCore import QUrl  # type: ignore
    _WEBENGINE_OK = True
except Exception:
    QWebEngineView = None  # type: ignore
    QWebEnginePage = None  # type: ignore
    QWebEngineProfile = None  # type: ignore
    QWebEngineUrlRequestInterceptor = None  # type: ignore
    QUrl = None  # type: ignore
    _WEBENGINE_OK = False

from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QFormLayout, QGroupBox,
    QMessageBox, QSplitter, QTabWidget, QFileDialog,
    QCheckBox, QComboBox, QSpinBox, QScrollArea
)

from blocknet_client import BlockNetClient


def app_data_dir(app_name: str = "BlockNetGUI") -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    p = Path(base) / app_name
    p.mkdir(parents=True, exist_ok=True)
    return p


def resource_path(rel: str) -> Path:
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

BIN_EXE = resource_path("BlockNet.exe")
if not BIN_EXE.exists():
    BIN_EXE = resource_path("blocknet.exe")


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
        QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 6px;
            background: #121212;
            selection-background-color: #3c78c8;
            color: #e6e6e6;
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
    t = (text or "").strip()
    if not t:
        return ""
    if t.startswith("{") or t.startswith("[") or t in ("true", "false", "null") or t[0].isdigit() or t[0] == "-":
        try:
            return json.loads(t)
        except Exception:
            return t
    return t


def _parse_relay_parts(relay: str) -> Tuple[str, str, int, str]:
    r = (relay or "").strip()
    if not r:
        return "http", "127.0.0.1", 38888, ""
    if "://" not in r:
        r = "http://" + r
    u = urllib.parse.urlsplit(r)
    scheme = (u.scheme or "http").lower()
    host = u.hostname or "127.0.0.1"
    port = int(u.port or (443 if scheme == "https" else 80))
    base_path = (u.path or "").rstrip("/")
    if base_path == "/":
        base_path = ""
    return scheme, host, port, base_path


def _parse_relay_host_port(relay: str) -> Tuple[str, int]:
    scheme, host, port, _ = _parse_relay_parts(relay)
    _ = scheme
    return host, port


def _relay_base_url(relay: str) -> str:
    scheme, host, port, base_path = _parse_relay_parts(relay)
    return f"{scheme}://{host}:{port}{base_path}"


def _join_url(base: str, path: str) -> str:
    base = (base or "").rstrip("/")
    path = (path or "")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


if _WEBENGINE_OK and QWebEngineUrlRequestInterceptor is not None:
    class _BlockNetRequestInterceptor(QWebEngineUrlRequestInterceptor):
        def __init__(self, mw: "MainWindow") -> None:
            super().__init__(mw)
            self._mw = mw

        def interceptRequest(self, info) -> None:  # type: ignore[override]
            try:
                token = self._mw.ed_token.text().strip() if hasattr(self._mw, "ed_token") else ""
                if token:
                    info.setHttpHeader(b"Authorization", f"Bearer {token}".encode("utf-8"))
                    info.setHttpHeader(b"X-Blocknet-Key", token.encode("utf-8"))
                    info.setHttpHeader(b"X-Blocknet-Token", token.encode("utf-8"))
            except Exception:
                pass
else:
    _BlockNetRequestInterceptor = None  # type: ignore


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BlockNet Control Panel")

        self._last_ctx: Optional[str] = None
        self._webw_ready = False
        self._webw_pending_js: list[str] = []

        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.SeparateChannels)
        self.proc.readyReadStandardOutput.connect(self._read_stdout)
        self.proc.readyReadStandardError.connect(self._read_stderr)
        self.proc.errorOccurred.connect(self._on_proc_error)
        self.proc.finished.connect(self._on_finished)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._poll_stats)

        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(350)
        self.save_timer.timeout.connect(self._save_cfg)

        self.mono = QFont("Consolas")
        self.mono.setStyleHint(QFont.Monospace)
        self.mono.setPointSize(10)

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

        self.main_split = QSplitter(Qt.Horizontal)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.setHandleWidth(10)
        root.addWidget(self.main_split, 1)

        self.left_tabs = QTabWidget()
        self.left_tabs.setMinimumWidth(430)
        self.main_split.addWidget(self.left_tabs)

        self.right_tabs = QTabWidget()
        self.main_split.addWidget(self.right_tabs)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        self._build_left_server_tab()
        self._build_left_proxy_tab()
        self._build_left_gateway_tab()
        self._build_left_storage_tab()
        self._build_left_api_config_tab()

        self._build_right_output_tabs()
        self._build_right_api_tabs()

        self.statusBar().showMessage("Ready")

        self._load_cfg()
        self._sync_relay_from_host_port()
        self._wire_autosave()

        self.main_split.splitterMoved.connect(lambda *_: self._schedule_save())

        self._set_running(False)

    def _wrap_scroll(self, inner: QWidget) -> QWidget:
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setFrameShape(QScrollArea.NoFrame)
        sc.setWidget(inner)
        return sc

    # ---------------- WebEngine helpers ----------------

    def _api_route_url(self, route: str) -> str:
        pfx = self._normalize_prefix()
        if not route.startswith("/"):
            route = "/" + route
        return _join_url(_relay_base_url(self.ed_relay.text().strip()), pfx + route)

    def _make_authed_web_view(self) -> Optional[QWebEngineView]:
        if not _WEBENGINE_OK or QWebEngineView is None or QWebEnginePage is None or QWebEngineProfile is None:
            return None
        try:
            profile = QWebEngineProfile(self)
            if _BlockNetRequestInterceptor is not None:
                interceptor = _BlockNetRequestInterceptor(self)
                try:
                    if hasattr(profile, "setUrlRequestInterceptor"):
                        profile.setUrlRequestInterceptor(interceptor)  # type: ignore[attr-defined]
                    elif hasattr(profile, "setRequestInterceptor"):
                        profile.setRequestInterceptor(interceptor)  # type: ignore[attr-defined]
                except Exception:
                    pass
                profile._bn_interceptor = interceptor  # type: ignore[attr-defined]

            page = QWebEnginePage(profile, self)
            view = QWebEngineView()
            view.setPage(page)
            view._bn_profile = profile  # type: ignore[attr-defined]
            return view
        except Exception:
            return None

    def _load_embedded_url(self, view: Optional[QWebEngineView], url: str, sink: Optional[QPlainTextEdit] = None) -> None:
        if view is None or not _WEBENGINE_OK or QUrl is None:
            if sink is not None:
                self._append_plain(sink, f"embedded browser unavailable, open externally instead:\n{url}")
            return
        try:
            if sink is not None:
                self._append_plain(sink, f"loading embedded:\n{url}")
            view.load(QUrl(url))
        except Exception as e:
            if sink is not None:
                self._append_plain(sink, f"embedded load error: {e}")

    # ---------------- Left tabs ----------------

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

        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(0, 4096)
        self.sp_threads.setValue(0)

        self.ed_threads_flag = QLineEdit("--threads")
        self.ed_threads_flag.setPlaceholderText("e.g. --threads or -t")

        self.ed_server_extra = QLineEdit("")
        self.ed_server_extra.setPlaceholderText('e.g. --log-level info')

        fl.addRow("Listen host", self.ed_host)
        fl.addRow("Listen port", self.ed_port)
        fl.addRow("Relay (host:port)", self.ed_relay)
        fl.addRow("Token", self.ed_token)
        fl.addRow("Spool dir", self.ed_spool)
        fl.addRow("Threads (0=auto)", self.sp_threads)
        fl.addRow("Threads flag", self.ed_threads_flag)
        fl.addRow("Server extra", self.ed_server_extra)

        row1 = QHBoxLayout()
        self.btn_gen = QPushButton("Generate Token")
        self.btn_start = QPushButton("Start")
        self.btn_stop = QPushButton("Stop")
        row1.addWidget(self.btn_gen)
        row1.addWidget(self.btn_start)
        row1.addWidget(self.btn_stop)
        fl.addRow(row1)

        row2 = QHBoxLayout()
        self.btn_stats = QPushButton("Fetch Stats")
        self.btn_clear_out = QPushButton("Clear Output")
        self.btn_clear_log = QPushButton("Clear Console")
        self.btn_clear_net = QPushButton("Clear Network")
        row2.addWidget(self.btn_stats)
        row2.addWidget(self.btn_clear_out)
        row2.addWidget(self.btn_clear_log)
        row2.addWidget(self.btn_clear_net)
        fl.addRow(row2)

        self.btn_gen.clicked.connect(self._gen_token)
        self.btn_start.clicked.connect(self._start_server)
        self.btn_stop.clicked.connect(self._stop_server)
        self.btn_stats.clicked.connect(self._poll_stats)

        lay.addWidget(gb)

        gb2 = QGroupBox("Quick Actions")
        l2 = QVBoxLayout(gb2)
        self.btn_api_ping = QPushButton("API: /v1/ping")
        self.btn_rx_status = QPushButton("API: RandomX status")
        self.btn_net_status = QPushButton("API: Network status")
        self.btn_audio_status = QPushButton("API: Audio status")
        self.btn_audio_ui = QPushButton("Open Audio UI")
        self.btn_python_status_quick = QPushButton("API: Python bridge status")
        self.btn_python_ui_quick = QPushButton("Open Python Bridge Admin UI")
        self.btn_web_test = QPushButton("API: Web fetch (example.com)")
        l2.addWidget(self.btn_api_ping)
        l2.addWidget(self.btn_rx_status)
        l2.addWidget(self.btn_net_status)
        l2.addWidget(self.btn_audio_status)
        l2.addWidget(self.btn_audio_ui)
        l2.addWidget(self.btn_python_status_quick)
        l2.addWidget(self.btn_python_ui_quick)
        l2.addWidget(self.btn_web_test)
        lay.addWidget(gb2)

        self.btn_api_ping.clicked.connect(self._do_api_ping)
        self.btn_rx_status.clicked.connect(self._do_randomx_status)
        self.btn_net_status.clicked.connect(self._do_network_status)
        self.btn_audio_status.clicked.connect(self._do_audio_status)
        self.btn_audio_ui.clicked.connect(self._do_audio_open_ui)
        self.btn_python_status_quick.clicked.connect(self._do_python_status)
        self.btn_python_ui_quick.clicked.connect(self._do_python_open_admin_ui_external)
        self.btn_web_test.clicked.connect(self._do_web_example)

        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Server")

    def _build_left_proxy_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("TLS Proxy (optional)")
        fl = QFormLayout(gb)

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

        fl.addRow(self.cb_proxy)
        fl.addRow("Proxy listen", self.ed_proxy_listen)
        fl.addRow("Proxy backend", self.ed_proxy_backend)
        fl.addRow("Proxy cert", _hbox(self.ed_proxy_cert, self.btn_proxy_cert))
        fl.addRow("Proxy key", _hbox(self.ed_proxy_key, self.btn_proxy_key))
        fl.addRow("Proxy inject token", self.ed_proxy_inject)
        fl.addRow("Proxy allow list", self.ed_proxy_allow)
        fl.addRow("Proxy log", self.cmb_proxy_log)

        self.btn_proxy_cert.clicked.connect(lambda: self._browse_file_into(self.ed_proxy_cert))
        self.btn_proxy_key.clicked.connect(lambda: self._browse_file_into(self.ed_proxy_key))

        lay.addWidget(gb)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Proxy")

    def _build_left_gateway_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("Edge Gateway (optional)")
        fl = QFormLayout(gb)

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
        self.ed_gateway_extra.setPlaceholderText('e.g. --gateway-sinkhole-file "rules.txt"')

        fl.addRow(self.cb_gateway)
        fl.addRow("Gateway listen", self.ed_gateway_listen)
        fl.addRow("Gateway backend", self.ed_gateway_backend)
        fl.addRow("Gateway cert", _hbox(self.ed_gateway_cert, self.btn_gateway_cert))
        fl.addRow("Gateway key", _hbox(self.ed_gateway_key, self.btn_gateway_key))
        fl.addRow("Gateway allow list", self.ed_gateway_allow)
        fl.addRow("Gateway log", self.cmb_gateway_log)
        fl.addRow("Gateway extra", self.ed_gateway_extra)

        self.btn_gateway_cert.clicked.connect(lambda: self._browse_file_into(self.ed_gateway_cert))
        self.btn_gateway_key.clicked.connect(lambda: self._browse_file_into(self.ed_gateway_key))

        lay.addWidget(gb)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Gateway")

    def _build_left_storage_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb = QGroupBox("Quick Put / Get")
        fl = QFormLayout(gb)

        self.ed_key = QLineEdit("greeting")
        self.ed_mime = QLineEdit("text/plain")
        self.ed_put = QLineEdit("hello world")
        self.ed_get = QLineEdit("greeting")

        fl.addRow("Key", self.ed_key)
        fl.addRow("MIME", self.ed_mime)
        fl.addRow("Put text", self.ed_put)
        fl.addRow("Get (key or obj_...)", self.ed_get)

        row = QHBoxLayout()
        self.btn_put = QPushButton("PUT")
        self.btn_get = QPushButton("GET")
        row.addWidget(self.btn_put)
        row.addWidget(self.btn_get)

        fl.addRow(row)

        self.btn_put.clicked.connect(self._do_put)
        self.btn_get.clicked.connect(self._do_get)

        lay.addWidget(gb)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "Storage")

    def _build_left_api_config_tab(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)

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
        self.ed_p2pool_extra = QLineEdit("")
        self.ed_p2pool_extra.setPlaceholderText("extra p2pool args")

        self.cb_api_webworker = QCheckBox("Enable WebWorker API (--api-webworker on)")
        self.cb_api_webworker.setChecked(False)

        self.cb_api_process = QCheckBox("Enable Process API (--api-process on)")
        self.cb_api_process.setChecked(False)

        self.cb_api_network = QCheckBox("Enable Network API (--api-network on)")
        self.cb_api_network.setChecked(True)
        self.ed_network_wintun_dll = QLineEdit("wintun.dll")
        self.btn_network_wintun_dll = QPushButton("Browse…")
        self.ed_network_iface = QLineEdit("blocknet")
        self.cb_network_set_ipv4 = QCheckBox("Set IPv4 on interface (--api-network-set-ipv4 on)")
        self.cb_network_set_ipv4.setChecked(False)
        self.ed_network_ipv4 = QLineEdit("")
        self.ed_network_ipv4.setPlaceholderText("e.g. 169.254.153.101/16")

        self.cb_api_audio = QCheckBox("Enable Audio API (--api-audio on)")
        self.cb_api_audio.setChecked(False)

        self.cb_api_python = QCheckBox("Enable Python API (--api-python on)")
        self.cb_api_python.setChecked(False)

        fl.addRow(self.cb_api)
        fl.addRow("API prefix", self.ed_api_prefix)
        fl.addRow(self.cb_api_media)
        fl.addRow(self.cb_api_randomx)
        fl.addRow("RandomX DLL", _hbox(self.ed_randomx_dll, self.btn_randomx_dll))
        fl.addRow(self.cb_api_web)
        fl.addRow(self.cb_api_p2pool)
        fl.addRow("P2Pool extra", self.ed_p2pool_extra)
        fl.addRow(self.cb_api_webworker)
        fl.addRow(self.cb_api_process)
        fl.addRow(self.cb_api_network)
        fl.addRow("Wintun DLL", _hbox(self.ed_network_wintun_dll, self.btn_network_wintun_dll))
        fl.addRow("Interface name", self.ed_network_iface)
        fl.addRow(self.cb_network_set_ipv4)
        fl.addRow("Interface IPv4 CIDR", self.ed_network_ipv4)
        fl.addRow(self.cb_api_audio)
        fl.addRow(self.cb_api_python)

        self.btn_randomx_dll.clicked.connect(lambda: self._browse_file_into(self.ed_randomx_dll))
        self.btn_network_wintun_dll.clicked.connect(lambda: self._browse_file_into(self.ed_network_wintun_dll))

        lay.addWidget(gb)

        gbw = QGroupBox("Web API Safety / Limits")
        wfl = QFormLayout(gbw)

        self.cb_web_block_private = QCheckBox("Block private hosts")
        self.cb_web_block_private.setChecked(True)

        self.cb_web_allow_http = QCheckBox("Allow http://")
        self.cb_web_allow_http.setChecked(True)

        self.cb_web_allow_https = QCheckBox("Allow https://")
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

        gba = QGroupBox("Audio API Config")
        afl = QFormLayout(gba)

        self.ed_audio_spool_dir = QLineEdit(str(app_data_dir() / "audio"))
        self.btn_audio_spool_dir = QPushButton("Browse…")
        self.cb_audio_persist = QCheckBox("Persist playlists")
        self.cb_audio_persist.setChecked(True)

        self.ed_audio_searxng_url = QLineEdit("")
        self.ed_audio_searxng_url.setPlaceholderText("e.g. http://127.0.0.1:8888")

        self.ed_audio_proxy = QLineEdit("http://127.0.0.1:8080")
        self.cb_audio_use_proxy = QCheckBox("Use proxy")
        self.cb_audio_use_proxy.setChecked(True)

        self.sp_audio_timeout = QSpinBox()
        self.sp_audio_timeout.setRange(1000, 60000)
        self.sp_audio_timeout.setValue(12000)

        self.sp_audio_max_fetch_kb = QSpinBox()
        self.sp_audio_max_fetch_kb.setRange(64, 10240)
        self.sp_audio_max_fetch_kb.setValue(2048)

        self.sp_audio_scan_max_results = QSpinBox()
        self.sp_audio_scan_max_results.setRange(1, 200)
        self.sp_audio_scan_max_results.setValue(30)

        self.sp_audio_scan_expand_pages = QSpinBox()
        self.sp_audio_scan_expand_pages.setRange(0, 50)
        self.sp_audio_scan_expand_pages.setValue(6)

        self.sp_audio_scan_max_links = QSpinBox()
        self.sp_audio_scan_max_links.setRange(1, 200)
        self.sp_audio_scan_max_links.setValue(40)

        self.cb_audio_block_private = QCheckBox("Block private hosts")
        self.cb_audio_block_private.setChecked(True)

        afl.addRow("Spool dir", _hbox(self.ed_audio_spool_dir, self.btn_audio_spool_dir))
        afl.addRow(self.cb_audio_persist)
        afl.addRow("SearXNG URL", self.ed_audio_searxng_url)
        afl.addRow("HTTP proxy", self.ed_audio_proxy)
        afl.addRow(self.cb_audio_use_proxy)
        afl.addRow("Timeout (ms)", self.sp_audio_timeout)
        afl.addRow("Max fetch (KB)", self.sp_audio_max_fetch_kb)
        afl.addRow("Scan max results", self.sp_audio_scan_max_results)
        afl.addRow("Scan expand pages", self.sp_audio_scan_expand_pages)
        afl.addRow("Scan max links/page", self.sp_audio_scan_max_links)
        afl.addRow(self.cb_audio_block_private)

        self.btn_audio_spool_dir.clicked.connect(lambda: self._browse_dir_into(self.ed_audio_spool_dir))

        lay.addWidget(gba)

        gbp = QGroupBox("Python API / ws_bridge")
        pfl = QFormLayout(gbp)

        self.cb_python_serve = QCheckBox("Serve script/UI (--api-python-serve on)")
        self.cb_python_serve.setChecked(True)

        self.cb_python_control = QCheckBox("Allow start/stop from API (--api-python-control on)")
        self.cb_python_control.setChecked(False)

        self.cb_python_control_local = QCheckBox("Control localhost only (--api-python-control-local on)")
        self.cb_python_control_local.setChecked(True)

        self.ed_python_spool_dir = QLineEdit(str(app_data_dir() / "python_bridge"))
        self.btn_python_spool_dir = QPushButton("Browse…")
        self.ed_python_exe = QLineEdit("python")
        self.ed_python_bridge_host = QLineEdit("127.0.0.1")

        self.sp_python_bridge_port = QSpinBox()
        self.sp_python_bridge_port.setRange(1, 65535)
        self.sp_python_bridge_port.setValue(39001)

        self.ed_python_blocknet_url = QLineEdit("http://127.0.0.1:38888")
        self.ed_python_blocknet_prefix = QLineEdit("/v1")
        self.ed_python_headers_json = QLineEdit("{}")
        self.ed_python_headers_json.setPlaceholderText('e.g. {"X-Blocknet-Key":"dev-..."}')

        self.btn_python_spool_dir.clicked.connect(lambda: self._browse_dir_into(self.ed_python_spool_dir))

        pfl.addRow(self.cb_python_serve)
        pfl.addRow(self.cb_python_control)
        pfl.addRow(self.cb_python_control_local)
        pfl.addRow("Spool dir", _hbox(self.ed_python_spool_dir, self.btn_python_spool_dir))
        pfl.addRow("Python executable", self.ed_python_exe)
        pfl.addRow("Bridge listen host", self.ed_python_bridge_host)
        pfl.addRow("Bridge listen port", self.sp_python_bridge_port)
        pfl.addRow("Bridge BlockNet URL", self.ed_python_blocknet_url)
        pfl.addRow("Bridge API prefix", self.ed_python_blocknet_prefix)
        pfl.addRow("Bridge headers JSON", self.ed_python_headers_json)

        lay.addWidget(gbp)
        lay.addStretch(1)
        self.left_tabs.addTab(self._wrap_scroll(tab), "API Config")

    # ---------------- Right tabs ----------------

    def _build_right_output_tabs(self) -> None:
        out_tab = QWidget()
        out_l = QVBoxLayout(out_tab)
        self.txt_out = QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(self.mono)
        out_l.addWidget(self.txt_out)
        self.right_tabs.addTab(out_tab, "Output")

        log_tab = QWidget()
        log_l = QVBoxLayout(log_tab)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(self.mono)
        log_l.addWidget(self.txt_log)
        self.right_tabs.addTab(log_tab, "Server Console")

        proxy_tab = QWidget()
        proxy_l = QVBoxLayout(proxy_tab)
        self.txt_proxy = QPlainTextEdit()
        self.txt_proxy.setReadOnly(True)
        self.txt_proxy.setFont(self.mono)
        proxy_l.addWidget(self.txt_proxy)
        self.right_tabs.addTab(proxy_tab, "Proxy")

        gateway_tab = QWidget()
        gateway_l = QVBoxLayout(gateway_tab)
        self.txt_gateway = QPlainTextEdit()
        self.txt_gateway.setReadOnly(True)
        self.txt_gateway.setFont(self.mono)
        gateway_l.addWidget(self.txt_gateway)
        self.right_tabs.addTab(gateway_tab, "Gateway")

        net_tab = QWidget()
        net_l = QVBoxLayout(net_tab)
        top = QHBoxLayout()
        self.cb_net_pause = QCheckBox("Pause")
        self.btn_net_clear = QPushButton("Clear")
        self.btn_net_clear.clicked.connect(lambda: self.txt_net.setPlainText(""))
        top.addWidget(QLabel("Network logs"))
        top.addStretch(1)
        top.addWidget(self.cb_net_pause)
        top.addWidget(self.btn_net_clear)
        net_l.addLayout(top)

        self.txt_net = QPlainTextEdit()
        self.txt_net.setReadOnly(True)
        self.txt_net.setFont(self.mono)
        net_l.addWidget(self.txt_net, 1)
        self.right_tabs.addTab(net_tab, "Network")

        self.btn_clear_out.clicked.connect(lambda: self.txt_out.setPlainText(""))
        self.btn_clear_log.clicked.connect(lambda: self.txt_log.setPlainText(""))
        self.btn_clear_net.clicked.connect(lambda: self.txt_net.setPlainText(""))

    def _build_right_api_tabs(self) -> None:
        self.right_tabs.addTab(self._wrap_scroll(self._tab_texttovec()), "API: TextToVec")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_vectortext()), "API: VectorText")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_web()), "API: Web")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_media()), "API: Media")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_randomx()), "API: RandomX")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_p2pool()), "API: P2Pool")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_network()), "API: Network")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_audio()), "API: Audio")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_python()), "API: Python")
        self.right_tabs.addTab(self._wrap_scroll(self._tab_webworker()), "API: WebWorker")

    def _wrap_scroll(self, inner: QWidget) -> QWidget:
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setFrameShape(QScrollArea.NoFrame)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        sc.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        sc.setWidget(inner)
        return sc
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
        self.vtxt_vector_b64.setPlaceholderText("optional vector_b64f32")

        self.vtxt_max_tokens = QSpinBox()
        self.vtxt_max_tokens.setRange(1, 2000)
        self.vtxt_max_tokens.setValue(160)

        self.vtxt_topk = QSpinBox()
        self.vtxt_topk.setRange(1, 256)
        self.vtxt_topk.setValue(16)

        self.vtxt_seed = QLineEdit("0")

        self.btn_vtxt = QPushButton("Run vectortext")
        self.btn_vtxt.clicked.connect(self._do_vectortext)

        fl.addRow("prompt", self.vtxt_prompt)
        fl.addRow("payload", self.vtxt_payload)
        fl.addRow("key", self.vtxt_key)
        fl.addRow("lexicon_key", self.vtxt_lexicon_key)
        fl.addRow("context_key", self.vtxt_context_key)
        fl.addRow("idf", self.vtxt_idf)
        fl.addRow("tokens", self.vtxt_tokens)
        fl.addRow("lexicon (inline)", self.vtxt_lexicon_inline)
        fl.addRow("context (inline)", self.vtxt_context_inline)
        fl.addRow("vector (JSON)", self.vtxt_vector_json)
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

        gb1 = QGroupBox("POST /v1/web/fetch")
        fl1 = QFormLayout(gb1)

        self.web_url = QLineEdit("https://example.com")
        self.web_mode = QComboBox()
        self.web_mode.addItems(["html", "text"])
        self.web_include_js = QCheckBox("include_js")
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

        gb2 = QGroupBox("POST /v1/web/js")
        fl2 = QFormLayout(gb2)

        self.webjs_url = QLineEdit("https://example.com")
        self.webjs_fetch_bodies = QCheckBox("fetch_bodies")
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

        gb3 = QGroupBox("POST /v1/web/links")
        fl3 = QFormLayout(gb3)

        self.weblinks_url = QLineEdit("https://example.com")
        self.weblinks_filter = QComboBox()
        self.weblinks_filter.addItems(["all", "same-origin", "external-only"])
        self.weblinks_max = QSpinBox()
        self.weblinks_max.setRange(1, 8192)
        self.weblinks_max.setValue(512)

        self.btn_web_links = QPushButton("Run web/links")
        self.btn_web_links.clicked.connect(self._do_web_links)

        fl3.addRow("url", self.weblinks_url)
        fl3.addRow("filter", self.weblinks_filter)
        fl3.addRow("max_links", self.weblinks_max)
        fl3.addRow(self.btn_web_links)

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

        gbi = QGroupBox("POST /v1/imagetovec")
        fli = QFormLayout(gbi)

        self.img_path = QLineEdit("")
        self.btn_img_browse = QPushButton("Browse…")
        self.btn_img_browse.clicked.connect(
            lambda: self._browse_file_into(
                self.img_path,
                "Images (*.png *.jpg *.jpeg *.webp *.bmp *.gif);;All files (*.*)"
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

        gbv = QGroupBox("POST /v1/videotovec")
        flv = QFormLayout(gbv)

        self.vid_path = QLineEdit("")
        self.btn_vid_browse = QPushButton("Browse…")
        self.btn_vid_browse.clicked.connect(
            lambda: self._browse_file_into(
                self.vid_path,
                "Videos (*.mp4 *.mkv *.webm *.mov *.avi);;All files (*.*)"
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
        self.rx_data = QPlainTextEdit()
        self.rx_data.setFont(self.mono)

        self.btn_rxhash = QPushButton("Compute RandomX hash")
        self.btn_rxhash.clicked.connect(self._do_randomx_hash)

        fl.addRow("seed_hex", self.rx_seed_hex)
        fl.addRow("data mode", self.rx_data_mode)
        fl.addRow("data", self.rx_data)
        fl.addRow(self.btn_rxhash)

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

        flb.addRow("items (array or full body)", self.rx_batch_items)
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
        self.p2_open_extra_json.setPlaceholderText('{"mini": true}')

        fl0.addRow("host", self.p2_open_host)
        fl0.addRow("wallet", self.p2_open_wallet)
        fl0.addRow("rig_id", self.p2_open_rig)
        fl0.addRow("threads (0=default)", self.p2_open_threads)
        fl0.addRow("extra JSON", self.p2_open_extra_json)

        gb = QGroupBox("P2Pool API")
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

        gb2 = QGroupBox("Submit share")
        fl2 = QFormLayout(gb2)

        self.p2_submit_json = QPlainTextEdit()
        self.p2_submit_json.setFont(self.mono)
        self.p2_submit_json.setPlainText(json.dumps({
            "session": "",
            "line": "submit ..."
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

    def _tab_network(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb1 = QGroupBox("GET /v1/network/status")
        l1 = QVBoxLayout(gb1)
        self.btn_net_stat = QPushButton("Fetch network status")
        self.btn_net_stat.clicked.connect(self._do_network_status)
        l1.addWidget(self.btn_net_stat)

        gb2 = QGroupBox("POST /v1/network/poll")
        fl2 = QFormLayout(gb2)

        self.net_poll_max = QSpinBox()
        self.net_poll_max.setRange(1, 2048)
        self.net_poll_max.setValue(64)

        self.net_poll_wait = QSpinBox()
        self.net_poll_wait.setRange(0, 60000)
        self.net_poll_wait.setValue(0)

        self.net_poll_enc = QComboBox()
        self.net_poll_enc.addItems(["b64", "hex"])

        self.btn_net_poll = QPushButton("Poll packets")
        self.btn_net_poll.clicked.connect(self._do_network_poll)

        fl2.addRow("max", self.net_poll_max)
        fl2.addRow("wait_ms", self.net_poll_wait)
        fl2.addRow("encoding", self.net_poll_enc)
        fl2.addRow(self.btn_net_poll)

        gb3 = QGroupBox("POST /v1/network/inject")
        fl3 = QFormLayout(gb3)

        self.net_inj_mode = QComboBox()
        self.net_inj_mode.addItems(["packet_b64", "packet_hex"])

        self.net_inj_pkt = QPlainTextEdit()
        self.net_inj_pkt.setFont(self.mono)
        self.net_inj_pkt.setPlaceholderText("Paste raw IP packet as base64 or hex")

        self.net_inj_repeat = QSpinBox()
        self.net_inj_repeat.setRange(1, 1000)
        self.net_inj_repeat.setValue(1)

        self.btn_net_inject = QPushButton("Inject packet")
        self.btn_net_inject.clicked.connect(self._do_network_inject)

        fl3.addRow("mode", self.net_inj_mode)
        fl3.addRow("packet", self.net_inj_pkt)
        fl3.addRow("repeat", self.net_inj_repeat)
        fl3.addRow(self.btn_net_inject)

        lay.addWidget(gb1)
        lay.addWidget(gb2)
        lay.addWidget(gb3)

        self.net_out = self._mk_api_out()
        lay.addWidget(self.net_out, 1)
        return tab

    def _tab_audio(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb1 = QGroupBox("GET /v1/audio/status / Open UI")
        fl1 = QFormLayout(gb1)

        self.audio_play_url = QLineEdit("")
        self.audio_play_url.setPlaceholderText("optional URL to pass to /audio/play")

        row1 = QHBoxLayout()
        self.btn_audio_tab_status = QPushButton("Fetch audio status")
        self.btn_audio_tab_open_ui = QPushButton("Open /audio/ui")
        self.btn_audio_tab_embed_ui = QPushButton("Load embedded /audio/ui")
        self.btn_audio_tab_open_play = QPushButton("Open /audio/play")
        row1.addWidget(self.btn_audio_tab_status)
        row1.addWidget(self.btn_audio_tab_open_ui)
        row1.addWidget(self.btn_audio_tab_embed_ui)
        row1.addWidget(self.btn_audio_tab_open_play)

        self.btn_audio_tab_status.clicked.connect(self._do_audio_status)
        self.btn_audio_tab_open_ui.clicked.connect(self._do_audio_open_ui)
        self.btn_audio_tab_embed_ui.clicked.connect(self._do_audio_embed_ui)
        self.btn_audio_tab_open_play.clicked.connect(self._do_audio_open_play)

        fl1.addRow("play url", self.audio_play_url)
        fl1.addRow(row1)

        gb2 = QGroupBox("POST /v1/audio/scan")
        fl2 = QFormLayout(gb2)

        self.audio_scan_query = QLineEdit("")
        self.audio_scan_query.setPlaceholderText("ambient sample pack mp3")
        self.btn_audio_scan = QPushButton("Scan")
        self.btn_audio_scan.clicked.connect(self._do_audio_scan)

        fl2.addRow("query", self.audio_scan_query)
        fl2.addRow(self.btn_audio_scan)

        gb3 = QGroupBox("Playlist")
        fl3 = QFormLayout(gb3)

        self.audio_playlist_name = QLineEdit("")
        self.audio_playlist_combo = QComboBox()
        self.audio_item_title = QLineEdit("")
        self.audio_item_url = QLineEdit("")
        self.audio_remove_item_id = QLineEdit("")

        row3a = QHBoxLayout()
        self.btn_audio_pl_create = QPushButton("Create")
        self.btn_audio_pl_refresh = QPushButton("Refresh list")
        self.btn_audio_pl_get = QPushButton("Get")
        row3a.addWidget(self.btn_audio_pl_create)
        row3a.addWidget(self.btn_audio_pl_refresh)
        row3a.addWidget(self.btn_audio_pl_get)

        row3b = QHBoxLayout()
        self.btn_audio_pl_rename = QPushButton("Rename")
        self.btn_audio_pl_clear = QPushButton("Clear")
        row3b.addWidget(self.btn_audio_pl_rename)
        row3b.addWidget(self.btn_audio_pl_clear)

        row3c = QHBoxLayout()
        self.btn_audio_pl_add = QPushButton("Add item")
        self.btn_audio_pl_remove = QPushButton("Remove item")
        row3c.addWidget(self.btn_audio_pl_add)
        row3c.addWidget(self.btn_audio_pl_remove)

        self.btn_audio_pl_create.clicked.connect(self._do_audio_playlist_create)
        self.btn_audio_pl_refresh.clicked.connect(self._do_audio_playlist_refresh)
        self.btn_audio_pl_get.clicked.connect(self._do_audio_playlist_get)
        self.btn_audio_pl_rename.clicked.connect(self._do_audio_playlist_rename)
        self.btn_audio_pl_clear.clicked.connect(self._do_audio_playlist_clear)
        self.btn_audio_pl_add.clicked.connect(self._do_audio_playlist_add)
        self.btn_audio_pl_remove.clicked.connect(self._do_audio_playlist_remove)

        fl3.addRow("playlist name", self.audio_playlist_name)
        fl3.addRow("active playlist", self.audio_playlist_combo)
        fl3.addRow(row3a)
        fl3.addRow(row3b)
        fl3.addRow("item title", self.audio_item_title)
        fl3.addRow("item url", self.audio_item_url)
        fl3.addRow("remove item id", self.audio_remove_item_id)
        fl3.addRow(row3c)

        lay.addWidget(gb1)
        lay.addWidget(gb2)
        lay.addWidget(gb3)

        self.audio_out = self._mk_api_out()
        lay.addWidget(self.audio_out, 1)

        if _WEBENGINE_OK:
            self.audio_view = self._make_authed_web_view()
            if self.audio_view is not None:
                self.audio_view.setMinimumHeight(420)
                lay.addWidget(self.audio_view, 1)
            else:
                self.audio_view = None
        else:
            self.audio_view = None
        return tab

    def _tab_python(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        gb1 = QGroupBox("Python bridge admin")
        fl1 = QFormLayout(gb1)

        row1 = QHBoxLayout()
        self.btn_py_status = QPushButton("Fetch status")
        self.btn_py_log = QPushButton("Fetch log tail")
        self.btn_py_script = QPushButton("Fetch bridge script")
        row1.addWidget(self.btn_py_status)
        row1.addWidget(self.btn_py_log)
        row1.addWidget(self.btn_py_script)

        row2 = QHBoxLayout()
        self.btn_py_start = QPushButton("Start bridge")
        self.btn_py_stop = QPushButton("Stop bridge")
        self.btn_py_embed_admin = QPushButton("Load embedded admin UI")
        self.btn_py_open_bridge = QPushButton("Open running bridge UI")
        row2.addWidget(self.btn_py_start)
        row2.addWidget(self.btn_py_stop)
        row2.addWidget(self.btn_py_embed_admin)
        row2.addWidget(self.btn_py_open_bridge)

        fl1.addRow(row1)
        fl1.addRow(row2)

        self.btn_py_status.clicked.connect(self._do_python_status)
        self.btn_py_log.clicked.connect(self._do_python_log)
        self.btn_py_script.clicked.connect(self._do_python_script)
        self.btn_py_start.clicked.connect(self._do_python_start)
        self.btn_py_stop.clicked.connect(self._do_python_stop)
        self.btn_py_embed_admin.clicked.connect(self._do_python_embed_admin_ui)
        self.btn_py_open_bridge.clicked.connect(self._do_python_open_bridge_ui)

        lay.addWidget(gb1)

        gb2 = QGroupBox("Python bridge output")
        l2 = QVBoxLayout(gb2)
        self.python_out = self._mk_api_out()
        l2.addWidget(self.python_out)
        lay.addWidget(gb2)

        gb3 = QGroupBox("Bridge script preview")
        l3 = QVBoxLayout(gb3)
        self.python_script_out = QPlainTextEdit()
        self.python_script_out.setFont(self.mono)
        l3.addWidget(self.python_script_out)
        lay.addWidget(gb3, 1)

        if _WEBENGINE_OK:
            self.python_view = self._make_authed_web_view()
            if self.python_view is not None:
                self.python_view.setMinimumHeight(420)
                lay.addWidget(self.python_view, 1)
            else:
                self.python_view = None
        else:
            self.python_view = None
        return tab

    # ---------------- WebWorker harness ----------------

    def _webworker_harness_html(self) -> str:
        return r"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>BlockNet Worker Harness</title>
<style>
  body { margin:0; background:#101113; color:#e6e6e6; font-family:system-ui,sans-serif; }
  header { position:sticky; top:0; padding:10px 12px; background:#17181c; border-bottom:1px solid #2d2f36; z-index:5; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .pill { font-size:12px; padding:4px 10px; border:1px solid #343741; border-radius:999px; }
  .ok { color:#9fe59f; }
  .bad { color:#ffb1b1; }
  main { padding:12px; max-width:1200px; margin:0 auto; }
  .card { background:#15161a; border:1px solid #2d2f36; border-radius:12px; padding:12px; margin:12px 0; }
  .grid { display:grid; gap:10px; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); }
  .wcard { border:1px solid #343741; border-radius:10px; background:#111217; padding:10px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  pre { white-space: pre-wrap; word-break: break-word; background:#0b0c0f; border:1px solid #2d2f36; border-radius:10px; padding:10px; min-height:120px; max-height:280px; overflow:auto; }
  button { border:1px solid #3a3d48; border-radius:8px; background:#20232b; color:#fff; padding:8px 10px; font-weight:600; }
  .hint { opacity:.75; font-size:12px; }
  .kv { display:grid; grid-template-columns:110px 1fr; gap:4px 8px; font-size:12px; }
</style>
</head>
<body>
<header>
  <div class="row">
    <b>BlockNet Worker Harness</b>
    <span id="globalPill" class="pill">idle</span>
    <span id="presetPill" class="pill mono"></span>
    <span style="flex:1"></span>
    <button onclick="bn_startMiner((window.__bn_preset||{}).miner||{})">Start Miner</button>
    <button onclick="bn_startRandomX((window.__bn_preset||{}).randomx||{})">Start RandomX</button>
    <button onclick="bn_startHash((window.__bn_preset||{}).hash||{})">Start Hash</button>
    <button onclick="bn_statusAll()">Status All</button>
    <button onclick="bn_stopAll()">Stop All</button>
    <button onclick="bn_clearAll()">Clear</button>
  </div>
  <div class="hint">This harness is local to the GUI/browser and fetches worker scripts from your BlockNet server using the preset payloads pushed in by the GUI.</div>
</header>

<main>
  <div class="card">
    <div class="hint mono" id="presetJson"></div>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Miner Workers</h3>
    <div class="grid" id="miner_cards"></div>
    <pre id="miner_log"></pre>
  </div>

  <div class="card">
    <h3 style="margin-top:0">RandomX RPC Workers</h3>
    <div class="grid" id="randomx_cards"></div>
    <pre id="randomx_log"></pre>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Local Hash Workers</h3>
    <div class="grid" id="hash_cards"></div>
    <pre id="hash_log"></pre>
  </div>

  <div class="card">
    <h3 style="margin-top:0">Global Log</h3>
    <pre id="global_log"></pre>
  </div>
</main>

<script>
window.__bn_preset = { miner:{}, randomx:{}, hash:{} };

function $(id){ return document.getElementById(id); }
function iso(){ return new Date().toISOString(); }

function logTo(id, line){
  const el = $(id);
  if (!el) return;
  el.textContent = `[${iso()}] ${line}\n` + el.textContent;
}

function setPill(id, text, cls){
  const el = $(id);
  if (!el) return;
  el.textContent = text;
  el.className = "pill " + (cls || "");
}

function fmtHr(hs){
  const n = Number(hs || 0);
  if (!Number.isFinite(n) || n <= 0) return "-";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + " MH/s";
  if (n >= 1e3) return (n / 1e3).toFixed(2) + " kH/s";
  return n.toFixed(2) + " H/s";
}

class WorkerGroup {
  constructor(name, cardsId, logId){
    this.name = name;
    this.cardsId = cardsId;
    this.logId = logId;
    this.workers = [];
    this.state = [];
  }

  clear(){
    logTo(this.logId, "clear");
    $(this.logId).textContent = "";
  }

  _renderCards(){
    const root = $(this.cardsId);
    if (!root) return;
    root.innerHTML = "";
    for (let i = 0; i < this.state.length; i++) {
      const st = this.state[i];
      const div = document.createElement("div");
      div.className = "wcard";
      div.innerHTML = `
        <div class="row" style="justify-content:space-between">
          <b>${this.name} #${i}</b>
          <span class="pill">${st.running ? "running" : "idle"}</span>
        </div>
        <div class="kv mono" style="margin-top:8px">
          <div>session</div><div>${st.session || "-"}</div>
          <div>job</div><div>${st.job || "-"}</div>
          <div>hashrate</div><div>${fmtHr(st.hashrate || 0)}</div>
          <div>hashes</div><div>${st.hashes || 0}</div>
          <div>found</div><div>${st.found || 0}</div>
          <div>submitted</div><div>${st.submitted || 0}</div>
          <div>accepted</div><div>${st.accepted || 0}</div>
          <div>last err</div><div>${st.last_error || "-"}</div>
        </div>
      `;
      root.appendChild(div);
    }
  }

  stop(kill=true){
    for (const w of this.workers){
      try { w.postMessage({ op:"stop" }); } catch(e){}
      if (kill) {
        try { w.terminate(); } catch(e){}
      }
    }
    if (kill) {
      this.workers = [];
      this.state = [];
      this._renderCards();
    }
  }

  status(){
    for (const w of this.workers){
      try { w.postMessage({ op:"status" }); } catch(e){}
    }
  }

  start(payload){
    payload = payload || {};
    const workerUrl = String(payload.worker_url || payload.workerUrl || "");
    const count = Math.max(1, Number(payload.count || 1) | 0);
    const cfg = payload.cfg || {};
    const scriptHeaders = payload.script_headers || {};

    if (!workerUrl) {
      logTo(this.logId, "worker_url missing");
      return { ok:false, error:"worker_url missing" };
    }

    this.stop(true);
    this.workers = [];
    this.state = [];

    logTo(this.logId, `start count=${count} url=${workerUrl}`);

    const createWorkerFromUrl = async (url, headers) => {
      const resp = await fetch(url, { method:"GET", headers: headers || {} });
      const txt = await resp.text();
      if (!resp.ok) {
        throw new Error(`fetch failed ${resp.status}: ${txt.slice(0, 200)}`);
      }
      const blob = new Blob([txt], { type: "application/javascript" });
      const blobUrl = URL.createObjectURL(blob);
      const w = new Worker(blobUrl, { type: "classic" });
      setTimeout(() => { try { URL.revokeObjectURL(blobUrl); } catch(e){} }, 5000);
      return w;
    };

    (async () => {
      try {
        for (let i = 0; i < count; i++) {
          const w = await createWorkerFromUrl(workerUrl, scriptHeaders);
          this.workers.push(w);
          this.state.push({
            running:false, session:"", job:"",
            hashrate:0, hashes:0, found:0, submitted:0, accepted:0, last_error:""
          });

          w.onmessage = (ev) => {
            const m = ev.data || {};
            const op = m.op || "msg";
            const st = this.state[i] || {};

            if (op === "started") st.running = true;
            if (op === "stopped") st.running = false;
            if (op === "session") {
              st.running = true;
              st.session = String(m.session || "");
              if (m.job && m.job.job_id) st.job = String(m.job.job_id);
            }
            if (op === "job" && m.job && m.job.job_id) st.job = String(m.job.job_id);
            if (op === "scan" && m.stats) {
              st.hashrate = Number(m.stats.hashrate_hs || 0);
              st.hashes = Number(st.hashes || 0) + Number(m.stats.hashes_done || 0);
              st.found = Number(st.found || 0) + Number(m.stats.found || 0);
              if (m.stats.job_id) st.job = String(m.stats.job_id);
            }
            if (op === "submit") {
              st.submitted = Number(st.submitted || 0) + 1;
              if (m.ok) st.accepted = Number(st.accepted || 0) + 1;
            }
            if (op === "status" && m.stats) {
              st.running = !!m.running;
              if (m.session) st.session = String(m.session);
              if (m.stats.last_job_id) st.job = String(m.stats.last_job_id);
              if (Number.isFinite(m.stats.hashes_done)) st.hashes = Number(m.stats.hashes_done);
              if (Number.isFinite(m.stats.shares_found)) st.found = Number(m.stats.shares_found);
              if (Number.isFinite(m.stats.shares_submitted)) st.submitted = Number(m.stats.shares_submitted);
              if (Number.isFinite(m.stats.shares_submit_ok)) st.accepted = Number(m.stats.shares_submit_ok);
              if (m.stats.last_error) st.last_error = String(m.stats.last_error);
            }
            if (op === "error") st.last_error = String(m.error || "error");
            logTo(this.logId, `#${i} ${op}: ${JSON.stringify(m)}`);
            this._renderCards();
          };

          w.onerror = (ev) => {
            const st = this.state[i] || {};
            st.last_error = String(ev && ev.message ? ev.message : ev);
            logTo(this.logId, `#${i} onerror: ${st.last_error}`);
            this._renderCards();
          };

          w.postMessage({ op:"start", cfg: cfg });
        }

        this._renderCards();
      } catch (e) {
        logTo(this.logId, "start error: " + String(e && e.message ? e.message : e));
      }
    })();

    return { ok:true };
  }
}

const minerG = new WorkerGroup("miner", "miner_cards", "miner_log");
const randomxG = new WorkerGroup("randomx", "randomx_cards", "randomx_log");
const hashG = new WorkerGroup("hash", "hash_cards", "hash_log");

function _globalSet(){
  const any = minerG.workers.length || randomxG.workers.length || hashG.workers.length;
  setPill("globalPill", any ? "running" : "idle", any ? "ok" : "");
  $("presetPill").textContent = location.origin;
}

function bn_setPreset(preset){
  window.__bn_preset = preset || { miner:{}, randomx:{}, hash:{} };
  $("presetJson").textContent = JSON.stringify(window.__bn_preset, null, 2);
  logTo("global_log", "preset updated");
  _globalSet();
  return { ok:true };
}

function bn_startMiner(payload){
  logTo("global_log", "start miner");
  const r = minerG.start(payload || {});
  _globalSet();
  return r;
}

function bn_startRandomX(payload){
  logTo("global_log", "start randomx");
  const r = randomxG.start(payload || {});
  _globalSet();
  return r;
}

function bn_startHash(payload){
  logTo("global_log", "start hash");
  const r = hashG.start(payload || {});
  _globalSet();
  return r;
}

function bn_statusAll(){
  minerG.status();
  randomxG.status();
  hashG.status();
  logTo("global_log", "status all");
  _globalSet();
  return { ok:true };
}

function bn_stopAll(){
  minerG.stop(true);
  randomxG.stop(true);
  hashG.stop(true);
  logTo("global_log", "stop all");
  _globalSet();
  return { ok:true };
}

function bn_clearAll(){
  minerG.clear();
  randomxG.clear();
  hashG.clear();
  $("global_log").textContent = "";
  logTo("global_log", "cleared");
  return { ok:true };
}

window.bn_setPreset = bn_setPreset;
window.bn_startMiner = bn_startMiner;
window.bn_startRandomX = bn_startRandomX;
window.bn_startHash = bn_startHash;
window.bn_statusAll = bn_statusAll;
window.bn_stopAll = bn_stopAll;
window.bn_clearAll = bn_clearAll;

_globalSet();
bn_setPreset(window.__bn_preset);
</script>
</body>
</html>
"""

    def _tab_webworker(self) -> QWidget:
        tab = QWidget()
        lay = QVBoxLayout(tab)

        shared = QGroupBox("Shared WebWorker Settings")
        sfl = QFormLayout(shared)

        self.webw_base = QLineEdit("")
        self.webw_base.setPlaceholderText("auto from Relay")

        self.webw_send_auth = QCheckBox("Send auth headers to fetch worker scripts and APIs")
        self.webw_send_auth.setChecked(True)

        row = QHBoxLayout()
        self.btn_webw_config = QPushButton("Fetch /webworker/config")
        self.btn_webw_sync = QPushButton("Sync harness preset")
        self.btn_webw_status = QPushButton("Status all")
        self.btn_webw_stop = QPushButton("Stop all")
        self.btn_webw_clear = QPushButton("Clear")
        self.btn_webw_open_external = QPushButton("Open external harness")
        row.addWidget(self.btn_webw_config)
        row.addWidget(self.btn_webw_sync)
        row.addWidget(self.btn_webw_status)
        row.addWidget(self.btn_webw_stop)
        row.addWidget(self.btn_webw_clear)
        row.addWidget(self.btn_webw_open_external)

        sfl.addRow("baseUrl", self.webw_base)
        sfl.addRow(self.webw_send_auth)
        sfl.addRow(row)
        lay.addWidget(shared)

        miner = QGroupBox("Miner Worker")
        mfl = QFormLayout(miner)

        self.webw_miner_url = QLineEdit("")
        self.webw_miner_url.setPlaceholderText("auto: /webworker/miner.js")

        self.webw_miner_count = QSpinBox()
        self.webw_miner_count.setRange(1, 64)
        self.webw_miner_count.setValue(1)

        self.webw_scan_iters = QSpinBox()
        self.webw_scan_iters.setRange(1, 50_000_000)
        self.webw_scan_iters.setSingleStep(50_000)
        self.webw_scan_iters.setValue(200_000)

        self.webw_scan_max_results = QSpinBox()
        self.webw_scan_max_results.setRange(1, 512)
        self.webw_scan_max_results.setValue(4)

        self.webw_scan_threads = QSpinBox()
        self.webw_scan_threads.setRange(0, 4096)
        self.webw_scan_threads.setValue(0)

        self.webw_poll_max_msgs = QSpinBox()
        self.webw_poll_max_msgs.setRange(1, 512)
        self.webw_poll_max_msgs.setValue(32)

        self.webw_sleep_ms = QSpinBox()
        self.webw_sleep_ms.setRange(0, 5000)
        self.webw_sleep_ms.setValue(0)

        self.webw_poll_first = QCheckBox("poll_first")
        self.webw_poll_first.setChecked(True)

        self.btn_webw_start_miner = QPushButton("Start miner workers")
        self.btn_webw_start_miner.clicked.connect(self._do_webworker_start_miner)

        mfl.addRow("worker_url", self.webw_miner_url)
        mfl.addRow("count", self.webw_miner_count)
        mfl.addRow("scan_iters", self.webw_scan_iters)
        mfl.addRow("scan_max_results", self.webw_scan_max_results)
        mfl.addRow("scan_threads", self.webw_scan_threads)
        mfl.addRow("poll_max_msgs", self.webw_poll_max_msgs)
        mfl.addRow("sleep_ms", self.webw_sleep_ms)
        mfl.addRow(self.webw_poll_first)
        mfl.addRow(self.btn_webw_start_miner)
        lay.addWidget(miner)

        rx = QGroupBox("RandomX RPC Worker")
        rfl = QFormLayout(rx)

        self.webw_rx_url = QLineEdit("")
        self.webw_rx_url.setPlaceholderText("auto: /webworker/randomx_rpc.js")

        self.webw_rx_count = QSpinBox()
        self.webw_rx_count.setRange(1, 64)
        self.webw_rx_count.setValue(1)

        self.webw_rx_hash_ms = QSpinBox()
        self.webw_rx_hash_ms.setRange(1000, 120000)
        self.webw_rx_hash_ms.setValue(15000)

        self.webw_rx_batch_ms = QSpinBox()
        self.webw_rx_batch_ms.setRange(1000, 120000)
        self.webw_rx_batch_ms.setValue(30000)

        self.webw_rx_wasm_url = QLineEdit("")
        self.webw_rx_wasm_url.setPlaceholderText("optional wasm helper URL")

        self.btn_webw_start_rx = QPushButton("Start RandomX RPC workers")
        self.btn_webw_start_rx.clicked.connect(self._do_webworker_start_randomx)

        rfl.addRow("worker_url", self.webw_rx_url)
        rfl.addRow("count", self.webw_rx_count)
        rfl.addRow("hash_ms", self.webw_rx_hash_ms)
        rfl.addRow("batch_ms", self.webw_rx_batch_ms)
        rfl.addRow("local_randomx_wasm_url", self.webw_rx_wasm_url)
        rfl.addRow(self.btn_webw_start_rx)
        lay.addWidget(rx)

        hw = QGroupBox("Local Hash Worker")
        hfl = QFormLayout(hw)

        self.webw_hash_url = QLineEdit("")
        self.webw_hash_url.setPlaceholderText("auto: /webworker/hash_local.js")

        self.webw_hash_count = QSpinBox()
        self.webw_hash_count.setRange(1, 64)
        self.webw_hash_count.setValue(1)

        self.btn_webw_start_hash = QPushButton("Start local hash workers")
        self.btn_webw_start_hash.clicked.connect(self._do_webworker_start_hash)

        hfl.addRow("worker_url", self.webw_hash_url)
        hfl.addRow("count", self.webw_hash_count)
        hfl.addRow(self.btn_webw_start_hash)
        lay.addWidget(hw)

        gb_out = QGroupBox("WebWorker output")
        out_l = QVBoxLayout(gb_out)
        self.webw_out = self._mk_api_out()
        out_l.addWidget(self.webw_out)
        lay.addWidget(gb_out)

        if _WEBENGINE_OK:
            self.webw_view = self._make_authed_web_view()
            if self.webw_view is not None:
                self.webw_view.setMinimumHeight(520)
                try:
                    if QUrl is not None:
                        self.webw_view.setHtml(self._webworker_harness_html(),
                                               QUrl("about:blank"))  # type: ignore[arg-type]
                    else:
                        self.webw_view.setHtml(self._webworker_harness_html())
                except Exception:
                    pass
                try:
                    self.webw_view.loadFinished.connect(self._on_webw_load_finished)  # type: ignore[attr-defined]
                except Exception:
                    pass
                lay.addWidget(self.webw_view, 1)
            else:
                self.webw_view = None
        else:
            self.webw_view = None

        if self.webw_view is None:
            fb = QGroupBox("Embedded harness unavailable")
            fbl = QVBoxLayout(fb)
            msg = QPlainTextEdit()
            msg.setReadOnly(True)
            msg.setFont(self.mono)
            msg.setPlainText(
                "PyQtWebEngine is not installed.\n\n"
                "You can still use 'Open external harness' in your browser.\n"
                "For embedded mode:\n  pip install PyQtWebEngine\n"
            )
            fbl.addWidget(msg)
            lay.addWidget(fb, 1)

        self.btn_webw_config.clicked.connect(self._do_webworker_config)
        self.btn_webw_sync.clicked.connect(self._do_webworker_sync)
        self.btn_webw_status.clicked.connect(self._do_webworker_status_all)
        self.btn_webw_stop.clicked.connect(self._do_webworker_stop_all)
        self.btn_webw_clear.clicked.connect(self._do_webworker_clear_all)
        self.btn_webw_open_external.clicked.connect(self._do_webworker_open_external)

        return tab

    def _on_webw_load_finished(self, ok: bool) -> None:
        self._webw_ready = bool(ok)
        if not ok:
            self._append_plain(self.webw_out, "embedded harness load failed")
            return

        if self._webw_pending_js:
            pending = list(self._webw_pending_js)
            self._webw_pending_js.clear()
            for js in pending:
                self._webworker_run_js(js, queue_if_unready=False)

        self._do_webworker_sync()

    # ---------------- Shared helpers ----------------

    def _schedule_save(self) -> None:
        self.save_timer.start()

    def _set_running(self, running: bool) -> None:
        if running:
            self.status_pill.setText("RUNNING")
            self.status_pill.setStyleSheet("background:#1f4d2e; color:#eaffea;")
        else:
            self.status_pill.setText("STOPPED")
            self.status_pill.setStyleSheet("background:#4a1f1f; color:#ffecec;")

        self.btn_start.setDisabled(running)
        self.btn_stop.setDisabled(not running)

    def _client(self) -> BlockNetClient:
        return BlockNetClient(self.ed_relay.text().strip(), self.ed_token.text().strip())

    def _append_plain(self, w: QPlainTextEdit, s: str, *, prefix: str = "") -> None:
        s = (s or "").replace("\r\n", "\n").replace("\r", "\n")
        for line in s.split("\n"):
            if line:
                w.appendPlainText(prefix + line)

        max_blocks = 4000
        doc = w.document()
        if doc.blockCount() > max_blocks:
            cursor = w.textCursor()
            cursor.movePosition(cursor.Start)
            for _ in range(doc.blockCount() - max_blocks):
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

    def _browse_dir_into(self, edit: QLineEdit) -> None:
        start_dir = edit.text().strip() or str(Path.home())
        path = QFileDialog.getExistingDirectory(self, "Select directory", start_dir)
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

    def _split_extra_args(self, s: str) -> list[str]:
        s = (s or "").strip()
        if not s:
            return []
        out: list[str] = []
        cur: list[str] = []
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

    def _append_threads_args(self, args: list[str], threads: int, flag_str: str) -> None:
        if threads <= 0:
            return
        fs = (flag_str or "").strip() or "--threads"
        toks = self._split_extra_args(fs) or ["--threads"]

        if len(toks) == 1 and "=" in toks[0]:
            k, v = toks[0].split("=", 1)
            args.append(f"{k}={threads}" if not v.strip() else toks[0])
            return

        args.extend(toks)
        args.append(str(threads))

    def _normalize_prefix(self, prefix: Optional[str] = None) -> str:
        pfx = (prefix or self._api_prefix() or "/v1").strip()
        if not pfx.startswith("/"):
            pfx = "/" + pfx
        return pfx.rstrip("/")

    def _http_text(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        *,
        prefix: Optional[str] = None,
        accept: str = "text/plain, text/html, application/json"
    ) -> Tuple[int, Dict[str, str], str]:
        scheme, host, port, relay_base = _parse_relay_parts(self.ed_relay.text().strip())
        pfx = self._normalize_prefix(prefix)

        if not path.startswith("/"):
            path = "/" + path

        full_path = f"{relay_base}{pfx}{path}"

        token = self.ed_token.text().strip()
        headers: Dict[str, str] = {"Accept": accept}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Blocknet-Key"] = token
            headers["X-Blocknet-Token"] = token

        data: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=15, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=15)

        try:
            conn.request(method.upper(), full_path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read() or b""
            txt = raw.decode("utf-8", errors="replace")
            return int(resp.status), {k: v for (k, v) in resp.getheaders()}, txt
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _http_json(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, *, prefix: Optional[str] = None) -> Any:
        scheme, host, port, relay_base = _parse_relay_parts(self.ed_relay.text().strip())
        pfx = self._normalize_prefix(prefix)

        if not path.startswith("/"):
            path = "/" + path

        full_path = f"{relay_base}{pfx}{path}"

        token = self.ed_token.text().strip()
        headers: Dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Blocknet-Key"] = token
            headers["X-Blocknet-Token"] = token

        data: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=15, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=15)

        try:
            conn.request(method.upper(), full_path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read() or b""
            txt = raw.decode("utf-8", errors="replace")

            try:
                out = json.loads(txt) if txt.strip() else {}
            except Exception:
                out = {"ok": False, "raw": txt}

            if isinstance(out, dict):
                out.setdefault("status", int(resp.status))
                out.setdefault("headers", {k: v for (k, v) in resp.getheaders()})
            return out
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ---------------- Output routing ----------------

    def _classify_line(self, line: str) -> Tuple[bool, bool, bool, Optional[str], str]:
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
            return True, False, False, "proxy", cleaned

        if low_ls.startswith("[gateway]") or low_ls.startswith("gateway:") or low_ls.startswith("edge gateway") or low_ls.startswith("edge-gateway"):
            cleaned = lstripped
            for pfx in ("[gateway]", "gateway:", "edge gateway", "edge-gateway"):
                if cleaned.lower().startswith(pfx):
                    cleaned = cleaned[len(pfx):].lstrip()
                    break
            return False, True, False, "gateway", cleaned

        if low_ls.startswith("[blocknet][api-network]") or low_ls.startswith("[api-network]") or low_ls.startswith("api-network:"):
            cleaned = lstripped
            for pfx in ("[blocknet][api-network]", "[api-network]", "api-network:"):
                if cleaned.lower().startswith(pfx):
                    cleaned = cleaned[len(pfx):].lstrip()
                    break
            return False, False, True, "network", cleaned

        if low_ls.startswith("[blocknet][iface]") or low_ls.startswith("[iface]"):
            cleaned = lstripped
            for pfx in ("[blocknet][iface]", "[iface]"):
                if cleaned.lower().startswith(pfx):
                    cleaned = cleaned[len(pfx):].lstrip()
                    break
            return False, False, True, "network", cleaned

        if low_ls.startswith("[blocknet][if:") or low_ls.startswith("[if:"):
            cleaned = lstripped
            if cleaned.lower().startswith("[blocknet]"):
                cleaned = cleaned[len("[blocknet]"):].lstrip()
            return False, False, True, "network", cleaned

        is_proxy = ("[proxy]" in low) or ("tls proxy" in low) or ("tlsproxy" in low) or ("proxy:" in low)
        is_gateway = ("[gateway]" in low) or ("edge gateway" in low) or ("edge-gateway" in low) or ("gateway:" in low)
        is_network = (
            ("[api-network" in low)
            or ("[blocknet][api-network]" in low)
            or ("[blocknet][iface" in low)
            or ("[blocknet][iface]" in low)
            or ("[blocknet][if:" in low)
            or ("[if:" in low and "[blocknet]" in low)
            or ("wintun" in low and "[blocknet]" in low)
        )

        ctx: Optional[str] = None
        if is_proxy and not is_gateway and not is_network:
            ctx = "proxy"
        elif is_gateway and not is_proxy and not is_network:
            ctx = "gateway"
        elif is_network and not (is_proxy or is_gateway):
            ctx = "network"

        return is_proxy, is_gateway, is_network, ctx, raw.strip("\r\n")

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

            is_proxy, is_gateway, is_network, ctx, cleaned = self._classify_line(raw_line)

            if (raw_line.startswith(" ") or raw_line.startswith("\t")) and not (is_proxy or is_gateway or is_network) and self._last_ctx:
                ctx = self._last_ctx
                is_proxy = (ctx == "proxy")
                is_gateway = (ctx == "gateway")
                is_network = (ctx == "network")

            if ctx:
                self._last_ctx = ctx

            if is_proxy and not is_gateway and not is_network:
                self._append_plain(self.txt_proxy, cleaned, prefix="[stderr] " if is_stderr else "")
            elif is_gateway and not is_proxy and not is_network:
                self._append_plain(self.txt_gateway, cleaned, prefix="[stderr] " if is_stderr else "")
            elif is_network and not (is_proxy or is_gateway):
                if not self.cb_net_pause.isChecked():
                    self._append_plain(self.txt_net, cleaned, prefix="[stderr] " if is_stderr else "")
            else:
                if is_proxy:
                    self._append_plain(self.txt_proxy, cleaned, prefix="[stderr] " if is_stderr else "")
                if is_gateway:
                    self._append_plain(self.txt_gateway, cleaned, prefix="[stderr] " if is_stderr else "")
                if is_network and not self.cb_net_pause.isChecked():
                    self._append_plain(self.txt_net, cleaned, prefix="[stderr] " if is_stderr else "")

    def _read_stdout(self) -> None:
        data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if data.strip():
            self._route_process_text(data, is_stderr=False)

    def _read_stderr(self) -> None:
        data = bytes(self.proc.readAllStandardError()).decode("utf-8", errors="replace")
        if data.strip():
            self._route_process_text(data, is_stderr=True)

    def _on_proc_error(self, err) -> None:
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway, self.txt_net):
            self._append_plain(w, f"[gui] process error: {err}")
        self._set_running(False)
        self.timer.stop()

    def _on_finished(self) -> None:
        self.timer.stop()
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway, self.txt_net):
            self._append_plain(w, "[gui] server process exited")
        self._set_running(False)

    # ---------------- Server actions ----------------

    def _gen_token(self) -> None:
        self.ed_token.setText("dev-" + secrets.token_hex(16))
        self._schedule_save()

    def _start_server(self) -> None:
        self._save_cfg()

        if not BIN_EXE.exists():
            QMessageBox.critical(
                self,
                "Missing BlockNet executable",
                f"Not found:\n{BIN_EXE}\n\nPlace BlockNet.exe next to gui.py or bundle it with PyInstaller."
            )
            return

        if self.proc.state() != QProcess.NotRunning:
            QMessageBox.information(self, "Already running", "Server is already running.")
            return

        relay = self.ed_relay.text().strip()
        spool = self.ed_spool.text().strip()
        token = self.ed_token.text().strip()

        args: list[str] = ["serve", "--listen", relay, "--spool", spool]

        th = int(self.sp_threads.value())
        if th > 0:
            self._append_threads_args(args, th, self.ed_threads_flag.text())

        if token:
            args += ["--token", token]

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

            if self.cb_api_webworker.isChecked():
                args += ["--api-webworker", "on"]

            if self.cb_api_process.isChecked():
                args += ["--api-process", "on"]

            if self.cb_api_network.isChecked():
                args += ["--api-network", "on"]
                ndll = self.ed_network_wintun_dll.text().strip()
                if ndll:
                    args += ["--api-network-wintun-dll", ndll]
                nname = self.ed_network_iface.text().strip()
                if nname:
                    args += ["--api-network-iface", nname]
                args += ["--api-network-set-ipv4", "on" if self.cb_network_set_ipv4.isChecked() else "off"]
                nip = self.ed_network_ipv4.text().strip()
                if nip:
                    args += ["--api-network-ipv4", nip]

            if self.cb_api_audio.isChecked():
                args += ["--api-audio", "on"]
                aspool = self.ed_audio_spool_dir.text().strip()
                if aspool:
                    args += ["--api-audio-spool-dir", aspool]
                args += ["--api-audio-persist", "on" if self.cb_audio_persist.isChecked() else "off"]

                searx = self.ed_audio_searxng_url.text().strip()
                if searx:
                    args += ["--api-audio-searxng-url", searx]

                aproxy = self.ed_audio_proxy.text().strip()
                if aproxy:
                    args += ["--api-audio-proxy", aproxy]

                args += ["--api-audio-use-proxy", "on" if self.cb_audio_use_proxy.isChecked() else "off"]
                args += ["--api-audio-timeout-ms", str(self.sp_audio_timeout.value())]
                args += ["--api-audio-max-fetch-bytes", str(self.sp_audio_max_fetch_kb.value() * 1024)]
                args += ["--api-audio-scan-max-results", str(self.sp_audio_scan_max_results.value())]
                args += ["--api-audio-scan-expand-pages", str(self.sp_audio_scan_expand_pages.value())]
                args += ["--api-audio-scan-max-links-per-page", str(self.sp_audio_scan_max_links.value())]
                args += ["--api-audio-block-private", "on" if self.cb_audio_block_private.isChecked() else "off"]

            if self.cb_api_python.isChecked():
                args += ["--api-python", "on"]
                args += ["--api-python-serve", "on" if self.cb_python_serve.isChecked() else "off"]
                args += ["--api-python-control", "on" if self.cb_python_control.isChecked() else "off"]
                args += ["--api-python-control-local", "on" if self.cb_python_control_local.isChecked() else "off"]

                pyspool = self.ed_python_spool_dir.text().strip()
                if pyspool:
                    args += ["--api-python-spool-dir", pyspool]

                pyexe = self.ed_python_exe.text().strip()
                if pyexe:
                    args += ["--api-python-exe", pyexe]

                pyhost = self.ed_python_bridge_host.text().strip()
                if pyhost:
                    args += ["--api-python-bridge-host", pyhost]

                args += ["--api-python-bridge-port", str(int(self.sp_python_bridge_port.value()))]

                bnurl = self.ed_python_blocknet_url.text().strip()
                if bnurl:
                    args += ["--api-python-blocknet-url", bnurl]

                bnpfx = self.ed_python_blocknet_prefix.text().strip()
                if bnpfx:
                    args += ["--api-python-blocknet-prefix", bnpfx]

                hdrs = self.ed_python_headers_json.text().strip()
                if hdrs:
                    args += ["--api-python-headers-json", hdrs]

        proxy_on = self.cb_proxy.isChecked()
        gateway_on = self.cb_gateway.isChecked()

        if proxy_on and gateway_on:
            pl = self.ed_proxy_listen.text().strip()
            gl = self.ed_gateway_listen.text().strip()
            if pl and gl and pl == gl:
                QMessageBox.critical(
                    self,
                    "Port conflict",
                    "Proxy and Gateway are both enabled and listen on the same address."
                )
                return

        if proxy_on:
            args += ["--proxy", "on"]
            if self.ed_proxy_listen.text().strip():
                args += ["--proxy-listen", self.ed_proxy_listen.text().strip()]
            if self.ed_proxy_backend.text().strip():
                args += ["--proxy-backend", self.ed_proxy_backend.text().strip()]

            pc = self._resolve_cert_key_path(self.ed_proxy_cert.text())
            pk = self._resolve_cert_key_path(self.ed_proxy_key.text())
            if pc and pk:
                args += ["--proxy-cert", pc, "--proxy-key", pk]

            if self.ed_proxy_inject.text().strip():
                args += ["--proxy-inject-token", self.ed_proxy_inject.text().strip()]
            if self.ed_proxy_allow.text().strip():
                args += ["--proxy-allow", self.ed_proxy_allow.text().strip()]
            if self.cmb_proxy_log.currentText().strip():
                args += ["--proxy-log", self.cmb_proxy_log.currentText().strip()]

        if gateway_on:
            args += ["--gateway", "on"]
            if self.ed_gateway_listen.text().strip():
                args += ["--gateway-listen", self.ed_gateway_listen.text().strip()]
            if self.ed_gateway_backend.text().strip():
                args += ["--gateway-backend", self.ed_gateway_backend.text().strip()]

            gc = self._resolve_cert_key_path(self.ed_gateway_cert.text())
            gk = self._resolve_cert_key_path(self.ed_gateway_key.text())
            if gc and gk:
                args += ["--gateway-cert", gc, "--gateway-key", gk]

            if self.ed_gateway_allow.text().strip():
                args += ["--gateway-allow", self.ed_gateway_allow.text().strip()]
            if self.cmb_gateway_log.currentText().strip():
                args += ["--gateway-log", self.cmb_gateway_log.currentText().strip()]

            args += self._split_extra_args(self.ed_gateway_extra.text())

        args += self._split_extra_args(self.ed_server_extra.text())
        self._last_ctx = None

        cmdline = f"{BIN_EXE} " + " ".join(args)
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway, self.txt_net):
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

        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway, self.txt_net):
            self._append_plain(w, "[gui] stopping server...")

        self.proc.terminate()
        if not self.proc.waitForFinished(2000):
            for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway, self.txt_net):
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
        except Exception as e:
            self._append_plain(self.txt_out, f"get error: {e}")

    # ---------------- Existing API actions ----------------

    def _api_prefix(self) -> str:
        return self.ed_api_prefix.text().strip() or "/v1"

    def _do_api_ping(self) -> None:
        try:
            j = self._client().api_ping(prefix=self._api_prefix())
            self._append_json(self.txt_out, j)
        except Exception as e:
            self._append_plain(self.txt_out, f"api ping error: {e}")

    def _do_texttovec(self) -> None:
        try:
            j = self._client().api_texttovec(
                self.ttv_text.toPlainText(),
                dim=int(self.ttv_dim.value()),
                normalize=bool(self.ttv_norm.isChecked()),
                output=self.ttv_outfmt.currentText().strip(),
                prefix=self._api_prefix(),
            )
            self.ttv_out.setPlainText("")
            self._append_json(self.ttv_out, j)
        except Exception as e:
            self._append_plain(self.ttv_out, f"texttovec error: {e}")

    def _do_vectortext(self) -> None:
        try:
            body: Dict[str, Any] = {
                "prompt": self.vtxt_prompt.toPlainText().strip(),
                "payload": self.vtxt_payload.toPlainText(),
                "key": self.vtxt_key.text().strip(),
                "lexicon_key": self.vtxt_lexicon_key.text().strip(),
                "context_key": self.vtxt_context_key.text().strip(),
                "max_tokens": int(self.vtxt_max_tokens.value()),
                "topk": int(self.vtxt_topk.value()),
            }

            if self.vtxt_idf.text().strip():
                body["idf"] = _maybe_json_value(self.vtxt_idf.text())
            if self.vtxt_tokens.text().strip():
                body["tokens"] = _maybe_json_value(self.vtxt_tokens.text())
            if self.vtxt_lexicon_inline.toPlainText().strip():
                body["lexicon"] = _maybe_json_value(self.vtxt_lexicon_inline.toPlainText())
            if self.vtxt_context_inline.toPlainText().strip():
                body["context"] = _maybe_json_value(self.vtxt_context_inline.toPlainText())

            vb64 = self.vtxt_vector_b64.text().strip()
            if vb64:
                body["vector_b64f32"] = vb64
            else:
                v = json.loads(self.vtxt_vector_json.toPlainText().strip() or "[]")
                if not isinstance(v, list):
                    raise ValueError("vector must be a JSON list")
                body["vector"] = v

            if self.vtxt_seed.text().strip():
                body["seed"] = _maybe_json_value(self.vtxt_seed.text())

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
            body = {
                "image_b64": base64.b64encode(Path(p).read_bytes()).decode("ascii"),
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
            body = {
                "video_b64": base64.b64encode(Path(p).read_bytes()).decode("ascii"),
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
            body[mode] = data

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
            raw = self.rx_batch_items.toPlainText().strip()
            if not raw:
                raise ValueError("items JSON required")

            parsed = json.loads(raw)
            if isinstance(parsed, list):
                body: Dict[str, Any] = {"seed_hex": seed_hex, "items": parsed}
            elif isinstance(parsed, dict):
                body = dict(parsed)
                body.setdefault("seed_hex", seed_hex)
                if "items" not in body or not isinstance(body["items"], list):
                    raise ValueError("body must include items[]")
            else:
                raise ValueError("JSON must be an array or object")

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

    def _do_network_status(self) -> None:
        try:
            j = self._http_json("GET", "/network/status", None, prefix=self._api_prefix())
            self.net_out.setPlainText("")
            self._append_json(self.net_out, j)
            self._append_json(self.txt_out, j)
        except Exception as e:
            self.net_out.setPlainText("")
            self._append_plain(self.net_out, f"network status error: {e}")

    def _do_network_poll(self) -> None:
        try:
            body = {
                "max": int(self.net_poll_max.value()),
                "wait_ms": int(self.net_poll_wait.value()),
                "encoding": self.net_poll_enc.currentText().strip(),
            }
            j = self._http_json("POST", "/network/poll", body, prefix=self._api_prefix())
            self.net_out.setPlainText("")
            self._append_json(self.net_out, j)
        except Exception as e:
            self._append_plain(self.net_out, f"network poll error: {e}")

    def _do_network_inject(self) -> None:
        try:
            pkt = self.net_inj_pkt.toPlainText().strip()
            if not pkt:
                raise ValueError("packet required")
            body: Dict[str, Any] = {"repeat": int(self.net_inj_repeat.value())}
            body[self.net_inj_mode.currentText().strip()] = pkt
            j = self._http_json("POST", "/network/inject", body, prefix=self._api_prefix())
            self.net_out.setPlainText("")
            self._append_json(self.net_out, j)
        except Exception as e:
            self._append_plain(self.net_out, f"network inject error: {e}")

    def _do_p2pool_open(self) -> None:
        try:
            body: Dict[str, Any] = {}
            if self.p2_open_host.text().strip():
                body["host"] = self.p2_open_host.text().strip()
            if self.p2_open_wallet.text().strip():
                body["wallet"] = self.p2_open_wallet.text().strip()
            if self.p2_open_rig.text().strip():
                body["rig_id"] = self.p2_open_rig.text().strip()
            if int(self.p2_open_threads.value()) > 0:
                body["threads"] = int(self.p2_open_threads.value())

            raw_extra = self.p2_open_extra_json.toPlainText().strip()
            if raw_extra:
                extra = json.loads(raw_extra)
                if not isinstance(extra, dict):
                    raise ValueError("extra JSON must be an object")
                body.update(extra)

            cli = self._client()
            try:
                j = cli.api_p2pool_open(body, prefix=self._api_prefix()) if body else cli.api_p2pool_open(prefix=self._api_prefix())
            except TypeError:
                j = cli.api_p2pool_open(prefix=self._api_prefix())

            self.p2_out.setPlainText("")
            self._append_json(self.p2_out, j)
            sess = j.get("session") or j.get("id") or ""
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
            body = json.loads(self.p2_submit_json.toPlainText().strip() or "{}")
            if not isinstance(body, dict):
                raise ValueError("submit payload must be an object")
            if not body.get("session") and self.p2_session.text().strip():
                body["session"] = self.p2_session.text().strip()
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

    # ---------------- Audio helpers/actions ----------------

    def _audio_base_url(self) -> str:
        return _join_url(_relay_base_url(self.ed_relay.text().strip()).rstrip("/"), self._normalize_prefix() + "/audio")

    def _audio_ui_url(self, *, play_url: str = "") -> str:
        url = self._audio_base_url() + "/ui"
        q: Dict[str, str] = {}
        tok = self.ed_token.text().strip()
        if tok:
            q["token"] = tok
        if play_url.strip():
            q["url"] = play_url.strip()
        if q:
            url += "?" + urllib.parse.urlencode(q)
        return url

    def _audio_play_open_url(self, play_url: str) -> str:
        url = self._audio_base_url() + "/play"
        q: Dict[str, str] = {"url": play_url.strip()}
        tok = self.ed_token.text().strip()
        if tok:
            q["token"] = tok
        return url + "?" + urllib.parse.urlencode(q)

    def _current_audio_playlist_id(self) -> str:
        data = self.audio_playlist_combo.currentData()
        if data:
            return str(data)
        txt = self.audio_playlist_combo.currentText().strip()
        return txt

    def _set_audio_playlist_list(self, j: Dict[str, Any]) -> None:
        arr = j.get("playlists") or []
        current = self._current_audio_playlist_id()
        self.audio_playlist_combo.clear()
        for item in arr:
            pid = str(item.get("id") or "")
            name = str(item.get("name") or pid)
            count = int(item.get("items_count") or 0)
            self.audio_playlist_combo.addItem(f"{name} ({count})", pid)
        if current:
            for i in range(self.audio_playlist_combo.count()):
                if str(self.audio_playlist_combo.itemData(i)) == current:
                    self.audio_playlist_combo.setCurrentIndex(i)
                    break

    def _do_audio_status(self) -> None:
        try:
            j = self._http_json("GET", "/audio/status", None, prefix=self._api_prefix())
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
            self._append_json(self.txt_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"audio status error: {e}")

    def _do_audio_open_ui(self) -> None:
        try:
            webbrowser.open(self._audio_ui_url())
            self.statusBar().showMessage("Opened Audio UI")
        except Exception as e:
            self._append_plain(self.audio_out, f"open audio ui error: {e}")

    def _do_audio_embed_ui(self) -> None:
        self._load_embedded_url(self.audio_view, self._api_route_url("/audio/ui"), self.audio_out)

    def _do_audio_open_play(self) -> None:
        try:
            play_url = self.audio_play_url.text().strip()
            if not play_url:
                raise ValueError("play url required")
            webbrowser.open(self._audio_play_open_url(play_url))
            self.statusBar().showMessage("Opened Audio Play")
        except Exception as e:
            self._append_plain(self.audio_out, f"open audio play error: {e}")

    def _do_audio_scan(self) -> None:
        try:
            query = self.audio_scan_query.text().strip()
            if not query:
                raise ValueError("query required")
            j = self._http_json("POST", "/audio/scan", {"query": query}, prefix=self._api_prefix())
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)

            results = j.get("results") or []
            if results:
                first = results[0]
                if isinstance(first, dict) and first.get("url"):
                    self.audio_play_url.setText(str(first.get("url")))
                    self.audio_item_url.setText(str(first.get("url")))
                    if first.get("title"):
                        self.audio_item_title.setText(str(first.get("title")))
        except Exception as e:
            self._append_plain(self.audio_out, f"audio scan error: {e}")

    def _do_audio_playlist_refresh(self) -> None:
        try:
            j = self._http_json("GET", "/audio/playlist/list", None, prefix=self._api_prefix())
            self._set_audio_playlist_list(j if isinstance(j, dict) else {})
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist list error: {e}")

    def _do_audio_playlist_create(self) -> None:
        try:
            body = {"name": self.audio_playlist_name.text().strip()}
            j = self._http_json("POST", "/audio/playlist/create", body, prefix=self._api_prefix())
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
            self._do_audio_playlist_refresh()

            playlist = j.get("playlist") or {}
            pid = str(playlist.get("id") or "")
            if pid:
                for i in range(self.audio_playlist_combo.count()):
                    if str(self.audio_playlist_combo.itemData(i)) == pid:
                        self.audio_playlist_combo.setCurrentIndex(i)
                        break
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist create error: {e}")

    def _do_audio_playlist_get(self) -> None:
        try:
            pid = self._current_audio_playlist_id()
            if not pid:
                raise ValueError("playlist id required")
            path = "/audio/playlist/get?id=" + urllib.parse.quote(pid)
            j = self._http_json("GET", path, None, prefix=self._api_prefix())
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist get error: {e}")

    def _do_audio_playlist_rename(self) -> None:
        try:
            pid = self._current_audio_playlist_id()
            name = self.audio_playlist_name.text().strip()
            if not pid or not name:
                raise ValueError("playlist and new name required")
            j = self._http_json(
                "POST",
                "/audio/playlist/rename",
                {"playlist_id": pid, "name": name},
                prefix=self._api_prefix(),
            )
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
            self._do_audio_playlist_refresh()
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist rename error: {e}")

    def _do_audio_playlist_clear(self) -> None:
        try:
            pid = self._current_audio_playlist_id()
            if not pid:
                raise ValueError("playlist id required")
            j = self._http_json(
                "POST",
                "/audio/playlist/clear",
                {"playlist_id": pid},
                prefix=self._api_prefix(),
            )
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist clear error: {e}")

    def _do_audio_playlist_add(self) -> None:
        try:
            pid = self._current_audio_playlist_id()
            title = self.audio_item_title.text().strip()
            url = self.audio_item_url.text().strip()
            if not pid or not url:
                raise ValueError("playlist and item url required")
            j = self._http_json(
                "POST",
                "/audio/playlist/add",
                {"playlist_id": pid, "title": title, "url": url},
                prefix=self._api_prefix(),
            )
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist add error: {e}")

    def _do_audio_playlist_remove(self) -> None:
        try:
            pid = self._current_audio_playlist_id()
            item_id = self.audio_remove_item_id.text().strip()
            if not pid or not item_id:
                raise ValueError("playlist and item id required")
            j = self._http_json(
                "POST",
                "/audio/playlist/remove",
                {"playlist_id": pid, "item_id": item_id},
                prefix=self._api_prefix(),
            )
            self.audio_out.setPlainText("")
            self._append_json(self.audio_out, j)
        except Exception as e:
            self._append_plain(self.audio_out, f"playlist remove error: {e}")

    # ---------------- Python bridge helpers/actions ----------------

    def _do_python_status(self) -> None:
        try:
            j = self._http_json("GET", "/network/ws_bridge/status", None, prefix=self._api_prefix())
            self.python_out.setPlainText("")
            self._append_json(self.python_out, j)
            self._append_json(self.txt_out, j)
        except Exception as e:
            self._append_plain(self.python_out, f"python bridge status error: {e}")

    def _do_python_log(self) -> None:
        try:
            j = self._http_json("GET", "/network/ws_bridge/log", None, prefix=self._api_prefix())
            self.python_out.setPlainText("")
            self._append_json(self.python_out, j)
        except Exception as e:
            self._append_plain(self.python_out, f"python bridge log error: {e}")

    def _do_python_script(self) -> None:
        try:
            _, _, txt = self._http_text(
                "GET",
                "/network/ws_bridge.py",
                None,
                prefix=self._api_prefix(),
                accept="text/x-python, text/plain"
            )
            self.python_script_out.setPlainText(txt)
            self._append_plain(self.python_out, "bridge script fetched")
        except Exception as e:
            self._append_plain(self.python_out, f"python bridge script error: {e}")

    def _do_python_start(self) -> None:
        try:
            body = {
                "listen_host": self.ed_python_bridge_host.text().strip() or "127.0.0.1",
                "listen_port": int(self.sp_python_bridge_port.value()),
            }
            j = self._http_json("POST", "/network/ws_bridge/start", body, prefix=self._api_prefix())
            self.python_out.setPlainText("")
            self._append_json(self.python_out, j)
        except Exception as e:
            self._append_plain(self.python_out, f"python bridge start error: {e}")

    def _do_python_stop(self) -> None:
        try:
            j = self._http_json("POST", "/network/ws_bridge/stop", {"graceful": True}, prefix=self._api_prefix())
            self.python_out.setPlainText("")
            self._append_json(self.python_out, j)
        except Exception as e:
            self._append_plain(self.python_out, f"python bridge stop error: {e}")

    def _do_python_embed_admin_ui(self) -> None:
        self._load_embedded_url(self.python_view, self._api_route_url("/network/ws_bridge_ui"), self.python_out)

    def _do_python_open_admin_ui_external(self) -> None:
        try:
            webbrowser.open(self._api_route_url("/network/ws_bridge_ui"))
        except Exception as e:
            self._append_plain(self.python_out, f"open python admin ui error: {e}")

    def _do_python_open_bridge_ui(self) -> None:
        try:
            host = self.ed_python_bridge_host.text().strip() or "127.0.0.1"
            port = int(self.sp_python_bridge_port.value())
            webbrowser.open(f"http://{host}:{port}/ui")
        except Exception as e:
            self._append_plain(self.python_out, f"open running bridge ui error: {e}")

    # ---------------- WebWorker helpers/actions ----------------

    def _webworker_effective_base(self) -> str:
        b = self.webw_base.text().strip()
        return b.rstrip("/") if b else _relay_base_url(self.ed_relay.text().strip()).rstrip("/")

    def _webworker_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        token = self.ed_token.text().strip()
        if token and self.webw_send_auth.isChecked():
            headers["Authorization"] = f"Bearer {token}"
            headers["X-Blocknet-Key"] = token
            headers["X-Blocknet-Token"] = token
        return headers

    def _webworker_abs_url(self, value: str, default_path: str) -> str:
        v = (value or "").strip()
        if not v:
            v = default_path
        if v.startswith("http://") or v.startswith("https://"):
            return v
        return _join_url(self._webworker_effective_base(), v)

    def _webworker_miner_payload(self) -> Dict[str, Any]:
        return {
            "count": int(self.webw_miner_count.value()),
            "worker_url": self._webworker_abs_url(self.webw_miner_url.text(), self._normalize_prefix() + "/webworker/miner.js"),
            "script_headers": self._webworker_headers(),
            "cfg": {
                "baseUrl": self._webworker_effective_base(),
                "apiPrefix": self._normalize_prefix(),
                "headers": self._webworker_headers(),
                "poll": {"max_msgs": int(self.webw_poll_max_msgs.value())},
                "scan": {
                    "iters": int(self.webw_scan_iters.value()),
                    "max_results": int(self.webw_scan_max_results.value()),
                    "threads": int(self.webw_scan_threads.value()),
                    "poll_first": bool(self.webw_poll_first.isChecked()),
                },
                "sleep_ms": int(self.webw_sleep_ms.value()),
            },
        }

    def _webworker_randomx_payload(self) -> Dict[str, Any]:
        return {
            "count": int(self.webw_rx_count.value()),
            "worker_url": self._webworker_abs_url(self.webw_rx_url.text(), self._normalize_prefix() + "/webworker/randomx_rpc.js"),
            "script_headers": self._webworker_headers(),
            "cfg": {
                "baseUrl": self._webworker_effective_base(),
                "apiPrefix": self._normalize_prefix(),
                "headers": self._webworker_headers(),
                "timeouts": {
                    "hash_ms": int(self.webw_rx_hash_ms.value()),
                    "batch_ms": int(self.webw_rx_batch_ms.value()),
                },
                "local_randomx_wasm_url": self.webw_rx_wasm_url.text().strip(),
            },
        }

    def _webworker_hash_payload(self) -> Dict[str, Any]:
        return {
            "count": int(self.webw_hash_count.value()),
            "worker_url": self._webworker_abs_url(self.webw_hash_url.text(), self._normalize_prefix() + "/webworker/hash_local.js"),
            "script_headers": self._webworker_headers(),
            "cfg": {},
        }

    def _webworker_preset_bundle(self) -> Dict[str, Any]:
        return {
            "miner": self._webworker_miner_payload(),
            "randomx": self._webworker_randomx_payload(),
            "hash": self._webworker_hash_payload(),
        }

    def _webworker_run_js(self, js: str, *, queue_if_unready: bool = True) -> bool:
        if self.webw_view is None:
            return False
        if not self._webw_ready and queue_if_unready:
            self._webw_pending_js.append(js)
            return True
        try:
            self.webw_view.page().runJavaScript(js)  # type: ignore[union-attr]
            return True
        except Exception:
            return False

    def _do_webworker_sync(self) -> None:
        try:
            preset = self._webworker_preset_bundle()
            if self._webworker_run_js("bn_setPreset(" + json.dumps(preset) + ")"):
                self._append_plain(self.webw_out, "Harness preset synced.")
            else:
                self._append_plain(self.webw_out, "Harness preset sync skipped (embedded view unavailable).")
        except Exception as e:
            self._append_plain(self.webw_out, f"sync preset error: {e}")

    def _do_webworker_config(self) -> None:
        try:
            j = self._http_json("GET", "/webworker/config", None, prefix=self._api_prefix())
            self.webw_out.setPlainText("")
            self._append_json(self.webw_out, j)

            if isinstance(j, dict) and j.get("ok"):
                base = self._webworker_effective_base()

                def _abs(v: str) -> str:
                    return v if v.startswith("http://") or v.startswith("https://") else _join_url(base, v)

                miner_js = str(j.get("miner_js") or "").strip()
                rx_js = str(j.get("randomx_rpc_js") or "").strip()
                hash_js = str(j.get("hash_local_js") or "").strip()

                if miner_js:
                    self.webw_miner_url.setText(_abs(miner_js))
                if rx_js:
                    self.webw_rx_url.setText(_abs(rx_js))
                if hash_js:
                    self.webw_hash_url.setText(_abs(hash_js))

                d = j.get("defaults") or {}
                try:
                    self.webw_scan_iters.setValue(int(d.get("scan_iters", self.webw_scan_iters.value())))
                except Exception:
                    pass
                try:
                    self.webw_scan_max_results.setValue(int(d.get("scan_max_results", self.webw_scan_max_results.value())))
                except Exception:
                    pass
                try:
                    self.webw_scan_threads.setValue(int(d.get("scan_threads", self.webw_scan_threads.value())))
                except Exception:
                    pass
                try:
                    self.webw_poll_max_msgs.setValue(int(d.get("poll_max_msgs", self.webw_poll_max_msgs.value())))
                except Exception:
                    pass
                try:
                    self.webw_sleep_ms.setValue(int(d.get("sleep_ms", self.webw_sleep_ms.value())))
                except Exception:
                    pass
                try:
                    if "poll_first" in d:
                        self.webw_poll_first.setChecked(bool(d.get("poll_first")))
                except Exception:
                    pass

            self._do_webworker_sync()
        except Exception as e:
            self._append_plain(self.webw_out, f"webworker/config error: {e}")

    def _do_webworker_start_miner(self) -> None:
        try:
            payload = self._webworker_miner_payload()
            self.webw_out.setPlainText("")
            self._append_plain(self.webw_out, "Starting miner workers...")
            self._append_json(self.webw_out, payload)
            self._do_webworker_sync()

            js = "bn_startMiner(" + json.dumps(payload) + ")"
            if not self._webworker_run_js(js):
                self._do_webworker_open_external(("miner", payload))
        except Exception as e:
            self._append_plain(self.webw_out, f"start miner workers error: {e}")

    def _do_webworker_start_randomx(self) -> None:
        try:
            payload = self._webworker_randomx_payload()
            self.webw_out.setPlainText("")
            self._append_plain(self.webw_out, "Starting RandomX RPC workers...")
            self._append_json(self.webw_out, payload)
            self._do_webworker_sync()

            js = "bn_startRandomX(" + json.dumps(payload) + ")"
            if not self._webworker_run_js(js):
                self._do_webworker_open_external(("randomx", payload))
        except Exception as e:
            self._append_plain(self.webw_out, f"start randomx workers error: {e}")

    def _do_webworker_start_hash(self) -> None:
        try:
            payload = self._webworker_hash_payload()
            self.webw_out.setPlainText("")
            self._append_plain(self.webw_out, "Starting local hash workers...")
            self._append_json(self.webw_out, payload)
            self._do_webworker_sync()

            js = "bn_startHash(" + json.dumps(payload) + ")"
            if not self._webworker_run_js(js):
                self._do_webworker_open_external(("hash", payload))
        except Exception as e:
            self._append_plain(self.webw_out, f"start hash workers error: {e}")

    def _do_webworker_status_all(self) -> None:
        if not self._webworker_run_js("bn_statusAll()"):
            self._append_plain(self.webw_out, "Status requested (use external harness/browser if embedded view is unavailable).")

    def _do_webworker_stop_all(self) -> None:
        if not self._webworker_run_js("bn_stopAll()"):
            self._append_plain(self.webw_out, "Stop requested (external harness/browser workers must be stopped there).")

    def _do_webworker_clear_all(self) -> None:
        if not self._webworker_run_js("bn_clearAll()"):
            self.webw_out.setPlainText("")

    def _do_webworker_open_external(self, autostart: Optional[Tuple[str, Dict[str, Any]]] = None) -> None:
        try:
            html_path = app_data_dir() / "blocknet_webworker_harness.html"
            preset = self._webworker_preset_bundle()

            html = self._webworker_harness_html()
            html += "\n<script>\n"
            html += "bn_setPreset(" + json.dumps(preset) + ");\n"
            if autostart is not None:
                kind, payload = autostart
                if kind == "miner":
                    html += "setTimeout(()=>{ try { bn_startMiner(" + json.dumps(payload) + "); } catch(e) { console.error(e); } }, 200);\n"
                elif kind == "randomx":
                    html += "setTimeout(()=>{ try { bn_startRandomX(" + json.dumps(payload) + "); } catch(e) { console.error(e); } }, 200);\n"
                elif kind == "hash":
                    html += "setTimeout(()=>{ try { bn_startHash(" + json.dumps(payload) + "); } catch(e) { console.error(e); } }, 200);\n"
            html += "</script>\n"

            html_path.write_text(html, encoding="utf-8")
            webbrowser.open(str(html_path.as_uri()))
            self._append_plain(self.webw_out, f"Opened external harness: {html_path}")
        except Exception as e:
            self._append_plain(self.webw_out, f"open external harness error: {e}")

    # ---------------- Persistence ----------------

    def _wire_autosave(self) -> None:
        edits = [
            self.ed_host, self.ed_port, self.ed_relay, self.ed_token, self.ed_spool,
            self.ed_threads_flag, self.ed_server_extra,

            self.ed_proxy_listen, self.ed_proxy_backend, self.ed_proxy_cert, self.ed_proxy_key,
            self.ed_proxy_inject, self.ed_proxy_allow,

            self.ed_gateway_listen, self.ed_gateway_backend, self.ed_gateway_cert, self.ed_gateway_key,
            self.ed_gateway_allow, self.ed_gateway_extra,

            self.ed_key, self.ed_mime, self.ed_put, self.ed_get,

            self.ed_api_prefix, self.ed_randomx_dll, self.ed_web_ua, self.ed_p2pool_extra,
            self.ed_network_wintun_dll, self.ed_network_iface, self.ed_network_ipv4,

            self.ed_audio_spool_dir, self.ed_audio_searxng_url, self.ed_audio_proxy,

            self.ed_python_spool_dir, self.ed_python_exe, self.ed_python_bridge_host,
            self.ed_python_blocknet_url, self.ed_python_blocknet_prefix, self.ed_python_headers_json,

            self.webw_base, self.webw_miner_url, self.webw_rx_url, self.webw_hash_url, self.webw_rx_wasm_url,
        ]
        for e in edits:
            e.textChanged.connect(self._schedule_save)

        self.ed_host.textChanged.connect(self._sync_relay_from_host_port)
        self.ed_port.textChanged.connect(self._sync_relay_from_host_port)

        for sp in (
            self.sp_threads,
            self.sp_web_timeout, self.sp_web_max_page_kb, self.sp_web_max_scripts,
            self.sp_audio_timeout, self.sp_audio_max_fetch_kb, self.sp_audio_scan_max_results,
            self.sp_audio_scan_expand_pages, self.sp_audio_scan_max_links,
            self.sp_python_bridge_port,
            self.p2_open_threads,
            self.webw_miner_count, self.webw_scan_iters, self.webw_scan_max_results,
            self.webw_scan_threads, self.webw_poll_max_msgs, self.webw_sleep_ms,
            self.webw_rx_count, self.webw_rx_hash_ms, self.webw_rx_batch_ms,
            self.webw_hash_count,
        ):
            sp.valueChanged.connect(self._schedule_save)

        for cb in (
            self.cb_proxy, self.cb_gateway,
            self.cb_api, self.cb_api_media, self.cb_api_randomx, self.cb_api_web,
            self.cb_api_p2pool, self.cb_api_webworker, self.cb_api_process,
            self.cb_api_network, self.cb_network_set_ipv4, self.cb_api_audio, self.cb_api_python,
            self.cb_web_block_private, self.cb_web_allow_http, self.cb_web_allow_https,
            self.cb_audio_persist, self.cb_audio_use_proxy, self.cb_audio_block_private,
            self.cb_python_serve, self.cb_python_control, self.cb_python_control_local,
            self.webw_send_auth, self.webw_poll_first,
        ):
            cb.stateChanged.connect(self._schedule_save)

        for cmb in (self.cmb_proxy_log, self.cmb_gateway_log):
            cmb.currentTextChanged.connect(self._schedule_save)

        self.p2_open_host.textChanged.connect(self._schedule_save)
        self.p2_open_wallet.textChanged.connect(self._schedule_save)
        self.p2_open_rig.textChanged.connect(self._schedule_save)
        self.p2_open_extra_json.textChanged.connect(self._schedule_save)

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
            self.sp_threads.setValue(int(j.get("threads", self.sp_threads.value())))
            self.ed_threads_flag.setText(j.get("threads_flag", self.ed_threads_flag.text()))

            self.cb_proxy.setChecked(bool(j.get("proxy_enabled", False)))
            self.ed_proxy_listen.setText(j.get("proxy_listen", self.ed_proxy_listen.text()))
            self.ed_proxy_backend.setText(j.get("proxy_backend", self.ed_proxy_backend.text()))
            self.ed_proxy_cert.setText(j.get("proxy_cert", self.ed_proxy_cert.text()))
            self.ed_proxy_key.setText(j.get("proxy_key", self.ed_proxy_key.text()))
            self.ed_proxy_inject.setText(j.get("proxy_inject", self.ed_proxy_inject.text()))
            self.ed_proxy_allow.setText(j.get("proxy_allow", self.ed_proxy_allow.text()))
            self.cmb_proxy_log.setCurrentText(j.get("proxy_log", self.cmb_proxy_log.currentText()))

            self.cb_gateway.setChecked(bool(j.get("gateway_enabled", False)))
            self.ed_gateway_listen.setText(j.get("gateway_listen", self.ed_gateway_listen.text()))
            self.ed_gateway_backend.setText(j.get("gateway_backend", self.ed_gateway_backend.text()))
            self.ed_gateway_cert.setText(j.get("gateway_cert", self.ed_gateway_cert.text()))
            self.ed_gateway_key.setText(j.get("gateway_key", self.ed_gateway_key.text()))
            self.ed_gateway_allow.setText(j.get("gateway_allow", self.ed_gateway_allow.text()))
            self.ed_gateway_extra.setText(j.get("gateway_extra", self.ed_gateway_extra.text()))
            self.cmb_gateway_log.setCurrentText(j.get("gateway_log", self.cmb_gateway_log.currentText()))

            self.cb_api.setChecked(bool(j.get("api_enabled", True)))
            self.ed_api_prefix.setText(j.get("api_prefix", self.ed_api_prefix.text()))
            self.cb_api_media.setChecked(bool(j.get("api_media", True)))
            self.cb_api_randomx.setChecked(bool(j.get("api_randomx", True)))
            self.cb_api_web.setChecked(bool(j.get("api_web", True)))
            self.cb_api_p2pool.setChecked(bool(j.get("api_p2pool", False)))
            self.cb_api_webworker.setChecked(bool(j.get("api_webworker", False)))
            self.cb_api_process.setChecked(bool(j.get("api_process", False)))
            self.cb_api_network.setChecked(bool(j.get("api_network", True)))
            self.cb_api_audio.setChecked(bool(j.get("api_audio", False)))
            self.cb_api_python.setChecked(bool(j.get("api_python", False)))

            self.ed_randomx_dll.setText(j.get("randomx_dll", self.ed_randomx_dll.text()))
            self.ed_p2pool_extra.setText(j.get("p2pool_extra", self.ed_p2pool_extra.text()))
            self.ed_network_wintun_dll.setText(j.get("network_wintun_dll", self.ed_network_wintun_dll.text()))
            self.ed_network_iface.setText(j.get("network_iface", self.ed_network_iface.text()))
            self.cb_network_set_ipv4.setChecked(bool(j.get("network_set_ipv4", False)))
            self.ed_network_ipv4.setText(j.get("network_ipv4", self.ed_network_ipv4.text()))

            self.cb_web_block_private.setChecked(bool(j.get("web_block_private", True)))
            self.cb_web_allow_http.setChecked(bool(j.get("web_allow_http", True)))
            self.cb_web_allow_https.setChecked(bool(j.get("web_allow_https", True)))
            self.sp_web_timeout.setValue(int(j.get("web_timeout", self.sp_web_timeout.value())))
            self.sp_web_max_page_kb.setValue(int(j.get("web_max_page_kb", self.sp_web_max_page_kb.value())))
            self.sp_web_max_scripts.setValue(int(j.get("web_max_scripts", self.sp_web_max_scripts.value())))
            self.ed_web_ua.setText(j.get("web_ua", self.ed_web_ua.text()))

            self.ed_audio_spool_dir.setText(j.get("audio_spool_dir", self.ed_audio_spool_dir.text()))
            self.cb_audio_persist.setChecked(bool(j.get("audio_persist", True)))
            self.ed_audio_searxng_url.setText(j.get("audio_searxng_url", self.ed_audio_searxng_url.text()))
            self.ed_audio_proxy.setText(j.get("audio_proxy", self.ed_audio_proxy.text()))
            self.cb_audio_use_proxy.setChecked(bool(j.get("audio_use_proxy", True)))
            self.sp_audio_timeout.setValue(int(j.get("audio_timeout_ms", self.sp_audio_timeout.value())))
            self.sp_audio_max_fetch_kb.setValue(int(j.get("audio_max_fetch_kb", self.sp_audio_max_fetch_kb.value())))
            self.sp_audio_scan_max_results.setValue(int(j.get("audio_scan_max_results", self.sp_audio_scan_max_results.value())))
            self.sp_audio_scan_expand_pages.setValue(int(j.get("audio_scan_expand_pages", self.sp_audio_scan_expand_pages.value())))
            self.sp_audio_scan_max_links.setValue(int(j.get("audio_scan_max_links", self.sp_audio_scan_max_links.value())))
            self.cb_audio_block_private.setChecked(bool(j.get("audio_block_private", True)))

            self.cb_python_serve.setChecked(bool(j.get("python_serve", self.cb_python_serve.isChecked())))
            self.cb_python_control.setChecked(bool(j.get("python_control", self.cb_python_control.isChecked())))
            self.cb_python_control_local.setChecked(bool(j.get("python_control_local", self.cb_python_control_local.isChecked())))
            self.ed_python_spool_dir.setText(j.get("python_spool_dir", self.ed_python_spool_dir.text()))
            self.ed_python_exe.setText(j.get("python_exe", self.ed_python_exe.text()))
            self.ed_python_bridge_host.setText(j.get("python_bridge_host", self.ed_python_bridge_host.text()))
            self.sp_python_bridge_port.setValue(int(j.get("python_bridge_port", self.sp_python_bridge_port.value())))
            self.ed_python_blocknet_url.setText(j.get("python_blocknet_url", self.ed_python_blocknet_url.text()))
            self.ed_python_blocknet_prefix.setText(j.get("python_blocknet_prefix", self.ed_python_blocknet_prefix.text()))
            self.ed_python_headers_json.setText(j.get("python_headers_json", self.ed_python_headers_json.text()))

            self.p2_open_host.setText(j.get("p2_open_host", self.p2_open_host.text()))
            self.p2_open_wallet.setText(j.get("p2_open_wallet", self.p2_open_wallet.text()))
            self.p2_open_rig.setText(j.get("p2_open_rig", self.p2_open_rig.text()))
            self.p2_open_threads.setValue(int(j.get("p2_open_threads", self.p2_open_threads.value())))
            self.p2_open_extra_json.setPlainText(j.get("p2_open_extra_json", self.p2_open_extra_json.toPlainText()))

            self.webw_base.setText(j.get("webw_base", self.webw_base.text()))
            self.webw_send_auth.setChecked(bool(j.get("webw_send_auth", self.webw_send_auth.isChecked())))

            self.webw_miner_url.setText(j.get("webw_miner_url", self.webw_miner_url.text()))
            self.webw_miner_count.setValue(int(j.get("webw_miner_count", self.webw_miner_count.value())))
            self.webw_scan_iters.setValue(int(j.get("webw_scan_iters", self.webw_scan_iters.value())))
            self.webw_scan_max_results.setValue(int(j.get("webw_scan_max_results", self.webw_scan_max_results.value())))
            self.webw_scan_threads.setValue(int(j.get("webw_scan_threads", self.webw_scan_threads.value())))
            self.webw_poll_max_msgs.setValue(int(j.get("webw_poll_max_msgs", self.webw_poll_max_msgs.value())))
            self.webw_sleep_ms.setValue(int(j.get("webw_sleep_ms", self.webw_sleep_ms.value())))
            self.webw_poll_first.setChecked(bool(j.get("webw_poll_first", self.webw_poll_first.isChecked())))

            self.webw_rx_url.setText(j.get("webw_rx_url", self.webw_rx_url.text()))
            self.webw_rx_count.setValue(int(j.get("webw_rx_count", self.webw_rx_count.value())))
            self.webw_rx_hash_ms.setValue(int(j.get("webw_rx_hash_ms", self.webw_rx_hash_ms.value())))
            self.webw_rx_batch_ms.setValue(int(j.get("webw_rx_batch_ms", self.webw_rx_batch_ms.value())))
            self.webw_rx_wasm_url.setText(j.get("webw_rx_wasm_url", self.webw_rx_wasm_url.text()))

            self.webw_hash_url.setText(j.get("webw_hash_url", self.webw_hash_url.text()))
            self.webw_hash_count.setValue(int(j.get("webw_hash_count", self.webw_hash_count.value())))

            try:
                s = j.get("main_split_state", "")
                if s:
                    self.main_split.restoreState(_b64d(s))
                else:
                    self.main_split.setSizes([480, 980])
            except Exception:
                self.main_split.setSizes([480, 980])

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
                "api_webworker": bool(self.cb_api_webworker.isChecked()),
                "api_process": bool(self.cb_api_process.isChecked()),
                "api_network": bool(self.cb_api_network.isChecked()),
                "api_audio": bool(self.cb_api_audio.isChecked()),
                "api_python": bool(self.cb_api_python.isChecked()),

                "randomx_dll": self.ed_randomx_dll.text().strip(),
                "p2pool_extra": self.ed_p2pool_extra.text().strip(),

                "web_block_private": bool(self.cb_web_block_private.isChecked()),
                "web_allow_http": bool(self.cb_web_allow_http.isChecked()),
                "web_allow_https": bool(self.cb_web_allow_https.isChecked()),
                "web_timeout": int(self.sp_web_timeout.value()),
                "web_max_page_kb": int(self.sp_web_max_page_kb.value()),
                "web_max_scripts": int(self.sp_web_max_scripts.value()),
                "web_ua": self.ed_web_ua.text().strip(),

                "network_wintun_dll": self.ed_network_wintun_dll.text().strip(),
                "network_iface": self.ed_network_iface.text().strip(),
                "network_set_ipv4": bool(self.cb_network_set_ipv4.isChecked()),
                "network_ipv4": self.ed_network_ipv4.text().strip(),

                "audio_spool_dir": self.ed_audio_spool_dir.text().strip(),
                "audio_persist": bool(self.cb_audio_persist.isChecked()),
                "audio_searxng_url": self.ed_audio_searxng_url.text().strip(),
                "audio_proxy": self.ed_audio_proxy.text().strip(),
                "audio_use_proxy": bool(self.cb_audio_use_proxy.isChecked()),
                "audio_timeout_ms": int(self.sp_audio_timeout.value()),
                "audio_max_fetch_kb": int(self.sp_audio_max_fetch_kb.value()),
                "audio_scan_max_results": int(self.sp_audio_scan_max_results.value()),
                "audio_scan_expand_pages": int(self.sp_audio_scan_expand_pages.value()),
                "audio_scan_max_links": int(self.sp_audio_scan_max_links.value()),
                "audio_block_private": bool(self.cb_audio_block_private.isChecked()),

                "python_serve": bool(self.cb_python_serve.isChecked()),
                "python_control": bool(self.cb_python_control.isChecked()),
                "python_control_local": bool(self.cb_python_control_local.isChecked()),
                "python_spool_dir": self.ed_python_spool_dir.text().strip(),
                "python_exe": self.ed_python_exe.text().strip(),
                "python_bridge_host": self.ed_python_bridge_host.text().strip(),
                "python_bridge_port": int(self.sp_python_bridge_port.value()),
                "python_blocknet_url": self.ed_python_blocknet_url.text().strip(),
                "python_blocknet_prefix": self.ed_python_blocknet_prefix.text().strip(),
                "python_headers_json": self.ed_python_headers_json.text().strip(),

                "p2_open_host": self.p2_open_host.text().strip(),
                "p2_open_wallet": self.p2_open_wallet.text().strip(),
                "p2_open_rig": self.p2_open_rig.text().strip(),
                "p2_open_threads": int(self.p2_open_threads.value()),
                "p2_open_extra_json": self.p2_open_extra_json.toPlainText(),

                "webw_base": self.webw_base.text().strip(),
                "webw_send_auth": bool(self.webw_send_auth.isChecked()),

                "webw_miner_url": self.webw_miner_url.text().strip(),
                "webw_miner_count": int(self.webw_miner_count.value()),
                "webw_scan_iters": int(self.webw_scan_iters.value()),
                "webw_scan_max_results": int(self.webw_scan_max_results.value()),
                "webw_scan_threads": int(self.webw_scan_threads.value()),
                "webw_poll_max_msgs": int(self.webw_poll_max_msgs.value()),
                "webw_sleep_ms": int(self.webw_sleep_ms.value()),
                "webw_poll_first": bool(self.webw_poll_first.isChecked()),

                "webw_rx_url": self.webw_rx_url.text().strip(),
                "webw_rx_count": int(self.webw_rx_count.value()),
                "webw_rx_hash_ms": int(self.webw_rx_hash_ms.value()),
                "webw_rx_batch_ms": int(self.webw_rx_batch_ms.value()),
                "webw_rx_wasm_url": self.webw_rx_wasm_url.text().strip(),

                "webw_hash_url": self.webw_hash_url.text().strip(),
                "webw_hash_count": int(self.webw_hash_count.value()),

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
    w.resize(1420, 900)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())