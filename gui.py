# gui.py
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional, Tuple

from PyQt5.QtCore import QProcess, QTimer, Qt, QStandardPaths
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QFormLayout, QGroupBox,
    QMessageBox, QSplitter, QTabWidget,
    QCheckBox, QComboBox, QFileDialog, QSizePolicy
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

        /* Make splitter handles obvious & draggable */
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

        # LEFT: vertical splitter so the sections on the left are resizable by dragging
        self.left_split = QSplitter(Qt.Vertical)
        self.left_split.setChildrenCollapsible(False)
        self.left_split.setHandleWidth(10)
        self.left_split.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.left_split.setMinimumWidth(380)

        self.main_split.addWidget(self.left_split)

        # ---------------- Left panel sections ----------------

        # Connection / Server
        gb_conn = QGroupBox("Connection / Server")
        gb_conn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        gb_conn.setMinimumHeight(110)
        fl = QFormLayout(gb_conn)

        self.ed_host = QLineEdit("127.0.0.1")
        self.ed_port = QLineEdit("38887")
        self.ed_relay = QLineEdit("127.0.0.1:38887")
        self.ed_token = QLineEdit("")
        self.ed_token.setEchoMode(QLineEdit.Password)
        self.ed_spool = QLineEdit(_default_spool_dir())

        fl.addRow("Listen host", self.ed_host)
        fl.addRow("Listen port", self.ed_port)
        fl.addRow("Relay (host:port)", self.ed_relay)
        fl.addRow("Token", self.ed_token)
        fl.addRow("Spool dir", self.ed_spool)

        btn_row = QHBoxLayout()
        self.btn_gen = QPushButton("Generate Token")
        self.btn_start = QPushButton("Start")
        self.btn_stop = QPushButton("Stop")
        self._set_running(False)
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
        self.btn_clear_out.clicked.connect(lambda: self.txt_out.setPlainText(""))
        self.btn_clear_log.clicked.connect(lambda: self.txt_log.setPlainText(""))

        self.left_split.addWidget(gb_conn)

        # TLS Proxy
        gb_proxy = QGroupBox("TLS Proxy (optional)")
        gb_proxy.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        gb_proxy.setMinimumHeight(110)
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

        self.left_split.addWidget(gb_proxy)

        # Gateway
        gb_gateway = QGroupBox("Edge Gateway (optional)")
        gb_gateway.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        gb_gateway.setMinimumHeight(110)
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

        self.left_split.addWidget(gb_gateway)

        # Quick Put/Get
        gb_io = QGroupBox("Quick Put / Get")
        gb_io.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        gb_io.setMinimumHeight(110)
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

        self.left_split.addWidget(gb_io)

        # ---------------- Right panel: tabs ----------------
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)

        tabs = QTabWidget()

        out_tab = QWidget()
        out_l = QVBoxLayout(out_tab)
        self.txt_out = QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(self.mono)
        out_l.addWidget(self.txt_out)
        tabs.addTab(out_tab, "Output")

        log_tab = QWidget()
        log_l = QVBoxLayout(log_tab)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(self.mono)
        log_l.addWidget(self.txt_log)
        tabs.addTab(log_tab, "Server Console")

        proxy_tab = QWidget()
        proxy_l = QVBoxLayout(proxy_tab)
        self.txt_proxy = QPlainTextEdit()
        self.txt_proxy.setReadOnly(True)
        self.txt_proxy.setFont(self.mono)
        proxy_l.addWidget(self.txt_proxy)
        tabs.addTab(proxy_tab, "Proxy")

        gateway_tab = QWidget()
        gateway_l = QVBoxLayout(gateway_tab)
        self.txt_gateway = QPlainTextEdit()
        self.txt_gateway.setReadOnly(True)
        self.txt_gateway.setFont(self.mono)
        gateway_l.addWidget(self.txt_gateway)
        tabs.addTab(gateway_tab, "Gateway")

        right_l.addWidget(tabs)
        self.main_split.addWidget(right)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        self.statusBar().showMessage("Ready")

        # load config (includes splitter positions)
        self._load_cfg()
        self._sync_relay_from_host_port()
        self._wire_autosave()

        self.left_split.splitterMoved.connect(lambda *_: self._schedule_save())
        self.main_split.splitterMoved.connect(lambda *_: self._schedule_save())

    # -------- helpers --------

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
        s = s.replace("\r\n", "\n").replace("\r", "\n")
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

    def _sync_relay_from_host_port(self) -> None:
        host = self.ed_host.text().strip() or "127.0.0.1"
        port = self.ed_port.text().strip() or "38887"
        self.ed_relay.setText(f"{host}:{port}")

    def _wire_autosave(self) -> None:
        edits = [
            self.ed_host, self.ed_port, self.ed_relay, self.ed_token, self.ed_spool,
            self.ed_proxy_listen, self.ed_proxy_backend, self.ed_proxy_cert, self.ed_proxy_key,
            self.ed_proxy_inject, self.ed_proxy_allow,
            self.ed_gateway_listen, self.ed_gateway_backend, self.ed_gateway_cert, self.ed_gateway_key,
            self.ed_gateway_allow, self.ed_gateway_extra,
            self.ed_key, self.ed_mime, self.ed_put, self.ed_get,
        ]
        for e in edits:
            e.textChanged.connect(self._schedule_save)

        self.ed_host.textChanged.connect(self._sync_relay_from_host_port)
        self.ed_port.textChanged.connect(self._sync_relay_from_host_port)

        self.cb_proxy.stateChanged.connect(self._schedule_save)
        self.cb_gateway.stateChanged.connect(self._schedule_save)
        self.cmb_proxy_log.currentTextChanged.connect(self._schedule_save)
        self.cmb_gateway_log.currentTextChanged.connect(self._schedule_save)

    def _browse_file_into(self, edit: QLineEdit) -> None:
        start_dir = str(Path.home())
        cur = edit.text().strip()
        if cur:
            try:
                p = Path(cur)
                if p.exists():
                    start_dir = str(p.parent)
            except Exception:
                pass

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file",
            start_dir,
            "PEM/Cert files (*.pem *.crt *.key);;All files (*.*)"
        )
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

    # -------- stdout/stderr routing (cout goes here) --------

    def _classify_line(self, line: str) -> Tuple[bool, bool, Optional[str], str]:
        """
        Returns (is_proxy, is_gateway, ctx, cleaned_line)

        ctx is only set when the line strongly indicates a component.
        cleaned_line strips leading tags like "[proxy]" so the tab looks clean.
        """
        raw = line
        low = raw.strip().lower()
        lstripped = raw.lstrip()
        low_ls = lstripped.lower()

        # Strong tag-at-start routing (best)
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

        # Secondary keyword routing (works when your C++ logs don't prefix)
        is_proxy = ("[proxy]" in low) or ("tls proxy" in low) or ("tlsproxy" in low) or ("proxy:" in low)
        is_gateway = ("[gateway]" in low) or ("edge gateway" in low) or ("edge-gateway" in low) or ("gateway:" in low)

        ctx: Optional[str] = None
        if is_proxy and not is_gateway:
            ctx = "proxy"
        elif is_gateway and not is_proxy:
            ctx = "gateway"

        return is_proxy, is_gateway, ctx, raw.strip("\r\n")

    def _route_process_text(self, text: str, *, is_stderr: bool) -> None:
        """
        Always:
          - Server Console: all stdout/stderr
          - Output: mirrors stdout/stderr

        Additionally:
          - Proxy tab: proxy-related lines
          - Gateway tab: gateway-related lines

        This captures std::cout/std::cerr from blocknet.exe via QProcess and
        routes it into the correct tab based on tags/keywords.
        """
        if not text:
            return

        # Always mirror into the two main logs first
        if is_stderr:
            self._append_plain(self.txt_log, text, prefix="[stderr] ")
            self._append_plain(self.txt_out, text, prefix="[stderr] ")
        else:
            self._append_plain(self.txt_log, text)
            self._append_plain(self.txt_out, text, prefix="[server] ")

        # Now route line-by-line into Proxy/Gateway tabs
        t = text.replace("\r\n", "\n").replace("\r", "\n")
        for raw_line in t.split("\n"):
            if not raw_line.strip():
                # blank line: don't change context
                continue

            is_proxy, is_gateway, ctx, cleaned = self._classify_line(raw_line)

            # If line is indented and we had a previous context, inherit it
            if (raw_line.startswith(" ") or raw_line.startswith("\t")) and not (is_proxy or is_gateway) and self._last_ctx:
                ctx = self._last_ctx
                is_proxy = (ctx == "proxy")
                is_gateway = (ctx == "gateway")

            if ctx:
                self._last_ctx = ctx

            # Route to the correct tab(s)
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
                "Missing blocknet.exe",
                f"Not found: {BIN_EXE}\n\nPlace blocknet.exe next to gui.py (or bundle it with PyInstaller)."
            )
            return

        if self.proc.state() != QProcess.NotRunning:
            QMessageBox.information(self, "Already running", "Server is already running.")
            return

        relay = self.ed_relay.text().strip()
        spool = self.ed_spool.text().strip()
        token = self.ed_token.text().strip()

        args = ["serve", "--listen", relay, "--spool", spool]
        if token:
            args += ["--token", token]

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

        # Reset context routing when starting fresh
        self._last_ctx = None

        cmdline = f"{BIN_EXE} " + " ".join(args)
        for w in (self.txt_log, self.txt_out, self.txt_proxy, self.txt_gateway):
            self._append_plain(w, f"[gui] starting: {cmdline}")

        self.proc.setProgram(str(BIN_EXE))
        self.proc.setArguments(args)
        self.proc.setWorkingDirectory(str(app_data_dir()))
        self.proc.start()

        if not self.proc.waitForStarted(2000):
            QMessageBox.critical(self, "Failed to start", "blocknet.exe did not start. See console for details.")
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
            self._append_plain(self.txt_out, json.dumps(j, indent=2))
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
            self._append_plain(self.txt_out, json.dumps(j, indent=2))
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

    # -------- config persistence --------

    def closeEvent(self, ev) -> None:
        self._save_cfg()
        self._stop_server()
        super().closeEvent(ev)

    def _load_cfg(self) -> None:
        if not CFG_PATH.exists():
            self.left_split.setSizes([260, 240, 240, 220])
            self.main_split.setSizes([480, 900])
            return

        try:
            j = json.loads(CFG_PATH.read_text(encoding="utf-8"))

            self.ed_relay.setText(j.get("relay", self.ed_relay.text()))
            self.ed_token.setText(j.get("token", self.ed_token.text()))
            self.ed_spool.setText(j.get("spool", self.ed_spool.text()))
            self.ed_host.setText(j.get("host", self.ed_host.text()))
            self.ed_port.setText(j.get("port", self.ed_port.text()))

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

            try:
                s = j.get("left_split_state", "")
                if s:
                    self.left_split.restoreState(_b64d(s))
                else:
                    self.left_split.setSizes([260, 240, 240, 220])
            except Exception:
                self.left_split.setSizes([260, 240, 240, 220])

            try:
                s = j.get("main_split_state", "")
                if s:
                    self.main_split.restoreState(_b64d(s))
                else:
                    self.main_split.setSizes([480, 900])
            except Exception:
                self.main_split.setSizes([480, 900])

        except Exception:
            self.left_split.setSizes([260, 240, 240, 220])
            self.main_split.setSizes([480, 900])

    def _save_cfg(self) -> None:
        try:
            j = {
                "relay": self.ed_relay.text().strip(),
                "token": self.ed_token.text().strip(),
                "spool": self.ed_spool.text().strip(),
                "host": self.ed_host.text().strip(),
                "port": self.ed_port.text().strip(),

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

                "left_split_state": _b64e(bytes(self.left_split.saveState())),
                "main_split_state": _b64e(bytes(self.main_split.saveState())),
            }
            CFG_PATH.write_text(json.dumps(j, indent=2), encoding="utf-8")
        except Exception:
            pass


def main() -> int:
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    w = MainWindow()
    w.resize(1250, 820)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())