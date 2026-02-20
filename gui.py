# gui.py
from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

from PyQt5.QtCore import QProcess, QTimer, Qt, QStandardPaths
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit, QFormLayout, QGroupBox,
    QMessageBox, QSplitter, QTabWidget, QFrame, QSizePolicy
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

    # PyInstaller extraction dir
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / rel)
        candidates.append(Path(meipass) / Path(rel).name)

    # Folder of the running executable (frozen) OR current working dir
    exe_dir = Path(sys.executable).resolve().parent
    candidates.append(exe_dir / rel)
    candidates.append(exe_dir / Path(rel).name)

    # Folder of this script (dev)
    script_dir = Path(__file__).resolve().parent
    candidates.append(script_dir / rel)
    candidates.append(script_dir / Path(rel).name)

    for c in candidates:
        if c.exists():
            return c

    # fallback to script dir (even if missing, for error message)
    return script_dir / rel


APP_DIR = Path(sys.executable).resolve().parent
CFG_PATH = app_data_dir() / "blocknet_gui_config.json"
BIN_EXE = resource_path("blocknet.exe")  # expects blocknet.exe alongside or bundled


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

    # tasteful, readable styling
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
        QPushButton:hover {
            background: #333333;
        }
        QPushButton:pressed {
            background: #1f1f1f;
        }
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
        QTabBar::tab:selected {
            background: #1f1f1f;
        }
        QLabel#StatusPill {
            border-radius: 10px;
            padding: 4px 10px;
            font-weight: 600;
        }
    """)


# ----------------------------- GUI -----------------------------------------------

def _default_spool_dir() -> str:
    tmp = os.environ.get("TEMP") or os.environ.get("TMP") or str(app_data_dir())
    return str(Path(tmp) / "blocknet_spool")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BlockNet Control Panel")

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

        # fonts
        self.mono = QFont("Consolas")
        self.mono.setStyleHint(QFont.Monospace)
        self.mono.setPointSize(10)

        # root layout
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

        # splitter (left controls, right console)
        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        root.addWidget(split, 1)

        # ---------------- Left panel ----------------
        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(0, 0, 0, 0)
        left_l.setSpacing(10)

        # Connection / Server box
        gb_conn = QGroupBox("Connection / Server")
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

        left_l.addWidget(gb_conn)

        # Quick Put/Get box
        gb_io = QGroupBox("Quick Put / Get")
        io = QFormLayout(gb_io)

        self.ed_key = QLineEdit("greeting")
        self.ed_mime = QLineEdit("text/plain")
        self.ed_put = QLineEdit("hello world")
        self.ed_get = QLineEdit("greeting")  # key or obj_ ref

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

        left_l.addWidget(gb_io)
        left_l.addStretch(1)

        split.addWidget(left)

        # ---------------- Right panel: tabs ----------------
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)

        tabs = QTabWidget()

        # Output tab (API results + also mirrored server stdout/stderr)
        out_tab = QWidget()
        out_l = QVBoxLayout(out_tab)
        self.txt_out = QPlainTextEdit()
        self.txt_out.setReadOnly(True)
        self.txt_out.setFont(self.mono)
        out_l.addWidget(self.txt_out)
        tabs.addTab(out_tab, "Output")

        # Server Console tab (raw process output)
        log_tab = QWidget()
        log_l = QVBoxLayout(log_tab)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(self.mono)
        log_l.addWidget(self.txt_log)
        tabs.addTab(log_tab, "Server Console")

        right_l.addWidget(tabs)

        split.addWidget(right)
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([360, 820])

        # status bar
        self.statusBar().showMessage("Ready")

        # load saved config
        self._load_cfg()
        self._sync_relay_from_host_port()

    # -------- helpers --------

    def _set_running(self, running: bool) -> None:
        if running:
            self.status_pill.setText("RUNNING")
            self.status_pill.setStyleSheet("background:#1f4d2e; color:#eaffea;")
        else:
            self.status_pill.setText("STOPPED")
            self.status_pill.setStyleSheet("background:#4a1f1f; color:#ffecec;")

        # guard: buttons may not exist yet during early init
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

        # keep it from growing forever
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

    # -------- process output --------

    def _read_stdout(self) -> None:
        data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        if not data.strip():
            return
        # show in BOTH places (you asked for cout in Output too)
        self._append_plain(self.txt_log, data)
        self._append_plain(self.txt_out, data, prefix="[server] ")

    def _read_stderr(self) -> None:
        data = bytes(self.proc.readAllStandardError()).decode("utf-8", errors="replace")
        if not data.strip():
            return
        self._append_plain(self.txt_log, data, prefix="[stderr] ")
        self._append_plain(self.txt_out, data, prefix="[stderr] ")

    def _on_proc_error(self, err) -> None:
        # QProcess errors are enums; show something readable
        self._append_plain(self.txt_log, f"[gui] process error: {err}")
        self._append_plain(self.txt_out, f"[gui] process error: {err}")
        self._set_running(False)
        self.timer.stop()

    def _on_finished(self) -> None:
        self.timer.stop()
        self._append_plain(self.txt_log, "[gui] server process exited")
        self._append_plain(self.txt_out, "[gui] server process exited")
        self._set_running(False)

    # -------- actions --------

    def _gen_token(self) -> None:
        tok = "dev-" + secrets.token_hex(16)
        self.ed_token.setText(tok)
        self._save_cfg()

    def _start_server(self) -> None:
        self._sync_relay_from_host_port()

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

        self._append_plain(self.txt_log, f"[gui] starting: {BIN_EXE} " + " ".join(args))
        self._append_plain(self.txt_out, f"[gui] starting: {BIN_EXE} " + " ".join(args))

        self.proc.setProgram(str(BIN_EXE))
        self.proc.setArguments(args)

        # Workdir: use writable dir (good for frozen apps)
        wd = str(app_data_dir())
        self.proc.setWorkingDirectory(wd)

        self.proc.start()

        if not self.proc.waitForStarted(2000):
            QMessageBox.critical(self, "Failed to start", "blocknet.exe did not start. See console for details.")
            self._set_running(False)
            return

        self._set_running(True)
        self.timer.start()
        self._save_cfg()

    def _stop_server(self) -> None:
        if self.proc.state() == QProcess.NotRunning:
            return
        self._append_plain(self.txt_log, "[gui] stopping server...")
        self._append_plain(self.txt_out, "[gui] stopping server...")
        self.proc.terminate()
        if not self.proc.waitForFinished(2000):
            self._append_plain(self.txt_log, "[gui] force kill")
            self._append_plain(self.txt_out, "[gui] force kill")
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
            return
        try:
            j = json.loads(CFG_PATH.read_text(encoding="utf-8"))
            self.ed_relay.setText(j.get("relay", self.ed_relay.text()))
            self.ed_token.setText(j.get("token", self.ed_token.text()))
            self.ed_spool.setText(j.get("spool", self.ed_spool.text()))
            self.ed_host.setText(j.get("host", self.ed_host.text()))
            self.ed_port.setText(j.get("port", self.ed_port.text()))
        except Exception:
            pass

    def _save_cfg(self) -> None:
        try:
            j = {
                "relay": self.ed_relay.text().strip(),
                "token": self.ed_token.text().strip(),
                "spool": self.ed_spool.text().strip(),
                "host": self.ed_host.text().strip(),
                "port": self.ed_port.text().strip(),
            }
            CFG_PATH.write_text(json.dumps(j, indent=2), encoding="utf-8")
        except Exception:
            pass


def main() -> int:
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    w = MainWindow()
    w.resize(1200, 780)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())