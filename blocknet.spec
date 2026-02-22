# blocknet_onefile.spec
# Build: pyinstaller --noconfirm --clean blocknet_onefile.spec

# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

PROJECT_DIR = Path(os.getcwd()).resolve()

datas = []
binaries = []

def add_data(src: Path, dest: str = ".") -> None:
    if src.exists():
        datas.append((str(src), dest))
    else:
        print(f"[spec] WARNING: data not found: {src}")

def add_bin(src: Path, dest: str = ".") -> None:
    if src.exists():
        binaries.append((str(src), dest))
    else:
        print(f"[spec] WARNING: binary not found: {src}")

# ---- bundle your native server exe (extracted to sys._MEIPASS in onefile) ----
add_data(PROJECT_DIR / "blocknet.exe", ".")


# ---- bundle OpenSSL DLLs (so blocknet.exe can find them next to itself) ----
# If blocknet.exe depends on these at runtime, bundling them as *binaries* is correct.
add_bin(PROJECT_DIR / "libcrypto-3-x64.dll", ".")
add_bin(PROJECT_DIR / "libssl-3-x64.dll", ".")

hiddenimports = []
hiddenimports += collect_submodules("PyQt5")
datas += collect_data_files("PyQt5", include_py_files=False)

a = Analysis(
    ["gui.py"],
    pathex=[str(PROJECT_DIR)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="BlockNetGUI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)