# blocknet_onefile.spec
# Build: pyinstaller --noconfirm --clean blocknet_onefile.spec

# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

PROJECT_DIR = Path(os.getcwd()).resolve()

datas = []
blocknet_exe = PROJECT_DIR / "blocknet.exe"
if blocknet_exe.exists():
    # In onefile, datas are extracted at runtime into sys._MEIPASS
    datas.append((str(blocknet_exe), "."))
else:
    print(f"[spec] WARNING: blocknet.exe not found at: {blocknet_exe}")

hiddenimports = []
hiddenimports += collect_submodules("PyQt5")
datas += collect_data_files("PyQt5", include_py_files=False)

a = Analysis(
    ["gui.py"],
    pathex=[str(PROJECT_DIR)],
    binaries=[],
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