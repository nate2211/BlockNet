<img width="596" height="410" alt="Screenshot 2026-02-20 093903" src="https://github.com/user-attachments/assets/a2a91462-7f99-41cc-a2d7-bcab812dcaf3" />
BlockNetProject

BlockNetProject is a lightweight "blob relay" designed to store and retrieve binary objects over HTTP. It includes a C++ core server/client, a PyQt5 management GUI, and Python-integrated blocks for seamless use in block-processing frameworks.
🚀 Overview

It’s designed for simplicity and speed:

    PUT bytes → get back a unique ref (e.g., obj_...).

    GET by ref or by a logical key (pointing to the latest version).

    Auth: Optional Bearer token security.

    Monitoring: Basic stats and heartbeat client tracking.

    Maintenance: Automated TTL + cleanup (configurable in C++ build).

📂 Repository Structure
Plaintext

blocknetProject/
├── gui.py              # PyQt5 GUI (Server control, stats, quick testing)
├── blocknet_client.py   # Python client wrapper
├── blocks_blocknet.py   # Framework blocks: put, get, stats, heartbeat
├── main.py             # Optional framework entrypoint
├── registry.py         # Block registration logic
├── block.py            # BaseBlock & param_specs support
├── blocknet.exe        # Compiled C++ server/client binary
├── blocknet.spec       # PyInstaller specification for bundling
└── config.json         # (Generated) GUI configuration

    Note: blocknet.exe is built from the C++ BlockNet source and must be present in the root or bundled via PyInstaller.

⚡ Quick Start (CLI)
1. Start the Server

Generate a token and define your spool (storage) directory:
PowerShell

$TOKEN = "dev-" + [guid]::NewGuid().ToString("N")
$SPOOL = "$env:TEMP\blocknet_spool"

.\blocknet.exe serve --listen 127.0.0.1:38887 --spool "$SPOOL" --token "$TOKEN"

2. Common Operations

Check Stats:
PowerShell

.\blocknet.exe stats --relay 127.0.0.1:38887 --token "$TOKEN"

Send Heartbeat:
PowerShell

.\blocknet.exe heartbeat --relay 127.0.0.1:38887 --id "pc1" --json "{`"cpu`":12,`"mem`":34}" --token "$TOKEN"

Put / Get Data:
PowerShell

# Put data with a key
"hello world" | .\blocknet.exe put --relay 127.0.0.1:38887 --key greeting --mime text/plain --token "$TOKEN"

# Get by key (latest version)
.\blocknet.exe get --relay 127.0.0.1:38887 --key greeting --token "$TOKEN"

🖥️ Using the PyQt5 GUI

Run the GUI from source:
Bash

python gui.py

The GUI provides a control center to:

    Generate/manage secure tokens.

    Start/Stop the blocknet.exe server process.

    Monitor server health via /v1/stats.

    Perform ad-hoc PUT/GET operations for debugging.

🧩 Integration with Block Frameworks
1. Registration

Ensure the BlockNet blocks are imported into your registry:
Python

import blocks_blocknet  # Registers put, get, stats, and heartbeat

2. Block Usage Examples

blocknet_put

    Input: Text or Bytes.

    Output: Returns obj_... reference string for downstream blocks.

blocknet_get

    mode=auto: Automatically detects if the input is a ref (starts with obj_) or a key.

    as=auto: Automatically decodes JSON/Text to strings; otherwise returns raw bytes.

    ⚠️ Important: blocknet_get retrieves data from the relay, not local file paths. To store a file, you must read the file into memory first, then use blocknet_put.

🔐 Authentication & Tokens

The "token" is user-defined at runtime. There is no central authority; the server simply validates that the client's token matches the one it was started with.

    Server Start: .\blocknet.exe serve --token "your-secret-here"

    Client Call: --extra blocknet_put.token="your-secret-here"

    Open Access: Start the server without the --token flag to disable auth.

🛠️ Troubleshooting
Issue	Solution
Failed to listen	Port 38887 is likely in use. Run netstat -ano | findstr :38887 to find the conflicting process.
Unauthorized (401)	Token mismatch. Ensure the token passed to the client matches the server's start-up token.
404 / Empty Body	You are requesting a ref or key that doesn't exist. Check for typos or verify the data was successfully "Put."
📦 Packaging

When bundling with PyInstaller, ensure blocknet.exe is included as a data file and accessed via a runtime-safe path (like sys._MEIPASS).
Bash

pyinstaller --noconfirm --clean blocknet.spec

License: MIT

Would you like me to help you draft the blocknet.spec file or a Python snippet for handling those resource paths?
