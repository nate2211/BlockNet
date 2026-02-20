from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from registry import BLOCKS
from blocknet_client import BlockNetClient
from block import BaseBlock


@dataclass
class BlockNetPutBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        key = str(params.get("key", ""))
        mime = str(params.get("mime", "application/octet-stream"))

        data = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", errors="replace")

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.put(bytes(data), key=key, mime=mime)

        # output the ref (best for pipelines)
        ref = j.get("ref", "")
        return ref, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_put", BlockNetPutBlock)

@dataclass
class BlockNetGetBlock(BaseBlock):
    """
    Params:
      relay, token
      mode: "auto" | "ref" | "key"
      as: "auto" | "text" | "bytes"
    Payload: ref string OR key string (depending on mode)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        mode = str(params.get("mode", "auto")).lower()
        as_mode = str(params.get("as", "auto")).lower()

        s = str(payload or "").strip()
        if not s:
            return "", {"ok": False, "error": "empty payload"}

        cli = BlockNetClient(relay=relay, token=token)

        if mode == "ref" or (mode == "auto" and s.startswith("obj_")):
            status, hdrs, data = cli.get_ref(s)
            used = {"mode": "ref", "ref": s}
        else:
            status, hdrs, data = cli.get_key(s)
            used = {"mode": "key", "key": s}

        ok = (status == 200)

        if as_mode == "bytes":
            out: Any = data
        elif as_mode == "text":
            out = data.decode("utf-8", errors="replace")
        else:
            ctype = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
            if ctype.startswith("text/") or "json" in ctype:
                out = data.decode("utf-8", errors="replace")
            else:
                # safe default: bytes (pipeline may store this to a file later)
                out = data

        meta = {"ok": ok, "status": status, "headers": hdrs, **used}
        if not ok:
            # if server returned json error, try show it
            try:
                meta["error_body"] = data.decode("utf-8", errors="replace")
            except Exception:
                pass
        return out, meta


BLOCKS.register("blocknet_get", BlockNetGetBlock)

@dataclass
class BlockNetStatsBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        cli = BlockNetClient(relay=relay, token=token)
        j = cli.stats()
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_stats", BlockNetStatsBlock)


@dataclass
class BlockNetHeartbeatBlock(BaseBlock):
    """
    Params:
      relay, token, id
    Payload:
      optional json string/dict for stats
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38887"))
        token = str(params.get("token", ""))
        cid = str(params.get("id", "client1"))

        stats: Dict[str, Any] = {}
        if isinstance(payload, dict):
            stats = payload
        elif payload:
            try:
                stats = json.loads(str(payload))
            except Exception:
                stats = {"payload": str(payload)}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.heartbeat(cid, stats)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_heartbeat", BlockNetHeartbeatBlock)