from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from registry import BLOCKS
from blocknet_client import BlockNetClient
from block import BaseBlock


# ---------------- existing blocks ----------------

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
                out = data

        meta = {"ok": ok, "status": status, "headers": hdrs, **used}
        if not ok:
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


# ---------------- NEW: API blocks (core/media/randomx/web/p2pool) ----------------

def _api_prefix(params: Dict[str, Any]) -> str:
    pfx = str(params.get("api_prefix", "/v1") or "/v1").strip()
    if not pfx.startswith("/"):
        pfx = "/" + pfx
    return pfx.rstrip("/")


@dataclass
class BlockNetPingBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_ping(prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_ping", BlockNetPingBlock)


@dataclass
class BlockNetTextToVecBlock(BaseBlock):
    """
    Payload: text (string)
    Params: relay, token, api_prefix, dim, normalize, output
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        text = "" if payload is None else str(payload)
        dim = int(params.get("dim", 1024))
        normalize = bool(params.get("normalize", True))
        output = str(params.get("output", "b64f32"))

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_texttovec(text, dim=dim, normalize=normalize, output=output, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_texttovec", BlockNetTextToVecBlock)


def _b64_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@dataclass
class BlockNetImageToVecBlock(BaseBlock):
    """
    Payload:
      - bytes: raw image bytes
      - str: treated as already-base64 (unless params.base64=false, then it becomes utf8 bytes)
      - dict: sent as-is (advanced)
    Params:
      relay, token, api_prefix, dim, normalize, output, base64 (default True)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        dim = int(params.get("dim", 1024))
        normalize = bool(params.get("normalize", True))
        output = str(params.get("output", "b64f32"))
        treat_str_as_b64 = bool(params.get("base64", True))

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            if isinstance(payload, (bytes, bytearray)):
                b64 = _b64_bytes(bytes(payload))
            else:
                s = "" if payload is None else str(payload)
                b64 = s if treat_str_as_b64 else _b64_bytes(s.encode("utf-8", errors="replace"))

            body = {"image_b64": b64, "dim": dim, "normalize": normalize, "output": output}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_imagetovec(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_imagetovec", BlockNetImageToVecBlock)


@dataclass
class BlockNetVideoToVecBlock(BaseBlock):
    """
    Same conventions as imagetovec, but uses video_b64.
    Params additionally: max_frames (optional)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        dim = int(params.get("dim", 1024))
        normalize = bool(params.get("normalize", True))
        output = str(params.get("output", "b64f32"))
        max_frames = int(params.get("max_frames", 256))
        treat_str_as_b64 = bool(params.get("base64", True))

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            if isinstance(payload, (bytes, bytearray)):
                b64 = _b64_bytes(bytes(payload))
            else:
                s = "" if payload is None else str(payload)
                b64 = s if treat_str_as_b64 else _b64_bytes(s.encode("utf-8", errors="replace"))
            body = {"video_b64": b64, "dim": dim, "normalize": normalize, "output": output, "max_frames": max_frames}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_videotovec(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_videotovec", BlockNetVideoToVecBlock)


@dataclass
class BlockNetVectorTextBlock(BaseBlock):
    """
    POST /vectortext

    Payload:
      - dict: full body for vectortext (recommended)
      - str: becomes prompt; params.payload supplies payload string
    Params:
      relay, token, api_prefix
      payload, key, lexicon_key, context_key
      idf_key, tokens_key
      max_tokens, topk, seed
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            # simple mode: payload is prompt, plus params
            body = {
                "prompt": "" if payload is None else str(payload),
                "payload": str(params.get("payload", "")),
            }

        # pass-through first-class routing keys
        for k in ("key", "lexicon_key", "context_key", "idf_key", "tokens_key"):
            if k in params and k not in body:
                body[k] = params.get(k)

        # optional inline lexicon/context blocks (can be json/dict/str)
        if "lexicon" in params and "lexicon" not in body:
            body["lexicon"] = params.get("lexicon")
        if "context" in params and "context" not in body:
            body["context"] = params.get("context")

        # generation controls
        if "max_tokens" in params and "max_tokens" not in body:
            body["max_tokens"] = int(params.get("max_tokens"))
        if "topk" in params and "topk" not in body:
            body["topk"] = int(params.get("topk"))
        if "seed" in params and "seed" not in body:
            body["seed"] = params.get("seed")

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_vectortext(body, prefix=pfx)

        # best pipeline output is the generated text if present
        out = j.get("generated", j)
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_vectortext", BlockNetVectorTextBlock)


@dataclass
class BlockNetRandomXStatusBlock(BaseBlock):
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_randomx_status(prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_randomx_status", BlockNetRandomXStatusBlock)


@dataclass
class BlockNetRandomXHashBlock(BaseBlock):
    """
    Payload:
      - bytes: becomes data_b64
      - str: becomes data_hex (if looks hex) else data_b64(utf8)
      - dict: sent as-is
    Params:
      relay, token, api_prefix, seed_hex
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        seed_hex = str(params.get("seed_hex", "")).strip()
        if not seed_hex:
            return "", {"ok": False, "error": "missing seed_hex param"}

        if isinstance(payload, dict):
            body = dict(payload)
            body.setdefault("seed_hex", seed_hex)
        else:
            body: Dict[str, Any] = {"seed_hex": seed_hex}
            if isinstance(payload, (bytes, bytearray)):
                body["data_b64"] = _b64_bytes(bytes(payload))
            else:
                s = "" if payload is None else str(payload).strip()
                is_hex = all(c in "0123456789abcdefABCDEF" for c in s) and (len(s) % 2 == 0) and len(s) > 0
                if is_hex:
                    body["data_hex"] = s
                else:
                    body["data_b64"] = _b64_bytes(s.encode("utf-8", errors="replace"))

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_randomx_hash(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_randomx_hash", BlockNetRandomXHashBlock)

@dataclass
class BlockNetRandomXHashBatchBlock(BaseBlock):
    """
    POST /randomx/hash_batch

    Params:
      relay, token, api_prefix, seed_hex
      max_items (optional): truncate items list (default 0 = no truncate)

    Payload:
      - dict: treated as full request body (seed_hex filled from params if missing)
      - list: treated as items[]
      - str: JSON list or JSON object
      - bytes: treated as ONE item (data_b64)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        seed_hex = str(params.get("seed_hex", "")).strip()
        payload_seed = ""
        if isinstance(payload, dict):
            payload_seed = str(payload.get("seed_hex", "")).strip()

        if not seed_hex and not payload_seed:
            return "", {"ok": False, "error": "missing seed_hex param"}

        # Build request body
        if isinstance(payload, dict):
            body: Dict[str, Any] = dict(payload)
            if seed_hex:
                body.setdefault("seed_hex", seed_hex)

        elif isinstance(payload, list):
            body = {"seed_hex": seed_hex, "items": payload}

        elif isinstance(payload, (bytes, bytearray)):
            body = {"seed_hex": seed_hex, "items": [{"data_b64": _b64_bytes(bytes(payload))}]}

        else:
            s = "" if payload is None else str(payload).strip()
            if not s:
                return "", {"ok": False, "error": "empty payload (expected items JSON)"}
            try:
                parsed = json.loads(s)
            except Exception:
                return "", {"ok": False, "error": "payload must be JSON list or object"}

            if isinstance(parsed, dict):
                body = dict(parsed)
                if seed_hex:
                    body.setdefault("seed_hex", seed_hex)
            elif isinstance(parsed, list):
                body = {"seed_hex": seed_hex, "items": parsed}
            else:
                return "", {"ok": False, "error": "payload JSON must be an object or array"}

        if "items" not in body or not isinstance(body["items"], list):
            return "", {"ok": False, "error": "missing items[] (must be a JSON array)"}

        # Optional truncate
        try:
            max_items = int(params.get("max_items", 0))
        except Exception:
            max_items = 0
        if max_items > 0:
            body["items"] = body["items"][:max_items]

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_randomx_hash_batch(body, prefix=pfx)

        # Pipeline-friendly output
        out = j.get("results", j)
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_randomx_hash_batch", BlockNetRandomXHashBatchBlock)

@dataclass
class BlockNetRandomXScanBlock(BaseBlock):
    """
    POST /randomx/scan

    Payload:
      - dict: full request body (recommended)
      - bytes: treated as blob (blob_b64)
      - str: treated as blob_hex if hex-looking else blob_b64(utf8)

    Params:
      relay, token, api_prefix
      seed_hex (required unless in payload dict)
      nonce_offset (default 39)
      start_nonce (default 0)
      iters (default 200000)
      target64 (required unless in payload dict)
      max_results (default 4)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        # If caller gave dict, pass through (fill missing from params)
        if isinstance(payload, dict):
            body: Dict[str, Any] = dict(payload)
        else:
            body = {}

        # seed_hex
        if "seed_hex" not in body:
            seed_hex = str(params.get("seed_hex", "")).strip()
            if not seed_hex:
                return "", {"ok": False, "error": "missing seed_hex (param or payload dict)"}
            body["seed_hex"] = seed_hex

        # target64
        if "target64" not in body:
            if "target64" in params:
                body["target64"] = int(params.get("target64"))
            else:
                return "", {"ok": False, "error": "missing target64 (param or payload dict)"}

        # convenience blob fill if not provided
        if "blob_hex" not in body and "blob_b64" not in body:
            if isinstance(payload, (bytes, bytearray)):
                body["blob_b64"] = _b64_bytes(bytes(payload))
            elif payload is not None and not isinstance(payload, dict):
                s = str(payload).strip()
                is_hex = all(c in "0123456789abcdefABCDEF" for c in s) and (len(s) % 2 == 0) and len(s) > 0
                if is_hex:
                    body["blob_hex"] = s
                else:
                    body["blob_b64"] = _b64_bytes(s.encode("utf-8", errors="replace"))

        # defaults / optional knobs
        body.setdefault("nonce_offset", int(params.get("nonce_offset", 39)))
        body.setdefault("start_nonce", int(params.get("start_nonce", 0)))
        body.setdefault("iters", int(params.get("iters", 200000)))
        body.setdefault("max_results", int(params.get("max_results", 4)))

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_randomx_scan(body, prefix=pfx)

        # pipeline-friendly output: found list if present
        out = j.get("found", j)
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_randomx_scan", BlockNetRandomXScanBlock)
@dataclass
class BlockNetWebFetchBlock(BaseBlock):
    """
    Payload:
      - str: url
      - dict: request body for /web/fetch
    Params:
      relay, token, api_prefix, mode, include_js, max_bytes, max_scripts
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {"url": str(payload or "")}

        if not body.get("url"):
            return "", {"ok": False, "error": "missing url"}

        for k in ("mode", "include_js", "max_bytes", "max_scripts"):
            if k in params and k not in body:
                body[k] = params.get(k)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_web_fetch(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_web_fetch", BlockNetWebFetchBlock)


@dataclass
class BlockNetWebJsBlock(BaseBlock):
    """
    Payload:
      - str: url
      - dict: request body for /web/js
    Params:
      relay, token, api_prefix, fetch_bodies, max_scripts
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {"url": str(payload or "")}

        if not body.get("url"):
            return "", {"ok": False, "error": "missing url"}

        for k in ("fetch_bodies", "max_scripts"):
            if k in params and k not in body:
                body[k] = params.get(k)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_web_js(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_web_js", BlockNetWebJsBlock)

@dataclass
class BlockNetWebLinksBlock(BaseBlock):
    """
    POST /web/links

    Payload:
      - str: url
      - dict: request body for /web/links
    Params:
      relay, token, api_prefix
      same_origin (bool)        # optional
      external_only (bool)      # optional
      max_links (int)           # optional
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {"url": str(payload or "")}

        if not body.get("url"):
            return "", {"ok": False, "error": "missing url"}

        for k in ("same_origin", "external_only", "max_links"):
            if k in params and k not in body:
                body[k] = params.get(k)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_web_links(body, prefix=pfx)

        # nice pipeline output if server returns a list
        out = j.get("links", j.get("urls", j))
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_web_links", BlockNetWebLinksBlock)


@dataclass
class BlockNetWebRssFindBlock(BaseBlock):
    """
    POST /web/rss_find

    Payload:
      - str: url
      - dict: request body for /web/rss_find
    Params:
      relay, token, api_prefix
      max_feeds (int)           # optional
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {"url": str(payload or "")}

        if not body.get("url"):
            return "", {"ok": False, "error": "missing url"}

        if "max_feeds" in params and "max_feeds" not in body:
            body["max_feeds"] = params.get("max_feeds")

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_web_rss_find(body, prefix=pfx)

        # nice pipeline output if server returns a list
        out = j.get("feeds", j.get("urls", j))
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_web_rss_find", BlockNetWebRssFindBlock)

# ---- P2Pool blocks ----

@dataclass
class BlockNetP2PoolOpenBlock(BaseBlock):
    """
    Opens a session. Output is session token by default (best for pipelines).
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_p2pool_open(prefix=pfx)
        session = j.get("session", "")
        return session, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_open", BlockNetP2PoolOpenBlock)


@dataclass
class BlockNetP2PoolPollBlock(BaseBlock):
    """
    Payload: session token (string) OR dict body
    Params: max_msgs
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)
        max_msgs = int(params.get("max_msgs", 32))

        cli = BlockNetClient(relay=relay, token=token)

        if isinstance(payload, dict):
            session = str(payload.get("session", "") or "")
            max_msgs = int(payload.get("max_msgs", max_msgs))
        else:
            session = str(payload or "")

        if not session:
            return "", {"ok": False, "error": "missing session"}

        j = cli.api_p2pool_poll(session, max_msgs=max_msgs, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_poll", BlockNetP2PoolPollBlock)


@dataclass
class BlockNetP2PoolJobBlock(BaseBlock):
    """
    Payload: session token
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        session = str(payload or "").strip()
        if not session:
            return "", {"ok": False, "error": "missing session"}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_p2pool_job(session, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_job", BlockNetP2PoolJobBlock)


@dataclass
class BlockNetP2PoolSubmitBlock(BaseBlock):
    """
    Payload:
      - dict: {session, job_id, nonce, result}
      - str: treated as result; requires params.session/job_id/nonce
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body = dict(payload)
        else:
            body = {
                "session": str(params.get("session", "")),
                "job_id": str(params.get("job_id", "")),
                "nonce": str(params.get("nonce", "")),
                "result": str(payload or ""),
            }

        for k in ("session", "job_id", "nonce", "result"):
            if not str(body.get(k, "")).strip():
                return "", {"ok": False, "error": f"missing {k}"}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_p2pool_submit(body, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_submit", BlockNetP2PoolSubmitBlock)


@dataclass
class BlockNetP2PoolCloseBlock(BaseBlock):
    """
    Payload: session token
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        session = str(payload or "").strip()
        if not session:
            return "", {"ok": False, "error": "missing session"}

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_p2pool_close(session, prefix=pfx)
        return j, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_close", BlockNetP2PoolCloseBlock)

@dataclass
class BlockNetP2PoolScanBlock(BaseBlock):
    """
    POST /p2pool/scan

    Payload:
      - str: session token
      - dict: full request body {session, start_nonce, iters, max_results, nonce_offset, poll_first}

    Params:
      relay, token, api_prefix
      session (if payload is not session)
      start_nonce (default 0)
      iters (default 200000)
      max_results (default 4)
      nonce_offset (default 39)
      poll_first (default False)
    """
    def execute(self, payload: Any, *, params: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        relay = str(params.get("relay", "127.0.0.1:38888"))
        token = str(params.get("token", ""))
        pfx = _api_prefix(params)

        if isinstance(payload, dict):
            body: Dict[str, Any] = dict(payload)
        else:
            sess = str(payload or "").strip()
            if not sess:
                sess = str(params.get("session", "")).strip()
            body = {"session": sess}

        if not str(body.get("session", "")).strip():
            return "", {"ok": False, "error": "missing session"}

        # optional knobs
        body.setdefault("start_nonce", int(params.get("start_nonce", 0)))
        body.setdefault("iters", int(params.get("iters", 200000)))
        body.setdefault("max_results", int(params.get("max_results", 4)))
        body.setdefault("nonce_offset", int(params.get("nonce_offset", 39)))
        body.setdefault("poll_first", bool(params.get("poll_first", False)))

        cli = BlockNetClient(relay=relay, token=token)
        j = cli.api_p2pool_scan(body, prefix=pfx)

        # pipeline-friendly output: found list if present
        out = j.get("found", j)
        return out, {"ok": bool(j.get("ok", False)), "response": j}


BLOCKS.register("blocknet_p2pool_scan", BlockNetP2PoolScanBlock)