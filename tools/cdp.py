#!/usr/bin/env python3
"""Minimal Chrome DevTools Protocol driver for capturing Landui console traffic.

The browser is launched separately in HEADED mode:

    google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/opencode/chrome-prof \\
        --no-first-run https://account.console.landui.com/

Usage:
    python3 tools/cdp.py targets
    python3 tools/cdp.py shot /tmp/opencode/shot.png
    python3 tools/cdp.py eval "document.title"
    python3 tools/cdp.py cookies
    python3 tools/cdp.py watch captures/raw.jsonl [--seconds 600]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import requests
import websocket

DEBUG_HOST = os.environ.get("CDP_HOST", "127.0.0.1")
DEBUG_PORT = int(os.environ.get("CDP_PORT", "9222"))


def http(path: str) -> Any:
    r = requests.get(f"http://{DEBUG_HOST}:{DEBUG_PORT}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def pages() -> list[dict]:
    return [t for t in http("/json/list") if t.get("type") == "page"]


def pick_page(url_contains: str | None = None) -> dict:
    targets = pages()
    if not targets:
        raise SystemExit("no page target found")
    if url_contains:
        for t in targets:
            if url_contains in (t.get("url") or ""):
                return t
    # prefer the most recently focused landui page
    for t in targets:
        if "landui" in (t.get("url") or ""):
            return t
    return targets[0]


class CDP:
    def __init__(self, ws_url: str):
        self.ws = websocket.create_connection(ws_url, timeout=30, max_size=200 * 1024 * 1024)
        self._id = 0

    def send(self, method: str, **params) -> dict:
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    def wait_for(self, method: str, timeout: float = 30) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("method") == method:
                return msg.get("params", {})
        raise TimeoutError(method)

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception as exc:  # noqa: BLE001 - 关闭失败无所谓
            print(f"close failed: {exc}", file=sys.stderr)


def connect(url_contains: str | None = "landui") -> CDP:
    page = pick_page(url_contains)
    return CDP(page["webSocketDebuggerUrl"])


def cmd_targets(_args) -> None:
    for t in http("/json/list"):
        if t.get("type") != "page":
            continue
        print(f"{t['id']}  {t.get('url')}\n    ws={t['webSocketDebuggerUrl']}")


def cmd_shot(args) -> None:
    cdp = connect(args.match)
    cdp.send("Page.enable")
    data = cdp.send("Page.captureScreenshot", format="png", captureBeyondViewport=False)["data"]
    import base64

    with open(args.path, "wb") as f:
        f.write(base64.b64decode(data))
    cdp.close()
    print(args.path)


def cmd_eval(args) -> None:
    cdp = connect(args.match)
    res = cdp.send(
        "Runtime.evaluate",
        expression=args.expression,
        returnByValue=True,
        awaitPromise=True,
        allowUnsafeEvalBlockedByCSP=True,
    )
    cdp.close()
    print(json.dumps(res.get("result", {}), ensure_ascii=False, indent=2))


def cmd_cookies(_args) -> None:
    cdp = connect(None)
    cookies = cdp.send("Network.getAllCookies")["cookies"]
    cdp.close()
    for c in cookies:
        print(
            f"{c['domain']}\t{c['name']}\t{c['value'][:60]}{'...' if len(c['value']) > 60 else ''}"
        )


def cmd_watch(args) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(args.outfile)), exist_ok=True)
    cdp = connect(args.match)
    cdp.send("Network.enable", maxTotalBufferSize=200 * 1024 * 1024, maxResourceBufferSize=50 * 1024 * 1024)
    cdp.send("Page.enable")

    out = open(args.outfile, "a", encoding="utf-8")  # noqa: SIM115 - finally 里关闭
    requests_by_id: dict[str, dict] = {}
    pending_bodies: set[str] = set()
    deadline = time.time() + args.seconds if args.seconds else None
    count = 0

    def emit(rec: dict) -> None:
        out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        out.flush()

    print(f"watching {args.outfile} (Ctrl-C to stop)", file=sys.stderr)
    cdp.ws.settimeout(1.0)
    try:
        while deadline is None or time.time() < deadline:
            try:
                raw = cdp.ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            msg = json.loads(raw)
            method = msg.get("method")
            p = msg.get("params", {})
            if method == "Network.requestWillBeSent":
                req = p["request"]
                rec = {
                    "id": p["requestId"],
                    "ts": round(p.get("timestamp", 0), 3),
                    "url": req["url"],
                    "method": req["method"],
                    "type": p.get("type"),
                    "headers": req.get("headers", {}),
                    "postData": req.get("postData"),
                }
                requests_by_id[p["requestId"]] = rec
                if args.verbose:
                    print(f"-> {req['method']} {req['url']}", file=sys.stderr)
            elif method == "Network.responseReceived":
                rec = requests_by_id.get(p["requestId"])
                if rec is not None:
                    resp = p["response"]
                    rec.update(
                        status=resp.get("status"),
                        mime=resp.get("mimeType"),
                        resp_headers=resp.get("headers", {}),
                    )
            elif method == "Network.loadingFinished":
                rec = requests_by_id.pop(p["requestId"], None)
                if rec is None:
                    continue
                if rec.get("mime") and ("json" in rec["mime"] or "javascript" in rec["mime"]):
                    pending_bodies.add(p["requestId"])
                    try:
                        body = cdp.send("Network.getResponseBody", requestId=p["requestId"]).get("body", "")
                    except Exception:  # noqa: BLE001 - 拿不到 body 不影响抓包
                        body = ""
                    if body:
                        rec["body"] = body[: args.max_body]
                emit(rec)
                count += 1
                if args.verbose:
                    print(f"<- {rec.get('status')} {rec['url'][:160]}", file=sys.stderr)
            elif method == "Network.loadingFailed":
                rec = requests_by_id.pop(p["requestId"], None)
                if rec:
                    rec["failed"] = p.get("errorText")
                    emit(rec)
    except KeyboardInterrupt:
        pass
    finally:
        out.close()
        cdp.close()
    print(f"captured {count} requests -> {args.outfile}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", default="landui", help="substring of page URL to attach to")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("targets").set_defaults(func=cmd_targets)

    s = sub.add_parser("shot")
    s.add_argument("path")
    s.set_defaults(func=cmd_shot)

    s = sub.add_parser("eval")
    s.add_argument("expression")
    s.set_defaults(func=cmd_eval)

    sub.add_parser("cookies").set_defaults(func=cmd_cookies)

    s = sub.add_parser("watch")
    s.add_argument("outfile")
    s.add_argument("--seconds", type=float, default=0)
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--max-body", type=int, default=400_000)
    s.set_defaults(func=cmd_watch)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
