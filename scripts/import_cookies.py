#!/usr/bin/env python3
"""从正在运行的 Chrome 里抓取 landui.com 的 Cookie，存成 SDK 的 auth.json。

前置：Chrome 以调试端口启动（非 headless），并且你已经在里面登录了蓝队云。

    google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/landui-chrome \\
        https://www.landui.com/user/

然后：

    uv run python scripts/import_cookies.py            # 默认 9222 端口
    uv run python scripts/import_cookies.py --port 9223 --out ~/.config/landui-sdk/auth.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from landui_sdk.client import DEFAULT_AUTH_FILE


def _ws_url(port: int, host: str) -> str:
    """优先用页面 target（Network.getAllCookies 只在这里可靠）。"""
    try:
        targets = requests.get(f"http://{host}:{port}/json/list", timeout=5).json()
    except requests.RequestException as exc:
        raise SystemExit(
            f"连不上 Chrome 调试端口 {host}:{port}，"
            "请用 --remote-debugging-port=9222 启动非 headless Chrome 并保持打开"
        ) from exc
    pages = [t for t in targets if t.get("type") == "page"]
    for t in pages:
        if "landui" in (t.get("url") or ""):
            return t["webSocketDebuggerUrl"]
    if pages:
        return pages[0]["webSocketDebuggerUrl"]
    return requests.get(f"http://{host}:{port}/json/version", timeout=5).json()[
        "webSocketDebuggerUrl"
    ]


def fetch_cookies(port: int, host: str = "127.0.0.1") -> list[dict]:
    ws_url = _ws_url(port, host)
    try:
        import websocket  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("需要 websocket-client：uv add --dev websocket-client") from exc
    ws = websocket.create_connection(ws_url, timeout=10)
    try:
        for method in ("Network.getAllCookies", "Storage.getCookies"):
            ws.send(json.dumps({"id": 1, "method": method}))
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    break
            result = msg.get("result") or {}
            if result.get("cookies"):
                return result["cookies"]
        raise SystemExit(f"读取 Cookie 失败：{msg.get('error')}")
    finally:
        ws.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("CDP_PORT", "9222")))
    ap.add_argument("--host", default=os.environ.get("CDP_HOST", "127.0.0.1"))
    ap.add_argument("--out", default=DEFAULT_AUTH_FILE)
    args = ap.parse_args()

    cookies = [c for c in fetch_cookies(args.port, args.host) if "landui" in c["domain"]]
    if not cookies:
        raise SystemExit("没抓到 landui 的 Cookie：确认已在那个 Chrome 里登录？")

    payload = {
        "cookies": [
            {
                "name": c["name"],
                "value": c["value"],
                "domain": c["domain"],
                "path": c.get("path", "/"),
            }
            for c in cookies
        ]
    }
    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), "utf-8")
    out.chmod(0o600)
    print(f"已保存 {len(cookies)} 个 Cookie -> {out}")


if __name__ == "__main__":
    main()
