"""账号密码的本地保管（让程序自己读，人不用每次输）。

* 文件：``~/.config/landui-sdk/credentials.json``，权限 0600
* 也支持环境变量：``LANDUI_USERNAME`` / ``LANDUI_PASSWORD``（优先于文件）
* **明文**存储：和浏览器记住密码一个级别。介意的话用环境变量或系统钥匙串。

SDK 内部只有在需要登录时才会读它，不会打印、不会写日志、不会进异常信息。
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

CREDENTIALS_PATH = "~/.config/landui-sdk/credentials.json"


@dataclass
class Credentials:
    username: str
    password: str = ""

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    def __repr__(self) -> str:  # 防止不小心 print 出密码
        masked = "'***'" if self.password else "''"
        return f"Credentials(username={self.username!r}, password={masked})"


class CredentialStore:
    def __init__(self, path: str | os.PathLike = CREDENTIALS_PATH):
        self.path = Path(path).expanduser()

    # ------------------------------------------------------------------ 读
    def load(self) -> Credentials | None:
        """环境变量优先，其次文件；都没有返回 None。"""
        user = os.environ.get("LANDUI_USERNAME")
        pwd = os.environ.get("LANDUI_PASSWORD")
        if user and pwd:
            return Credentials(user, pwd)
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return None
        user = str(data.get("username") or "").strip()
        pwd = str(data.get("password") or "")
        if not user:
            return None
        # 允许「只记住账号」：password 为空也算有效记录
        return Credentials(user, pwd)

    # ------------------------------------------------------------------ 写
    def save(self, credentials: Credentials) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"username": credentials.username, "password": credentials.password}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), "utf-8")
        try:
            self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return self.path

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def exists(self) -> bool:
        return self.load() is not None
