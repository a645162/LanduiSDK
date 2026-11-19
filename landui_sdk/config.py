"""本地配置：每台服务器的多套 SSH 账号、备注、终端偏好。

安全说明：密码/私钥口令按你的要求明文存本地 ``~/.config/landui-sdk/config.json``，
权限 0600。介意的话可以只用 ssh-agent 或密钥（密钥本身不带口令时无需存任何秘密）。
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

CONFIG_PATH = "~/.config/landui-sdk/config.json"

AUTH_PASSWORD = "password"
AUTH_KEY = "key"
AUTH_AGENT = "agent"
AUTH_LABELS = {
    AUTH_PASSWORD: "密码",
    AUTH_KEY: "密钥",
    AUTH_AGENT: "SSH Agent",
}


@dataclass
class SshAccount:
    """一个可以登录该服务器的账号（同一台机器可以有多个）。"""

    user: str = "root"
    port: int = 22
    auth_mode: str = AUTH_AGENT
    password: str = ""
    key_path: str = ""
    key_passphrase: str = ""
    label: str = ""

    @property
    def display(self) -> str:
        name = f"{self.user}@{self.port}"
        if self.label:
            name += f"（{self.label}）"
        return name

    @property
    def auth_label(self) -> str:
        text = AUTH_LABELS.get(self.auth_mode, self.auth_mode)
        if self.auth_mode == AUTH_KEY and self.key_path:
            text += f"：{Path(self.key_path).expanduser().name}"
        return text


@dataclass
class ServerProfile:
    server_id: int
    note: str = ""
    custom_name: str = ""
    accounts: list[SshAccount] = field(default_factory=list)
    default_account: str = "root"      # 用 user 名标识
    # 兼容旧版本字段（自动迁移到 accounts）
    ssh_user: str = "root"
    ssh_port: int = 0
    ssh_password: str = ""

    # ------------------------------------------------------------------ 账号
    def normalize(self) -> None:
        """把老配置迁移成 accounts，并补齐默认账号。"""
        if not self.accounts and (self.ssh_port or self.ssh_password):
            self.accounts = [
                SshAccount(
                    user=self.ssh_user or "root",
                    port=self.ssh_port or 22,
                    auth_mode=AUTH_PASSWORD if self.ssh_password else AUTH_AGENT,
                    password=self.ssh_password,
                )
            ]
        if self.accounts:
            if not self.default_account or not any(
                a.user == self.default_account for a in self.accounts
            ):
                self.default_account = self.accounts[0].user
        elif not self.default_account:
            self.default_account = "root"

    def account(self, user: str | None = None) -> SshAccount | None:
        self.normalize()
        if not self.accounts:
            return None
        if user:
            for account in self.accounts:
                if account.user == user:
                    return account
            return None
        for account in self.accounts:
            if account.user == self.default_account:
                return account
        return self.accounts[0]

    def upsert_account(self, account: SshAccount) -> None:
        for index, existing in enumerate(self.accounts):
            if existing.user == account.user:
                self.accounts[index] = account
                break
        else:
            self.accounts.append(account)
        if not self.default_account:
            self.default_account = account.user

    def remove_account(self, user: str) -> None:
        self.accounts = [a for a in self.accounts if a.user != user]
        if self.default_account == user and self.accounts:
            self.default_account = self.accounts[0].user

    # ------------------------------------------------------------------ 便捷
    @property
    def primary(self) -> SshAccount | None:
        return self.account()


@dataclass
class AppConfig:
    profiles: dict[str, ServerProfile] = field(default_factory=dict)
    ssh_launcher: str = "auto"         # 见 landui_sdk.ssh.LAUNCHERS
    ssh_launcher_custom: str = ""      # 自定义模板，支持 {cmd} {user} {host} {port}
    auto_login: bool = True            # 启动时用本地保存的账号密码静默登录
    terminal: str = ""                 # 旧字段，保留做兼容
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ io
    @classmethod
    def load(cls, path: str | os.PathLike = CONFIG_PATH) -> AppConfig:
        p = Path(path).expanduser()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            return cls()

        profiles: dict[str, ServerProfile] = {}
        for key, raw in (data.get("profiles") or {}).items():
            accounts = [
                SshAccount(**{k: v for k, v in a.items() if k in _ACCOUNT_FIELDS})
                for a in (raw.get("accounts") or [])
                if isinstance(a, dict)
            ]
            profile = ServerProfile(
                server_id=int(raw.get("server_id") or key),
                note=raw.get("note", ""),
                custom_name=raw.get("custom_name", ""),
                accounts=accounts,
                default_account=raw.get("default_account", "root"),
                ssh_user=raw.get("ssh_user", "root"),
                ssh_port=int(raw.get("ssh_port") or 0),
                ssh_password=raw.get("ssh_password", ""),
            )
            profile.normalize()
            profiles[str(key)] = profile

        return cls(
            profiles=profiles,
            ssh_launcher=data.get("ssh_launcher") or "auto",
            ssh_launcher_custom=data.get("ssh_launcher_custom", ""),
            auto_login=bool(data.get("auto_login", True)),
            terminal=data.get("terminal", ""),
            extra=data.get("extra", {}),
        )

    def save(self, path: str | os.PathLike = CONFIG_PATH) -> Path:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "profiles": {k: asdict(v) for k, v in self.profiles.items()},
            "ssh_launcher": self.ssh_launcher,
            "ssh_launcher_custom": self.ssh_launcher_custom,
            "auto_login": self.auto_login,
            "terminal": self.terminal,
            "extra": self.extra,
        }
        p.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
        try:
            p.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return p

    # ------------------------------------------------------------- profile
    def get(self, server_id: int) -> ServerProfile:
        key = str(server_id)
        if key not in self.profiles:
            self.profiles[key] = ServerProfile(server_id=server_id)
        profile = self.profiles[key]
        profile.normalize()
        return profile


_ACCOUNT_FIELDS = {
    "user", "port", "auth_mode", "password", "key_path", "key_passphrase", "label",
}
