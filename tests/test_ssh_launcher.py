"""SSH 打开方式 / 多账号配置的离线测试。"""

from __future__ import annotations

import json
import shutil

import pytest

from landui_sdk.config import AppConfig, SshAccount
from landui_sdk.ssh import (
    SshTarget,
    build_launcher_argv,
    build_ssh_command,
    write_askpass,
)


def test_target_auth_mode_precedence():
    assert SshTarget("h").auth_mode == "agent"
    assert SshTarget("h", password="p").auth_mode == "password"
    assert SshTarget("h", password="p", key_path="~/k").auth_mode == "key"


def test_ssh_command_with_key():
    target = SshTarget("1.2.3.4", 2222, "deploy", key_path="~/.ssh/id_ed25519")
    args = build_ssh_command(target)
    assert "-i" in args
    idx = args.index("-i")
    assert args[idx + 1].endswith(".ssh/id_ed25519")
    assert "IdentitiesOnly=yes" in args
    assert args[-1] == "deploy@1.2.3.4"


def test_askpass_handles_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = write_askpass()
    assert path.exists()
    body = path.read_text("utf-8")
    assert "LANDUI_SSH_PASSWORD" in body
    assert "assphrase" in body
    assert path.stat().st_mode & 0o700 == 0o700


def test_custom_launcher_template():
    target = SshTarget("1.2.3.4", 2222, "root", password="x")
    argv = build_launcher_argv(
        "custom", target, custom="mytool open {user}@{host} --port {port}"
    )
    assert argv == ["mytool", "open", "root@1.2.3.4", "--port", "2222"]


def test_custom_launcher_uses_cmd_shell():
    target = SshTarget("1.2.3.4", 22, "root")
    argv = build_launcher_argv("custom", target, custom="alacritty -e bash -lc {cmd}",
                               keep_open=False)
    assert argv[:4] == ["alacritty", "-e", "bash", "-lc"]
    assert argv[4].startswith("ssh -p 22")


def test_auto_launcher_uses_detected_terminal(monkeypatch):
    from landui_sdk import ssh

    monkeypatch.setattr(ssh, "detect_terminal", lambda: ("/usr/bin/xterm", ["-e"]))
    argv = build_launcher_argv("auto", SshTarget("1.2.3.4"), keep_open=False)
    assert argv[0] == "/usr/bin/xterm"
    assert argv[-1].startswith("ssh -p 22")
    assert argv[-1].endswith("root@1.2.3.4")


@pytest.mark.skipif(shutil.which("tabby") is None, reason="本机没装 Tabby")
def test_tabby_launcher():
    argv = build_launcher_argv("tabby", SshTarget("1.2.3.4", 2200, "ops"),
                               keep_open=False)
    assert argv[:2] == ["tabby", "run"]
    assert argv[-1].startswith("ssh -p 2200")
    assert argv[-1].endswith("ops@1.2.3.4")


def test_config_migrates_legacy_profile(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "profiles": {
            "10001": {
                "server_id": 10001,
                "ssh_user": "deploy",
                "ssh_port": 2222,
                "ssh_password": "old-pass",
                "note": "生产",
            }
        }
    }), "utf-8")
    cfg = AppConfig.load(path)
    profile = cfg.get(10001)
    assert len(profile.accounts) == 1
    acc = profile.account()
    assert (acc.user, acc.port, acc.password) == ("deploy", 2222, "old-pass")
    assert acc.auth_mode == "password"
    assert profile.default_account == "deploy"


def test_config_multiple_accounts_roundtrip(tmp_path):
    path = tmp_path / "config.json"
    cfg = AppConfig(ssh_launcher="tabby")
    profile = cfg.get(1)
    profile.upsert_account(SshAccount(user="root", port=22, auth_mode="key",
                                      key_path="~/.ssh/id_ed25519", label="运维"))
    profile.upsert_account(SshAccount(user="deploy", port=2222, auth_mode="password",
                                      password="p", label="部署"))
    profile.default_account = "deploy"
    cfg.save(path)

    loaded = AppConfig.load(path)
    p2 = loaded.get(1)
    assert [a.user for a in p2.accounts] == ["root", "deploy"]
    assert p2.account().user == "deploy"
    assert p2.account("root").auth_mode == "key"
    assert loaded.ssh_launcher == "tabby"
    assert path.stat().st_mode & 0o600 == 0o600


def test_remove_account_updates_default(tmp_path):
    cfg = AppConfig()
    profile = cfg.get(1)
    profile.upsert_account(SshAccount(user="root"))
    profile.upsert_account(SshAccount(user="ops"))
    profile.default_account = "root"
    profile.remove_account("root")
    assert profile.default_account == "ops"
    assert [a.user for a in profile.accounts] == ["ops"]
