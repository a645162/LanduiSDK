"""SSH 命令拼装的离线测试。"""

from __future__ import annotations

import shutil

from landui_sdk.ssh import SshTarget, build_ssh_command, detect_terminal


def test_build_command_no_password():
    args = build_ssh_command(SshTarget("1.2.3.4", 2222, "root"))
    assert args[0] == "ssh"
    assert "-p" in args and "2222" in args
    assert args[-1] == "root@1.2.3.4"
    assert "StrictHostKeyChecking=accept-new" in " ".join(args)


def test_build_command_with_password_uses_sshpass_when_available():
    target = SshTarget("1.2.3.4", 22, "root", "p@ss word")
    args = build_ssh_command(target)
    if shutil.which("sshpass"):
        assert args[0] == "sshpass"
        assert "p@ss word" in args
    else:
        assert args[0] == "ssh"


def test_detect_terminal_returns_something_on_desktop():
    found = detect_terminal()
    # CI/无桌面环境下可能是 None，这里只保证不抛异常
    assert found is None or isinstance(found, tuple)
