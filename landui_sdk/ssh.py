"""一键 SSH：拼命令、准备凭据、用你喜欢的终端打开。

支持三种登录方式：

* **密码**：OpenSSH 8.4+ 用 ``SSH_ASKPASS_REQUIRE=force`` 自动填（不需要 sshpass）
* **密钥**：``-i 私钥``；私钥有口令也能通过 askpass 自动填
* **SSH Agent**：什么都不用配，走 ``ssh-agent``

支持多种打开方式（见 ``LAUNCHERS``）：系统终端自动探测、GNOME Terminal、Konsole、
kitty、WezTerm、**Tabby**、Windows 的 PowerShell / Windows Terminal，或者自定义命令模板。
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

ASKPASS_PATH = "~/.cache/landui-sdk/askpass.sh"
OK_MARK = "__LANDUI_SSH_OK__"

AUTH_PASSWORD = "password"
AUTH_KEY = "key"
AUTH_AGENT = "agent"

_TERMINALS: list[tuple[str, list[str]]] = [
    ("x-terminal-emulator", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("mate-terminal", ["-x"]),
    ("tilix", ["-e"]),
    ("kitty", ["-e"]),
    ("alacritty", ["-e"]),
    ("wezterm", ["start", "--"]),
    ("foot", ["-e"]),
    ("xterm", ["-e"]),
]


@dataclass
class SshTarget:
    host: str
    port: int = 22
    user: str = "root"
    password: str = ""
    key_path: str = ""
    key_passphrase: str = ""

    @property
    def address(self) -> str:
        return f"{self.user}@{self.host}"

    @property
    def auth_mode(self) -> str:
        if self.key_path:
            return AUTH_KEY
        if self.password:
            return AUTH_PASSWORD
        return AUTH_AGENT


# --------------------------------------------------------------------- 凭据
def write_askpass() -> Path:
    """生成 askpass 脚本：同时支持登录密码和私钥口令（只读环境变量）。"""
    path = Path(ASKPASS_PATH).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "#!/bin/sh\n"
        'case "$1" in\n'
        '  *assphrase*) printf "%s\\n" "$LANDUI_SSH_PASSPHRASE" ;;\n'
        '  *) printf "%s\\n" "$LANDUI_SSH_PASSWORD" ;;\n'
        "esac\n"
    )
    if not path.exists() or path.read_text("utf-8") != body:
        path.write_text(body, "utf-8")
    try:
        path.chmod(stat.S_IRWXU)  # 0700
    except OSError:
        pass
    return path


def has_sshpass() -> bool:
    return shutil.which("sshpass") is not None


def _ssh_supports_askpass() -> bool:
    """SSH_ASKPASS_REQUIRE 需要 OpenSSH >= 8.4。"""
    try:
        out = subprocess.run(
            ["ssh", "-V"], check=False, capture_output=True, text=True, timeout=5
        ).stderr
    except (OSError, subprocess.SubprocessError):
        return False
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", out)
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2))) >= (8, 4)


def ssh_env(target: SshTarget) -> dict[str, str]:
    """给终端进程准备环境变量（凭据只存在环境里，不写文件）。"""
    env = dict(os.environ)
    need_askpass = bool(target.password or target.key_passphrase)
    if need_askpass:
        env["LANDUI_SSH_PASSWORD"] = target.password
        env["LANDUI_SSH_PASSPHRASE"] = target.key_passphrase
        env["SSH_ASKPASS"] = str(write_askpass())
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env.setdefault("DISPLAY", os.environ.get("DISPLAY") or ":0")
    else:
        env.pop("LANDUI_SSH_PASSWORD", None)
        env.pop("LANDUI_SSH_PASSPHRASE", None)
    return env


def build_ssh_command(
    target: SshTarget, *, strict_host_key: bool = False
) -> list[str]:
    """生成 ssh 参数列表。"""
    args = ["ssh", "-p", str(target.port)]
    if not strict_host_key:
        args += ["-o", "StrictHostKeyChecking=accept-new"]
    args += ["-o", "ConnectTimeout=12", "-o", "NumberOfPasswordPrompts=1"]
    if target.key_path:
        key = str(Path(target.key_path).expanduser())
        args += ["-i", key, "-o", "IdentitiesOnly=yes"]
    args.append(target.address)
    return args


def _use_sshpass(target: SshTarget) -> bool:
    """老版本 OpenSSH 且只配了密码时，退回 sshpass。"""
    return (
        bool(target.password)
        and not target.key_path
        and not _ssh_supports_askpass()
        and has_sshpass()
    )


def _clean_stderr(text: str) -> str:
    lines = [
        line for line in text.splitlines()
        if "post-quantum" not in line and not line.startswith("** ")
    ]
    return "\n".join(lines).strip()


def test_connection(target: SshTarget, timeout: float = 25.0) -> tuple[bool, str]:
    """后台跑一次非交互登录，确认端口/密码/密钥是否可用。"""
    args = build_ssh_command(target) + [
        "-o", "BatchMode=no",
        f"echo {OK_MARK} && uname -sr",
    ]
    if _use_sshpass(target):
        args = ["sshpass", "-p", target.password, *args]
    env = ssh_env(target)
    try:
        proc = subprocess.run(
            ["setsid", "-w", *args] if shutil.which("setsid") else args,
            check=False, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"连接超时（{timeout:.0f}s）"
    out = _clean_stderr((proc.stdout or "") + (proc.stderr or ""))
    if proc.returncode == 0 and OK_MARK in out:
        return True, out.replace(OK_MARK, "").strip()
    return False, out[-500:] or f"ssh 退出码 {proc.returncode}"


# --------------------------------------------------------------------- 打开方式
def detect_terminal() -> tuple[str, list[str]] | None:
    for name, extra in _TERMINALS:
        path = shutil.which(name)
        if path:
            return path, extra
    return None


@dataclass(frozen=True)
class Launcher:
    id: str
    label: str
    kind: str          # terminal / tabby / windows / custom
    executable: str = ""
    args: tuple[str, ...] = ()


LAUNCHERS: list[Launcher] = [
    Launcher("auto", "自动探测系统终端", "auto"),
    Launcher("tabby", "Tabby", "tabby", "tabby"),
    Launcher("x-terminal-emulator", "系统默认终端 (x-terminal-emulator)", "terminal",
             "x-terminal-emulator", ("-e",)),
    Launcher("gnome-terminal", "GNOME Terminal", "terminal", "gnome-terminal", ("--",)),
    Launcher("konsole", "Konsole", "terminal", "konsole", ("-e",)),
    Launcher("xfce4-terminal", "Xfce Terminal", "terminal", "xfce4-terminal", ("-x",)),
    Launcher("mate-terminal", "MATE Terminal", "terminal", "mate-terminal", ("-x",)),
    Launcher("tilix", "Tilix", "terminal", "tilix", ("-e",)),
    Launcher("kitty", "kitty", "terminal", "kitty", ("-e",)),
    Launcher("alacritty", "Alacritty", "terminal", "alacritty", ("-e",)),
    Launcher("wezterm", "WezTerm", "terminal", "wezterm", ("start", "--")),
    Launcher("foot", "foot", "terminal", "foot", ("-e",)),
    Launcher("xterm", "xterm", "terminal", "xterm", ("-e",)),
    Launcher("powershell", "PowerShell（Windows）", "windows", "powershell.exe"),
    Launcher("pwsh", "PowerShell 7（pwsh）", "windows", "pwsh"),
    Launcher("wt", "Windows Terminal（wt.exe）", "windows", "wt.exe"),
    Launcher("cmd", "命令提示符（Windows）", "windows", "cmd.exe"),
    Launcher("custom", "自定义命令模板", "custom"),
]

LAUNCHER_MAP = {l.id: l for l in LAUNCHERS}


def launcher_available(launcher_id: str) -> bool:
    spec = LAUNCHER_MAP.get(launcher_id)
    if spec is None or spec.kind in ("auto", "custom"):
        return True
    return shutil.which(spec.executable) is not None


def _shell_cmd(target: SshTarget, keep_open: bool) -> str:
    if _use_sshpass(target):
        args = ["sshpass", "-p", target.password, *build_ssh_command(target)]
    else:
        args = build_ssh_command(target)
    cmd = " ".join(shlex.quote(a) for a in args)
    if keep_open:
        cmd += "; echo; echo '[会话已结束] 按回车关闭窗口'; read -r _"
    return cmd


def build_launcher_argv(launcher_id: str, target: SshTarget, *, keep_open: bool = True,
                        custom: str = "") -> list[str]:
    """按选择的打开方式拼出完整的进程参数。"""
    shell_cmd = _shell_cmd(target, keep_open)
    spec = LAUNCHER_MAP.get(launcher_id)

    if launcher_id == "custom" or (spec is None):
        template = custom or os.environ.get("LANDUI_SSH_LAUNCHER", "")
        if not template:
            raise ValueError(
                "自定义打开方式为空。示例：x-terminal-emulator -e bash -lc {cmd}"
            )
        fields = {
            "cmd": shell_cmd,
            "address": target.address,
            "user": target.user,
            "host": target.host,
            "port": str(target.port),
            "key": str(Path(target.key_path).expanduser()) if target.key_path else "",
        }
        # 先切分模板再替换：{cmd} 单独作为一个 argv 元素，
        # 这样 "bash -lc {cmd}" 里的 -lc 才能拿到完整命令。
        argv = []
        for token in shlex.split(template):
            for key, value in fields.items():
                token = token.replace("{" + key + "}", value)
            argv.append(token)
        return argv

    if spec and spec.kind == "auto":
        detected = detect_terminal()
        if detected is None:
            raise RuntimeError("没找到可用的终端，请在设置里选一个打开方式")
        exe, extra = detected
        return [exe, *extra, "bash", "-lc", shell_cmd]

    if spec is None:
        raise ValueError(f"未知的打开方式：{launcher_id}")
    if not launcher_available(launcher_id) and spec.kind != "custom":
        raise RuntimeError(
            f"找不到可执行文件 {spec.executable}，请安装或在设置里换一种打开方式"
        )

    if spec.kind == "tabby":
        # tabby run <命令>：在 Tabby 里开新标签并执行
        return [spec.executable, "run", "bash", "-lc", shell_cmd]

    if spec.kind == "windows":
        exe = shutil.which(spec.executable) or spec.executable
        if spec.id == "wt":
            return [exe, "new-tab", "powershell.exe", "-NoExit", "-Command", shell_cmd]
        if spec.id == "cmd":
            return [path_or(exe), "/k", shell_cmd]
        # powershell / pwsh
        return [exe, "-NoExit", "-Command", shell_cmd]

    # 普通终端
    exe = shutil.which(spec.executable) or spec.executable
    return [exe, *spec.args, "bash", "-lc", shell_cmd]


def path_or(exe: str) -> str:
    return shutil.which(exe) or exe


def launch_ssh(
    target: SshTarget, launcher: str = "auto", *, custom: str = "", keep_open: bool = True
) -> str:
    """在选定的终端里连上服务器，返回实际执行的 shell 命令（便于展示/复制）。"""
    argv = build_launcher_argv(launcher, target, keep_open=keep_open, custom=custom)
    proc = subprocess.Popen(
        argv,
        env=ssh_env(target),
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 有些客户端会立刻崩（例如 Tabby 在某些 Wayland 环境下），
    # 稍等一下看它有没有秒退，好给出人话提示而不是静默失败。
    try:
        code = proc.wait(timeout=1.5)
    except subprocess.TimeoutExpired:
        code = None
    if code not in (None, 0):
        raise RuntimeError(
            f"打开方式「{launcher}」启动失败（退出码 {code}）。"
            "请在「设置 → 打开方式」里换一个终端，或检查该客户端是否正常。"
        )
    return argv[-1] if argv else ""
