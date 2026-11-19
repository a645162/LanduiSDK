"""命令行入口：``uv run landui <命令>``。

    landui login --from-chrome
    landui ls
    landui info 10001
    landui ssh 10001
    landui fw rules 5192
    landui fw open 5192 8080 --desc "临时测试"
"""

from __future__ import annotations

import argparse
import getpass
import subprocess
import sys
import tempfile
from pathlib import Path

from landui_sdk.client import DEFAULT_AUTH_FILE, LanduiClient
from landui_sdk.config import AUTH_PASSWORD, AppConfig, SshAccount
from landui_sdk.credentials import Credentials, CredentialStore
from landui_sdk.errors import CaptchaRequired, LanduiError
from landui_sdk.ssh import SshTarget, launch_ssh


def _client(args: argparse.Namespace) -> LanduiClient:
    client = LanduiClient.from_cookies_file(args.auth)
    return client


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("-" * len(line))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


# ----------------------------------------------------------------- 命令实现
def _solve_captcha(captcha: CaptchaRequired) -> str:
    """把验证码图片落到临时文件并尝试打开，然后让用户手输。"""
    path = Path(tempfile.gettempdir()) / "landui-captcha.png"
    try:
        path.write_bytes(captcha.image)
    except OSError:
        pass
    for opener in ("xdg-open", "open"):
        try:
            subprocess.Popen(
                [opener, str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            break
        except OSError:
            continue
    print(f"需要图形验证码，图片：{path}")
    return input("验证码（4 位字符）: ").strip()


def _login_with_password(client: LanduiClient, username: str, password: str) -> None:
    """处理「可能第一次就要验证码」的登录。密码只在内存里传递。"""
    try:
        client.login(username, password)
        return
    except CaptchaRequired as cap:
        answer = _solve_captcha(cap)
        client.login(username, password, answer, cap.captcha_id, precheck=False)


def cmd_login(args: argparse.Namespace) -> int:
    client = LanduiClient()

    if args.from_chrome:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from import_cookies import fetch_cookies  # type: ignore

        cookies = [c for c in fetch_cookies(args.port) if "landui" in c["domain"]]
        client.set_cookies({c["name"]: c["value"] for c in cookies})
    elif args.cookie_file:
        client.load_auth(args.cookie_file)
    elif args.credentials:
        store = CredentialStore()
        creds = store.load()
        if creds is None or args.reprompt:
            username = input("账号: ").strip()
            # getpass 不回显，也不会进 shell 历史
            password = getpass.getpass("密码（不回显，程序自己用）: ")
        else:
            username, password = creds.username, creds.password
        try:
            _login_with_password(client, username, password)
        except LanduiError as exc:
            print(f"登录失败：{exc}", file=sys.stderr)
            return 1
        if args.save_credentials:
            path = store.save(Credentials(username, password))
            print(f"账号密码已保存 -> {path}（权限 0600）")
    else:
        print("用 --from-chrome / --cookie-file / --credentials 指定登录方式")
        return 2

    if not client.is_logged_in():
        print("登录态无效：先在浏览器登录 www.landui.com/user/")
        return 1
    path = client.save_auth(args.auth)
    print(f"已保存登录态 -> {path}")
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    servers = _client(args).cloud.all_servers()
    _print_table(
        ["ID", "名称", "状态", "IP", "规格", "系统", "到期"],
        [[s.id, s.name, s.status, s.ip, s.cpu_mem, s.os, s.expire_at] for s in servers],
    )
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    d = _client(args).cloud.get_server(args.id)
    print(f"名称     {d.name}")
    print(f"状态     {d.status}")
    print(f"公网IP   {d.ip}")
    print(f"SSH      {d.ssh_command}")
    print(f"账号     {d.login_user}")
    print(f"端口     {d.ssh_port}")
    print(f"规格     {d.cpu_mem}  {d.bandwidth}")
    print(f"地域     {d.region}")
    print(f"开通     {d.created_at}")
    print(f"到期     {d.expire_at} ({d.expire_hint})")
    return 0


def cmd_pwd(args: argparse.Namespace) -> int:
    print(_client(args).cloud.get_ssh_password(args.id))
    return 0


def cmd_power(args: argparse.Namespace) -> int:
    cloud = _client(args).cloud
    if args.action == "on":
        print(cloud.power_on(args.id) or "已提交开机")
    elif args.action == "off":
        print(cloud.power_off(args.id) or "已提交关机")
    else:
        if args.code:
            print(cloud.restart(args.id, args.code) or "已提交重启")
        else:
            print(cloud.send_restart_code(args.id) or "验证码已发送")
            print("收到验证码后：landui restart <id> --code 123456")
    return 0


def cmd_ssh(args: argparse.Namespace) -> int:
    client = _client(args)
    cfg = AppConfig.load()
    detail = client.cloud.get_server(args.id)
    profile = cfg.get(args.id)

    if not profile.accounts:
        profile.upsert_account(
            SshAccount(
                user=detail.login_user or "root",
                port=detail.ssh_port or 22,
                auth_mode=AUTH_PASSWORD,
            )
        )
    account = profile.account(args.user)
    if account is None:
        account = SshAccount(user=args.user or detail.login_user or "root",
                             port=detail.ssh_port or 22)
        profile.upsert_account(account)

    if args.password:
        account.password = client.cloud.get_ssh_password(args.id)
        account.auth_mode = AUTH_PASSWORD
    if args.key:
        account.key_path = args.key
        account.auth_mode = "key"
    if args.port:
        account.port = args.port
    cfg.save()

    target = SshTarget(
        host=detail.ip,
        port=account.port,
        user=account.user,
        password=account.password,
        key_path=account.key_path,
        key_passphrase=account.key_passphrase,
    )
    launcher = args.launcher or cfg.ssh_launcher
    cmd = launch_ssh(target, launcher, custom=cfg.ssh_launcher_custom)
    print(f"[{launcher}] {cmd}")
    return 0


def cmd_accounts(args: argparse.Namespace) -> int:
    cfg = AppConfig.load()
    profile = cfg.get(args.id)
    if not profile.accounts:
        print(f"还没有配置账号。先跑：landui ssh {args.id} --password")
        return 1
    rows = []
    for acc in profile.accounts:
        rows.append([
            acc.user, acc.port, acc.auth_label, acc.label or "",
            "默认" if acc.user == profile.default_account else "",
        ])
    _print_table(["用户名", "端口", "认证", "备注", "默认"], rows)
    return 0


def cmd_fw(args: argparse.Namespace) -> int:
    fw = _client(args).firewall
    if args.fw_cmd == "groups":
        _print_table(
            ["ID", "名称", "规则数", "实例数", "描述"],
            [[g.id, g.name, g.rule_count, g.vps_count, g.description]
             for g in fw.list_groups()],
        )
    elif args.fw_cmd == "rules":
        direction = "Outbound" if args.direction == "out" else "Inbound"
        _print_table(
            ["ID", "行为", "协议", "端口", "授权IP", "优先级", "描述"],
            [[r.id, r.action, r.protocol, r.port or "全部", r.ip or "全部",
              r.weight, r.description]
             for r in fw.list_rules(args.group, direction)],
        )
    elif args.fw_cmd == "open":
        fw.add_rule(
            args.group,
            port=args.port,
            protocol=args.proto.upper(),
            action="Deny" if args.action == "deny" else "Allow",
            ip=args.ip,
            weight=args.weight,
            description=args.desc,
        )
        print("规则已添加")
    elif args.fw_cmd == "rm":
        fw.delete_rules(args.group, args.rule_ids)
        print("规则已删除")
    return 0


def cmd_acl(args: argparse.Namespace) -> int:
    client = _client(args)
    d = client.cloud.get_server(args.id)
    rules = client.firewall.list_acl(args.id, d.name)
    _print_table(
        ["ID", "权重", "方向", "行为", "协议", "远端", "本地"],
        [[r.id, r.weight, r.direction, r.action, r.protocol,
          f"{r.remote_ip}:{r.remote_port}", f"{r.local_ip}:{r.local_port}"] for r in rules],
    )
    return 0


# --------------------------------------------------------------------- 入口
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="landui",
        description="蓝队云命令行运维（非官方第三方实现，与蓝队云官方无关）",
    )
    ap.add_argument("--auth", default=DEFAULT_AUTH_FILE, help="登录态文件")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("login", help="登录 / 导入登录态")
    p.add_argument("--from-chrome", action="store_true", help="从调试端口的 Chrome 抓 Cookie")
    p.add_argument("--cookie-file", help="从 auth.json 导入")
    p.add_argument("--credentials", action="store_true", help="用账号密码登录")
    p.add_argument("--save-credentials", action="store_true",
                   help="登录成功后把账号密码存到本地（0600）")
    p.add_argument("--reprompt", action="store_true", help="忽略已存的账号密码，重新输入")
    p.add_argument("--port", type=int, default=9222)
    p.set_defaults(func=cmd_login)

    sub.add_parser("ls", help="服务器列表").set_defaults(func=cmd_ls)

    p = sub.add_parser("info", help="实例详情")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("pwd", help="读取登录密码")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_pwd)

    for action in ("on", "off", "restart"):
        p = sub.add_parser(action, help=f"{action} 实例")
        p.add_argument("id", type=int)
        p.add_argument("--code", help="重启验证码")
        p.set_defaults(func=cmd_power, action=action)

    p = sub.add_parser("ssh", help="拉起 SSH 终端")
    p.add_argument("id", type=int)
    p.add_argument("--user", help="指定登录用户（多账号时）")
    p.add_argument("--port", type=int, help="覆盖端口")
    p.add_argument("--password", action="store_true", help="读取并缓存云端密码")
    p.add_argument("--key", help="使用指定私钥（-i）")
    p.add_argument("--launcher", help="打开方式：auto/tabby/gnome-terminal/powershell…")
    p.set_defaults(func=cmd_ssh)

    p = sub.add_parser("accounts", help="查看某台服务器已保存的 SSH 账号")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_accounts)

    p = sub.add_parser("acl", help="单机 ACL 策略")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_acl)

    fw = sub.add_parser("fw", help="安全组防火墙")
    fwsub = fw.add_subparsers(dest="fw_cmd", required=True)

    fwsub.add_parser("groups", help="安全组列表").set_defaults(func=cmd_fw)

    p = fwsub.add_parser("rules", help="规则列表")
    p.add_argument("group", type=int)
    p.add_argument("--direction", choices=["in", "out"], default="in")
    p.set_defaults(func=cmd_fw)

    p = fwsub.add_parser("open", help="添加放行规则")
    p.add_argument("group", type=int)
    p.add_argument("port")
    p.add_argument("--proto", default="TCP")
    p.add_argument("--ip", default="0.0.0.0/0")
    p.add_argument("--action", choices=["allow", "deny"], default="allow")
    p.add_argument("--weight", type=int, default=200)
    p.add_argument("--desc", default="")
    p.set_defaults(func=cmd_fw)

    p = fwsub.add_parser("rm", help="删除规则")
    p.add_argument("group", type=int)
    p.add_argument("rule_ids", type=int, nargs="+")
    p.set_defaults(func=cmd_fw)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except LanduiError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
