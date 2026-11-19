#!/usr/bin/env python3
"""生成 README 用的界面截图（全部使用假数据，不含真实服务器信息）。

    QT_QPA_PLATFORM=offscreen uv run --extra gui python tools/screenshots.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))

import app as gui
import firewall_window as fw
import ssh_dialog

from landui_sdk.config import AppConfig, SshAccount
from landui_sdk.models import (
    FirewallRule,
    SecurityGroup,
    Server,
    ServerDetail,
)

OUT = ROOT / "docs"

DEMO_SERVERS = [
    Server(
        id=10001, name="demo-server", ip="203.0.113.10", status="运行中",
        cpu_mem="2核 4G", bandwidth="10Mbps", os="Rocky-linux 9.5",
        expire_at="2027-12-01 23:34:07", expire_hint="1年后过期", region="西南1区",
    ),
    Server(
        id=10002, name="web-02", ip="203.0.113.11", status="关机",
        cpu_mem="4核 8G", bandwidth="20Mbps", os="Ubuntu 24.04",
        expire_at="2026-12-20 10:00:00", expire_hint="1个月后过期", region="华东2区",
    ),
]

DEMO_RULES = [
    FirewallRule(id=90001, direction="Inbound", action="拒绝", protocol="全部",
                 port="", ip="", weight=10, description="默认拒绝"),
    FirewallRule(id=90002, direction="Inbound", action="允许", protocol="ICMP",
                 port="", ip="", weight=40, description="ping"),
    FirewallRule(id=90003, direction="Inbound", action="允许", protocol="TCP",
                 port="22", ip="203.0.113.0/24", weight=50, description="办公网 SSH"),
    FirewallRule(id=90004, direction="Inbound", action="允许", protocol="TCP",
                 port="80", ip="", weight=60, description="HTTP"),
    FirewallRule(id=90005, direction="Inbound", action="允许", protocol="TCP",
                 port="443", ip="", weight=70, description="HTTPS"),
    FirewallRule(id=90006, direction="Inbound", action="允许", protocol="TCP",
                 port="8000-8100", ip="0.0.0.0/0", weight=120, description="灰度端口"),
    FirewallRule(id=90007, direction="Inbound", action="允许", protocol="UDP",
                 port="11010-11013", ip="0.0.0.0/0", weight=160, description="组网"),
]

OUT_RULES = [
    FirewallRule(id=90101, direction="Outbound", action="允许", protocol="TCP",
                 port="1-65535", ip="0.0.0.0/0", weight=180, description="All"),
]


class FakeCloud:
    def all_servers(self):
        return DEMO_SERVERS

    def get_server(self, sid):
        base = DEMO_SERVERS[0]
        return ServerDetail(**{**base.__dict__, "login_user": "root", "ssh_port": 2222})


class FakeFirewall:
    def list_groups(self):
        return [
            SecurityGroup(id=5192, name="Default", vps_count=2,
                          description="示例默认规则", rule_count=16,
                          created_at="2025-12-01 23:34:48"),
            SecurityGroup(id=5200, name="Web", vps_count=1,
                          description="网站专用", rule_count=3,
                          created_at="2025-12-02 10:00:00"),
        ]

    def group_instances(self, gid):
        if gid == 5192:
            return [{"vpsname": "demo-server"}, {"vpsname": "web-02"}]
        return [{"vpsname": "web-03"}]

    def list_rules(self, gid, direction="Inbound"):
        return list(DEMO_RULES if direction == "Inbound" else OUT_RULES)

    def list_acl(self, *_a):
        return []

    # 截图不会触发写操作
    def add_rule(self, *a, **k): ...
    def update_rule(self, *a, **k): ...
    def delete_rules(self, *a): ...
    def create_group(self, *a): ...
    def update_group(self, *a): ...
    def delete_group(self, *a): ...
    def bind_instances(self, *a): ...
    def add_acl(self, *a, **k): ...
    def delete_acl(self, *a): ...


class FakeClient:
    cloud = FakeCloud()
    firewall = FakeFirewall()


def pump(app: QApplication, seconds: float = 1.5) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.03)


def main() -> None:
    app = QApplication(sys.argv)
    OUT.mkdir(exist_ok=True)
    client = FakeClient()

    # 主窗口
    main = gui.MainWindow(client)  # type: ignore[arg-type]
    main.resize(1180, 700)
    main.show()
    pump(app)
    main.tbl.selectRow(0)
    pump(app, 0.5)
    main.grab().save(str(OUT / "screenshot.png"))
    main.close()

    # 防火墙
    server = DEMO_SERVERS[0]
    fwin = fw.FirewallWindow(client, server)  # type: ignore[arg-type]
    fwin.resize(1320, 980)
    fwin.show()
    pump(app, 2.0)
    fwin.tables["Inbound"].selectRow(5)
    pump(app, 0.5)
    fwin.grab().save(str(OUT / "screenshot-firewall.png"))

    # 诊断页
    fwin.tabs.setCurrentIndex(3)
    fwin.ed_check_ports.setText("22,80,443,8080")
    fwin._check_ports()
    pump(app, 0.5)
    fwin.grab().save(str(OUT / "screenshot-diagnose.png"))
    fwin.close()

    # SSH 账号
    cfg = AppConfig()
    profile = cfg.get(10001)
    profile.upsert_account(SshAccount(user="root", port=2222, auth_mode="password",
                                      password="demo", label="运维"))
    profile.upsert_account(SshAccount(user="deploy", port=2222, auth_mode="key",
                                      key_path="~/.ssh/id_ed25519", label="部署"))
    profile.default_account = "root"
    dlg = ssh_dialog.SshAccountsDialog(server, cfg, None)
    dlg.resize(760, 420)
    dlg.show()
    pump(app, 0.5)
    dlg.grab().save(str(OUT / "screenshot-ssh-accounts.png"))
    dlg.close()

    print("screenshots written to", OUT)


if __name__ == "__main__":
    main()
