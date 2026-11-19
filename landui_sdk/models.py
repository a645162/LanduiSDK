"""数据模型（全部为纯 dataclass，便于 UI 层直接使用）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Server:
    """云服务器列表中的一行。"""

    id: int
    name: str
    ip: str = ""
    region: str = ""
    status: str = ""
    cpu_mem: str = ""
    bandwidth: str = ""
    disk: str = ""
    os: str = ""
    created_at: str = ""
    expire_at: str = ""
    expire_hint: str = ""
    auto_renew: str = ""
    group: str = ""
    remark: str = ""

    @property
    def is_running(self) -> bool:
        return self.status == "运行中"


@dataclass
class ServerDetail(Server):
    """实例详情（/user/cloud/manage.html 解析结果）。"""

    login_user: str = ""
    ssh_port: int | None = None
    pay_type: str = ""
    product_type: str = ""
    defense_peak: str = ""
    disks: list[str] = field(default_factory=list)
    # 密码需要单独调用 get_ssh_password() / get_vnc_password() 才会返回
    ssh_password: str | None = None
    vnc_password: str | None = None

    @property
    def ssh_target(self) -> str:
        return f"{self.login_user}@{self.ip}"

    @property
    def ssh_command(self) -> str:
        port = self.ssh_port or 22
        return f"ssh -p {port} {self.login_user or 'root'}@{self.ip}"


@dataclass
class SecurityGroup:
    """安全组（云防火墙）。"""

    id: int
    name: str
    vps_count: int = 0
    description: str = ""
    rule_count: int = 0
    created_at: str = ""


@dataclass
class FirewallRule:
    """安全组规则。direction 为 Inbound / Outbound。"""

    id: int
    direction: str
    action: str = ""
    protocol: str = ""
    port: str = ""
    ip: str = ""
    weight: int = 0
    description: str = ""
    created_at: str = ""

    @property
    def is_allow(self) -> bool:
        return self.action in ("允许", "Allow")


@dataclass
class AclRule:
    """单机 ACL 硬防策略（/user/cloud/getaclList）。"""

    id: int
    weight: int = 0
    direction: str = ""
    action: str = ""
    protocol: str = ""
    remote_ip: str = ""
    remote_port: str = ""
    local_ip: str = ""
    local_port: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TablePage:
    """通用 datatable / layui table 返回。"""

    rows: list[Any] = field(default_factory=list)
    total: int = 0
    raw: dict[str, Any] = field(default_factory=dict)
