"""云防火墙：安全组（推荐）+ 单机 ACL 硬防。

两套体系：

* **安全组** ``/user/firewall/*`` —— 按组管理，可绑定多台实例，规则分入/出方向。
  日常「开个端口」用这个。
* **单机 ACL 硬防** ``/user/cloud/acl*`` —— 绑定到单个实例、按权重排序的硬防策略，
  多数账号是空的。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from landui_sdk.models import AclRule, FirewallRule, SecurityGroup
from landui_sdk.parsers import strip_tags

IN, OUT = "Inbound", "Outbound"


class FirewallAPI:
    """安全组 / 单机 ACL。"""

    def __init__(self, client):
        self.c = client

    # -------------------------------------------------------------- 安全组
    def list_groups(self) -> list[SecurityGroup]:
        """安全组列表。"""
        payload = self.c.api("GET", "/user/firewall/safegroups.html")
        rows = payload.get("data") or [] if isinstance(payload, dict) else []
        groups: list[SecurityGroup] = []
        for r in rows:
            if not isinstance(r, list) or len(r) < 6:
                continue
            groups.append(
                SecurityGroup(
                    id=int(r[0]),
                    name=strip_tags(str(r[1])),
                    vps_count=int(r[2] or 0),
                    description=strip_tags(str(r[3])),
                    rule_count=int(r[4] or 0),
                    created_at=strip_tags(str(r[5])),
                )
            )
        return groups

    def create_group(self, name: str, description: str = "") -> None:
        self.c.api(
            "POST",
            "/user/firewall/add.html",
            data={"name": name, "desc": description},
            referer=self.c.base_url + "/user/firewall.html",
        )

    def update_group(self, group_id: int, name: str, description: str = "") -> None:
        self.c.api(
            "POST",
            f"/user/firewall/edit.html?id={group_id}",
            data={"name": name, "desc": description},
        )

    def delete_group(self, group_id: int) -> None:
        """删除安全组（会同时清空组内规则并解除实例绑定）。"""
        self.c.api("POST", "/user/firewall/destroy", data={"id": group_id})

    def bind_instances(self, group_id: int, instances: Sequence[str]) -> None:
        """把实例加入安全组。

        ``instances`` 传实例**名称**（如 ``demo-server``），网页端也是这么提交的。
        """
        payload = {"groupId": group_id, "ids[]": list(instances)}
        self.c.api("POST", "/user/firewall/groupVpsAdd", data=payload)

    def group_instances(self, group_id: int) -> list[dict[str, Any]]:
        """组内实例及其勾选状态。"""
        payload = self.c.api(
            "POST",
            "/user/firewall/tableListCloud",
            data={"groupId": group_id, "type": "s_ip", "keywords": ""},
        )
        return payload.get("info") or [] if isinstance(payload, dict) else []

    # -------------------------------------------------------------- 规则
    def list_rules(self, group_id: int, direction: str = IN) -> list[FirewallRule]:
        """列出规则。direction = Inbound / Outbound。"""
        payload = self.c.api(
            "GET",
            f"/user/firewall/grouprulestablelist.html?id={group_id}&direction={direction}",
        )
        rows = payload.get("data") or [] if isinstance(payload, dict) else []
        rules: list[FirewallRule] = []
        for r in rows:
            if not isinstance(r, list) or len(r) < 9:
                continue
            rules.append(
                FirewallRule(
                    id=int(r[1]),
                    direction=direction,
                    action=strip_tags(str(r[2])),
                    protocol=strip_tags(str(r[3])),
                    port=strip_tags(str(r[4])),
                    ip=strip_tags(str(r[5])),
                    weight=int(r[6] or 0),
                    description=strip_tags(str(r[7])),
                    created_at=strip_tags(str(r[8])),
                )
            )
        return rules

    def add_rule(
        self,
        group_id: int,
        *,
        port: str,
        protocol: str = "TCP",
        action: str = "Allow",
        ip: str = "0.0.0.0/0",
        direction: str = IN,
        weight: int = 100,
        description: str = "",
    ) -> None:
        """添加一条规则。

        :param port: ``22`` 或 ``8000-8100``
        :param protocol: TCP / UDP / ICMP / ANY
        :param action: Allow / Deny
        :param ip: 授权 IP，默认全网
        :param weight: 优先级，数字大的先执行
        """
        form: dict[str, Any] = {
            "id": group_id,
            "direction": direction,
            "weight": weight,
            "protocolType": 2 if protocol.upper() in ("TCP", "UDP") else 1,
            "protocol": protocol.upper(),
            "protocolV": protocol.upper(),
            "action": action,
            "port": port,
            "ip": ip,
            "desc": description,
        }
        if direction == IN:
            form.update(remote_ip=ip, local_port=port)
        else:
            form.update(local_ip=ip, remote_port=port)
        self.c.api(
            "POST",
            "/user/firewall/rulesAdd",
            data=form,
            referer=f"{self.c.base_url}/user/firewall/rulesin.html?id={group_id}",
        )

    def add_rules_batch(self, group_id: int, rules: Iterable[dict[str, Any]]) -> None:
        """批量添加（网页「快速添加」）。

        每个元素至少含 ``port``，可选 ``protocol`` / ``action`` / ``ip`` / ``desc`` /
        ``weight`` / ``direction``。
        """
        data: dict[str, Any] = {"id": group_id}
        for i, rule in enumerate(rules):
            direction = rule.get("direction", IN)
            port = str(rule.get("port", ""))
            protocol = str(rule.get("protocol", "TCP")).upper()
            ip = str(rule.get("ip", "0.0.0.0/0"))
            item = {
                "id": group_id,
                "direction": direction,
                "weight": rule.get("weight", 100),
                "protocol": protocol,
                "action": rule.get("action", "Allow"),
                "port": port,
                "ip": ip,
                "desc": rule.get("desc", ""),
            }
            if direction == IN:
                item.update(local_port=port, remote_ip=ip)
            else:
                item.update(local_ip=ip, remote_port=port)
            for key, value in item.items():
                data[f"rules[{i}][{key}]"] = value
        self.c.api("POST", "/user/firewall/rulesAddBatch", data=data)

    def update_rule(self, group_id: int, rule_id: int, **changes: Any) -> None:
        """修改规则，字段同 :meth:`add_rule`（必须带 ``port`` / ``direction``）。"""
        direction = changes.get("direction", IN)
        port = str(changes.get("port", ""))
        ip = str(changes.get("ip", "0.0.0.0/0"))
        protocol = str(changes.get("protocol", "TCP")).upper()
        form: dict[str, Any] = {
            "id": group_id,
            "direction": direction,
            "weight": changes.get("weight", 100),
            "protocolType": 2 if protocol in ("TCP", "UDP") else 1,
            "protocol": protocol,
            "protocolV": protocol,
            "action": changes.get("action", "Allow"),
            "port": port,
            "ip": ip,
            "desc": changes.get("description", ""),
            "ruleId": rule_id,
        }
        if direction == IN:
            form.update(remote_ip=ip, local_port=port)
        else:
            form.update(local_ip=ip, remote_port=port)
        self.c.api("POST", "/user/firewall/rulesEdit", data=form)

    def delete_rules(self, group_id: int, rule_ids: Sequence[int]) -> None:
        self.c.api(
            "POST",
            "/user/firewall/rulesRemove",
            data={"id": group_id, "ruleIds[]": [int(r) for r in rule_ids]},
        )

    # ---------------------------------------------------------- 单机 ACL
    def list_acl(self, server_id: int, cloud_name: str) -> list[AclRule]:
        """单机 ACL 硬防策略列表。"""
        payload = self.c.api(
            "GET",
            "/user/cloud/getaclList",
            data={"id": server_id, "cloudname": cloud_name, "type": "vps"},
            referer=f"{self.c.base_url}/user/cloud/acl.html?type=vps&cn={cloud_name}&id={server_id}",
        )
        rows = payload.get("data") or [] if isinstance(payload, dict) else []
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            out.append(
                AclRule(
                    id=int(r.get("id") or 0),
                    weight=int(r.get("weight") or 0),
                    direction=r.get("direction") or "",
                    action=r.get("action") or "",
                    protocol=r.get("protocol") or "",
                    remote_ip=r.get("remote_ip") or "",
                    remote_port=str(r.get("remote_port") or ""),
                    local_ip=r.get("local_ip") or "",
                    local_port=str(r.get("local_port") or ""),
                    raw=r,
                )
            )
        return out

    def add_acl(
        self,
        server_id: int,
        cloud_name: str,
        *,
        weight: int,
        direction: str = IN,
        action: str = "Allow",
        protocol: str = "TCP",
        remote_ip: str = "",
        remote_port: str = "",
        local_ip: str = "",
        local_port: str = "",
    ) -> None:
        """新增单机 ACL 策略。``weight`` 不能与已有策略重复。"""
        self.c.api(
            "POST",
            f"/user/cloud/acladd?cn={cloud_name}&id={server_id}",
            data={
                "weight": weight,
                "direction": direction,
                "action": action,
                "protocol": protocol.upper(),
                "protocol_other": "",
                "stateful": 1,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_ip": local_ip,
                "local_port": local_port,
                "adapter": "",
            },
        )

    def delete_acl(self, acl_id: int) -> None:
        self.c.api("POST", f"/user/cloud/acldel.html?id={acl_id}")

    def clear_acl(self, server_id: int, cloud_name: str) -> None:
        """清空该实例所有 ACL 策略。"""
        self.c.api("POST", f"/user/cloud/aclcls.html?cn={cloud_name}&id={server_id}")


# ----------------------------------------------------------------- 规则匹配
# 给「这个端口到底通不通」用的纯函数，UI 和脚本都能复用。

_ANY_PORT = ("", "全部", "ANY", "ALL", "1-65535")


def parse_port_spec(spec: str) -> list[tuple[int, int]]:
    """把 ``22`` / ``8000-8100`` / ``22,80,443`` 解析成区间列表。

    非法片段会被忽略，方便直接吃网页上人工填的脏数据。
    """
    out: list[tuple[int, int]] = []
    for part in str(spec or "").replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                continue
            if a > b:
                a, b = b, a
            out.append((a, b))
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            out.append((p, p))
    return out


def port_in_spec(spec: str, port: int) -> bool:
    text = str(spec or "").strip()
    if text.upper() in _ANY_PORT or text == "":
        return True
    for lo, hi in parse_port_spec(text):
        if lo <= port <= hi:
            return True
    return False


def protocol_matches(rule_protocol: str, protocol: str) -> bool:
    rp = (rule_protocol or "").strip().upper()
    if rp in ("", "全部", "ANY", "ALL"):
        return True
    return rp == protocol.strip().upper()


def effective_rule(
    rules: Sequence[FirewallRule], port: int, protocol: str = "TCP"
) -> FirewallRule | None:
    """按优先级（weight 从大到小）找第一条命中该端口的规则。"""
    for rule in sorted(rules, key=lambda r: r.weight, reverse=True):
        if protocol_matches(rule.protocol, protocol) and port_in_spec(rule.port, port):
            return rule
    return None


@dataclass
class RuleIssue:
    """规则体检结果。level: info / warn / danger"""

    level: str
    message: str
    rule_ids: list[int] = field(default_factory=list)


def _spec_ranges(spec: str) -> list[tuple[int, int]]:
    text = str(spec or "").strip()
    if text.upper() in _ANY_PORT or text == "":
        return [(1, 65535)]
    return parse_port_spec(text) or [(1, 65535)]


def spec_covers(outer: str, inner: str) -> bool:
    """outer 的端口范围是否完全包含 inner。"""
    o = _spec_ranges(outer)
    for lo, hi in _spec_ranges(inner):
        if not any(a <= lo and hi <= b for a, b in o):
            return False
    return True


def _ip_is_any(ip: str) -> bool:
    return str(ip or "").strip() in ("", "0.0.0.0/0", "::/0", "全部")


def suggest_weight(rules: Sequence[FirewallRule]) -> int:
    """新规则默认权重：插到当前最前面。"""
    top = max((r.weight for r in rules), default=0)
    return min(max(top + 10, 10), 65535)


def analyze_rules(
    rules: Sequence[FirewallRule], *, broad_allow: bool = True
) -> list[RuleIssue]:
    """规则体检：重复、冲突、被遮蔽、过度放行。

    只做保守判断（端口区间用包含关系，IP 只认完全相同或 0.0.0.0/0），
    宁可少报也不误导。
    """
    issues: list[RuleIssue] = []
    ordered = sorted(rules, key=lambda r: r.weight, reverse=True)

    # 1) 完全重复
    seen: dict[tuple[str, str, str, str], list[int]] = {}
    for r in rules:
        key = (
            r.action,
            (r.protocol or "").upper(),
            ",".join(f"{a}-{b}" for a, b in _spec_ranges(r.port)),
            (r.ip or "").strip(),
        )
        seen.setdefault(key, []).append(r.id)
    for ids in seen.values():
        if len(ids) > 1:
            issues.append(RuleIssue("warn", f"有 {len(ids)} 条完全重复的规则（ID {ids}）", ids))

    # 2) 对全网开放全部端口（出方向默认全放行很常见，调用方可关掉）
    for r in rules if broad_allow else []:
        if (r.protocol or "").upper() == "ICMP":
            continue  # ICMP 没有端口概念
        if r.is_allow and _ip_is_any(r.ip) and spec_covers(r.port, "1-65535"):
            issues.append(
                RuleIssue("danger", f"规则 #{r.id} 对 0.0.0.0/0 放行了全部端口，安全风险高", [r.id])
            )

    # 3) 被更高优先级的规则完全覆盖
    for i, low in enumerate(ordered):
        for high in ordered[:i]:
            if high.id == low.id or high.weight <= low.weight:
                continue
            ip_ok = _ip_is_any(high.ip) or (high.ip or "").strip() == (low.ip or "").strip()
            proto_ok = (high.protocol or "").upper() in ("", "全部", "ANY") or (
                (high.protocol or "").upper() == (low.protocol or "").upper()
            )
            if ip_ok and proto_ok and spec_covers(high.port, low.port):
                if high.action == low.action:
                    issues.append(
                        RuleIssue(
                            "info",
                            f"规则 #{low.id} 被 #{high.id} 完全覆盖，属于多余规则",
                            [low.id, high.id],
                        )
                    )
                else:
                    issues.append(
                        RuleIssue(
                            "warn",
                            f"规则 #{low.id}（{low.action}）永远匹配不到："
                            f"先被 #{high.id}（{high.action}）拦下",
                            [low.id, high.id],
                        )
                    )
                break
    return issues


@dataclass
class PortSegment:
    """端口视图用的区间片段：某段端口最终落到了哪条规则上。"""

    start: int
    end: int
    action: str
    rule_id: int

    @property
    def is_allow(self) -> bool:
        return self.action in ("允许", "Allow")


def resolve_port_map(
    rules: Sequence[FirewallRule], protocol: str = "TCP"
) -> list[PortSegment]:
    """把规则「翻译」成 1-65535 的区间视图。

    按优先级取每条规则真正生效的那段端口，相邻同规则的区间会合并，
    用来画端口图 / 生成「开放范围」摘要。
    """
    relevant = [r for r in rules if protocol_matches(r.protocol, protocol)]
    if not relevant:
        return []

    bounds: set[int] = {1, 65536}
    for rule in relevant:
        for lo, hi in _spec_ranges(rule.port):
            bounds.add(max(lo, 1))
            bounds.add(min(hi + 1, 65536))
    points = sorted(bounds)

    segments: list[PortSegment] = []
    for i in range(len(points) - 1):
        start = points[i]
        end = points[i + 1] - 1
        if start > 65535:
            break
        hit = effective_rule(relevant, start, protocol)
        if hit is None:
            continue
        if segments and segments[-1].rule_id == hit.id and segments[-1].end + 1 == start:
            segments[-1].end = end
        else:
            segments.append(PortSegment(start, end, hit.action, hit.id))
    return segments


def summarize_segments(segments: Sequence[PortSegment], action: str = "允许") -> str:
    """把区间拼成人话：``21, 80, 443, 8000-8100``。"""
    want = action in ("允许", "Allow")
    parts = [
        f"{s.start}" if s.start == s.end else f"{s.start}-{s.end}"
        for s in segments if s.is_allow == want
    ]
    return ", ".join(parts)


def renumber_weights(
    ordered_rules: Sequence[FirewallRule], *, step: int = 10, top: int | None = None
) -> dict[int, int]:
    """按给定顺序重排优先级，返回 ``{规则ID: 新权重}``。

    从 ``top`` 开始每条减 ``step``；``top`` 缺省时取 ``条数*step``（夹在 1-65535）。
    不会修改原对象，方便先算完再逐个提交。
    """
    count = len(ordered_rules)
    if count == 0:
        return {}
    if top is None:
        top = count * step
    top = max(1, min(int(top), 65535))
    return {
        rule.id: max(1, top - index * step)
        for index, rule in enumerate(ordered_rules)
    }
