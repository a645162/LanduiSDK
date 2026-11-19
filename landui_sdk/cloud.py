"""云服务器相关接口（列表 / 详情 / 电源 / 密码 / 快照 / 日志）。"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from landui_sdk.errors import APIError
from landui_sdk.models import Server, ServerDetail, TablePage
from landui_sdk.parsers import cell_lines, parse_kv_page, parse_spec, strip_tags

if TYPE_CHECKING:
    from landui_sdk.client import LanduiClient

LIST_PATH = "/user/cloud/tablelist.html"
PAGE_PATH = "/user/cloud/manage.html"


class CloudAPI:
    """云服务器运维接口。"""

    def __init__(self, client: LanduiClient):
        self.c = client

    # ------------------------------------------------------------------ 列表
    def list_servers(self, page: int = 1, page_size: int = 50) -> TablePage:
        """分页拉取云服务器列表（第 1 页 = start 1）。"""
        start = (max(page, 1) - 1) * page_size + 1
        payload = self.c.api(
            "POST",
            LIST_PATH,
            data={
                "start": start,
                "length": page_size,
                "order[0][name]": "id",
                "order[0][dir]": "desc",
            },
            referer=self.c.base_url + "/user/cloud/index.html",
        )
        rows = payload.get("data") or [] if isinstance(payload, dict) else []
        servers = [self._parse_row(r) for r in rows if isinstance(r, list)]
        total = int(payload.get("recordsTotal") or len(servers)) if isinstance(payload, dict) else 0
        return TablePage(rows=servers, total=total, raw=payload if isinstance(payload, dict) else {})

    def all_servers(self, page_size: int = 100) -> list[Server]:
        """拉全量（自动翻页）。"""
        out: list[Server] = []
        page = 1
        while True:
            result = self.list_servers(page=page, page_size=page_size)
            out.extend(result.rows)
            if not result.rows or len(out) >= result.total:
                break
            page += 1
        return out

    @staticmethod
    def _parse_row(cells: list[str]) -> Server:
        def cell(i: int) -> str:
            return cells[i] if i < len(cells) else ""

        cell0 = cell(0)
        m = re.search(r'value="(\d+)"', cell0)
        sid = int(m.group(1)) if m else 0

        name_cell = cell(1)
        name = strip_tags(name_cell)
        remark = ""
        m = re.search(r"<em[^>]*class=[\"']?gray[^>]*>(.*?)</em>", name_cell, re.DOTALL)
        if m:
            remark = strip_tags(m.group(1))

        ip = ""
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", cell(4))
        if m:
            ip = m.group(1)

        status = strip_tags(cell(5))
        spec = parse_spec(cell(6))

        dates = cell_lines(cell(7))
        created = dates[0] if dates else ""
        expire = dates[1] if len(dates) > 1 else ""
        hint = dates[2] if len(dates) > 2 else ""

        group_cell = cell(8)
        group = strip_tags(
            re.search(r'<span class="selected-content">(.*?)</span>', group_cell, re.DOTALL).group(1)
            if re.search(r'<span class="selected-content">(.*?)</span>', group_cell, re.DOTALL)
            else group_cell
        )

        return Server(
            id=sid,
            name=name,
            ip=ip,
            region=strip_tags(cell(3)),
            status=status,
            cpu_mem=spec.get("规格", ""),
            bandwidth=spec.get("带宽", ""),
            disk=" / ".join(
                x for x in (spec.get("系统盘", ""), spec.get("硬盘", "")) if x
            ),
            os=spec.get("系统", ""),
            created_at=created,
            expire_at=expire,
            expire_hint=hint,
            auto_renew=strip_tags(cell(9)),
            group=group,
            remark=remark,
        )

    # ------------------------------------------------------------------ 详情
    def get_server(self, server_id: int) -> ServerDetail:
        """实例详情：含 **SSH 端口**、登录账号、到期时间等。"""
        page = self.c.html(f"{PAGE_PATH}?id={server_id}")
        kv = parse_kv_page(page)

        def dt(key: str) -> str:
            m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", kv.get(key, ""))
            return m.group(0) if m else kv.get(key, "")

        port_text = kv.get("登录端口", "")
        m = re.search(r"\d+", port_text)
        ssh_port = int(m.group()) if m else None

        disks = []
        for key in ("SSD系统盘", "SSD数据盘", "硬盘信息"):
            if kv.get(key):
                disks.append(f"{key}: {kv[key]}")

        detail = ServerDetail(
            id=int(server_id),
            name=kv.get("名称", ""),
            ip=kv.get("公网IP", ""),
            region=kv.get("地域", ""),
            login_user=kv.get("登录账号", ""),
            ssh_port=ssh_port,
            pay_type=kv.get("付费方式", ""),
            product_type=kv.get("产品类型", ""),
            created_at=dt("开通时间"),
            expire_at=dt("到期时间"),
            cpu_mem=kv.get("实例规格", ""),
            bandwidth=kv.get("公网带宽", ""),
            defense_peak=kv.get("防御峰值", ""),
            auto_renew=kv.get("自动续费", ""),
            expire_hint=kv.get("到期时间", "").replace(dt("到期时间"), "").strip(),
            disks=disks,
        )
        # 状态不在详情页文本里，单独查一次（很便宜）
        try:
            detail.status = self.status(server_id)
        except APIError:
            pass
        return detail

    # ------------------------------------------------------------------ 状态
    def status(self, server_id: int) -> str:
        """实例状态字符串：运行中 / 关机 / 关机中 / 开机中 …"""
        value = self.c.api("GET", f"/user/cloud/vpsstatus.html?id={server_id}")
        return str(value).strip()

    # ------------------------------------------------------------------ 密码
    def get_ssh_password(self, server_id: int) -> str:
        """读取实例登录密码（网页上「登录密码」小眼睛）。"""
        payload = self.c.api("POST", f"/user/cloud/getpassword.html?id={server_id}")
        info = payload.get("info") or {}
        return str(info.get("password") or "")

    def get_vnc_password(self, server_id: int) -> str:
        payload = self.c.api("POST", f"/user/cloud/getvncpass.html?id={server_id}")
        info = payload.get("info") or {}
        return str(info.get("password") or "")

    # ------------------------------------------------------------------ 电源
    def power_on(self, server_id: int) -> str:
        """开机（网页「启动」）。"""
        payload = self.c.api("POST", f"/user/cloud/startsave.html?id={server_id}")
        return str(payload.get("info") or "")

    def power_off(self, server_id: int) -> str:
        """关机（网页「关机」）。"""
        payload = self.c.api("POST", f"/user/cloud/serverstopsave.html?id={server_id}")
        return str(payload.get("info") or "")

    def send_restart_code(self, server_id: int, way: str = "mobile") -> str:
        """重启需要短信/邮箱验证码：先发码。way = mobile | email"""
        payload = self.c.api(
            "POST",
            f"/user/cloud/productSendCode?id={server_id}",
            data={"type": way, "text": "重启云服务器"},
            referer=f"{self.c.base_url}/user/cloud/serverrestart.html?id={server_id}",
        )
        return str(payload.get("info") or "")

    def restart(self, server_id: int, code: str, way: str = "mobile") -> str:
        """重启（网页「重启」）。**需要验证码**，先调 :meth:`send_restart_code`。"""
        payload = self.c.api(
            "POST",
            f"/user/cloud/serverrestartsave.html?id={server_id}",
            data={"verType": way, f"code[{way}]": code},
        )
        return str(payload.get("info") or "")

    # ---------------------------------------------- 批量（ids 走查询串）
    def _batch(self, action: str, ids: Iterable[int], data: dict | None = None) -> str:
        id_text = ",".join(str(i) for i in ids)
        payload = self.c.api(
            "POST", f"/user/cloud/batch{action}save.html?ids={id_text}", data=data or {}
        )
        return str(payload.get("info") or "")

    def batch_power_on(self, ids: Iterable[int]) -> str:
        return self._batch("start", ids)

    def batch_power_off(self, ids: Iterable[int]) -> str:
        return self._batch("stop", ids)

    def batch_restart(self, ids: Iterable[int], code: str, way: str = "mobile") -> str:
        return self._batch("restart", ids, {"verType": way, f"code[{way}]": code})

    # ------------------------------------------------------------------ 备注
    def set_remark(self, server_id: int, remark: str) -> None:
        self.c.api(
            "POST",
            f"/user/group/remark.html?id={server_id}&type=3",
            data={"ld_bz": remark, "id": server_id, "type": 3},
        )

    # ------------------------------------------------------------------ 其他
    def operation_log(self, server_id: int, page: int = 1, page_size: int = 20) -> TablePage:
        return self._datatable(
            f"/user/cloud/savelogtablelist.html?id={server_id}",
            page,
            page_size,
            f"/user/cloud/serverlog.html?id={server_id}",
        )

    def login_records(self, server_id: int) -> str:
        """登录日志页面（服务端渲染，返回原始 HTML）。"""
        return self.c.html(f"/user/cloud/loginrecords.html?id={server_id}")

    def snapshots(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self._datatable(
            "/user/snapshot/snapshotlist.html", page, page_size,
            "/user/snapshot/lists.html",
        )

    def monitoring(self, server_id: int, kind: int = 2, hours: int = 1) -> Any:
        """资源监控。kind: 1=网络 2=CPU 3=内存 4=磁盘。未装探针时返回空。"""
        return self.c.api(
            "POST",
            "/user/cloud/getchart",
            data={"id": server_id, "type": kind, "time": hours, "hostid": ""},
            referer=f"{self.c.base_url}/user/cloud/monitoring.html?id={server_id}",
        )

    def _datatable(self, path: str, page: int, page_size: int, referer: str) -> TablePage:
        start = (max(page, 1) - 1) * page_size + 1
        payload = self.c.api(
            "POST",
            path,
            data={
                "start": start,
                "length": page_size,
                "order[0][name]": "id",
                "order[0][dir]": "desc",
            },
            referer=self.c.base_url + referer,
        )
        if not isinstance(payload, dict):
            raise APIError(f"接口返回格式异常: {path}", payload)
        return TablePage(
            rows=payload.get("data") or [],
            total=int(payload.get("recordsTotal") or 0),
            raw=payload,
        )
