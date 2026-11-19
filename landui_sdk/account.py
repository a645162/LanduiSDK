"""账号下其它产品的只读列表（域名 / 虚拟主机 / 租用托管 / SSL / 回收站 / 告警规则）。

这些列表接口统一是 DataTables：POST ``start`` + ``length`` + ``order``，
返回 ``{data: [[...]]}``，这里只做原样透出，字段含义以网页为准。
"""

from __future__ import annotations

from typing import Any

from landui_sdk.models import TablePage


class AccountAPI:
    def __init__(self, client):
        self.c = client

    def table(
        self, path: str, page: int = 1, page_size: int = 20, *, referer: str | None = None
    ) -> TablePage:
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
            referer=referer,
        )
        if not isinstance(payload, dict):
            return TablePage(raw={"raw": payload})
        return TablePage(
            rows=payload.get("data") or [],
            total=int(payload.get("recordsTotal") or 0),
            raw=payload,
        )

    # ------------------------------------------------------------ 直接可用
    def domains(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self.table("/user/domain/tablelist.html", page, page_size)

    def virtual_hosts(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self.table("/user/host/tablelist.html", page, page_size)

    def dedicated_servers(self, page: int = 1, page_size: int = 20) -> TablePage:
        """租用 / 托管。"""
        return self.table("/user/idc/tablelist.html", page, page_size)

    def ssl_certificates(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self.table("/user/ssl/tablelist.html?expirday=", page, page_size)

    def recycled_servers(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self.table("/user/cloud/recoverylist.html", page, page_size)

    def alert_rules(self, page: int = 1, page_size: int = 20) -> TablePage:
        return self.table("/user/monitor_new/tablelistrule.html", page, page_size)

    def profile(self) -> dict[str, Any]:
        """账号概览页里的基础信息（余额、实名状态等以页面为准）。"""
        page = self.c.html("/user/")
        from landui_sdk.parsers import parse_kv_page

        return parse_kv_page(page)
