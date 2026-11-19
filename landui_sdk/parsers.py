"""HTML 片段解析工具。

蓝队云后台是服务端渲染的 PHP + DataTables，列表数据以「HTML 片段数组」返回，
所以这里用最小正则把需要的字段抠出来，不引入 bs4 依赖。
"""

from __future__ import annotations

import html as _html
import re

_TAG_RE = re.compile(r"<[^>]+>")
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_WS_RE = re.compile(r"[ \t\r\f\v]+")


def strip_tags(text: str) -> str:
    """去掉标签并还原实体，<br> 变单空格。"""
    text = _BR_RE.sub(" ", text or "")
    text = _TAG_RE.sub("", text)
    return _WS_RE.sub(" ", _html.unescape(text)).strip()


def cell_lines(cell: str) -> list[str]:
    """按 <br> 切分一个单元格，返回去标签后的非空行。"""
    parts = _BR_RE.split(_html.unescape(cell or ""))
    out = []
    for p in parts:
        s = strip_tags(p)
        if s:
            out.append(s)
    return out


def first_match(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text or "", re.DOTALL)
    return _html.unescape(m.group(1)).strip() if m else default


def parse_kv_page(html: str) -> dict[str, str]:
    """解析详情页 ``<span class="name">标签</span><p>值</p>`` 结构。

    先去掉 HTML 注释：云控制台的详情页里大量使用 ``<!-- -->`` 注释掉未启用字段，
    不剔除会让正则跨块匹配，把标签和值配错。
    """
    clean = re.sub(r"<!--.*?-->", "", html or "", flags=re.DOTALL)
    pairs = re.findall(
        r'<span class="name"[^>]*>\s*([^<]{0,40}?)\s*</span>\s*<p[^>]*>(.*?)</p>',
        clean,
        re.DOTALL,
    )
    out: dict[str, str] = {}
    for k, v in pairs:
        key = strip_tags(k)
        if key and key not in out:
            out[key] = strip_tags(v)
    return out


def parse_spec(text: str) -> dict[str, str]:
    """把 '规格：2核 4G 带宽：10Mbps …' 拆成字典。"""
    out: dict[str, str] = {}
    for line in cell_lines(text):
        if "：" in line:
            k, v = line.split("：", 1)
            out[k.strip()] = v.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out
