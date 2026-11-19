"""离线解析测试：不联网，只验证 HTML 片段的抠取逻辑。"""

from __future__ import annotations

from landui_sdk.cloud import CloudAPI
from landui_sdk.parsers import cell_lines, parse_kv_page, parse_spec, strip_tags

MANAGE_SNIPPET = """
<table><tbody>
  <tr><td><div class="list"><span class="name">名称</span>
      <p>ld123 <em class="gray"></em>
      <a href="javascript:void(0);" class="edit"></a></p></div></td></tr>
  <!-- <td><div class="list"><span class="name">SSD系统盘</span><p> 40 G</p></div></td> -->
  <tr><td><div class="list"><span class="name">登录端口</span>
      <p> 2222</p></div></td></tr>
  <tr><td><div class="list"><span class="name">到期时间</span>
      <p> 2027-12-01 23:34:07 <span style="color: green">1年后过期</span></p></div></td></tr>
</tbody></table>
"""

ROW = [
    '<p class="ld-checkbox"><label><input type="checkbox" name="ids[]" value="10001"></label></p>',
    "<span class='do-remark'>demo-server</span><br /><a href='#' title='编辑备注'></a>",
    '<a href="/user/cloud/monitoring.html?id=10001" class="monitor"></a>',
    "大陆地区",
    "外网IP:203.0.113.10<br>",
    '<span class="run-status">运行中</span>',
    "规格：2核 4G<br />带宽：10Mbps<br />系统盘：40GB<br />硬盘：60GB<br/>系统：Rocky-linux 9.5",
    "2025-12-01 23:34:07<br />2027-12-01 23:34:07<br /><span>1年后过期</span>",
    '<div><a><span class="selected-content">暂无分组</span></a></div>',
    "<font color=red>未开通</font>",
    '<div data-ldtype=4><a href="/user/cloud/manage.html?id=10001">管理</a></div>',
]


def test_strip_tags_and_lines():
    assert strip_tags("<b>a</b><br>b") == "a b"
    assert cell_lines("x<br />y<br/>z") == ["x", "y", "z"]


def test_parse_spec():
    spec = parse_spec(ROW[6])
    assert spec["规格"] == "2核 4G"
    assert spec["系统"] == "Rocky-linux 9.5"


def test_parse_kv_skips_comments():
    kv = parse_kv_page(MANAGE_SNIPPET)
    assert kv["名称"] == "ld123"
    assert kv["登录端口"] == "2222"
    assert "SSD系统盘" not in kv
    assert kv["到期时间"].startswith("2027-12-01")


def test_parse_cloud_row():
    s = CloudAPI._parse_row(ROW)
    assert s.id == 10001
    assert s.name == "demo-server"
    assert s.ip == "203.0.113.10"
    assert s.status == "运行中"
    assert s.cpu_mem == "2核 4G"
    assert s.bandwidth == "10Mbps"
    assert s.os == "Rocky-linux 9.5"
    assert s.expire_at == "2027-12-01 23:34:07"
    assert s.expire_hint == "1年后过期"
    assert s.group == "暂无分组"
    assert s.is_running
