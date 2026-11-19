"""防火墙规则匹配 / 体检的离线测试。"""

from __future__ import annotations

from landui_sdk.firewall import (
    analyze_rules,
    effective_rule,
    parse_port_spec,
    port_in_spec,
    protocol_matches,
    spec_covers,
    suggest_weight,
)
from landui_sdk.models import FirewallRule


def rule(id_: int, weight: int, port: str, action: str = "允许", proto: str = "TCP",
         ip: str = "0.0.0.0/0") -> FirewallRule:
    return FirewallRule(
        id=id_, direction="Inbound", action=action, protocol=proto,
        port=port, ip=ip, weight=weight,
    )


def test_parse_port_spec():
    assert parse_port_spec("22") == [(22, 22)]
    assert parse_port_spec("8000-8100") == [(8000, 8100)]
    assert parse_port_spec("22,80,8000-8100") == [(22, 22), (80, 80), (8000, 8100)]
    assert parse_port_spec("8100-8000") == [(8000, 8100)]
    assert parse_port_spec("abc") == []
    assert parse_port_spec("22，80") == [(22, 22), (80, 80)]  # 中文逗号


def test_port_in_spec():
    assert port_in_spec("1-65535", 12345)
    assert port_in_spec("", 12345)
    assert port_in_spec("全部", 12345)
    assert not port_in_spec("22", 23)
    assert port_in_spec("8000-8100", 8000)
    assert port_in_spec("8000-8100", 8100)


def test_protocol_matches():
    assert protocol_matches("TCP", "tcp")
    assert protocol_matches("ANY", "UDP")
    assert protocol_matches("", "ICMP")
    assert not protocol_matches("TCP", "UDP")


def test_effective_rule_respects_weight():
    rules = [
        rule(1, 10, "1-65535", "拒绝", proto="ANY"),
        rule(2, 100, "22", "允许"),
    ]
    assert effective_rule(rules, 22).id == 2
    assert effective_rule(rules, 80).id == 1
    assert effective_rule(rules, 22, "UDP").id == 1
    assert effective_rule([], 22) is None


def test_spec_covers():
    assert spec_covers("1-65535", "22")
    assert spec_covers("8000-8100", "8001-8009")
    assert not spec_covers("8000-8005", "8001-8009")


def test_suggest_weight_is_on_top():
    assert suggest_weight([]) == 10
    assert suggest_weight([rule(1, 100, "22")]) == 110


def test_analyze_duplicates_and_shadowing():
    rules = [
        rule(1, 100, "1-65535", "允许"),
        rule(2, 50, "22", "拒绝"),
        rule(3, 200, "80", "允许"),
        rule(4, 200, "80", "允许"),
    ]
    issues = analyze_rules(rules)
    texts = " ".join(i.message for i in issues)
    assert "重复" in texts
    assert "永远匹配不到" in texts
    assert any(i.level == "danger" for i in issues)
    # 重复的两条都被点名
    dup = next(i for i in issues if "重复" in i.message)
    assert set(dup.rule_ids) == {3, 4}


def test_analyze_clean_rules():
    rules = [rule(1, 100, "22", "允许"), rule(2, 50, "443", "允许")]
    assert analyze_rules(rules) == []


def test_resolve_port_map_with_overrides():
    from landui_sdk.firewall import resolve_port_map, summarize_segments

    rules = [
        rule(1, 10, "1-65535", "拒绝", proto="ANY"),
        rule(2, 60, "80", "允许"),
        rule(3, 70, "8000-8100", "允许"),
        rule(4, 80, "8050", "拒绝"),
    ]
    segs = resolve_port_map(rules, "TCP")
    assert (80, 80) in [(s.start, s.end) for s in segs]
    assert any(s.start == 8000 and s.end == 8049 for s in segs)
    assert any(s.start == 8050 and s.end == 8050 and s.action == "拒绝" for s in segs)
    assert summarize_segments(segs, "允许") == "80, 8000-8049, 8051-8100"


def test_resolve_port_map_empty():
    from landui_sdk.firewall import resolve_port_map

    assert resolve_port_map([], "TCP") == []


def test_renumber_weights():
    from landui_sdk.firewall import renumber_weights

    rules = [rule(1, 123, "22"), rule(2, 500, "80"), rule(3, 7, "443")]
    out = renumber_weights(rules)
    assert out == {1: 30, 2: 20, 3: 10}
    assert renumber_weights(rules, top=1000, step=100) == {1: 1000, 2: 900, 3: 800}
    assert renumber_weights([]) == {}
