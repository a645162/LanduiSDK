"""云防火墙管理器（日常主力窗口）。

界面分三块：
* 左：规则表（搜索/过滤/多选/双击详情）
* 右：**内联编辑面板**，选中即填充，所有字段都是下拉/数字框，不用另开弹窗
* 下：**端口视图**，把 1-65535 画成色带，绿色放行/红色拒绝/灰色无规则，
  点击色带直接跳到对应规则

安全组：切换 / 新建 / 重命名 / 删除 / 绑定本机 / 看影响哪些机器。
规则：增删改查、批量改、导入导出、常用端口预设、端口连通性判定、规则体检。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6.QtCore import QPoint, QRect, Qt, Signal
from PySide6.QtGui import QColor, QKeySequence, QPainter, QPen, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolTip,
    QVBoxLayout,
    QWidget,
)
from ui_common import err_box, run_async

from landui_sdk import LanduiClient
from landui_sdk.firewall import (
    IN,
    OUT,
    PortSegment,
    analyze_rules,
    effective_rule,
    parse_port_spec,
    renumber_weights,
    resolve_port_map,
    suggest_weight,
    summarize_segments,
)
from landui_sdk.models import AclRule, FirewallRule, SecurityGroup, Server

PRESETS: list[tuple[str, str, str]] = [
    ("自定义", "", ""),
    ("SSH", "22", "TCP"),
    ("HTTP", "80", "TCP"),
    ("HTTPS", "443", "TCP"),
    ("MySQL", "3306", "TCP"),
    ("PostgreSQL", "5432", "TCP"),
    ("Redis", "6379", "TCP"),
    ("SQL Server", "1433", "TCP"),
    ("RDP", "3389", "TCP"),
    ("Ping / ICMP", "", "ICMP"),
    ("全部 TCP", "1-65535", "TCP"),
    ("全部 UDP", "1-65535", "UDP"),
]

COLUMNS = ["优先级", "行为", "协议", "端口", "授权IP", "描述", "创建时间"]
ID_COLUMN = len(COLUMNS)

PROTO_CHOICES = ["TCP", "UDP", "ICMP", "全部"]
ACTION_MAP = {"允许": "Allow", "拒绝": "Deny"}
ACTION_BACK = {"Allow": "允许", "Deny": "拒绝"}

COLOR_ALLOW = QColor("#2e9e5b")
COLOR_DENY = QColor("#d64545")
COLOR_NONE = QColor("#d8d8d8")
COLOR_UNKNOWN = QColor("#c9c9c9")


# --------------------------------------------------------------------- 工具
def normalize_ip(text: str) -> str:
    text = text.strip() or "0.0.0.0/0"
    parts = text.split("/")
    try:
        octets = [int(x) for x in parts[0].split(".")]
    except ValueError as exc:
        raise ValueError(f"IP 不合法：{text}") from exc
    if len(octets) != 4 or any(not 0 <= o <= 255 for o in octets):
        raise ValueError(f"IP 不合法：{text}")
    if len(parts) == 2:
        if not parts[1].isdigit() or not 0 <= int(parts[1]) <= 32:
            raise ValueError(f"掩码不合法：{text}")
    elif len(parts) > 2:
        raise ValueError(f"IP 不合法：{text}")
    return text


def validate_ports(text: str) -> list[tuple[int, int]]:
    ranges = parse_port_spec(text)
    if not ranges:
        raise ValueError("端口不能为空，例：22 或 8000-8100 或 22,80,443")
    for lo, hi in ranges:
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
            raise ValueError(f"端口超出范围：{lo}-{hi}（1-65535）")
    return ranges


def split_ranges(ranges: list[tuple[int, int]], limit: int = 256) -> list[tuple[int, int]]:
    """把区间拆成单端口，超过 limit 就原样返回（防止一次建几百条规则）。"""
    total = sum(hi - lo + 1 for lo, hi in ranges)
    if total > limit:
        return ranges
    return [(p, p) for lo, hi in ranges for p in range(lo, hi + 1)]


def _match_filter(rule: FirewallRule, needle: str, action: str, proto: str) -> bool:
    if action != "全部" and ACTION_BACK.get(rule.action, rule.action) != action:
        return False
    is_any_proto = (rule.protocol or "").upper() in ("", "ANY", "全部")
    if proto != "全部" and not is_any_proto and (rule.protocol or "") != proto:
        return False
    needle = needle.strip().lower()
    if not needle:
        return True
    haystack = " ".join(
        [rule.action, rule.protocol, rule.port, rule.ip, rule.description, str(rule.weight)]
    ).lower()
    return needle in haystack


def _format_rule(rule: FirewallRule) -> str:
    return (
        f"#{rule.id} {ACTION_BACK.get(rule.action, rule.action)} "
        f"{rule.protocol or '全部'} {rule.port or '全部'} ← {rule.ip or '全部'}"
    )


class RuleTable(QTableWidget):
    """支持拖拽调顺序的规则表：拖完把新的 ID 顺序发出去。"""

    order_changed = Signal(list)

    def dropEvent(self, event) -> None:
        sorting = self.isSortingEnabled()
        self.setSortingEnabled(False)
        super().dropEvent(event)
        ids: list[int] = []
        for row in range(self.rowCount()):
            item = self.item(row, ID_COLUMN)
            if item is not None and item.text():
                ids.append(int(item.text()))
        if sorting:
            self.setSortingEnabled(True)
        if ids:
            self.order_changed.emit(ids)


# --------------------------------------------------------------------- 端口视图
class PortMapView(QWidget):
    """端口色带：绿=放行、红=拒绝、灰=没有规则命中。

    三条：1-65535 / 1-1024 / 1-256，越往下越放大，小端口也能看清。
    点击色带直接跳到对应规则。
    """

    rule_clicked = Signal(int)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMinimumHeight(148)
        self.setMouseTracking(True)
        self._segments: list[tuple[int, int, PortSegment | None]] = []
        self._by_id: dict[int, FirewallRule] = {}

    def set_rules(self, rules: list[FirewallRule], protocol: str = "TCP") -> None:
        segments = resolve_port_map(rules, protocol)
        self._by_id = {r.id: r for r in rules}
        display: list[tuple[int, int, PortSegment | None]] = []
        cursor = 1
        for seg in segments:
            if seg.start > cursor:
                display.append((cursor, seg.start - 1, None))
            display.append((seg.start, seg.end, seg))
            cursor = seg.end + 1
        if cursor <= 65535:
            display.append((cursor, 65535, None))
        self._segments = display
        self.update()

    # ------------------------------------------------------------------
    def _strips(self) -> list[tuple[QRect, int, int, list[int]]]:
        width = max(self.width() - 16, 10)
        return [
            (QRect(8, 6, width, 24), 1, 65535, [1, 10000, 20000, 30000, 40000, 50000, 65535]),
            (QRect(8, 44, width, 24), 1, 1024, [1, 256, 512, 768, 1024]),
            (QRect(8, 82, width, 24), 1, 256, [1, 22, 80, 128, 192, 256]),
        ]

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)
        painter.fillRect(self.rect(), QColor("#fafafa"))
        painter.setPen(QPen(QColor("#ddd")))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))

        font = painter.font()
        font.setPointSizeF(7.5)
        painter.setFont(font)

        for rect, lo, hi, ticks in self._strips():
            painter.fillRect(rect, COLOR_NONE)
            span = hi - lo + 1
            for start, end, seg in self._segments:
                s = max(start, lo)
                e = min(end, hi)
                if s > e:
                    continue
                x0 = rect.left() + (s - lo) / span * rect.width()
                x1 = rect.left() + (e - lo + 1) / span * rect.width()
                color = COLOR_NONE if seg is None else (
                    COLOR_ALLOW if seg.is_allow else COLOR_DENY
                )
                painter.fillRect(
                    QRect(int(x0), rect.top(), max(2, int(x1 - x0)), rect.height()), color
                )
            painter.setPen(QPen(QColor("#bbb")))
            painter.drawRect(rect)

            painter.setPen(QColor("#666"))
            for tick in ticks:
                x = rect.left() + (tick - lo) / span * rect.width()
                label_x = min(int(x) - 8, rect.right() - 30)
                painter.drawText(QPoint(label_x, rect.bottom() + 11), str(tick))
            label = f"{lo}-{hi}"
            label_rect = QRect(rect.right() - 62, rect.top() + 5, 56, 15)
            painter.fillRect(label_rect, QColor(255, 255, 255, 205))
            painter.setPen(QColor("#555"))
            painter.drawText(label_rect, Qt.AlignCenter, label)

        legend_y = self.height() - 8
        painter.setPen(Qt.NoPen)
        painter.setBrush(COLOR_ALLOW)
        painter.drawRect(8, legend_y - 7, 10, 7)
        painter.setBrush(COLOR_DENY)
        painter.drawRect(78, legend_y - 7, 10, 7)
        painter.setBrush(COLOR_NONE)
        painter.drawRect(148, legend_y - 7, 10, 7)
        painter.setPen(QColor("#666"))
        painter.drawText(QPoint(22, legend_y), "放行")
        painter.drawText(QPoint(92, legend_y), "拒绝")
        painter.drawText(QPoint(162, legend_y), "无规则")
        painter.drawText(QPoint(226, legend_y), "点色带可跳到对应规则（悬停看端口）")

    # ------------------------------------------------------------------
    def _hit(self, x: int, y: int) -> int | None:
        for rect, lo, hi, _ticks in self._strips():
            if rect.left() <= x <= rect.right() and rect.top() - 12 <= y <= rect.bottom() + 12:
                ratio = (x - rect.left()) / max(rect.width(), 1)
                return lo + int(ratio * (hi - lo))
        return None

    def mouseMoveEvent(self, event) -> None:
        port = self._hit(int(event.position().x()), int(event.position().y()))
        if port is None:
            return
        seg = next((s for start, end, s in self._segments if start <= port <= end), None)
        if seg is None:
            QToolTip.showText(event.globalPosition().toPoint(), f"{port}：没有规则命中")
            return
        rule = self._by_id.get(seg.rule_id)
        text = f"{port}：{'放行' if seg.is_allow else '拒绝'}"
        if rule:
            text += f"\n#{rule.id} 优先级 {rule.weight}  {rule.port or '全部'}"
        QToolTip.showText(event.globalPosition().toPoint(), text)

    def mousePressEvent(self, event) -> None:
        port = self._hit(int(event.position().x()), int(event.position().y()))
        if port is None:
            return
        for start, end, seg in self._segments:
            if start <= port <= end and seg is not None:
                self.rule_clicked.emit(seg.rule_id)
                return


# --------------------------------------------------------------------- 内联编辑
class RuleEditorPanel(QGroupBox):
    """右侧编辑面板。选中表格即填充，全部用下拉/数字框改，直接保存。"""

    save_requested = Signal(list, object)   # payloads, 原规则或 None
    delete_requested = Signal(object)
    copy_requested = Signal(object)
    priority_action = Signal(str)           # top / up / down / bottom

    MODE_SINGLE, MODE_RANGE, MODE_MULTI = 0, 1, 2

    def __init__(self, direction: str, parent: QWidget | None = None):
        super().__init__("规则编辑", parent)
        self.direction = direction
        self.current: FirewallRule | None = None
        self._existing: list[FirewallRule] = []
        self._loading = False
        self._dirty = False

        root = QVBoxLayout(self)
        self.lbl_title = QLabel("新建规则")
        self.lbl_title.setStyleSheet("font-weight:600")
        root.addWidget(self.lbl_title)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        self.cb_preset = QComboBox()
        for name, port, proto in PRESETS:
            self.cb_preset.addItem(name, (port, proto))
        form.addRow("常用", self.cb_preset)

        self.cb_proto = QComboBox()
        self.cb_proto.addItems(PROTO_CHOICES)
        form.addRow("协议", self.cb_proto)

        self.cb_mode = QComboBox()
        self.cb_mode.addItems(["单端口", "端口段", "多端口/多段"])
        form.addRow("端口形式", self.cb_mode)

        self.stack = QStackedWidget()
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(80)
        single = QWidget()
        sl = QHBoxLayout(single)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.addWidget(self.sp_port, 1)
        self.stack.addWidget(single)

        rng = QWidget()
        rl = QHBoxLayout(rng)
        rl.setContentsMargins(0, 0, 0, 0)
        self.sp_start = QSpinBox()
        self.sp_start.setRange(1, 65535)
        self.sp_start.setValue(8000)
        self.sp_end = QSpinBox()
        self.sp_end.setRange(1, 65535)
        self.sp_end.setValue(8100)
        rl.addWidget(self.sp_start, 1)
        rl.addWidget(QLabel("-"))
        rl.addWidget(self.sp_end, 1)
        self.stack.addWidget(rng)

        multi = QWidget()
        ml = QHBoxLayout(multi)
        ml.setContentsMargins(0, 0, 0, 0)
        self.ed_multi = QLineEdit()
        self.ed_multi.setPlaceholderText("22,80,8000-8100")
        ml.addWidget(self.ed_multi)
        self.stack.addWidget(multi)
        self.stack.setMaximumHeight(36)
        form.addRow("端口", self.stack)

        self.chk_split = QCheckBox("拆成单端口规则（每个端口各一条）")
        self.chk_split.setToolTip("范围端口需要单独控制时勾选；规则太多时建议保留范围")
        form.addRow("", self.chk_split)

        self.ed_ip = QLineEdit("0.0.0.0/0")
        form.addRow("授权IP", self.ed_ip)

        self.cb_action = QComboBox()
        self.cb_action.addItems(["允许", "拒绝"])
        form.addRow("行为", self.cb_action)

        self.sp_weight = QSpinBox()
        self.sp_weight.setRange(1, 65535)
        self.sp_weight.setValue(200)
        form.addRow("优先级", self.sp_weight)

        prio_row = QHBoxLayout()
        self.prio_buttons: list[QPushButton] = []
        for text, action, tip in (
            ("置顶", "top", "置顶：调到最前面（最先匹配）"),
            ("上移", "up", "上移一位，和上一条交换优先级"),
            ("下移", "down", "下移一位"),
            ("置底", "bottom", "置底：最后才匹配"),
        ):
            btn = QPushButton(text)
            btn.setToolTip(tip)
            btn.clicked.connect(lambda _=False, a=action: self.priority_action.emit(a))
            prio_row.addWidget(btn)
            self.prio_buttons.append(btn)
        form.addRow("快速调整", prio_row)

        self.ed_desc = QLineEdit()
        form.addRow("描述", self.ed_desc)

        self.lbl_hint = QLabel("")
        self.lbl_hint.setWordWrap(True)
        self.lbl_hint.setStyleSheet("color:#666")
        form.addRow("", self.lbl_hint)

        root.addLayout(form)

        btns = QGridLayout()
        self.btn_save = QPushButton("保存")
        self.btn_save.setDefault(True)
        self.btn_dup = QPushButton("另存为副本")
        self.btn_del = QPushButton("删除")
        self.btn_reset = QPushButton("清空")
        btns.addWidget(self.btn_save, 0, 0)
        btns.addWidget(self.btn_dup, 0, 1)
        btns.addWidget(self.btn_del, 1, 0)
        btns.addWidget(self.btn_reset, 1, 1)
        root.addLayout(btns)

        self.cb_mode.currentIndexChanged.connect(self.stack.setCurrentIndex)
        self.cb_preset.currentIndexChanged.connect(self._apply_preset)
        for widget in (self.sp_port, self.sp_start, self.sp_end):
            widget.valueChanged.connect(lambda _v: self._update_hint())
        self.ed_multi.textChanged.connect(lambda _t: self._update_hint())
        self.cb_proto.currentIndexChanged.connect(lambda _i: self._update_hint())
        self.ed_ip.textChanged.connect(lambda _t: self._update_hint())

        self.btn_save.clicked.connect(self._emit_save)
        self.btn_dup.clicked.connect(self._emit_copy)
        self.btn_del.clicked.connect(self._emit_delete)
        self.btn_reset.clicked.connect(lambda: self.reset_new(self._existing))

        for widget in (self.sp_port, self.sp_start, self.sp_end, self.sp_weight):
            widget.valueChanged.connect(self._mark_dirty)
        for widget in (self.ed_multi, self.ed_ip, self.ed_desc):
            widget.textChanged.connect(self._mark_dirty)
        for combo in (self.cb_proto, self.cb_mode, self.cb_action, self.cb_preset):
            combo.currentIndexChanged.connect(self._mark_dirty)

        self._set_edit_mode(False)

    # ------------------------------------------------------------------
    def _mark_dirty(self, *_args) -> None:
        if self._loading or self._dirty:
            return
        self._set_dirty(True)

    def _set_dirty(self, dirty: bool) -> None:
        self._dirty = dirty
        if dirty:
            self.setTitle("规则编辑 ● 未保存")
            self.setStyleSheet("QGroupBox::title { color:#c05621; }")
            self.btn_save.setText("保存 *")
            self.btn_save.setStyleSheet(
                "QPushButton { background:#e69138; color:white; font-weight:600; }"
            )
        else:
            self.setTitle("规则编辑")
            self.setStyleSheet("")
            self.btn_save.setText("保存")
            self.btn_save.setStyleSheet("")

    def is_dirty(self) -> bool:
        return self._dirty

    def _set_edit_mode(self, editing: bool) -> None:
        self.btn_del.setEnabled(editing)
        self.btn_dup.setEnabled(editing)
        for btn in self.prio_buttons:
            btn.setEnabled(editing)
        self.chk_split.setVisible(not editing)
        self.chk_split.setChecked(False)
        self.lbl_title.setText("编辑规则" if editing else "新建规则")

    def set_rank(self, rank: int, total: int) -> None:
        self._rank = (rank, total)
        if self.current:
            self.lbl_title.setText(f"编辑规则 #{self.current.id} · 第 {rank}/{total} 位")
        else:
            self.lbl_title.setText("新建规则")

    def reset_new(self, existing: list[FirewallRule]) -> None:
        self._loading = True
        self._existing = existing
        self.current = None
        self._rank = None
        self.cb_preset.setCurrentIndex(0)
        self.cb_proto.setCurrentText("TCP")
        self.cb_mode.setCurrentIndex(0)
        self.stack.setCurrentIndex(0)
        self.sp_port.setValue(80)
        self.ed_multi.clear()
        self.ed_ip.setText("0.0.0.0/0")
        self.cb_action.setCurrentText("允许")
        self.sp_weight.setValue(suggest_weight(existing))
        self.ed_desc.clear()
        self._set_edit_mode(False)
        self._loading = False
        self._set_dirty(False)
        self._update_hint()

    def set_rule(self, rule: FirewallRule, *, as_copy: bool = False) -> None:
        previous_rank = getattr(self, "_rank", None)
        self._rank = None
        self._loading = True
        self.current = None if as_copy else rule
        self.cb_preset.setCurrentIndex(0)
        self.cb_proto.setCurrentText(rule.protocol or "TCP")
        spec = rule.port or "1-65535"
        ranges = parse_port_spec(spec)
        if len(ranges) == 1 and ranges[0][0] == ranges[0][1]:
            self.cb_mode.setCurrentIndex(self.MODE_SINGLE)
            self.sp_port.setValue(ranges[0][0])
        elif len(ranges) == 1:
            self.cb_mode.setCurrentIndex(self.MODE_RANGE)
            self.sp_start.setValue(ranges[0][0])
            self.sp_end.setValue(ranges[0][1])
        else:
            self.cb_mode.setCurrentIndex(self.MODE_MULTI)
            self.ed_multi.setText(spec)
        self.stack.setCurrentIndex(self.cb_mode.currentIndex())
        self.ed_ip.setText(rule.ip or "0.0.0.0/0")
        self.cb_action.setCurrentText(ACTION_BACK.get(rule.action, "允许"))
        self.sp_weight.setValue(min(rule.weight + (10 if as_copy else 0), 65535))
        self.ed_desc.setText(
            (rule.description + " (副本)").strip() if as_copy else rule.description
        )
        self._set_edit_mode(not as_copy)
        self._loading = False
        self._set_dirty(False)
        self._update_hint()
        if previous_rank and not as_copy:
            self.set_rank(*previous_rank)

    def show_multi(self, count: int) -> None:
        """多选时禁用编辑，避免误改一批。"""
        self._loading = True
        self.current = None
        self._rank = None
        self.lbl_title.setText(f"已选 {count} 条规则")
        self._set_edit_mode(False)
        self.btn_save.setEnabled(False)
        self._loading = False
        self.lbl_hint.setText("多选时请用「批量修改」；要看单条请只选一条。")

    def _apply_preset(self, _index: int) -> None:
        if self._loading:
            return
        port, proto = self.cb_preset.currentData()
        if not port and not proto:
            return
        if proto:
            self.cb_proto.setCurrentText(proto)
        if proto == "ICMP":
            self.cb_mode.setCurrentIndex(self.MODE_RANGE)
            self.sp_start.setValue(1)
            self.sp_end.setValue(65535)
        elif port:
            ranges = parse_port_spec(port)
            if len(ranges) == 1 and ranges[0][0] == ranges[0][1]:
                self.cb_mode.setCurrentIndex(self.MODE_SINGLE)
                self.sp_port.setValue(ranges[0][0])
            elif len(ranges) == 1:
                self.cb_mode.setCurrentIndex(self.MODE_RANGE)
                self.sp_start.setValue(ranges[0][0])
                self.sp_end.setValue(ranges[0][1])
            else:
                self.cb_mode.setCurrentIndex(self.MODE_MULTI)
                self.ed_multi.setText(port)
        self._update_hint()

    def _port_text(self) -> str:
        mode = self.cb_mode.currentIndex()
        if mode == self.MODE_SINGLE:
            return str(self.sp_port.value())
        if mode == self.MODE_RANGE:
            lo, hi = self.sp_start.value(), self.sp_end.value()
            if lo > hi:
                lo, hi = hi, lo
            return f"{lo}-{hi}"
        return self.ed_multi.text().strip()

    def _update_hint(self) -> None:
        if self._loading:
            return
        try:
            ranges = validate_ports(self._port_text())
            ip = normalize_ip(self.ed_ip.text())
        except ValueError as exc:
            self.lbl_hint.setText(str(exc))
            self.lbl_hint.setStyleSheet("color:#c00")
            return

        total = sum(hi - lo + 1 for lo, hi in ranges)
        split = self.chk_split.isChecked() and not self.current
        count = len(split_ranges(ranges)) if split else len(ranges)
        parts = [f"{count} 条规则，覆盖 {total} 个端口"]
        if self.cb_action.currentText() == "允许" and ip == "0.0.0.0/0" and total > 1024:
            parts.append("对全网开放较大范围，注意风险")
        if self.current:
            parts.append(f"正在编辑 #{self.current.id}")
        self.lbl_hint.setText("；".join(parts))
        self.lbl_hint.setStyleSheet("color:#b06000" if len(parts) > 1 else "color:#666")

    # ------------------------------------------------------------------
    def payloads(self) -> list[dict[str, Any]]:
        ranges = validate_ports(self._port_text())
        split = self.chk_split.isChecked() and not self.current
        if split:
            ranges = split_ranges(ranges)
        proto = self.cb_proto.currentText()
        action = ACTION_MAP[self.cb_action.currentText()]
        ip = normalize_ip(self.ed_ip.text())
        out = []
        for i, (lo, hi) in enumerate(ranges):
            out.append(
                {
                    "port": str(lo) if lo == hi else f"{lo}-{hi}",
                    "protocol": "ANY" if proto == "全部" else proto,
                    "action": action,
                    "ip": ip,
                    "direction": self.direction,
                    "weight": self.sp_weight.value() + i,
                    "description": self.ed_desc.text().strip(),
                }
            )
        return out

    def _emit_save(self) -> None:
        try:
            payloads = self.payloads()
        except ValueError as exc:
            QMessageBox.warning(self, "检查一下", str(exc))
            return
        if self.current and len(payloads) != 1:
            QMessageBox.warning(self, "不能批量编辑", "编辑只能保留一条规则。")
            return
        self.btn_save.setEnabled(True)
        self.save_requested.emit(payloads, self.current)

    def _emit_copy(self) -> None:
        if self.current:
            self.copy_requested.emit(self.current)

    def _emit_delete(self) -> None:
        if self.current:
            self.delete_requested.emit(self.current)


# --------------------------------------------------------------------- 弹窗类
class RuleDetailDialog(QDialog):
    """双击规则看到的详情窗口。"""

    def __init__(self, rule: FirewallRule, direction: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.rule = rule
        self.result_action: str | None = None
        self.setWindowTitle(f"规则详情 #{rule.id}")
        self.setMinimumWidth(480)

        root = QVBoxLayout(self)
        grid = QGridLayout()
        ranges = parse_port_spec(rule.port or "1-65535")
        port_text = rule.port or "全部（1-65535）"
        if len(ranges) > 1:
            port_text += f"（{len(ranges)} 段，共 {sum(b - a + 1 for a, b in ranges)} 个端口）"
        rows = [
            ("方向", "入方向" if direction == IN else "出方向"),
            ("优先级", rule.weight),
            ("行为", ACTION_BACK.get(rule.action, rule.action)),
            ("协议", rule.protocol or "全部"),
            ("端口", port_text),
            ("授权IP", rule.ip or "全部（0.0.0.0/0）"),
            ("描述", rule.description or "—"),
            ("创建时间", rule.created_at or "—"),
            ("规则ID", rule.id),
        ]
        for i, (k, v) in enumerate(rows):
            grid.addWidget(QLabel(f"<b>{k}</b>"), i, 0)
            label = QLabel(str(v))
            label.setWordWrap(True)
            grid.addWidget(label, i, 1)
        root.addLayout(grid)

        bottom = QHBoxLayout()
        btn_copy = QPushButton("复制一条")
        btn_close = QPushButton("关闭")
        bottom.addStretch(1)
        bottom.addWidget(btn_copy)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

        btn_copy.clicked.connect(lambda: self._choose("copy"))
        btn_close.clicked.connect(self.reject)

    def _choose(self, action: str) -> None:
        self.result_action = action
        self.accept()


class QuickAddDialog(QDialog):
    """勾选常用端口批量添加。"""

    def __init__(self, direction: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.direction = direction
        self.setWindowTitle(f"快速添加 · {'入方向' if direction == IN else '出方向'}")
        self.items: list[tuple[Any, QLineEdit, str, str]] = []

        root = QVBoxLayout(self)
        root.addWidget(QLabel("勾选要放行的服务（端口可改，支持 8000-8100）："))
        grid = QGridLayout()
        presets = [p for p in PRESETS if p[0] not in ("自定义", "全部 TCP", "全部 UDP")]
        for i, (name, port, proto) in enumerate(presets):
            box = QCheckBox(name)
            edit = QLineEdit(port)
            edit.setMaximumWidth(110)
            grid.addWidget(box, i // 3, (i % 3) * 2)
            grid.addWidget(edit, i // 3, (i % 3) * 2 + 1)
            self.items.append((box, edit, proto, name))
        root.addLayout(grid)

        form = QFormLayout()
        self.ed_ip = QLineEdit("0.0.0.0/0")
        form.addRow("授权IP", self.ed_ip)
        self.sp_weight = QSpinBox()
        self.sp_weight.setRange(1, 65535)
        self.sp_weight.setValue(200)
        form.addRow("起始优先级", self.sp_weight)
        root.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("添加")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        root.addWidget(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def payloads(self) -> list[dict[str, Any]]:
        ip = normalize_ip(self.ed_ip.text())
        out: list[dict[str, Any]] = []
        for box, edit, proto, name in self.items:
            if not box.isChecked():
                continue
            for lo, hi in validate_ports(edit.text().strip() or "1-65535"):
                out.append(
                    {
                        "port": str(lo) if lo == hi else f"{lo}-{hi}",
                        "protocol": proto,
                        "action": "Allow",
                        "ip": ip,
                        "direction": self.direction,
                        "weight": self.sp_weight.value() + len(out),
                        "description": name,
                    }
                )
        return out


class GroupDialog(QDialog):
    def __init__(self, title: str, name: str = "", desc: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        form = QFormLayout(self)
        self.ed_name = QLineEdit(name)
        self.ed_desc = QLineEdit(desc)
        form.addRow("名称", self.ed_name)
        form.addRow("描述", self.ed_desc)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("保存")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        form.addRow(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def values(self) -> tuple[str, str]:
        return self.ed_name.text().strip(), self.ed_desc.text().strip()


class AclDialog(QDialog):
    def __init__(self, existing: list[AclRule], parent=None):
        super().__init__(parent)
        self.setWindowTitle("新增单机 ACL 策略")
        self.setMinimumWidth(480)
        form = QFormLayout(self)

        self.sp_weight = QSpinBox()
        self.sp_weight.setRange(1, 65535)
        self.sp_weight.setValue(max({r.weight for r in existing}, default=0) + 10)
        form.addRow("权重（不能重复）", self.sp_weight)

        self.cb_direction = QComboBox()
        self.cb_direction.addItems(["入方向", "出方向"])
        form.addRow("方向", self.cb_direction)

        self.cb_action = QComboBox()
        self.cb_action.addItems(["允许", "拒绝"])
        form.addRow("行为", self.cb_action)

        self.cb_proto = QComboBox()
        self.cb_proto.addItems(["TCP", "UDP", "ICMP", "ANY"])
        form.addRow("协议", self.cb_proto)

        self.ed_remote_ip = QLineEdit()
        self.ed_remote_ip.setPlaceholderText("不填=任意")
        form.addRow("远端 IP", self.ed_remote_ip)
        self.ed_remote_port = QLineEdit()
        self.ed_remote_port.setPlaceholderText("不填=任意，可填 8000-8100")
        form.addRow("远端端口", self.ed_remote_port)
        self.ed_local_ip = QLineEdit()
        self.ed_local_ip.setPlaceholderText("不填=任意")
        form.addRow("本地 IP", self.ed_local_ip)
        self.ed_local_port = QLineEdit()
        self.ed_local_port.setPlaceholderText("不填=任意，可填 8000-8100")
        form.addRow("本地端口", self.ed_local_port)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("保存")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        form.addRow(buttons)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def values(self) -> dict[str, Any]:
        return {
            "weight": self.sp_weight.value(),
            "direction": IN if self.cb_direction.currentIndex() == 0 else OUT,
            "action": ACTION_MAP[self.cb_action.currentText()],
            "protocol": self.cb_proto.currentText(),
            "remote_ip": self.ed_remote_ip.text().strip(),
            "remote_port": self.ed_remote_port.text().strip(),
            "local_ip": self.ed_local_ip.text().strip(),
            "local_port": self.ed_local_port.text().strip(),
        }


# --------------------------------------------------------------------- 主窗口
class FirewallWindow(QDialog):
    def __init__(self, client: LanduiClient, server: Server, parent: QWidget | None = None):
        super().__init__(parent)
        self.client = client
        self.server = server
        self.groups: list[SecurityGroup] = []
        self.bound_groups: set[int] = set()
        self.instances: list[dict[str, Any]] = []
        self.instance_map: dict[int, list[dict[str, Any]]] = {}
        self.rules: dict[str, list[FirewallRule]] = {IN: [], OUT: []}
        self.acl_rules: list[AclRule] = []
        self._error_shown = False
        self._acl_loaded = False
        # 刷新后要恢复选中的规则（按方向存 id）
        self._pending_select: dict[str, int | None] = {}
        self._pending_status: str | None = None
        self._selection_guard = False

        self.setWindowTitle(f"云防火墙 · {server.name} ({server.ip})")
        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowMinMaxButtonsHint
            | Qt.WindowSystemMenuHint
        )
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setSizeGripEnabled(True)
        self.resize(1320, 900)
        root = QVBoxLayout(self)

        # ---------------- 安全组
        head = QGroupBox("安全组")
        head_layout = QVBoxLayout(head)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("当前组"))
        self.cb_group = QComboBox()
        self.cb_group.setMinimumWidth(320)
        row1.addWidget(self.cb_group)
        self.lbl_bind = QLabel("")
        row1.addWidget(self.lbl_bind)
        self.btn_bind = QPushButton("把本机加入该组")
        row1.addWidget(self.btn_bind)
        row1.addStretch(1)
        self.btn_new_group = QPushButton("新建组")
        self.btn_rename_group = QPushButton("重命名")
        self.btn_del_group = QPushButton("删除组")
        self.btn_refresh = QPushButton("刷新")
        for b in (self.btn_new_group, self.btn_rename_group, self.btn_del_group, self.btn_refresh):
            row1.addWidget(b)
        head_layout.addLayout(row1)

        self.lbl_instances = QLabel("")
        self.lbl_instances.setWordWrap(True)
        head_layout.addWidget(self.lbl_instances)
        root.addWidget(head)

        # ---------------- 页签
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.tables: dict[str, QTableWidget] = {}
        self.filters: dict[str, tuple[QLineEdit, QComboBox, QComboBox]] = {}
        self.panels: dict[str, RuleEditorPanel] = {}
        self.portmaps: dict[str, PortMapView] = {}
        self.map_protos: dict[str, QComboBox] = {}
        self.summaries: dict[str, QLabel] = {}

        for direction, label in ((IN, "入方向"), (OUT, "出方向")):
            self.tabs.addTab(self._build_rule_page(direction), label)
        self.tabs.addTab(self._build_acl_page(), "单机 ACL")
        self.tabs.addTab(self._build_diag_page(), "诊断")

        bottom = QHBoxLayout()
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("color:#666")
        bottom.addWidget(self.lbl_status, 1)
        self.btn_close = QPushButton("关闭")
        bottom.addWidget(self.btn_close)
        root.addLayout(bottom)

        self.btn_close.clicked.connect(self.accept)
        self.btn_refresh.clicked.connect(lambda: self.reload(groups_too=True))
        self.btn_bind.clicked.connect(self._bind)
        self.cb_group.currentIndexChanged.connect(lambda _: self._on_group_changed())
        self.btn_new_group.clicked.connect(self._create_group)
        self.btn_rename_group.clicked.connect(self._rename_group)
        self.btn_del_group.clicked.connect(self._delete_group)
        self.tabs.currentChanged.connect(self._on_tab_changed)

        QShortcut(QKeySequence("F5"), self, activated=lambda: self.reload(groups_too=True))
        QShortcut(QKeySequence("Delete"), self, activated=self._delete_current_selection)
        QShortcut(QKeySequence("Ctrl+Up"), self, activated=lambda: self._priority_current("up"))
        QShortcut(
            QKeySequence("Ctrl+Down"), self, activated=lambda: self._priority_current("down")
        )

        self.reload(groups_too=True)

    # ------------------------------------------------------------ 页面
    def _build_rule_page(self, direction: str) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)

        bar = QHBoxLayout()
        flt = QLineEdit()
        flt.setPlaceholderText("搜端口 / IP / 描述")
        flt.setClearButtonEnabled(True)
        flt.setMaximumWidth(230)
        cb_action = QComboBox()
        cb_action.addItems(["全部", "允许", "拒绝"])
        cb_proto = QComboBox()
        cb_proto.addItems(["全部", "TCP", "UDP", "ICMP"])
        bar.addWidget(flt)
        bar.addWidget(cb_action)
        bar.addWidget(cb_proto)
        bar.addStretch(1)

        btn_add = QPushButton("新建")
        btn_quick = QPushButton("快速添加")
        btn_del = QPushButton("删除")
        btn_bulk = QPushButton("批量修改")
        btn_renumber = QPushButton("重排优先级")
        btn_renumber.setToolTip("按当前顺序重新编号（10/20/30…），清理重复或过大的权重")
        btn_export = QPushButton("导出")
        btn_import = QPushButton("导入")
        for b in (btn_add, btn_quick, btn_del, btn_bulk, btn_renumber, btn_export, btn_import):
            bar.addWidget(b)
        v.addLayout(bar)

        splitter = QSplitter(Qt.Horizontal)
        table = RuleTable(0, ID_COLUMN + 1)
        table.setHorizontalHeaderLabels([*COLUMNS, "ID"])
        table.setColumnHidden(ID_COLUMN, True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        for col in (0, 1, 2):
            table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.horizontalHeader().setSortIndicator(0, Qt.DescendingOrder)
        table.verticalHeader().setVisible(False)
        table.setDragDropMode(QAbstractItemView.InternalMove)
        table.setDragEnabled(True)
        table.setAcceptDrops(True)
        table.setDropIndicatorShown(True)
        table.setDefaultDropAction(Qt.MoveAction)
        table.setToolTip("拖动行可直接调优先级（需按优先级列排序）")
        splitter.addWidget(table)

        panel = RuleEditorPanel(direction)
        panel.setMinimumWidth(330)
        panel.setMaximumWidth(400)
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 0)
        v.addWidget(splitter, 1)

        # 端口视图
        map_box = QGroupBox("端口视图")
        ml = QVBoxLayout(map_box)
        top = QHBoxLayout()
        top.addWidget(QLabel("协议"))
        cb_map_proto = QComboBox()
        cb_map_proto.addItems(["TCP", "UDP"])
        top.addWidget(cb_map_proto)
        self.map_protos[direction] = cb_map_proto
        self.summaries[direction] = QLabel("")
        self.summaries[direction].setWordWrap(True)
        top.addWidget(self.summaries[direction], 1)
        ml.addLayout(top)
        portmap = PortMapView()
        ml.addWidget(portmap)
        v.addWidget(map_box)

        self.tables[direction] = table
        self.panels[direction] = panel
        self.portmaps[direction] = portmap
        self.filters[direction] = (flt, cb_action, cb_proto)

        flt.textChanged.connect(lambda _t, d=direction: self._render(d))
        cb_action.currentIndexChanged.connect(lambda _i, d=direction: self._render(d))
        cb_proto.currentIndexChanged.connect(lambda _i, d=direction: self._render(d))
        cb_map_proto.currentIndexChanged.connect(
            lambda _i, d=direction: self._update_portmap(d)
        )
        table.doubleClicked.connect(lambda _idx, d=direction: self._open_detail(d))
        table.customContextMenuRequested.connect(
            lambda pos, d=direction: self._context_menu(d, pos)
        )
        table.itemSelectionChanged.connect(lambda d=direction: self._on_selection(d))
        portmap.rule_clicked.connect(lambda rid, d=direction: self._select_rule_by_id(d, rid))
        table.order_changed.connect(lambda ids, d=direction: self._apply_order(d, ids))
        table.horizontalHeader().sortIndicatorChanged.connect(
            lambda _c, _o, d=direction: self._update_drag(d)
        )

        btn_add.clicked.connect(lambda _=False, d=direction: self._new_rule(d))
        btn_quick.clicked.connect(lambda _=False, d=direction: self._quick_add(d))
        btn_del.clicked.connect(lambda _=False, d=direction: self._delete_selected(d))
        btn_bulk.clicked.connect(lambda _=False, d=direction: self._bulk_modify(d))
        btn_renumber.clicked.connect(
            lambda _=False, d=direction: self._priority_action(d, "renumber")
        )
        btn_export.clicked.connect(lambda _=False, d=direction: self._export(d))
        btn_import.clicked.connect(lambda _=False, d=direction: self._import(d))

        panel.save_requested.connect(
            lambda payloads, rule, d=direction: self._save_from_panel(d, payloads, rule)
        )
        panel.delete_requested.connect(
            lambda rule, d=direction: self._delete_one(d, rule)
        )
        panel.copy_requested.connect(
            lambda rule, d=direction: panel.set_rule(rule, as_copy=True)
        )
        panel.priority_action.connect(
            lambda action, d=direction: self._priority_action(d, action)
        )
        return page

    def _build_acl_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        bar = QHBoxLayout()
        bar.addWidget(
            QLabel("单机 ACL 硬防：绑在单台机器上、按权重排序，和安全组是两套机制"), 1
        )
        self.btn_acl_add = QPushButton("新增策略")
        self.btn_acl_del = QPushButton("删除策略")
        self.btn_acl_refresh = QPushButton("刷新")
        for b in (self.btn_acl_add, self.btn_acl_del, self.btn_acl_refresh):
            bar.addWidget(b)
        v.addLayout(bar)

        self.tbl_acl = QTableWidget(0, 7)
        self.tbl_acl.setHorizontalHeaderLabels(
            ["ID", "权重", "方向", "行为", "协议", "远端 IP:端口", "本地 IP:端口"]
        )
        self.tbl_acl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_acl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_acl.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tbl_acl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_acl.setAlternatingRowColors(True)
        v.addWidget(self.tbl_acl, 1)
        self.lbl_acl = QLabel("")
        self.lbl_acl.setStyleSheet("color:#888")
        v.addWidget(self.lbl_acl)

        self.btn_acl_add.clicked.connect(self._add_acl)
        self.btn_acl_del.clicked.connect(self._delete_acl)
        self.btn_acl_refresh.clicked.connect(self._load_acl)
        return page

    def _build_diag_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)

        box = QGroupBox("端口连通性检查（支持 22,80,8000-8100）")
        grid = QGridLayout(box)
        self.ed_check_ports = QLineEdit()
        self.ed_check_ports.setPlaceholderText("22 或 80,443 或 8000-8010")
        self.cb_check_proto = QComboBox()
        self.cb_check_proto.addItems(["TCP", "UDP", "ICMP"])
        self.cb_check_dir = QComboBox()
        self.cb_check_dir.addItems(["入方向", "出方向"])
        self.btn_check = QPushButton("检查")
        grid.addWidget(QLabel("端口"), 0, 0)
        grid.addWidget(self.ed_check_ports, 0, 1)
        grid.addWidget(self.cb_check_proto, 0, 2)
        grid.addWidget(self.cb_check_dir, 0, 3)
        grid.addWidget(self.btn_check, 0, 4)
        v.addWidget(box)

        self.tbl_check = QTableWidget(0, 4)
        self.tbl_check.setHorizontalHeaderLabels(["端口", "结果", "命中规则", "备注"])
        self.tbl_check.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_check.setEditTriggers(QAbstractItemView.NoEditTriggers)
        v.addWidget(self.tbl_check, 2)

        v.addWidget(QLabel("规则体检"))
        self.txt_issues = QTextEdit()
        self.txt_issues.setReadOnly(True)
        self.txt_issues.setMaximumHeight(190)
        v.addWidget(self.txt_issues, 1)

        self.btn_check.clicked.connect(self._check_ports)
        self.ed_check_ports.returnPressed.connect(self._check_ports)
        return page

    # ------------------------------------------------------------ 通用
    @property
    def group_id(self) -> int | None:
        idx = self.cb_group.currentIndex()
        return self.groups[idx].id if 0 <= idx < len(self.groups) else None

    def _status(self, text: str) -> None:
        self.lbl_status.setText(text)

    def _fail(self, message: str) -> None:
        if self._error_shown:
            return
        self._error_shown = True
        if "登录" in message or "NotLoggedIn" in message:
            QMessageBox.warning(self, "登录失效", message + "\n\n请回主窗口重新登录。")
            self.reject()
            return
        err_box(self, message)

    # ------------------------------------------------------------ 加载
    def reload(self, groups_too: bool = False) -> None:
        self._error_shown = False
        self._status("加载中…")
        if groups_too:
            run_async(self, self._fetch_all, self._after_groups, self._fail)
        else:
            self._load_rules()

    def _fetch_all(self) -> dict[str, Any]:
        groups = self.client.firewall.list_groups()
        bound: set[int] = set()
        detail: dict[int, list[dict[str, Any]]] = {}
        for g in groups:
            try:
                instances = self.client.firewall.group_instances(g.id)
            except Exception as exc:  # noqa: BLE001 - 单个组失败不影响整体
                print(f"读取安全组 {g.id} 实例失败：{exc}")
                continue
            detail[g.id] = instances
            g.vps_count = len(instances)
            if any(item.get("vpsname") == self.server.name for item in instances):
                bound.add(g.id)
        return {"groups": groups, "bound": bound, "instances": detail}

    def _after_groups(self, data: dict[str, Any]) -> None:
        self.groups = data["groups"]
        self.bound_groups = data["bound"]
        self.instance_map = data["instances"]
        current = self.group_id
        self.cb_group.blockSignals(True)
        self.cb_group.clear()
        for g in self.groups:
            mark = "● " if g.id in self.bound_groups else "　"
            self.cb_group.addItem(
                f"{mark}{g.name}（{g.rule_count} 规则 / {g.vps_count} 台）", g.id
            )
        self.cb_group.blockSignals(False)

        target = 0
        for i, g in enumerate(self.groups):
            if g.id in self.bound_groups:
                target = i
                break
        if current is not None:
            for i, g in enumerate(self.groups):
                if g.id == current:
                    target = i
        if self.cb_group.count():
            self.cb_group.blockSignals(True)
            self.cb_group.setCurrentIndex(target)
            self.cb_group.blockSignals(False)
        self._on_group_changed()
        self._status(f"{len(self.groups)} 个安全组 · 已刷新")

    def _on_group_changed(self) -> None:
        gid = self.group_id
        if gid is None:
            return
        bound = gid in self.bound_groups
        self.lbl_bind.setText("✅ 本机已在此组" if bound else "⚠ 本机不在此组")
        self.lbl_bind.setStyleSheet("color:#137333" if bound else "color:#c00")
        self.btn_bind.setEnabled(not bound)
        instances = self.instance_map.get(gid, [])
        self.instances = instances
        if instances:
            names = "、".join(item.get("vpsname", "?") for item in instances[:12])
            more = f" 等 {len(instances)} 台" if len(instances) > 12 else ""
            self.lbl_instances.setText(
                f"这个组还影响：{names}{more}　（改规则会一起生效，注意影响面）"
            )
            self.lbl_instances.setStyleSheet("color:#b06000")
        else:
            self.lbl_instances.setText("这个组还没绑定任何实例")
            self.lbl_instances.setStyleSheet("color:#888")
        self._load_rules()

    def _load_rules(self) -> None:
        gid = self.group_id
        if gid is None:
            return

        def job():
            return {
                IN: self.client.firewall.list_rules(gid, IN),
                OUT: self.client.firewall.list_rules(gid, OUT),
            }

        run_async(self, job, self._after_rules, self._fail)

    def _after_rules(self, rules: dict[str, list[FirewallRule]]) -> None:
        self.rules = rules
        for direction in self.tables:
            self._render(direction)
            self._update_portmap(direction)
            keep = self._pending_select.pop(direction, None)
            if keep is not None:
                self._select_rule_by_id(direction, keep)
            else:
                self.panels[direction].reset_new(self.rules[direction])
        self._refresh_issues()
        if self._pending_status:
            self._status(self._pending_status)
            self._pending_status = None
        else:
            self._status(
                f"入方向 {len(rules[IN])} 条 · 出方向 {len(rules[OUT])} 条"
            )

    # ------------------------------------------------------------ 渲染
    def _render(self, direction: str) -> None:
        table = self.tables[direction]
        flt, cb_action, cb_proto = self.filters[direction]
        rows = [
            r for r in self.rules[direction]
            if _match_filter(r, flt.text(), cb_action.currentText(), cb_proto.currentText())
        ]
        rows.sort(key=lambda r: r.weight, reverse=True)

        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for row, rule in enumerate(rows):
            values = [
                rule.weight,
                ACTION_BACK.get(rule.action, rule.action),
                rule.protocol or "全部",
                rule.port or "全部",
                rule.ip or "全部",
                rule.description,
                rule.created_at,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem()
                if col == 0:
                    item.setData(Qt.DisplayRole, int(value))
                else:
                    item.setText(str(value))
                if col == 1:
                    item.setForeground(Qt.darkGreen if rule.is_allow else Qt.red)
                if col == 3 and (rule.port in ("", "1-65535")):
                    item.setForeground(QColor("#b06000"))
                if col == 4 and rule.ip in ("", "0.0.0.0/0"):
                    item.setForeground(QColor("#b06000"))
                table.setItem(row, col, item)
            table.setItem(row, ID_COLUMN, QTableWidgetItem(str(rule.id)))
        table.setSortingEnabled(True)
        table.sortItems(0, Qt.DescendingOrder)
        table.horizontalHeader().setSortIndicator(0, Qt.DescendingOrder)
        self._update_drag(direction)

    def _update_portmap(self, direction: str) -> None:
        protocol = self.map_protos[direction].currentText()
        rules = self.rules[direction]
        self.portmaps[direction].set_rules(rules, protocol)
        segments = resolve_port_map(rules, protocol)

        def short(text: str, limit: int = 4) -> str:
            parts = [p for p in text.split(", ") if p]
            if not parts:
                return "无"
            if len(parts) > limit:
                return ", ".join(parts[:limit]) + f" …共 {len(parts)} 段"
            return ", ".join(parts)

        allow = short(summarize_segments(segments, "允许"))
        deny = short(summarize_segments(segments, "拒绝"))
        allow_count = sum(s.end - s.start + 1 for s in segments if s.is_allow)
        deny_count = sum(s.end - s.start + 1 for s in segments if not s.is_allow)
        self.summaries[direction].setText(
            f"<b style='color:#2e9e5b'>放行 {allow_count} 个端口</b>：{allow}　"
            f"<b style='color:#d64545'>拒绝 {deny_count} 个端口</b>：{deny}"
        )

    # ------------------------------------------------------------ 选中/编辑
    def _selected(self, direction: str) -> list[FirewallRule]:
        table = self.tables[direction]
        by_id = {r.id: r for r in self.rules[direction]}
        out = []
        for index in table.selectionModel().selectedRows():
            item = table.item(index.row(), ID_COLUMN)
            if item is None:
                continue
            rule = by_id.get(int(item.text()))
            if rule is not None:
                out.append(rule)
        return sorted(out, key=lambda r: r.weight, reverse=True)

    def _on_selection(self, direction: str) -> None:
        if self._selection_guard:
            return
        selected = self._selected(direction)
        panel = self.panels[direction]
        target = selected[0] if len(selected) == 1 else None

        if panel.is_dirty():
            same = (
                target is not None
                and panel.current is not None
                and target.id == panel.current.id
            )
            if not same:
                if QMessageBox.question(
                    self, "未保存的修改",
                    "右侧编辑面板还有改动没保存，确定放弃吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
                ) != QMessageBox.Yes:
                    self._restore_selection(direction, panel)
                    return
                panel._set_dirty(False)

        panel.btn_save.setEnabled(True)
        if len(selected) == 1:
            panel.set_rule(selected[0])
            ordered = sorted(
                self.rules[direction], key=lambda r: (-r.weight, r.id)
            )
            rank = next(
                (i + 1 for i, r in enumerate(ordered) if r.id == selected[0].id), 0
            )
            panel.set_rank(rank, len(ordered))
        elif not selected:
            panel.reset_new(self.rules[direction])
        else:
            panel.show_multi(len(selected))

    def _restore_selection(self, direction: str, panel: RuleEditorPanel) -> None:
        """用户选择「不放弃」时，把表格选中恢复成正在编辑的那条。"""
        self._selection_guard = True
        try:
            if panel.current is not None:
                self._select_rule_by_id(direction, panel.current.id)
            else:
                self.tables[direction].clearSelection()
        finally:
            self._selection_guard = False

    def closeEvent(self, event) -> None:
        dirty = [d for d, p in self.panels.items() if p.is_dirty()]
        if dirty and QMessageBox.question(
            self, "未保存的修改",
            "还有规则改动没保存，关闭窗口会丢弃，继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            event.ignore()
            return
        super().closeEvent(event)

    # ------------------------------------------------------------ 优先级
    def _direction_of_tab(self) -> str | None:
        idx = self.tabs.currentIndex()
        if idx == 0:
            return IN
        if idx == 1:
            return OUT
        return None

    def _priority_current(self, action: str) -> None:
        direction = self._direction_of_tab()
        if direction:
            self._priority_action(direction, action)

    def _filters_active(self, direction: str) -> bool:
        flt, cb_action, cb_proto = self.filters[direction]
        return (
            bool(flt.text().strip())
            or cb_action.currentIndex() != 0
            or cb_proto.currentIndex() != 0
        )

    def _update_drag(self, direction: str) -> None:
        table = self.tables[direction]
        by_weight = table.horizontalHeader().sortIndicatorSection() == 0
        table.setDragEnabled(by_weight)
        table.setAcceptDrops(by_weight)
        table.setToolTip(
            "拖动行可直接调优先级"
            if by_weight else "先按「优先级」列排序，才能拖动调整顺序"
        )

    def _priority_action(self, direction: str, action: str) -> None:
        rules = self.rules[direction]
        if not rules:
            return
        ordered = sorted(rules, key=lambda r: (-r.weight, r.id))

        if action == "renumber":
            if self._filters_active(direction):
                self._status("先清空过滤再重排")
                return
            self._renumber(direction, ordered)
            return

        rule = self.panels[direction].current
        if rule is None:
            self._status("先选中一条规则，再用 置顶/上移/下移/置底 调优先级")
            return
        idx = next((i for i, r in enumerate(ordered) if r.id == rule.id), -1)
        if idx < 0:
            return

        top_weight = max(r.weight for r in ordered)
        bottom_weight = min(r.weight for r in ordered)

        if action == "top":
            if idx == 0:
                self._status("已经在最前面")
                return
            if top_weight + 10 <= 65535:
                self._update_weights(direction, [(rule, top_weight + 10)])
            else:
                self._renumber(direction, [rule, *[r for r in ordered if r.id != rule.id]])
        elif action == "bottom":
            if idx == len(ordered) - 1:
                self._status("已经在最末尾")
                return
            if bottom_weight - 10 >= 1:
                self._update_weights(direction, [(rule, bottom_weight - 10)])
            else:
                self._renumber(direction, [*[r for r in ordered if r.id != rule.id], rule])
        else:
            step = -1 if action == "up" else 1
            target = idx + step
            if target < 0 or target >= len(ordered):
                self._status("已经到头了")
                return
            other = ordered[target]
            if rule.weight == other.weight:
                moved = list(ordered)
                moved.insert(target, moved.pop(idx))
                self._renumber(direction, moved)
            else:
                self._update_weights(direction, [(rule, other.weight), (other, rule.weight)])

    def _apply_order(self, direction: str, ordered_ids: list[int]) -> None:
        rules = self.rules[direction]
        if not rules:
            return
        if self._filters_active(direction):
            self._status("有过滤条件，先清空过滤再拖动排序")
            self._load_rules()
            return
        by_id = {r.id: r for r in rules}
        ordered = [by_id[i] for i in ordered_ids if i in by_id]
        ordered += [r for r in rules if r.id not in ordered_ids]
        self._renumber(direction, ordered, action_text="按拖动顺序重排")

    def _renumber(
        self, direction: str, ordered: list[FirewallRule], action_text: str = "重排优先级"
    ) -> None:
        weights = renumber_weights(ordered)
        pairs = [(r, weights[r.id]) for r in ordered if weights[r.id] != r.weight]
        if not pairs:
            self._status("已经是最整齐的 10/20/30…，无需重排")
            return
        self._status(f"{action_text}：更新 {len(pairs)} 条…")
        self._update_weights(direction, pairs, done_text=f"{action_text}完成")

    def _update_weights(
        self,
        direction: str,
        pairs: list[tuple[FirewallRule, int]],
        done_text: str = "优先级已调整",
    ) -> None:
        gid = self.group_id
        if gid is None or not pairs:
            return

        def job():
            for rule, weight in pairs:
                self.client.firewall.update_rule(
                    gid, rule.id,
                    direction=direction,
                    port=rule.port or "1-65535",
                    protocol=rule.protocol or "TCP",
                    action=rule.action,
                    ip=rule.ip or "0.0.0.0/0",
                    weight=weight,
                    description=rule.description,
                )

        keep_id = self.panels[direction].current.id if self.panels[direction].current else None

        def done(_: object) -> None:
            self._pending_status = done_text
            if keep_id is not None:
                self._pending_select[direction] = keep_id
            self._load_rules()

        run_async(self, job, done, self._fail)

    def _select_rule_by_id(self, direction: str, rule_id: int) -> None:
        table = self.tables[direction]
        for row in range(table.rowCount()):
            item = table.item(row, ID_COLUMN)
            if item and item.text() == str(rule_id):
                table.selectRow(row)
                table.scrollToItem(item)
                return
        self._status(f"规则 #{rule_id} 不在当前筛选结果里")

    def _new_rule(self, direction: str) -> None:
        self.tables[direction].clearSelection()
        self.panels[direction].reset_new(self.rules[direction])
        self.panels[direction].sp_port.setFocus()

    def _save_from_panel(
        self, direction: str, payloads: list[dict[str, Any]], rule: FirewallRule | None
    ) -> None:
        gid = self.group_id
        if gid is None:
            return
        if rule is None:
            def job():
                for payload in payloads:
                    self.client.firewall.add_rule(gid, **payload)
            msg = f"已添加 {len(payloads)} 条"
        else:
            payload = payloads[0]
            run_async(
                self,
                lambda: self.client.firewall.update_rule(
                    gid, rule.id,
                    direction=direction,
                    port=payload["port"],
                    protocol=payload["protocol"],
                    action=payload["action"],
                    ip=payload["ip"],
                    weight=payload["weight"],
                    description=payload["description"],
                ),
                lambda _: (
                    self._status(f"已修改 #{rule.id}"),
                    self._pending_select.__setitem__(direction, rule.id),
                    self._load_rules(),
                ),
                self._fail,
            )
            return

        run_async(
            self, job,
            lambda _: (
                self._status(msg),
                self.panels[direction].reset_new(self.rules[direction]),
                self._load_rules(),
            ),
            self._fail,
        )

    def _delete_one(self, direction: str, rule: FirewallRule) -> None:
        gid = self.group_id
        if gid is None:
            return
        if QMessageBox.question(
            self, "删除规则", f"确认删除？\n\n{_format_rule(rule)}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        run_async(
            self,
            lambda: self.client.firewall.delete_rules(gid, [rule.id]),
            lambda _: (self._status(f"已删除 #{rule.id}"), self._load_rules()),
            self._fail,
        )

    def _open_detail(self, direction: str) -> None:
        selected = self._selected(direction)
        if not selected:
            return
        dlg = RuleDetailDialog(selected[0], direction, self)
        dlg.exec()
        if dlg.result_action == "copy":
            self.panels[direction].set_rule(selected[0], as_copy=True)

    def _delete_selected(self, direction: str) -> None:
        gid = self.group_id
        selected = self._selected(direction)
        if gid is None or not selected:
            self._status("选中要删的规则")
            return
        preview = "\n".join(_format_rule(r) for r in selected[:10])
        if len(selected) > 10:
            preview += f"\n… 共 {len(selected)} 条"
        if QMessageBox.question(
            self, "删除规则",
            f"确认删除 {len(selected)} 条规则？\n\n{preview}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        ids = [r.id for r in selected]
        run_async(
            self,
            lambda: self.client.firewall.delete_rules(gid, ids),
            lambda _: (self._status(f"已删除 {len(ids)} 条"), self._load_rules()),
            self._fail,
        )

    def _quick_add(self, direction: str) -> None:
        gid = self.group_id
        if gid is None:
            return
        dlg = QuickAddDialog(direction, self)
        if dlg.exec() != QDialog.Accepted:
            return
        payloads = dlg.payloads()
        if not payloads:
            self._status("没勾选任何服务")
            return

        def job():
            for payload in payloads:
                self.client.firewall.add_rule(gid, **payload)

        run_async(
            self, job,
            lambda _: (self._status(f"已添加 {len(payloads)} 条"), self._load_rules()),
            self._fail,
        )

    def _bulk_modify(self, direction: str) -> None:
        gid = self.group_id
        selected = self._selected(direction)
        if gid is None or not selected:
            self._status("先多选规则")
            return
        menu = QMenu(self)
        act_weight = menu.addAction(f"改优先级（{len(selected)} 条）")
        act_ip = menu.addAction("改授权 IP")
        act_action = menu.addAction("改行为（允许/拒绝）")
        act_split = menu.addAction("把范围端口拆成单端口规则")
        act_to_out = menu.addAction("复制到反方向")
        chosen = menu.exec(self.cursor().pos())
        if chosen is None:
            return

        updates: list[tuple[FirewallRule, dict[str, Any]]] = []
        if chosen is act_weight:
            value, ok = QInputDialog.getInt(self, "批量改优先级", "新的优先级：", 200, 1, 65535)
            if not ok:
                return
            updates = [(r, {"weight": value + i}) for i, r in enumerate(selected)]
        elif chosen is act_ip:
            value, ok = QInputDialog.getText(self, "批量改授权IP", "新的授权IP：", text="0.0.0.0/0")
            if not ok:
                return
            try:
                ip = normalize_ip(value)
            except ValueError as exc:
                QMessageBox.warning(self, "IP", str(exc))
                return
            updates = [(r, {"ip": ip}) for r in selected]
        elif chosen is act_action:
            label, ok = QInputDialog.getItem(self, "批量改行为", "行为：", ["允许", "拒绝"])
            if not ok:
                return
            updates = [(r, {"action": ACTION_MAP[label]}) for r in selected]
        elif chosen is act_split:
            total = sum(
                sum(hi - lo + 1 for lo, hi in parse_port_spec(r.port or "1-65535"))
                for r in selected
            )
            if total > 512:
                QMessageBox.warning(self, "太多了", f"会生成 {total} 条规则，建议保留范围。")
                return
            if QMessageBox.question(
                self, "拆分端口", f"拆成 {total} 条单端口规则，原规则会被删除，继续？"
            ) != QMessageBox.Yes:
                return
            rules = list(selected)

            def job_split():
                for r in rules:
                    for lo, hi in parse_port_spec(r.port or "1-65535"):
                        for port in range(lo, hi + 1):
                            self.client.firewall.add_rule(
                                gid,
                                port=str(port),
                                protocol=r.protocol or "TCP",
                                action="Allow" if r.is_allow else "Deny",
                                ip=r.ip or "0.0.0.0/0",
                                direction=direction,
                                weight=r.weight,
                                description=r.description,
                            )
                    self.client.firewall.delete_rules(gid, [r.id])

            run_async(
                self, job_split,
                lambda _: (self._status(f"已拆分 {total} 条"), self._load_rules()),
                self._fail,
            )
            return
        elif chosen is act_to_out:
            other = OUT if direction == IN else IN

            def job_copy():
                for r in selected:
                    self.client.firewall.add_rule(
                        gid,
                        port=r.port or "1-65535",
                        protocol=r.protocol or "TCP",
                        action="Allow" if r.is_allow else "Deny",
                        ip=r.ip or "0.0.0.0/0",
                        direction=other,
                        weight=r.weight,
                        description=r.description,
                    )

            run_async(
                self, job_copy,
                lambda _: (self._status(f"已复制 {len(selected)} 条到反方向"), self._load_rules()),
                self._fail,
            )
            return
        else:
            return

        def job_update():
            for rule, changes in updates:
                payload: dict[str, Any] = {
                    "direction": direction,
                    "port": rule.port or "1-65535",
                    "protocol": rule.protocol or "TCP",
                    "action": rule.action,
                    "ip": rule.ip or "0.0.0.0/0",
                    "weight": rule.weight,
                    "description": rule.description,
                }
                payload.update(changes)
                self.client.firewall.update_rule(gid, rule.id, **payload)

        run_async(
            self, job_update,
            lambda _: (self._status(f"已修改 {len(updates)} 条"), self._load_rules()),
            self._fail,
        )

    # ------------------------------------------------------------ 右键/快捷键
    def _context_menu(self, direction: str, pos) -> None:
        table = self.tables[direction]
        selected = self._selected(direction)
        menu = QMenu(self)
        act_detail = menu.addAction("查看详情")
        act_edit = menu.addAction("在右侧编辑")
        act_copy = menu.addAction("复制一条")
        menu.addSeparator()
        act_del = menu.addAction("删除")
        menu.addSeparator()
        act_cp_port = menu.addAction("复制端口")
        act_cp_ip = menu.addAction("复制授权IP")
        act_cp_json = menu.addAction("复制为 JSON")
        for a in (act_detail, act_edit, act_copy, act_del, act_cp_port, act_cp_ip, act_cp_json):
            a.setEnabled(bool(selected))
        chosen = menu.exec(table.viewport().mapToGlobal(pos))
        if chosen is None or not selected:
            return
        rule = selected[0]
        if chosen is act_detail:
            self._open_detail(direction)
        elif chosen is act_edit:
            self.panels[direction].set_rule(rule)
            self.panels[direction].sp_weight.setFocus()
        elif chosen is act_copy:
            self.panels[direction].set_rule(rule, as_copy=True)
        elif chosen is act_del:
            self._delete_selected(direction)
        elif chosen is act_cp_port:
            self._to_clipboard(rule.port or "1-65535")
        elif chosen is act_cp_ip:
            self._to_clipboard(rule.ip or "0.0.0.0/0")
        elif chosen is act_cp_json:
            self._to_clipboard(json.dumps(
                {
                    "action": ACTION_BACK.get(rule.action, rule.action),
                    "protocol": rule.protocol,
                    "port": rule.port,
                    "ip": rule.ip,
                    "weight": rule.weight,
                    "description": rule.description,
                },
                ensure_ascii=False, indent=1,
            ))

    def _to_clipboard(self, text: str) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(text)
        self._status(f"已复制：{text[:60]}")

    def _delete_current_selection(self) -> None:
        idx = self.tabs.currentIndex()
        if idx in (0, 1):
            self._delete_selected(IN if idx == 0 else OUT)

    # ------------------------------------------------------------ 导入导出
    def _export(self, direction: str) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "导出规则",
            str(Path.home() / f"landui-firewall-{self.server.name}-{direction}.json"),
            "JSON (*.json)",
        )
        if not path:
            return
        data = [
            {
                "action": ACTION_BACK.get(r.action, r.action),
                "protocol": r.protocol,
                "port": r.port,
                "ip": r.ip,
                "weight": r.weight,
                "description": r.description,
            }
            for r in self.rules[direction]
        ]
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
        self._status(f"已导出 {len(data)} 条 -> {path}")

    def _import(self, direction: str) -> None:
        gid = self.group_id
        path, _ = QFileDialog.getOpenFileName(self, "导入规则", str(Path.home()), "JSON (*.json)")
        if not path or gid is None:
            return
        try:
            data = json.loads(Path(path).read_text("utf-8"))
            if not isinstance(data, list):
                raise TypeError("JSON 顶层应是数组")
        except (OSError, ValueError, TypeError) as exc:
            QMessageBox.warning(self, "导入失败", str(exc))
            return

        prepared: list[dict[str, Any]] = []
        for item in data:
            try:
                port = str(item.get("port") or "1-65535")
                validate_ports(port)
                ip = normalize_ip(str(item.get("ip") or "0.0.0.0/0"))
            except ValueError as exc:
                QMessageBox.warning(self, "导入失败", f"{item}\n{exc}")
                return
            prepared.append(
                {
                    "port": port,
                    "protocol": str(item.get("protocol") or "TCP"),
                    "action": ACTION_MAP.get(str(item.get("action") or "允许"), "Allow"),
                    "ip": ip,
                    "direction": direction,
                    "weight": int(item.get("weight") or 200),
                    "description": str(item.get("description") or ""),
                }
            )
        if QMessageBox.question(
            self, "导入确认", f"将向当前安全组添加 {len(prepared)} 条规则，继续？"
        ) != QMessageBox.Yes:
            return

        def job():
            for payload in prepared:
                self.client.firewall.add_rule(gid, **payload)

        run_async(
            self, job,
            lambda _: (self._status(f"已导入 {len(prepared)} 条"), self._load_rules()),
            self._fail,
        )

    # ------------------------------------------------------------ 安全组
    def _create_group(self) -> None:
        dlg = GroupDialog("新建安全组", parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        name, desc = dlg.values()
        if not name:
            QMessageBox.warning(self, "新建", "名称不能为空")
            return
        run_async(
            self,
            lambda: self.client.firewall.create_group(name, desc),
            lambda _: (self._status(f"已创建 {name}"), self.reload(groups_too=True)),
            self._fail,
        )

    def _rename_group(self) -> None:
        idx = self.cb_group.currentIndex()
        gid = self.group_id
        if gid is None or idx < 0:
            return
        group = self.groups[idx]
        dlg = GroupDialog("重命名安全组", group.name, group.description, self)
        if dlg.exec() != QDialog.Accepted:
            return
        name, desc = dlg.values()
        if not name:
            QMessageBox.warning(self, "重命名", "名称不能为空")
            return
        run_async(
            self, lambda: self.client.firewall.update_group(gid, name, desc),
            lambda _: (self._status("已重命名"), self.reload(groups_too=True)),
            self._fail,
        )

    def _delete_group(self) -> None:
        idx = self.cb_group.currentIndex()
        gid = self.group_id
        if gid is None or idx < 0:
            return
        group = self.groups[idx]
        if group.vps_count:
            QMessageBox.warning(
                self, "不能删",
                f"这个组还绑着 {group.vps_count} 台实例，先去网页解绑（或换组）再删。",
            )
            return
        text, ok = QInputDialog.getText(
            self, "删除安全组",
            f"删除会清空组内 {group.rule_count} 条规则，且不可恢复。\n"
            f"请输入组名「{group.name}」确认：",
        )
        if not ok or text.strip() != group.name:
            return
        run_async(
            self, lambda: self.client.firewall.delete_group(gid),
            lambda _: (self._status("已删除"), self.reload(groups_too=True)),
            self._fail,
        )

    def _bind(self) -> None:
        gid = self.group_id
        if gid is None:
            return
        others = [g for g in self.groups if g.id != gid and g.id in self.bound_groups]
        note = ""
        if others:
            note = (
                f"\n\n注意：本机当前还在「{others[0].name}」，"
                "这个接口只做「加入」，不会自动退出旧组，请到网页确认。"
            )
        if QMessageBox.question(
            self, "加入安全组",
            f"把 {self.server.name} 加入「{self.cb_group.currentText()}」？{note}",
        ) != QMessageBox.Yes:
            return
        run_async(
            self,
            lambda: self.client.firewall.bind_instances(gid, [self.server.name]),
            lambda _: (self._status("已加入"), self.reload(groups_too=True)),
            self._fail,
        )

    # ------------------------------------------------------------ 诊断
    def _refresh_issues(self) -> None:
        if not hasattr(self, "txt_issues"):
            return
        issues = analyze_rules(self.rules[IN]) + analyze_rules(
            self.rules[OUT], broad_allow=False
        )
        if not issues:
            self.txt_issues.setPlainText("没发现明显问题。")
            self.tabs.setTabText(3, "诊断")
            return
        order = {"danger": 0, "warn": 1, "info": 2}
        lines = []
        for issue in sorted(issues, key=lambda i: order.get(i.level, 3)):
            icon = {"danger": "[危险]", "warn": "[警告]", "info": "[提示]"}.get(issue.level, "·")
            lines.append(f"{icon} {issue.message}")
        self.txt_issues.setPlainText("\n".join(lines))
        bad = sum(1 for i in issues if i.level in ("danger", "warn"))
        self.tabs.setTabText(3, f"诊断（{bad}）" if bad else "诊断")

    def _check_ports(self) -> None:
        text = self.ed_check_ports.text().strip()
        try:
            ranges = validate_ports(text)
        except ValueError as exc:
            QMessageBox.warning(self, "端口", str(exc))
            return
        direction = IN if self.cb_check_dir.currentIndex() == 0 else OUT
        protocol = self.cb_check_proto.currentText()
        rules = self.rules[direction]

        ports: list[int] = []
        for lo, hi in ranges:
            ports.extend(range(lo, hi + 1))
            if len(ports) > 200:
                ports = ports[:200]
                break

        self.tbl_check.setRowCount(len(ports))
        in_group = self.group_id in self.bound_groups
        for row, port in enumerate(ports):
            hit = effective_rule(rules, port, protocol)
            if hit is None:
                result, detail = "无规则 → 默认拒绝", "—"
                color = QColor("#c00")
                note = "可以点「新建」加一条"
            else:
                result = "放行" if hit.is_allow else "拒绝"
                detail = _format_rule(hit)
                color = QColor("#137333") if hit.is_allow else QColor("#c00")
                note = "" if hit.is_allow else "被该规则拦截"
            if not in_group:
                note = (note + "｜本机不在此组").strip("｜")
            for col, value in enumerate([port, result, detail, note]):
                item = QTableWidgetItem(str(value))
                if col == 1:
                    item.setForeground(color)
                self.tbl_check.setItem(row, col, item)
        self._refresh_issues()
        self._status(f"检查了 {len(ports)} 个端口（{'入' if direction == IN else '出'}方向 {protocol}）")

    def _on_tab_changed(self, index: int) -> None:
        if index == 2 and not self._acl_loaded:
            self._load_acl()
        elif index == 3:
            self._refresh_issues()

    # ------------------------------------------------------------ 单机 ACL
    def _load_acl(self) -> None:
        def job():
            return self.client.firewall.list_acl(self.server.id, self.server.name)

        run_async(self, job, self._after_acl, lambda m: self.lbl_acl.setText(m))

    def _after_acl(self, rules: list[AclRule]) -> None:
        self._acl_loaded = True
        self.acl_rules = rules
        self.tbl_acl.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            values = [
                rule.id, rule.weight, rule.direction, rule.action, rule.protocol,
                f"{rule.remote_ip or '*'} : {rule.remote_port or '*'}",
                f"{rule.local_ip or '*'} : {rule.local_port or '*'}",
            ]
            for col, value in enumerate(values):
                self.tbl_acl.setItem(row, col, QTableWidgetItem(str(value)))
        self.lbl_acl.setText(f"{len(rules)} 条策略（多数账号为空；权重不能重复）")

    def _add_acl(self) -> None:
        dlg = AclDialog(self.acl_rules, self)
        if dlg.exec() != QDialog.Accepted:
            return
        values = dlg.values()
        run_async(
            self,
            lambda: self.client.firewall.add_acl(self.server.id, self.server.name, **values),
            lambda _: (self.lbl_acl.setText("已添加"), self._load_acl()),
            self._fail,
        )

    def _delete_acl(self) -> None:
        rows = self.tbl_acl.selectionModel().selectedRows()
        if not rows:
            self.lbl_acl.setText("先选中策略")
            return
        ids = [int(self.tbl_acl.item(r.row(), 0).text()) for r in rows]
        if QMessageBox.question(self, "删除", f"删除 {len(ids)} 条 ACL 策略？") != QMessageBox.Yes:
            return

        def job():
            for acl_id in ids:
                self.client.firewall.delete_acl(acl_id)

        run_async(self, job, lambda _: (self.lbl_acl.setText("已删除"), self._load_acl()), self._fail)
