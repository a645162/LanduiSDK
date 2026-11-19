"""SSH 账号管理：一台服务器可以存多个用户/端口/认证方式。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from ui_common import run_async

from landui_sdk import LanduiClient
from landui_sdk.config import (
    AUTH_AGENT,
    AUTH_KEY,
    AUTH_LABELS,
    AUTH_PASSWORD,
    AppConfig,
    ServerProfile,
    SshAccount,
)
from landui_sdk.models import Server
from landui_sdk.ssh import SshTarget, test_connection

MODES = [AUTH_PASSWORD, AUTH_KEY, AUTH_AGENT]


class AccountEditDialog(QDialog):
    """新增/编辑一个 SSH 账号。"""

    def __init__(
        self,
        server: Server,
        account: SshAccount | None = None,
        *,
        client: LanduiClient | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.server = server
        self.client = client
        self.account = account
        self.setWindowTitle(("编辑账号 · " if account else "新增账号 · ") + server.name)
        self.setMinimumWidth(520)

        form = QFormLayout(self)
        self.ed_user = QLineEdit(account.user if account else "root")
        self.sp_port = QLineEdit(str(account.port if account else (server.ip and 22 or 22)))
        self.sp_port.setPlaceholderText("22")
        self.ed_label = QLineEdit(account.label if account else "")
        self.ed_label.setPlaceholderText("备注，例如「部署用」「只读」")
        form.addRow("用户名", self.ed_user)
        form.addRow("端口", self.sp_port)
        form.addRow("备注", self.ed_label)

        self.cb_mode = QComboBox()
        for mode in MODES:
            self.cb_mode.addItem(AUTH_LABELS[mode], mode)
        if account:
            self.cb_mode.setCurrentIndex(MODES.index(account.auth_mode)
                                         if account.auth_mode in MODES else 0)
        form.addRow("认证方式", self.cb_mode)

        self.stack = QStackedWidget()

        # 密码
        pw = QWidget()
        pw_l = QHBoxLayout(pw)
        pw_l.setContentsMargins(0, 0, 0, 0)
        self.ed_password = QLineEdit(account.password if account else "")
        self.ed_password.setEchoMode(QLineEdit.Password)
        self.ed_password.setPlaceholderText("登录密码")
        self.btn_cloud_pw = QPushButton("用云端密码")
        self.btn_cloud_pw.setToolTip("读取蓝队云记录的登录密码填入（可能已被你在系统里改过）")
        pw_l.addWidget(self.ed_password, 1)
        pw_l.addWidget(self.btn_cloud_pw)
        self.stack.addWidget(pw)

        # 密钥
        key = QWidget()
        key_l = QVBoxLayout(key)
        key_l.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.ed_key = QLineEdit(account.key_path if account else "")
        self.ed_key.setPlaceholderText("~/.ssh/id_ed25519")
        self.btn_browse = QPushButton("浏览…")
        row.addWidget(self.ed_key, 1)
        row.addWidget(self.btn_browse)
        key_l.addLayout(row)
        self.ed_passphrase = QLineEdit(account.key_passphrase if account else "")
        self.ed_passphrase.setEchoMode(QLineEdit.Password)
        self.ed_passphrase.setPlaceholderText("私钥口令（没有就留空）")
        key_l.addWidget(self.ed_passphrase)
        self.stack.addWidget(key)

        # Agent
        agent = QWidget()
        agent_l = QVBoxLayout(agent)
        agent_l.setContentsMargins(0, 0, 0, 0)
        agent_l.addWidget(QLabel("使用 ssh-agent / 默认私钥，不需要在这里存任何秘密。"))
        self.stack.addWidget(agent)

        form.addRow("凭据", self.stack)

        self.lbl_test = QLabel("")
        self.lbl_test.setWordWrap(True)
        self.lbl_test.setStyleSheet("color:#666")
        form.addRow("测试", self.lbl_test)

        row2 = QHBoxLayout()
        self.btn_test = QPushButton("测试连接")
        self.btn_test_all = QPushButton("保存并关闭")
        row2.addWidget(self.btn_test)
        row2.addStretch(1)
        form.addRow("", row2)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("保存")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        form.addRow("", buttons)
        buttons.accepted.connect(self._on_ok)
        buttons.rejected.connect(self.reject)

        self.cb_mode.currentIndexChanged.connect(
            lambda i: self.stack.setCurrentIndex(i)
        )
        self.stack.setCurrentIndex(self.cb_mode.currentIndex())
        self.btn_browse.clicked.connect(self._browse_key)
        self.btn_cloud_pw.clicked.connect(self._fill_cloud_password)
        self.btn_test.clicked.connect(self._test)

    # ------------------------------------------------------------------
    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择私钥", str(Path.home() / ".ssh"), "私钥 (*)"
        )
        if path:
            self.ed_key.setText(path)

    def _fill_cloud_password(self) -> None:
        if self.client is None:
            QMessageBox.information(self, "提示", "当前没有登录态，无法读取云端密码")
            return
        try:
            self.ed_password.setText(self.client.cloud.get_ssh_password(self.server.id))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "读取失败", str(exc))

    def value(self) -> SshAccount:
        mode = self.cb_mode.currentData()
        try:
            port = int(self.sp_port.text().strip() or "22")
        except ValueError:
            port = 22
        return SshAccount(
            user=self.ed_user.text().strip() or "root",
            port=port,
            auth_mode=mode,
            password=self.ed_password.text() if mode == AUTH_PASSWORD else "",
            key_path=self.ed_key.text().strip() if mode == AUTH_KEY else "",
            key_passphrase=self.ed_passphrase.text() if mode == AUTH_KEY else "",
            label=self.ed_label.text().strip(),
        )

    def _target(self) -> SshTarget:
        acc = self.value()
        return SshTarget(
            host=self.server.ip,
            port=acc.port,
            user=acc.user,
            password=acc.password,
            key_path=acc.key_path,
            key_passphrase=acc.key_passphrase,
        )

    def _test(self) -> None:
        target = self._target()
        self.lbl_test.setText(f"正在连接 {target.address}:{target.port} …")
        self.lbl_test.setStyleSheet("color:#666")

        def done(result: tuple[bool, str]) -> None:
            ok, message = result
            if ok:
                self.lbl_test.setText(f"✅ 连接成功：{message}")
                self.lbl_test.setStyleSheet("color:#137333")
            else:
                self.lbl_test.setText("❌ " + message[-300:])
                self.lbl_test.setStyleSheet("color:#c00")

        run_async(self, lambda: test_connection(target), done, lambda m: self.lbl_test.setText(m))

    def _on_ok(self) -> None:
        acc = self.value()
        if not acc.user:
            QMessageBox.warning(self, "检查一下", "用户名不能为空")
            return
        if acc.auth_mode == AUTH_KEY and not acc.key_path:
            QMessageBox.warning(self, "检查一下", "选了密钥认证，但没指定私钥文件")
            return
        if acc.auth_mode == AUTH_KEY and not Path(acc.key_path).expanduser().exists():
            QMessageBox.warning(self, "检查一下", f"私钥不存在：{acc.key_path}")
            return
        self.accept()


class SshAccountsDialog(QDialog):
    """一台服务器的账号列表：增删改、设默认、测试。"""

    def __init__(
        self,
        server: Server,
        config: AppConfig,
        client: LanduiClient | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.server = server
        self.config = config
        self.client = client
        self.profile: ServerProfile = config.get(server.id)
        self.setWindowTitle(f"SSH 账号 · {server.name} ({server.ip})")
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowSystemMenuHint
        )
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setSizeGripEnabled(True)
        self.resize(760, 460)

        v = QVBoxLayout(self)
        v.addWidget(
            QLabel("同一台服务器可以有多个登录用户；双击可编辑，连接时会让你选。")
        )

        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["用户名", "端口", "认证方式", "备注", "默认"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl.setAlternatingRowColors(True)
        v.addWidget(self.tbl, 1)

        bar = QHBoxLayout()
        self.btn_add = QPushButton("新增账号")
        self.btn_edit = QPushButton("编辑")
        self.btn_del = QPushButton("删除")
        self.btn_default = QPushButton("设为默认")
        bar.addWidget(self.btn_add)
        bar.addWidget(self.btn_edit)
        bar.addWidget(self.btn_del)
        bar.addWidget(self.btn_default)
        bar.addStretch(1)
        v.addLayout(bar)

        bottom = QHBoxLayout()
        self.lbl_tip = QLabel("")
        self.lbl_tip.setStyleSheet("color:#888")
        bottom.addWidget(self.lbl_tip, 1)
        btn_close = QPushButton("关闭")
        bottom.addWidget(btn_close)
        v.addLayout(bottom)

        self.btn_add.clicked.connect(self._add)
        self.btn_edit.clicked.connect(self._edit)
        self.btn_del.clicked.connect(self._delete)
        self.btn_default.clicked.connect(self._set_default)
        self.tbl.doubleClicked.connect(lambda _i: self._edit())
        btn_close.clicked.connect(self.accept)

        self._reload()

    # ------------------------------------------------------------------
    def _reload(self) -> None:
        self.profile.normalize()
        accounts = self.profile.accounts
        self.tbl.setRowCount(len(accounts))
        for row, acc in enumerate(accounts):
            values = [
                acc.user,
                acc.port,
                acc.auth_label,
                acc.label,
                "默认" if acc.user == self.profile.default_account else "",
            ]
            for col, value in enumerate(values):
                self.tbl.setItem(row, col, QTableWidgetItem(str(value)))
        self.lbl_tip.setText(f"{len(accounts)} 个账号")

    def _selected(self) -> SshAccount | None:
        rows = self.tbl.selectionModel().selectedRows()
        if not rows:
            return None
        name = self.tbl.item(rows[0].row(), 0).text()
        return self.profile.account(name)

    def _add(self) -> None:
        dlg = AccountEditDialog(self.server, None, client=self.client, parent=self)
        if dlg.exec() == QDialog.Accepted:
            self.profile.upsert_account(dlg.value())
            self.config.save()
            self._reload()

    def _edit(self) -> None:
        acc = self._selected()
        if acc is None:
            return
        dlg = AccountEditDialog(self.server, acc, client=self.client, parent=self)
        if dlg.exec() == QDialog.Accepted:
            self.profile.upsert_account(dlg.value())
            self.config.save()
            self._reload()

    def _delete(self) -> None:
        acc = self._selected()
        if acc is None:
            return
        if QMessageBox.question(self, "删除", f"删除账号 {acc.user}？") != QMessageBox.Yes:
            return
        self.profile.remove_account(acc.user)
        self.config.save()
        self._reload()

    def _set_default(self) -> None:
        acc = self._selected()
        if acc is None:
            return
        self.profile.default_account = acc.user
        self.config.save()
        self._reload()
