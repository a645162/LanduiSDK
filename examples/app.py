#!/usr/bin/env python3
"""蓝队云本地运维台（PySide6 + requests + landui-sdk）。

功能：
* 云服务器列表 / 状态自动刷新
* 一键拉起 SSH（自动读实例的 SSH 端口，密码可本地缓存）
* 开机 / 关机 / 重启（重启要短信验证码）
* 安全组防火墙：查看、开端口、删规则
* 单机 ACL 硬防查看

运行::

    uv run --extra gui python examples/app.py
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool, QTimer, Signal
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from firewall_window import FirewallWindow
from ssh_dialog import SshAccountsDialog
from ui_common import run_async

from landui_sdk import APIError, CaptchaRequired, LanduiClient
from landui_sdk.config import AUTH_PASSWORD, AppConfig, SshAccount
from landui_sdk.credentials import Credentials, CredentialStore
from landui_sdk.models import Server
from landui_sdk.ssh import (
    LAUNCHERS,
    SshTarget,
    launch_ssh,
    launcher_available,
    test_connection,
)

AUTH_FILE = Path("~/.config/landui-sdk/auth.json").expanduser()


# ---------------------------------------------------------------- 登录窗口
class ClickableLabel(QLabel):
    """点一下就发 clicked 的标签，用来做「点击刷新验证码」。"""

    clicked = Signal()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class LoginDialog(QDialog):
    def __init__(
        self,
        client: LanduiClient,
        parent: QWidget | None = None,
        captcha: CaptchaRequired | None = None,
    ):
        super().__init__(parent)
        self.client = client
        self.store = CredentialStore()
        self._captcha_id = captcha.captcha_id if captcha else ""
        self.setWindowTitle("蓝队云登录")
        self.setMinimumWidth(420)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        self.tabs = tabs
        root.addWidget(tabs)

        # --- 账号密码（默认页）
        w2 = QWidget()
        f2 = QFormLayout(w2)
        self.ed_user = QLineEdit()
        self.ed_pass = QLineEdit()
        self.ed_pass.setEchoMode(QLineEdit.Password)
        self.ed_captcha = QLineEdit()
        self.ed_captcha.setPlaceholderText("看上面的图填写，点图可刷新")
        self.chk_user = QCheckBox("记住账号")
        self.chk_pass = QCheckBox("记住密码（本机明文，权限 0600）")
        f2.addRow("账号", self.ed_user)
        f2.addRow("密码", self.ed_pass)

        # 验证码区域：默认折叠，服务端明确要了才显示
        self.captcha_box = QWidget()
        cap_l = QVBoxLayout(self.captcha_box)
        cap_l.setContentsMargins(0, 0, 0, 0)
        cap_l.setSpacing(4)
        cap_top = QHBoxLayout()
        self.lbl_captcha = ClickableLabel()
        self.lbl_captcha.setToolTip("点击刷新验证码")
        self.lbl_captcha.setCursor(Qt.PointingHandCursor)
        self.lbl_captcha.setMinimumSize(120, 40)
        self.lbl_captcha.setStyleSheet("border:1px solid #ddd; background:#fff")
        self.btn_captcha = QPushButton("换一张")
        cap_top.addWidget(self.lbl_captcha)
        cap_top.addWidget(self.btn_captcha)
        cap_top.addStretch(1)
        cap_l.addLayout(cap_top)
        cap_bottom = QHBoxLayout()
        cap_bottom.addWidget(QLabel("验证码"))
        cap_bottom.addWidget(self.ed_captcha, 1)
        cap_l.addLayout(cap_bottom)
        f2.addRow(self.captcha_box)
        remember_row = QHBoxLayout()
        remember_row.addWidget(self.chk_user)
        remember_row.addWidget(self.chk_pass)
        remember_row.addStretch(1)
        f2.addRow("", remember_row)
        self.captcha_box.setVisible(False)

        # --- Cookie 导入
        w1 = QWidget()
        l1 = QVBoxLayout(w1)
        l1.addWidget(QLabel(
            "先在 Chrome 里登录 landui.com，然后这里一键导入：\n"
            "Chrome 需带 --remote-debugging-port=9222 启动（本工具会自动尝试）。"
        ))
        row = QHBoxLayout()
        btn_chrome = QPushButton("从 Chrome 导入")
        btn_file = QPushButton("从文件导入…")
        row.addWidget(btn_chrome)
        row.addWidget(btn_file)
        l1.addLayout(row)
        self.lbl_auth = QLabel(str(AUTH_FILE))
        self.lbl_auth.setStyleSheet("color:#888")
        l1.addWidget(self.lbl_auth)
        l1.addStretch(1)

        tabs.addTab(w2, "账号密码")
        tabs.addTab(w1, "Cookie")
        tabs.setCurrentIndex(0)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("登录")
        self.buttons.button(QDialogButtonBox.Cancel).setText("取消")
        root.addWidget(self.buttons)

        # 预填已保存的账号；勾了「记住密码」就把密码也填进输入框（显示为圆点）
        saved = self.store.load()
        if saved:
            self.ed_user.setText(saved.username)
            self.chk_user.setChecked(True)
            if saved.has_password:
                self.ed_pass.setText(saved.password)
                self.chk_pass.setChecked(True)
        if captcha:
            self._show_captcha(captcha)
        self.chk_pass.toggled.connect(
            lambda on: self.chk_user.setChecked(True) if on else None
        )
        self.chk_user.toggled.connect(
            lambda on: None if on else self.chk_pass.setChecked(False)
        )
        self.btn_captcha.clicked.connect(self._load_captcha)
        self.lbl_captcha.clicked.connect(self._load_captcha)
        btn_chrome.clicked.connect(self._import_chrome)
        btn_file.clicked.connect(self._import_file)
        self.buttons.accepted.connect(self._login)
        self.buttons.rejected.connect(self.reject)

    # ------------------------------------------------------------------
    def _set_captcha(self, image: bytes) -> None:
        pix = QPixmap()
        if pix.loadFromData(image):
            self.lbl_captcha.setPixmap(pix)
            self.btn_captcha.setText("换一张")

    def _show_captcha(self, captcha: CaptchaRequired) -> None:
        self._captcha_id = captcha.captcha_id
        self._set_captcha(captcha.image)
        self.captcha_box.setVisible(True)
        self.tabs.setCurrentIndex(0)
        self.ed_captcha.setFocus()

    def _need_captcha(self, captcha: CaptchaRequired) -> None:
        """服务端要验证码：换图并提示，不当作错误弹框。"""
        self._show_captcha(captcha)
        self.ed_captcha.setPlaceholderText("请输入图中字符，然后点「登录」")

    def _load_captcha(self) -> None:
        try:
            captcha_id, image = self.client.get_captcha()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "验证码", str(exc))
            return
        self._captcha_id = captcha_id
        self._set_captcha(image)
        self.captcha_box.setVisible(True)
        self.ed_captcha.clear()

    def _import_chrome(self) -> None:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
            from import_cookies import fetch_cookies  # type: ignore

            cookies = [c for c in fetch_cookies(9222) if "landui" in c["domain"]]
            self.client.set_cookies({c["name"]: c["value"] for c in cookies})
            self.client.save_auth(AUTH_FILE)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "导入失败", str(exc))
            return
        if self.client.is_logged_in():
            self.accept()
        else:
            QMessageBox.warning(self, "导入失败", "Cookie 有了，但服务端说没登录，请重新在浏览器登录后重试")

    def _import_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择 auth.json", str(AUTH_FILE.parent))
        if not path:
            return
        try:
            self.client.load_auth(path)
            self.client.save_auth(AUTH_FILE)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "导入失败", str(exc))
            return
        if self.client.is_logged_in():
            self.accept()
        else:
            QMessageBox.warning(self, "导入失败", "登录态已失效")

    def _login(self) -> None:
        user = self.ed_user.text().strip()
        pwd = self.ed_pass.text()
        if not user or not pwd:
            QMessageBox.information(self, "提示", "填一下账号密码，或者用 Cookie 导入")
            return
        try:
            self.client.login(
                user,
                pwd,
                self.ed_captcha.text().strip(),
                getattr(self, "_captcha_id", ""),
            )
        except CaptchaRequired as cap:
            self._need_captcha(cap)
            return
        except APIError as exc:
            QMessageBox.warning(self, "登录", str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "登录失败", str(exc))
            return
        if not self.client.is_logged_in():
            QMessageBox.warning(self, "登录", "接口说成功了，但没有拿到控制台权限，试试 Cookie 导入")
            return
        self.client.save_auth(AUTH_FILE)
        remember_user = self.chk_user.isChecked()
        remember_pass = self.chk_pass.isChecked()
        if remember_pass:
            self.store.save(Credentials(user, pwd))
        elif remember_user:
            self.store.save(Credentials(user, ""))
        else:
            self.store.clear()
        self.accept()


# ---------------------------------------------------------------- 主窗口
class MainWindow(QMainWindow):
    def __init__(self, client: LanduiClient):
        super().__init__()
        self.client = client
        self.config = AppConfig.load()
        self.servers: list[Server] = []
        self._refreshing = False
        self._login_prompting = False
        # 登录态坏掉后进入「静默」：不再弹框、不再自动请求，直到手动登录成功
        self._auth_broken = False
        self._relogin_prompted = False
        self.setWindowTitle("蓝队云运维台 · 非官方第三方")
        self.resize(1180, 700)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        toolbar = QHBoxLayout()
        self.btn_refresh = QPushButton("刷新")
        self.btn_ssh = QPushButton("打开 SSH")
        self.btn_copy = QPushButton("复制 SSH 命令")
        self.btn_on = QPushButton("开机")
        self.btn_off = QPushButton("关机")
        self.btn_restart = QPushButton("重启")
        self.btn_fw = QPushButton("云防火墙")
        self.btn_pwd = QPushButton("读取密码")
        self.btn_test = QPushButton("测试 SSH")
        self.btn_settings = QPushButton("设置")
        self.btn_login = QPushButton("重新登录")
        for b in (self.btn_refresh, self.btn_ssh, self.btn_copy, self.btn_on,
                  self.btn_off, self.btn_restart, self.btn_fw, self.btn_pwd, self.btn_test):
            toolbar.addWidget(b)
        toolbar.addStretch(1)
        toolbar.addWidget(self.btn_login)
        toolbar.addWidget(self.btn_settings)
        root.addLayout(toolbar)

        self.tbl = QTableWidget(0, 8)
        self.tbl.setHorizontalHeaderLabels(
            ["名称", "状态", "公网IP", "SSH端口", "规格", "系统", "到期", "备注"]
        )
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.setSelectionMode(QTableWidget.SingleSelection)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tbl.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self.tbl, 1)

        self.detail = QLabel("选中一台服务器查看详情")
        self.detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.detail.setStyleSheet("padding:8px; background:#fafafa; border:1px solid #eee;")
        root.addWidget(self.detail)

        self.statusBar().showMessage("就绪")

        self.btn_refresh.clicked.connect(self.reload)
        self.tbl.itemSelectionChanged.connect(self._show_detail)
        self.tbl.doubleClicked.connect(lambda _: self.open_ssh())
        self.btn_ssh.clicked.connect(self.open_ssh)
        self.btn_copy.clicked.connect(self.copy_ssh)
        self.btn_on.clicked.connect(lambda: self._power("on"))
        self.btn_off.clicked.connect(lambda: self._power("off"))
        self.btn_restart.clicked.connect(self._restart)
        self.btn_fw.clicked.connect(self._firewall)
        self.btn_pwd.clicked.connect(self._read_password)
        self.btn_settings.clicked.connect(self._settings)
        self.btn_login.clicked.connect(self._relogin)
        self.btn_test.clicked.connect(self._test_ssh)

        self.timer = QTimer(self)
        self.timer.setInterval(20_000)
        self.timer.timeout.connect(lambda: self.reload(quiet=True))
        self.timer.start()
        self.reload()

    # ------------------------------------------------------------------ 数据
    def current_server(self) -> Server | None:
        rows = self.tbl.selectionModel().selectedRows() if self.tbl.selectionModel() else []
        if not rows:
            return None
        idx = rows[0].row()
        return self.servers[idx] if 0 <= idx < len(self.servers) else None

    def reload(self, quiet: bool = False) -> None:
        if self._refreshing or self._login_prompting:
            return  # 同一时间只允许一个刷新，避免失败时弹一堆框
        if self._auth_broken and quiet:
            return  # 登录态已坏，别让定时器继续打接口
        self._refreshing = True
        if not quiet:
            self.statusBar().showMessage("加载中…")

        def done(servers: list[Server]) -> None:
            self._refreshing = False
            self._auth_broken = False
            self._relogin_prompted = False
            self._fill_table(servers)
            if not self.timer.isActive():
                self.timer.start()

        def fail(msg: str) -> None:
            self._refreshing = False
            self._on_error(msg)

        run_async(self, lambda: self.client.cloud.all_servers(), done, fail)

    def _fill_table(self, servers: list[Server]) -> None:
        selected = self.current_server().id if self.current_server() else None
        self.servers = servers
        self.tbl.blockSignals(True)
        self.tbl.setRowCount(len(servers))
        for row, s in enumerate(servers):
            profile = self.config.get(s.id)
            account = profile.account()
            configured = bool(profile.accounts)
            port = account.port if account else "未配置"
            if account and len(profile.accounts) > 1:
                port = f"{account.port} ({account.user} +{len(profile.accounts) - 1})"
            values = [s.name, s.status, s.ip, port, s.cpu_mem, s.os, s.expire_at, profile.note]
            for col, v in enumerate(values):
                item = QTableWidgetItem(str(v))
                if col == 0:
                    item.setData(Qt.UserRole, s.id)
                if col == 1 and s.is_running:
                    item.setForeground(Qt.darkGreen)
                if not configured:
                    # 没保存过 SSH 账号：整行浅黄，提示去配置
                    item.setBackground(QColor("#fff4d6"))
                    item.setToolTip("还没有保存 SSH 账号：右键 →「SSH 账号管理…」")
                if col == 3 and not configured:
                    item.setForeground(QColor("#b06000"))
                self.tbl.setItem(row, col, item)
            if selected == s.id:
                self.tbl.selectRow(row)
        self.tbl.blockSignals(False)
        if selected:
            self._show_detail()
        missing = sum(1 for s in servers if not self.config.get(s.id).accounts)
        text = f"{len(servers)} 台服务器 · 已更新"
        if missing:
            text += f" · {missing} 台未配置 SSH（黄色行）"
        self.statusBar().showMessage(text)

    def _on_error(self, msg: str) -> None:
        if "登录" in msg or "NotLoggedIn" in msg:
            self._auth_broken = True
            self.timer.stop()
            if self._relogin_prompted:
                # 已经问过了，用户选了「不登录」——闭嘴，只留状态栏提示
                self.statusBar().showMessage("登录已失效，点右上角「重新登录」")
                return
            self._relogin_prompted = True
            self._prompt_relogin(msg)
            return
        self.statusBar().showMessage("加载失败：" + msg)

    def _prompt_relogin(self, msg: str) -> None:
        """登录失效只提示一次；之后进入静默，直到登录成功。"""
        if self._login_prompting:
            return
        self._login_prompting = True
        self.timer.stop()
        try:
            wants = QMessageBox.question(
                self, "登录失效", f"{msg}\n\n现在重新登录？"
            ) == QMessageBox.Yes
            if wants and LoginDialog(self.client, self).exec() == QDialog.Accepted:
                self._auth_broken = False
                self._relogin_prompted = False
                self._refreshing = False
                self.reload()
        finally:
            self._login_prompting = False
            if not self._auth_broken and not self.timer.isActive():
                self.timer.start()

    def _relogin(self) -> None:
        if LoginDialog(self.client, self).exec() == QDialog.Accepted:
            self._auth_broken = False
            self._relogin_prompted = False
            self._refreshing = False
            self.reload()

    def _show_detail(self) -> None:
        s = self.current_server()
        if not s:
            self.detail.setText("选中一台服务器查看详情")
            return
        profile = self.config.get(s.id)
        account = profile.account()
        if account:
            ssh_text = f"{account.user}@{s.ip}:{account.port}（{account.auth_label}）"
            if len(profile.accounts) > 1:
                ssh_text += f"　另有 {len(profile.accounts) - 1} 个账号"
        else:
            ssh_text = "未配置（右键 → SSH 账号管理）"
        self.detail.setText(
            f"<b>{s.name}</b>　{s.status}　{s.ip}　SSH {ssh_text}<br>"
            f"规格 {s.cpu_mem} · {s.bandwidth} · {s.os}<br>"
            f"到期 {s.expire_at}（{s.expire_hint}）　地域 {s.region}"
        )
        if not account:
            self._load_ssh_port(s)

    def _load_ssh_port(self, s: Server) -> None:
        def ok(detail) -> None:
            profile = self.config.get(s.id)
            if not profile.accounts:
                profile.upsert_account(
                    SshAccount(
                        user=detail.login_user or "root",
                        port=detail.ssh_port or 22,
                        auth_mode=AUTH_PASSWORD,
                    )
                )
            self.config.save()
            self.reload(quiet=True)

        run_async(self, lambda: self.client.cloud.get_server(s.id), ok, lambda m: None)
    # ------------------------------------------------------------------ 动作
    def _power(self, kind: str) -> None:
        s = self.current_server()
        if not s:
            return
        label = "开机" if kind == "on" else "关机"
        if QMessageBox.question(self, label, f"{label} {s.name}？") != QMessageBox.Yes:
            return
        fn = self.client.cloud.power_on if kind == "on" else self.client.cloud.power_off
        run_async(self, lambda: fn(s.id),
                  lambda info: (QMessageBox.information(self, label, str(info) or "已提交"),
                                self.reload(quiet=True)),
                  self._on_error)

    def _restart(self) -> None:
        s = self.current_server()
        if not s:
            return
        if QMessageBox.question(
            self, "重启", f"重启 {s.name} 需要短信验证码。\n现在发送验证码到注册手机？"
        ) != QMessageBox.Yes:
            return

        def sent(info: str) -> None:
            code, ok = QInputDialog.getText(self, "重启", "输入收到的验证码：")
            if not ok or not code.strip():
                return
            run_async(self, lambda: self.client.cloud.restart(s.id, code.strip()),
                      lambda msg: (QMessageBox.information(self, "重启", str(msg) or "已提交"),
                                   self.reload(quiet=True)),
                      self._on_error)

        run_async(self, lambda: self.client.cloud.send_restart_code(s.id),
                  lambda info: (QMessageBox.information(self, "已发送", str(info) or "验证码已发送"),
                                sent(str(info))),
                  self._on_error)

    # ------------------------------------------------------------ SSH
    def _ensure_profile(self, s: Server) -> None:
        """没配过账号就按云端详情建一个默认账号。"""
        profile = self.config.get(s.id)
        if profile.accounts:
            return
        detail = self.client.cloud.get_server(s.id)
        profile.upsert_account(
            SshAccount(
                user=detail.login_user or "root",
                port=detail.ssh_port or 22,
                auth_mode=AUTH_PASSWORD,
            )
        )
        self.config.save()

    def _account(self, s: Server, user: str | None = None) -> SshAccount:
        profile = self.config.get(s.id)
        account = profile.account(user)
        if account is None:
            raise RuntimeError("还没有配置 SSH 账号：右键 → SSH 账号管理")
        return account

    def _target(self, s: Server, user: str | None = None) -> SshTarget:
        account = self._account(s, user)
        return SshTarget(
            host=s.ip,
            port=account.port,
            user=account.user,
            password=account.password,
            key_path=account.key_path,
            key_passphrase=account.key_passphrase,
        )

    def _ensure_credential(self, s: Server, account: SshAccount) -> None:
        """密码模式下本地没存密码，就先用云端那个顶上（可能已被改过）。"""
        if account.auth_mode != AUTH_PASSWORD or account.password:
            return
        try:
            account.password = self.client.cloud.get_ssh_password(s.id)
            self.config.save()
        except Exception as exc:  # noqa: BLE001 - 读不到就让用户手输
            print(f"读取云端密码失败：{exc}")

    def _manage_ssh(self, s: Server) -> None:
        try:
            self._ensure_profile(s)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "SSH", str(exc))
            return
        SshAccountsDialog(s, self.config, self.client, self).exec()
        self.reload(quiet=True)

    def _choose_account(self, s: Server) -> str | None:
        """多账号时让用户选一个；返回用户名，取消返回 None。"""
        profile = self.config.get(s.id)
        accounts = profile.accounts
        if len(accounts) <= 1:
            return accounts[0].user if accounts else None

        menu = QMenu(self)
        for acc in accounts:
            mark = "★ " if acc.user == profile.default_account else "　 "
            action = menu.addAction(f"{mark}{acc.user} : {acc.port} · {acc.auth_label}")
            action.setData(acc.user)
        menu.addSeparator()
        manage = menu.addAction("SSH 账号管理…")
        chosen = menu.exec(self.cursor().pos())
        if chosen is None:
            return None
        if chosen is manage:
            self._manage_ssh(s)
            return None
        return chosen.data()

    def open_ssh(self, user: str | None = None) -> None:
        s = self.current_server()
        if not s:
            return
        try:
            self._ensure_profile(s)
            if user is None:
                user = self._choose_account(s)
                if user is None:
                    return
            account = self._account(s, user)
            self._ensure_credential(s, account)
            target = self._target(s, user)
            cmd = launch_ssh(
                target,
                self.config.ssh_launcher,
                custom=self.config.ssh_launcher_custom,
            )
            self.statusBar().showMessage(f"已用 {account.user} 打开：{cmd[:80]}")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "SSH", str(exc))

    def copy_ssh(self) -> None:
        s = self.current_server()
        if not s:
            return
        try:
            self._ensure_profile(s)
            account = self._account(s)
            parts = ["ssh", "-p", str(account.port)]
            if account.key_path:
                parts += ["-i", account.key_path]
            parts.append(f"{account.user}@{s.ip}")
            cmd = " ".join(parts)
            QApplication.clipboard().setText(cmd)
            self.statusBar().showMessage("已复制：" + cmd)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "复制", str(exc))

    def _test_ssh(self, user: str | None = None) -> None:
        s = self.current_server()
        if not s:
            return
        try:
            self._ensure_profile(s)
            if user is None:
                user = self._choose_account(s)
                if user is None:
                    return
            account = self._account(s, user)
            self._ensure_credential(s, account)
            target = self._target(s, user)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "SSH", str(exc))
            return
        self.statusBar().showMessage(f"正在测试 {target.address}:{target.port} …")

        def done(result: tuple[bool, str]) -> None:
            ok, message = result
            if ok:
                QMessageBox.information(
                    self, "SSH 正常",
                    f"已用 {account.user}（{account.auth_label}）连上 "
                    f"{target.address}:{target.port}\n{message}",
                )
                self.statusBar().showMessage("SSH 连接正常")
            else:
                self.statusBar().showMessage("SSH 连接失败")
                if QMessageBox.question(
                    self, "连不上",
                    f"用当前凭据登录失败：\n\n{message[-300:]}\n\n"
                    "要打开「SSH 账号管理」改密码/换密钥再试吗？",
                ) == QMessageBox.Yes:
                    self._manage_ssh(s)

        run_async(self, lambda: test_connection(target), done, self._on_error)

    def _read_password(self) -> None:
        s = self.current_server()
        if not s:
            return
        run_async(self, lambda: self.client.cloud.get_ssh_password(s.id),
                  lambda pwd: self._show_password(s, pwd), self._on_error)

    def _show_password(self, s: Server, pwd: str) -> None:
        profile = self.config.get(s.id)
        account = profile.account()
        dlg = QMessageBox(self)
        dlg.setWindowTitle("登录密码")
        dlg.setText(f"{s.name} 的登录密码：\n\n{pwd}")
        target = account.user if account else "默认账号"
        dlg.setInformativeText(
            f"可以存到本地账号「{target}」里，之后一键 SSH 就不用手输。"
        )
        save_btn = dlg.addButton("保存到本地", QMessageBox.ActionRole)
        copy_btn = dlg.addButton("复制", QMessageBox.ActionRole)
        dlg.addButton("关闭", QMessageBox.RejectRole)
        dlg.exec()
        if dlg.clickedButton() is save_btn:
            account = account or SshAccount()
            account.password = pwd
            account.auth_mode = AUTH_PASSWORD
            profile.upsert_account(account)
            self.config.save()
            QMessageBox.information(
                self, "已保存",
                f"已写入 {Path('~/.config/landui-sdk/config.json').expanduser()}",
            )
        elif dlg.clickedButton() is copy_btn:
            QApplication.clipboard().setText(pwd)

    def _firewall(self) -> None:
        s = self.current_server()
        if not s:
            return
        FirewallWindow(self.client, s, self).exec()

    # ------------------------------------------------------------- 右键菜单
    def _context_menu(self, pos) -> None:
        s = self.current_server()
        if not s:
            return
        menu = QMenu(self)
        act_ssh = menu.addAction("打开 SSH")
        act_ip = menu.addAction("复制公网 IP")
        menu.addSeparator()
        act_note = menu.addAction("编辑本地备注")
        act_accounts = menu.addAction("SSH 账号管理…")
        act_test = menu.addAction("测试 SSH 连接")
        menu.addSeparator()
        act_pwd = menu.addAction("读取登录密码")
        act_fw = menu.addAction("云防火墙")

        chosen = menu.exec(self.tbl.viewport().mapToGlobal(pos))
        if chosen is act_ssh:
            self.open_ssh()
        elif chosen is act_ip:
            QApplication.clipboard().setText(s.ip)
        elif chosen is act_note:
            self._edit_note(s)
        elif chosen is act_accounts:
            self._manage_ssh(s)
        elif chosen is act_test:
            self._test_ssh()
        elif chosen is act_pwd:
            self._read_password()
        elif chosen is act_fw:
            self._firewall()

    def _edit_note(self, s: Server) -> None:
        profile = self.config.get(s.id)
        text, ok = QInputDialog.getText(self, "本地备注", f"{s.name} 的备注：", text=profile.note)
        if ok:
            profile.note = text
            self.config.save()
            self.reload(quiet=True)

    def _settings(self) -> None:
        dlg = SettingsDialog(self.config, self.client, self)
        dlg.exec()


# ---------------------------------------------------------------- 设置窗口
class SettingsDialog(QDialog):
    def __init__(self, config: AppConfig, client: LanduiClient, parent: QWidget | None = None):
        super().__init__(parent)
        self.config = config
        self.client = client
        self.setWindowTitle("设置")
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowSystemMenuHint
        )
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setSizeGripEnabled(True)
        self.resize(560, 340)
        self.store = CredentialStore()

        form = QFormLayout(self)

        self.cb_launcher = QComboBox()
        for spec in LAUNCHERS:
            label = spec.label
            if not launcher_available(spec.id):
                label += "（未安装）"
            self.cb_launcher.addItem(label, spec.id)
        idx = self.cb_launcher.findData(config.ssh_launcher or "auto")
        if idx >= 0:
            self.cb_launcher.setCurrentIndex(idx)
        form.addRow("打开方式", self.cb_launcher)

        self.ed_custom = QLineEdit(config.ssh_launcher_custom)
        self.ed_custom.setPlaceholderText(
            "自定义模板，支持 {cmd} {user} {host} {port} {address} {key}"
        )
        form.addRow("自定义命令", self.ed_custom)
        self.lbl_launcher_hint = QLabel(
            '示例：tabby run bash -lc {cmd}　或　alacritty -e bash -lc {cmd}'
        )
        self.lbl_launcher_hint.setStyleSheet("color:#888")
        self.lbl_launcher_hint.setWordWrap(True)
        form.addRow("", self.lbl_launcher_hint)

        self.chk_auto = QCheckBox("启动时用保存的账号密码自动登录")
        self.chk_auto.setChecked(config.auto_login)
        form.addRow("自动登录", self.chk_auto)

        saved = self.store.load()
        cred_row = QHBoxLayout()
        if saved is None:
            cred_text = "未保存账号"
        elif saved.has_password:
            cred_text = f"已保存：{saved.username}（含密码）"
        else:
            cred_text = f"已保存：{saved.username}（仅账号）"
        self.lbl_cred = QLabel(cred_text)
        btn_clear = QPushButton("清除")
        btn_clear.setEnabled(saved is not None)
        btn_clear.clicked.connect(self._clear_credentials)
        cred_row.addWidget(self.lbl_cred, 1)
        cred_row.addWidget(btn_clear)
        form.addRow("本地账号", cred_row)

        self.lbl_auth = QLabel(f"登录态文件：{AUTH_FILE}")
        form.addRow("登录态", self.lbl_auth)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Save).setText("保存")
        form.addRow(buttons)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

    def _clear_credentials(self) -> None:
        if QMessageBox.question(self, "清除", "删除本地保存的账号/密码？") != QMessageBox.Yes:
            return
        self.store.clear()
        self.lbl_cred.setText("未保存账号")

    def _save(self) -> None:
        self.config.ssh_launcher = self.cb_launcher.currentData() or "auto"
        self.config.ssh_launcher_custom = self.ed_custom.text().strip()
        self.config.auto_login = self.chk_auto.isChecked()
        self.config.save()
        self.accept()


# ---------------------------------------------------------------- 入口
def _bootstrap_login(client: LanduiClient) -> bool:
    """Cookie -> 本地账号密码 -> 弹登录框。返回是否已登录。"""
    if AUTH_FILE.exists():
        client.load_auth(AUTH_FILE)

    if client.is_logged_in():
        return True

    # 本地存了账号密码就静默试一次，密码只在本进程内使用
    try:
        if AppConfig.load().auto_login and client.login_with_stored_credentials():
            return True
    except CaptchaRequired as cap:
        # 风控要验证码：直接弹框，并把图带过去
        dlg = LoginDialog(client, captcha=cap)
        return dlg.exec() == QDialog.Accepted
    except Exception as exc:  # noqa: BLE001 - 密码错/网络差都退回手动登录
        print(f"自动登录失败，转手动登录：{type(exc).__name__}")

    return LoginDialog(client).exec() == QDialog.Accepted


def main() -> int:
    app = QApplication(sys.argv)
    client = LanduiClient()
    if not _bootstrap_login(client):
        return 1

    try:
        win = MainWindow(client)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 1
    win.show()
    code = app.exec()
    QThreadPool.globalInstance().waitForDone(3000)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
