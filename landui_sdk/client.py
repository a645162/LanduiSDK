"""底层 HTTP 客户端：会话、Cookie 持久化、登录、通用请求封装。"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import requests

from landui_sdk.account import AccountAPI
from landui_sdk.cloud import CloudAPI
from landui_sdk.errors import APIError, CaptchaRequired, LanduiError, NotLoggedInError
from landui_sdk.firewall import FirewallAPI

BASE_URL = "https://www.landui.com"
ACCOUNT_URL = "https://account.console.landui.com"
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
)
DEFAULT_AUTH_FILE = "~/.config/landui-sdk/auth.json"

# 服务端把 HTML / 文本包成 JSON 字符串返回，统一在 _decode 里拆掉
_JSON_PREFIX = ('"', "{", "[")


class LanduiClient:
    """蓝队云控制台客户端。

    典型用法::

        client = LanduiClient.from_cookies_file()      # 读取已保存的登录态
        client.cloud.list_servers()

    Cookie 失效时抛 :class:`NotLoggedInError`。
    """

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        *,
        timeout: float = 30.0,
        base_url: str = BASE_URL,
        account_url: str = ACCOUNT_URL,
        user_agent: str = DEFAULT_UA,
    ):
        self.base_url = base_url.rstrip("/")
        self.account_url = account_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        if cookies:
            self.set_cookies(cookies)

        self.cloud = CloudAPI(self)
        self.firewall = FirewallAPI(self)
        self.account = AccountAPI(self)

    # ------------------------------------------------------------------ auth
    def set_cookies(self, cookies: dict[str, str]) -> None:
        for name, value in cookies.items():
            self.session.cookies.set(name, value, domain=".landui.com")

    @property
    def cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.session.cookies}

    def auth_payload(self) -> dict[str, Any]:
        """导出可持久化的登录态（含 domain，便于回灌）。"""
        return {
            "cookies": [
                {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                for c in self.session.cookies
            ]
        }

    def load_auth(self, path: str | os.PathLike = DEFAULT_AUTH_FILE) -> None:
        data = json.loads(Path(path).expanduser().read_text("utf-8"))
        for c in data.get("cookies", []):
            self.session.cookies.set(
                c["name"], c["value"], domain=c.get("domain") or ".landui.com",
                path=c.get("path") or "/",
            )

    def save_auth(self, path: str | os.PathLike = DEFAULT_AUTH_FILE) -> Path:
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.auth_payload(), ensure_ascii=False, indent=1), "utf-8")
        try:  # 登录态等同密码，尽量收紧权限
            p.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return p

    @classmethod
    def from_cookies_file(
        cls, path: str | os.PathLike = DEFAULT_AUTH_FILE, **kwargs: Any
    ) -> LanduiClient:
        client = cls(**kwargs)
        client.load_auth(path)
        return client

    def is_logged_in(self) -> bool:
        try:
            page = self.html("/user/")
        except (LanduiError, requests.RequestException):
            return False
        return "安全退出" in page

    # ----------------------------------------------------------------- login
    def get_captcha(self) -> tuple[str, bytes]:
        """返回 (captcha_id, 图片字节)。图片可直接塞进 QPixmap。"""
        data = self.api("GET", f"{self.account_url}/api/common/captcha")
        info = data.get("data") or {}
        captcha_id = info.get("captcha_id") or ""
        raw = info.get("captcha_data") or ""
        if raw.startswith("data:"):
            import base64

            raw = raw.split(",", 1)[-1]
        import base64

        try:
            image = base64.b64decode(raw)
        except ValueError:  # 坏图片就当没有
            image = b""
        if not captcha_id:
            raise APIError("获取验证码失败", data)
        return captcha_id, image

    def check_account(self, username: str) -> dict[str, Any]:
        """登录前置检查：服务端据此决定要不要图形验证码。

        返回 ``data.is_captcha``（True 表示这次登录要验证码）。
        """
        return self.api(
            "POST",
            f"{self.account_url}/api/users/login/accountcheck",
            data={"username": username},
            check=False,
        )

    def login(
        self,
        username: str,
        password: str,
        captcha_answer: str = "",
        captcha_id: str = "",
        *,
        precheck: bool = True,
    ) -> dict[str, Any]:
        """账号密码登录。

        流程与网页一致：

        1. ``accountcheck`` 只带账号 → 服务端说 ``is_captcha=true`` 就先要验证码；
        2. ``login/account`` 带上验证码（如果需要）提交账号密码；
        3. 返回 ``code=200`` 成功，``205`` 需要/验证码错误，``302`` 密码太弱。

        需要验证码时抛 :class:`CaptchaRequired`，里面带着图片，
        让用户看一眼填 4 位字符，再带着 ``captcha_id`` 重试即可。

        密码只在本方法的请求体里出现，不会被打印或写日志。
        """
        if precheck:
            check = self.check_account(username)
            info = (check.get("data") or {}) if isinstance(check, dict) else {}
            need_captcha = bool(info.get("is_captcha")) or check.get("code") == 205
            if need_captcha and not captcha_answer:
                cid, image = self.get_captcha()
                raise CaptchaRequired(cid, image, str(check.get("msg") or "需要图形验证码"))

        payload: dict[str, Any] = {"username": username, "password": password}
        if captcha_answer:
            payload["captcha_answer"] = captcha_answer
            payload["captcha_id"] = captcha_id
        data = self.api(
            "POST",
            f"{self.account_url}/api/users/login/account",
            data=payload,
            check=False,
        )
        code = data.get("code") if isinstance(data, dict) else None
        if code == 200:
            self._share_account_cookies()
            return data
        if code == 205:
            cid, image = self.get_captcha()
            raise CaptchaRequired(cid, image, str(data.get("msg") or "验证码错误或已过期"))
        raise APIError(str(data.get("msg") or f"登录失败 (code={code})"), data)

    def login_with_stored_credentials(self, *, save_auth: bool = True) -> bool:
        """用本地保存的账号密码登录；没有凭据返回 False。

        可能抛 :class:`CaptchaRequired`（这时需要人看一眼图）。
        """
        from landui_sdk.credentials import CredentialStore

        creds = CredentialStore().load()
        if creds is None or not creds.has_password:
            return False
        self.login(creds.username, creds.password)
        if save_auth:
            self.save_auth()
        return True

    def _share_account_cookies(self) -> None:
        """账号中心下发的 Cookie 若是 host-only，补一份到 .landui.com。

        否则 ``www.landui.com`` 认不出登录态。
        """
        for cookie in list(self.session.cookies):
            if cookie.domain and cookie.domain.startswith("account.console."):
                self.session.cookies.set(
                    cookie.name, cookie.value, domain=".landui.com", path="/"
                )

    def logout(self) -> None:
        try:
            self.session.get(f"{self.account_url}/index/user/logout", timeout=self.timeout)
        finally:
            self.session.cookies.clear()

    # ------------------------------------------------------------------ http
    def _decode(self, resp: requests.Response) -> Any:
        text = resp.text or ""
        head = text.lstrip()[:1]
        if head in _JSON_PREFIX:
            try:
                value = json.loads(text)
            except ValueError:
                return text
            # 服务端常见：HTML 页面被 json.dumps 成字符串
            if isinstance(value, str):
                return value
            return value
        return text

    def request(
        self,
        method: str,
        path: str,
        *,
        data: Any = None,
        params: Any = None,
        referer: str | None = None,
        ajax: bool = True,
        timeout: float | None = None,
    ) -> requests.Response:
        url = path if path.startswith("http") else self.base_url + path
        headers: dict[str, str] = {}
        if referer:
            headers["Referer"] = referer
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": timeout or self.timeout,
            "allow_redirects": True,
        }
        if method.upper() == "GET":
            kwargs["params"] = params
        else:
            kwargs["data"] = data if data is not None else {}
            if params:
                kwargs["params"] = params
        resp = self._request_with_retry(method, url, **kwargs)
        if not ajax:
            # 网页抓取不需要伪装成 XHR，否则服务端会把 HTML 包成 JSON
            pass
        return resp

    def _request_with_retry(
        self, method: str, url: str, *, retries: int = 2, **kwargs: Any
    ) -> requests.Response:
        """站点偶发直接掐 TLS 连接，握手段失败时重试两次（请求还没发出去，安全）。"""
        last: Exception | None = None
        for attempt in range(retries + 1):
            try:
                return self.session.request(method, url, **kwargs)
            except requests.exceptions.SSLError as exc:
                last = exc
                if attempt < retries:
                    time.sleep(0.6 * (attempt + 1))
            except requests.exceptions.ConnectionError as exc:
                last = exc
                if attempt < retries:
                    time.sleep(0.6 * (attempt + 1))
        assert last is not None
        raise last

    def api(
        self,
        method: str,
        path: str,
        *,
        data: Any = None,
        params: Any = None,
        referer: str | None = None,
        check: bool = True,
    ) -> Any:
        """调用返回 JSON 的接口，自动解包 ``status`` / ``code``。"""
        resp = self.request(method, path, data=data, params=params, referer=referer)
        payload = self._decode(resp)
        if isinstance(payload, dict):
            status = payload.get("status")
            if status == "n":
                info = str(payload.get("info") or payload.get("msg") or "")
                if "登录" in info or "登陆" in info:
                    raise NotLoggedInError(info or "登录态已失效")
                if check:
                    raise APIError(info or "接口返回失败", payload)
            if check and "code" in payload and payload["code"] not in (0, 200, "0", "200"):
                code = payload["code"]
                msg = str(payload.get("msg") or payload.get("info") or "")
                if code in (401, 403):
                    raise NotLoggedInError(msg or "登录态已失效")
                if "登录" in msg:
                    raise NotLoggedInError(msg)
        return payload

    def html(self, path: str, *, params: Any = None, data: Any = None, method: str = "GET") -> str:
        """抓取 HTML 页面（已处理 JSON 字符串包装）。"""
        resp = self.request(method, path, params=params, data=data, ajax=False)
        payload = self._decode(resp)
        if isinstance(payload, dict):
            raise APIError(f"接口返回了 JSON 而不是页面: {path}", payload)
        text = str(payload)
        if "请先登录" in text or "/user/login" in text and "安全退出" not in text:
            raise NotLoggedInError()
        return text
