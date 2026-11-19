"""异常类型。"""

from __future__ import annotations

from typing import Any


class LanduiError(Exception):
    """SDK 基础异常。"""


class NotLoggedInError(LanduiError):
    """Cookie / 会话已失效，需要重新登录。"""

    def __init__(self, message: str = "登录态已失效，请重新登录或重新导入 Cookie"):
        super().__init__(message)


class APIError(LanduiError):
    """接口返回 status != 'y' 或 code != 200。"""

    def __init__(self, message: str, payload: Any = None):
        super().__init__(message)
        self.payload = payload


class CaptchaRequired(LanduiError):
    """登录被风控拦下，需要图形验证码。

    ``captcha_id`` 要原样带回登录请求，``image`` 是可直接显示的 PNG/JPEG 字节。
    """

    def __init__(self, captcha_id: str, image: bytes, message: str = "需要图形验证码"):
        super().__init__(message)
        self.captcha_id = captcha_id
        self.image = image
