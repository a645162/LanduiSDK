"""登录流程与凭据存储的离线测试（不联网）。"""

from __future__ import annotations

import stat

import pytest

from landui_sdk.client import LanduiClient
from landui_sdk.credentials import Credentials, CredentialStore
from landui_sdk.errors import APIError, CaptchaRequired


class FakeClient(LanduiClient):
    """把 HTTP 层换掉，只验证登录状态机。"""

    def __init__(self, responses: list[dict]):
        super().__init__()
        self.responses = list(responses)
        self.calls: list[tuple[str, dict | None]] = []

    def api(self, method, path, *, data=None, params=None, referer=None, check=True):  # type: ignore[override]
        self.calls.append((path, data))
        return self.responses.pop(0)

    def get_captcha(self):  # type: ignore[override]
        return "cid-1", b"\x89PNG-fake"

    def _share_account_cookies(self) -> None:  # type: ignore[override]
        pass


def test_login_requires_captcha():
    client = FakeClient([{"code": 200, "data": {"is_captcha": True}}])
    with pytest.raises(CaptchaRequired) as exc:
        client.login("u", "p")
    assert exc.value.captcha_id == "cid-1"
    assert exc.value.image.startswith(b"\x89PNG")
    # 只打了 accountcheck，没有提交密码
    assert len(client.calls) == 1
    assert client.calls[0][0].endswith("/api/users/login/accountcheck")
    assert client.calls[0][1] == {"username": "u"}


def test_login_with_captcha_succeeds():
    client = FakeClient([{"code": 200, "data": {}}])
    result = client.login("u", "p", "abcd", "cid-1", precheck=False)
    assert result["code"] == 200
    path, data = client.calls[0]
    assert path.endswith("/api/users/login/account")
    assert data["captcha_answer"] == "abcd"
    assert data["captcha_id"] == "cid-1"
    assert data["password"] == "p"


def test_login_without_captcha_when_server_says_ok():
    client = FakeClient(
        [
            {"code": 200, "data": {"is_captcha": False}},
            {"code": 200, "data": {}},
        ]
    )
    assert client.login("u", "p")["code"] == 200
    assert [c[0].rsplit("/", 1)[-1] for c in client.calls] == ["accountcheck", "account"]


def test_login_error_does_not_leak_password():
    client = FakeClient([{"code": 500, "msg": "账号或密码错误"}])
    with pytest.raises(APIError) as exc:
        client.login("u", "secret-pw", precheck=False)
    assert "secret-pw" not in str(exc.value)


def test_credential_store_roundtrip(tmp_path):
    store = CredentialStore(tmp_path / "credentials.json")
    assert store.load() is None
    path = store.save(Credentials("alice", "s3cret"))
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = store.load()
    assert loaded == Credentials("alice", "s3cret")
    assert "s3cret" not in repr(loaded)
    store.clear()
    assert store.load() is None


def test_credentials_env_priority(tmp_path, monkeypatch):
    store = CredentialStore(tmp_path / "credentials.json")
    store.save(Credentials("file-user", "file-pass"))
    monkeypatch.setenv("LANDUI_USERNAME", "env-user")
    monkeypatch.setenv("LANDUI_PASSWORD", "env-pass")
    loaded = store.load()
    assert loaded == Credentials("env-user", "env-pass")


def test_username_only_credentials(tmp_path):
    store = CredentialStore(tmp_path / "credentials.json")
    store.save(Credentials("bob", ""))
    loaded = store.load()
    assert loaded == Credentials("bob", "")
    assert loaded.has_password is False
    assert "***" not in repr(loaded)


def test_login_without_password_does_not_auto_login(tmp_path, monkeypatch):
    store = CredentialStore(tmp_path / "credentials.json")
    store.save(Credentials("bob", ""))

    class NoLogin(FakeClient):
        def login(self, *a, **k):  # type: ignore[override]
            raise AssertionError("没有密码不应该尝试登录")

    client = NoLogin([])
    monkeypatch.setattr(
        "landui_sdk.credentials.CredentialStore",
        lambda *a, **k: store,
    )
    assert client.login_with_stored_credentials() is False
