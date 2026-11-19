"""蓝队云 (landui.com) 非官方 SDK.

    from landui_sdk import LanduiClient

    client = LanduiClient.from_cookies_file("~/.config/landui-sdk/auth.json")
    for s in client.cloud.list_servers():
        print(s.id, s.name, s.ip, s.status, s.ssh_port)
"""

from landui_sdk.account import AccountAPI
from landui_sdk.client import LanduiClient
from landui_sdk.cloud import CloudAPI
from landui_sdk.credentials import Credentials, CredentialStore
from landui_sdk.errors import (
    APIError,
    CaptchaRequired,
    LanduiError,
    NotLoggedInError,
)
from landui_sdk.firewall import FirewallAPI
from landui_sdk.models import (
    FirewallRule,
    SecurityGroup,
    Server,
    ServerDetail,
    TablePage,
)

__version__ = "0.1.0"
__all__ = [
    "APIError",
    "AccountAPI",
    "CaptchaRequired",
    "CloudAPI",
    "CredentialStore",
    "Credentials",
    "FirewallAPI",
    "FirewallRule",
    "LanduiClient",
    "LanduiError",
    "NotLoggedInError",
    "SecurityGroup",
    "Server",
    "ServerDetail",
    "TablePage",
]
