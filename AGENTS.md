# AGENTS.md

蓝队云（landui.com）控制台的**非官方第三方** SDK + 本地 PySide6 运维台。
与蓝队云官方无隶属/授权关系；改动时不要在任何产物里去掉这层声明。
所有接口均从网页前端行为逆向整理，随时可能失效。

## 这里最不能犯的错

1. **绝不提交任何凭据**。以下路径已在 `.gitignore`：
   `~/.config/landui-sdk/` 下的 `auth.json`（登录 Cookie）、`credentials.json`
   （账号密码）、`config.json`（SSH 账号/密码/私钥口令），以及仓库内
   `captures/`、`sources/`（探索期的抓包与网页快照，含 Cookie 和真实 IP）。
   提交前跑一遍审计：

   ```bash
   git diff --cached --name-only | xargs -r grep -nEi \
     'PHPSESSID|ACCESS_TOKEN|landuiRS_SIDS|password|secret|token|/home/' || true
   # 再人工过一眼：真实公网 IP、真实实例 ID、个人账号名、截图里有没有这些
   ```

2. **不要拿登录接口做自动化探测/爆破**。站点 WAF 会直接封 IP 并告警，
   只允许用户主动触发的正常登录。

3. 测试里不允许有真实 IP / 实例 ID / 账号。示例统一用
   `203.0.113.0/24`（TEST-NET-3）、`10001`、`demo-server`。

## 环境与命令

```bash
uv sync                      # 运行 SDK/CLI/测试所需
uv sync --extra gui          # 需要图形界面时
uv run pytest -q             # 离线测试（不联网）
uv run ruff check landui_sdk examples tools scripts tests
uv run landui ls             # CLI
uv run --extra gui python examples/app.py   # 图形界面
QT_QPA_PLATFORM=offscreen uv run --extra gui python tools/screenshots.py  # 生成 README 截图（假数据）
```

Python >= 3.10。依赖只用 `requests`；GUI 额外需要 `pyside6`。

## 代码地图

```
landui_sdk/
  client.py       会话/Cookie 持久化/登录/请求封装（含 TLS 抖动重试）
  cloud.py        云服务器：列表、详情（SSH 端口）、开关机、密码、日志、快照
  firewall.py     安全组 + 单机 ACL + 端口区间匹配/体检/重编号（纯函数）
  account.py      域名/虚拟主机/托管/SSL/回收站 列表
  ssh.py          多认证方式拼 ssh 命令 + 终端/Tabby/Windows 启动器
  config.py       本地配置：每台机器多套 SSH 账号、启动器偏好
  credentials.py  控制台账号密码保管（0600 / 环境变量优先）
  cli.py          landui 命令行
examples/
  app.py               主窗口（服务器列表 + 一键 SSH + 入口）
  firewall_window.py   防火墙管理台（表格 + 内联编辑 + 端口视图）
  ssh_dialog.py        SSH 账号管理
  ui_common.py         线程池封装 run_async / 错误提示
docs/API.md      接口清单（路径、参数、返回列、验证状态）
tools/           cdp 抓包、截图生成（开发用，不进运行时依赖）
```

## 接口约定（踩过的坑）

- 带 `X-Requested-With: XMLHttpRequest` 时，服务端会把 HTML 包成 JSON 字符串；
  `client._decode` 负责解包。
- 列表接口是 DataTables：`start` **从 1 开始**、`length`、`order[0][name]=id`。
- 统一响应 `{"status":"y"|"n","info":...}`；`status=n` 抛 `APIError`。
- `rulesAdd` 的 `weight`/`desc` 生效；`rulesAddBatch` 会被服务端忽略并按 200/210… 自增。
- 安全组规则有 weight，越大越先匹配；端口为空/`1-65535` 表示全部。
- 详情页有大量 `<!-- -->` 注释字段，解析前必须先去注释（`parsers.parse_kv_page`）。

## 写操作的验证状态

已在真实账号验证：开机、关机、加规则、改规则、删规则（用 TEST-NET 的临时规则，
测试后已删除）。
未验证：建组/改名/删组、单机 ACL、重装、重置密码。改这些代码时保持谨慎并更新
`docs/API.md` 的 ✅/⚠ 标记。

## GUI 约定

- **不要在主线程发请求**：一律 `run_async(self, job, on_ok, on_error)`
  （`examples/ui_common.py`），任务对象会挂在父窗口上防止被 GC。
- 登录态失效（`NotLoggedInError`）只能提示一次，然后进入静默，等用户手动重登；
  不要在定时器里反复弹框。
- 防火墙编辑面板有脏状态（`RuleEditorPanel.is_dirty`）：
  切换选中/关窗必须确认，取消时恢复原选中（`_restore_selection`）。
- 界面文案用中文；命令、路径、错误信息保持原文。

## 新增一个接口的做法

1. 在 `landui_sdk/<模块>.py` 里加方法，走 `self.c.api(...)` / `self.c.html(...)`。
2. 用 `dataclass` 放进 `models.py`，解析逻辑放 `parsers.py`。
3. 在 `docs/API.md` 补一行，标注 ✅读/✅写/⚠ 未验证。
4. 加离线测试（构造 HTML 片段或假 client），**不要联网**。
