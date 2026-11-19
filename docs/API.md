# 蓝队云控制台接口清单

> **非官方整理**：本文档与代码均为第三方实现，与蓝队云官方无关；接口可能随时变更。

抓取时间：2026-11-19　示例实例：`10001`（demo-server）　（文中 ID/IP 均为示例值）

图例：**✅读** 已在本机实测返回正确数据；**✅写** 已实测成功；**⚠** 依据网页 JS
整理、未执行（多为删除/需要验证码的操作，故未在你的账号上验证）。

通用约定：

* 站点：`https://www.landui.com`，账号中心：`https://account.console.landui.com`
* 请求头带 `X-Requested-With: XMLHttpRequest` 时，HTML 会被包成 JSON 字符串，需要解包。
* 统一响应：`{"status":"y"|"n","info": "...", "url": ""}`；列表接口是 DataTables：
  `{"status":"y","data":[[...]],"recordsTotal":N}`，参数 `start`（**从 1 开始**）、`length`、
  `order[0][name]=id&order[0][dir]=desc`。

## 登录 / 会话

| 功能 | 方法 | 路径 | 备注 |
| --- | --- | --- | --- |
| 图形验证码 | GET | `account.console.landui.com/api/common/captcha` | 返回 `{code:200,data:{captcha_id,captcha_data}}`，`captcha_data` 是 base64 图 |
| 登录前置检查 | POST | `account.console.landui.com/api/users/login/accountcheck` | 只传 `username`；`data.is_captcha=true` 表示这次要验证码 |
| 账号密码登录 | POST | `account.console.landui.com/api/users/login/account` | `username,password[,captcha_answer,captcha_id]`；`205`=要/错验证码，`302`=密码太弱 |
| 退出 | GET | `account.console.landui.com/index/user/logout` | ⚠ |

登录顺序：`accountcheck` → 需要验证码就 `GET api/common/captcha` 拿图和 `captcha_id`
→ `login/account`。成功后把账号中心下发的 host-only Cookie 复制一份到 `.landui.com`，
否则 `www.landui.com` 不认登录态。

关键 Cookie（都在 `.landui.com`）：`PHPSESSID`、`landuiUSER_CENTER_ACCESS_TOKEN`、
`landuiRS_SIDS`。拿着这组 Cookie 即可直接请求控制台。

## 云服务器 `/user/cloud`

| 功能 | 方法 | 路径 | 参数 | 状态 |
| --- | --- | --- | --- | --- |
| 列表 | POST | `/user/cloud/tablelist.html` | `start,length,order[0][name]=id,order[0][dir]=desc` | ✅读 |
| 详情页 | GET | `/user/cloud/manage.html?id={id}` | — | ✅读 |
| 状态 | GET | `/user/cloud/vpsstatus.html?id={id}` | — | ✅读，返回 `"运行中"` |
| 登录密码 | POST | `/user/cloud/getpassword.html?id={id}` | — | ✅读 `{info:{password}}` |
| VNC 密码 | POST | `/user/cloud/getvncpass.html?id={id}` | — | ✅读 |
| 开机 | POST | `/user/cloud/startsave.html?id={id}` | 空 | ✅写 |
| 关机 | POST | `/user/cloud/serverstopsave.html?id={id}` | 空 | ✅写 |
| 发重启验证码 | POST | `/user/cloud/productSendCode?id={id}` | `type=mobile\|email,text=重启云服务器` | ⚠ |
| 重启 | POST | `/user/cloud/serverrestartsave.html?id={id}` | `verType,code[mobile]` | ⚠ 需验证码 |
| 批量开机 | POST | `/user/cloud/batchstartsave.html?ids=1,2` | 空 | ⚠ |
| 批量关机 | POST | `/user/cloud/batchstopsave.html?ids=1,2` | 空 | ⚠ |
| 批量重启 | POST | `/user/cloud/batchrestartsave.html?ids=1,2` | `verType,code[...]` | ⚠ |
| 操作日志 | POST | `/user/cloud/savelogtablelist.html?id={id}` | DataTables | ✅读（空） |
| 登录日志 | GET | `/user/cloud/loginrecords.html?id={id}` | — | ✅读（HTML） |
| 防御日志 | GET | `/user/cloud/ddoslog.html?id={id}` | — | ✅读（HTML） |
| 资源监控 | POST | `/user/cloud/getchart` | `id,type(1网络/2CPU/3内存/4磁盘),time=1,hostid=""` | ✅读（无探针为空） |
| 改备注 | POST | `/user/group/remark.html?id={id}&type=3` | `ld_bz,id,type=3` | ⚠ |
| 改分组 | POST | `/user/group/ajaxSaveOne` | `saveid,id,typeid` | ⚠ |
| 快照列表 | POST | `/user/snapshot/snapshotlist.html` | DataTables | ✅读（空） |
| 创建快照入口 | GET | `/user/snapshot/addtip.html?id={id}` | — | ✅读（页面） |
| 回收站 | POST | `/user/cloud/recoverylist.html` | DataTables | ✅读 |
| 重装系统 | POST | `/user/cloud/savereinstall.html?id={id}` | `systemid,system_ver,verType,code[...]` | ⚠ 危险 |
| 重置密码 | POST | `/user/cloud/resetpwdsave.html?id={id}` | `password,password2,verType,code[...]` | ⚠ 危险 |
| 改 VNC 密码 | POST | `/user/cloud/vncpwdsave.html?id={id}` | `vnctype,password,password2,...` | ⚠ |
| VNC 控制台 | — | `/user/cloud/vnc.html?id={id}` → `/user/cloud/vncconsole` | — | 页面内嵌 |

### 详情页字段

`manage.html` 里 `div.list > span.name + p` 就是键值对：`名称 / 地域 / 公网IP /
登录账号 / 登录密码（掩码）/ VNC登录密码 / **登录端口** / 付费方式 / 产品类型 /
开通时间 / 到期时间 / 自动续费 / 实例规格 / SSD系统盘 / 公网带宽 / 防御峰值`。

> 页面里大量 `<!-- -->` 注释掉旧字段，解析前必须先删注释，否则键值会串行。

## 云防火墙（安全组）`/user/firewall`

| 功能 | 方法 | 路径 | 参数 | 状态 |
| --- | --- | --- | --- | --- |
| 安全组列表 | GET | `/user/firewall/safegroups.html` | — | ✅读 |
| 新建安全组 | POST | `/user/firewall/add.html` | `name,desc` | ⚠ |
| 修改安全组 | POST | `/user/firewall/edit.html?id={gid}` | `name,desc` | ⚠ |
| 删除安全组 | POST | `/user/firewall/destroy` | `id` | ⚠ |
| 关联实例 | POST | `/user/firewall/groupVpsAdd` | `groupId,ids[]`（**实例名**） | ⚠ |
| 组内实例 | POST | `/user/firewall/tableListCloud` | `groupId,type=s_ip,keywords=` | ✅读 |
| 规则列表 | GET | `/user/firewall/grouprulestablelist.html?id={gid}&direction=Inbound\|Outbound` | — | ✅读 |
| 添加规则 | POST | `/user/firewall/rulesAdd` | 见下 | ✅写 |
| 批量添加 | POST | `/user/firewall/rulesAddBatch` | `id, rules[i][...]` | ✅写（⚠ 实测服务端忽略 weight/desc，会自动排 200/210…） |
| 修改规则 | POST | `/user/firewall/rulesEdit` | 同添加 + `ruleId` | ✅写 |
| 删除规则 | POST | `/user/firewall/rulesRemove` | `id, ruleIds[]` | ✅写 |

`safegroups.html` 返回行：
`[组ID, 名称, 关联实例数, 描述, 规则数, 创建时间, 操作按钮HTML]`

`grouprulestablelist` 返回行：
`[复选框HTML, 规则ID, 行为(允许/拒绝), 协议, 端口(空=全部), 授权IP(空=全部), 优先级, 描述, 创建时间, 操作HTML]`

添加规则的 payload（网页 Vue 里的 form）：

```
id=<组ID>
direction=Inbound|Outbound
weight=200                 # 越大越先执行
protocolType=1|2           # 1=全部/ICMP, 2=TCP/UDP
protocol=TCP|UDP|ICMP|ANY
protocolV=同上
action=Allow|Deny
port=22 | 8000-8100 | 1-65535
ip=0.0.0.0/0
desc=
# 入方向追加：remote_ip=<ip>, local_port=<port>
# 出方向追加：local_ip=<ip>, remote_port=<port>
```

## 端口视图怎么算出来的

规则按 `weight` 从大到小排序，对每个端口取第一条协议匹配且端口区间包含它的规则；
把所有规则的区间端点收集起来切成小段，就得到 1-65535 的完整归属图。
SDK 里是 `landui_sdk.firewall.resolve_port_map()`，纯函数，UI 和脚本都能用。

## 单机 ACL 硬防 `/user/cloud`

| 功能 | 方法 | 路径 | 参数 | 状态 |
| --- | --- | --- | --- | --- |
| 策略列表 | GET | `/user/cloud/getaclList` | `id,cloudname,type=vps` | ✅读（layui 格式 `{code:0,count,data}`） |
| 新增策略 | POST | `/user/cloud/acladd?cn={name}&id={id}` | `weight,direction,action,protocol,protocol_other,stateful,remote_ip,remote_port,local_ip,local_port,adapter` | ⚠ |
| 删除策略 | POST | `/user/cloud/acldel.html?id={aclId}` | — | ⚠ |
| 清空策略 | POST | `/user/cloud/aclcls.html?cn={name}&id={id}` | — | ⚠ 危险 |
| 拖动排序 | POST | `/user/cloud/ajaxaclUpdate` | `id,cloudname,type,row,cache,oldIndex,newIndex` | ⚠ |

> 两套防火墙的区别：**安全组**按组挂实例，是日常开端口用的；**ACL** 是绑单机、
> 按 weight 排序的硬防策略，普通账号多为空。

## 其它产品列表（DataTables，只读）

| 产品 | 路径 |
| --- | --- |
| 域名 | `/user/domain/tablelist.html` |
| 虚拟主机 | `/user/host/tablelist.html` |
| 租用/托管 | `/user/idc/tablelist.html` |
| SSL 证书 | `/user/ssl/tablelist.html?expirday=` |
| 告警规则 | `/user/monitor_new/tablelistrule.html` |

## 未做的部分

* 负载均衡 / 云数据库 / 对象存储 / 容器镜像 / DNS 是**独立子控制台**
  （`lb.` / `rds.` / `oss.` / `dcr.` / `dns.console.landui.com`），接口体系不同，未覆盖。
* 工单、发票、实名认证等账号类接口未整理。
