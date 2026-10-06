# 产品指标（v1）

租户管理员**显式开启**后，服务端只保存回答四个问题所需的按日计数：首次接入完成耗时、接入步骤流失、按文件大小区间与传输方式拆分的互传成功率、失败后重试的成功率。默认关闭；不采集凭证、文件名、文本内容、内网地址、IP、User-Agent 或跨租户可关联的访客标识；有固定的保存期限和一键清除。

关联 [issue #38](https://github.com/devShuai/specus/issues/38) 的待办「产品指标」，见 [docs/issues/product-followups.md](../../docs/issues/product-followups.md)。

**状态：契约已定（第 13 节各项采用推荐默认值），已实现。** Java、Go、.NET 与 C 四个服务端实现第 6 节的四张表与第 7 节的接口，并经各自真实的 HTTP 处理代码逐节回放共享向量；管理前端提供开关与说明、汇总视图、成员常驻说明和互传结果上报。四端共同遵守的实现约定见第 14 节。共享向量 `protocol/test-vectors/product-metrics-v1.json` 由 `tools/protocol/generate_product_metrics_vectors.py` 生成。

## 1. 现状

### 1.1 首次接入：界面步骤与服务端能看到的事实

接入页 `CLIENT_ONBOARDING_STEPS`（`apps/admin-web/src/lib/clientOnboarding.ts`）和帮助页给出的顺序是：下载 → 创建接入凭证并保存 `client.jsonc` → 启动客户端并等待上线 → 发布服务 → 手动验证访问。按服务端能否观察到，对应关系如下：

| 用户动作 | 服务端写路径 | 现有表（四端同名或同义） | 可观察 |
| --- | --- | --- | --- |
| 注册 / 管理员新建账号 | 注册验证完成、管理员新建用户 | `specus_management_user`（`tenant_id`、`role`、`created_at`；无最近登录时间） | 是 |
| 登录管理后台 | 签发管理会话 | 无持久记录 | 是（写路径上） |
| 下载客户端 | 无：安装包来自 GitHub Release 或下载链接 | — | 否 |
| 创建接入凭证 | `POST` 新建凭证 | `specus_client_credential`（`owner_username`、`created_at`） | 是 |
| 启动客户端，实例出现并在线 | 客户端首次 apiKey/secret 登录时生成实例 | `specus_client_account`（`owner_username`）、`specus_client_identity`（含机器指纹、OS 用户、主机名） | 是 |
| 发布服务 | 新建 HTTP route / TCP 端口映射 | `http_route_mapping`、`specus_mapping`（含 `target_base_url`、`target_address`） | 是 |
| 验证访问 | 用户自己打开访问链接；连通性检查（[service-connectivity-check.md](service-connectivity-check.md)）尚在实现 | — | 否 |

自助注册把用户放进配置的租户（默认 `default`），角色为 `USER`；内置管理员来自配置，不是数据库里的用户行。

### 1.2 互传：浏览器知道哪些结果

- 发送方式（`FileDeliveryMode`）只有 `device`（发给房间里的设备）和 `link`（生成文件链接，经对象存储）。
- 设备传输的实际路径（`PeerTransportPath`）是 `direct` 或 `turn`。远端设备失败后，经用户逐次授权可以改走临时存储（`cloudFallbackPermitted`：已同意、已登录、且不在同一局域网）。
- 发送记录的状态是 `queued / connecting / sending / completed / failed / cancelled`。`failed` 或 `cancelled` 的记录可以由用户重试，重试仍发给原接收设备，不扩大原授权。
- 只有**发送方浏览器**知道一次尝试的结局：直连和 TURN 的内容不经过服务端，服务端只看得到云端路径的预签名、完成和下载。
- 互传房间**不属于任何租户**：`public_transfer_room` 只有 `room_name`、`owner_token_hash`、`created_by_peer_id`。只有云端附件 `transfer_attachment` 记录了已登录用户的 `tenant_id/username`。

### 1.3 「概览」和流量表已经算了什么

`GET /api/admin/overview` 返回实例数与在线数（实例列表与会话表）、控制连接成功/失败次数（`specus_connection_record` 计数，普通用户只算自己的实例）、累计上下行字节和外部连接计数（进程内计数器）。「近日日流量」和「客户端流量排行」来自 `GET /api/admin/traffic?limit=120`，即 `specus_traffic_usage`（每实例每 UTC 日一行）；版本分布来自实例列表。另有 `specus_resource_traffic_usage`、`specus_connection_stat`（按月）、HTTP/TCP 流量明细（默认关闭）。

这些都是**运维数据**：按客户端名称记录，`specus_connection_record.remote_address` 存了来源地址，明细表存了请求内容。它们回答不了上述四个问题，本契约也**不得读取或关联**它们（第 11 节）。

### 1.4 开关与设置存储

四端都没有通用的租户设置、用户偏好或同意记录表，也没有通用审计表。唯一可参照的是出口分流的租户总开关 `peer_mesh_egress_switch(tenant_id 主键, enabled 默认 0, updated_by, updated_at)`：`PUT /api/admin/peer-mesh/egress/switch`，非 `ADMIN` 返回 `403`。HTTP 流量明细是「全局配置 + 每条 route 开关」，都默认关闭。

由此得到三条结论，决定了契约的形状：

1. **接入里程碑全部能在服务端写路径上看到。** 浏览器上报接入事件只会更不准、更容易伪造，所以 v1 不让浏览器上报任何接入事件。
2. **互传结果只有发送方浏览器知道**，只能由它上报。房间没有租户，因此只有**已登录发送方**的结果计入**其所在租户**；匿名互传一律不计数。
3. 新增一张租户开关表和三张计数表，不复用任何现有表。

## 2. 范围

| 问题 | 指标 | 来源 |
| --- | --- | --- |
| 首次接入完成耗时 | 完成者从账号创建到首次发布服务的耗时分桶及中位桶 | 服务端里程碑 |
| 步骤流失 | 每一步到达人数与相对上一步的转化率 | 服务端里程碑 |
| 按文件大小区间/传输方式拆分的成功率 | 路径 × 大小区间、发送方式两种切法的成功率 | 浏览器上报的尝试结果 |
| 失败重试成功率 | 「失败后重试」这类尝试的成功率 | 同上 |

不在 v1 内：下载和「验证访问」两步（服务端看不到，见第 13 节）、失败原因、传输耗时与速度、接收方结果、剪贴板/白板、Peer 服务、跨租户或全平台汇总、按用户或按设备的任何视图。

## 3. 开启模型

- **租户级开关，默认关闭。** 每个租户一行；没有行即关闭。只有该租户的 `ADMIN`（含默认租户的内置管理员）可以开关，`USER` 返回 `403`。开关只影响本租户。
- **开启必须确认说明。** `PUT` 开启时必须带 `"disclosureVersion": 1`，表示界面已经展示了第 1 版说明并由管理员确认；缺失或不等于当前版本返回 `400 PRODUCT_METRICS_DISCLOSURE_REQUIRED`。说明的内容改变时提升版本，已开启的租户不受影响，但下次开启需确认新版本。
- **只对开启之后的事实生效。** 不回填：开启前创建的账号永远不进入接入队列，开启前的传输不计数，也不得从现有表的 `created_at` 推算历史（第 11 节）。
- **关闭立即停止采集**（各实例对开关的缓存不超过 30 秒），同时删除该租户所有进行中的接入进度行（不汇总）；已有的按日计数保留到期满，除非清除。关闭界面紧接着提供「同时清除已收集的数据」。
- **再次开启**清空「已清除」标记，从零开始新的队列。

### 3.1 界面必须说明的内容

开启确认框（管理员）逐条列出，措辞可以调整但内容不能缺：

- 统计什么：新账号在 14 天内是否完成「登录 → 创建接入凭证 → 客户端上线 → 发布服务」以及完成耗时区间；已登录成员在互传中每次发送的方式（设备/链接）、实际路径（直连/中继/临时存储/未建立）、文件大小区间、第几次尝试和结果（成功/失败/取消）。
- 不统计什么：凭证、文件名、文件类型、精确大小、文本或剪贴板内容、房间与设备标识、IP 或内网地址、目标地址、浏览器信息、失败原因文本。匿名访客的互传不统计。
- 怎么保存：只存按天汇总的计数；接入进度只在 14 天窗口内按账号暂存，结束即汇总并删除。计数保存 180 天。
- 谁能看：只有本租户管理员能看汇总，看不到任何个人或单次记录。
- 怎么停：随时关闭；关闭时可以一并清除全部已收集数据。

成员一侧：开关打开时，管理后台（账户菜单或帮助页）和已登录的互传页显示一行常驻说明，例如「你所在组织已开启产品指标：只统计传输方式、文件大小区间与成败次数，不含文件名、内容或地址」，并链接到完整说明。互传页的说明旁提供「本设备不参与」，选择保存在浏览器本地存储里；选择后该浏览器不再发送任何传输事件。

## 4. 事件与字段（封闭清单）

### 4.1 服务端观察的接入里程碑

| 序号 | `step` | 记录时机（服务端写路径成功之后） | 归属 |
| ---: | --- | --- | --- |
| 1 | `account_created` | 注册验证完成或管理员新建用户；**唯一能开启进度的里程碑** | 新账号 |
| 2 | `signed_in` | 为该用户签发管理会话（密码或 OIDC） | 该用户 |
| 3 | `credential_created` | 新建接入凭证 | 凭证的 `owner_username` |
| 4 | `client_online` | 客户端控制连接登录成功（含首次登录生成实例） | 实例的 `owner_username` |
| 5 | `service_published` | 新建 HTTP route 或 TCP 端口映射 | 目标实例的 `owner_username` |

规则：

- 账号创建时租户开关打开，才为它新建一行进度（`tenantId + username` 唯一，已存在则忽略）。没有进度行的用户，后续里程碑一律忽略；内置管理员不是用户行，永远不进入队列。
- 每个里程碑只记**首次**时刻，重复发生不改写。
- 里程碑按发生记录，不要求前一步已经记录：管理员可能先替用户建凭证，用户之后才登录。**到达的步骤取已记录的最大序号**，较晚的步骤视为隐含了较早的步骤（统计「到达第 k 步及以后」的人数，见 7.5）。
- **窗口 14 天**：`service_published` 在 `startedAt + 14 天` 之前（严格小于）发生，进度行立即以「完成」关闭，耗时为两者之差。等于或晚于窗口结束时，进度行以「未完成」关闭，到达步骤取窗口内已记录的最大序号。任何里程碑落在窗口结束之后，先按过期关闭，再丢弃该里程碑。清理任务对过期行做同样的关闭。结果与清理任务何时运行无关。
- **关闭**：在同一事务里删除进度行，并把计数器 `(tenantId, cohortDay = startedAt 的 UTC 日期, reachedStep, durationBucket)` 加一。未完成的 `durationBucket` 为 `"none"`。
- 用户被删除时删除其进度行，不汇总。租户关闭开关时删除该租户全部进度行，不汇总。
- 多实例之间时钟偏差可能让耗时为负，按 0 计。

不记录凭证或实例的标识、客户端名称、机器指纹、route 路径、目标地址、服务类型，也不区分是谁执行的操作。

### 4.2 浏览器上报的传输结果

发送方浏览器在一次尝试进入终态时生成一条事件。**每条事件恰好有以下五个字段**，值都是区分大小写的字符串：

| 字段 | 取值 | 含义 |
| --- | --- | --- |
| `mode` | `device`、`link` | 用户选择的发送方式 |
| `path` | `direct`、`turn`、`cloud`、`unestablished` | 这次尝试最终走的路径。`device` 加上 `cloud` 表示经授权改走临时存储。还没有建立任何路径就结束时为 `unestablished` |
| `sizeBucket` | 第 5 节的五个区间 | 该文件大小所在区间，由浏览器计算，精确大小不离开浏览器 |
| `attempt` | `first`、`retry_after_failure`、`retry_after_cancel` | 该发送记录的第一次尝试，还是在上一次尝试失败/取消之后由用户发起的重试 |
| `outcome` | `success`、`failure`、`cancelled` | 发送记录进入 `completed`、`failed`、`cancelled` |

组合约束：`mode = link` 时 `path` 只能是 `cloud` 或 `unestablished`；`outcome = success` 时 `path` 不能是 `unestablished`。

上报规则：

- 只有已登录、`GET /settings` 返回 `enabled: true`、且本设备未选择「不参与」时才发送。接收方从不上报，因此一次传输只计一次。
- 每次尝试最多一条事件。页面关闭时仍在进行中的尝试不上报。
- **最多送达一次**：事件不带 ID 和时间戳；浏览器攒到 20 条或首条待发事件已等待 5 秒时发送，`pagehide` 时用 `fetch(..., {keepalive: true})` 发出剩余事件；请求失败、`429` 或 `400` 都直接丢弃，不重试。因此计数是下界。
- 计数日期取服务端收到请求时的 UTC 日期。

### 4.3 永不采集

以下内容不得出现在请求、计数行、日志或响应里：凭证与 token、文件名、MIME 类型、精确字节数、文件哈希、文本/剪贴板/白板内容、房间名或口令、房间/设备/peer 标识、客户端名称、route 路径、目标地址、ICE 候选与任何 IP 或内网地址、User-Agent 和设备信息、失败原因文本、客户端时间戳、事件 ID 或任何持久的访客标识。服务端用封闭 schema 校验请求，任何多余字段都使整个请求被拒绝，不存在「忽略未知字段」的路径。

## 5. 分桶与比率

文件大小（字节）。0 字节和负数不会产生事件（发送前确认已拦截空文件）：

| `sizeBucket` | 范围 |
| --- | --- |
| `lt1m` | 1 ≤ s < 1 MiB |
| `1m-16m` | 1 MiB ≤ s < 16 MiB |
| `16m-128m` | 16 MiB ≤ s ≤ 128 MiB（含设备传输内存上限 128 MiB） |
| `128m-512m` | 128 MiB < s ≤ 512 MiB（含默认附件上限） |
| `gt512m` | s > 512 MiB |

区间与当前产品限制解耦：服务端不因「设备传输不允许超过 128 MiB」拒绝 `device` + `128m-512m`，限制将来可能变化。

接入耗时（秒，`completedAt - startedAt`，负数按 0）：

| `durationBucket` | 范围 |
| --- | --- |
| `lt10m` | [0, 600) |
| `10m-30m` | [600, 1800) |
| `30m-2h` | [1800, 7200) |
| `2h-24h` | [7200, 86400) |
| `1d-3d` | [86400, 259200) |
| `3d-14d` | [259200, 1209600) |

比率一律用整数基点，四舍五入（0.5 进位）：`rateBp(n, d) = floor((20000·n + d) / (2·d))`，`d = 0` 时为 `null`。成功率的分母是 `success + failure`，**`cancelled` 不进分母**，单独计数展示。

## 6. 存储与聚合

不存原始事件。逻辑上四张表（物理表名建议如下）：

| 表 | 主键 | 其他列 |
| --- | --- | --- |
| `product_metrics_switch` | `tenant_id` | `enabled`、`updated_by`、`updated_at`、`purged_at` |
| `product_metrics_onboarding_progress` | `tenant_id, username` | `started_at`、`signed_in_at`、`credential_created_at`、`client_online_at`（都可空） |
| `product_metrics_onboarding_daily` | `tenant_id, cohort_day, reached_step, duration_bucket` | `users` |
| `product_metrics_transfer_daily` | `tenant_id, day, mode, path, size_bucket, attempt, outcome` | `count` |

- 进度行是唯一带账号名的数据，只为完成「同一个人从第 1 步走到第 5 步花了多久」而存在，最长存活 14 天加一次清理周期；读接口从不返回它。没有 `service_published_at` 列，因为完成即关闭。
- 传输计数在收到请求时直接累加。一个请求在**一个事务**里完成「读开关 → 限流 → 对每个键做原子累加」（`INSERT ... ON CONFLICT DO UPDATE SET count = count + ?` 或等价写法），不在内存里先读后写，也不在实例内存里缓冲。
- `username` 只用于进度行定位，`updated_by` 只给管理员看；计数表里没有任何用户列。

## 7. 接口

全部要求与管理后台相同的 Bearer 登录；身份和租户只取自会话，请求体里不接受租户或账号字段。成功响应带 `Cache-Control: private, no-store`。

### 7.1 查看开关

```http
GET /api/admin/product-metrics/settings
```

任何已登录成员可读，互传页和管理后台据此决定是否显示说明、是否上报：

```json
{"schemaVersion": 1, "enabled": true, "disclosureVersion": 1, "retentionDays": 180,
 "onboardingWindowDays": 14, "updatedAt": "2026-09-01T00:00:00Z", "updatedBy": "root"}
```

`updatedBy` 只返回给 `ADMIN`。从未设置过时 `enabled: false`、`updatedAt: null`。`disclosureVersion` 是服务端当前要求确认的版本。

### 7.2 开关

```http
PUT /api/admin/product-metrics/settings
{"enabled": true, "disclosureVersion": 1}
```

`ADMIN` 才可调用，否则返回 `403`。请求体只能含 `enabled`（必填，布尔）和 `disclosureVersion`（整数），否则返回 `400 PRODUCT_METRICS_INVALID`。开启时版本不符返回 `400 PRODUCT_METRICS_DISCLOSURE_REQUIRED`。关闭只需 `{"enabled": false}`。状态没有变化时不改 `updatedAt/updatedBy`。关闭时删除进度行（第 3 节）。响应体同 7.1。

### 7.3 清除

```http
DELETE /api/admin/product-metrics/data
```

`ADMIN` 才可调用。在一个事务里删除本租户的进度行和两张计数表的全部行，并把 `purged_at` 记为当前时刻，返回 `{"purged": true, "enabled": <当前开关>}`。开关打开时也可以清除，之后从零继续计数。

### 7.4 上报传输结果

```http
POST /api/admin/product-metrics/transfer-outcomes
Content-Type: application/json

{"schemaVersion": 1, "events": [
  {"mode": "device", "path": "direct", "sizeBucket": "lt1m", "attempt": "first", "outcome": "success"}]}
```

任何已登录成员可调用。按以下顺序处理，前一步拒绝时后面的步骤都不执行，也不消耗限流额度：

| 顺序 | 情形 | HTTP | 响应体 |
| ---: | --- | ---: | --- |
| 1 | 没有有效会话 | `401` | — |
| 2 | 原始请求体超过 4096 字节（解析前判断） | `413` | `{"code": "PRODUCT_METRICS_TOO_LARGE"}` |
| 3 | 不是 JSON；顶层不是恰好含 `schemaVersion`（整数 1，布尔不算）与 `events`（1..20 个元素的数组）的对象；任一事件不符合 4.2 | `400` | `{"code": "PRODUCT_METRICS_INVALID"}`，整批不计 |
| 4 | 租户开关关闭 | `200` | `{"collecting": false, "accepted": 0}` |
| 5 | 限流（第 8 节） | `429` | `{"code": "PRODUCT_METRICS_RATE_LIMITED"}`，整批不计 |
| 6 | 计数 | `200` | `{"collecting": true, "accepted": <事件数>}` |

浏览器收到 `collecting: false` 时停止上报，并重新读取 7.1。

### 7.5 汇总

```http
GET /api/admin/product-metrics/summary?from=2026-09-01&to=2026-09-21
```

`ADMIN` 才可调用。`from`、`to` 是闭区间的 UTC 日期，缺省时 `to` 为今天，`from` 为 `to` 往前 29 天。`from > to`、跨度超过 180 天、`to` 晚于今天、`from` 早于保存期（今天往前 179 天）时，返回 `400 PRODUCT_METRICS_RANGE`。开关关闭后仍可读取保留的数据。

```json
{
  "schemaVersion": 1, "enabled": true, "from": "2026-09-01", "to": "2026-09-21", "generatedAt": "2026-09-21T00:00:00Z",
  "onboarding": {
    "windowDays": 14, "cohortUsers": 7, "pendingUsers": 1, "final": false,
    "steps": [
      {"step": "account_created", "users": 7, "fromPreviousRateBp": null},
      {"step": "signed_in", "users": 7, "fromPreviousRateBp": 10000},
      {"step": "credential_created", "users": 6, "fromPreviousRateBp": 8571},
      {"step": "client_online", "users": 5, "fromPreviousRateBp": 8333},
      {"step": "service_published", "users": 4, "fromPreviousRateBp": 8000}
    ],
    "completed": 4, "completionRateBp": 5714,
    "durations": [{"bucket": "lt10m", "users": 1}, {"bucket": "10m-30m", "users": 1}, {"bucket": "30m-2h", "users": 1},
                  {"bucket": "2h-24h", "users": 0}, {"bucket": "1d-3d", "users": 0}, {"bucket": "3d-14d", "users": 1}],
    "medianDurationBucket": "10m-30m"
  },
  "transfers": {
    "cells": [{"path": "direct", "sizeBucket": "lt1m", "success": 3, "failure": 1, "cancelled": 0, "successRateBp": 7500}],
    "byMode": [{"mode": "device", "success": 8, "failure": 4, "cancelled": 1, "successRateBp": 6667},
               {"mode": "link", "success": 1, "failure": 1, "cancelled": 0, "successRateBp": 5000}],
    "byAttempt": [{"attempt": "first", "success": 6, "failure": 3, "cancelled": 1, "successRateBp": 6667},
                  {"attempt": "retry_after_failure", "success": 2, "failure": 2, "cancelled": 0, "successRateBp": 5000},
                  {"attempt": "retry_after_cancel", "success": 1, "failure": 0, "cancelled": 0, "successRateBp": 10000}],
    "total": {"success": 9, "failure": 5, "cancelled": 1, "successRateBp": 6429}
  }
}
```

- **接入**按队列日期（账号创建的 UTC 日期）落在区间内的用户统计。已关闭的计数加上仍在进行的进度行（按其当前到达步骤），因此最近的队列不会因为「完成即关闭、流失要等 14 天」而偏向完成。`steps[k].users` 是到达第 k 步或更后面步骤的人数。`pendingUsers` 是仍在窗口内的进度行数，`final` 等于 `pendingUsers == 0`；不是 final 时，界面必须标明完成率仍会变化。已过窗口但还没被清理的进度行按未完成计算，不计入 `pendingUsers`。
- `medianDurationBucket`：把完成者按区间顺序排开，取第 ⌈n/2⌉ 个所在的区间；没有完成者时为 `null`。
- **传输**按计数日期落在区间内的行统计。`cells` 按 `path`（`direct, turn, cloud, unestablished`）再按大小区间的顺序排列，只列出有计数的格子；`byMode`、`byAttempt` 总是列出全部取值。四个问题里的「失败重试成功率」就是 `byAttempt` 中 `retry_after_failure` 的 `successRateBp`。
- 响应里没有用户名、日期明细之外的维度，也没有任何单条记录。

## 8. 限流与载荷上限

- 请求体最多 4096 字节，每个请求最多 20 条事件。20 条最长取值的事件约 2.7 KB。
- 按事件数计的固定窗口（UTC 整分钟）：每个 `tenantId + username` 每分钟 120 条，每个租户每分钟 3000 条。一个请求如果会让任一计数超出上限，就整批拒绝且不消耗额度。发送队列上限为 40 项，正常使用远低于这个限额。
- 限流器按进程计，与现有限流器一致；多实例时实际上限是实例数倍，可以接受，因为它只影响本租户自己的统计。如果部署启用了互传集群的共享限流（[public-transfer-cluster.md](public-transfer-cluster.md)），可以复用。
- 上报接口的访问日志不得记录请求体。

## 9. 保存期限与清除

- 计数行（两张按日表）保存 180 天：清理时删除日期早于「今天往前 179 天」的行，今天也算一天。
- 进度行最多存活 14 天（窗口）加一个清理周期，然后关闭并删除。
- 清理任务每小时至少运行一次，任何实例都可以运行，可以重复执行：
  1. 开关关闭的租户：删除全部进度行（处理与关闭操作并发的写入）；
  2. 其余进度行中已过窗口的，按 4.1 关闭；
  3. 删除超过保存期的计数行；
  4. 开关关闭**并且**清除过（`purged_at` 不为空）的租户：删除全部计数行，用来清掉开关缓存期内写入的残留。
- 清除见 7.3；删除租户或用户时同步删除对应的行。
- 清除是硬删除，无法恢复；数据库备份里的副本按部署自身的备份保留策略过期，界面说明里应写明这一点。

## 10. 多实例一致性

- 开关存于共享数据库，每租户一行。各实例可以缓存开关，最多 30 秒。关闭后最多 30 秒内仍可能有写入；如果同时清除，第 9 节第 4 步会在下一次清理时删掉这些残留。
- 进度行：创建使用主键去重（insert-if-absent）；里程碑用条件更新 `SET x_at = ? WHERE ... AND x_at IS NULL`，先到者为准。关闭在一个事务里执行「删除进度行（影响行数必须为 1）→ 累加日计数」，影响 0 行时不累加，所以并发的完成和清理只会计一次。
- 计数：只用数据库原子累加，不先读后写，不在内存缓冲。
- 日期边界取处理请求的实例的 UTC 时钟；实例间偏差会让午夜附近的计数落到相邻日期，可以接受。
- C server 使用同样的表和规则；它不实现的写路径（例如没有自助注册）就不会产生对应里程碑。

## 11. 禁止的推断与用途

- 不得把指标表与 `specus_connection_record`、流量用量与明细、`transfer_attachment`、互传房间、Peer 审计、`specus_client_identity` 等任何现有表关联，也不得把这些表当作指标来源。
- 不得从现有表的 `created_at` 回填开启前的接入数据，不得把关闭期间的事实补进来。
- 不得推断或展示单个用户、设备、房间的行为，不得尝试再识别；不提供按用户、按客户端或按小时的维度。
- 不得从大小区间推断文件类型或内容，不得从路径分布推断网络位置或 NAT 类型并归到个人。
- 不得把指标用于计费、额度、限流、封禁或滥用判定，也不得作为 SLA。传输计数是由用户浏览器上报的下界，可能缺失，也可能被本租户成员在限流范围内伪造。
- `success` 只表示发送方看到「对方已接收」或「文件链接已生成」，不表示对方已经保存文件；`service_published` 只表示创建了发布，不表示可以访问。
- 不得跨租户比较或汇总，v1 不提供平台级视图。

## 12. 共享向量

`protocol/test-vectors/product-metrics-v1.json`（由 `tools/protocol/generate_product_metrics_vectors.py` 生成，生成器内含参考实现，写文件前用手算结果断言）：

| 部分 | 内容 |
| --- | --- |
| `vocabulary`、`constants` | 封闭取值、区间边界、上限 |
| `sizeBuckets`、`durationBuckets`、`rates` | 区间边界（含 0、负数、128 MiB、512 MiB、窗口边界）与基点舍入（含 0.5 进位） |
| `ingestValidation` | 44 个原样请求体（`bodyText`）及其期望：多余字段（文件名、精确大小、MIME、文本、房间/peer、IP、ICE 地址、UA、错误文本、时间戳、事件 ID、耗时、租户、访客 ID）、类型与大小写、组合约束、整批拒绝、恰好 4096 字节与 4097 字节 |
| `scenarios` | `onboarding-funnel`（开关权限与说明确认、开启前账号、窗口内差 1 秒完成、恰好到窗口结束过期、先建凭证后登录、关闭丢弃进度、用户删除、清除、汇总与区间校验）、`transfer-outcomes`（计数、跨午夜、未开启租户、关闭后上报、清除、各切法的比率）、两个限流场景、`retention-sweep`（预置行：保存期边界、过期关闭、关闭租户的残留、清除后的残留） |

各端按场景顺序回放：把时钟固定在每个 op 的 `at`，比较带 `status` 的响应，并在每个 `checkpoint` 比较四张表的内容（时间按时刻比较）。`milestone` 是服务端内部写路径的钩子，由测试直接触发；其 `effect` 只供排错，不要求可观察。`limits` 是该场景的限流配置，实现需要能在测试里设置。

## 13. 已定事项（采用推荐默认值）

以下各项在草案阶段列为未决，按维护者对同类问题的一贯做法，采用各条的推荐默认值。

| 问题 | 推荐默认 |
| --- | --- |
| 部署级总开关：运营方能否整体禁用此功能 | 提供配置 `productMetrics.allowed`，默认 `true`；为 `false` 时 7.1 恒返回 `enabled: false`，开启请求返回 `409`，上报一律 `collecting: false` |
| 匿名互传是否计数 | 不计。房间没有租户，没有人能替匿名访客同意；如果以后需要，只能做部署级、单独说明的开关，不在 v1 |
| 成员级退出 | v1 只提供互传页的「本设备不参与」（本地存储）。接入里程碑来自管理员本来就能看到的事实，不提供逐人退出；如果合规要求，v2 加服务端用户级退出标记 |
| 接入窗口长度 | 14 天。7 天会把需要审批或采购设备的团队算作流失；30 天会让进度行存活过久，最近一个月的结论也迟迟不能定 |
| 「下载客户端」与「验证访问」两步 | v1 不纳入。验证访问待连通性检查实现后，可以把「某 route 首次 `access-succeeded`」作为第 6 步并提升 `disclosureVersion`；下载不做浏览器埋点 |
| 失败阶段（连接/传输/上传/确认）| v1 不采集。确有诊断需求时，增加一个四值封闭枚举，并提升说明版本 |
| 小样本抑制（某格人数少于 k 时隐藏）| v1 不做：汇总没有用户维度，管理员本来就能看到账号、凭证和发布的创建时间，按日差分也会让阈值失效。依靠成员侧常驻说明保证透明 |
| 计数保存期 | 180 天，不提供租户自定义；允许缩短作为后续选项 |
| Peer 服务发布是否算 `service_published` | 不算：它由客户端配置上报，不是管理端的发布动作 |
| 上报与开关接口放在 `/api/admin` 下 | 是。互传页已登录时使用同一 Bearer；不新开公开端点 |

## 14. 实现约定

四个服务端在契约之外统一采用以下做法，彼此保持一致：

- **表**：表名与列名即第 6 节的建议名。时间列（`updated_at`、`purged_at`、`started_at`、`*_at`）是 epoch 毫秒（BIGINT），
  日期列（`cohort_day`、`day`）是 UTC `YYYY-MM-DD` 文本，因此区间筛选与保存期截止都是字符串比较。没有外键和代理主键。
- **开关读取**：每次上报、里程碑与读取都直接读库，不做实例内缓存（第 10 节允许最多 30 秒，这里取 0）。
- **部署级开关**（第 13 节）：Go/C `SPECUS_PRODUCT_METRICS_ALLOWED`，Java `specus.product-metrics.allowed`，
  .NET `Specus:ProductMetrics:Allowed`。为 `false` 时开启返回 `409 {"code": "PRODUCT_METRICS_NOT_ALLOWED"}`，关闭仍可执行。
- **存储故障**：任何读写失败返回 `503 {"code": "PRODUCT_METRICS_UNAVAILABLE"}`，不把读不到当作零。
- **封闭 schema**：除第 4.2、7.2 节外，重复的键、`1.0`/`1e0` 形式的版本号、JSON 之后的多余内容和非法 UTF-8 也使整个请求无效。
- **时刻输出**：`updatedAt`、`generatedAt` 截断到秒，形如 `2026-09-01T00:00:00Z`；`from`/`to` 只接受 `YYYY-MM-DD`，格式不符同样返回
  `400 PRODUCT_METRICS_RANGE`。
- **里程碑钩子**：在写路径提交之后调用，失败只记日志（租户、步骤、错误类别），从不影响写路径本身；`signed_in` 覆盖密码登录、
  注册验证后的签发和本地签发会话的 OIDC 登录。OIDC 首次登录自动建号不算 `account_created`（第 4.1 节未列出这一写路径）。
- **日志**：指标相关日志只含租户、操作与错误类别，不含用户名、请求体或任何第 4.3 节列出的内容。
