# 服务连通性检查（v1，草案）

所有者或租户管理员可以对**一条自己选中的 HTTP route** 做一次有界的端到端检查。检查按固定顺序给出四个阶段：已配置、设备在线、目标可达、访问成功。每个阶段带稳定的结果码和判定时刻，遇到第一个没有通过的阶段就停止。它回答的问题是「此刻从服务端经设备到目标走一遍，停在哪一步」，不是「目录里登记了什么」。

关联 [issue #38](https://github.com/devShuai/specus/issues/38) 的待办「真实端到端连通性检查」，见 [docs/issues/product-followups.md](../../docs/issues/product-followups.md)。

**状态：仅为契约草案，四个服务端、四个客户端和管理前端都还没有实现。** 共享向量 `protocol/test-vectors/service-connectivity-check-v1.json` 由 `tools/protocol/generate_service_connectivity_vectors.py` 生成。

## 1. 现状

### 1.1 用户今天能选择的服务

| 服务 | 管理入口 | 访问路径 | 今天的「检查」 |
| --- | --- | --- | --- |
| HTTP route | `GET /api/admin/http-routes`、`POST /api/admin/clients/{id}/http-routes`、`PUT/DELETE /api/admin/http-routes/{id}` | 公网 `ANY /http/{clientName}/{route}/**`。服务端在设备的 `data` 连接上开 NAT stream，客户端访问 `targetBaseUrl`，见 [http-route.md](http-route.md) | 无。管理页只显示设备的在线标记；新建后提示「已创建 · 待验证访问」，并给出访问链接 |
| TCP 端口映射 | `/api/admin/specus-mappings`、`POST /api/admin/clients/{id}/specus-mappings` | 公网端口经 NAT `OPEN` 转到设备本地端口 | 无 |
| Peer 服务 | `/api/admin/peer-mesh/services`、`/api/admin/peer-mesh/service-sharing` | 对端经 Peer Mesh 虚拟 IP 访问 `publishedPort`，数据面在两台客户端之间端到端加密，见 [peer-mesh.md](peer-mesh.md) | 「检查目录状态」：重新读取服务定义和共享状态，再按发布端最近一次 `service-report` 重算可用性。结果只存在页面状态里，时间取浏览器时钟，不向目标发起连接 |

Peer 服务目录里的「已发布」来自发布端自己的本地探测：TCP 连接成功，或者 UDP 收到了应答。它反映的是发布端上报那一刻的情况，而不是「现在能访问」。issue #37 已经把这个动作改名为「检查目录状态」，并明确它不构成连接验证。本契约不改变这一点。

### 1.2 目标不可达时，今天线上传回什么

前提是 route 已启用且设备在线。客户端连不上 `targetBaseUrl` 时，四个客户端都**不会自己编造 HTTP 响应**。它们都发 NAT `RST(value, metadata.reason)`，但 `value` 各不相同，`reason` 是自由文本：

| 客户端 | 设备上没有该 route | 连接被拒、连接超时、DNS、TLS 等上游失败 | 连接超时 | 等待响应头超时 |
| --- | --- | --- | --- | --- |
| Go | `24`「未配置 HTTP route」（目标地址无效也用 `24`） | `26`，reason 为 `*url.Error` 文本，含完整目标 URL 和原始 query | 5 s | 20 s |
| Java | `8`「未配置 HTTP route」 | `8`，reason 为 Netty 或 JDK 的异常文本（如 `Connection refused: /127.0.0.1:8080`） | 5 s | 无 |
| .NET | `22`「unknown HTTP route」 | `26`，reason 为 `HttpRequestException` 文本 | 5 s | 无 |
| Android | `22`「HTTP route is not configured」 | `22`，reason 为异常文本 | 5 s | 无 |

同一个数字在不同客户端里含义不同：`22` 在 Go 里表示请求队列超限，在 .NET 里表示未知 route，在 Android 里表示所有失败。规范和向量都没有定义码表，唯一的 RST fixture（`control-v2/frames/nat_rst.bin`，`value=7`）只用来固定线格式。

服务端那一侧，四端**都不读 `value`**，对响应头之前的 RST 也各自处理：

| 服务端 | 响应头之前收到 RST | 设备不在线或没有 `data` 连接 | 等待响应头超时 |
| --- | --- | --- | --- |
| Java | `502`，响应体为 reason | `502`「客户端不在线」 | `504`，`SPECUS_HTTP_TIMEOUT_MS`，默认 30 s，请求体上传完才开始计时 |
| Go | `502`，响应体为 reason | `502`，最多等 3 s 的重连宽限 | `504`，同一配置，从开流时开始计时 |
| .NET | `IOException` 逃出转发路径，变成没有响应体、也不记录的 `500` | `503` | `504`，`Specus:Http:TimeoutMs`，默认 30 s |
| C | reason 被丢弃，返回 `502`「direct http target client is offline」，与离线无法区分 | `502` | `504`，固定 30 s |

管理页的「在线」看的是 `control` 连接，HTTP 数据面看的是 `data` 连接，两者可能不一致：页面显示在线，公网请求却得到 `502`/`503`。流量明细 `specus_http_traffic_exchange` 的 `error` 列在 Java 和 Go 中会存 reason；但只有打开全局明细采集（默认关闭）并且 route 也开启了明细采集时才会写入，.NET 和 C 根本不记录 RST 导致的失败。四个服务端都没有从服务端内部经 route 发起请求的接口；http-route.md 里提到的「管理预览」，指的是流量明细里的正文解压预览。

由此得到两条结论，契约的形状由它们决定：

1. **设备转回来的响应头，可以证明目标确实答复了。** 任何版本的客户端都只转发上游真实给出的状态码，从不编造响应头。因此旧客户端转回的任何状态码都可以采信。
2. **响应头之前的 RST，今天无法可靠分类。** 数字码在不同语言之间相互冲突。Java 和 Android 对所有失败只用一个码；reason 文本混着中文、英文和运行时或操作系统给出的消息。按文本做模式匹配，会把四种运行时、多个操作系统语言环境和未来的文案改动一起绑进协议，因此不采用。区分「目标拒绝连接」和「设备没有该 route」需要客户端做一处最小改动（第 6 节）；旧客户端的这一阶段只能报 `unverified`，绝不报通过。

### 1.3 鉴权、限流与存储

- **route 的读写权限**在四个服务端一致：同一租户，并且调用者是管理员，或者其用户名等于该客户端的 `owner_username`。没有按 route 单独设的 ACL。对不存在的 route 和别人的 route，四端的响应并不一致：Java 和 .NET 多为 `400`，Go 和 .NET 的越权分支返回 `403`，C 返回 `404`。本接口统一返回 `404`。
- **已有的限流器**都是进程内的固定窗口计数，按 IP、登录账号、控制会话或客户端设键，键数有硬上限。没有一个按管理用户设键，也没有一个以 route 为键。本接口另立两个键（第 7 节）。
- **已有的存储里没有合适的地方记录检查结果**。没有通用审计或操作日志表；route 表 `http_route_mapping` 只有 `created_at` 和 `updated_at`。`specus_http_traffic_exchange` 是公网请求的流量明细，带来源地址和错误文本，默认不写入。Peer 服务审计在 Java、Go、.NET 中只是内存里最近 80 条，只有 C 把它落了库。见第 8 节。

## 2. 范围

v1 只覆盖 **HTTP route**。以下内容不在 v1 中，实现必须拒绝，不得用别的检查冒充：

| 不覆盖 | 原因 |
| --- | --- |
| Peer 服务 | 服务端不在 Peer 数据面上，数据面在两台客户端之间端到端加密，服务端没有任何办法自己访问 `publishedPort`。真实检查要么让发布端立刻重做一次本地探测（这需要新的 `PEER_CONTROL` 消息，而且只能证明到「目标可达」），要么让用户选定的一台消费端设备经 Mesh 去访问（这还需要第二台设备在线）。两条路都需要新的信令，见第 13 节 |
| TCP 端口映射 | TCP 没有应用层答复，「访问成功」没有定义；只能证明 connect 成功。另外，Java 客户端在本地 TCP 连接失败时会关闭整条 `data` 连接（`NatClientHandler` 在 catch 里重新抛出异常，`NatCommonHandler.exceptionCaught` 随后关闭 ctx），对它做探测会断掉这台设备上所有正在进行的流。这个缺陷修复之前不提供 |
| WebSocket Upgrade | 检查只发普通 HTTP 请求 |
| 公网入口的 Basic 认证 | 检查从服务端内部发起，不经过公网入口，也不知道访问密码（服务端只存哈希）。入口认证属于服务端本地配置，不是连通性问题 |
| 批量与目录级检查 | 一次请求只检查一条 route。不提供「全部检查」，服务端不做后台或周期探测 |

## 3. 接口

### 3.1 请求

```http
POST /api/admin/http-routes/{routeId}/connectivity-check
Authorization: Bearer <管理 token>
Content-Type: application/json

{"path": "/healthz"}
```

- 鉴权方式与 route 管理接口相同。身份和租户只从已认证的会话中取得，请求体里没有任何账号或租户选择字段。
- 授权与 `PUT /api/admin/http-routes/{id}` 相同：同一租户，并且是管理员或该客户端的所有者。route 不存在、属于其他租户、或者不属于调用者，**一律返回 `404`**，防止跨租户枚举 route id。
- 请求体可以为空，也可以是 `{}`。唯一可选的字段是 `path`，缺省为 `/`。`path` 的规则如下：
  - 长度 1..256 字节，以 `/` 开头，不能以 `//` 开头；
  - 只允许 RFC 3986 `pchar` 和 `/`，其中包括合法的 `%XX`；
  - 不允许 `?`、`#`、反斜杠、空白、控制字符，也不允许任何 `.` 或 `..` 路径段；
  - 其他未知字段、非 JSON object 的请求体、非法 `path` 都返回 `400`。

  `path` 只能落在该 route 自己的 `targetBaseUrl` 之下，因为客户端按 [http-route.md](http-route.md) 的 `targetBaseUrl + relativePath` 规则拼出目标。调用者无法借此指定别的主机或端口。
- 用 `POST` 而不用 `GET`，是因为检查有副作用：它会向用户的服务发请求，还会消耗限流额度。浏览器刷新、预取、链接预览和目录轮询都不会发出带 JSON 体的 `POST`，所以刷新页面不会触发检查，也不能冒充检查。

### 3.2 处理顺序与接口状态码

服务端按以下顺序处理。前面任何一步拒绝时，后面的步骤都不执行，也不消耗限流额度：

| 顺序 | 情形 | HTTP | `code` |
| ---: | --- | ---: | --- |
| 1 | 没有有效的管理会话 | `401` | — |
| 2 | 请求体或 `path` 非法 | `400` | `CHECK_REQUEST_INVALID` |
| 3 | 读取 route、客户端或在线状态失败 | `503` | `CHECK_UNAVAILABLE` |
| 4 | route 不存在或调用者不可见 | `404` | `CHECK_TARGET_NOT_FOUND` |
| 5 | 同一 route 已有一次检查在进行 | `429` | `CHECK_IN_PROGRESS` |
| 6 | 本进程同时进行的检查已达上限 | `503` | `CHECK_BUSY` |
| 7 | 限流（第 7 节） | `429` | `CHECK_RATE_LIMITED` |
| 8 | 检查已执行，不论停在哪一阶段 | `200` | 见响应体 |

- 非 `200` 的响应体为 `{"code": "<上表的 code>"}`，可以附带 `message`。`429` 和 `503` 都带 `Retry-After`（整秒，向上取整，至少 1）。
- **第 3 步读取失败不能报成「未配置」**，否则后端故障会被显示成用户配置错误。
- 检查执行了，接口就返回 `200`，即使某个阶段失败。阶段失败是检查的结果，不是接口的错误。
- 所有响应都带 `Cache-Control: private, no-store`。
- 旧服务端会返回 `404` 或 `405`。前端应显示「服务端不支持连接检查」，不能把它说成 route 有问题，更不能显示为通过。

### 3.3 响应

```json
{
  "schemaVersion": 1,
  "kind": "http-route",
  "routeId": 42,
  "checkedAt": "2026-10-06T08:00:00Z",
  "outcome": "failed",
  "stoppedAt": "target-reachable",
  "code": "TARGET_CONNECT_REFUSED",
  "totalMs": 4,
  "requests": ["HEAD"],
  "stages": [
    {"stage": "configured", "result": "passed", "code": "CONFIGURED", "atMs": 0},
    {"stage": "device-online", "result": "passed", "code": "DEVICE_ONLINE", "atMs": 4},
    {"stage": "target-reachable", "result": "failed", "code": "TARGET_CONNECT_REFUSED", "atMs": 4},
    {"stage": "access-succeeded", "result": "skipped"}
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `checkedAt` | 检查开始时刻，取服务端时钟，UTC RFC 3339，精确到秒 |
| `outcome` | `succeeded`：四个阶段全部通过。`failed`：某个阶段失败。`unverified`：某个阶段无法判定 |
| `stoppedAt` | 第一个没有通过的阶段；`succeeded` 时为 `null` |
| `code` | 决定 `outcome` 的阶段码。成功时为 `ACCESS_OK` |
| `totalMs` | 检查开始到最后一个已判定阶段的毫秒数，用单调时钟计，不超过预算 |
| `requests` | 实际发往设备的探测方法，依次为 `[]`、`["HEAD"]` 或 `["HEAD", "GET"]` |
| `stages` | 永远是四项，顺序固定。`result` 取 `passed`、`failed`、`unverified` 或 `skipped`。`skipped` 项没有 `code` 和 `atMs` |
| `statusClass` | 决定 `access-succeeded` 的那次请求的状态码类别，取值如 `2xx`、`4xx`。只在那次请求拿到了响应头时出现：HEAD 回了 `405`、随后的 GET 没有回应时，这个字段不出现 |

响应中**不含**以下内容：`targetBaseUrl`、目标主机或端口、`path` 回显、响应头（包括 `Location`、`Server`）、响应体，以及 RST 的 `reason` 文本。精确状态码也不返回，只返回状态类别和第 4 节的分桶码。

`checkedAt` 和 `routeId` 是运行时的值，不在向量里；向量的 `expect.body` 是其余部分，与实现的输出逐字段一致。

## 4. 阶段

四个阶段的顺序固定。每个阶段在可以下结论时被判定：`atMs` 就是判定那一刻距检查开始的毫秒数。阶段只能按顺序判定，后面的阶段不能改写前面阶段的结论。第一个不是 `passed` 的阶段之后，其余阶段一律为 `skipped`。

### 4.1 `configured`：已配置

只读服务端记录，判定于 `atMs = 0`。

| code | result | 条件 |
| --- | --- | --- |
| `CONFIGURED` | passed | route 已启用，所属客户端已启用，`targetBaseUrl` 是合法的绝对 `http`/`https` 地址 |
| `ROUTE_DISABLED` | failed | route 的 `enabled` 为 `false` |
| `CLIENT_DISABLED` | failed | 所属客户端（账号）已停用 |
| `ROUTE_TARGET_INVALID` | failed | 存量记录中的 `targetBaseUrl` 不合法。管理接口保存时已经校验，这一项是防御性检查 |

### 4.2 `device-online`：设备在线

服务端先检查前提：要有一个已认证的 `control` 会话，以及与它绑定的 `data` 连接。前提不满足时判定于 `atMs = 0`，并且不发送任何探测。前提满足后，服务端把探测流写到 `data` 连接上。之后，这一阶段在**设备第一次回应时**判定，或者在预算耗尽时判定。

| code | result | 条件 |
| --- | --- | --- |
| `DEVICE_ONLINE` | passed | 设备回应了：转回响应头，或者发出 RST。预算耗尽时也判为通过（见 4.3 的 `TARGET_TIMEOUT`） |
| `DEVICE_OFFLINE` | failed | 没有已认证的 `control` 会话 |
| `DEVICE_DATA_CHANNEL_DOWN` | failed | 有 `control` 会话，但没有 `data` 连接。这正是管理页显示「在线」、公网请求却失败的那种情况。检查反映的是当下的状态，不等待重连宽限（Go 公网路径有 3 s 的宽限） |
| `DEVICE_BUSY` | failed | 该 `data` 连接上的流数已经达到服务端上限，探测流开不出来。探测与公网请求共用这个上限，没有预留名额 |
| `DEVICE_ROUTE_NOT_LOADED` | failed | 已声明能力的客户端在 RST 中报告 `failure=route-not-loaded`：设备还没有加载这条 route，例如配置推送滞后或推送失败 |
| `DEVICE_LINK_LOST` | failed | 写入 `OPEN` 失败，或者在设备回应之前 `data` 连接断开、会话被替换 |

预算耗尽时把这一阶段判为通过，理由是：服务端持有该设备在线的 `data` 连接，心跳正常，写入也成功了。设备卡死而 TCP 连接仍然存活的情况很少见；在一次只有 10 秒的检查里，它和「目标迟迟不给响应头」无法区分，所以统一报到下一阶段的 `TARGET_TIMEOUT`，并在说明里如实写明这一点。

### 4.3 `target-reachable`：目标可达

| code | result | 条件 |
| --- | --- | --- |
| `TARGET_ANSWERED` | passed | 设备转回了响应头，状态码不限 |
| `TARGET_CONNECT_REFUSED` | failed | `failure=connect-refused`：目标端口没有监听 |
| `TARGET_CONNECT_TIMEOUT` | failed | `failure=connect-timeout`：客户端自己的 5 s 连接超时到期 |
| `TARGET_DNS_FAILED` | failed | `failure=dns-failed`：目标主机名无法解析 |
| `TARGET_TLS_FAILED` | failed | `failure=tls-failed`：TLS 握手或证书校验失败 |
| `TARGET_UNREACHABLE` | failed | `failure=unreachable`：没有到主机或网络的路由，或者在连接阶段被重置 |
| `TARGET_ADDRESS_INVALID` | failed | `failure=target-invalid`：设备认为这个目标地址无法使用（例如设备侧的解析规则比服务端更严） |
| `TARGET_PROTOCOL_ERROR` | failed | `failure=protocol-error`：已经连上，但在响应头之前连接被关闭，或者返回的不是合法的 HTTP。典型原因是用 `http://` 指向了 TLS 端口，或者指向了根本不是 HTTP 的端口 |
| `TARGET_TIMEOUT` | failed | 预算内没有任何回应，服务端已经取消该流 |
| `TARGET_UNVERIFIED` | unverified | 设备回了 RST，但没有可信的分类。可能是旧客户端（会话没有声明能力），可能是没有 `failure` 字段，也可能是本服务端不认识的 `failure` 值 |

`TARGET_UNVERIFIED` 是本契约里**最重要的一条约束**：说不清的时候报「无法判定」，不报通过，也不按 reason 文本去猜。

### 4.4 `access-succeeded`：访问成功

由决定性那次请求的状态码判定。通常是 HEAD；HEAD 收到 `405` 或 `501` 时，改由随后那次 GET 决定。

| code | result | 条件 |
| --- | --- | --- |
| `ACCESS_OK` | passed | `200..399`。重定向算作答复，但不跟随 |
| `ACCESS_AUTH_REQUIRED` | failed | `401`、`403`、`407`：目标要求它自己的凭据。检查从不携带凭据 |
| `ACCESS_NOT_FOUND` | failed | `404`、`410`：可以换一个 `path` 再试 |
| `ACCESS_CLIENT_ERROR` | failed | 其他 `4xx` |
| `ACCESS_SERVER_ERROR` | failed | `5xx`。这个状态码来自目标本身，例如它前面的反向代理找不到后端；客户端从不编造响应头 |
| `ACCESS_NO_ANSWER` | failed | HEAD 已经答复 `405`/`501`，但随后的 GET 在预算内没有给出响应头：收到 RST、连接断开，或者超时 |

把 `401`/`403` 判为失败、而不是「通过但需登录」，这一点列为待定问题（第 13 节）。

## 5. 探测

### 5.1 发起方式

检查复用现有的 HTTP stream 路径：服务端在设备的 `data` 连接上分配 `streamId`，发送 `OPEN(source=http, phase=request)`，然后立即发送请求 `FIN`。探测请求不经过公网入口，因此：

- 不经过 route 的 Basic 认证；
- 不做路径改写；
- 不写入 `specus_http_traffic_exchange`，也不计入 route 的流量统计；
- 与公网请求共用该 `data` 连接的流数上限和流控窗口，不预留名额。流数已满时判为 `DEVICE_BUSY`。

OPEN 的 metadata 固定如下：

```json
{
  "source": "http",
  "phase": "request",
  "requestId": "<服务端生成>",
  "method": "HEAD",
  "route": "<route 名>",
  "relativePath": "/",
  "rawQuery": "",
  "headers": ["Accept:*/*", "User-Agent:specus-connectivity-check/1"]
}
```

不带 `contentLength` 和 `trailerNames`，也不带任何 `Authorization`、`Cookie`，以及来自管理请求的任何 header。`relativePath` 取请求体的 `path`，缺省为 `/`。`User-Agent` 让目标的访问日志能认出这次探测。

### 5.2 方法与次数

- 先发 `HEAD`。
- 只有当 HEAD 的响应状态是 `405` 或 `501` 时，才在同一预算内再发**一次** `GET`，`path` 相同。其他任何状态码都不追加请求，包括 `404`：`404` 说明问题在路径，换方法没有意义。
- GET 不携带 `Range`。带 `Range: bytes=0-0` 虽然能省流量，但空资源会因此返回 `416`，被误判成访问失败。
- 不重试，不跟随重定向。

所以一次检查最多向目标发两个请求，而且第二个请求只在目标明确表示不支持 HEAD 时才发。

### 5.3 预算与收尾

- 整次检查的预算为 **10 000 ms**，从开始处理第 1 步计起，用单调时钟。HEAD 和 GET 共用这一个预算，GET 只能用剩下的时间。
- 客户端连接超时都是 5 s，所以 `connect-timeout` 能在预算内传回。等待响应头的时间，客户端目前要么没有上限，要么是 20 s，因此大于预算；预算到期时由服务端判定 `TARGET_TIMEOUT`。
- **一收到响应头，那次请求就结束了。** 如果该流还没有双向结束，服务端立即发送 `RST`，客户端随之取消上游请求并关闭响应体（[http-route.md](http-route.md) 第 5 节已有此要求）。响应体不读取、不缓冲、不保存。RST 到达之前已经在途的响应 `DATA` 最多一个初始窗口（1 MiB），服务端直接丢弃，不回送 `WINDOW_UPDATE`。
- 预算到期、调用方断开管理请求，或者服务端停机时，都对在途的探测流发送 `RST`。调用方中途断开不退还限流额度。

## 6. 客户端改动（最小）

不新增 NAT 消息类型、command 或帧字段。只做两件事：在登录 `environment` 里声明能力，在已有的 RST metadata JSON 里加一个键。

### 6.1 能力声明

```json
"clientHttpRouteCapabilities": {"version": 1}
```

- `version` 为 `0` 或缺省：旧客户端。
- `version >= 1`：该客户端对 `source=http` 的流，在响应 `OPEN` 之前失败时，按 6.2 的规则给 RST 加上分类（能分类的才加）；并且客户端永远不编造响应头。

服务端把这个值存入 `ClientSession`，与 `clientEgressCapabilities` 的处理方式相同。旧服务端会忽略 `environment` 里的未知对象：`clientEgressCapabilities` 和 `clientPeerServiceCapabilities` 就是这样加进来的。

### 6.2 RST 分类

声明了能力的客户端，在 HTTP 流发送响应 `OPEN` **之前**失败时，在 RST 的 metadata 中加入 `failure`：

```json
{"reason": "<原有文本>", "failure": "connect-refused"}
```

| `failure` | 何时 | 服务端报告 |
| --- | --- | --- |
| `route-not-loaded` | 当前配置快照里没有这条 route，或者它的 `targetBaseUrl` 为空 | `device-online` / `DEVICE_ROUTE_NOT_LOADED` |
| `target-invalid` | 有这条 route，但拼出的目标地址不能用（scheme 非法、地址非法、路径非法） | `target-reachable` / `TARGET_ADDRESS_INVALID` |
| `connect-refused` | TCP 连接被拒绝（`ECONNREFUSED` 等价物） | `TARGET_CONNECT_REFUSED` |
| `connect-timeout` | 客户端自己的连接超时到期 | `TARGET_CONNECT_TIMEOUT` |
| `dns-failed` | 目标主机名解析失败或没有可用地址 | `TARGET_DNS_FAILED` |
| `tls-failed` | TLS 握手失败，或证书或主机名校验失败 | `TARGET_TLS_FAILED` |
| `unreachable` | 主机或网络不可达，没有路由，连接阶段被重置 | `TARGET_UNREACHABLE` |
| `protocol-error` | 已连上，但在响应头之前上游关闭，或者响应头不合法 | `TARGET_PROTOCOL_ERROR` |

- 集合是封闭的。不属于上表的失败**不带 `failure`**，包括请求格式非法、本地队列或大小超限、内部错误，以及被服务端 RST 取消。不确定时宁可省略，省略的结果是 `TARGET_UNVERIFIED`。
- 分类必须基于运行时给出的错误类型或错误码，例如 Go 的 `*net.OpError`/`*net.DNSError`/`x509` 错误、Java 的 `ConnectException`/`ConnectTimeoutException`/`UnknownHostException`/`SSLException`、.NET 的 `SocketError` 与 `AuthenticationException`、Android 上 Netty 的对应类型。不能基于消息文本。
- `value` 维持各语言现有的数字不变（服务端不读它），`reason` 也照旧。响应 `OPEN` 之后的失败（响应体超限、读取失败）与本检查无关，不加 `failure`。
- 服务端**只采信声明了 `version >= 1` 的会话发来的 `failure`**。旧会话的 RST 即使碰巧带了同名键，也按 `TARGET_UNVERIFIED` 处理，见向量 `legacy-client-reset-ignores-failure`。

### 6.3 兼容矩阵

| 服务端 | 客户端 | 结果 |
| --- | --- | --- |
| 新 | 新 | 四个阶段全部可以判定 |
| 新 | 旧 | 转回响应头时，四个阶段照常判定。响应头之前的 RST 判为 `TARGET_UNVERIFIED`，设备没有该 route 的情况也会落在这里。不会出现虚假的通过 |
| 旧 | 新 | 接口不存在（`404`/`405`）。公网路径照旧：服务端只读 `reason`，忽略多出来的 `failure` 键和能力对象 |
| 旧 | 旧 | 不变 |

## 7. 限流与并发

**并发上限**

- 每条 route 同时最多 1 次检查，超出时返回 `429 CHECK_IN_PROGRESS`。
- 每个服务端进程同时最多 32 次检查，超出时返回 `503 CHECK_BUSY`。
- 这两个上限都在执行之前判断，被拒的请求不消耗速率额度。

**速率**

用 GCRA（generic cell rate algorithm）：每个键只存一个整数「理论到达时刻」TAT，单位为毫秒。允许 `burst` 次突发，容差 `tolerance = (burst - 1) × interval`。

- 请求在 `now` 时刻放行的条件是 `now >= TAT - tolerance`。
- 放行后 `TAT = max(TAT, now) + interval`。
- 被拒时，需要等待的时间为 `TAT - tolerance - now`。

两个键都放行，请求才放行。被拒的请求两个键都不消耗。`Retry-After` 取两个键中较长的等待时间，单位为秒，向上取整。

| 键 | interval | burst | 作用 |
| --- | ---: | ---: | --- |
| `tenantId + routeId` | 10 000 ms | 1 | 保护目标设备和目标服务。这个键不含调用者：所有者和管理员共用，两个人不能把一条 route 的探测频率翻倍 |
| `tenantId + username` | 30 000 ms | 10 | 限制一个人轮流检查很多 route。突发 10 次之后，持续速率不超过每分钟 2 次 |

已执行的检查一律消耗额度，不论停在哪一阶段。不选择「只有真正发出探测才扣额度」，因为那样规则会依赖检查过程中的状态，各端实现时容易对不齐；而停在第一、第二阶段的检查成本只是几次读库。

所有状态都在进程内存里，与现有限流器一致。键数设硬上限（建议 10 000）：TAT 不晚于 `now` 的条目等同于不存在，可以随时淘汰；全部条目都仍然有效而又需要新增时，在第 7 步按 `503 CHECK_BUSY` 拒绝，不淘汰仍然有效的条目，因为淘汰一个有效条目就等于给它清零了额度。多实例部署下，限额按实例计算；这与现有限流器的口径相同。检查只能在持有该设备 `data` 连接的那个实例上执行，与公网请求相同。

为什么要限流：route 的所有者本来就可以通过公网链接访问自己的服务，检查并没有扩大可达范围。但检查会把「连接被拒绝」「超时」「DNS 失败」这些区别交给调用者，而公网入口只会给一个 `502`。所有者如果反复修改 `targetBaseUrl` 再检查，就能借助自己的设备扫描设备所在网络。限流把这种用法压到「每条 route 每 10 秒一次、每人每分钟两次」的量级，与手动排障的节奏相当。共享向量的 `rate.events` 固定了边界行为。

## 8. 记录

**v1 只返回结果，不在服务端持久化。** 理由如下：

1. 现有存储里没有合适的位置（见 1.3）。新增一张表或几列，要改 Go 的 SQLite/MySQL/PostgreSQL 三份 schema、Java 实体、.NET 的 DbContext 和 C 的 SQLite，而 Java 的流量明细还可能落在 Elasticsearch。这超出了「一个检查接口」的范围，应该单独决定。
2. 持久化的「上次检查通过」放在 route 列表旁边，会被当成当前状态来读。这正是 issue #37 要去掉的那种误导：页面刷新时显示一个昨天的绿色对勾。
3. 不能借用 `specus_http_traffic_exchange`。它记录的是公网请求，带来源地址和错误文本，混入检查会污染流量统计，也会把 RST 的 reason 写进库里。

v1 保留以下几样东西：

- **接口响应本身**：带 `checkedAt`、停止阶段、`code` 和各阶段的 `atMs`，满足「记录时间与失败阶段」的展示要求。
- **服务端日志**：每次已执行的检查写一行，格式固定为
  `[connectivity-check] tenant=<tenantId> user=<username> route=<routeId> outcome=<outcome> stage=<stoppedAt|-> code=<code> totalMs=<n>`。
  被限流的请求按相同主体每分钟最多记录一行。日志里不写目标地址、`path`、状态码或 reason。
- **管理前端**：每条 route 在当前页面状态里保留最近一次结果，并注明「检查于 hh:mm:ss」。不写入 `localStorage`。切换登录会话时清空。

是否持久化最近一次结果（每条 route 一行，随 route 删除而删除）列为待定问题。如果决定要做，应当另起一个版本：由服务端写入，在 route 列表里作为独立的 `lastCheck` 字段返回，并要求前端标明时间，不能把它当作当前状态显示。

## 9. 隐私与日志

- 检查结果只包含阶段、结果码、毫秒数和状态类别。目标地址、`path` 回显、响应头、响应体和 RST 的 `reason` 都不进入响应、日志或任何存储。客户端的 reason 文本可能含完整的目标 URL 和原始 query（Go 就是这样），也可能含本地地址。
- 精确状态码不返回。第 4.4 节的分桶码只比状态类别细了一层，而所有者本来就能在 route 流量明细里看到每个请求的状态码，所以这不算额外泄露。
- 检查不携带任何凭据或 Cookie，也不转发管理请求的任何 header。
- 授权失败、route 不存在和跨租户访问的响应完全相同，都是 `404`。
- 附带发现（不属于本契约，需要另行处理）：今天 Java 和 Go 的公网入口把客户端的 RST reason 原样作为 `502` 响应体返回给**任何公网访问者**，其中可能包括目标 URL、内网地址和 query。本接口不重复这个做法。

## 10. 管理前端约束

- 检查只能由用户在某一条 route 上**点击按钮**触发。页面加载、刷新、轮询、列表渲染、切换标签页、新建或编辑 route 之后，都不得自动触发。不提供「全部检查」。
- 检查进行中时，按钮处于禁用状态，并显示「正在检查」；同一 route 不得并发发起。
- 结果按四个阶段逐项显示，第一个未通过的阶段要突出显示，并给出对应的下一步。`unverified` 要显示为「无法判定」，并提示「升级该设备的客户端可以得到确切原因」。它不能显示成失败，更不能显示成通过。
- 结果要标明检查时间，取响应里的 `checkedAt`。页面里只要还提到 route，就要说清楚：在线状态、目录状态和打开访问链接，都不等于检查通过。
- 收到 `429` 时按 `Retry-After` 显示倒计时。收到旧服务端的 `404`/`405` 时，显示「服务端不支持连接检查」。
- Peer 服务页的「检查目录状态」维持原样，与本检查无关，并且不得改名为连接检查。

## 11. 共享向量

`protocol/test-vectors/service-connectivity-check-v1.json` 由 `python tools/protocol/generate_service_connectivity_vectors.py` 生成。生成器内置参考状态机，写文件之前会用手写的期望表对每条用例逐一断言，因此不会发布自相矛盾的向量。它还断言：

- 阶段顺序固定，失败或无法判定的阶段之后全部为 `skipped`，之前全部为 `passed`；
- 各阶段的 `atMs` 单调不减，最后一个已判定阶段的 `atMs` 等于 `totalMs`，并且不超过预算；
- 结果为 `succeeded` 时，一定有设备转回的响应头；
- 码表中每一个失败码或无法判定码，至少有一条用例覆盖；用例不使用码表以外的码；
- `rate.events` 的放行和拒绝、限流键和 `Retry-After` 与手写期望一致。

输入的含义：

- `input.answers` 是设备对每个探测请求的回应，按发送顺序列出：
  - `response`：带 `status`；
  - `rst`：带可选的 `failure`；
  - `link-lost`：回应之前连接断开；
  - `open-failed`：探测流没能交给设备，`cause` 为 `write-failed` 或 `stream-limit`；
  - `none`：预算内没有回应。
- `atMs` 由测试注入的单调时钟给出。
- `device.httpRouteCapability` 为该会话声明的 `clientHttpRouteCapabilities.version`。

服务端实现读取这份向量时，应该用假的设备回应和假时钟驱动真实的处理代码，断言 `httpStatus` 和 `expect.body` 逐字段相等。只断言「语义相近」不算通过。客户端实现读取 `rstFailures`，用真实的失败（本地未监听的端口、无法解析的名字、自签证书等）断言 RST 带对应的 `failure`。

## 12. 放弃的方案

| 方案 | 不采用的原因 |
| --- | --- |
| 解析 RST 的 `reason` 文本来分类 | 文本来自四种运行时和操作系统语言环境，中英文混杂，随依赖库升级而变；一旦匹配错误，就是虚假的诊断 |
| 复用 RST 的数字 `value` 并定一张码表 | 现有数字在各语言之间冲突（`22`、`8`、`26` 含义各不相同），而且服务端从不读取。重新编号要四个客户端同时改，期间新旧数字无法区分；而带名字的 `failure` 键和能力声明可以逐个客户端上线 |
| 新增一种 NAT 消息或「探测」command | 现有 HTTP stream 已经能表达「发一个请求、拿回响应头或失败」。新增帧类型要改四端的编解码和中央 fixture，而且旧客户端会把它当作协议违规关闭连接 |
| 经公网入口自己请求 `/http/{clientName}/{route}/` | 会经过 Basic 认证（服务端没有明文密码），会写入流量明细，还拿不到失败分类，只能看到同一个 `502` |
| 只用 GET，或者带 `Range: bytes=0-0` 的 GET | HEAD 对目标的副作用最小；`Range` 会让空资源返回 `416`，造成误判 |
| 跟随重定向 | `Location` 可能指向任意主机，跟随就超出了 route 配置的目标 |
| 把客户端连接超时内的 TCP connect 当作「目标可达」 | 只能证明端口开着，HTTP 层可能根本不通（例如用 http 访问 TLS 端口）。v1 的「目标可达」要求真的拿到响应头 |
| 后台定期探测，或者在 route 列表里显示「健康」 | issue 要求只对用户显式选中的服务做探测。定期探测相当于持续扫描用户内网，而且会把过去的结果当成现在的状态显示 |
| 固定窗口限流（复用现有限流器） | 窗口边界处会允许连续两次探测；GCRA 每个键只存一个整数，没有边界效应，并且容易写成跨语言一致的向量 |
| 把检查结果写入 `specus_http_traffic_exchange` | 见第 8 节 |

## 13. 待定问题（需要维护者决定）

1. **`401`/`403` 算不算访问成功？** 本草案判为 `failed / ACCESS_AUTH_REQUIRED`。理由是检查从不携带凭据，「访问成功」的含义是匿名请求拿到了非错误答复。另一种做法是判为通过并附加提示，这对自带登录的服务更友好，但会让「通过」的含义变宽。
2. **是否持久化每条 route 的最近一次结果？** 见第 8 节。如果要做，需要四端各做一次 schema 迁移，并决定保存期限，以及是否记录操作者。
3. **Peer 服务的检查走哪条路？** 一种是发布端立刻重新探测本地目标（新增 `PEER_CONTROL` 请求和应答），只能证明到「目标可达」。另一种是由用户选定的消费端设备经 Mesh 访问（需要消费端客户端的配合，并且该设备在线），可以证明「访问成功」。两者都需要新的信令和 Mesh 侧的授权规则。
4. **TCP 端口映射**要等 Java 客户端「本地连接失败就关闭整条 data 连接」的缺陷修复之后，再决定是否提供只到「目标可达」的检查。
5. **限流数值**（每条 route 每 10 秒一次，每人突发 10 次、之后每 30 秒一次）和**预算**（10 秒）是否合适。是否需要做成可配置项；如果做成可配置，向量只固定默认值。
6. **`path` 参数是否保留。** 它让 API 类服务可以检查健康端点，避免根路径的 `404` 被误读为不可用。代价是多一条输入校验规则。也可以改为在 route 上持久化一个「检查路径」。
7. **多实例部署**：检查必须落到持有设备 `data` 连接的实例上。如果部署在负载均衡后面，而管理请求落到了别的实例，就只能报 `DEVICE_OFFLINE`。这与公网请求今天的行为相同，但对检查来说会造成误导。是否需要转发，或者把这种情况报成单独的码。
8. **公网 `502` 响应体泄露客户端 reason 文本**（见第 9 节）是否另开 issue 处理。

## 14. 实现入口（待实现）

| 实现 | 服务端 | 客户端 |
| --- | --- | --- |
| Java | `HttpRouteResource` 新增端点，沿用 `HttpRouteService` 的可见性判断；用 `NatServerHandler.openHttpStream` 和 `HttpStreamExchange.awaitResponseHead` 发起内部流。`onReset` 需要把 RST metadata 交给检查，不能只保留 reason | `HttpStreamForwarder` 失败分类；`NatClientHandler.failHttpStream` 携带 `failure` |
| Go | `internal/management` 新增端点（`requireClientAccess`）；`nat.Coordinator.OpenHTTPStream`。`session.go` 现在只把 reason 交给 `onReset`，需要把 `failure` 一并传下去；检查不使用 3 s 重连宽限 | `internal/client/http_stream.go` 失败分类；`sendNatReset` 携带 `failure` |
| .NET | `AdminApiEndpoints` 新增端点（`ManagementContext.CanAccess`）；`DirectHttpDispatcher.OpenAsync`。`HttpSpecusStream.OnReset` 的 `IOException` 必须在检查路径里接住，现状会逃逸成 `500` | `HttpStreamChannel`、`NatClientHandler` 失败分类 |
| C | `admin_http.c` 新增端点（`admin_load_accessible_client`）；`main.c` 的 `direct_http_forward` 与 `st_admin_direct_http_sink`。现状把 RST reason 释放后返回 `-1`，与离线共用一个结果，需要单独的返回值和 `failure` | — |
| Android | — | `SpecusCore.HttpStreamForwarder` 失败分类 |
| 管理前端 | `HttpRoutesPanel` 的检查按钮与结果展示 | — |
