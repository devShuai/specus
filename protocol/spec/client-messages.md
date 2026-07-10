# 管理端与客户端消息协议

本文定义管理端 `/ws/client-messages` WebSocket，以及该 WebSocket 与控制连接
`MessageType.CLIENT_TO_CLIENT` 之间的双向 fallback。Java server 是语义基准；Go、.NET server 的完整实现必须保持一致。

该 WebSocket 是管理端通道，不是客户端控制连接的替代品：管理端通过 WebSocket 发消息，服务端通过已认证控制连接投递给客户端；
客户端通过控制连接回复 `admin:<username>`，服务端再投递到对应管理 WebSocket。

## 1. WebSocket 握手鉴权

端点：

```text
/ws/client-messages
```

鉴权 token 按以下优先级提取：

1. 查询参数第一个非空 `token`：`/ws/client-messages?token=<jwt>`；
2. `Authorization: Bearer <jwt>`，供可以设置自定义 header 的非浏览器客户端使用。

查询参数优先：只要第一个 query token 非空，即使它无效也不得回退到 Bearer header。`Bearer ` 前缀区分大小写。
JWT 使用与管理 REST 相同的 HS256/OIDC RS256 解码和 tenant/role 解析。

缺 token 或 token 无效时必须拒绝 WebSocket Upgrade：

```http
HTTP/1.1 403 Forbidden
X-Auth-Reason: missing token
```

或：

```http
HTTP/1.1 403 Forbidden
X-Auth-Reason: invalid token
```

失败发生在升级前，不是 WebSocket close frame。浏览器通常只能观察到异常关闭，诊断工具可以读取 `X-Auth-Reason`。

## 2. 建连 hello

升级成功后，服务端登记 `(tenantId, username)` 订阅并首先发送：

```json
{
  "type": "hello",
  "channel": "client-messages",
  "username": "alice",
  "tenantId": "default"
}
```

同一用户可以同时建立多个连接；来自客户端的消息会 fan-out 到该用户当前所有打开的连接。

## 3. 管理端发送消息

### 3.1 命令

管理端发送 JSON 文本：

```json
{
  "type": "message",
  "messageId": "ui-generated-id",
  "toClientName": "client-a",
  "message": "hello"
}
```

字段规则：

| 字段 | 规则 |
| --- | --- |
| `type` | 必须精确等于 `message` |
| `messageId` | 可选；服务端仅原样关联 ack，不据此去重 |
| `toClientName` | 必需，去除首尾空白后查找目标 |
| `message` | 必需，去除首尾空白后投递 |

### 3.2 tenant、owner、能力与在线判断

服务端必须按以下顺序验证目标：

1. 目标账号存在且启用；
2. 目标 `tenantId` 与当前管理上下文完全相等；
3. 管理员可访问同 tenant 的目标；普通用户的 username 还必须与目标 `ownerUsername` 完全相等；
4. 目标至少有一个状态为 `NETTY_ONLINE` 的 session，其 `messageReceiveCapable=true`；
5. 目标当前存在已完成 LOGIN 的活动控制 channel。

tenant、username 和 owner 比较区分大小写。第 1 至 3 步失败统一返回 `target-not-found`，避免暴露其他 tenant/owner 的目标。
接收能力必须检查所有在线 session，不能只读取最新一条 session。能力来自启动登录
`environment.clientMessageCapabilities.receiveMessages`，见 [client-auth.md](client-auth.md)。

### 3.3 控制通道投递与 sent

验证通过后，服务端向目标控制连接发送 `MessageResponsePacket`：

| 字段 | 值 |
| --- | --- |
| `messageType` | `CLIENT_TO_CLIENT` |
| `clientName` | `admin:<current-username>` |
| `toClientName` | 目标账号的规范 client name |
| `message` | 去除首尾空白后的消息正文 |

随后向发起 WebSocket 返回：

```json
{
  "type": "sent",
  "messageId": "ui-generated-id",
  "toClientName": "client-a",
  "message": "hello"
}
```

缺失 `messageId` 时返回空字符串。`sent` 只表示请求通过校验并已交给异步控制 channel 写队列，不是目标客户端已收到、
已解析或已展示的确认；Java 在异步 write future 完成前就发送该 ack。本协议不提供送达回执、持久队列或自动重试。

## 4. WebSocket error payload

可恢复的输入/目标错误通过文本消息返回，连接保持打开：

```json
{"type":"error","error":"invalid-json"}
```

带可解析命令的错误还包含 `messageId`，缺失时为空字符串：

```json
{
  "type": "error",
  "error": "target-offline",
  "messageId": "ui-generated-id"
}
```

稳定 error 标识：

| `error` | 条件 |
| --- | --- |
| `invalid-json` | JSON 无法反序列化为命令；该响应不含 `messageId` |
| `unsupported-type` | `type` 不是精确的 `message` |
| `target-and-message-required` | 目标或去空白后的正文为空 |
| `target-not-found` | 账号不存在、停用或当前管理上下文无权访问 |
| `target-cannot-receive-message` | 没有任一 `NETTY_ONLINE` session 声明接收能力 |
| `target-offline` | 接收能力检查通过，但当前无已登录活动控制 channel |

客户端必须按 `error` 标识处理，不得解析自然语言日志。

## 5. 客户端到管理端 fallback

已认证客户端可在控制连接发送：

```text
MessageRequestPacket
  messageType = CLIENT_TO_CLIENT
  toClientName = admin:<username>
  message = <body>
```

`admin:` 前缀匹配不区分大小写；前缀后的 username 去除首尾空白后，必须与订阅 WebSocket 的 username 完全相等，
且 tenant 必须与来源客户端 tenant 完全相等。投递给所有匹配且打开的管理 WebSocket：

```json
{
  "type": "message",
  "direction": "in",
  "fromClientName": "client-a",
  "toClientName": "admin:alice",
  "message": "reply",
  "createdAt": "2026-07-10T00:00:00Z"
}
```

来源客户端必须已认证、来源账号必须存在且启用，目标和正文必须非空。控制帧中的正文按原值投递，不执行管理端发送路径的
trim。没有匹配管理连接或发送失败时，服务端静默丢弃并记录日志，不向来源控制客户端返回应用层 ack。

## 6. 客户端到客户端 fallback

`CLIENT_TO_CLIENT` 控制消息的目标不是 `admin:` 时，Java 执行客户端到客户端 fallback：

1. 来源 session 已认证，来源与目标账号都存在且启用；
2. 目标名去除首尾空白后查找；
3. `PeerMeshService.canPeer(source, target)` 允许该方向：tenant 和规范化 owner 均区分大小写，双方 Peer Mesh device
   已启用；同 owner 直接允许，否则必须存在正向 `source -> target` 的 `OUTBOUND/BOTH` ACL，或反向
   `target -> source` 的 `INBOUND/BOTH` ACL，且该 ACL 的 `allowed=true`；
4. 目标有已登录活动控制 channel。

满足条件时服务端发送 `MessageResponsePacket`，其中 `clientName` 是真实来源 client name、`toClientName` 是真实目标名、
`messageType=CLIENT_TO_CLIENT`、正文保持原值。该 fallback 不执行管理端路径的 `messageReceiveCapable` 检查；目标离线、
ACL 拒绝或写失败只记录日志，不提供排队、重试或来源 ack。

## 7. 消息大小与二进制帧

`/ws/client-messages` 是文本 JSON 协议。应用层单条文本上限为 `65,536` 个 Java UTF-16 code unit，计算对象是完整 JSON
文本而非仅 `message` 字段。Java `String.length()` 对补充平面字符计为两个 code unit。恰好 `65,536` 可进入解析，超过时
以 close code `1009` 关闭。

二进制 WebSocket frame 不属于本协议。完整实现必须像 Java `TextWebSocketHandler` 一样拒绝并关闭，close code 为
`1003`。不得把二进制内容隐式按 UTF-8 JSON 处理。

## 8. 附件消息

本 WebSocket 的 `message` 字段仍是字符串；附件字节不经过 WebSocket 或控制连接。管理端附件必须先使用
[public-transfer.md](public-transfer.md) 中 `ADMIN_CLIENT_MESSAGE` 的三个 REST 端点取得对象存储 URL，再把附件元数据编码进
客户端能够理解的消息正文。

客户端只能声明真实的 `clientMessageCapabilities`。未实现附件下载或媒体预览的客户端必须声明
`attachments=false`、`mediaPreview=false`、`maxAttachmentBytes=0`；路由存在不等于客户端具备数据面能力。

## 9. 轻量 C server 边界

C server 目前只持久化启动登录里的 wire-level `clientMessageCapabilities`，用于兼容数据库和管理视图。它不实现：

- `/ws/client-messages`；
- live 管理订阅与 fan-out；
- client-to-admin/client 消息数据面；
- 对象存储附件数据面。

C 的离线/轻量视图必须保守报告不可接收，不能因为数据库保存了能力字段就声称实时消息可用。管理附件路径的禁用响应见
[public-transfer.md](public-transfer.md)。

## 10. Java 参考入口

| 能力 | Java 源码 |
| --- | --- |
| WebSocket 路由 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/WebSocketConfig.java` |
| query-first/Bearer 握手鉴权 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/JwtHandshakeInterceptor.java` |
| hello、管理端发送、client-to-admin fan-out | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/websocket/ClientMessagesWebSocketHandler.java` |
| client-to-admin/client 控制通道 fallback | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/handler/MessageRequestHandler.java` |
| 在线 session 接收能力 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/model/ClientSession.java` |
| 目标账号和 owner 权限 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/ClientAccountService.java` |
| client-to-client ACL | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/management/service/PeerMeshService.java` |
