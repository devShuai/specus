# 管理端与客户端消息协议

本文定义管理端 `/ws/client-messages` 与已认证客户端控制连接之间的备用消息通道。Peer 直连可用时客户端优先发送
STMSG2；服务端通道用于直连不可用时的低频消息，不传输附件字节。

Java、Go 与 .NET server 必须保持相同语义。C server 不实现实时消息 WebSocket。

## 1. 一次性 WebSocket ticket

管理端先用管理 Bearer token 调用：

```http
POST /api/admin/ws-tickets
Content-Type: application/json

{"endpoint":"client-messages"}
```

响应包含 45 秒有效的随机 `ticket` 与 `expiresAt`，并设置 `Cache-Control: no-store`。ticket 绑定 endpoint、管理身份、
tenant 和来源地址，只能原子消费一次。

升级请求必须只有一个 query 参数：

```text
/ws/client-messages?ticket=<one-time-ticket>
```

原始管理 JWT、Bearer header 和 `token=` query 都不属于协议。缺失或无效 ticket 在 Upgrade 前返回 `403`，并分别设置
`X-Auth-Reason: missing ticket` 或 `invalid ticket`。ticket 重用、过期、scope 不符或来源地址不符都必须拒绝。

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

同一管理用户可以建立多个连接。客户端发给 `admin:<username>` 的消息会 fan-out 到该用户当前所有打开连接。

## 3. 管理端发送

```json
{
  "type": "message",
  "messageId": "ui-generated-id",
  "toClientName": "client-a",
  "message": "hello"
}
```

`type` 必须精确为 `message`。目标和正文去除首尾空白后必须非空；`messageId` 用于关联状态，不是持久 outbox ID。

服务端按顺序验证：

1. 目标账号存在且启用；
2. tenant 完全相同；
3. 管理员可访问同 tenant，普通用户还必须与 owner username 完全相同；
4. 至少一个 `NETTY_ONLINE` session 声明 `messageReceiveCapable=true`；
5. 目标有已登录的活动 `control` 连接。

tenant、username 和 owner 比较区分大小写。账号不存在、停用或无权访问统一返回 `target-not-found`，避免跨 tenant
枚举。能力判断必须检查全部在线 session，不能只看最新一条数据库记录。

验证通过后，服务端向目标控制连接写入：

```text
MessageResponsePacket
  messageType = CLIENT_TO_CLIENT
  clientName = admin:<username>
  toClientName = <canonical target>
  message = <trimmed body>
```

只有目标 channel write 成功后才返回：

```json
{
  "type": "written",
  "messageId": "ui-generated-id",
  "toClientName": "client-a",
  "message": "hello"
}
```

写入失败返回：

```json
{
  "type": "failed",
  "messageId": "ui-generated-id",
  "error": "target-write-failed"
}
```

目标写操作必须异步等待，不能阻塞该管理 WebSocket 继续处理其他命令。`written` 只表示服务端已把 frame 写入目标连接，
不表示目标应用已解析、展示或已读。只有收到 STMSG2 应用 ACK 时才能显示 `delivered`；当前协议不定义 `read`。

## 4. 可恢复错误

输入与目标错误使用文本响应，连接保持打开：

| error | 条件 |
| --- | --- |
| `invalid-json` | JSON 无法解析；不含 messageId |
| `unsupported-type` | type 不是 `message` |
| `target-and-message-required` | 目标或正文为空 |
| `target-not-found` | 账号不存在、停用或无权限 |
| `target-cannot-receive-message` | 没有在线 session 声明接收能力 |
| `target-offline` | 能力记录存在，但当前无活动 control 连接 |
| `target-write-failed` | 写入目标控制连接失败，外层 type 为 `failed` |

客户端必须按稳定 error 标识处理，不解析自然语言日志。

## 5. 客户端到管理端

客户端在 control 连接发送：

```text
MessageRequestPacket
  messageType = CLIENT_TO_CLIENT
  toClientName = admin:<username>
  message = <body>
```

`admin:` 前缀匹配不区分大小写；其后的 username 去空白后必须与管理订阅完全相等，tenant 必须与来源客户端相同。
服务端向全部匹配管理连接发送：

```json
{
  "type": "message",
  "direction": "in",
  "fromClientName": "client-a",
  "toClientName": "admin:alice",
  "message": "reply",
  "createdAt": "2026-07-21T00:00:00Z"
}
```

没有在线管理订阅时不持久化、不排队。产品若要提供离线聊天，必须另建持久 outbox、重试、TTL 与配额，不能把当前
控制 frame 描述成离线消息。

## 6. 客户端到客户端备用通道

目标不是 `admin:` 时，服务端只在以下条件满足时转发：来源已认证，双方账号启用，tenant/owner/ACL 允许 Peer，目标有
活动 control 连接。服务端转发真实来源 client name 与原正文。

该路径是 Peer direct/TURN 不可用时的备用通道，不绕过 Peer ACL。离线、ACL 拒绝或 write 失败不会自动转 OSS；附件
字节始终走 WebRTC/TURN 或对象存储直传。

## 7. STMSG2 与附件

消息正文只接受 STMSG2 envelope。附件 envelope 只包含 `objectId`、文件名、MIME、大小、hash 等元数据，不包含预签名
URL。接收方必须按权限向服务端换取短期单次下载跳转。

旧 STMSG1 必须拒绝。Java CLI 不声明消息能力，也不编码或解析 STMSG2。

管理附件必须先调用 `ADMIN_CLIENT_MESSAGE` 附件 REST 取得预签名 PUT，客户端直传对象存储并 complete；接收端再申请
下载授权。服务端不经由 WebSocket 或控制连接转发文件字节。

## 8. 大小与帧类型

管理 WebSocket 只接受 JSON 文本。完整文本最多 65,536 个 Java UTF-16 code unit；超过时以 close code `1009`
关闭。二进制 WebSocket frame 以 close code `1003` 拒绝。

应用正文仍受控制协议 `MESSAGE_*` 1 MiB body 上限约束。客户端不得用多条无序消息规避单消息限制。

## 9. C server 边界

C server 只保存启动登录中的消息能力字段，供数据库和管理视图展示；不实现 `/ws/client-messages`、实时 fan-out、
STMSG2 客户端数据面或对象存储。C 环境必须报告实时消息不可用。

## 10. 参考入口

| 能力 | Java 入口 |
| --- | --- |
| ticket 签发/消费 | `WebSocketTicketResource`、`WebSocketTicketService` |
| 管理 WebSocket | `ClientMessagesWebSocketHandler` |
| control 备用转发 | `MessageRequestHandler` |
| 在线能力 | `ClientSession`、`ClientAuthService` |
| Peer ACL | `PeerMeshService` |
