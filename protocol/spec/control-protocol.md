# 控制连接协议

控制连接是客户端与服务端之间的长连接，默认监听 `7010/TCP`，可选叠加 TLS。它承载登录、心跳、管理信令、TCP 端口映射数据、HTTP 直转请求、WebSocket 隧道和 Peer Mesh 信令。

## 主帧格式

所有非 UDP 的控制连接消息都以固定 11 字节头开始：

| 字段 | 长度 | 类型 | 说明 |
| --- | --- | --- | --- |
| `magic` | 4 字节 | big-endian int | 固定 `0x14353565` |
| `version` | 1 字节 | unsigned byte | 当前保留，Java 默认来自 `Packet.version` |
| `serializer` | 1 字节 | unsigned byte | 消息体序列化算法 |
| `command` | 1 字节 | signed byte | 指令类型 |
| `length` | 4 字节 | big-endian int | 后续 body 字节数 |
| `body` | N 字节 | bytes | 指令对应消息体 |

Netty pipeline 中 `Spliter` 负责按 `magic + length` 切帧，`PacketDecoder` / `PacketEncoder` 负责调用 `PacketCodec` 编解码。

## `Command`

| 指令 | 数值 | 消息体 | 方向 | 说明 |
| --- | ---: | --- | --- | --- |
| `LOGIN_REQUEST` | `1` | `LoginRequestPacket` | client -> server | 控制连接登录，必须携带 HTTP 登录得到的 `accessToken` |
| `LOGIN_RESPONSE` | `-1` | `LoginResponsePacket` | server -> client | 登录结果，失败后服务端主动关闭连接 |
| `MESSAGE_REQUEST` | `2` | `MessageRequestPacket` | client -> server | 通用消息，目前主要用于 `PEER_CONTROL` |
| `MESSAGE_RESPONSE` | `-2` | `MessageResponsePacket` | server -> client | 通用下行消息，承载 `NAT_CONTROL`、`PEER_CONTROL` 等 |
| `LOGOUT_REQUEST` | `3` | `LogoutRequestPacket` | client -> server | 退出请求 |
| `LOGOUT_RESPONSE` | `-3` | `LogoutResponsePacket` | server -> client | 退出响应 |
| `HEARTBEAT_REQUEST` | `4` | `HeartBeatRequestPacket` | client -> server | 写空闲时客户端发送 |
| `HEARTBEAT_RESPONSE` | `-4` | `HeartBeatResponsePacket` | server -> client | 服务端心跳响应 |
| `HTTP_REQUEST` | `5` | `HttpRequestPacket` | legacy | 旧同步 HTTP 请求 |
| `HTTP_RESPONSE` | `-5` | `HttpResponsePacket` | legacy | 旧同步 HTTP 响应 |
| `NAT_MESSAGE` | `6` | 自定义 NAT body | 双向 | TCP 端口映射、WebSocket 隧道数据 |
| `DIRECT_HTTP_REQUEST` | `7` | `DirectHttpRequestPacket` | server -> client | HTTP route 直转请求 |
| `DIRECT_HTTP_RESPONSE` | `-7` | `DirectHttpResponsePacket` | client -> server | HTTP route 直转响应 |

## 序列化算法

默认序列化算法为 `COMPACT_BINARY`。Java `PacketCodec.encode(ByteBuf, Packet)` 会对普通 `Packet` 使用紧凑二进制；只有 `NAT_MESSAGE` 例外，元数据保持自定义 JSON 布局。

紧凑二进制 payload 结构：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `payloadType` | 1 字节 | `0` 表示原始 payload，`1` 表示 raw deflate payload |
| `payload` | N 字节 | 对象字段按固定 schema 顺序编码后的数据 |

压缩规则：

- 原始对象 schema 编码结果大于等于 `64` 字节时尝试 deflate。
- 压缩后更短才使用 `payloadType=1`。
- 解压上限为 `16 MiB`，超过会拒绝。
- 字符串使用 UTF-8，空值用长度标记 `0` 表示。
- `int` 使用无符号 varint；可空 `long` 使用 `0/1` 标记加 ZigZag varlong。

当前紧凑 schema 覆盖登录、消息、心跳、legacy HTTP、Direct HTTP 请求和响应。跨语言实现必须按字段顺序编码，不依赖字段名。

## `MessageType`

`MessageRequestPacket` 和 `MessageResponsePacket` 包含：

| 字段 | 说明 |
| --- | --- |
| `clientName` | 来源客户端名；服务端下发时可为目标客户端名或 `server` |
| `toClientName` | 目标客户端名 |
| `messageType` | 通用消息类型 |
| `message` | 字符串消息体，通常是 JSON |

`MessageType` 当前值：

| 类型 | ordinal | 说明 |
| --- | ---: | --- |
| `SERVER_TO_CLIENT` | `0` | 普通服务端消息 |
| `CLIENT_TO_SERVER` | `1` | 普通客户端上行消息 |
| `CLIENT_TO_CLIENT` | `2` | 客户端间普通消息 |
| `NAT_CONTROL` | `3` | 服务端向客户端下发 TCP 映射和 HTTP route 快照 |
| `PEER_CONTROL` | `4` | Peer Mesh JSON 信令 |

注意：紧凑二进制里的 enum 使用 `ordinal + 1` 编码，`0` 表示 `null`。

## 登录与心跳

客户端启动时先走 HTTP 登录，拿到 `clientName`、`clientSessionId` 和 `accessToken`。随后建立控制连接并发送：

```json
{
  "clientName": "shuaiwin-shshi-fa22b7af",
  "clientSessionId": 123456789,
  "accessToken": "cs_xxx"
}
```

服务端用 token hash 查找 `ClientSession`，校验过期时间、客户端是否启用、连接频率、同一机器实例数和凭证在线实例数。成功后绑定 `SessionUtil`，写入连接记录，并异步下发 `NAT_CONTROL` 和 Peer Mesh roster。

客户端只有收到 `LOGIN_RESPONSE.success=true` 才重置重连退避。token 过期时客户端会重新执行 HTTP 登录并重连；快过期时也会主动刷新，尽量不中断服务。

心跳由客户端写空闲触发，服务端读空闲超时会关闭控制连接。连接断开后客户端按指数退避重连，退避上限为 `60s`。

## `NAT_CONTROL`

`NAT_CONTROL` 使用 `MESSAGE_RESPONSE` 承载，`message` 是 JSON。服务端每次下发的是当前权威全量快照，而不是增量。

```json
{
  "clientName": "client-a",
  "remoteAddress": "tunnel.example.com",
  "remotePort": 7010,
  "tunnelConfigList": [
    {
      "port": 10022,
      "tunnelAddress": "192.168.1.10",
      "tunnelPort": 22
    }
  ],
  "httpTunnelConfigList": [
    {
      "route": "nexus",
      "targetBaseUrl": "http://192.168.1.252:8080"
    }
  ]
}
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `clientName` | 目标客户端名 |
| `remoteAddress` | 服务端公网地址；可为空，主要用于展示 |
| `remotePort` | 控制连接端口 |
| `tunnelConfigList` | 已启用 TCP 端口映射全集 |
| `httpTunnelConfigList` | 已启用 HTTP route 全集；字段缺省表示服务端尚未接管该客户端 HTTP route |

`httpTunnelConfigList` 的三种语义：

- 字段缺省：客户端继续使用 HTTP 登录响应里的初始快照。
- 字段为空数组：客户端清空 HTTP route。
- 字段为数组：客户端用该数组整体替换内存 route 表。

## `NAT_MESSAGE`

`NAT_MESSAGE` 的 body 不使用普通 `Packet` schema，而是自定义布局：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `natMessageType` | 4 字节 | `NatMessageType.code` |
| `metaDataLength` | 4 字节 | JSON 元数据长度 |
| `metaData` | N 字节 | JSON object，使用 `FASTJSON` |
| `data` | N 字节 | 可选，使用 `CompactBinarySerializer.encodePayload` 包装 |

`NatMessageType`：

| 类型 | code | 说明 |
| --- | ---: | --- |
| `REGISTER` | `1` | 客户端向服务端注册公网监听端口 |
| `REGISTER_RESULT` | `2` | 服务端返回注册结果 |
| `CONNECTED` | `3` | 服务端通知客户端有外部连接或 WebSocket 流建立 |
| `DISCONNECTED` | `4` | 任一端通知连接关闭 |
| `DATA` | `5` | 双向数据 payload |
| `KEEPALIVE` | `6` | 保活 |
| `UNREGISTER` | `7` | 取消端口注册 |
| `HTTP_ROUTES_REPORT` | `8` | 客户端上报当前 HTTP route 快照，仅用于展示和诊断 |

常见 `metaData` 字段：

| 字段 | 说明 |
| --- | --- |
| `channelId` | 单条外部 TCP/WebSocket 连接的逻辑 ID |
| `port` | 公网监听端口 |
| `clientName` | 客户端名 |
| `source` | `ws` 表示该帧属于 HTTP WebSocket 隧道 |
| `route` | HTTP route 名称 |
| `relativePath` | WebSocket 建连时的相对路径 |
| `rawQuery` | 原始 query string |
| `headers` | Header 字符串列表 |

TCP 端口映射流程：

1. 服务端下发 `NAT_CONTROL`。
2. 客户端为每个 TCP 映射发送 `REGISTER`。
3. 服务端启动对应公网端口监听并回 `REGISTER_RESULT`。
4. 外部连接到达后服务端发 `CONNECTED(channelId)`。
5. 双方用 `DATA(channelId)` 传输字节。
6. 任一端关闭后发送 `DISCONNECTED(channelId)`。

WebSocket 隧道复用 `NAT_MESSAGE`，但 `DATA.data[0]` 是帧类型前缀：`0x01` 表示 TextFrame，`0x02` 表示 BinaryFrame。
