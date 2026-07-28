# 控制与隧道流协议 v2

本协议是唯一受支持的 TCP 线协议，不保留 v1 解码、旧 HTTP command、serializer 回退或 payload
压缩格式。客户端先完成 HTTP 登录，再建立一条控制连接和一条专用数据连接。两条连接默认使用同一
TCP/TLS 监听端口，由登录帧中的 `connectionRole` 绑定角色。

## 传输安全

- 公网生产环境必须使用文件证书 TLS。
- 只有显式声明 `tls-terminated-upstream` 且 TCP listener 绑定 loopback 或受控私网时，才允许上游四层
  代理终止 TLS。
- `prod` / `production` profile 下明文公网 listener 或 self-signed 证书会阻止服务启动。
- 控制与数据连接使用相同的 TLS 策略；不能只保护控制连接。

## 连接角色

客户端按以下顺序建连：

1. 建立 `control` 连接并发送 `LOGIN_REQUEST`。
2. 收到成功的 `LOGIN_RESPONSE` 后建立 `data` 连接。
3. `data` 使用相同的 `clientName`、`clientSessionId` 和 `accessToken` 登录。
4. 服务端只有在匹配的 `control` 已绑定时才接受 `data`。

每个 TCP 连接只能登录一次。同一客户端会话只保留一条 `control` 和一条 `data`；新连接替换同角色旧
连接。控制连接关闭时，服务端同时关闭匹配的数据连接。

| 角色 | 登录后允许的 client -> server 帧 |
| --- | --- |
| `control` | `MESSAGE_REQUEST`、心跳、退出 |
| `data` | `NAT_MESSAGE`、心跳、退出 |

服务端下行遵守同一边界：管理、NAT 配置和 Peer 信令只走 `control`；TCP、HTTP、WebSocket 字节流只走
`data`。角色不匹配、重复登录和登录前非登录帧均为协议违规并关闭连接。

## 主帧

所有帧使用固定 11 字节 big-endian 头：

| 字段 | 长度 | 值 |
| --- | ---: | --- |
| `magic` | 4 | `0x14353565` |
| `version` | 1 | 必须为 `2` |
| `serializer` | 1 | 必须为 `4`，即 CompactBinary |
| `command` | 1 | 固定 wire ID，按有符号 byte 解释 |
| `bodyLength` | 4 | 后续 body 字节数，`int32 >= 0` |
| `body` | N | command 专属 body |

解码器必须在分配前验证 magic、version、serializer、command、长度及完整帧上限，并要求 body 被完全
消费。禁止接受截断或尾随字节。

- 登录前完整帧上限：`16 KiB`。
- 登录后默认完整帧上限：`32 MiB`，服务端可配置得更小。
- `MESSAGE_*` body 上限：`1 MiB`。
- NAT metadata 上限：`65,535` 字节。
- NAT DATA 发送分片上限：`64 KiB`。

## Command registry

| command | wire ID | body | 角色 |
| --- | ---: | --- | --- |
| `LOGIN_REQUEST` | `1` | CompactBinary login request | 未认证 |
| `LOGIN_RESPONSE` | `-1` | CompactBinary login response | 未认证响应 |
| `MESSAGE_REQUEST` | `2` | CompactBinary message request | control |
| `MESSAGE_RESPONSE` | `-2` | CompactBinary message response | control |
| `LOGOUT_REQUEST` | `3` | 空 body | control/data |
| `LOGOUT_RESPONSE` | `-3` | CompactBinary result | control/data |
| `HEARTBEAT_REQUEST` | `4` | 空 body | control/data |
| `HEARTBEAT_RESPONSE` | `-4` | 空 body | control/data |
| `NAT_MESSAGE` | `6` | NAT stream v2 body | data |

未登记的 command 必须拒绝。`5/-5` 和 `7/-7` 已删除，不能按旧同步 HTTP 或 Direct HTTP schema
解释。

## CompactBinary

CompactBinary body 直接由固定 schema 字段串接，不再包含 `payloadType`，也不执行 deflate。字符串使用
UTF-8 长度前缀；nullable 值使用显式 presence marker；整数按对应 codec 的 varint/ZigZag 规则编码。

所有 schema 都要求 exact consumption。增加、删除或重排字段属于线协议破坏性修改，必须同时提升协议版本，
不能在 v2 body 尾部追加“可选字段”。

`LOGIN_REQUEST` 字段顺序固定为：

1. `clientName: string`
2. `clientSessionId: nullable int64`
3. `accessToken: string`
4. `connectionRole: string`，仅允许 `control` 或 `data`

`MessageType` 使用固定 wire ID，不依赖语言枚举 ordinal：

| 类型 | wire ID |
| --- | ---: |
| `SERVER_TO_CLIENT` | `1` |
| `CLIENT_TO_SERVER` | `2` |
| `CLIENT_TO_CLIENT` | `3` |
| `NAT_CONTROL` | `4` |
| `PEER_CONTROL` | `5` |

## NAT stream v2

`NAT_MESSAGE` body 由固定 16 字节头、可选 JSON object metadata 和原始 data 组成：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| `type` | 1 | `NatMessageType` wire ID |
| `flags` | 1 | 当前仅 bit 0 `END_STREAM` |
| `metadataLength` | 2 | unsigned，最大 `65,535` |
| `streamId` | 4 | unsigned，连接内唯一；`0` 保留给连接级帧 |
| `value` | 4 | unsigned，WINDOW_UPDATE credit 或 RST error code |
| `dataLength` | 4 | 原始 data 长度 |
| `metadata` | M | UTF-8 JSON object，只用于 OPEN/FIN/RST 等控制阶段 |
| `data` | N | 原始字节，不压缩、不加第二层长度或 Base64 |

| type | ID | `streamId` | 语义 |
| --- | ---: | --- | --- |
| `REGISTER` | `1` | `0` | 注册公网 TCP 端口 |
| `REGISTER_RESULT` | `2` | `0` | 注册结果 |
| `OPEN` | `3` | 非零 | 建立 TCP、HTTP 或 WebSocket 逻辑流 |
| `FIN` | `4` | 非零 | 当前方向半关闭；可携带 trailers metadata |
| `DATA` | `5` | 非零 | 原始流数据；metadata/value 必须为空/零 |
| `KEEPALIVE` | `6` | `0` | 数据连接保活 |
| `UNREGISTER` | `7` | `0` | 取消公网端口 |
| `RST` | `8` | 非零 | 立即取消；`value` 为错误码，可携带 reason |
| `WINDOW_UPDATE` | `9` | 非零 | 增加发送 credit，`value > 0` |

每流初始发送窗口为 `1 MiB`，窗口累计上限 `16 MiB`，单流待发送队列上限 `4 MiB`。发送端按流轮转，
每轮最多发送一个不超过 `64 KiB` 的 DATA 分片；credit 不足或数据连接不可写时暂停对应上游读取。消费
DATA 后按实际字节数回送 `WINDOW_UPDATE`。窗口溢出、队列溢出、DATA-after-FIN 或非法状态转换使用
`RST` 或关闭违规连接。

## HTTP streaming

HTTP route 不使用独立 command。服务端在数据连接上发送：

1. `OPEN`，metadata 含 `source=http`、`phase=request`、`method`、`route`、`relativePath`、
   `rawQuery`、`headers` 和可选 `contentLength`。
2. 零到多个请求 `DATA`。
3. 请求 `FIN`。
4. 客户端以 `OPEN(source=http, phase=response, statusCode, headers)` 返回响应头。
5. 零到多个响应 `DATA`，随后 `FIN(trailers?)`。

浏览器断开、超时或任一端失败必须发送 `RST`，并取消 upstream 请求。SSE 和大响应按 DATA 到达即向
下游写出，不等待完整 body。

## WebSocket frame specus

WebSocket payload 在 NAT DATA 内使用 `SWS2` 二进制 envelope：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| magic | 4 | ASCII `SWS2` |
| opcode | 1 | continuation/text/binary/close/ping/pong |
| flags | 1 | bit 0 FIN，bits 1..3 RSV |
| closeCode | 2 | 仅 CLOSE 有效 |
| payloadLength | 4 | 后续 payload 长度 |
| payload | N | 最大 `64 KiB - 12` |

控制帧必须 FIN、不得携带 RSV、payload 不超过 125 字节；CLOSE reason 最大 123 字节。未知 opcode、错误
长度、非法 close code 和尾随字节必须拒绝。

## 测试向量

唯一主副本位于 `protocol/test-vectors/control-v2/frames`。Java 生成器负责更新合法和 malformed fixture；
Java、Go、.NET 与 C 测试必须直接读取该目录。v1、旧 HTTP command 和 deflate fixture 不得重新加入。
