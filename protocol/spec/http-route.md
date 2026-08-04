# HTTP route 与 WebSocket 流协议

HTTP route 是与 TCP 端口映射并行的数据面能力。公网请求进入服务端
`/http/{clientName}/{route}/**`，服务端在目标客户端的专用 `data` 连接上建立 NAT stream；客户端再访问
本机或内网 upstream。

本协议只支持控制协议 v2 的流式路径。旧同步 HTTP 与 Direct HTTP command 已删除。

## 1. 公网入口

```text
ANY /http/{clientName}/{route}/**
```

- `clientName` 必须对应已启用且在线的客户端；
- `route` 必须存在、启用并属于该客户端；
- 服务端持久化 route 可选择启用 HTTP Basic 入口认证；未启用时保持公开访问；
- 后续相对路径保留原始百分号编码；
- query 使用原始 query string，不执行 decode/re-encode；
- 普通请求使用 HTTP stream；支持 HTTP-route WebSocket 的实现使用同一 NAT stream 上的 SWS2。

认证已启用但凭据缺失或错误时返回 `401`，并携带 `WWW-Authenticate: Basic`；认证配置读取失败时返回
`503`。认证在读取请求体、创建 NAT stream，以及受支持实现执行 WebSocket Upgrade 之前完成。找不到客户端或活动 `data`
连接时返回 `502/503`（以实现的离线语义为准）；route 不存在由客户端拒绝。请求超时返回 `504`，请求体超过
配置上限返回 `413`。

## 2. route 配置

每条 route 至少包含：

| 字段 | 说明 |
| --- | --- |
| `clientId` | 所属客户端 |
| `route` | URL 中稳定的 route 名 |
| `targetBaseUrl` | 客户端实际访问的绝对 `http/https` 基础地址；WebSocket Upgrade 时客户端按 scheme 映射为 `ws/wss` |
| `enabled` | 是否允许公网访问 |
| `pathRewriteEnabled` | 是否对可安全缓冲的小型 HTML/CSS 响应执行路径改写 |
| `authEnabled` | 是否要求公网调用方通过 HTTP Basic 认证；默认 `false` |
| `authUsername` | Basic 用户名，trim 后最多 120 字符且不得含 `:`、CR 或 LF |

管理 API 的 mutation 使用可选 `authPassword` 接收密码，最长 256 字符；服务端只保存其哈希。响应仅返回
`authEnabled`、`authUsername` 与 `authPasswordConfigured`，不会返回明文或哈希。更新时省略密码、传 `null`
或传全空白字符串表示保留原密码；首次启用认证必须同时具备用户名和密码。关闭认证保留已有凭据，便于之后
重新启用。

入口认证仅属于 server 公网边界，不进入 `httpSpecusConfigList`，客户端也不持有访问密码。没有服务端持久化
记录的 legacy 本地 route 继续按公开入口处理，以兼容客户端本地配置。

目标 URI 由 `targetBaseUrl + relativePath + ?rawQuery` 构造。base URL 不能包含 query/fragment，相对路径不能
含控制字符。HTTP 客户端不自动跟随 redirect，响应原样返回给公网调用方。

## 3. 请求流

服务端分配非零 `uint32 streamId`，并在目标客户端 `data` 连接发送 NAT `OPEN`：

```json
{
  "source": "http",
  "phase": "request",
  "requestId": "123",
  "method": "POST",
  "route": "api",
  "relativePath": "/items/%E4%BD%A0",
  "rawQuery": "x=%2F",
  "headers": ["Content-Type:application/json"],
  "contentLength": 12,
  "trailerNames": ["Digest"]
}
```

`contentLength` 仅在公网请求已知长度时出现；`trailerNames` 仅在公网请求通过 `Trailer` header 声明尾部字段时
出现。随后发送零到多个 NAT `DATA`，每个 payload 最大 64 KiB；请求结束发送 NAT `FIN`，请求 trailers 放在
`FIN.metadata.trailers` 的 `name:value` 字符串数组中。接收端只转发 OPEN 已声明且名称合法的 trailer；未声明字段、
禁止字段和 CR/LF 注入必须丢弃或拒绝。没有 trailers 且长度已知时应保留定长请求，不得无条件改为 chunked。

Java、Go、.NET 与 Android client 都必须按上述规范流式转发 request trailers；任何实现都不得因平台 HTTP API
限制而静默丢弃 trailer、改写带 body 的 method，或把 early response 延迟到上传结束。Android 使用受 VPN protect 的
Netty HTTP/1.1 transport 满足该契约。

客户端必须在读取 request DATA 后按实际消费字节发送 `WINDOW_UPDATE`。如果 upstream 无法建立、请求格式无效、
本地队列超限或服务端取消，任一端发送 `RST(value=errorCode, metadata.reason)` 并释放 stream。

## 4. 响应流

客户端取得 upstream 响应头后立即返回同一 streamId 的 NAT `OPEN`：

```json
{
  "source": "http",
  "phase": "response",
  "statusCode": 200,
  "headers": ["Content-Type:text/event-stream"],
  "trailerNames": ["Digest"]
}
```

响应 body 按到达顺序发送 NAT `DATA`，最后发送 NAT `FIN`；trailers 使用：

```json
{"trailers":["Digest:sha-256=..."]}
```

响应 OPEN 的 `trailerNames` 声明规则与请求相同，服务端据此生成公网响应的 `Trailer` 声明，并只接受 FIN 中对应
字段。服务端收到响应 OPEN 后即可提交公网响应头，DATA 到达后立即写出并 flush。因此 SSE、流式下载和大响应不需要
等待完整 body。服务端消费响应 DATA 后回送 WINDOW_UPDATE，客户端必须在 credit 不足时暂停 upstream 读取。

Java 基准实现的请求体上限为 16 MiB，响应体上限为 64 MiB。上限针对完整流，不是单帧；跨语言实现不得通过发送
多个 DATA 绕过累计限制。

## 5. 流控与状态机

HTTP 使用控制协议定义的统一流控：

- 初始发送窗口 1 MiB；
- 最大累计窗口 16 MiB；
- 单流待发送队列上限 4 MiB；
- 活动流公平轮转，每轮最多发送一个 64 KiB DATA；
- `WINDOW_UPDATE.value` 必须大于 0，且不能导致窗口溢出；
- FIN 只关闭当前发送方向；双方 FIN 后 stream 才正常结束；
- DATA-after-FIN、重复 OPEN、未知 stream 或非法状态转换按控制协议的 stream 生命周期规则处理：单流错误只 RST
  受影响 stream，只有针对从未打开 stream 的 RST 才关闭 data connection。

公网调用方断开、Servlet/ASP.NET/Go context 取消或超时必须发送 RST。客户端收到 RST 后立即取消 upstream 请求并
关闭 response body，不继续后台下载。

## 6. Header 规则

以下 hop-by-hop 或由当前连接重新计算的 header 不转发：

```text
Connection, Content-Length, Host, Keep-Alive, Proxy-Authenticate,
Proxy-Authorization, TE, Trailer, Transfer-Encoding, Upgrade
```

其他 header 按 `name:value` 数组保留重复值。受保护 route 的入口 `Authorization: Basic ...` 在校验成功后必须
从转发 metadata 和流量明细中移除，防止公网凭据泄露给 upstream 或持久化；公开 route 的 Authorization 仍原样
透传，以支持 upstream 自身的 Bearer/Basic 认证。公网响应的 Content-Length 由实际输出决定；经过路径改写或
解压后必须移除旧 Content-Length/Content-Encoding。可解析的单范围 `Range` 会裁剪到最多 8 MiB；multi-range、
suffix range 或其它未识别表达式原样交给 upstream 处理，最终响应仍受累计大小上限约束。

## 7. WebSocket SWS2

Java、Go、.NET server 的完整对齐实现与 C server 的兼容子集都使用 `/http/{clientName}/{route}/**` 接收
WebSocket Upgrade，并与普通 HTTP 共用 route Basic gate；认证失败必须在返回 `101 Switching Protocols` 之前拒绝，
且不得创建 NAT stream。建立后，WebSocket frame 放入 NAT DATA 的 SWS2 二进制 envelope：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| magic | 4 | ASCII `SWS2` |
| opcode | 1 | continuation/text/binary/close/ping/pong |
| flags | 1 | bit 0 FIN，bits 1..3 RSV |
| closeCode | 2 | 仅 close 有效 |
| payloadLength | 4 | 后续 payload 长度 |
| payload | N | 原始 frame payload |

固定头为 12 字节。控制帧必须 FIN、payload 不超过 125 字节；close reason 最大 123 字节。非 CLOSE 的 closeCode
必须为 0；CLOSE 可使用 0（仅无 reason）或 `1000..4999` 中除 `1004`、`1005`、`1006`、`1015` 外的值。未知 opcode、
非法 RSV、错误 close code、截断、尾随字节和超过 NAT chunk 上限的单个 SWS2 envelope 必须拒绝。原始 WebSocket
data frame 可在 16 MiB 上限内规范化为一组 SWS2：首段保留 opcode/RSV，后续段使用 continuation，只有末段继承
原始 FIN；ping/pong/close 等控制帧必须保持单帧且不得拆分。该规范化保留 WebSocket 消息与扩展语义，不把未知类型
当 binary，也不使用旧的一字节 text/binary 前缀。

## 8. 响应路径改写

只有 route 显式启用 `pathRewriteEnabled`、Content-Type 可改写且响应不超过配置的 rewrite buffer 上限时，服务端才
缓冲 HTML/CSS 并改写相对 URL。超过上限后立即转为流式透传，不能继续无界增长。

改写可处理 HTML URL 属性、`srcset`、CSS `url(...)`、`@import` 和运行时 polyfill。gzip/deflate/br 解码仅用于
管理预览或明确的响应改写，不属于控制 wire 压缩。

## 9. 观测与存储

每个请求记录 route/client、method、relativePath、rawQuery、status、耗时、请求/响应字节和失败原因。正文预览按
配置截断，采集队列有界，不能反向阻塞数据面。流量计数按实际 DATA 字节累计，不包含控制 framing。

日志和指标不得把 streamId、完整 URL、token、Basic Authorization 或正文作为常驻标签。

## 10. 实现入口

| 实现 | 服务端 | 客户端 |
| --- | --- | --- |
| Java | `HttpSpecusController`、`HttpStreamExchange` | `HttpStreamForwarder` |
| Go | `internal/directhttp`、`internal/nat/http_stream.go` | `internal/client/http_stream.go` |
| .NET | `DirectHttpEndpoints`、`HttpSpecusStream`、`WebSocketSpecusStream` | `HttpStreamChannel`、`WebSocketSpecusChannel` |
| Android | — | `SpecusCore.HttpStreamForwarder`、`SpecusCore.LocalWebSocketSpecus` |
| C server | `admin_http.c`、`main.c` v2 NAT + SWS2 兼容子集；未通过完整 SWS2 向量与严格状态机门禁 | 使用 Java/Go/.NET/Android v2 客户端 |

中央合法与 malformed frame 位于 `protocol/test-vectors/control-v2/frames`。
