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
- 后续相对路径保留原始百分号编码；
- query 使用原始 query string，不执行 decode/re-encode；
- 普通请求使用 HTTP stream，WebSocket Upgrade 使用同一 NAT stream 上的 SWS2。

找不到客户端或活动 `data` 连接时返回 `502`；route 不存在时返回 `404`。请求超时返回 `504`，请求体超过
配置上限返回 `413`。

## 2. route 配置

每条 route 至少包含：

| 字段 | 说明 |
| --- | --- |
| `clientId` | 所属客户端 |
| `route` | URL 中稳定的 route 名 |
| `targetBaseUrl` | 客户端实际访问的 `http/https/ws/wss` 基础地址 |
| `enabled` | 是否允许公网访问 |
| `pathRewriteEnabled` | 是否对可安全缓冲的小型 HTML/CSS 响应执行路径改写 |

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
  "contentLength": 12
}
```

`contentLength` 仅在公网请求已知长度时出现。随后发送零到多个 NAT `DATA`，每个 payload 最大 64 KiB；请求
结束发送 NAT `FIN`，请求 trailers 放在 `FIN.metadata.trailers` 的 `name:value` 字符串数组中。

客户端必须在读取 request DATA 后按实际消费字节发送 `WINDOW_UPDATE`。如果 upstream 无法建立、请求格式无效、
本地队列超限或服务端取消，任一端发送 `RST(value=errorCode, metadata.reason)` 并释放 stream。

## 4. 响应流

客户端取得 upstream 响应头后立即返回同一 streamId 的 NAT `OPEN`：

```json
{
  "source": "http",
  "phase": "response",
  "statusCode": 200,
  "headers": ["Content-Type:text/event-stream"]
}
```

响应 body 按到达顺序发送 NAT `DATA`，最后发送 NAT `FIN`；trailers 使用：

```json
{"trailers":["Digest:sha-256=..."]}
```

服务端收到响应 OPEN 后即可提交公网响应头，DATA 到达后立即写出并 flush。因此 SSE、流式下载和大响应不需要等待
完整 body。服务端消费响应 DATA 后回送 WINDOW_UPDATE，客户端必须在 credit 不足时暂停 upstream 读取。

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
- DATA-after-FIN、重复 OPEN、未知 stream 或非法状态转换必须 RST 或关闭违规连接。

公网调用方断开、Servlet/ASP.NET/Go context 取消或超时必须发送 RST。客户端收到 RST 后立即取消 upstream 请求并
关闭 response body，不继续后台下载。

## 6. Header 规则

以下 hop-by-hop 或由当前连接重新计算的 header 不转发：

```text
Connection, Content-Length, Host, Keep-Alive, Proxy-Authenticate,
Proxy-Authorization, TE, Trailer, Transfer-Encoding, Upgrade
```

其他 header 按 `name:value` 数组保留重复值。公网响应的 Content-Length 由实际输出决定；经过路径改写或解压后必须
移除旧 Content-Length/Content-Encoding。`Range` 只接受有界的单范围表达式，非法或无界范围不得直接传给 upstream。

## 7. WebSocket SWS2

WebSocket Upgrade 仍使用 `/http/{clientName}/{route}/**`。建立后，WebSocket frame 放入 NAT DATA 的 SWS2
二进制 envelope：

| 字段 | 长度 | 说明 |
| --- | ---: | --- |
| magic | 4 | ASCII `SWS2` |
| opcode | 1 | continuation/text/binary/close/ping/pong |
| flags | 1 | bit 0 FIN，bits 1..3 RSV |
| closeCode | 2 | 仅 close 有效 |
| payloadLength | 4 | 后续 payload 长度 |
| payload | N | 原始 frame payload |

固定头为 12 字节。控制帧必须 FIN、payload 不超过 125 字节；close reason 最大 123 字节。未知 opcode、非法 RSV、
错误 close code、截断、尾随字节和超过 NAT chunk 上限的 frame 必须拒绝。SWS2 保留 WebSocket frame 语义，不把
未知类型当 binary，也不使用旧的一字节 text/binary 前缀。

## 8. 响应路径改写

只有 route 显式启用 `pathRewriteEnabled`、Content-Type 可改写且响应不超过配置的 rewrite buffer 上限时，服务端才
缓冲 HTML/CSS 并改写相对 URL。超过上限后立即转为流式透传，不能继续无界增长。

改写可处理 HTML URL 属性、`srcset`、CSS `url(...)`、`@import` 和运行时 polyfill。gzip/deflate/br 解码仅用于
管理预览或明确的响应改写，不属于控制 wire 压缩。

## 9. 观测与存储

每个请求记录 route/client、method、relativePath、rawQuery、status、耗时、请求/响应字节和失败原因。正文预览按
配置截断，采集队列有界，不能反向阻塞数据面。流量计数按实际 DATA 字节累计，不包含控制 framing。

日志和指标不得把 streamId、完整 URL、token 或正文作为常驻标签。

## 10. 实现入口

| 实现 | 服务端 | 客户端 |
| --- | --- | --- |
| Java | `HttpTunnelController`、`HttpStreamExchange` | `HttpStreamForwarder` |
| Go | `internal/directhttp`、`internal/nat/http_stream.go` | `internal/client/http_stream.go` |
| .NET | `DirectHttpDispatcher`、`HttpTunnelStream` | `HttpStreamChannel` |
| C server | `admin_http.c`、`main.c` NAT stream bridge | 使用 Java/Go/.NET v2 客户端 |

中央合法与 malformed frame 位于 `protocol/test-vectors/control-v2/frames`。
