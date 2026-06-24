# HTTP route 直转协议

HTTP route 是与 TCP 端口映射并行的能力。公网访问者请求服务端 `/http/{clientName}/{route}/**`，服务端把 HTTP 请求封装成 `DIRECT_HTTP_REQUEST` 走控制连接发给客户端；客户端访问自己内网可达的目标服务，再把响应封装成 `DIRECT_HTTP_RESPONSE` 返回服务端。

## 公网入口

入口路径：

```text
/http/{clientName}/{route}/**
```

示例：

```bash
curl -i "http://127.0.0.1:8088/http/shuaiwin-shshi-fa22b7af/nexus/service/rest/v1/status?pretty=true"
```

路径解析：

| 部分 | 说明 |
| --- | --- |
| `clientName` | 目标客户端名，必须在线 |
| `route` | 客户端 HTTP route 名称，精确匹配 |
| `relativePath` | route 后面的路径，最少为 `/` |
| `rawQuery` | 原始 query string，不含 `?` |

`/http/**` 默认是公网流量入口，不要求管理 JWT。真正能访问的内网目标由服务端管理的 HTTP route 白名单决定。

## route 配置

管理 API：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/admin/http-routes` | 查询 HTTP route，可按 `clientId` 过滤 |
| `POST` | `/api/admin/clients/{id}/http-routes` | 为客户端新增 route |
| `PUT` | `/api/admin/http-routes/{routeId}` | 编辑、启停、配置路径改写或明细采集 |
| `DELETE` | `/api/admin/http-routes/{routeId}` | 删除 route |

route 字段：

| 字段 | 说明 |
| --- | --- |
| `route` | 公网路径中的 route 名称，客户端侧精确匹配 |
| `targetBaseUrl` | 客户端访问的内网目标基础地址，只支持 `http` 和 `https` |
| `enabled` | 是否启用 |
| `pathRewriteEnabled` | 是否对响应 HTML/CSS/JS 里的绝对路径做改写 |
| `detailCaptureEnabled` | 是否采集 HTTP 明细，默认关闭 |

服务端是 HTTP route 的权威来源。客户端 HTTP 登录响应会携带初始快照，后续 route CRUD 通过 `NAT_CONTROL.httpTunnelConfigList` 热更新。

## `DIRECT_HTTP_REQUEST`

服务端收到公网 HTTP 请求后创建 `DirectHttpRequestPacket`：

| 字段 | 说明 |
| --- | --- |
| `requestId` | 请求 ID；服务端等待响应时按它匹配 future |
| `requestMethod` | 原始 HTTP 方法 |
| `route` | route 名称 |
| `relativePath` | route 后面的相对路径，必须以 `/` 开头 |
| `rawQuery` | 原始 query string，可为空 |
| `headers` | Header 列表，格式为 `Name:Value` |
| `body` | 原始请求体字节 |

请求体限制：

- 服务端入口默认限制 `16 MiB`，由 `TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE` 控制。
- 客户端转发前也有 `16 MiB` 请求体保护。

服务端不会转发 hop-by-hop Header：

```text
connection
content-length
host
keep-alive
proxy-authenticate
proxy-authorization
te
trailer
transfer-encoding
upgrade
```

## 客户端转发规则

客户端用 `route` 查内存 route 表，拿到 `targetBaseUrl` 后拼接：

```text
target = targetBaseUrl + relativePath + ?rawQuery
```

安全约束：

- `targetBaseUrl` 只支持 `http` 和 `https`。
- `targetBaseUrl` 不能带 query 或 fragment。
- 拼接后的目标不能改变 scheme、host、port。
- `relativePath` 必须以 `/` 开头，不能包含 CR/LF。
- 路径不能使用 `.` 或 `..` 越界到 `targetBaseUrl` 基础路径之外。

客户端使用 Apache HttpClient，关闭自动重定向和自动内容解压。访问内网 HTTPS 目标时，当前 Java 实现使用 trust-all `SSLContext` 和 `NoopHostnameVerifier`，适合内网自签证书场景，但不提供目标证书校验。

`Range` Header 会被限制为单段且最大 `8 MiB`：

- `bytes=0-999999999` 会收敛为 `bytes=0-8388607`。
- 多段 Range 或非 bytes Range 不做改写。

响应体限制为 `64 MiB`。超过限制时客户端返回 `502` 和错误信息。

## `DIRECT_HTTP_RESPONSE`

客户端返回 `DirectHttpResponsePacket`：

| 字段 | 说明 |
| --- | --- |
| `requestId` | 与请求一致 |
| `statusCode` | 上游 HTTP 状态码 |
| `headers` | 响应 Header 列表，格式为 `Name:Value` |
| `body` | 响应体原始字节 |
| `error` | 转发失败时的错误信息 |

服务端收到后：

- `error` 不为空时，按 `statusCode` 返回错误；缺省为 `502`。
- 正常响应会复制可转发 Header。
- 开启路径改写时，可能会修改响应 body，并移除 `Content-Encoding` / `Content-Length`，由 Spring/Tomcat 重新计算长度。

## 响应路径改写

当 route 开启 `pathRewriteEnabled`，服务端会对以下正文类型做改写：

```text
text/html
text/css
text/javascript
application/javascript
application/x-javascript
application/ecmascript
text/ecmascript
```

改写目标：

- HTML 中 `href`、`src`、`action`、`poster` 等属性里的单斜杠绝对路径。
- HTML `srcset` 中的单斜杠绝对路径。
- CSS `url(/path)` 和 `@import "/path"`。
- HTML `<head>` 中注入运行时脚本，兜底改写 `fetch`、`XMLHttpRequest`、`history`、`setAttribute`、`EventSource`、`WebSocket` 中的单斜杠绝对路径。

不会改写：

- `http://`、`https://` 等完整 URL。
- `//cdn.example.com` 这类协议相对路径。
- `data:`、`javascript:` 等特殊协议。
- 已带 `/http/{clientName}/{route}` 前缀的路径。

如果 body 超过 `tunnel.http.rewrite.max-body-bytes`，或压缩解码失败，会跳过改写并原样返回。

## WebSocket 隧道

浏览器对 `/http/{clientName}/{route}/**` 发起 WebSocket upgrade 时，服务端使用 `NAT_MESSAGE` 而不是 `DIRECT_HTTP_REQUEST`：

1. 服务端分配 `channelId`。
2. 服务端向客户端发送 `NatMessageType.CONNECTED`，`metaData.source=ws`，并携带 route、路径、query、Header 和握手 body。
3. 浏览器 Text/Binary 帧封装为 `NatMessageType.DATA(channelId)`。
4. `data[0]` 表示帧类型：`0x01` 为 TextFrame，`0x02` 为 BinaryFrame。
5. 客户端连接内网 WebSocket 服务后，双向转发 DATA。
6. 任一端关闭时发送 `DISCONNECTED(channelId)`。

## 观测与存储

HTTP 明细采集由两层开关共同决定：

- 全局开关：`TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED`。
- route 开关：`detailCaptureEnabled`，新建默认关闭。

管理接口：

```text
GET /api/admin/traffic/http-exchanges
```

查询参数：

| 参数 | 说明 |
| --- | --- |
| `clientId` | 按客户端过滤 |
| `route` | 按 route 过滤 |
| `responseBodyType` / `responseDataType` | 按响应体类型过滤 |
| `field` | 搜索字段 |
| `q` | 搜索关键字 |
| `page` | 页码，从 `0` 开始 |
| `size` | 每页大小，最大 `500` |

常用搜索字段由 `HttpTrafficSearchField` 定义，前端会提供字段下拉。配置 Elasticsearch 后，HTTP 明细写入 `TUNNEL_ELASTICSEARCH_HTTP_INDEX`，否则写入数据库。

服务端保存完整请求体和响应体。对于 `Content-Encoding: gzip`、`deflate`、`br` 的新记录，服务端会尽量解压后保存可展示内容；旧记录展示时前端会做兼容兜底。
