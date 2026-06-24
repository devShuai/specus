# shuai-tunnel 详细设计文档

> 版本：与 `main` 分支当前实现对齐（顶层提交 `57f1a67 feat: add load test helpers and enhance connection management for scaling`）。
> 本文档描述系统的总体设计、协议、各模块职责、数据模型、并发模型、安全模型与运维相关的关键决策，便于后续二次开发和审计。

## 1. 目标与定位

`shuai-tunnel` 是一个用于学习与演进的 **Java 内网穿透平台**。设计目标按优先级依次为：

1. **可读性与可演进**：以最小可用的协议栈实现一条公网到内网的隧道，所有关键流程可直接从源码读出，不依赖外部框架黑盒。
2. **易部署**：一个 Spring Boot 服务端 + 一个 Java/Go 客户端，默认使用 SQLite 即可跑通。
3. **可观测**：登录成功/失败、流量、连接频率、端口映射状态都进入数据库与管理后台。
4. **安全升级路径清晰**：HMAC 登录、Bearer JWT 鉴权、可选 TLS 控制通道，留出生产化空间。
5. **不追求极致性能**：当前默认是单服务端节点；针对单机 1 万连接的优化方案见 `docs/single-node-10k-connections-optimization-plan.md`。

当前版本仍以单体 `tunnel-server` 部署为主。后续若要把控制端和连接端拆分、让连接端做高可用和滚动 drain，方案见 `docs/server-control-edge-ha-plan.md`。

非目标：不提供 P2P 打洞（相关研究见 `docs/direct-connect-hole-punching-research.md`）、不实现 UDP 穿透（`UdpConnection` 留空占位）、不做多区域调度。

## 2. 顶层架构

```
+-------------+   TCP/HTTP    +---------------------------+   Custom Frame Protocol    +----------------+   TCP    +-------------+
| 公网访问者   | ────────────► |  tunnel-server (8088/7010)| ◄────────────────────────► | tunnel-client  | ───────► | 内网目标服务 |
+-------------+               +---------------------------+   (over TCP / 可选 TLS)    +----------------+          +-------------+
                                          ▲
                                          │ Bearer JWT (HS256/RS256)
                                          ▼
                              +---------------------------+
                              |      管理后台 / OIDC       |
                              +---------------------------+
```

**两类入口**：

- **TCP**：服务端按"公网映射端口 → 客户端 → 内网目标"的链路转发原始字节流。每个 `TunnelMapping` 在服务端动态启动一个 `TcpServer`。
- **HTTP**：服务端在 `8088/http/{client}/{route}/...` 上接收请求，通过控制连接同步发给客户端，客户端在本地发起真实 HTTP 请求并把响应回传，最终由服务端写回原始 HTTP 响应。

**两类连接**：

- **控制连接**：客户端与服务端之间一条长连接（默认 `7010/TCP`，可叠加 TLS）。承载登录、心跳、`NAT_CONTROL` 下发、HTTP 直转、NAT 隧道字节流。所有控制信令多路复用在这一条连接上。
- **公网监听端口**：每条启用的 `TunnelMapping` 一个监听端口，承载真实数据流量。

## 3. 模块结构

| 模块 | 路径 | 职责 |
| --- | --- | --- |
| `tunnel-common` | `implementations/java/common/src/main/java/com/theshuai/common` | 协议、编解码、命令、序列化、HMAC、通用 Handler、`Session`/`SyncFuture` |
| `tunnel-server` | `implementations/java/server/src/main/java/com/theshuai/tunnelserver` | Netty 服务端、管理 REST、登录鉴权、HTTP 直转入口、TLS、持久化、归档 |
| `tunnel-client` | `implementations/java/client/src/main/java/com/theshuai/tunnelclient` | Java 客户端：启动、读取本地配置、控制连接重连、本地连接池 |
| `implementations/go/client` | `implementations/go/client` | Go 客户端：与 Java 客户端协议对等，登录后还会注册本地 `tunnelConfigList` |
| `tools/` | `tools/` | 负载测试与运维辅助脚本 |

模块之间**只有 Java 三模块互相依赖**，Go 客户端独立维护协议实现，因此协议变更需要同步两套实现。

## 4. 协议设计

### 4.1 帧格式（`PacketCodec`）

控制连接上所有消息均为定长帧头 + 变长帧体：

```
+--------+--------+----------+----------+------------+-------------------+
| magic  | ver    | algo(1B) | cmd(1B)  | length(4B) | body (length B)   |
| 4B     | 1B     |          |          |            |                   |
+--------+--------+----------+----------+------------+-------------------+
0        4        5          6          7            11
```

- `magic = 0x14353565`（位于 `PacketCodec`），用于 `Spliter` 在错位/脏数据时丢弃直到下一个 magic。
- `ver = 1`，预留扩展。
- `algo`：序列化算法号，对应 `SerializerAlgorithm` 枚举：`COMPACT_BINARY`（默认）、`FASTJSON`、`PROTOBUF`、`JACKSON`。
- `cmd`：业务命令号，对应 `Command`（见 §4.3）。
- `length`：body 字节长度，约束在 `0..16 MiB`。

**帧拆分**：`Spliter`（基于 LengthFieldBasedFrameDecoder 思路）保证半包/粘包正确切分。

### 4.2 序列化算法（`com.theshuai.common.serialize.impl`）

| 算法 | 用途 | 备注 |
| --- | --- | --- |
| `CompactBinarySerializer` | **默认**控制消息编码 | 自描述紧凑二进制：省略字段名、变长整数、短类型标记；payload ≥ 阈值且压缩后变小时启用 Deflate；带 1 字节 payload 类型标记，解压上限 16 MiB |
| `FastJsonSerializer` | NAT 元数据 (`NatMessagePacket`) | 因为 NAT 元数据采用自定义布局：JSON 头 + 紧凑二进制载荷段 |
| `ProtobufSerializer` | 预留 | 当前未在主路径上使用 |
| `JacksonSerializer` | 工具 | REST 层使用 |

NAT 数据帧的封装规则：
1. `NatMessagePacket` 头由 FastJSON 序列化（保留可读性，便于排查）；
2. 隧道字节流 payload 走紧凑二进制的 **payload 编码**（同样可触发 Deflate）；
3. 整体仍以一个 `Command.NAT_*` 帧发送。

### 4.3 命令集（`Command` 枚举）

| 类别 | 命令 | 含义 |
| --- | --- | --- |
| 控制 | `LOGIN_REQUEST` / `LOGIN_RESPONSE` | 客户端登录、服务端返回结果 |
| 控制 | `LOGOUT_REQUEST` / `LOGOUT_RESPONSE` | 客户端主动离线 |
| 控制 | `HEARTBEAT_REQUEST` / `HEARTBEAT_RESPONSE` | 心跳保活 |
| 控制 | `MESSAGE_REQUEST` / `MESSAGE_RESPONSE` | 通用控制消息（含服务端下发 `NAT_CONTROL` 配置） |
| HTTP | `HTTP_REQUEST` / `HTTP_RESPONSE` | 服务端代客户端发起 HTTP 同步请求（用于将客户端作为 HTTP "前置代理"） |
| HTTP 直转 | `DIRECT_HTTP_REQUEST` / `DIRECT_HTTP_RESPONSE` | 公网 HTTP 入口 → 客户端目标服务（`HttpTunnelController` 主路径） |
| NAT | `NAT_REGISTER` / `NAT_REGISTER_RESULT` / `NAT_UNREGISTER` | 客户端注册/反注册一组端口映射 |
| NAT | `NAT_CONNECT_ESTABLISHED` / `NAT_DISCONNECT` | 公网连接到达 / 断开通知，触发客户端建立/销毁 LocalTunnel |
| NAT | `NAT_DATA` / `NAT_KEEPALIVE` | 真实字节流转发与保活（`NatMessageType` 区分子类型） |

### 4.4 握手与会话

```
client                                  server
  │  TCP/TLS handshake                     │
  │ ─────────────────────────────────────► │
  │  LoginRequestPacket                    │
  │   { clientName, password=HMAC(pw)·     │
  │     nonce, timestamp }                 │
  │ ─────────────────────────────────────► │
  │                  ┌─────────────────────┤  (a) 服务端按 clientName 查 ClientAccount
  │                  │  ManagedLoginRequest│  (b) 时间戳 ±30s 校验
  │                  │  Handler            │  (c) HMAC-SHA256 校验：key = SHA-256(plainPwd) hex
  │                  │                     │  (d) 频率限制（默认 30/min）
  │                  │                     │  (e) 写 ConnectionRecord（成功/失败原因）
  │                  └─────────────────────┤
  │  LoginResponsePacket(success/reason)   │
  │ ◄───────────────────────────────────── │
  │                                        │
  │  服务端如登录成功 → 推送启用映射快照    │
  │  Command.MESSAGE_REQUEST(NAT_CONTROL)  │
  │ ◄───────────────────────────────────── │
  │                                        │
  │  HeartbeatRequest（每 ~30s）            │
  │ ─────────────────────────────────────► │
  │  HeartbeatResponse                     │
  │ ◄───────────────────────────────────── │
```

登录签名（`HmacSigner`）：

- `key = lower_hex( SHA-256(plain_password) )`：与 `PasswordService` 保存到数据库中的摘要保持一致，**明文密码本身从不上线**。
- `signature = HMAC-SHA256(key, clientName | "\n" | timestamp | "\n" | nonce)`。
- `timestamp` 单位为秒，服务端允许 ±30 秒漂移；`nonce` 为单调或随机字符串。
- 当前版本**不强制持久化 nonce**，因此严格意义上是"基于时间窗的弱重放防护"。如需更强的防重放，需要扩展为窗口内 nonce 集合（见 §13）。

会话表示：`Session`（`tunnel-common`）。每条已登录的控制连接在服务端管理一个 `Session`，`SessionUtil` 提供按 `clientName` / `Channel` 双向查找。`Channel.attr` 上挂 `Attributes.SESSION` 等若干槽位（见 `Attributes`）。

## 5. Netty Pipeline

### 5.1 服务端控制连接 Pipeline（`NettyServer`）

```
[可选] SslHandler  ──►  Spliter  ──►  PacketDecoder  ──►  PacketEncoder
                                          │
                                          ▼
                  IdleStateHandler(SocketIdleStateHandler)
                                          │
                                          ▼
       ┌──────────────────────┬──────────────────────┬──────────────────────┐
       ▼                      ▼                      ▼                      ▼
ManagedLoginRequest    HeartbeatRequest    MessageRequest          NatServerHandler
Handler                Handler             Handler                 (动态附加)
       │                      │                      │
       ▼                      ▼                      ▼
LogoutRequestHandler   ServerMessageHandler    DirectHttp/HttpResponseHandler
```

要点：

- `SslHandler` 是否安装由 `TUNNEL_TLS_MODE` 决定（`disabled` / `file` / `self-signed`，见 `TlsProperties` + `TlsContextFactory`）。
- `IdleStateHandler` 配合 `HEARTBEAT_REQUEST` 实现"读空闲 → 触发心跳 / 关闭连接"。
- `NatServerHandler` 在客户端发出 `NAT_REGISTER` 之后挂入；它持有该客户端正在使用的 `tunnelId → Channel`、`connectionId → Channel` 映射，用于把公网入站 `RemoteTunnelHandler` 的字节流绑定到该客户端。
- 公网监听端口（`TcpServer`）的 pipeline 为 `RemoteTunnelHandler`，不参与控制连接帧解析，它只负责把 `ByteBuf` 包成 `NAT_DATA` 写到对应客户端的控制 Channel。

### 5.2 客户端控制连接 Pipeline（`NettyClient`）

与服务端对偶：`Spliter → PacketDecoder → PacketEncoder → SocketIdleStateHandler → AuthHandler → MessageRequestHandler/HeartbeatResponseHandler/...`。客户端额外有：

- `NatClientHandler`：收到 `NAT_REGISTER_RESULT` / `NAT_CONNECT_ESTABLISHED` 后挂入；每个建立的 NAT 连接维护一条到本地 `LocalTunnelHandler` 的下游 socket。
- `LocalTunnelHandler`：连本地真实业务，把回程字节流再经 `NatClientHandler → 控制连接 → 服务端 RemoteTunnelHandler` 写回公网访问者。
- `DirectHttpResponseHandler`：把客户端本地发起的 HTTP 响应（来自 `tunnel-client` 的 `HttpRequestExecutor` 或 Go 的 `http.go`）打包成 `DIRECT_HTTP_RESPONSE` 回传。

## 6. 数据流

### 6.1 NAT TCP 转发

```
公网访问者
   │  1. 连接到服务端公网映射端口 (TcpServer)
   ▼
RemoteTunnelHandler
   │  2. channelActive：申请 connectionId，写一条 NAT_CONNECT_ESTABLISHED
   │     给目标客户端的控制 Channel
   ▼
NatServerHandler (服务端侧)
   │  3. 通过控制连接发出 NAT_CONNECT_ESTABLISHED(tunnelId, connId)
   ▼
NatClientHandler (客户端侧)
   │  4. 按 tunnelId 取出本地 (target_addr, target_port)，
   │     建立 LocalTunnelHandler 连接
   ▼
LocalTunnelHandler ──► 内网目标 TCP 服务

数据帧：
公网字节 → NAT_DATA(connId, payload) → 控制连接 → NatClientHandler → LocalTunnelHandler → 内网
内网字节 → LocalTunnelHandler → NAT_DATA(connId, payload) → 控制连接 → NatServerHandler → RemoteTunnelHandler → 公网

断开：
任一侧 channelInactive → 发 NAT_DISCONNECT(connId) → 对端关闭对应下游连接
```

设计要点：

- **连接 ID 而非 tunnel ID 寻路**：每条公网入站连接在服务端分配一个全局唯一 `connectionId`，避免同一映射上多并发流量错路由。
- **背压**：使用 Netty `ChannelBackpressure`（`AUTO_READ` 模式），对端不可写时关闭本端 `autoRead`，恢复后再打开，避免内存堆积。
- **保活**：长时间无流量时由 `NAT_KEEPALIVE` 维持中间链路，避免 NAT 设备清理表项。

### 6.2 HTTP 直转（`HttpTunnelController` + `DirectHttpResponseHandler`）

```
GET /http/{clientName}/{route}/api/foo?x=1   (公网 HTTP 8088)
         │
         ▼
HttpTunnelController
  - 校验 client 在线、route 在 client 配置白名单内
  - 构造 DirectHttpRequestPacket(reqId, method, path, headers, body)
  - 通过 DirectHttpFutureManager 注册一个 SyncFuture<DirectHttpResponsePacket>
  - 发送到客户端控制 Channel
         │
         ▼ (客户端)
client 解码 → 调用本地 HTTP 客户端访问 targetBaseUrl + path → 把响应封装成 DIRECT_HTTP_RESPONSE 回传
         │
         ▼
DirectHttpResponseHandler
  - 通过 reqId 找到 SyncFuture，写入响应
HttpTunnelController
  - 等待 future（默认超时 30s，TUNNEL_HTTP_TIMEOUT_MS）
  - 把状态码、头、body 写回访问者
```

约束：

- **请求体大小**：默认 16 MiB（`TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE`），超过返回 413。
- **超时**：30s（`TUNNEL_HTTP_TIMEOUT_MS`），超时触发清理 `SyncFuture`。
- **白名单**：客户端配置 `httpTunnelConfigList[].route`，未注册的 route 返回 404；关键安全边界。

## 7. 安全模型

### 7.1 控制连接加密（`TlsProperties` / `TlsContextFactory`）

| 模式 | 行为 |
| --- | --- |
| `disabled`（默认） | 明文 TCP，向后兼容 |
| `file` | 加载 JKS / PKCS12 keystore 签发服务端证书，生产推荐 |
| `self-signed` | 启动时一次性生成自签名证书，仅供开发/测试 |

**当前限制**：Java 客户端入口 `TunnelClientApplication` 默认按明文连接；启用 TLS 需要显式调用 `NettyClient.buildClientSslContext(...)` 并以带 `SslContext` 的构造函数启动。Go 客户端同理需要在控制连接上显式启用 TLS。这是已知 gap（见 §13）。

### 7.2 客户端到服务端：HMAC 登录

详见 §4.4。要点：

- 数据库存储 SHA-256(明文)，同时作为 HMAC 密钥；明文密码仅在创建/重置时一次性向管理员展示。
- 时间戳 ±30s 滑动窗，nonce 当前不持久化。
- 频率限制按 `client` 维度：默认每分钟 30 次（含成功与失败），`0` = 不限。

### 7.3 管理后台：双登录通道

`SecurityConfig` 配置 `OAuth2 Resource Server`，对 `/api/admin/**` 校验 Bearer JWT，按 JWT header 的 `alg` 自动路由：

| 方式 | 算法 | 校验路径 |
| --- | --- | --- |
| 用户名/密码（`/auth/login`） | HS256 | `LocalTokenService` 用本地 `TUNNEL_AUTH_JWT_SECRET`（留空时启动随机生成）签发与校验 |
| OIDC Authorization Code + PKCE | RS256 | 通过 `TUNNEL_OIDC_JWK_SET_URI` JWKS 远程验签 |

公开路径白名单：`/`, `/index.html`, 静态资源, `/auth/login`, `/oidc/**`, `/http/**`, `/actuator/health`。

`/http/**` 故意不需要管理 token——它是面向公网的业务流量入口，仅靠"客户端配置中的 route 白名单"控制可见性。

### 7.4 威胁模型与边界

- **可信**：服务端进程本身、数据库、管理员浏览器（在 OIDC/密码登录之后）。
- **半可信**：客户端进程（密码丢失即等于身份丢失，故密码以摘要存储且支持重置）。
- **不可信**：公网访问者、`/http/**` 调用方、未经 NAT_CONTROL 注册的端口请求。
- **未覆盖**：传输层在 `disabled` 模式下不防止 MITM；nonce 未持久化时存在重放窗口（30s 内可重放同一签名）。

## 8. 持久化设计

### 8.1 ER 简图

```
ClientAccount (1) ─── (N) TunnelMapping
       │
       ├─── (N) ConnectionRecord  ── 滚动 60 天
       │              │
       │              └── 月度汇总到 ConnectionStat (长期保留)
       │
       └─── (N) TrafficUsage  (按 clientName + UTC 日期聚合)
```

### 8.2 关键实体

- **`ClientAccount`**：`clientId`（外部短码）、`clientName`、`passwordHash`（hex SHA-256）、`enabled`、`connectionRateLimitPerMinute`（默认 30）、`createdAt`、`updatedAt`。
- **`TunnelMapping`**：`clientId`、`listenPort`、`targetAddress`、`targetPort`、`enabled`、时间戳。
- **`ConnectionRecord`**：连接尝试明细，含成功/失败原因、源 IP、登录耗时、字节计数。**滚动 60 天**保留。
- **`ConnectionStat`**：月度汇总 (`yearMonth`, `clientName`, `successCount`, `failureCount`, `totalCount`)，长期保留。
- **`TrafficUsage`**：按 `(clientName, utcDate)` 聚合的上下行字节数，`TrafficUsageService` 在内存中累加并周期性 flush。

### 8.3 数据库支持矩阵

| DB | 驱动 | Dialect | 备注 |
| --- | --- | --- | --- |
| SQLite | `org.sqlite.JDBC` | `org.hibernate.community.dialect.SQLiteDialect` | 默认；适合演示与单机部署 |
| MySQL | `com.mysql.cj.jdbc.Driver` | `org.hibernate.dialect.MySQLDialect` | 通过 `TUNNEL_DB_*` 切换 |
| PostgreSQL | `org.postgresql.Driver` | `org.hibernate.dialect.PostgreSQLDialect` | 同上 |

`DatabaseInitializer` 提供幂等初始化与可选的种子数据（`TUNNEL_DB_SEED_DEMO_CLIENT=true` 时插入 `Demo client / test1234`）。

### 8.4 索引与查询

- `ConnectionRecord (clientName, occurredAt)` 复合索引：用于按客户端的时间范围明细查询与归档扫描。
- `TrafficUsage (clientName, usageDate)` 唯一约束 + 复合索引。
- 控制路径上**不**对热点表做联表，避免 Hibernate 多次 N+1。

## 9. 并发与线程模型（`ServerExecutorConfig`）

| 池 | 用途 | 默认 |
| --- | --- | --- |
| Netty boss | 接受新连接 | 1 线程 |
| Netty worker | I/O 多路复用 | CPU 数 × 2 |
| `loginExecutor` | 处理登录中的密码校验、写连接记录 | 有界（避免登录风暴打满 worker） |
| `trafficFlushScheduler` | 定时把 `TrafficUsage` 内存累计 flush 到 DB | `TUNNEL_TRAFFIC_FLUSH_INTERVAL_MS` |
| `connectionArchiveScheduler` | 月度归档 + 删除老明细 | `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS`（默认 1h） |
| Spring MVC | `/api/admin/**`、`/auth/**`、`/http/**` | Tomcat 默认 |

线程交接关键点：

1. **登录**：worker 收到 `LOGIN_REQUEST` → 提交到 `loginExecutor` → DB 校验 → 回到 Channel 的 EventLoop 写 `LoginResponse`。所有写回 Channel 的动作必须切回该 Channel 的 EventLoop。
2. **HTTP 直转等待**：`HttpTunnelController.handle()` 在 Tomcat 线程上 `SyncFuture.get(timeout)`，由 worker 线程的 `DirectHttpResponseHandler.complete()` 唤醒。
3. **NAT 数据帧**：`RemoteTunnelHandler` 与控制连接在不同 worker 上，写控制连接时会跨 EventLoop 调度。

## 10. 重连与空闲

### 10.1 客户端重连

`NettyClient` 在 `channelInactive` 后启动指数退避重连：初始 1 秒，倍增至上限（典型 30 秒），上限后保持周期重试。Go 客户端使用同样的退避策略（`client.go`）。重连成功后会重新走完整的登录 + 等待 `NAT_CONTROL` 流程，确保映射状态一致。

### 10.2 空闲检测

`SocketIdleStateHandler` 配合心跳：

- 客户端：写空闲达到阈值 → 主动发 `HEARTBEAT_REQUEST`。
- 服务端：读空闲超过 N 倍心跳间隔 → 关闭连接，触发资源清理（`SessionUtil.unbind`、关闭对应所有 NAT 下游连接）。

## 11. 配置矩阵（环境变量）

| 类别 | 变量 | 默认 |
| --- | --- | --- |
| 端口 | `TUNNEL_NETTY_PORT` | `7010` |
| 端口 | `server.port` (Spring Boot) | `8088` |
| 公网地址 | `TUNNEL_PUBLIC_ADDRESS` | (空，用于管理页展示) |
| DB | `TUNNEL_DB_URL` / `_DRIVER` / `_DIALECT` / `_USERNAME` / `_PASSWORD` / `_POOL_SIZE` / `_BATCH_SIZE` / `_SEED_DEMO_CLIENT` | SQLite 默认 |
| 流量 | `TUNNEL_TRAFFIC_FLUSH_INTERVAL_MS` | 视实现 |
| 归档 | `TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` | `60` |
| 归档 | `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` | `3600000` |
| HTTP | `TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE` | `16 MiB` |
| HTTP | `TUNNEL_HTTP_TIMEOUT_MS` | `30000` |
| 鉴权 | `TUNNEL_AUTH_USERNAME` / `_PASSWORD` / `_PASSWORD_LOGIN_ENABLED` / `_JWT_SECRET` / `_TOKEN_TTL_SECONDS` | `admin` / `admin` / `true` / 启动随机 / `28800` |
| OIDC | `TUNNEL_OIDC_*`（CLIENT_ID, REDIRECT_URI, SCOPE, AUDIENCE, ISSUER, JWK_SET_URI, AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, END_SESSION_ENDPOINT, CLIENT_SECRET）| 默认指向项目网关 |
| TLS | `TUNNEL_TLS_MODE` / `_KEYSTORE` / `_KEYSTORE_PASSWORD` / `_KEY_PASSWORD` | `disabled` |

## 12. 关键流程时序

### 12.1 登录 + 自动下发映射

```
client                     server                       DB
  │ TCP/TLS connect            │                          │
  │ ─────────────────────────► │                          │
  │ LOGIN_REQUEST              │                          │
  │ ─────────────────────────► │ findByClientName ───────►│
  │                            │ ◄─────────────── account │
  │                            │ verify HMAC + ts window  │
  │                            │ rate-limit check         │
  │                            │ insert ConnectionRecord ─►
  │ LOGIN_RESPONSE(success)    │                          │
  │ ◄───────────────────────── │                          │
  │ MESSAGE_REQUEST(NAT_CONTROL│                          │
  │   = mappings snapshot)     │ findEnabledMappings ────►│
  │ ◄───────────────────────── │                          │
  │ NAT_REGISTER (ack)         │                          │
  │ ─────────────────────────► │                          │
  │ NAT_REGISTER_RESULT        │ start TcpServer per port │
  │ ◄───────────────────────── │                          │
```

### 12.2 管理员新增映射 → 实时下发

```
Admin UI               AdminController        ClientManagementService    NatControlService    Online client
  │  POST /tunnels        │                        │                          │                       │
  │ ────────────────────► │                        │                          │                       │
  │                       │ validate, persist ────►│ saveTunnelMapping        │                       │
  │                       │                        │ publish snapshot ───────►│                       │
  │                       │                        │                          │ findChannelByClient   │
  │                       │                        │                          │ writeAndFlush ───────►│
  │                       │                        │                          │   MESSAGE_REQUEST(NAT │
  │                       │                        │                          │   _CONTROL=snapshot)  │
  │                       │                        │                          │                       │ register
  │                       │                        │                          │ ◄──────────────────── ack
  │ 200 OK                │                        │                          │                       │
  │ ◄──────────────────── │                        │                          │                       │
```

客户端离线时不会立即推送，下次登录会自动重新发送完整启用映射快照（**最终一致**）。手动调用 `POST /api/admin/clients/{id}/nat-control` 在客户端离线时返回 `409`。

## 13. 已知 gap 与演进路线

- **TLS 客户端默认不开**：Java 客户端入口 `TunnelClientApplication` 仍以明文连接为默认，需把 TLS 抬到 `tunnelClientConfig.json` 字段（如 `tls: { enabled, trustStorePath, trustStorePassword, insecureSkipVerify }`），Go 客户端同步暴露相同字段。
- **登录 nonce 未持久化**：当前在 30s 窗口内可重放同一签名。建议在 `loginExecutor` 处加内存 LRU（按 `clientName`），并在多节点部署时升级到共享存储（Redis）。
- **UDP 转发缺失**：`UdpConnection` 留空。如要补齐，需要在协议层新增 `NAT_UDP_*` 命令，并在服务端为每个 UDP 映射启动 `DatagramChannel`，按 `(srcAddr, srcPort)` 分配 connectionId。
- **测试覆盖**：核心协议有单元测试，但缺少真实 MySQL/PostgreSQL 集成测试和端到端隧道测试。`tools/` 下已有 load test 辅助。
- **服务端水平扩展**：当前 `Session` 与 `NatServerHandler` 状态都在 JVM 内存。若要多节点：客户端 → 节点之间需要绑定（一致性哈希或粘性路由），公网入站连接也必须落到客户端实际所在节点。详细方案见 `docs/single-node-10k-connections-optimization-plan.md` 与 P2P 研究文档。
- **同端口冲突**：`server.port=8088` 与 `tunnel-client` 默认相同，单机同时跑要覆盖其中一个。
- **协议演进**：`magic` 与 `version` 已预留；新增命令时建议保留向后兼容（旧版本未识别的 `cmd` 应当忽略而非断链），目前未实现该容忍逻辑。

## 14. 参考源码索引

| 主题 | 入口 |
| --- | --- |
| 服务端启动 | `implementations/java/server/.../TunnelServerApplication.java` |
| Netty 服务 | `implementations/java/server/.../server/NettyServer.java`、`server/TcpServer.java`、`server/RemotePortServerManager.java` |
| 公网入站 | `implementations/java/server/.../handler/RemoteTunnelHandler.java` |
| 控制连接 | `implementations/java/server/.../handler/NatServerHandler.java`、`handler/ManagedLoginRequestHandler.java` |
| 管理 REST | `implementations/java/server/.../management/controller/{Admin,Auth,Oidc}Controller.java` |
| 管理服务 | `implementations/java/server/.../management/service/{ClientManagement,NatControl,TrafficUsage,ConnectionArchive}Service.java` |
| 安全 | `implementations/java/server/.../security/{LocalTokenService,PasswordService,TlsContextFactory,TlsProperties}.java` |
| HTTP 直转 | `implementations/java/server/.../http/HttpTunnelController.java` |
| 协议核心 | `implementations/java/common/.../protocol/{PacketCodec,Packet,NatMessagePacket,NatMessageType,MessageType}.java` |
| 编解码 | `implementations/java/common/.../codec/{Spliter,PacketDecoder,PacketEncoder,PacketCodecHandler}.java` |
| 命令枚举 | `implementations/java/common/.../command/Command.java` |
| 序列化 | `implementations/java/common/.../serialize/**` |
| HMAC | `implementations/java/common/.../security/HmacSigner.java` |
| Java 客户端 | `implementations/java/client/.../client/{NettyClient,LocalTunnelHandler,UdpConnection}.java` |
| Go 客户端 | `implementations/go/client/internal/client/{client,nat,http,config}.go`、`internal/protocol/protocol.go` |

---

> 本设计文档与 README 互为补充：README 面向"如何运行"，本文档面向"为什么这样设计、关键路径在哪条文件里、改动时该警惕什么"。修改协议、登录、TLS 或归档逻辑时，请同步更新本文档相关章节。
