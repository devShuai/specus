# shuai-tunnel 详细设计文档

> 基线：2026-07-10，提交 `93823f4`。本文以 Java server/client/common 当前实现为准；跨语言线协议以 `protocol/spec/` 为权威入口。
> README 面向运行与部署，本文聚焦模块边界、关键数据流、线程与安全模型。

## 1. 目标与边界

`shuai-tunnel` 是以内网服务接入和私有组网为核心的多语言项目，Java 是当前参考实现。主要目标是：

1. 通过一条长期控制连接承载登录、心跳、配置下发、TCP 隧道和 HTTP 直转。
2. 使用管理面维护客户端凭证、账号、TCP 映射、HTTP 路由、连接记录和流量观测。
3. 让同一租户和用户下的客户端通过 Peer Mesh 虚拟 IP 互访，优先 UDP direct，失败时回退标准 TURN relay。
4. 默认以单节点、SQLite 和明文控制连接低门槛启动，同时提供 MySQL/PostgreSQL、TLS、OIDC、Elasticsearch 等升级路径。

当前边界：

- 公网 TCP 映射、HTTP/WS 直转和 Peer Mesh UDP 数据面已经实现。
- 公网 UDP 端口映射尚未实现；空的 `UdpConnection` 只是该能力的占位，不代表 Peer Mesh 没有 UDP。
- 控制连接和在线路由状态仍在单个 server 进程内；多节点需要粘性路由或共享会话/路由层。

## 2. 顶层架构

```text
                         管理 JWT / 客户端 HTTP HMAC 登录
管理后台、客户端启动器 ─────────────────────────────────────► Spring Boot :8088
                                                              │
公网 HTTP / WebSocket ───────► /http/{client}/{route}/**       │
                                                              ▼
公网 TCP ─► 动态 TcpServer ─► RemoteTunnelHandler ◄──────► Netty control :7010 ◄────► Java client
                                                              │                         │
                                                              │                         ├─► 内网 TCP
                                                              │                         └─► 内网 HTTP/WS
                                                              │
                                                              └─► STUN/TURN :3478/:3479 + relay 端口
                                                                                 ▲
Peer A 虚拟网卡 ◄──────── 加密 UDP direct / TURN relay ────────┴────────► Peer B 虚拟网卡
```

关键入口分为四类：

- **客户端启动登录**：`POST /api/client/auth/login`，用 `apiKey/secret` HMAC 换取短期运行时 token、控制端地址和配置快照。
- **控制连接**：默认 `7010/TCP`，可选 TLS；承载运行时 token 登录、心跳、`NAT_CONTROL`、`PEER_CONTROL`、`DIRECT_HTTP_*` 和 `NAT_MESSAGE`。
- **公网业务入口**：每个已注册 TCP `listenPort` 一个动态监听；HTTP/WS 使用 `/http/**`。
- **Peer Mesh 数据面**：标准 STUN/TURN 和客户端间 UDP direct；业务 IP 包端到端加密，relay 不解密业务明文。

## 3. Java 模块

| 模块 | 路径 | 主要职责 |
| --- | --- | --- |
| `tunnel-common` | `implementations/java/common` | 线协议、帧编解码、固定 schema 紧凑二进制、HMAC、心跳、NAT/Peer 公共模型 |
| `tunnel-server` | `implementations/java/server` | Netty 控制端与公网 TCP 监听、管理 REST、客户端认证、HTTP/WS 直转、Peer Mesh、持久化与观测 |
| `tunnel-client` | `implementations/java/client` | 读取 `client.jsonc`、HTTP 启动登录、控制连接与重连、本地 TCP/HTTP/WS 转发、Peer Mesh 虚拟网卡 |
| 管理前端 | `apps/admin-web` | 管理客户端、凭证、映射、路由、连接、流量和 Peer Mesh；构建产物由 server 静态托管 |

Java 的协议变更需要同步 `protocol/spec/`、测试向量和其它语言实现。

## 4. 控制协议

### 4.1 帧格式与大小边界

普通控制帧使用 11 字节固定头：

```text
+----------+---------+---------------+---------+------------+-----------------+
| magic 4B | ver 1B  | serializer 1B | cmd 1B  | length 4B  | body length bytes|
+----------+---------+---------------+---------+------------+-----------------+
0          4         5               6         7            11
```

- `magic = 0x14353565`，`version = 1`。
- `length` 是 body 长度；`Spliter` 基于 `LengthFieldBasedFrameDecoder` 处理半包和粘包。
- `Spliter` 默认最大**整帧**为 `32 MiB`。Java server 可用 `TUNNEL_NETTY_MAX_FRAME_SIZE` 覆盖；Java client 当前使用默认值。
- `CompactBinarySerializer` 的 `16 MiB` 是 Deflate **解压后 payload** 上限，不是整帧上限。

`NAT_MESSAGE` 仍使用同一个 11 字节帧头，但 body 是专用布局：

```text
natType(4B) + metadataLength(4B) + metadata(JSON) + optional data(compact payload)
```

因此 NAT 帧头的 serializer 标记为 FastJSON；只有 metadata 使用 JSON，隧道字节 `data` 使用紧凑 payload 的 raw/Deflate 包装。

### 4.2 序列化算法

| 线值 | 实现 | 当前用途 |
| --- | --- | --- |
| `1` | `FastJsonSerializer` | NAT metadata JSON；也作为可选普通帧 codec |
| `2` | `JacksonSerializer` | 可选普通帧 codec；Spring MVC REST 不依赖这个封装类 |
| `3` | `XML` 标记 | 仅保留常量，未注册 serializer |
| `4` | `CompactBinarySerializer` | 普通控制帧默认 codec；双方依赖相同的预注册固定 schema，并非自描述格式 |
| `5` | `ProtobufSerializer` | 已实现并有测试，但不在默认主路径 |

紧凑二进制省略字段名，按固定字段顺序编码，使用变长整数和短类型 codec。payload 首字节只表示 raw 或 Deflate；原始数据至少 `64 B` 且压缩后更小时才使用 Deflate。

### 4.3 三层消息类型

第一层是帧头 `Command`：

| Command | 值 | 说明 |
| --- | ---: | --- |
| `LOGIN_REQUEST` / `LOGIN_RESPONSE` | `1` / `-1` | 控制连接 token 登录 |
| `MESSAGE_REQUEST` / `MESSAGE_RESPONSE` | `2` / `-2` | 通用控制消息 |
| `LOGOUT_REQUEST` / `LOGOUT_RESPONSE` | `3` / `-3` | 主动离线 |
| `HEARTBEAT_REQUEST` / `HEARTBEAT_RESPONSE` | `4` / `-4` | 心跳 |
| `HTTP_REQUEST` / `HTTP_RESPONSE` | `5` / `-5` | 保留的同步 HTTP 协议类型；当前公网主路径不使用 |
| `NAT_MESSAGE` | `6` | NAT/WS 隧道统一承载帧 |
| `DIRECT_HTTP_REQUEST` / `DIRECT_HTTP_RESPONSE` | `7` / `-7` | 当前公网 HTTP 直转主路径 |

第二层是 `MESSAGE_*` 内的 `MessageType`：

- `SERVER_TO_CLIENT`
- `CLIENT_TO_SERVER`
- `CLIENT_TO_CLIENT`
- `NAT_CONTROL`：TCP 映射与 HTTP 路由权威快照
- `PEER_CONTROL`：Peer Mesh 设备、候选地址、探测和 session 信令

第三层是 `NAT_MESSAGE` 内的 `NatMessageType`：

- `REGISTER`、`REGISTER_RESULT`、`UNREGISTER`
- `CONNECTED`、`DISCONNECTED`、`DATA`、`KEEPALIVE`
- `HTTP_ROUTES_REPORT`：为旧客户端保留的线值；当前 Java server 收到后直接忽略

### 4.4 两阶段客户端认证

客户端认证不是在 Netty `LOGIN_REQUEST` 中直接发送密码 HMAC，而是分两步：

1. **HTTP 启动登录**
   - 客户端读取工作目录中的 `client.jsonc`，收集 `machineFingerprint`、`osUser` 等环境信息。
   - canonical message 为 `apiKey + "\n" + timestamp + "\n" + nonce + "\n" + machineFingerprint + "\n" + osUser`。
   - `key = SHA-256(secret)`，签名为 HMAC-SHA256；`timestamp` 单位是毫秒。
   - server 从 `ClientCredential.secretHash` 还原 HMAC key，校验签名和 `±60s` 时间窗，创建/复用 `ClientIdentity` 与 `ClientAccount`，再创建 `ClientSession`。
   - 响应包含 `clientName`、`clientSessionId`、明文 `accessToken`、token TTL、Netty 地址、TCP/HTTP 快照和 Peer Mesh 配置；数据库只保存 token hash。
2. **Netty 控制连接登录**
   - `LoginRequestPacket` 发送 `clientName`、`clientSessionId` 和 `accessToken`。
   - server 只保存 token 的 SHA-256，验证 session 未过期、账号/凭证启用、连接频率和在线实例上限。
   - 成功后绑定 `clientName → Channel`，写连接记录，并异步推送 `NAT_CONTROL` 与 `PEER_CONTROL`。

secret 明文不会发送到 server；数据库保存其 SHA-256。当前没有 nonce 去重存储，因此同一 HTTP 登录请求在 60 秒窗口内仍可能被重放，时间窗只是弱重放缓解。

## 5. Netty Pipeline

### 5.1 Server 控制连接

实际初始化顺序：

```text
[SslHandler]
→ SocketIdleStateHandler
→ Spliter(maxFrameSize)
→ PacketCodecHandler
→ ManagedLoginRequestHandler
→ AuthHandler
→ HeartbeatRequestHandler
→ NatServerHandler
→ DirectHttpResponseHandler
→ ServerMessageHandler
→ LogoutRequestHandler
```

- `SslHandler` 只在 `TUNNEL_TLS_MODE != disabled` 时安装。
- `ManagedLoginRequestHandler` 把 DB/token 校验提交到有界 `loginExecutor`，涉及 Channel 的绑定和回包再切回该 Channel 的 EventLoop。
- `NatServerHandler` 从连接建立时就存在；它用 `REGISTER` 成功状态约束普通 TCP `DATA/DISCONNECTED`，并不是注册后才动态挂载。
- `PacketCodecHandler` 在 server 同时承担 decode/encode；不是两个独立的 `PacketDecoder`/`PacketEncoder`。

### 5.2 Java client 控制连接

初始顺序：

```text
[SslHandler]
→ ClientSocketIdleStateHandler
→ Spliter
→ PacketDecoder
→ LoginResponseHandler
→ MessageResponseHandler
→ DirectHttpRequestHandler
→ LogoutResponseHandler
→ PacketEncoder
```

收到首个 `NAT_CONTROL` 后，`MessageResponseHandler` 动态追加 `NatClientHandler`；handler 添加到已激活 Channel 时立即注册当前 TCP 映射并上报 HTTP routes。后续完整快照通过 `applyConfig`/`applyRoutes` 热替换。

客户端没有独立的 `AuthHandler` 或 `HeartbeatResponseHandler`。`DirectHttpRequestHandler` 接收 server 请求并回写 `DIRECT_HTTP_RESPONSE`；`DirectHttpResponseHandler` 位于 server。

## 6. 数据流

### 6.1 TCP NAT

注册阶段：

```text
server NAT_CONTROL 完整快照
  → client MessageResponseHandler
  → NatClientHandler REGISTER(port, tunnelAddress, tunnelPort, clientName)
  → server NatServerHandler 校验登录身份和全局端口占用
  → RemotePortServerManager.bind(port)
  → REGISTER_RESULT
```

转发阶段使用 `port` 标识映射、使用 Netty `channelId` 标识一条公网连接：

```text
公网连接 channelActive
  → CONNECTED {port, channelId}
  → client 按 port 找目标并建立本地 TCP Channel

公网字节
  → DATA {channelId} + payload
  → client LocalTunnelHandler
  → 内网服务

内网回包
  → DATA {channelId} + payload
  → server externalChannels[channelId]
  → 公网连接
```

任一侧断开都发送 `DISCONNECTED {channelId}`。控制 Channel 与公网/本地 Channel 之间通过 `ChannelBackpressure` 联动 `AUTO_READ`，避免不可写时无限积压。`listenPort` 是整台 server 的全局资源，不能跨租户复用。

### 6.2 HTTP 与 WebSocket 直转

HTTP 主路径：

```text
/http/{clientName}/{route}/**
  → HttpTunnelController 构造 DirectHttpRequestPacket
  → DirectHttpDispatcher 注册 SyncFuture、写控制 Channel 并等待
  → client DirectHttpRequestHandler 在线程池执行 DirectHttpForwarder
  → 按 route 精确查 targetBaseUrl，转发 method/path/query/headers/body
  → DIRECT_HTTP_RESPONSE
  → server DirectHttpResponseHandler → DirectHttpDispatcher.ack
  → Controller 返回状态码、headers 和 body
```

当前边界：

- server 请求体默认上限 `16 MiB`，等待默认 `30s`；离线返回 `503`，等待超时返回 `504`。
- client 也把请求体本地读取限制为 `16 MiB`、响应体本地读取限制为 `64 MiB`，并把单段 Range 控制在
  `8 MiB`；但 Direct HTTP 仍封装成单个控制帧，实际端到端能力还受默认 `32 MiB` 整帧和 deflate 后
  `16 MiB` 解压上限约束。因此 `64 MiB` 不是可保证传输的响应上限，稳定使用应把完整序列化 payload
  控制在 `16 MiB` 以下并预留字段开销。
- route 不存在时由 client 拒绝，当前响应是 `502` 和“未配置 HTTP route”，不是 controller 预先返回 `404`。
- client 校验 target scheme 为 HTTP/HTTPS、目标 origin 不变，且相对路径不能逃逸 base path。
- HTTP 路由开启路径改写后，server 可改写可识别响应中的绝对路径；默认单体上限 `10 MiB`。

WebSocket 升级同样挂在 `/http/**`，由 `WebSocketTunnelHandler` 建立 stream，并复用 `NAT_MESSAGE` 的 `CONNECTED/DATA/DISCONNECTED`，metadata 中以 `source="ws"` 和 `channelId` 区分。

### 6.3 Peer Mesh

Peer Mesh 默认关闭。启用后：

- `PeerMeshService` 分配 `100.96.0.0/11` 虚拟 IP，并按租户、owner 和 ACL 选择可见对端。
- `PeerSignalService` 通过 `PEER_CONTROL` 交换设备、候选地址和 session 授权。
- Java client 支持 Linux TUN、Windows Wintun、macOS utun 和 `noop`；`auto` 按当前系统选择。
- 客户端通过 STUN、UPnP/NAT-PMP/PCP 和候选探测尝试 UDP direct；direct 不健康时回退 TURN relay。
- Peer 数据帧使用 X25519/HKDF 派生密钥和 AES-GCM；server relay 只处理授权与外层帧。

## 7. 安全模型

### 7.1 控制连接 TLS

| 模式 | 行为 |
| --- | --- |
| `disabled`（默认） | 明文 TCP，兼容旧部署 |
| `file` | 从 JKS/PKCS12 keystore 加载 server 证书 |
| `self-signed` | 启动时生成临时自签名证书，仅用于开发/测试 |

Java client 入口默认仍以明文连接；启用 TLS 需要构造 `SslContext` 并使用 `NettyClient(TunnelBean, SslContext)`。`buildClientSslContext` 加载 truststore，`buildInsecureClientSslContext` 仅供测试。

### 7.2 客户端与管理面鉴权

- 客户端 HTTP 登录使用 `ClientCredential` 的 apiKey/secret HMAC；Netty 控制连接只使用 `ClientSession` runtime token。
- client token 默认 TTL 为 `28800s`。Java client 会在到期前主动重新执行 HTTP 登录；收到“访问令牌已过期”也会刷新后重连。
- 控制连接频率限制按 `ClientAccount` 统计最近一分钟连接记录，默认 `30/min`，`0` 表示不限。
- 管理本地登录由 `/auth/login` 签发 HS256 JWT；OIDC token 通过 JWKS 验签。`SecurityConfig` 根据 JWT 算法路由 decoder。

### 7.3 HTTP 安全边界

Spring Security 当前只要求 `/api/admin/**` 与 `/auth/refresh` 必须携带认证；`/api/public/**`、`/ws/**` 和其它请求在 filter chain 层 permitAll。`/ws/**` 中需要保护的端点由握手拦截器单独校验 JWT。

`/http/**` 是有意公开的业务入口，不要求管理 JWT。它的访问边界是在线客户端和该客户端当前生效的 route；公网 TCP 入口则受已登录客户端成功 `REGISTER` 的端口集合约束。

## 8. 持久化

### 8.1 客户端身份与运行时会话

```text
ClientCredential
  └─ ClientIdentity (credential + machineFingerprint + osUser)
       └─ ClientAccount
            ├─ ClientSession
            ├─ TunnelMapping
            ├─ HttpRouteMapping
            ├─ ConnectionRecord ──► ConnectionStat（月度归档）
            ├─ TrafficUsage / ResourceTrafficUsage
            └─ PeerMeshDevice / PeerMeshSession / PeerMeshAcl
```

- **`ClientCredential`**：`apiKey`、`secretHash`、启用状态和最大在线实例数；启动 secret 的权威存储。
- **`ClientIdentity`**：把凭证与 `machineFingerprint + osUser` 绑定到一个账号。
- **`ClientAccount`**：Long `id`、tenant、owner、`clientName`、启用状态和频率限制。遗留 `passwordHash` 字段仍在表中，但当前 HTTP/Netty 登录不使用它。
- **`ClientSession`**：只保存 runtime token hash，并记录 HTTP 已认证、Netty 在线、断开、环境和过期时间。

### 8.2 路由、连接与流量

- **`TunnelMapping`**：全局唯一 `listen_port`、目标地址/端口、启用状态和明细采集开关。
- **`HttpRouteMapping`**：`(client_id, route)` 唯一，保存 target base URL、启用、明细采集和路径改写开关。
- **`ConnectionRecord`**：client、channel、remote address、连接/断开时间、成功状态、失败原因和断开原因；不保存登录耗时或流量字节。
- **`ConnectionStat`**：按 tenant、clientName、自然月累加 total/success/failure，长期保留。
- **`TrafficUsage`**：按 `(client_id, usage_date)` 聚合上下行字节。
- **`ResourceTrafficUsage`**：按 tenant、client、资源类型/键和 UTC 日期聚合 TCP 映射或 HTTP route 流量。

连接记录关键索引是 `(client_id, connected_at)` 和 `connected_at`，分别服务频率限制/客户端历史与归档扫描。早于滚动保留窗口的记录按自然月汇总后，在同一事务中删除；默认保留 60 天。

HTTP/TCP 明细默认写业务数据库；配置 `TUNNEL_ELASTICSEARCH_URIS` 后切换到 Elasticsearch store。全局采集开关与每条 route/mapping 开关都必须开启才会记录明细。

### 8.3 数据库

| 数据库 | Driver | Hibernate Dialect |
| --- | --- | --- |
| SQLite（默认） | `org.sqlite.JDBC` | `org.hibernate.community.dialect.SQLiteDialect` |
| MySQL | `com.mysql.cj.jdbc.Driver` | `org.hibernate.dialect.MySQLDialect` |
| PostgreSQL | `org.postgresql.Driver` | `org.hibernate.dialect.PostgreSQLDialect` |

`DatabaseInitializer` 负责旧库 tenant/owner 和 HTTP body 字段回填，并可用 `TUNNEL_DB_SEED_DEMO_CLIENT` 控制 `Demo client` 与 `demo-client/test1234` 演示凭证种子。

## 9. 并发与线程模型

| 执行单元 | 当前行为 |
| --- | --- |
| Netty control boss | 默认 1 线程 |
| Netty control worker | `0` 表示使用 Netty 默认线程数 |
| 公网 TCP boss/worker | 与 control 分离；默认 boss 1、worker 使用 Netty 默认 |
| `loginExecutor` | 有界池，默认 core 8、max 32、queue 20000；执行 token 鉴权、连接记录和登录后配置推送 |
| Spring scheduler | 默认 pool size 2；执行流量 flush、连接归档、Peer/附件清理等定时任务 |
| HTTP 直转 | Tomcat 线程在 `DirectHttpDispatcher.forward` 中等待 `SyncFuture`；Netty worker 收到响应后唤醒 |
| client HTTP worker | `DirectHttpRequestHandler` 提交到共享 `ExecuteService` cached thread pool，避免阻塞 control EventLoop |
| TURN relay worker | 可配置有界工作池；队列满时丢弃新 relay 数据帧保护 server |

所有 DB 和阻塞工作都应避免直接占用 Netty EventLoop。跨 Channel 写由 Netty 调度到目标 EventLoop；NAT 两端用 writability 和 `AUTO_READ` 做背压。

## 10. 重连与心跳

### 10.1 Java client 重连与 token 刷新

控制连接失败后，`NettyClient` 使用 `2s → 4s → 8s → 16s → 32s → 60s` 指数退避，之后保持 60 秒上限。只有收到成功的 `LOGIN_RESPONSE` 才重置退避计数。

普通重连复用未过期 runtime token，再走完整 Netty 登录；登录成功后 server 重新推送权威 `NAT_CONTROL`/`PEER_CONTROL`。token 快过期时 client 主动重新执行 HTTP 登录，刷新 token、session、控制端地址和配置；明确的认证/策略拒绝会停止无意义重试。

### 10.2 空闲检测

- Java client：写空闲 `5s` 发送 `HEARTBEAT_REQUEST`，读空闲 `60s` 关闭并进入重连。
- Java server：写空闲 `30s` 发送兜底 `HEARTBEAT_RESPONSE`，读空闲 `60s` 关闭并清理 session、连接记录和 NAT 资源。

## 11. 核心配置默认值

| 类别 | 配置 / 环境变量 | 默认 |
| --- | --- | --- |
| Web | `server.port` | `8088` |
| Control | `TUNNEL_NETTY_PORT` | `7010` |
| Frame | `TUNNEL_NETTY_MAX_FRAME_SIZE` | `33554432`（32 MiB） |
| DB | `TUNNEL_DB_URL` / `TUNNEL_DB_POOL_SIZE` / `TUNNEL_DB_BATCH_SIZE` | SQLite / `1` / `50` |
| Seed | `TUNNEL_DB_SEED_DEMO_CLIENT` | `true` |
| Client token | `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` |
| Traffic | `TUNNEL_TRAFFIC_FLUSH_INTERVAL_MS` | `5000` |
| Archive | `TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` / `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` | `60` / `3600000` |
| HTTP | `TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE` / `TUNNEL_HTTP_TIMEOUT_MS` | `16777216` / `30000` |
| Admin auth | `TUNNEL_AUTH_USERNAME` / `_PASSWORD` / `_TOKEN_TTL_SECONDS` | `admin` / `admin` / `28800` |
| Peer Mesh | `TUNNEL_PEER_MESH_ENABLED` / `_STUN_TURN_PORT` / `_NAT_PROBE_ALTERNATE_PORT` | `false` / `3478` / `3479` |
| TLS | `TUNNEL_TLS_MODE` | `disabled` |

完整配置以 `implementations/java/server/src/main/resources/application.yml` 和对应 `@ConfigurationProperties` 类为准。

## 12. 关键时序

### 12.1 启动登录与自动注册

```text
Java client                 Spring HTTP                 DB                 Netty server
    │ POST client/auth/login     │                       │                       │
    │ HMAC(apiKey, ms, nonce, env) ────────────────────►│                       │
    │                            │ credential/identity/account/session           │
    │ ◄── token + session + endpoints + config ─────────│                       │
    │                                                                            │
    │ TCP[/TLS] connect ────────────────────────────────────────────────────────► │
    │ LOGIN_REQUEST(clientName, sessionId, accessToken) ───────────────────────► │
    │                                            verify token/session + rate limit│
    │ ◄──────────────────────── LOGIN_RESPONSE(success) ───────────────────────── │
    │ ◄──────────────────────── MESSAGE_RESPONSE(NAT_CONTROL snapshot) ────────── │
    │ NAT_MESSAGE REGISTER(port...) ────────────────────────────────────────────► │
    │ ◄──────────────────────── NAT_MESSAGE REGISTER_RESULT ───────────────────── │
```

### 12.2 管理面热更新

```text
Admin REST mutation
  → 在事务中保存 TunnelMapping / HttpRouteMapping
  → NatControlService.pushSnapshotIfOnline
  → 在线 client 收到完整 NAT_CONTROL 权威快照
  → TCP 映射增删触发 REGISTER / UNREGISTER
  → HTTP route 原子替换 DirectHttpRequestHandler 的不可变 route map
```

客户端离线时自动推送静默跳过，下次登录重新取得完整快照；手动 `POST /api/admin/clients/{id}/nat-control` 在离线时返回 `409`。

## 13. 已知限制与后续工作

- **Java client TLS 未配置化**：入口默认明文，需要把 truststore/校验策略正式加入 `client.jsonc`。
- **HTTP 登录 nonce 未去重**：签名有 60 秒时间窗，但窗口内可重放；单节点可加有界 nonce cache，多节点需共享存储。
- **公网 UDP 映射缺失**：如要实现，需要新增协议子类型、server `DatagramChannel` 和按来源端点维护的映射；这与已实现 Peer Mesh UDP 不同。
- **E2E 覆盖有限**：已有 `EndToEndTunnelIT` 覆盖 SQLite 进程内 HTTP HMAC、Netty token、真实 TCP 隧道和 route 热更新，但 `*IT` 尚未接入 Maven Failsafe；仍缺真实 MySQL/PostgreSQL、跨进程和 TLS 矩阵。
- **水平扩展**：`SessionUtil`、`NatServerHandler` 和动态监听仍是进程内状态；需要控制/连接端拆分、粘性路由、共享状态和 drain。详见 `server-control-edge-ha-plan.md`。
- **未知协议值容忍**：`magic`/`version` 已预留，但未知 `Command`/serializer 当前不能保证被安全忽略，协议演进必须先做兼容性验证。

## 14. 源码索引

| 主题 | 当前入口 |
| --- | --- |
| Server 启动 | `implementations/java/server/src/main/java/com/theshuai/tunnelserver/TunnelServerApplication.java` |
| Control Netty | `.../server/NettyServer.java`、`.../handler/ManagedLoginRequestHandler.java`、`.../handler/AuthHandler.java` |
| Client HTTP 认证 | `.../management/controller/ClientAuthResource.java`、`.../management/service/ClientAuthService.java` |
| Client 凭证/账号 | `.../management/service/ClientCredentialService.java`、`.../management/service/ClientAccountService.java` |
| NAT server | `.../handler/NatServerHandler.java`、`.../handler/RemoteTunnelHandler.java`、`.../server/RemotePortServerManager.java` |
| HTTP/WS 直转 | `.../http/HttpTunnelController.java`、`.../http/DirectHttpDispatcher.java`、`.../http/WebSocketTunnelHandler.java` |
| Peer Mesh server | `.../management/service/PeerMeshService.java`、`.../management/service/PeerSignalService.java`、`.../peer/StunTurnServer.java` |
| 管理 REST | `.../management/controller/*Resource.java`、`.../management/controller/AuthController.java`、`.../management/controller/OidcController.java` |
| 安全 | `.../config/SecurityConfig.java`、`.../security/LocalTokenService.java`、`.../security/TlsContextFactory.java` |
| 协议核心 | `implementations/java/common/src/main/java/com/theshuai/common/protocol/*`、`.../command/Command.java` |
| 编解码 | `.../codec/Spliter.java`、`.../codec/PacketCodecHandler.java`、`.../protocol/PacketCodec.java` |
| 紧凑二进制 | `.../serialize/impl/CompactBinarySerializer.java` |
| Java client 启动/连接 | `implementations/java/client/src/main/java/com/theshuai/tunnelclient/TunnelClientApplication.java`、`.../client/NettyClient.java` |
| Java client NAT/HTTP | `.../handler/NatClientHandler.java`、`.../handler/LocalTunnelHandler.java`、`.../handler/DirectHttpRequestHandler.java` |
| Java client Peer Mesh | `.../peer/PeerMeshClient.java`、`.../peer/PeerVirtualDevices.java` |
| 进程内 E2E | `implementations/java/server/src/test/java/com/theshuai/tunnelserver/integration/EndToEndTunnelIT.java` |

---

修改协议、客户端认证、TLS、NAT/HTTP 路由、Peer Mesh 或归档逻辑时，应同时更新本文、根 README、`protocol/spec/` 和跨语言测试向量。
