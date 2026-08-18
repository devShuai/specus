# specus 详细设计文档

> 基线：2026-08-04，`main` 当前实现。本文以 Java server/client/common 为参考；跨语言线协议以 `protocol/spec/` 为权威入口。
> README 面向运行与部署，本文聚焦模块边界、关键数据流、线程与安全模型。

## 1. 目标与边界

`specus` 是以内网服务接入和私有组网为核心的多语言项目，Java 是当前参考实现。主要目标是：

1. 通过一条 control 与一条专用 data 长连接分离管理信令和 TCP/HTTP/WebSocket 字节流。
2. 使用管理面维护客户端凭证、账号、TCP 映射、HTTP 路由、连接记录和流量观测。
3. 让同一租户和用户下的客户端通过 Peer Mesh 虚拟 IP 互访，优先 UDP direct，失败时回退标准 TURN relay。
4. 默认以单节点、SQLite 和明文控制连接低门槛启动，同时提供 MySQL/PostgreSQL、TLS、OIDC、Elasticsearch 等升级路径。

当前边界：

- 公网 TCP 映射、HTTP/WS 直转和 Peer Mesh UDP 数据面已经实现。
- 公网 UDP 端口映射尚未实现；空的 `UdpConnection` 只是该能力的占位，不代表 Peer Mesh 没有 UDP。
- control/data 连接和在线路由状态仍在单个 server 进程内；多节点需要粘性路由或共享会话/路由层。

## 2. 顶层架构

```text
                         管理 JWT / 客户端 HTTP HMAC 登录
管理后台、客户端启动器 ─────────────────────────────────────► Spring Boot :8088
                                                              │
公网 HTTP / WebSocket ───────► /http/{client}/{route}/**       │
                                                              ▼
公网 TCP ─► 动态 TcpServer ─► RemoteSpecusHandler ◄──────► Netty control :7010 ◄────► Java client
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
- **控制与数据连接**：默认共用 `7010/TCP` 监听和同一 TLS 策略；control 承载管理/信令，data 专门承载 `NAT_MESSAGE` 字节流。
- **公网业务入口**：每个已注册 TCP `listenPort` 一个动态监听；HTTP/WS 使用 `/http/**`。
- **Peer Mesh 数据面**：标准 STUN/TURN 和客户端间 UDP direct；业务 IP 包端到端加密，relay 不解密业务明文。

## 3. Java 模块

| 模块 | 路径 | 主要职责 |
| --- | --- | --- |
| `specus-common` | `implementations/java/common` | 线协议、帧编解码、固定 schema 紧凑二进制、HMAC、心跳、NAT/Peer 公共模型 |
| `specus-server` | `implementations/java/server` | Netty 控制端与公网 TCP 监听、管理 REST、客户端认证、HTTP/WS 直转、Peer Mesh、持久化与观测 |
| `specus-client` | `implementations/java/client` | 读取 `client.jsonc`、HTTP 启动登录、控制连接与重连、本地 TCP/HTTP/WS 转发、Peer Mesh 虚拟网卡 |
| 管理前端 | `apps/admin-web` | 管理客户端、凭证、映射、路由、连接、流量和 Peer Mesh；构建产物由 server 静态托管 |

Java 的协议变更需要同步 `protocol/spec/`、测试向量和其它语言实现。

## 4. 控制协议

### 4.1 帧格式与大小边界

所有 v2 帧使用 11 字节 big-endian 固定头：`magic(4) + version(1) + serializer(1) + command(1) +
bodyLength(4)`。`magic=0x14353565`、`version=2`、`serializer=4`；任一字段、command、长度或 body 尾随字节
不合法都必须拒绝。登录前完整帧上限为 `16 KiB`，登录后默认 `32 MiB`，NAT DATA 单分片不超过 `64 KiB`。

CompactBinary 按固定 schema 顺序编码字段，省略字段名并使用 varint/ZigZag 与显式 nullable marker；body 不带
raw/Deflate 标志，也不执行通用压缩。`NAT_MESSAGE` body 使用独立的 16 字节头，后接可选 UTF-8 JSON metadata
与原始 data 字节，详见 `protocol/spec/control-protocol.md`。

### 4.2 Command、连接角色与消息类型

v2 只登记 `LOGIN_* (±1)`、`MESSAGE_* (±2)`、`LOGOUT_* (±3)`、`HEARTBEAT_* (±4)` 和 `NAT_MESSAGE (6)`。
旧 `5/-5`、`7/-7` 与 serializer 回退已删除，收到即为协议违规。

客户端先以相同 runtime token 建立 `control`，成功后再建立 `data`：

- control 只允许管理消息、`NAT_CONTROL`、`PEER_CONTROL`、心跳和退出；
- data 只允许 `NAT_MESSAGE`、心跳和退出；
- 每条 TCP 连接只能登录一次，角色不匹配、重复登录或登录前非登录帧会关闭连接；
- control 断开时，同一 session 的 data 一并关闭。

`MessageType` 使用固定 wire ID：`SERVER_TO_CLIENT=1`、`CLIENT_TO_SERVER=2`、`CLIENT_TO_CLIENT=3`、
`NAT_CONTROL=4`、`PEER_CONTROL=5`。`NatMessageType` 使用 `REGISTER`、`REGISTER_RESULT`、`OPEN`、`FIN`、
`DATA`、`KEEPALIVE`、`UNREGISTER`、`RST`、`WINDOW_UPDATE`。

### 4.3 两阶段客户端认证

1. HTTP 启动登录读取 `client.jsonc`，用 `SHA-256(secret)` 作为 HMAC-SHA256 key，对
   `apiKey/timestamp/nonce/machineFingerprint/osUser` 的换行串签名。服务端校验 `±60s` 时间窗，创建或复用
   identity/account/session，返回 runtime token、Netty 地址、`nettyTls` 与配置快照；数据库只保存 token hash。
2. control/data 分别发送 `clientName`、`clientSessionId`、`accessToken` 和 `connectionRole`。服务端验证过期、
   账号/凭证状态、频率、实例上限与角色绑定，再推送 `NAT_CONTROL` / `PEER_CONTROL`。

secret 明文不发送到服务端。服务端按 `(apiKey, nonce)` 数据库唯一键原子消费登录 nonce，并按 TTL 清理历史项；
因此同一签名请求即使仍在 60 秒时间窗内也不能被第二次接受，多实例部署共享同一去重状态。

## 5. 连接处理

服务端监听在可选 `SslHandler` 后依次执行 idle、分帧、v2 codec、登录、连接角色检查和对应 control/data dispatcher；
数据库登录在有界 executor 执行，Channel 状态变更切回其 EventLoop。Java 客户端为 control 和 data 分别建立同 TLS
策略的 pipeline：control 处理登录响应、配置/Peer 消息和心跳，data 处理 NAT stream。首个及后续 `NAT_CONTROL`
都是完整权威快照，TCP 映射执行 REGISTER/UNREGISTER，HTTP route 原子替换本地路由表。

## 6. 数据流

### 6.1 TCP NAT

server 下发快照后，client 对每个映射发送 `REGISTER(port, specusAddress, specusPort)`；server 校验身份和全局端口
占用、绑定公网 listener，再返回 `REGISTER_RESULT`。每条公网连接分配非零且连接内唯一的 `streamId`：

```text
公网 accept → OPEN(streamId, port/channelId) → client 连接本地目标
公网/本地字节 ⇄ DATA(streamId) + WINDOW_UPDATE credit
任一方向 EOF → FIN(streamId)，只 half-close 该方向
双方 FIN → 正常释放；取消或 I/O 错误 → RST 立即释放
```

收到 FIN 后仍继续反向传输。重复 OPEN、重复 FIN、同方向 DATA-after-FIN、未知 DATA/FIN 或其它无效的单流状态转换
只向受影响 stream 返回 RST，不关闭同一 data 连接上的其它 stream；迟到 RST 命中最近关闭 tombstone 时幂等忽略，
只有针对从未打开 stream 的 RST 才视为 data-connection 协议违规并关闭连接。每流初始窗口 `1 MiB`、累计上限
`16 MiB`、待发送队列上限 `4 MiB`，按流公平轮转并结合 socket 可写性实施背压。`listenPort` 是整台 server 的
全局资源，不能跨租户复用。

### 6.2 HTTP 与 WebSocket 直转

`/http/{clientName}/{route}/**` 在专用 data 连接上同样建立 NAT stream。服务端先执行 route Basic gate，并从受保护
请求剥离入口 Authorization；随后请求头用 `OPEN(source=http, phase=request)`，body 用 DATA，结束用 FIN，client
以 response OPEN/DATA/FIN 流式返回。双方以 WINDOW_UPDATE 反馈实际消费，浏览器取消、超时和 upstream 错误通过
RST 传播。request/response trailers 在 OPEN 的 `trailerNames` 声明，在 FIN 的 `trailers` 携带实际值。

请求累计上限 `16 MiB`、响应累计上限 `64 MiB`；SSE 与下载无需整包缓冲。可解析的单段 Range 会裁剪到 `8 MiB`，
其它 Range 由 upstream 决定。route 不存在由 client 拒绝；路径必须留在 base URL 内。路径改写只作用于可安全缓冲的
HTML/CSS 等响应。

WebSocket Upgrade 复用相同入口和 Basic gate，成功后使用 `OPEN(source=ws)` 建立 NAT stream；WebSocket frame
封装为 SWS2 后放入 DATA，FIN/RST 管理 stream 生命周期。单个 SWS2 envelope 必须落在 NAT DATA 上限内；最多
16 MiB 的原始 data frame 若超过该上限，会保留首段 opcode/RSV 与末段 FIN，并规范化拆成 continuation envelopes。
控制帧必须保持单帧且 payload 不超过 125 字节。SWS2 保留逻辑 frame 语义、close code 与 payload，禁止旧的一字节
text/binary 前缀。

### 6.3 Peer Mesh

Peer Mesh 默认关闭。启用后：

- `PeerMeshService` 分配 `100.96.0.0/11` 虚拟 IP，并按租户、owner 和 ACL 选择可见对端。
- `PeerSignalService` 通过 `PEER_CONTROL` 交换设备、候选地址和 session 授权。
- Java client 支持 Linux TUN、Windows Wintun、macOS utun 和 `noop`；`auto` 按当前系统选择。
- 客户端通过 STUN、UPnP/NAT-PMP/PCP 和候选探测尝试 UDP direct；direct 不健康时回退 TURN relay。
- Peer 数据帧使用 X25519/HKDF 派生密钥和 AES-GCM；server relay 只处理授权与外层帧。

### 6.4 HTTP 媒体采集与离线播放

HTTP route 可独立开启 `mediaCaptureEnabled`。服务端在 Direct HTTP 响应写回浏览器的同时，把未经路径改写的原始
媒体字节分片上传到专用 RustFS/S3 兼容私有桶；普通 HTTP 明细只保留预览，不重复保存已外置的媒体正文。当前识别
HLS、DASH、渐进式音视频和媒体分段，按 ETag、Last-Modified、Range 与内容编码去重；中断的非清单响应可保留已收到
的连续区间，清单必须完整才可用。

播放端按同一资源的已缓存 Range 拼接对象，拒绝多段 Range 和缓存空洞。管理 API 先执行 tenant/owner 可见性检查；
公开播放只能使用短期随机票据，票据同时绑定 capture id、tenant、到期时间和可选回源策略。HLS/DASH 清单中的相对
资源会重写为票据或管理 asset 端点。完整配置但无法访问 RustFS 时服务端启动失败；配置关闭或不完整时媒体采集安全
禁用。过期任务负责中止遗留 multipart、删除对象、引用和数据库记录。

### 6.5 公共互传房间与流程图

共享房间首次使用随机 owner token 建立，数据库只保存其 SHA-256；邀请 token 分为 `EDITOR` 与 `VIEWER`，支持撤销、
到期和每房间数量上限。短配对码使用服务端 secret 的域分离 HMAC 保存，消费次数通过数据库原子更新；WebSocket
票据、附件完成/下载与流程图版本都解析为同一持久化 room id 和角色，避免仅比较原始房间口令造成授权分叉。

登录用户的云端流程图按 `tenantId + ownerUsername` 隔离，单用户最多 100 份、单快照最多 3 MiB；更新必须携带当前
revision。公共房间版本最多保留 50 份，VIEWER 只读，只有 OWNER 可删除版本和管理邀请。

## 7. 安全模型

### 7.1 控制连接 TLS

| 模式 | 行为 |
| --- | --- |
| `disabled`（默认） | 明文 TCP，兼容旧部署 |
| `file` | 从 JKS/PKCS12 keystore 加载 server 证书 |
| `self-signed` | 启动时生成临时自签名证书，仅用于开发/测试 |

HTTP 登录响应通过 `nettyTls` 明确声明 control/data 原始 TCP 端点是否要求 TLS。Java、Go、.NET、Android 客户端的
`controlTls.enabled` 省略时跟随该字段，旧服务端缺省按 `false`；显式 `true/false` 可覆盖。客户端支持 PEM CA、
证书主机名覆盖和仅开发使用的 `insecureSkipVerify`，控制连接与专用数据连接共用同一 TLS 策略和握手超时。
管理 `serverBaseUrl=https` 不隐含 Netty TLS，因为 HTTPS 可能终止于 HTTP 反向代理。

### 7.1.1 可信代理与真实客户端地址

限流、配对码兑换、上传配额、WebSocket ticket 绑定和互传"同网"分组都使用同一个客户端地址解析组件
（Java `ClientAddressResolver`、Go `security.ClientAddressResolver`、.NET `ClientAddressResolver`）。

`SPECUS_TRUSTED_PROXIES` 配置可信反代 CIDR，默认空：

- 连接对端不在可信网段时，`X-Forwarded-For` 与 `X-Real-IP` 完全不参与判定，直接使用连接对端地址。
  直连客户端因此无法通过自带转发头改写自己的来源地址、绕过限流或劫持他人 ticket。
- 连接对端可信时，按代理链**从右向左**解析 `X-Forwarded-For`：跳过链尾连续的可信代理，第一个非可信地址
  即真实客户端；客户端在链首伪造的条目不会被采纳。非法地址一律丢弃。
- 整条链都是可信代理（或没有 `X-Forwarded-For`）时，才使用代理显式覆写的 `X-Real-IP`。
- 无法解析出地址时返回 `unknown`，该值永远不参与"同网"分组。

部署反代时需要把后端端口限制为仅反代可达，并在反代上覆写这两个头，否则应保持 `SPECUS_TRUSTED_PROXIES` 为空。

### 7.2 客户端与管理面鉴权

- 客户端 HTTP 登录使用 `ClientCredential` 的 apiKey/secret HMAC；Netty 控制连接只使用 `ClientSession` runtime token。
- client token 默认 TTL 为 `28800s`。Java client 会在到期前主动重新执行 HTTP 登录；收到“访问令牌已过期”也会刷新后重连。
- 控制连接频率限制按 `ClientAccount` 统计最近一分钟连接记录，默认 `30/min`，`0` 表示不限。
- 管理本地登录由 `/auth/login` 签发 HS256 JWT；每次请求和刷新都重新解析当前本地账号状态。OIDC 授权码流程用
  独立 ID-token decoder 校验 issuer、`client_id` audience、`azp` 与 nonce 后签发本地 token；直接 OIDC bearer 还要求
  资源 audience，并必须按已验证的 `issuer + subject` 命中已绑定且启用的本地账号。外部 tenant/role 不直接授予权限。

### 7.3 HTTP 安全边界

Spring Security 当前只要求 `/api/admin/**` 与 `/auth/refresh` 必须携带认证；`/api/public/**`、`/ws/**` 和其它请求在 filter chain 层 permitAll。`/ws/**` 中需要保护的端点由握手拦截器单独校验 JWT。

`/http/**` 不要求管理 JWT，默认是公开业务入口；每条服务端持久化 route 可独立启用 HTTP Basic。Basic 密码只
保存哈希且不在 API 中回显，HTTP 与 WebSocket 在进入隧道前使用同一校验规则。它的其它访问边界是在线客户端和
该客户端当前生效的 route；公网 TCP 入口则受已登录客户端成功 `REGISTER` 的端口集合约束。

## 8. 持久化

### 8.1 客户端身份与运行时会话

```text
ClientCredential
  └─ ClientIdentity (credential + machineFingerprint + osUser)
       └─ ClientAccount
            ├─ ClientSession
            ├─ SpecusMapping
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

- **`SpecusMapping`**：全局唯一 `listen_port`、目标地址/端口、启用状态和明细采集开关。
- **`HttpRouteMapping`**：`(client_id, route)` 唯一，保存 target base URL、启用、明细采集、媒体采集、路径改写开关，以及
  可选的 Basic 用户名和密码哈希；展示模型只暴露 `authPasswordConfigured`，不返回哈希。
- **`ConnectionRecord`**：client、channel、remote address、连接/断开时间、成功状态、失败原因和断开原因；不保存登录耗时或流量字节。
- **`ConnectionStat`**：按 tenant、clientName、自然月累加 total/success/failure，长期保留。
- **`TrafficUsage`**：按 `(client_id, usage_date)` 聚合上下行字节。
- **`ResourceTrafficUsage`**：按 tenant、client、资源类型/键和 UTC 日期聚合 TCP 映射或 HTTP route 流量。
- **`HttpMediaCapture` / `HttpMediaReference`**：记录媒体对象、Range、状态、保留期与清单引用；对象正文只在 RustFS。
- **`PublicTransferRoom*` / `PublicTransferDiagramVersion`**：保存房间 owner/invite/pairing 角色与公共流程图版本。
- **`UserDiagramDocument`**：按 tenant/owner 保存登录用户流程图快照和乐观锁 revision。

连接记录关键索引是 `(client_id, connected_at)` 和 `connected_at`，分别服务频率限制/客户端历史与归档扫描。早于滚动保留窗口的记录按自然月汇总后，在同一事务中删除；默认保留 60 天。

HTTP/TCP 明细默认写业务数据库；配置 `SPECUS_ELASTICSEARCH_URIS` 后切换到 Elasticsearch store。全局采集开关与每条 route/mapping 开关都必须开启才会记录明细。

### 8.3 数据库

| 数据库 | Driver | Hibernate Dialect |
| --- | --- | --- |
| SQLite（默认） | `org.sqlite.JDBC` | `org.hibernate.community.dialect.SQLiteDialect` |
| MySQL | `com.mysql.cj.jdbc.Driver` | `org.hibernate.dialect.MySQLDialect` |
| PostgreSQL | `org.postgresql.Driver` | `org.hibernate.dialect.PostgreSQLDialect` |

`DatabaseInitializer` 负责旧库 tenant/owner 和 HTTP body 字段回填，并可用 `SPECUS_DB_SEED_DEMO_CLIENT` 控制 `Demo client` 与 `demo-client/test1234` 演示凭证种子。该开关只在 `SPECUS_ENV=dev` / `test` 下生效：`prod`（默认，含未设置和未知值）无条件跳过演示数据，并在启动时拒绝已知默认管理口令。三端（Java / Go / .NET）共用同一套环境判定、默认口令清单与登录限速语义。

## 9. 并发与线程模型

| 执行单元 | 当前行为 |
| --- | --- |
| Netty control boss | 默认 1 线程 |
| Netty control worker | `0` 表示使用 Netty 默认线程数 |
| 公网 TCP boss/worker | 与 control 分离；默认 boss 1、worker 使用 Netty 默认 |
| `loginExecutor` | 有界池，默认 core 8、max 32、queue 20000；执行 token 鉴权、连接记录和登录后配置推送 |
| Spring scheduler | 默认 pool size 2；执行流量 flush、连接归档、Peer/附件清理等定时任务 |
| HTTP stream | Tomcat 请求线程等待 `HttpStreamExchange` 的响应头并按事件流持续写出；data EventLoop 只投递事件，不做阻塞 upstream I/O |
| client HTTP worker | `HttpStreamForwarder` 提交到共享 `ExecuteService`，使用 Netty HTTP client 与手动 read/credit 背压，避免阻塞 data EventLoop |
| TURN relay worker | 可配置有界工作池；队列满时丢弃新 relay 数据帧保护 server |

所有 DB 和阻塞工作都应避免直接占用 Netty EventLoop。跨 Channel 写由 Netty 调度到目标 EventLoop；NAT 两端用 writability 和 `AUTO_READ` 做背压。

## 10. 重连与心跳

### 10.1 Java client 重连与 token 刷新

control 连接失败后，`NettyClient` 使用 `2s → 4s → 8s → 16s → 32s → 60s` 指数退避，之后保持 60 秒上限。只有收到成功的 `LOGIN_RESPONSE` 才重置退避计数。

普通重连复用未过期 runtime token，再走完整 Netty 登录；登录成功后 server 重新推送权威 `NAT_CONTROL`/`PEER_CONTROL`。token 快过期时 client 主动重新执行 HTTP 登录，刷新 token、session、控制端地址和配置；明确的认证/策略拒绝会停止无意义重试。

### 10.2 空闲检测

- Java client：写空闲 `5s` 发送 `HEARTBEAT_REQUEST`，读空闲 `60s` 关闭并进入重连。
- Java server：写空闲 `30s` 发送兜底 `HEARTBEAT_RESPONSE`，读空闲 `60s` 关闭并清理 session、连接记录和 NAT 资源。

## 11. 核心配置默认值

| 类别 | 配置 / 环境变量 | 默认 |
| --- | --- | --- |
| Web | `server.port` | `8088` |
| Control | `SPECUS_NETTY_PORT` | `7010` |
| Frame | `SPECUS_NETTY_MAX_FRAME_SIZE` | `33554432`（32 MiB） |
| DB | `SPECUS_DB_URL` / `SPECUS_DB_POOL_SIZE` / `SPECUS_DB_BATCH_SIZE` | SQLite / `1` / `50` |
| Seed | `SPECUS_DB_SEED_DEMO_CLIENT` | `true` |
| Client token | `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` |
| Traffic | `SPECUS_TRAFFIC_FLUSH_INTERVAL_MS` | `5000` |
| Archive | `SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` / `SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS` | `60` / `3600000` |
| HTTP | `SPECUS_HTTP_MAX_REQUEST_BODY_SIZE` / `SPECUS_HTTP_TIMEOUT_MS` | `16777216` / `30000` |
| Admin auth | `SPECUS_AUTH_USERNAME` / `_PASSWORD` / `_TOKEN_TTL_SECONDS` | `admin` / `admin` / `28800` |
| Peer Mesh | `SPECUS_PEER_MESH_ENABLED` / `_STUN_TURN_PORT` / `_NAT_PROBE_ALTERNATE_PORT` | `false` / `3478` / `3479` |
| TLS | `SPECUS_TLS_MODE` | `disabled` |

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
  → 在事务中保存 SpecusMapping / HttpRouteMapping
  → NatControlService.pushSnapshotIfOnline
  → 在线 client 收到完整 NAT_CONTROL 权威快照
  → TCP 映射增删触发 REGISTER / UNREGISTER
  → HTTP route 原子替换 NatClientHandler 的不可变 route map
```

客户端离线时自动推送静默跳过，下次登录重新取得完整快照；手动 `POST /api/admin/clients/{id}/nat-control` 在离线时返回 `409`。

## 13. 已知限制与后续工作

- **真实 TLS 部署矩阵待验收**：Java、Go、.NET、Android 客户端 TLS 已配置化并具备本地测试证书握手覆盖；仍需在目标环境验证生产 CA、L4 TLS 终止和各平台证书存储。
- **HTTP 登录 nonce 去重已落地**：签名保留 60 秒时间窗，同时用数据库唯一键原子消费 `(apiKey, nonce)` 并按 TTL 清理；多实例共享同一数据库去重状态，仍需在目标数据库上做并发与故障恢复压测。
- **公网 UDP 映射缺失**：如要实现，需要新增协议子类型、server `DatagramChannel` 和按来源端点维护的映射；这与已实现 Peer Mesh UDP 不同。
- **E2E 覆盖有限**：已有 `EndToEndSpecusIT` 覆盖 SQLite 进程内 HTTP HMAC、Netty token、真实 TCP 隧道和 route 热更新，但 `*IT` 尚未接入 Maven Failsafe；仍缺真实 MySQL/PostgreSQL、跨进程和 TLS 矩阵。
- **水平扩展**：`SessionUtil`、`NatServerHandler` 和动态监听仍是进程内状态；需要控制/连接端拆分、粘性路由、共享状态和 drain。详见 `server-control-edge-ha-plan.md`。
- **未知协议值容忍**：`magic`/`version` 已预留，但未知 `Command`/serializer 当前不能保证被安全忽略，协议演进必须先做兼容性验证。

## 14. 源码索引

| 主题 | 当前入口 |
| --- | --- |
| Server 启动 | `implementations/java/server/src/main/java/com/theshuai/specusserver/SpecusServerApplication.java` |
| Control Netty | `.../server/NettyServer.java`、`.../handler/ManagedLoginRequestHandler.java`、`.../handler/AuthHandler.java` |
| Client HTTP 认证 | `.../management/controller/ClientAuthResource.java`、`.../management/service/ClientAuthService.java` |
| Client 凭证/账号 | `.../management/service/ClientCredentialService.java`、`.../management/service/ClientAccountService.java` |
| NAT server | `.../handler/NatServerHandler.java`、`.../handler/RemoteSpecusHandler.java`、`.../server/RemotePortServerManager.java` |
| HTTP/WS 直转 | `.../http/HttpSpecusController.java`、`.../http/HttpStreamExchange.java`、`.../http/WebSocketSpecusHandler.java` |
| Peer Mesh server | `.../management/service/PeerMeshService.java`、`.../management/service/PeerSignalService.java`、`.../peer/StunTurnServer.java` |
| 管理 REST | `.../management/controller/*Resource.java`、`.../management/controller/AuthController.java`、`.../management/controller/OidcController.java` |
| 安全 | `.../config/SecurityConfig.java`、`.../security/LocalTokenService.java`、`.../security/TlsContextFactory.java` |
| 协议核心 | `implementations/java/common/src/main/java/com/theshuai/common/protocol/*`、`.../command/Command.java` |
| 编解码 | `.../codec/Spliter.java`、`.../codec/PacketCodecHandler.java`、`.../protocol/PacketCodec.java` |
| 紧凑二进制 | `.../serialize/impl/CompactBinarySerializer.java` |
| Java client 启动/连接 | `implementations/java/client/src/main/java/com/theshuai/specusclient/SpecusClientApplication.java`、`.../client/NettyClient.java` |
| Java client NAT/HTTP | `.../handler/NatClientHandler.java`、`.../handler/LocalSpecusHandler.java`、`.../handler/HttpStreamForwarder.java` |
| Java client Peer Mesh | `.../peer/PeerMeshClient.java`、`.../peer/PeerVirtualDevices.java` |
| 进程内 E2E | `implementations/java/server/src/test/java/com/theshuai/specusserver/integration/EndToEndSpecusIT.java` |

---

修改协议、客户端认证、TLS、NAT/HTTP 路由、Peer Mesh 或归档逻辑时，应同时更新本文、根 README、`protocol/spec/` 和跨语言测试向量。
