# specus-server C 语言迁移执行计划

## 目标

在不改动现有 Java `specus-server`、Java `specus-client`、Go client、C# 版本的前提下，新增一版并行的 C 语言 `specus-server`：

- 与现有 Java/Go client 的 wire protocol 兼容。
- 优先覆盖控制连接、登录鉴权、心跳、`NAT_CONTROL`、TCP NAT 转发这条核心链路。
- 后续逐步补齐管理 API、持久化、管理页面、Direct HTTP、OIDC、TLS。
- 每个阶段都能独立构建、可联调、可回退。

当前工程位置：

```text
implementations/c/server/
```

## 当前状态

2026-08-27 起，C server 已解除“轻量兼容实现”冻结，目标调整为按可验收批次全量对齐 Java server；以下状态更新至 2026-08-28。计划内源码批次与本地可构造门禁已经完成，剩余发布环境矩阵单独列出：

- C11 + POSIX socket + pthread + zlib + SQLite3 构建。
- Java v2 协议帧头：`0x14353565`、`version=2`、`serializer=4`、固定 command registry 与 body length；32 MiB 按 11 字节 header + body 的完整帧计算，错误 version/serializer/command、截断、尾随和超限长度均拒绝。
- CompactBinary 直接编码固定 schema，不含旧 `payloadType` 或 raw/deflate envelope；NAT stream 使用固定 16 字节头、JSON metadata 与原始 data，v1 和旧压缩 fixture 只作为拒绝用例。
- HMAC-SHA256 启动鉴权，支持 SQLite `specus_client_credential` 校验，创建/复用机器用户绑定的客户端身份，写入 `specus_client_session`，并签发 Java-shaped `cs_` runtime token。
- 内置管理密码默认空，不再提供 `admin/admin`；管理用户使用跨 server PBKDF2-SHA256 格式并在旧 SHA-256 登录成功后迁移。登录尝试按来源 IP 与大小写不敏感账号固定窗口限流，超限返回统一 `429 + Retry-After`。来源地址只在 socket peer 命中 `SPECUS_TRUSTED_PROXIES` 后采信转发头，并从右向左剥离可信代理。
- `SPECUS_ENV` 与 Java 同样将未设置和未知值解析为 prod；prod 拒绝已知弱管理口令与公开 JWT 占位值，并在主监听及管理 API 的所有 SQLite 初始化入口禁用演示数据播种。
- control/data 两类连接按 `clientSessionId + accessToken` 登录并绑定角色，校验 token 过期、客户端/凭证启用状态、同机单实例和最大在线实例数；control 关闭时同步清理匹配 data，管理会话状态仍使用 `NETTY_ONLINE` / `DISCONNECTED`。
- `NAT_CONTROL`、TCP NAT 的 `REGISTER`、`REGISTER_RESULT`、`OPEN`、`DATA`、`FIN`、`RST`、`WINDOW_UPDATE`、`UNREGISTER`、`KEEPALIVE` 核心流程可用。
- SQLite mapping/route 变更会重载完整配置并向在线 control session 热推 `NAT_CONTROL`；手工推送在线返回 `200`、离线返回 `409`。客户端管理 view 从活跃 control session 投影 `online/connectedSinceMs`，在线时返回持久化版本与消息能力，并聚合上下行总量。
- 管理 HTTP listener 已覆盖本地密码/邮件验证注册、OIDC、HS256 管理 JWT、管理用户、客户端凭证/包、客户端、TCP 映射、HTTP route、连接记录/归档、流量汇总、SQLite/Elasticsearch 明细、对象存储、媒体采集、公共房间/流程图和 Peer Mesh 管理接口。
- Direct HTTP 已支持普通 HTTP 请求和 WebSocket upgrade bridge；SQLite route 的 `insecureSkipVerify` 与 `mediaCaptureEnabled` 会经管理 API、登录快照和 `NAT_CONTROL` 下发。响应路径改写覆盖 HTML/CSS、gzip/deflate 解码及同源外链 runtime，公网 query 的裸 `{}` 会在进入 NAT `OPEN` 前编码。SWS2 校验读取中央应用协议向量并拒绝保留 close code；启用媒体采集时使用经启动校验的专用 S3-compatible/RustFS 存储。
- gzip/x-gzip、zlib deflate 与 raw deflate 已共用 Java 同值的有界解压模块：64 MiB 绝对上限、100:1 膨胀比、微小输入 64 KiB 固定额度；超限或损坏响应保持原始压缩字节，不进入路径改写。
- OIDC 浏览器配置接口已对齐 Java；`/oidc/token` 支持 HTTP/HTTPS token endpoint 的 Authorization Code + PKCE 代理交换，HTTPS 默认校验证书链和主机名，并支持显式私有 CA。
- control/data listener 已接入 OpenSSL TLS 1.2+，支持 PKCS#12、PEM 与开发期自签证书；prod 拒绝自签证书和公网明文监听，仅允许受信 L4 终止后绑定 loopback/私网。
- Peer Mesh 已覆盖 status/device/ACL/session/stats、service-sharing、service CRUD/import/audit；认证 `PEER_CONTROL` 创建真实 session 并处理 roster、offer/answer/candidates/close、path/traffic/NAT/virtual-device report、service catalog revision/TTL。所有管理 mutation 会即时 refresh 在线租户客户端，撤权会清空陈旧 catalog。
- `SPECUS_PEER_MESH_ENABLED=true` 时进程绑定内置 RFC 5389/5780 STUN 与 RFC 5766 TURN UDP listener，支持 alternate-address NAT probe、long-term credential、realm/nonce/MESSAGE-INTEGRITY、allocation/refresh/permission/channel/send/data/ChannelData、双 allocation、relay 端口池和配额/过期清理。
- 启动登录按真实 `sendMessages/receiveMessages/attachments/mediaPreview/maxAttachmentBytes` wire 字段持久化能力；离线管理 view 按 Java 归零。6 个附件路径支持 S3-compatible/Aliyun OSS presign/HEAD complete/download、一次性授权、room role、tenant/owner、quota/rate/expiry；未配置 provider 时仍精确返回 `409 OBJECT_STORAGE_DISABLED`。
- `/ws/client-messages` 已实现 endpoint 绑定 ticket、hello、管理端到 control 写入回执、客户端到管理订阅 fan-out 与方向性 Peer ACL 约束的客户端 fallback；目标写使用每管理 socket 64、进程 1,024 的有界异步任务，写成功后才回 `written`。输入执行完整 JSON、WebSocket 分片/控制帧、UTF-8 和 65,536 UTF-16 code unit 校验。附件和离线 outbox 不在该文本 fallback 内。
- `/ws/public-transfer/discovery` 已实现来源绑定 45 秒一次性 ticket、名称预检、同持久房间跨地址与同地址跨房间的合并可见域、不同地址隔离、peer/displayName 冲突、房间容量、hello/roster、定向/广播信令、ping、固定窗口限流、写超时、65,536 UTF-16 code unit 与 STWR2/STAP2 定向 relay 校验。可选 Redis 模式已对齐 presence lease、合并 revision、全局名称/peer/容量、分布式消息限流、STCE2 Pub/Sub 路由与故障失败关闭，并通过两个 C 进程真实 WebSocket E2E。SQLite 模式已补 OWNER/EDITOR/VIEWER 房间、邀请 list/create/revoke、8 位配对码创建/原子兑换、过期/撤销拒绝、20 个有效邀请上限、来源 IP 限流和公共流程图版本四端点（3 MiB、最新 50 版、VIEWER 只读/OWNER 删除）。
- Ubuntu `protocol-v2` CI 的 C server job 已安装 OpenSSL/libcurl/hiredis/utf8proc/Redis 依赖，并接入 CMake/CTest、Java reference server/client、C↔Java Redis discovery、NAT/Direct HTTP/WebSocket 与 SQLite runtime 热更新 E2E；合入后仍需以 GitHub Actions 实际绿灯作为远端门禁结论。

> 下方 Phase 0–10 保留最初迁移过程和验收设想，出现的 v1、`CONNECTED` / `DISCONNECTED`、旧独立 HTTP command 或 wire deflate 仅代表历史阶段，不是当前协议。当前行为以本节、`protocol/spec/` 和 `cross-language-java-alignment-plan.md` 为准。

全量对齐剩余发布环境队列：

- 真实私有 RustFS/Aliyun OSS/Elasticsearch、生产证书与生产 OIDC/SMTP/Turnstile。
- Go/.NET client × C server、Go/.NET server 与 C 的 Redis discovery 混部，以及跨语言 binary/fault 浏览器矩阵。
- 真实跨 NAT direct/relay、Windows/Linux/macOS/Android 真机 VPN/TUN、10 GB 长流量。
- 多客户端并发、短连接风暴、1 小时/24 小时 soak、进程故障注入与 HA 部署观测。

## 项目布局

```text
implementations/c/server/
├── CMakeLists.txt
├── Makefile
├── README.md
├── src/
│   ├── admin_http.c / .h         # 管理 API、静态资源、Direct HTTP / WebSocket bridge
│   ├── client_address.c / .h     # 可信代理 CIDR、真实客户端地址与转发链解析
│   ├── crypto.c / .h             # SHA-256、HMAC、PBKDF2、hex、constant-time compare
│   ├── decompression_limits.c/.h # 64 MiB / 100:1 有界 gzip/deflate 解压
│   ├── http_client.c / .h        # libcurl HTTP/HTTPS OIDC token 交换与严格证书校验
│   ├── json.c / .h               # NAT metadata 所需的最小 JSON 解析和转义
│   ├── login_rate_limiter.c / .h # 管理登录 IP / 账号双维固定窗口限流
│   ├── password_hash.c / .h      # 人类口令 PBKDF2 格式、旧 SHA-256 验证与登录迁移
│   ├── protocol.c / .h           # Java wire protocol + compact payload + NAT_MESSAGE
│   ├── public_discovery.c / .h   # 公共互传 ticket、roster、信令与 STWR2 relay
│   ├── public_room.c / .h        # SQLite 房间角色、邀请/配对与公共流程图版本
│   ├── security.c / .h           # 本地 JWT、OIDC 配置与 HTTP token exchange
│   ├── security_baseline.c / .h  # 部署环境、prod 弱凭据拒绝与演示数据门禁
│   ├── storage.c / .h            # SQLite schema、CRUD、流量与 Peer Mesh 管理数据
│   ├── tls_transport.c / .h      # OpenSSL control/data TLS listener 与部署门禁
│   └── main.c                    # 控制连接 listener + TCP NAT listener
└── tests/
    ├── admin_http_tests.c
    ├── client_address_tests.c
    ├── crypto_tests.c
    ├── decompression_limits_tests.c
    ├── http_client_tests.c
    ├── json_tests.c
    ├── login_rate_limiter_tests.c
    ├── password_hash_tests.c
    ├── protocol_fixture_tests.c
    ├── security_tests.c
    ├── security_baseline_tests.c
    ├── storage_tests.c
    └── tls_transport_tests.c
```

## 执行原则

- 保持 Java 协议兼容优先，C 代码的内部结构可以不照搬 Java/Spring/Netty。
- 先做可联调的核心路径，再补管理与生产特性。
- 协议层必须用 fixture 保底，尽量做到 Java fixture 和 C 编码字节一致。
- 每阶段都要有明确验收命令和至少一个端到端场景。
- C 工程保持并行目录，不替换现有 Java/C# 工程。
- 依赖要克制：当前已接受 `pthread`、`zlib`、`sqlite3`、OpenSSL 和 libcurl；新增依赖必须对应明确验收能力。

> 状态说明：以下 Phase 记录迁移过程，但已经按现行两阶段认证和当前命令修正，不能替代上面的“当前状态”。当前验证缺口以“总体验证矩阵”和“当前推荐下一步”为准。

## Phase 0 — 基线与兼容性护栏

**目标**：明确 C 版和 Java 版的协议边界，建立不会回归的测试护栏。

**任务**：

- 固定 Java wire fixtures 来源，继续复用 `implementations/csharp/protocol/tests/fixtures/*.bin`。
- 把 C 测试拆出协议测试文件，避免所有测试堆在 `crypto_tests.c`。
- 补齐以下 fixture 覆盖：
  - `login_request.bin` decode
  - `login_response.bin` encode
  - `heartbeat_request.bin` decode
  - `heartbeat_response.bin` encode
  - `message_response.bin` decode
  - `nat_register.bin` decode
  - `nat_register_result.bin` encode
  - `nat_connected.bin` encode
  - `nat_disconnected.bin` encode
  - `nat_unregister.bin` decode
  - `nat_data_small.bin` encode/decode
  - `nat_data_large_deflated.bin` encode/decode
- 给 `Makefile` 增加 `make test-fixtures` 或统一到 `make test`。

**验收**：

```bash
make -C implementations/c/server test
```

协议 fixture 测试全绿。

## Phase 1 — 协议与安全核心库

**目标**：把 C 版协议核心从 `main.c` 中进一步独立出来，形成稳定的可复用库。

**任务**：

- 完整化 compact-binary 的字段 codec：
  - string
  - bool
  - int
  - enum
  - byte array
  - numeric string
  - string map/list
  - UUID string
  - HTTP method
- 增加 decode/encode struct：
  - `LoginRequest`
  - `LoginResponse`
  - `MessageResponse`
  - `Logout*`
  - `Heartbeat*`
  - `NatMessage`
  - `DirectHttpRequest/Response`
- 将 SHA-256/HMAC 继续保持无 OpenSSL 依赖，或在后续 TLS 阶段统一切到 OpenSSL/libsodium，避免两套 crypto。
- 明确所有 decode 函数的内存所有权和释放函数。
- 增加 fuzz-like 边界测试：
  - invalid magic
  - invalid serializer
  - oversized length
  - truncated varint
  - invalid deflate
  - inflated payload 超过 `16 MiB`

**验收**：

- `make -C implementations/c/server test` 全绿。
- Java fixtures 覆盖的包可以全部 decode。
- C 编码出的非压缩 fixture 与 Java 字节一致；压缩 fixture 在相同 zlib 输出下保持一致，否则至少 decode payload 一致。

## Phase 2 — 控制通道和客户端运行闭环（已完成）

**目标**：C server 能稳定接受 Java client 的两阶段登录、鉴权、心跳和退出。

**任务**：

- HTTP `/api/client/auth/login` 按 `apiKey + timestamp + nonce + machineFingerprint + osUser` 验证
  HMAC-SHA256，默认接受 `±60s`，并签发 `clientSessionId + accessToken`。
- 控制连接使用上述 runtime token 登录；SQLite 模式校验 session、客户端/凭证启用状态、过期时间、同机实例数
  和凭证最大在线数。仅无匹配数据库凭证时保留环境 token 兼容路径用于 smoke test。
- 校验控制端口、client identity、session id 和 token/hash 配置；部分环境认证配置返回 `503`，不静默降级。
- 增加控制连接 idle：
  - 读空闲超时关闭。
  - 写空闲可选主动心跳/keepalive。
- 登录失败后明确关闭连接。
- 连接关闭时保证控制 fd、session、线程资源释放。

**验收**：

```bash
make -C implementations/c/server test

SPECUS_DATABASE_PATH=./specus-c.db \
SPECUS_ADMIN_PORT=18088 \
SPECUS_NETTY_PORT=17010 \
implementations/c/server/build/specus-server-c
```

使用数据库中启用的 credential 完成 HTTP 登录，Java client 控制连接日志出现登录成功，C server 日志出现
`login ok`，心跳不断开；断开后 session 标记为 `DISCONNECTED`。

## Phase 3 — TCP NAT 转发

**目标**：Java client 收到 C server 下发的 `NAT_CONTROL`，注册 TCP 映射，外部 TCP 流量能双向通过控制通道转发。

**当前状态**：已经有初版实现。

**任务**：

- 当前 `SPECUS_TCP_MAPPINGS` 格式继续保留：

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

- `NAT_CONTROL` 下发字段保持 Java 客户端可识别：
  - `clientName`
  - `remoteAddress`
  - `remotePort`
  - `specusConfigList`
  - `httpSpecusConfigList`（存在数据库或 `SPECUS_HTTP_ROUTES` 配置时下发；空数组表示清空）
- REGISTER 校验：
  - `clientName` 必须等于登录 session。
  - `port/specusAddress/specusPort` 必须存在于服务端下发配置。
  - 重复注册同一端口要返回失败。
- 外部 TCP 连接：
  - accept 后生成 `channelId`。
  - 下发 `CONNECTED`。
  - 外部到 client：`DATA`。
  - client 到外部：`DATA` 写回 fd。
  - 任一侧断开：发送/处理 `DISCONNECTED`。
- 增加资源限制：
  - 全局最大外部连接数。
  - 单 client 最大外部连接数。
  - 单端口最大外部连接数。
- 增加基础背压：
  - control channel 写失败关闭外部连接。
  - 外部 fd 写失败关闭对应连接。
  - 后续可切 non-blocking + poll/epoll。
- 完整联调脚本：
  - 启动本地 echo server。
  - 启动 C server。
  - 启动 Java client。
  - 从公网映射端口写入 payload。
  - 断言回包一致。

**验收**：

- Java client 日志出现 `Register to Nat server`。
- C server 日志出现 `register ok`。
- 外部连接访问 `publicPort` 能到达 client 侧 `targetHost:targetPort`。
- 1 MiB payload 双向传输成功。

## Phase 4 — 多客户端、账号模型和持久化

**目标**：从单个环境变量 client 过渡到数据库驱动的多客户端 server。

**候选依赖**：

- SQLite：`sqlite3`
- 配置文件：优先 JSON 文件，后续可接 SQLite。
- 人类管理口令：使用跨 server 共享的版本化 PBKDF2-SHA256 格式；旧 SHA-256 hex 仅用于登录迁移。机器凭据与 route gate 等高熵密钥继续使用 SHA-256 digest。

**任务**：

- 引入 SQLite schema：
  - `client_account`
  - `specus_mapping`
  - `http_route_mapping`
  - `connection_record`
  - `traffic_usage`
  - `connection_stat`
- 实现初始化：
  - 首次启动创建表。
  - 可选 seed `Demo client / test1234`。
- 登录鉴权改为查库：
  - client enabled。
  - 密码 hash。
  - 每分钟登录限流。
- session registry：
  - `clientName -> specus_session`
  - 重复登录踢旧连接。
- NAT_CONTROL 从数据库启用映射组装，而不是只读 `SPECUS_TCP_MAPPINGS`。
- 连接记录：
  - 登录成功/失败。
  - disconnected reason。
  - connected/disconnected timestamp。
- 流量统计：
  - upload/download 计数。
  - 周期 flush 到 SQLite。

**验收**：

- 多个 Java client 可同时登录。
- 每个 client 只能注册自己名下的映射。
- 重复登录会关闭旧 session。
- SQLite 中能看到连接记录和流量汇总。

## Phase 5 — 管理 API

**目标**：C server 能提供与 Java server 管理后台兼容的核心 REST API。

**候选实现路线**：

1. 轻量 C HTTP server：
   - 自写最小 HTTP/1.1 parser 只覆盖管理 API。
   - 优点是依赖少。
   - 缺点是边界处理和安全成本高。
2. 引入成熟库：
   - `libmicrohttpd`、`mongoose`、`civetweb` 任选其一。
   - 优先评估许可证、跨平台构建和静态文件支持。

**任务**：

- 实现 `/auth/login` 本地管理员登录。
- 实现 `/api/admin/clients` CRUD。
- 实现 `/api/admin/clients/{id}/specus-mappings` CRUD。
- 实现 `/api/admin/clients/{id}/nat-control` 手动下发。
- 实现 `/api/admin/overview`。
- 实现 `/api/admin/connections`。
- 实现 `/api/admin/traffic`。
- 错误响应对齐 Java 管理 API 的 status code 和 JSON 形状。
- 管理 API 鉴权先支持本地 HS256 JWT。

**验收**：

- 现有管理页面的主要请求能打通。
- 用 curl 可以登录、创建 client、创建 specus、向在线 client 下发 NAT_CONTROL。
- CRUD 后 Java client 能热更新端口映射。

## Phase 6 — 管理页面静态资源

**目标**：C server 能托管现有管理页面。

**任务**：

- 从 Java server 静态资源复制或共享：
  - `index.html`
  - `app.js`
  - `app.css`
- HTTP server 增加静态文件服务。
- 默认路由 `/` 返回 `index.html`。
- 未命中静态资源时返回 404。
- API 和静态文件路由互不冲突。
- 补充安全头：
  - `Cache-Control`
  - `X-Content-Type-Options`
  - 基础 CSP

**验收**：

- 浏览器打开 C server 管理端口可以看到管理页面。
- 管理页面登录、查看 clients、创建 specus、下发 NAT_CONTROL 可用。

## Phase 7 — Direct HTTP

**目标**：补齐 Java server 的 `/http/{client}/{route}/...` 直转 HTTP 能力。

**任务**：

- 实现 HTTP ingress route。
- 根据 client + route 查找 `targetBaseUrl`。
- 构造 `DIRECT_HTTP_REQUEST`：
  - request id
  - method
  - route
  - relative path
  - raw query
  - headers list
  - body bytes
- 等待 Java client 回 `DIRECT_HTTP_RESPONSE`。
- 超时返回 504。
- client 离线或 route 不存在返回 404/409。
- pending request 表使用 request id 索引，连接断开时清理。

**验收**：

- Java client 后面的本地 HTTP 服务可以通过 C server `/http/...` 访问。
- 并发请求不会串包。
- 超时和 client 断开能释放 pending request。

## Phase 8 — WebSocket 事件和归档任务

**目标**：补齐管理页面实时连接事件和历史统计维护。

**任务**：

- 实现 `/ws/connections`。
- WebSocket 握手支持 token 校验。
- 连接记录 insert/update 后广播事件。
- 归档任务：
  - 定期扫描旧 `connection_record`。
  - 聚合到 `connection_stat`。
  - 删除旧明细。
- flush traffic 定时任务改为固定 delay 语义。

**验收**：

- 管理页面能实时看到 client 上线/离线。
- 归档任务可通过测试数据验证。

## Phase 9 — TLS 和 OIDC

**目标**：补齐部署安全能力。

**候选依赖**：

- TLS：OpenSSL。
- JWT/JWK/OIDC：可自实现最小流程，也可评估 `libjwt`、`jansson` 等组合。

**任务**：

- 控制连接 TLS：
  - PKCS12。
  - PEM cert/key。
  - 可选自签。
- 管理 HTTP TLS。
- 本地 HS256 JWT 完善。
- OIDC：
  - `/oidc-config`
  - `/oidc/token`
  - JWKS 拉取和 RS256 验签
  - token exchange
- 配置项对齐 Java server 语义。

**验收**：

- Java client trust-all/self-signed 模式可连 C server TLS 控制端口。
- 管理页面可通过 HTTPS 访问。
- OIDC mock IdP 流程可登录。

## Phase 10 — 性能、稳定性和发布

**目标**：从可用原型收敛为可长期运行的 C server。

**任务**：

- 将阻塞线程模型评估为：
  - 当前 pthread per connection 保留为简单模式。
  - 高并发模式引入 `poll`/`epoll`/`kqueue`。
- 连接池和对象池：
  - frame buffer 复用。
  - NAT data buffer 复用。
- 统一日志：
  - 时间戳。
  - 连接 id。
  - clientName。
  - channelId。
- 指标：
  - 在线 client 数。
  - listener 数。
  - external connection 数。
  - up/down bytes。
- systemd 部署文件。
- release 构建：
  - `make release`
  - stripped binary。
  - README 部署说明。
- 压测：
  - 多 client。
  - 多端口。
  - 大 payload。
  - 短连接风暴。

**验收**：

- 长时间 soak test 不泄漏 fd/thread/memory。
- 1k+ 并发外部连接达到明确指标。
- C server 与 Java server 在核心场景可互换。

## 总体验证矩阵

| 能力 | 测试方式 | 当前状态 |
| --- | --- | --- |
| SHA-256/HMAC-SHA256/HMAC-SHA1/PBKDF2 | C 单元测试 | Ubuntu 24.04 WSL `make test` 已通过 |
| gzip/deflate 解压安全 | `decompression_limits_tests.c` + 管理 API 集成测试 | 64 MiB/100:1、64 KiB 恰好边界、gzip/zlib/raw-deflate 与压缩炸弹拒绝均通过 |
| Java frame header | fixture encode/decode + 等号/超限边界 | 已覆盖完整帧 32 MiB 口径；Ubuntu 24.04 WSL 已执行 |
| compact raw payload | fixture encode/decode | 已覆盖 |
| legacy compact deflate | v2 malformed/rejection fixture | wire deflate 已删除，只验证明确拒绝 |
| Java client 登录 | SQLite HTTP 登录 + control/data E2E | Windows JDK 21 Java client × WSL C server 已通过环境 token 与 SQLite credential 两条路径 |
| 心跳 | Java client 联调 | 登录后的 heartbeat response 已在联调运行期覆盖；长时间持续性仍待 soak |
| NAT_CONTROL | 协议测试 + Java client 联调 | 登录初始快照、手工推送、mapping/route 创建/删除/重建热推均通过 |
| TCP NAT 转发 | Java client + echo server | 小包、1 MiB、重连、动态删除与重建均通过 |
| 多 client | 集成测试 | 在线连接已按 `clientName` 链表隔离；多 client 集成验收未开始 |
| SQLite 持久化 | `storage_tests.c` + 管理 API + 跨进程 E2E | 单元测试与 SQLite credential、在线投影、动态配置 E2E 均通过；并发打开设置 5 秒 busy timeout |
| 管理 API / 启动安全 | `admin_http_tests.c`、`client_address_tests.c`、`security_baseline_tests.c` | PBKDF2、无默认口令、登录限流、可信代理、prod 弱凭据拒绝/演示数据禁用及既有 API 用例在 Ubuntu 24.04 WSL 通过 |
| 管理页面 | 静态文件服务 + 浏览器手测/API E2E | 静态文件服务已接线；浏览器完整流程待验收 |
| Direct HTTP | 协议/改写测试 + Java client E2E | POST/path/query 与 WebSocket/SWS2 text/continuation/ping/pong/close 已通过 |
| OIDC | HTTP/HTTPS mock token endpoint + API 测试 | Authorization Code + PKCE、严格证书链/主机名、私有 CA 正反例已通过 |
| TLS | TLS listener E2E | TLS 1.2+、PKCS#12/PEM、自签开发模式及 prod 公网明文/自签拒绝已通过 |
| 公共 ICE / 对象存储附件 | `admin_http_tests.c` + `object_storage_tests.c` + `object_storage_e2e.sh` | 内置 STUN/TURN 配置、临时 credential、6 路径 storage-disabled 失败关闭、S3-compatible presign/HEAD complete/download、授权/配额/过期清理均通过 |
| Elasticsearch 明细 | `elasticsearch_traffic_tests.c` + `elasticsearch_traffic_test.sh` | HTTP/TCP index 初始化、批量写入、分页查询与容量清理通过 fake ES 真实 HTTP 门禁 |
| HTTP 媒体采集 | `media_capture_tests.c` + `media_capture_test.sh` | multipart、HLS/DASH/渐进式、Range 去重/拼接/稀疏回放/回源、ticket/manifest/asset 和过期清理通过 fake S3 门禁 |
| Peer Mesh / STUN / TURN | `peer_mesh_tests.c` + `stun_turn_tests.c` | roster/session/candidate/close、service catalog/refresh、路径/流量、RFC 5780 NAT probe、TURN allocation/permission/channel/relay/quota/expiry 通过 |
| client-message control fallback | `admin_http_tests.c` + `storage_tests.c` | 真实 socket 覆盖 ticket/Upgrade/hello、双向 fan-out/回执；存储测试覆盖在线能力和方向性 Peer ACL，跨客户端 E2E 仍待补 |
| public-transfer discovery / room | `admin_http_tests.c` + `public_coordination_tests.c` + `public_discovery_cluster_e2e.sh` + `java_c_discovery_interop.sh` | 来源绑定单次 ticket、持久 OWNER/EDITOR/VIEWER 房间、邀请创建/列表/撤销、配对码原子兑换/限流、流程图角色权限/精确 3 MiB/超限拒绝/最新 50 版、同房间/同网合并域、隔离、冲突/容量、Unicode NFC 名称键、信令/ping/分布式限流/STWR2、双实例 Pub/Sub 与 Redis 故障关闭已通过；C↔Java roster/名称/双向信令混部通过，Go/.NET 与跨语言 binary/fault 浏览器矩阵仍待补 |

## 当前推荐下一步

1. 合入并观察 Ubuntu CI 中新增的 CMake/CTest `22/22`、C↔Java Redis discovery、`nat_e2e_smoke.sh` 和 `runtime_config_e2e.sh` 门禁；远端绿灯前不把本地 WSL 结果替代为 CI 结论。
2. 补跑 Go / .NET / Android client × C server 的 TCP、Direct HTTP 与 WebSocket E2E；Android 仍需真机。
3. 执行多客户端并发、短连接风暴、1 小时长连接和 24 小时 control soak，记录 fd/thread/memory 与延迟。
4. 按 #35 继续执行真实私有 OSS/ES、跨 NAT、跨语言客户端/Redis 混部、长时间压力与故障注入；源码能力已完成，只有外部环境矩阵通过后才能标为生产替换完成。

## 常用命令

```bash
# 构建并测试
make -C implementations/c/server test

# 清理构建产物
make -C implementations/c/server clean

# 推荐：SQLite 两阶段认证 + 管理 API + TCP NAT
SPECUS_DATABASE_PATH=./specus-c.db \
SPECUS_ADMIN_PORT=8088 \
SPECUS_NETTY_PORT=7010 \
SPECUS_TCP_MAPPINGS="18080=127.0.0.1:8080" \
implementations/c/server/build/specus-server-c
```

