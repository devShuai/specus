# tunnel-server C 语言迁移执行计划

## 目标

在不改动现有 Java `tunnel-server`、Java `tunnel-client`、Go client、C# 版本的前提下，新增一版并行的 C 语言 `tunnel-server`：

- 与现有 Java/Go client 的 wire protocol 兼容。
- 优先覆盖控制连接、登录鉴权、心跳、`NAT_CONTROL`、TCP NAT 转发这条核心链路。
- 后续逐步补齐管理 API、持久化、管理页面、Direct HTTP、OIDC、TLS。
- 每个阶段都能独立构建、可联调、可回退。

当前工程位置：

```text
implementations/c/server/
```

## 当前状态

当前 C server 冻结在“轻量兼容实现”阶段，用于协议联调和最小可用管理面，不继续扩展 Peer Mesh 数据面：

- C11 + POSIX socket + pthread + zlib + SQLite3 构建。
- Java 协议帧头：`0x14353565`、`version=1`、`serializer`、`command`、body length；32 MiB 按 11 字节 header + body 的完整帧计算，CompactBinary deflate 恰好 16 MiB 允许、超 1 字节拒绝。
- Java compact payload 的 raw/deflate 编解码，使用 raw deflate 参数对齐 Java `Deflater(..., true)` / `Inflater(true)`。
- HMAC-SHA256 启动鉴权，支持 SQLite `tunnel_client_credential` 校验，创建/复用机器用户绑定的客户端身份，写入 `tunnel_client_session`，并签发 Java-shaped `cs_` runtime token。
- Netty 控制通道按 `clientSessionId + accessToken` 登录，校验 token 过期、客户端/凭证启用状态、同机单实例和最大在线实例数，登录成功后进入 `NETTY_ONLINE`，断开后标记 `DISCONNECTED`。
- `NAT_CONTROL`、TCP NAT 的 `REGISTER`、`CONNECTED`、`DATA`、`DISCONNECTED`、`UNREGISTER` 核心流程可用。
- 轻量管理 HTTP listener 已覆盖本地密码登录、HS256 管理 JWT、管理用户、客户端凭证、客户端、TCP 映射、HTTP route、连接记录、连接归档统计、日流量、资源流量和 SQLite HTTP/TCP 明细查询。
- Direct HTTP 已支持普通 HTTP 请求和 WebSocket upgrade bridge，并接入 Java-compatible 响应路径改写，覆盖 HTML/CSS、runtime polyfill、gzip/deflate 解码。
- OIDC 浏览器配置接口已对齐 Java；`/oidc/token` 支持 HTTP token endpoint 的 Authorization Code + PKCE 代理交换，`https://` token endpoint 明确返回 `502`。
- Peer Mesh 管理契约已覆盖 status、device list、device enabled 持久化、带 `OUTBOUND/INBOUND/BOTH` direction 的 ACL list/create/delete、session list/close/close-open；tenant/owner 可见性比较区分大小写。C 数据面不会主动创建真实 peer session，虚拟网卡状态固定为 `UNSUPPORTED`。
- 公共 `/api/public/peer-mesh/stun-config` 与 `/api/public/transfer/ice-config` 可描述显式配置的外部 STUN/TURN，并用 HMAC-SHA1 生成临时 credential；C 进程本身不绑定 STUN/TURN UDP。
- 启动登录按真实 `sendMessages/receiveMessages/attachments/mediaPreview/maxAttachmentBytes` wire 字段持久化能力；离线管理 view 按 Java 归零。6 个附件路径精确匹配 Java，但因无对象存储抽象统一返回 `409 OBJECT_STORAGE_DISABLED`。

仍未实现或暂不推进：

- TLS listener 与 HTTPS OIDC token exchange。
- Elasticsearch 明细存储。
- Peer Mesh 真实数据面、虚拟网卡、标准 STUN/TURN 子集 relay。
- 公共发现 WebSocket、live client-message 和可用对象存储附件数据面。
- Java 同级别的生产级背压、水位线和完整 HA 治理。

## 项目布局

```text
implementations/c/server/
├── CMakeLists.txt
├── Makefile
├── README.md
├── src/
│   ├── admin_http.c / .h         # 管理 API、静态资源、Direct HTTP / WebSocket bridge
│   ├── crypto.c / .h             # SHA-256, HMAC-SHA256, HMAC-SHA1, hex, constant-time compare
│   ├── json.c / .h               # NAT metadata 所需的最小 JSON 解析和转义
│   ├── protocol.c / .h           # Java wire protocol + compact payload + NAT_MESSAGE
│   ├── security.c / .h           # 本地 JWT、OIDC 配置与 HTTP token exchange
│   ├── storage.c / .h            # SQLite schema、CRUD、流量与 Peer Mesh 管理数据
│   └── main.c                    # 控制连接 listener + TCP NAT listener
└── tests/
    ├── admin_http_tests.c
    ├── crypto_tests.c
    ├── json_tests.c
    ├── protocol_fixture_tests.c
    ├── security_tests.c
    └── storage_tests.c
```

## 执行原则

- 保持 Java 协议兼容优先，C 代码的内部结构可以不照搬 Java/Spring/Netty。
- 先做可联调的核心路径，再补管理与生产特性。
- 协议层必须用 fixture 保底，尽量做到 Java fixture 和 C 编码字节一致。
- 每阶段都要有明确验收命令和至少一个端到端场景。
- C 工程保持并行目录，不替换现有 Java/C# 工程。
- 依赖要克制：当前已接受 `pthread`、`zlib`、`sqlite3`；后续只有在继续推进 TLS / HTTPS OIDC 时再评估 TLS HTTP client 等额外库。

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

TUNNEL_DATABASE_PATH=./shuai-tunnel-c.db \
TUNNEL_ADMIN_PORT=18088 \
TUNNEL_NETTY_PORT=17010 \
implementations/c/server/build/shuai-tunnel-server-c
```

使用数据库中启用的 credential 完成 HTTP 登录，Java client 控制连接日志出现登录成功，C server 日志出现
`login ok`，心跳不断开；断开后 session 标记为 `DISCONNECTED`。

## Phase 3 — TCP NAT 转发

**目标**：Java client 收到 C server 下发的 `NAT_CONTROL`，注册 TCP 映射，外部 TCP 流量能双向通过控制通道转发。

**当前状态**：已经有初版实现。

**任务**：

- 当前 `TUNNEL_TCP_MAPPINGS` 格式继续保留：

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

- `NAT_CONTROL` 下发字段保持 Java 客户端可识别：
  - `clientName`
  - `remoteAddress`
  - `remotePort`
  - `tunnelConfigList`
  - `httpTunnelConfigList`（存在数据库或 `TUNNEL_HTTP_ROUTES` 配置时下发；空数组表示清空）
- REGISTER 校验：
  - `clientName` 必须等于登录 session。
  - `port/tunnelAddress/tunnelPort` 必须存在于服务端下发配置。
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
- 密码 hash：沿用 SHA-256 hex，保持与现有管理模型兼容。

**任务**：

- 引入 SQLite schema：
  - `client_account`
  - `tunnel_mapping`
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
  - `clientName -> tunnel_session`
  - 重复登录踢旧连接。
- NAT_CONTROL 从数据库启用映射组装，而不是只读 `TUNNEL_TCP_MAPPINGS`。
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
- 实现 `/api/admin/clients/{id}/tunnels` CRUD。
- 实现 `/api/admin/clients/{id}/nat-control` 手动下发。
- 实现 `/api/admin/overview`。
- 实现 `/api/admin/connections`。
- 实现 `/api/admin/traffic`。
- 错误响应对齐 Java 管理 API 的 status code 和 JSON 形状。
- 管理 API 鉴权先支持本地 HS256 JWT。

**验收**：

- 现有管理页面的主要请求能打通。
- 用 curl 可以登录、创建 client、创建 tunnel、向在线 client 下发 NAT_CONTROL。
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
- 管理页面登录、查看 clients、创建 tunnel、下发 NAT_CONTROL 可用。

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
| SHA-256/HMAC-SHA256/HMAC-SHA1 | C 单元测试 | MSVC 纯 crypto 子集通过；完整 POSIX suite 待 Linux 工具链 |
| Java frame header | fixture encode/decode + 等号/超限边界 | 已覆盖完整帧 32 MiB 口径；待 POSIX 工具链执行 |
| compact raw payload | fixture encode/decode | 已覆盖 |
| compact deflate payload | Java fixture encode/decode | 已覆盖 |
| Java client 登录 | 手动联调 | 已做过基础登录；当前需端口权限重跑 |
| 心跳 | Java client 联调 | 待持续性测试 |
| NAT_CONTROL | 协议测试 + Java client 联调 | 协议已覆盖，联调待重跑 |
| TCP NAT 转发 | Java client + echo server | 待完整 E2E |
| 多 client | 集成测试 | 在线连接已按 `clientName` 链表隔离；多 client 集成验收未开始 |
| SQLite 持久化 | `storage_tests.c` + 管理 API 测试 | 实现和测试用例已具备；仍待 Linux/C 工具链重跑 |
| 管理 API | `admin_http_tests.c` | 实现和测试用例已具备；仍待 Linux/C 工具链重跑 |
| 管理页面 | 静态文件服务 + 浏览器手测/API E2E | 静态文件服务已接线；浏览器完整流程待验收 |
| Direct HTTP | 协议/改写测试 + Java client E2E | 普通 HTTP、WebSocket bridge 和改写已实现；Java client E2E 待验收 |
| OIDC | HTTP mock token endpoint + API 测试 | HTTP Authorization Code + PKCE 已覆盖；HTTPS token exchange 未实现 |
| TLS | TLS listener E2E | 未实现 |
| 公共 ICE / 附件禁用契约 | `admin_http_tests.c` | 外部 ICE/临时 credential 与 6 路径 409 用例已写；待 POSIX 工具链执行 |

## 当前推荐下一步

1. 在 Linux/C 工具链环境执行 `make -C implementations/c/server test`，确认现有六组测试全部通过。
2. 在可绑定端口的环境跑完整 Java client × C server × echo server NAT E2E，并保存登录、心跳、NAT_CONTROL 和双向流量证据。
3. 补跑 Java / Go / .NET / Android client × C server 的 Direct HTTP 普通请求与 WebSocket E2E。
4. 若解除“轻量兼容实现”冻结，再单独评估 TLS listener、HTTPS OIDC token exchange 与生产级背压；不要把这些能力标为已完成。

## 常用命令

```bash
# 构建并测试
make -C implementations/c/server test

# 清理构建产物
make -C implementations/c/server clean

# 推荐：SQLite 两阶段认证 + 管理 API + TCP NAT
TUNNEL_DATABASE_PATH=./shuai-tunnel-c.db \
TUNNEL_ADMIN_PORT=8088 \
TUNNEL_NETTY_PORT=7010 \
TUNNEL_TCP_MAPPINGS="18080=127.0.0.1:8080" \
implementations/c/server/build/shuai-tunnel-server-c
```

