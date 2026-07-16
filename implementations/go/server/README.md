# implementations/go/server

Go 实现的 shuai-tunnel 服务端,与 Java / Go / .NET / Android client **线协议字节兼容**(11 字节帧头 + CompactBinary + NAT_MESSAGE + runtime token 登录)。服务端为纯 Go 实现；直接依赖包括数据库驱动、WebSocket、Brotli 和用于 PKCS12/PFX 读取的 `golang.org/x/crypto`。

## 运行

```bash
cd implementations/go/server
go generate ./web                    # 只同步 Go server 的内嵌管理后台静态资源
go build ./cmd/shuai-tunnel-server
./shuai-tunnel-server                 # 默认 SQLite + 控制端口 7010 + 管理端口 8088
./shuai-tunnel-server -config cfg.json
```

独立 RFC 5780 STUN（不启动业务 server、数据库或 TURN）：

```bash
go test ./internal/stunserver
go build -o shuai-stun-server ./cmd/shuai-stun-server
STUN_PRIMARY_BIND_ADDRESS=10.0.0.10 \
STUN_PRIMARY_PUBLIC_ADDRESS=203.0.113.10 \
STUN_ALTERNATE_BIND_ADDRESS=10.0.0.11 \
STUN_ALTERNATE_PUBLIC_ADDRESS=203.0.113.11 \
./shuai-stun-server
```

独立 STUN 与 Java/.NET 版本共用 `STUN_*` 环境变量，支持四端点
`CHANGE-REQUEST`、`RESPONSE-PORT`、`PADDING`、全局/单源限流和
`127.0.0.1:9108/metrics`。完整配置与 systemd 模板见
[`deploy/stun-server/systemd`](../../../deploy/stun-server/systemd/README.md)。

- 控制通道(Netty 等价)默认监听 `7010`,Java/Go/.NET/Android client 连这里。
- 管理后台 + Direct HTTP + WebSocket 默认监听 `:8088`,浏览器访问 `http://127.0.0.1:8088/`。
- 默认 seed 演示客户端账号 `Demo client` 和启动凭证 `apiKey=demo-client / secret=test1234`(可关)。
- 管理后台默认账号 `admin / admin`；内置 admin 之外的管理用户保存到 `tunnel_management_user`。

## 配置

可用 JSON 文件(`-config`)或 `TUNNEL_*` 环境变量(env 覆盖文件)。

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| `TUNNEL_NETTY_PORT` | 控制通道端口 | 7010 |
| `TUNNEL_NETTY_MAX_FRAME_SIZE` | 完整控制帧上限，包含 11 字节 header；值必须不小于 11（等于 11 时仅容纳零字节 body） | 33554432 |
| `TUNNEL_MANAGEMENT_ADDR` | 管理 HTTP 监听地址 | `:8088` |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | sqlite |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | 数据库连接串 | `./shuai-tunnel.db` |
| `TUNNEL_DB_SEED_DEMO_CLIENT` | 是否 seed 演示客户端 | true |
| `TUNNEL_AUTH_USERNAME` / `TUNNEL_AUTH_PASSWORD` | 管理后台账号 | admin / admin |
| `TUNNEL_AUTH_TENANT_ID` | 本地密码登录默认租户 | default |
| `TUNNEL_AUTH_JWT_SECRET` | 本地 JWT 签名密钥(空则随机,重启失效) | - |
| `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` | 客户端 HTTP 启动登录签发的 runtime token 有效期 | 28800 |
| `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | 创建客户端凭证时默认最大在线实例数 | 2 |
| `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | 同一机器指纹 + OS 用户允许同时在线的实例数 | 1 |
| `TUNNEL_LOGIN_EXECUTOR_MAX` / `TUNNEL_LOGIN_EXECUTOR_QUEUE` | Java 当前登录执行器环境变量别名；旧 `TUNNEL_LOGIN_EXECUTOR_MAX_SIZE` / `TUNNEL_LOGIN_EXECUTOR_QUEUE_CAPACITY` 仍兼容 | 32 / 20000 |
| `TUNNEL_PUBLIC_ADDRESS` | 下发给 client 的公网地址 | - |
| `TUNNEL_HTTP_TIMEOUT_MS` / `TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE` | Direct HTTP 超时 / 请求体体积上限 | 30000 / 16MiB |
| `TUNNEL_HTTP_REWRITE_MAX_BODY_BYTES` | HTTP 路由路径改写响应体上限 | 10MiB |
| `TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED` | HTTP/TCP 明细采集全局开关 | false |
| `TUNNEL_TRAFFIC_CAPTURE_PREVIEW_BYTES` | TCP payload 预览字节数 | 256 |
| `TUNNEL_TRAFFIC_CAPTURE_HEADER_CHARS` | HTTP Header 保存字符上限 | 8192 |
| `TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES` | HTTP body 解压预览最大字节数，避免压缩响应在管理页预览时无界膨胀 | 1048576 |
| `TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING` | HTTP/TCP 明细采集每类队列最大积压条数 | 20000 |
| `TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` | HTTP/TCP 明细采集单次 flush 最大条数 | 1000 |
| `TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` | HTTP/TCP 明细采集后台 flush 间隔 | 2000 |
| `TUNNEL_TRAFFIC_CAPTURE_SAMPLE_RATE` | TCP 常规帧采样率，首帧仍会捕获；取值 `0.0` 到 `1.0` | 1.0 |
| `TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` | 连接明细保留天数；更早记录归档到月度统计，`0` 关闭归档 | 60 |
| `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` | 连接明细归档任务执行间隔 | 3600000 |
| `TUNNEL_ELASTICSEARCH_URIS` | ES 地址，多个节点逗号分隔；为空时用数据库保存明细 | - |
| `TUNNEL_ELASTICSEARCH_USERNAME` / `TUNNEL_ELASTICSEARCH_PASSWORD` | ES Basic Auth | - |
| `TUNNEL_ELASTICSEARCH_API_KEY` | ES API Key，优先于用户名密码 | - |
| `TUNNEL_ELASTICSEARCH_HTTP_INDEX` / `TUNNEL_ELASTICSEARCH_TCP_INDEX` | HTTP / TCP 明细索引 | `shuai-tunnel-http-traffic` / `shuai-tunnel-tcp-traffic` |
| `TUNNEL_ELASTICSEARCH_HTTP_MAX_STORE_SIZE` / `TUNNEL_ELASTICSEARCH_TCP_MAX_STORE_SIZE` | HTTP / TCP 明细索引体积上限 | `100GB` / `10GB` |
| `TUNNEL_PEER_MESH_ENABLED` | 是否启用私有组网控制面 | false |
| `TUNNEL_PEER_MESH_CIDR` | 私有组网虚拟网段 | `100.96.0.0/11` |
| `TUNNEL_PEER_MESH_PUBLIC_ADDRESS` | 下发给客户端的 STUN/TURN 地址；空则回退 `TUNNEL_PUBLIC_ADDRESS` | - |
| `TUNNEL_PEER_MESH_STUN_TURN_PORT` | 标准 STUN/TURN UDP 主端口 | 3478 |
| `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | NAT 辅助探测端口；0 表示按主端口 +1 兜底 | 3479 |
| `TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS` | 下发给客户端和公开 NAT 检测页的公共 STUN 服务器，逗号或空白分隔 | - |
| `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS` | Peer session 授权有效期 | 3600 |
| `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS` | Relay allocation TTL | 300 |
| `TUNNEL_PEER_MESH_RELAY_MIN_PORT` / `TUNNEL_PEER_MESH_RELAY_MAX_PORT` | 标准 TURN relay allocation 端口范围 | 49152 / 65535 |
| `TUNNEL_PEER_MESH_RELAY_WORKER_THREADS` / `TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY` | Java relay worker 配置；Go 标准 TURN 当前由 relay socket goroutine 处理，先读取保留 | 0 / 10000 |
| `TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS` | Peer Mesh relay 流量聚合 flush 间隔；Go server 与 Java 一样在 relay 热路径聚合、后台批量落库 | 5000 |
| `TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED` | 是否要求 Allocate/Refresh/CreatePermission 携带 MESSAGE-INTEGRITY | true |
| `TUNNEL_PEER_MESH_TURN_REALM` | TURN realm | `shuai-tunnel` |
| `TUNNEL_PEER_MESH_TURN_SHARED_SECRET` | 临时 credential 签名密钥；空则进程内随机 | - |
| `TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | 临时 TURN credential TTL | 3600 |
| `TUNNEL_OBJECT_STORAGE_PROVIDER` | `disabled` / `aliyun-oss` | disabled |
| `TUNNEL_OBJECT_STORAGE_ENDPOINT` / `TUNNEL_OBJECT_STORAGE_BUCKET` / `TUNNEL_OBJECT_STORAGE_ACCESS_KEY_ID` / `TUNNEL_OBJECT_STORAGE_ACCESS_KEY_SECRET` | 私有 Aliyun OSS 连接与凭证 | - |
| `TUNNEL_OBJECT_STORAGE_PREFIX` | 附件 object key 前缀 | `shuai-tunnel/attachments` |
| `TUNNEL_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS` / `TUNNEL_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS` | 上传/下载预签名 URL TTL | 900 / 600 |
| `TUNNEL_OBJECT_STORAGE_RETENTION_HOURS` / `TUNNEL_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES` | 保留时间 / 附件上限 | 72 / 536870912 |
| `TUNNEL_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS` | 过期扫描间隔 | 3600000 |
| `TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP` / `TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS` | 公开 presign-upload 单 IP 固定窗口限流 | 30 / 300 |
| `TUNNEL_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM` | 同 roomToken 哈希 PENDING 附件上限 | 50 |
| `TUNNEL_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM` | 发现房间 peer 上限 | 32 |
| `TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION` / `TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS` | 发现连接消息限流 | 120 / 60 |
| `TUNNEL_TLS_MODE` | `disabled` / `file` / `self-signed` | disabled |
| `TUNNEL_TLS_KEYSTORE` / `TUNNEL_TLS_KEYSTORE_PASSWORD` | PKCS12 / PFX keystore 与密码(mode=file) | - |
| `TUNNEL_TLS_CERT_FILE` / `TUNNEL_TLS_KEY_FILE` | PEM 证书/私钥(mode=file) | - |
| `TUNNEL_OIDC_CLIENT_ID` / `TUNNEL_OIDC_CLIENT_SECRET` / `TUNNEL_OIDC_TOKEN_ENDPOINT` / `TUNNEL_OIDC_JWK_SET_URI` … | OIDC 单点登录 | - |
| `TUNNEL_OIDC_TENANT_CLAIM` | OIDC JWT 中用于读取租户的 claim 名称 | `tenant_id` |

### 切换数据库

```bash
# PostgreSQL
TUNNEL_DB_PROVIDER=postgres \
TUNNEL_CONNECTIONSTRINGS_TUNNEL="postgres://user:pass@localhost:5432/shuai?sslmode=disable" \
./shuai-tunnel-server

# MySQL
TUNNEL_DB_PROVIDER=mysql \
TUNNEL_CONNECTIONSTRINGS_TUNNEL="user:pass@tcp(localhost:3306)/shuai?parseTime=true" \
./shuai-tunnel-server
```

启动时按 dialect 用 `CREATE TABLE IF NOT EXISTS` 幂等建表(`internal/store/schema/*.sql`),客户端账号、启动凭证、机器身份、带客户端消息能力字段的运行时会话、`transfer_attachment`、管理用户、映射和统计表与 .NET/Java 对齐；历史 `peer_mesh_acl` 会幂等补充默认 `OUTBOUND` 的 `direction` 列；时间戳统一存 ISO-8601 字符串以保证字典序=时序。

映射表已包含 Java 管理面当前使用的通道级开关：TCP 映射的 `detail_capture_enabled`，HTTP 路由的 `detail_capture_enabled` 与 `path_rewrite_enabled`。这些字段默认关闭，启动迁移会对历史库幂等补列；当前 Go server 已能通过管理 API 保存和返回这些配置，并在 `path_rewrite_enabled=true` 时对可文本化 HTTP 响应做路径改写。

资源级流量和 HTTP/TCP 明细采集也已对齐到 Java 管理契约：TCP 映射 / HTTP route 会聚合写入 `tunnel_resource_traffic_usage`，Direct HTTP 成功/失败响应会写入 `tunnel_http_traffic_exchange`，TCP 端口映射双向 payload 会写入 `tunnel_tcp_traffic_frame`；明细采集热路径只入队，后台按配置批量 flush，管理明细查询默认不打断批量节奏，只有显式传 `flush=true` 时才会先 flush 再查；管理 API 支持资源流量列表、HTTP 分页与字段搜索、TCP 分页、单帧详情、按 channel 串流查询和 `inspection-status` 采集状态。HTTP 响应展示已兼容 `gzip`、`deflate` 的 zlib / raw deflate，以及 `br` Brotli 解码。

TCP 转发背压已对齐 Java/.NET 的 high/low watermark 语义：控制通道写入和外部 socket 写入都会按 `TUNNEL_NETTY_WRITE_BUFFER_LOW_WATER_MARK` / `TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK` 统计待写字节；超过高水位会暂停对应读循环，回落到低水位后恢复，避免慢 client 或慢公网连接造成无界积压。

明细存储支持 DB / Elasticsearch 双后端：默认未配置 `TUNNEL_ELASTICSEARCH_URIS` 时使用数据库；配置 ES 后自动创建 Java 兼容字段映射，HTTP/TCP 明细写入 ES 并从 ES 查询，HTTP 索引默认 100GB、TCP 索引默认 10GB，超过后按最旧 `id` 分批删除。

每日总流量表 `tunnel_traffic_usage` 已补齐 `tenant_id`，启动迁移会对历史库幂等补列；新写入会按客户端所属租户保存，管理查询按当前租户和可见客户端收敛，并兼容历史空租户行。

连接归档统计表 `tunnel_connection_stat` 也已补齐 `tenant_id`：新库 schema 直接按 `tenant_id + client_name + stat_month` 保持唯一，启动迁移会为历史库补列并按 `client_id` / `client_name` 回填租户；归档任务按租户、客户端名和月份聚合，默认保留最近 60 天明细、每小时执行一次，可通过 Java 同名 `TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` / `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` 调整；管理查询先限制当前租户，再按普通用户可见 clientId 收敛，避免不同租户同名客户端的统计混在一起。

## 多租户管理

Go server 已对齐 Java 管理面基础：

- 本地密码登录 JWT 写入 `tenant_id` 与 `role`，`/auth/refresh` 会保留这些 claim。
- `GET /api/admin/me` 返回当前管理用户；`/api/admin/users` 仅 admin 可用。
- 内置 admin 来自配置；其它管理用户保存到 `tunnel_management_user`。
- admin 可查看当前租户内全部客户端、凭证、映射、连接和流量；普通用户只能看到自己创建的资源。租户 ID 与 owner username 的权限比较与 Java 一样区分大小写。
- OIDC 令牌按 `TUNNEL_OIDC_TENANT_CLAIM` 读取租户，缺失时回退默认租户；配置中的内置 admin 用户会识别为 admin。
- 客户端 HTTP 启动登录响应返回凭证所属 `tenantId`、`maxOnlineInstances`、TCP/HTTP 映射和 Peer Mesh 配置；运行时会话写入 `tunnel_client_session`，HTTP 登录态为 `HTTP_AUTHENTICATED`，Netty 登录成功改为 `NETTY_ONLINE`，断开、过期和服务启动清理都会改为 `DISCONNECTED`。
- 客户端 runtime token TTL、同机用户在线实例上限和创建凭证时的默认最大在线实例数来自独立 `clientAuth` 配置组，分别对应 `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS`、`TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` 和 `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES`。
- Netty 运行时登录会检查同一机器/用户在线实例上限和凭证最大在线实例，连接断开后同时回收内存在线状态和数据库在线状态。
- 连接记录和连接归档统计都带租户维度：admin 看当前租户全部数据，普通用户只看自己可见客户端产生的记录和统计。

### TLS

```bash
TUNNEL_TLS_MODE=self-signed ./shuai-tunnel-server     # 启动时现场生成自签证书
TUNNEL_TLS_MODE=file TUNNEL_TLS_KEYSTORE=server.p12 TUNNEL_TLS_KEYSTORE_PASSWORD=changeit ./shuai-tunnel-server
TUNNEL_TLS_MODE=file TUNNEL_TLS_CERT_FILE=cert.pem TUNNEL_TLS_KEY_FILE=key.pem ./shuai-tunnel-server
```

TLS 同时作用于控制通道与管理 HTTP。`file` 模式优先使用 `TUNNEL_TLS_KEYSTORE`
加载 PKCS12 / PFX；未配置 keystore 时回退到 PEM 证书和私钥文件。

## 测试

```bash
go test ./...    # fixtures、登录/NAT/HTTP、TURN auth、附件、公共发现、client-messages、admin API、OIDC、TLS、帧边界
go vet ./...
```

协议层用仓库内 `implementations/csharp/protocol/tests/fixtures/*.bin`(已复制进 `internal/protocol/testdata`)做 golden 交叉校验:非压缩帧字节级一致,deflate 帧因 Go `compress/flate` 与 Java/.NET zlib 输出不同改为语义自洽校验(可互相解压,完全互通)。

## Peer Mesh 对齐状态

Go server 已对齐 Java 当前 Peer Mesh 控制面：

- `MessageType.PEER_CONTROL=4` 信令转发。
- HTTP 登录响应下发 `peerMesh` 配置。
- 按租户/用户分配虚拟 IP，默认同一 `tenantId + ownerUsername` 放行。
- 管理 API：状态、设备、带 `OUTBOUND` / `INBOUND` / `BOTH` 方向的 ACL、会话列表、启停设备、清理会话；跨 owner 的 `CLIENT_TO_CLIENT` fallback 同样按方向 ACL 判断。
- 设备上报、会话授权、路径/流量上报、强制关闭和在线 roster 下发。
- 内置标准 STUN/TURN UDP relay：Binding、备用端口 NAT 探测、带临时 credential/realm/nonce/MESSAGE-INTEGRITY 的 Allocate/Refresh/CreatePermission、401/438、Send/Data Indication、`SPM1` frame 授权校验和 relay 字节计量。
- 公共传输已提供 `/api/public/transfer/ice-config`、6 个附件 REST 路径和 `/ws/public-transfer/discovery`；语法有效的非对象 discovery JSON 按缺省 `signal` 转发并保留 `payload:null`。公开 presign 来源表满后新来源直接拒绝，只由每 10 分钟后台任务清理过期窗口。
- 管理/客户端消息使用 `/ws/client-messages` 和控制通道 `CLIENT_TO_CLIENT` fallback；`sent` ACK 不等待异步控制通道写完成，写失败仅记日志，与 Java Netty 行为一致。

Go client 当前已实现 Peer Mesh UDP 控制面、Java 兼容 X25519/HKDF/AES-GCM IP 数据帧、Linux `/dev/net/tun`、Windows Wintun 与 macOS utun 虚拟网卡读写、direct UDP 与标准 TURN relay data indication；代码数据面已具备通过虚拟 IP 承载业务流量的能力，真实 Windows / Linux / macOS 双机 ping、HTTP 和 relay fallback 仍需按跨语言验收矩阵手工验证。

## 包结构

- `internal/protocol` — 双向编解码(帧 + CompactBinary + NAT + HMAC)
- `internal/config` — 配置 + `TUNNEL_*` 映射
- `internal/store` — 多库抽象 + schema + 查询/CRUD/归档
- `internal/auth` — apiKey 签名校验、运行时 token、密码 hash、限流、id 生成
- `internal/session` — 会话注册表(同名登录顶替)
- `internal/control` — 监听器、连接、帧读写、空闲/心跳看门狗、登录线程池
- `internal/nat` — 远端端口管理、外部连接桥接、NAT_CONTROL 下发、流量统计
- `internal/directhttp` — Direct HTTP 转发 + 入口
- `internal/management` — admin/public REST API + DTO + 附件接口
- `internal/transfer` — Aliyun OSS 预签名、附件状态机、过期清理和公开限流
- `internal/security` — 本地 JWT(HS256)、OIDC(RS256/JWKS + token 交换)、TLS
- `internal/wsevents` — `/ws/connections` 事件广播；server 包另含公共发现和 client-message WebSocket hub
- `web` — 内嵌 SPA 静态资源
