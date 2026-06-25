# implementations/go/server

Go 实现的 shuai-tunnel 服务端,与 Java client / C# server **线协议字节兼容**(11 字节帧头 + CompactBinary + NAT_MESSAGE + runtime token 登录)。纯 Go 实现,依赖仅限数据库驱动与 WebSocket 库。

## 运行

```bash
cd implementations/go/server
go generate ./web                    # 只同步 Go server 的内嵌管理后台静态资源
go build ./cmd/shuai-tunnel-server
./shuai-tunnel-server                 # 默认 SQLite + 控制端口 7010 + 管理端口 8088
./shuai-tunnel-server -config cfg.json
```

- 控制通道(Netty 等价)默认监听 `7010`,Java/Go client 连这里。
- 管理后台 + Direct HTTP + WebSocket 默认监听 `:8088`,浏览器访问 `http://127.0.0.1:8088/`。
- 默认 seed 演示客户端账号 `Demo client` 和启动凭证 `apiKey=demo-client / secret=test1234`(可关)。
- 管理后台默认账号 `admin / admin`；内置 admin 之外的管理用户保存到 `tunnel_management_user`。

## 配置

可用 JSON 文件(`-config`)或 `TUNNEL_*` 环境变量(env 覆盖文件)。

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| `TUNNEL_NETTY_PORT` | 控制通道端口 | 7010 |
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
| `TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED` | HTTP/TCP 明细采集全局开关 | true |
| `TUNNEL_TRAFFIC_CAPTURE_PREVIEW_BYTES` | TCP payload 预览字节数 | 256 |
| `TUNNEL_TRAFFIC_CAPTURE_HEADER_CHARS` | HTTP Header 保存字符上限 | 8192 |
| `TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING` | HTTP/TCP 明细采集每类队列最大积压条数 | 20000 |
| `TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` | HTTP/TCP 明细采集单次 flush 最大条数 | 1000 |
| `TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` | HTTP/TCP 明细采集后台 flush 间隔 | 2000 |
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
| `TUNNEL_PEER_MESH_STUN_TURN_PORT` | STUN/TURN-lite UDP 端口 | 3478 |
| `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | NAT 辅助探测端口；0 表示关闭 | 0 |
| `TUNNEL_PEER_MESH_SESSION_TTL_SECONDS` | Peer session 授权有效期 | 3600 |
| `TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS` | Relay allocation TTL | 300 |
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

启动时按 dialect 用 `CREATE TABLE IF NOT EXISTS` 幂等建表(`internal/store/schema/*.sql`),客户端账号、启动凭证、机器身份、运行时会话、管理用户、映射和统计表与 C#/Java 对齐;时间戳统一存 ISO-8601 字符串以保证字典序=时序。

映射表已包含 Java 管理面当前使用的通道级开关：TCP 映射的 `detail_capture_enabled`，HTTP 路由的 `detail_capture_enabled` 与 `path_rewrite_enabled`。这些字段默认关闭，启动迁移会对历史库幂等补列；当前 Go server 已能通过管理 API 保存和返回这些配置，并在 `path_rewrite_enabled=true` 时对可文本化 HTTP 响应做路径改写。

资源级流量和 HTTP/TCP 明细采集也已对齐到 Java 管理契约：TCP 映射 / HTTP route 会聚合写入 `tunnel_resource_traffic_usage`，Direct HTTP 成功/失败响应会写入 `tunnel_http_traffic_exchange`，TCP 端口映射双向 payload 会写入 `tunnel_tcp_traffic_frame`；明细采集热路径只入队，后台按配置批量 flush，管理明细查询前会主动 flush 一次；管理 API 支持资源流量列表、HTTP 分页与字段搜索、TCP 分页、单帧详情和按 channel 串流查询。HTTP 响应展示已兼容 `gzip`、`deflate` 的 zlib / raw deflate，以及 `br` Brotli 解码。

TCP 转发背压已对齐 Java/.NET 的 high/low watermark 语义：控制通道写入和外部 socket 写入都会按 `TUNNEL_NETTY_WRITE_BUFFER_LOW_WATER_MARK` / `TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK` 统计待写字节；超过高水位会暂停对应读循环，回落到低水位后恢复，避免慢 client 或慢公网连接造成无界积压。

明细存储支持 DB / Elasticsearch 双后端：默认未配置 `TUNNEL_ELASTICSEARCH_URIS` 时使用数据库；配置 ES 后自动创建 Java 兼容字段映射，HTTP/TCP 明细写入 ES 并从 ES 查询，HTTP 索引默认 100GB、TCP 索引默认 10GB，超过后按最旧 `id` 分批删除。

每日总流量表 `tunnel_traffic_usage` 已补齐 `tenant_id`，启动迁移会对历史库幂等补列；新写入会按客户端所属租户保存，管理查询按当前租户和可见客户端收敛，并兼容历史空租户行。

连接归档统计表 `tunnel_connection_stat` 也已补齐 `tenant_id`：新库 schema 直接按 `tenant_id + client_name + stat_month` 保持唯一，启动迁移会为历史库补列并按 `client_id` / `client_name` 回填租户；归档任务按租户、客户端名和月份聚合，默认保留最近 60 天明细、每小时执行一次，可通过 Java 同名 `TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` / `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` 调整；管理查询先限制当前租户，再按普通用户可见 clientId 收敛，避免不同租户同名客户端的统计混在一起。

## 多租户管理

Go server 已对齐 Java 管理面基础：

- 本地密码登录 JWT 写入 `tenant_id` 与 `role`，`/auth/refresh` 会保留这些 claim。
- `GET /api/admin/me` 返回当前管理用户；`/api/admin/users` 仅 admin 可用。
- 内置 admin 来自配置；其它管理用户保存到 `tunnel_management_user`。
- admin 可查看当前租户内全部客户端、凭证、映射、连接和流量；普通用户只能看到自己创建的资源。
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
go test ./...    # 协议 fixtures、HTTP 启动登录、控制通道登录/心跳、NAT 回环、admin API、OIDC、TLS
go vet ./...
```

协议层用仓库内 `implementations/csharp/protocol/tests/fixtures/*.bin`(已复制进 `internal/protocol/testdata`)做 golden 交叉校验:非压缩帧字节级一致,deflate 帧因 Go `compress/flate` 与 Java/.NET zlib 输出不同改为语义自洽校验(可互相解压,完全互通)。

## Peer Mesh 对齐状态

Go server 已对齐 Java 当前 Peer Mesh 控制面：

- `MessageType.PEER_CONTROL=4` 信令转发。
- HTTP 登录响应下发 `peerMesh` 配置。
- 按租户/用户分配虚拟 IP，默认同一 `tenantId + ownerUsername` 放行。
- 管理 API：状态、设备、ACL、会话列表、启停设备、清理会话。
- 设备上报、会话授权、路径/流量上报、强制关闭和在线 roster 下发。
- 内置 STUN/TURN-lite UDP relay：binding、备用端口 NAT 探测、allocation/refresh、relay send/data 转发、`SPM1` frame 授权校验和 relay 字节计量。

Go client 当前已实现 Peer Mesh UDP 控制面、Java 兼容 X25519/HKDF/AES-GCM IP 数据帧、Linux `/dev/net/tun`、Windows Wintun 与 macOS utun 虚拟网卡读写、direct UDP 与 TURN-lite relay data frame；Linux / Windows / macOS 客户端可通过虚拟 IP 承载真实业务流量。

## 包结构

- `internal/protocol` — 双向编解码(帧 + CompactBinary + NAT + HMAC)
- `internal/config` — 配置 + `TUNNEL_*` 映射
- `internal/store` — 多库抽象 + schema + 查询/CRUD/归档
- `internal/auth` — apiKey 签名校验、运行时 token、密码 hash、限流、id 生成
- `internal/session` — 会话注册表(同名登录顶替)
- `internal/control` — 监听器、连接、帧读写、空闲/心跳看门狗、登录线程池
- `internal/nat` — 远端端口管理、外部连接桥接、NAT_CONTROL 下发、流量统计
- `internal/directhttp` — Direct HTTP 转发 + 入口
- `internal/management` — admin REST API + DTO
- `internal/security` — 本地 JWT(HS256)、OIDC(RS256/JWKS + token 交换)、TLS
- `internal/wsevents` — `/ws/connections` 事件广播
- `web` — 内嵌 SPA 静态资源
