# implementations/go/server

Go 实现的 specus 服务端，与 Java / Go / .NET / Android client 使用唯一的 **v2 线协议**
（11 字节帧头 + CompactBinary + NAT stream + runtime token + control/data 角色）。服务端为纯 Go 实现；
直接依赖包括数据库驱动、WebSocket、Brotli 和用于 PKCS12/PFX 读取的 `golang.org/x/crypto`。

## 运行

```bash
cd implementations/go/server
go generate ./web                    # 只同步 Go server 的内嵌管理后台静态资源
go build ./cmd/specus-server
./specus-server                 # 默认 SQLite + 控制端口 7010 + 管理端口 8088
./specus-server -config cfg.json
```

独立 RFC 5780 STUN（不启动业务 server、数据库或 TURN）：

```bash
go test ./internal/stunserver
go build -o specus-stun-server ./cmd/specus-stun-server
STUN_PRIMARY_BIND_ADDRESS=10.0.0.10 \
STUN_PRIMARY_PUBLIC_ADDRESS=203.0.113.10 \
STUN_ALTERNATE_BIND_ADDRESS=10.0.0.11 \
STUN_ALTERNATE_PUBLIC_ADDRESS=203.0.113.11 \
./specus-stun-server
```

独立 STUN 与 Java/.NET 版本共用 `STUN_*` 环境变量，支持四端点
`CHANGE-REQUEST`、`RESPONSE-PORT`、`PADDING`、全局/单源限流和
`127.0.0.1:9108/metrics`。完整配置与 systemd 模板见
[`deploy/stun-server/systemd`](../../../deploy/stun-server/systemd/README.md)。

- v2 隧道监听默认使用 `7010`，每个客户端会话在该监听上分别建立 `control` 与 `data` 连接。
- 管理后台 + HTTP/WebSocket 流式入口默认监听 `:8088`，浏览器访问 `http://127.0.0.1:8088/`。
- 默认 seed 演示客户端账号 `Demo client` 和启动凭证 `apiKey=demo-client / secret=test1234`(可关)。
- 管理后台默认账号 `admin / admin`；内置 admin 之外的管理用户保存到 `specus_management_user`。

## 配置

可用 JSON 文件(`-config`)或 `SPECUS_*` 环境变量(env 覆盖文件)。

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| `SPECUS_NETTY_PORT` | v2 control/data 隧道端口 | 7010 |
| `SPECUS_NETTY_BIND_ADDRESS` | control/data 隧道监听地址 | `0.0.0.0` |
| `SPECUS_NETTY_BOSS_THREADS` / `SPECUS_NETTY_REMOTE_BOSS_THREADS` | 控制监听 / 公网映射监听的并行 accept loop 数 | 1 / 1 |
| `SPECUS_NETTY_WORKER_THREADS` / `SPECUS_NETTY_REMOTE_WORKER_THREADS` | Java Netty event-loop 配置兼容字段；Go 由运行时以 goroutine 多路复用连接，无安全的一对一线程映射 | 0 / 0 |
| `SPECUS_NETTY_SO_BACKLOG` | Java 监听 backlog 配置兼容字段；Go 标准库不暴露逐 listener backlog，实际采用操作系统 `somaxconn` | 8192 |
| `SPECUS_NETTY_REUSE_ADDRESS` / `SPECUS_NETTY_KEEP_ALIVE` / `SPECUS_NETTY_TCP_NO_DELAY` | listener 地址复用与 accepted socket 选项 | true / true / true |
| `SPECUS_NETTY_MAX_FRAME_SIZE` | 完整控制帧上限，包含 11 字节 header；值必须不小于 11（等于 11 时仅容纳零字节 body） | 33554432 |
| `SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE` | 登录完成前的完整控制帧上限 | 16384 |
| `SPECUS_MANAGEMENT_ADDR` | 管理 HTTP 监听地址 | `:8088` |
| `SPECUS_LOG_FILE` | 独立运行时可选的日志文件绝对路径；配置后与标准输出双写。systemd 部署直接捕获完整 stdout/stderr 并强制留空，避免重复日志 | - |
| `SPECUS_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | sqlite |
| `SPECUS_CONNECTIONSTRINGS_SPECUS` | 数据库连接串 | `./specus.db` |
| `SPECUS_DB_SEED_DEMO_CLIENT` | 是否 seed 演示客户端 | true |
| `SPECUS_AUTH_USERNAME` / `SPECUS_AUTH_PASSWORD` | 管理后台账号 | admin / admin |
| `SPECUS_AUTH_TENANT_ID` | 本地密码登录默认租户 | default |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` / `SPECUS_AUTH_REGISTRATION_ENABLED` | 密码登录 / 访客自助注册总开关；注册还要求 Turnstile 与 SMTP | true / true（验证配置默认关闭） |
| `SPECUS_AUTH_TURNSTILE_*` | Cloudflare Turnstile site key、secret、Siteverify 地址与 hostname 白名单 | disabled |
| `SPECUS_AUTH_EMAIL_*` / `SPECUS_AUTH_SMTP_*` | 注册邮箱验证码与 SMTP 参数 | disabled |
| `SPECUS_AUTH_JWT_SECRET` | 本地 JWT 签名密钥(空则随机,重启失效) | - |
| `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | 客户端 HTTP 启动登录签发的 runtime token 有效期 | 28800 |
| `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | 创建客户端凭证时默认最大在线实例数 | 2 |
| `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | 同一机器指纹 + OS 用户允许同时在线的实例数 | 1 |
| `SPECUS_LOGIN_EXECUTOR_CORE` / `SPECUS_LOGIN_EXECUTOR_MAX` / `SPECUS_LOGIN_EXECUTOR_QUEUE` | 登录执行器 core / max / 有界队列；旧 `*_SIZE` / `*_CAPACITY` 名仍兼容 | 8 / 32 / 20000 |
| `SPECUS_PUBLIC_ADDRESS` | 下发给 client 的公网地址 | - |
| `SPECUS_HTTP_TIMEOUT_MS` / `SPECUS_HTTP_MAX_REQUEST_BODY_SIZE` | HTTP stream 超时 / 请求体体积上限 | 30000 / 16MiB |
| `SPECUS_HTTP_ROUTE_CACHE_TTL_MS` | HTTP route 访问策略短 TTL 缓存 | 2000 |
| `SPECUS_HTTP_REWRITE_MAX_BODY_BYTES` | HTTP 路由路径改写响应体上限 | 10MiB |
| `SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED` | HTTP/TCP 明细采集全局开关 | false |
| `SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES` | TCP payload 预览字节数 | 256 |
| `SPECUS_TRAFFIC_CAPTURE_HEADER_CHARS` | HTTP Header 保存字符上限 | 8192 |
| `SPECUS_TRAFFIC_CAPTURE_DECODE_MAX_BYTES` | HTTP body 解压预览最大字节数，避免压缩响应在管理页预览时无界膨胀 | 1048576 |
| `SPECUS_TRAFFIC_CAPTURE_MAX_PENDING` | HTTP/TCP 明细采集每类队列最大积压条数 | 20000 |
| `SPECUS_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` | HTTP/TCP 明细采集单次 flush 最大条数 | 1000 |
| `SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` | HTTP/TCP 明细采集后台 flush 间隔 | 2000 |
| `SPECUS_TRAFFIC_CAPTURE_SAMPLE_RATE` | TCP 常规帧采样率，首帧仍会捕获；取值 `0.0` 到 `1.0` | 1.0 |
| `SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` | 连接明细保留天数；更早记录归档到月度统计，`0` 关闭归档 | 60 |
| `SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS` | 连接明细归档任务执行间隔 | 3600000 |
| `SPECUS_ELASTICSEARCH_URIS` | ES 地址，多个节点逗号分隔；为空时用数据库保存明细 | - |
| `SPECUS_ELASTICSEARCH_USERNAME` / `SPECUS_ELASTICSEARCH_PASSWORD` | ES Basic Auth | - |
| `SPECUS_ELASTICSEARCH_API_KEY` | ES API Key，优先于用户名密码 | - |
| `SPECUS_ELASTICSEARCH_HTTP_INDEX` / `SPECUS_ELASTICSEARCH_TCP_INDEX` | HTTP / TCP 明细索引 | `specus-http-traffic` / `specus-tcp-traffic` |
| `SPECUS_ELASTICSEARCH_HTTP_MAX_STORE_SIZE` / `SPECUS_ELASTICSEARCH_TCP_MAX_STORE_SIZE` | HTTP / TCP 明细索引体积上限 | `100GB` / `10GB` |
| `SPECUS_PEER_MESH_ENABLED` | 是否启用私有组网控制面 | false |
| `SPECUS_PEER_MESH_CIDR` | 私有组网虚拟网段 | `100.96.0.0/11` |
| `SPECUS_PEER_MESH_PUBLIC_ADDRESS` | 下发给客户端的 STUN/TURN 地址；空则回退 `SPECUS_PUBLIC_ADDRESS` | - |
| `SPECUS_PEER_MESH_STUN_TURN_PORT` | 标准 STUN/TURN UDP 主端口 | 3478 |
| `SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` | NAT 辅助探测端口；0 表示按主端口 +1 兜底 | 3479 |
| `SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS` | 下发给客户端和公开 NAT 检测页的公共 STUN 服务器，逗号或空白分隔 | - |
| `SPECUS_PEER_MESH_SESSION_TTL_SECONDS` | Peer session 授权有效期 | 3600 |
| `SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS` | Relay allocation TTL | 300 |
| `SPECUS_PEER_MESH_RELAY_MIN_PORT` / `SPECUS_PEER_MESH_RELAY_MAX_PORT` | 标准 TURN relay allocation 端口范围 | 49152 / 65535 |
| `SPECUS_PEER_MESH_RELAY_WORKER_THREADS` / `SPECUS_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY` | 标准 TURN relay 的 worker 数与有界任务队列；线程数为 0 时按 CPU 在 2..8 范围自动选择，队列满时丢弃新的 relay data indication 以保护服务端 | 0 / 10000 |
| `SPECUS_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES` / `SPECUS_PEER_MESH_UDP_SEND_BUFFER_BYTES` / `SPECUS_PEER_MESH_UDP_TRAFFIC_CLASS` | STUN/TURN 与 relay socket 接收缓冲、发送缓冲及 IP TOS | 4194304 / 4194304 / 16 |
| `SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS` | Peer Mesh relay 流量聚合 flush 间隔；Go server 与 Java 一样在 relay 热路径聚合、后台批量落库 | 5000 |
| `SPECUS_PEER_MESH_TURN_AUTH_REQUIRED` | 是否要求 Allocate/Refresh/CreatePermission 携带 MESSAGE-INTEGRITY | true |
| `SPECUS_PEER_MESH_TURN_REALM` | TURN realm | `specus` |
| `SPECUS_PEER_MESH_TURN_SHARED_SECRET` | 临时 credential 签名密钥；空则进程内随机 | - |
| `SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | 临时 TURN credential TTL | 3600 |
| `SPECUS_OBJECT_STORAGE_PROVIDER` | `disabled` / `aliyun-oss` | disabled |
| `SPECUS_OBJECT_STORAGE_ENDPOINT` / `SPECUS_OBJECT_STORAGE_REGION` / `SPECUS_OBJECT_STORAGE_BUCKET` / `SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID` / `SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET` | 私有 Aliyun OSS V4 region、连接与凭证；标准 endpoint 可推导 region，CNAME 需显式配置 | - |
| `SPECUS_OBJECT_STORAGE_PREFIX` | 附件 object key 前缀 | `specus/attachments` |
| `SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL` | OSS 上传成功回调地址；空值禁用，客户端 complete 继续用 HEAD 兜底 | - |
| `SPECUS_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS` / `SPECUS_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS` / `SPECUS_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS` | 上传 V4 URL / 一次性下载授权 / OSS 直达 URL TTL | 900 / 600 / 30 |
| `SPECUS_OBJECT_STORAGE_RETENTION_HOURS` / `SPECUS_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES` | 保留时间 / 附件上限 | 72 / 536870912 |
| `SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES` / `SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES` | 每个登录账号的有效存储 / UTC 月下载跳转流量额度 | 1073741824 / 1073741824 |
| `SPECUS_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS` | 过期扫描间隔 | 3600000 |
| `SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP` / `SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS` | 公开 presign-upload 单 IP 固定窗口限流 | 30 / 300 |
| `SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM` | 同 roomToken 哈希 PENDING 附件上限 | 50 |
| `SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM` | 发现房间 peer 上限 | 32 |
| `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION` / `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS` | 发现连接消息限流 | 360 / 60 |
| `SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED` / `SPECUS_PUBLIC_TRANSFER_REDIS_URI` | 启用 Redis 多实例 presence、Pub/Sub、revision 与共享限流；URI 在启用时必填 | false / - |
| `SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX` | Redis key 与频道前缀 | specus:v2:public-transfer |
| `SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS` / `SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS` | presence TTL / 刷新间隔 | 30 / 10000 |
| `SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS` | Redis 命令超时，故障时失败关闭 | 2000 |
| `SPECUS_TLS_MODE` | `disabled` / `file` / `self-signed` | disabled |
| `SPECUS_TLS_KEYSTORE` / `SPECUS_TLS_KEYSTORE_PASSWORD` | PKCS12 / PFX keystore 与密码(mode=file) | - |
| `SPECUS_TLS_CERT_FILE` / `SPECUS_TLS_KEY_FILE` | PEM 证书/私钥(mode=file) | - |
| `SPECUS_TLS_REQUIRE_ENCRYPTION` / `SPECUS_TLS_TERMINATED_UPSTREAM` | 生产加密门禁 / 可信上游 TLS 终止；后者仅允许私网或 loopback 明文后端，并会向客户端声明 `nettyTls=true` | false / false |
| `SPECUS_OIDC_CLIENT_ID` / `SPECUS_OIDC_CLIENT_SECRET` / `SPECUS_OIDC_TOKEN_ENDPOINT` / `SPECUS_OIDC_JWK_SET_URI` … | OIDC 单点登录 | - |
| `SPECUS_OIDC_REGISTRATION_ENDPOINT` | 登录页 Certus 注册入口 | `https://certus.devshuai.com/register` |
| `SPECUS_OIDC_TENANT_CLAIM` | OIDC JWT 中用于读取租户的 claim 名称 | `tenant_id` |

### 切换数据库

```bash
# PostgreSQL
SPECUS_DB_PROVIDER=postgres \
SPECUS_CONNECTIONSTRINGS_SPECUS="postgres://user:pass@localhost:5432/specus?sslmode=disable" \
./specus-server

# MySQL
SPECUS_DB_PROVIDER=mysql \
SPECUS_CONNECTIONSTRINGS_SPECUS="user:pass@tcp(localhost:3306)/specus?parseTime=true" \
./specus-server
```

启动时按 dialect 用 `CREATE TABLE IF NOT EXISTS` 幂等建表(`internal/store/schema/*.sql`),客户端账号、启动凭证、机器身份、带客户端消息能力字段的运行时会话、`transfer_attachment`、管理用户、映射和统计表与 .NET/Java 对齐；历史 `peer_mesh_acl` 会幂等补充默认 `OUTBOUND` 的 `direction` 列，历史管理用户表会补齐 OIDC issuer/subject/identity-key 和唯一索引；客户端改名会在同一事务内同步 identity、TCP/HTTP route、Peer Mesh device/ACL 和聚合流量表的冗余名称。时间戳统一存 ISO-8601 字符串以保证字典序=时序。

映射表已包含 Java 管理面当前使用的通道级开关：TCP 映射的 `detail_capture_enabled`，HTTP 路由的 `detail_capture_enabled`、`path_rewrite_enabled` 与逐 route Basic 认证字段。认证默认关闭，管理响应只返回 `authPasswordConfigured`，不会返回密码或哈希；HTTP/WebSocket 都在打开隧道前校验，受保护 route 的入口 `Authorization` 不会下发客户端或写入流量明细。启动迁移会对历史库幂等补列；当前 Go server 也会在 `path_rewrite_enabled=true` 时对可文本化 HTTP 响应做路径改写。

资源级流量和 HTTP/TCP 明细采集也已对齐到 Java 管理契约：TCP 映射 / HTTP route 会聚合写入 `specus_resource_traffic_usage`，HTTP stream 成功/失败响应会写入 `specus_http_traffic_exchange`，TCP 端口映射双向 payload 会写入 `specus_tcp_traffic_frame`；明细采集热路径只入队，后台按配置批量 flush，管理明细查询默认不打断批量节奏，只有显式传 `flush=true` 时才会先 flush 再查；管理 API 支持资源流量列表、HTTP 分页与字段搜索、TCP 分页、单帧详情、按 channel 串流查询和 `inspection-status` 采集状态。HTTP 业务响应展示可解码 `gzip`、`deflate`（zlib / raw）和 `br` Brotli；这不改变 v2 wire body 禁止通用压缩的约束。

TCP 转发背压已对齐 Java/.NET 的 high/low watermark 语义：控制通道写入和外部 socket 写入都会按 `SPECUS_NETTY_WRITE_BUFFER_LOW_WATER_MARK` / `SPECUS_NETTY_WRITE_BUFFER_HIGH_WATER_MARK` 统计待写字节；超过高水位会暂停对应读循环，回落到低水位后恢复，避免慢 client 或慢公网连接造成无界积压。

明细存储支持 DB / Elasticsearch 双后端：默认未配置 `SPECUS_ELASTICSEARCH_URIS` 时使用数据库；配置 ES 后自动创建 Java 兼容字段映射，HTTP/TCP 明细写入 ES 并从 ES 查询，HTTP 索引默认 100GB、TCP 索引默认 10GB，超过后按最旧 `id` 分批删除。

每日总流量表 `specus_traffic_usage` 已补齐 `tenant_id`，启动迁移会对历史库幂等补列；新写入会按客户端所属租户保存，管理查询按当前租户和可见客户端收敛，并兼容历史空租户行。

连接归档统计表 `specus_connection_stat` 也已补齐 `tenant_id`：新库 schema 直接按 `tenant_id + client_name + stat_month` 保持唯一，启动迁移会为历史库补列并按 `client_id` / `client_name` 回填租户；归档任务按租户、客户端名和月份聚合，默认保留最近 60 天明细、每小时执行一次，可通过 Java 同名 `SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` / `SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS` 调整；管理查询先限制当前租户，再按普通用户可见 clientId 收敛，避免不同租户同名客户端的统计混在一起。

## 多租户管理

Go server 已对齐 Java 管理面基础：

- 本地密码登录 JWT 写入 `tenant_id` 与 `role`，但每次管理请求（包括 `/auth/refresh`）都会按签名后的 username 重新读取当前配置或数据库中的启用状态、租户和角色；降权与禁用立即生效。
- `GET /api/admin/me` 返回当前管理用户；`/api/admin/users` 仅 admin 可用。
- 内置 admin 来自配置；其它管理用户保存到 `specus_management_user`。
- admin 可查看当前租户内全部客户端、凭证、映射、连接和流量；普通用户只能看到自己创建的资源。租户 ID 与 owner username 的权限比较与 Java 一样区分大小写。
- OIDC Authorization Code + PKCE 交换固定使用服务端 `redirectUri`，强制 `codeVerifier` 与 nonce；ID Token 始终以 `client_id` 校验 audience，多 audience 时还要求匹配的 `azp`。issuer+subject 首次登录只创建 USER 或以 CAS 绑定同名未绑定账号；CAS 竞争后会重新读取并仅接受完全一致的绑定，外部 `preferred_username` 不能映射内置 admin。响应仅返回本地 Specus JWT，原始 ID Token 只作为 logout hint。直接 OIDC bearer 必须配置 issuer 与 audience，并按已验证的 issuer+subject 查找已绑定且启用的本地账号，权限使用数据库当前 username/tenant/role，不信任上游同名 claim，也不能调用本地 `/auth/refresh`。JWKS 刷新带独立超时和并发合并，并限制响应体、键数量、key id 与未知 kid 缓存；刷新冷却、短时旧 key overlap、缺失/空/重复 kid 选键语义均与 Java/Nimbus 对齐。
- 客户端 HTTP 启动登录响应返回凭证所属 `tenantId`、`maxOnlineInstances`、TCP/HTTP 映射和 Peer Mesh 配置；运行时会话写入 `specus_client_session`，HTTP 登录态为 `HTTP_AUTHENTICATED`，Netty 登录成功改为 `NETTY_ONLINE`，断开、过期和服务启动清理都会改为 `DISCONNECTED`。
- 客户端 runtime token TTL、同机用户在线实例上限和创建凭证时的默认最大在线实例数来自独立 `clientAuth` 配置组，分别对应 `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS`、`SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` 和 `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES`。
- Netty 运行时登录会检查同一机器/用户在线实例上限和凭证最大在线实例，连接断开后同时回收内存在线状态和数据库在线状态。
- 连接记录和连接归档统计都带租户维度：admin 看当前租户全部数据，普通用户只看自己可见客户端产生的记录和统计。

### TLS

```bash
SPECUS_TLS_MODE=self-signed ./specus-server     # 启动时现场生成自签证书
SPECUS_TLS_MODE=file SPECUS_TLS_KEYSTORE=server.p12 SPECUS_TLS_KEYSTORE_PASSWORD=changeit ./specus-server
SPECUS_TLS_MODE=file SPECUS_TLS_CERT_FILE=cert.pem SPECUS_TLS_KEY_FILE=key.pem ./specus-server
```

TLS 同时作用于控制通道与管理 HTTP。`file` 模式优先使用 `SPECUS_TLS_KEYSTORE`
加载 PKCS12 / PFX；未配置 keystore 时回退到 PEM 证书和私钥文件。
`SPECUS_TLS_REQUIRE_ENCRYPTION=true` 时会拒绝 self-signed 和公开明文 control bind；若 TLS 在 OpenResty 等可信上游终止，必须同时设置 `SPECUS_TLS_TERMINATED_UPSTREAM=true` 并把 Go control listener 绑定到私网或 loopback 地址。

## 测试

```bash
go test ./...    # fixtures、登录/NAT/HTTP、TURN auth、附件、公共发现、client-messages、admin API、OIDC、TLS、帧边界
go vet ./...
```

协议层直接读取仓库中央 `protocol/test-vectors/control-v2` fixture，逐字节校验 v2 控制帧、NAT stream 与 malformed 拒绝样例；wire body 不允许 Deflate fixture。

## Peer Mesh 对齐状态

Go server 已对齐 Java 当前 Peer Mesh 控制面：

- `MessageType.PEER_CONTROL=5` 信令转发（`NAT_CONTROL=4`）。
- HTTP 登录响应下发 `peerMesh` 配置。
- 按租户/用户分配虚拟 IP，默认同一 `tenantId + ownerUsername` 放行。
- 管理 API：状态、设备、带 `OUTBOUND` / `INBOUND` / `BOTH` 方向的 ACL、会话列表、启停设备、清理会话；跨 owner 的 `CLIENT_TO_CLIENT` fallback 同样按方向 ACL 判断。
- 设备上报、会话授权、路径/流量上报、强制关闭和在线 roster 下发。
- 内置标准 STUN/TURN UDP relay：Binding、备用端口 NAT 探测、带临时 credential/realm/nonce/MESSAGE-INTEGRITY 的 Allocate/Refresh/CreatePermission、401/438、Send/Data Indication、`SPM2` frame 授权校验和 relay 字节计量。
- 公共传输已提供 `/api/public/transfer/ice-config`、6 个附件 REST 路径和 `/ws/public-transfer/discovery`；语法有效的非对象 discovery JSON 按缺省 `signal` 转发并保留 `payload:null`。公开 presign 来源表满后新来源直接拒绝，只由每 10 分钟后台任务清理过期窗口。
- 管理/客户端消息使用 `/ws/client-messages` 和控制通道 `CLIENT_TO_CLIENT` fallback；只有目标连接写成功才返回 `written`，写失败返回 `failed`。该状态不冒充对端应用层 `delivered` ACK。

Go client 当前已实现 Peer Mesh UDP 控制面、v2 X25519/HKDF/AES-GCM IP 数据帧、Linux `/dev/net/tun`、Windows Wintun 与 macOS utun 虚拟网卡读写、direct UDP 与标准 TURN relay data indication；代码数据面已具备通过虚拟 IP 承载业务流量的能力，真实 Windows / Linux / macOS 双机 ping、HTTP 和 relay fallback 仍需按跨语言验收矩阵手工验证。

## 包结构

- `internal/protocol` — 双向编解码(帧 + CompactBinary + NAT + HMAC)
- `internal/config` — 配置 + `SPECUS_*` 映射
- `internal/store` — 多库抽象 + schema + 查询/CRUD/归档
- `internal/auth` — apiKey 签名校验、运行时 token、密码 hash、限流、id 生成
- `internal/session` — 会话注册表(同名登录顶替)
- `internal/control` — 监听器、连接、帧读写、空闲/心跳看门狗、登录线程池
- `internal/nat` — 远端端口管理、外部连接桥接、NAT_CONTROL 下发、流量统计
- `internal/directhttp` — HTTP stream 转发入口与响应改写
- `internal/management` — admin/public REST API + DTO + 附件接口
- `internal/transfer` — Aliyun OSS V4 预签名、一次性下载授权、附件状态机、过期清理和公开限流
- `internal/security` — 本地 JWT(HS256)、OIDC(RS256/JWKS + token 交换)、TLS
- `internal/wsevents` — `/ws/connections` 事件广播；server 包另含公共发现和 client-message WebSocket hub
- `web` — 内嵌 SPA 静态资源
