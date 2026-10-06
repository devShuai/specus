# 跨语言对齐：运行时语义

> 本文是从 `cross-language-java-alignment-plan.md` 拆分出来的四篇之一。索引与拆分理由见 [该文件](../cross-language-java-alignment-plan.md)。

本篇覆盖协议之外必须表现一致的行为：多租户与权限判定、HTTP 直转与流量观测、Peer Mesh 控制面与数据面。这些不影响能否连上，但决定同一个请求在不同实现上会不会得到同一个结果。

## 阶段 2：管理用户、多租户和 owner 权限

状态：Go server 与 .NET server 已完成本地管理用户、OIDC 身份绑定、多租户和 owner 权限的源码对齐；C server 已从 smoke-test stub 推进到轻量 SQLite 管理用户、多租户和 owner 可见性。

- Go server：
  - 新增 `specus_management_user` schema 与 store CRUD。
  - 本地 JWT 写入 `tenant_id` / `role`；每次管理请求和刷新都会按当前配置或数据库重新解析账号，禁用、删除、降权或迁租后旧 token 不再保留旧权限。
  - 新增 `/api/admin/me`、`/api/admin/users`。
  - 客户端版本编目同时支持 GitHub Release 外链与服务端托管包：公开接口提供 latest 下载列表、包流式下载和版本检查；admin 保留 JSON 外链 CRUD，并可通过 multipart 上传、显式切换 latest 和删除托管包。外链具备权威大小/SHA-256 后可参与升级，托管文件的大小与摘要由服务端计算。
  - OIDC Authorization Code + PKCE 强制服务端回调地址、verifier、nonce、ID Token `client_id` audience 与多 audience `azp`；按不可变 `issuer + subject` CAS 绑定本地普通用户，竞争绑定后会重新读取并只接受完全一致的身份，不能映射内置 admin。直接 RS256 Bearer 必须同时配置 issuer 与资源 audience，并命中已绑定且启用的本地账号；权限始终采用数据库当前 tenant/role，不信任外部同名 claim。JWKS 已补响应/键数量上限、请求合并与独立超时、刷新冷却、未知 kid 负缓存、旧 key 短时重叠，以及 Nimbus 对缺失/空/重复 kid 的选键语义。
  - `/api/admin/database/initialize` 响应已补齐 Java-shaped `tenantId`，`clients` 按当前管理租户统计。
  - HTTP 启动登录响应的 `tenantId` 已改为返回凭证所属租户，避免非 default 租户客户端拿到错误运行时上下文。
  - Netty 运行时登录已按 Java 语义检查同一机器/用户单实例与凭证 `maxOnlineInstances`，并在连接断开时回收内存会话在线状态。
  - `specus.client-auth.*` 已独立于管理端 `specus.auth.*`：HTTP 启动登录 token TTL 使用 `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS`，同机用户在线实例数使用 `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES`，凭证默认最大在线数使用 `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES`；同时补齐 Java 当前 `SPECUS_LOGIN_EXECUTOR_MAX` / `SPECUS_LOGIN_EXECUTOR_QUEUE` 环境变量别名。
  - 连接记录后台归档已改为读取 Java 同名配置：`SPECUS_CONNECTION_DETAIL_RETENTION_DAYS` 控制明细保留天数，`SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS` 控制归档间隔；保留天数小于等于 0 时关闭归档，归档 cutoff 使用 UTC 自然日边界。
  - 客户端会话历史保留窗口为 Go server 独有扩展（Java 未定义）：`SPECUS_CLIENT_SESSION_RETENTION_DAYS`（默认 30）在同一归档任务里删除已过期且断线时间早于 cutoff 的 `specus_client_session` 行；在线或未过期的会话永不删除，`0` 关闭清理。重连会不断退役旧会话行，而该表位于登录热路径上，因此需要明确的保留口径。
  - 新增 `specus_client_session` schema 与 store 操作；HTTP 启动登录写入 `HTTP_AUTHENTICATED`，Netty 登录成功改为 `NETTY_ONLINE`，断开和过期改为 `DISCONNECTED`，启动时会清理上一进程遗留的在线会话。
  - admin 可管理用户和查看当前租户内全部资源。
  - 普通用户只能看到自己创建的客户端、启动凭证、TCP 映射、HTTP route、连接记录、流量和归档统计。
  - `specus_traffic_usage` 已补齐 `tenant_id`，每日总流量写入、列表和历史空租户行兼容读取与 Java 租户归属一致。
  - `specus_connection_record` 已补齐 `tenant_id`，连接记录写入、overview 统计、分页查询和 `/ws/connections` 事件广播均按租户收敛；WebSocket 事件携带 Java-shaped `tenantId`，普通用户只接收自己 owner 客户端的连接事件。
  - `specus_connection_stat` 已补齐 `tenant_id`，归档聚合按 `tenantId + clientName + statMonth` 分组；管理查询先按租户收敛，再按普通用户可见 clientId 过滤，避免不同租户同名客户端的月度统计互相污染。
- .NET server：
  - 新增 `ManagementUser` EF entity、`ManagementContext`、`ManagementUserService`。
  - 初始化时幂等创建 `specus_management_user` 表。
  - 本地 JWT 写入 `tenant_id` / `role`；每次管理请求和刷新都会按当前配置或数据库重新解析账号，禁用、删除、降权或迁租后旧 token 不再保留旧权限。
  - OIDC Authorization Code + PKCE 强制服务端回调地址、verifier、nonce、ID Token `client_id` audience 与多 audience `azp`；按不可变 `issuer + subject` CAS 绑定本地普通用户，竞争绑定后会重新读取并只接受完全一致的身份，不能映射内置 admin。直接 RS256 Bearer 必须同时配置 issuer 与资源 audience，并命中已绑定且启用的本地账号；权限始终采用数据库当前 tenant/role，不信任外部同名 claim。JWKS 已补响应/键数量上限、并发刷新隔离、刷新冷却、未知 kid 负缓存、旧 key 短时重叠，以及 Nimbus 对缺失/空/重复 kid 的选键语义。
  - 管理 API 使用 `ManagementContext` 过滤客户端、凭证、映射、连接记录、流量和统计。
  - 新增 `Specus:ClientAuth` / `SPECUS_CLIENT_AUTH_*` 配置组：HTTP 启动登录 token TTL、同机用户在线实例上限和凭证默认最大在线数均从该组读取；`SPECUS_LOGIN_EXECUTOR_CORE`、`SPECUS_LOGIN_EXECUTOR_MAX`、`SPECUS_LOGIN_EXECUTOR_QUEUE` 已显式映射到 .NET 配置键。
  - 新增 `Specus:ConnectionRecord` / `SPECUS_CONNECTION_*` 配置组与 `ConnectionArchiveService` 后台任务：按 Java 语义把早于保留窗口的连接明细聚合到 `specus_connection_stat` 后删除，默认保留 60 天、每小时执行一次，保留天数小于等于 0 时关闭归档。
  - `/api/admin/database/initialize` 会使用当前 admin 管理上下文执行幂等初始化，响应包含 `tenantId`，`clients` 按当前租户统计。
  - 客户端版本编目同时支持 GitHub Release 外链与服务端托管包：公开接口提供 latest 下载列表、包流式下载和版本检查；admin 保留 JSON 外链 CRUD，并可通过 multipart 上传、显式切换 latest 和删除托管包。权威外链可参与升级；托管元数据、唯一 latest 约束和旧库回填已补齐 SQLite / MySQL / PostgreSQL migration。
  - `specus_traffic_usage` EF model、启动兼容补列、flush 写入和管理查询已补齐 `tenant_id`；旧库空租户行会在后续 flush 时归属到客户端租户。
  - `specus_connection_record` EF model、provider snapshot、启动兼容补列、写入和管理查询已补齐 `tenant_id`；`/ws/connections` 事件携带 Java-shaped `tenantId`，并按租户与 owner 权限过滤订阅者。
  - `specus_connection_stat` EF model、provider snapshot、启动兼容补列、历史行回填和管理查询已补齐 `tenant_id`；fresh migration 后由启动兼容 SQL 幂等补列，旧库按 clientId / clientName 回填到客户端所属租户。
- C server：
  - SQLite 初始化时幂等创建 `specus_management_user`，并提供 store CRUD。
  - `/auth/login` 仅在显式配置非空 `SPECUS_AUTH_PASSWORD` 时启用内置 admin 密码，不再提供 `admin/admin` 默认凭据；配置 `SPECUS_DATABASE_PATH` 后，也会校验启用状态的 `specus_management_user`。人类管理口令已使用 Java / Go / .NET 共享的 `$pbkdf2-sha256$v=1$i=...` 格式（默认 210,000 轮），旧 SHA-256 hex 在登录成功后原地升级；客户端凭据和逐 route Basic 密钥仍按高熵 secret 语义保留 SHA-256 digest。所有非空登录请求会同时计入来源 IP 和大小写不敏感账号的固定窗口预算，默认 `20/10` 次每 300 秒，超限统一返回 `429 + Retry-After`，成功只清账号预算。响应返回 Java-shaped `accessToken/tokenType/expiresIn`，token 为 HS256 JWT，包含 `iss=specus`、`sub`、`tenant_id`、`role`、`iat`、`exp`。
  - 真实 C 管理 HTTP socket 已对 `/api/admin/**` 和 `/auth/refresh` 校验 `Authorization: Bearer <token>`；与 Java `ManagementContextResolver` 一致，token 只标识账号，每个鉴权请求与每次续期都会重新读取 SQLite 管理用户（只读查询、无缓存）：内置 admin 须仍允许密码登录，库内用户须存在、启用且仍属 token 的租户，租户/角色/admin 权限取当前记录；否则请求返回 `403 账号未绑定、已禁用或权限已撤销`、续期返回 `401 账号已禁用、不存在或不再允许本地登录`，用户存储不可读时返回 500。`/auth/refresh` 按当前记录签发新 token，降级的 admin 续期后为 `USER`（2026-10-06 前 C 直接信任并复制 JWT 中的租户与角色）。C 单测用的直接 response builder 仍保留内置 admin 便捷上下文，方便 smoke-test endpoint body。
  - `/oidc-config` 返回 Java-shaped 浏览器登录配置：`configured`、`authorizationEndpoint`、`endSessionEndpoint`、`clientId`、`redirectUri`、`scope` 和 `passwordLoginEnabled`；`/oidc/token` 支持 Authorization Code + PKCE 代理交换、HTTP/HTTPS token endpoint、可选 Basic client secret，并把 IdP 的 `access_token`/`id_token` 原样放进 `accessToken/idToken/tokenType/expiresIn`。HTTPS 默认校验证书链和主机名，可显式配置私有 CA，不提供跳过校验开关。与 Java/Go/.NET 不同，C 不校验 ID Token 的 issuer/audience/nonce、不解析或绑定本地管理用户、不签发本地 Specus token，管理 API 又只接受本地 HS256 JWT，所以 OIDC 登录在 C 上不能进入管理 API；`admin_http_tests` 只覆盖 `/oidc-config` 形状与对明文 HTTP mock endpoint 的代理交换（HTTPS 证书链/主机名/私有 CA 由共用客户端的 `http_client_tests` 覆盖），Java `OidcControllerTests`/`SecurityConfigOidcTests` 的语义在 C 没有对应测试（见 [C server 测试对照](c-server-test-map.md)）。
  - `/api/admin/me` 返回内置 admin 视图；`/api/admin/users` 返回内置 admin 加当前租户 DB 管理用户，`POST /api/admin/users`、`PUT /api/admin/users/{username}`、`DELETE /api/admin/users/{username}` 在 SQLite 模式下可用，内置 admin 不允许被 DB mutation 修改。
  - 客户端、TCP 映射、HTTP route、连接记录、连接归档统计、日流量汇总和资源流量汇总接口已接入基础 Java-shaped 可见性规则：admin 访问当前租户所有客户端，普通用户只访问自己创建的客户端及其下属数据。
  - `connection_record` 已补齐物理 `tenant_id` 字段、启动兼容补列和历史行回填；运行时登录成功/失败写入真实租户，分页查询优先按记录租户过滤，WebSocket 连接事件继续使用 Java-shaped 顶层 `tenantId`。
  - `/api/client/auth/login` 在 SQLite 模式下会读取 `specus_client_credential`，按 Java canonical HMAC 校验 `apiKey/timestamp/nonce/machineFingerprint/osUser`，签名通过后原子消费 `(apiKey, nonce)` 并保留 120 s（进程内有界存储，重放返回 Java 同款 `400 客户端签名 nonce 已使用`，环境 token 模式同样生效），为 `credential + machineFingerprint + osUser` 创建或复用唯一客户端身份，写入 `specus_client_session=HTTP_AUTHENTICATED`，并返回 Java-shaped `tenantId`、`clientId`、`clientName`、`clientSessionId`、`accessToken`、`tokenTtlSeconds`、`nettyHost`/`nettyPort`/`nettyTls`、`maxOnlineInstances`、`policy`、TCP 映射和 HTTP route。Netty 控制通道随后按 `clientSessionId + accessToken` 验证该 session，检查过期、客户端/凭证启用状态、同机用户实例数和凭证最大在线实例数，登录成功标记 `NETTY_ONLINE`，断开标记 `DISCONNECTED`，启动时会清理上一进程遗留的 `NETTY_ONLINE` 与打开的连接记录。无匹配 SQLite 凭证时仍保留环境变量驱动的 smoke-test token 模式；只要配置了任意 `SPECUS_CLIENT_API_KEY` / `SPECUS_CLIENT_SECRET` / `SPECUS_CLIENT_SECRET_HASH`，就要求配置完整并校验签名，避免半配置时静默降级。
  - 当前阶段补齐 Java `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` 与 `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` 环境变量别名，旧的 `SPECUS_CLIENT_TOKEN_TTL_SECONDS` / `SPECUS_CLIENT_MAX_ONLINE_INSTANCES` 仍保留为兼容别名；控制通道已按 `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES`（默认 `1`）限制同一 `credential + machineFingerprint + osUser` 的在线实例数。
  - 会话生命周期（Issue #35「shutdown / reconnect / stale channel」）：控制登录不再要求 session 仍为 `HTTP_AUTHENTICATED`——此前普通断线后用同一 `clientSessionId + accessToken` 重连会被答以「同一台机器和用户已经有在线实例」，Go/Java 客户端据此停止重连；现在与 spec「token 在过期前可复用」一致。被同一机器用户之后的 HTTP 登录取代的旧 session 一律答「客户端访问令牌无效」，客户端会刷新而不是复用旧 session（Java/Go 只按 TTL 拒绝，这是 C 更严格的一侧）。计数前按 Java `closeStaleOnlineSessions` 把该凭证下没有存活 control 承载的 `NETTY_ONLINE` 行置为 `DISCONNECTED`。同一客户端的新 control/data 登录替换旧连接而不是拒绝（旧连接记 `REPLACED_BY_NEW_LOGIN`）：control 登录同时关闭旧 data 及其 NAT stream、pending Direct HTTP 和公网监听，旧 session 无法再挂 data；旧连接退出时只有在没有其它 control 承载同一 session 时才写 `DISCONNECTED`。control 断开只连带关闭同一 session 的 data；data 断开不再反向关闭 control（此前 C 独有，现与 Java/Go 一致）。同机用户计数不含正在登录的 session 本身（spec「同一客户端会话…新连接替换同角色旧连接」），因此旧 socket 无 FIN 半开时同一 session 可立即重登；Java/Go 会把该 session 自身计入并拒绝，直到读空闲超时。死连接由 `SPECUS_CONTROL_READ_IDLE_SECONDS` 关闭并退出在线投影。`SIGTERM`/`SIGINT` 时停止 accept、关闭全部 control/data（含未登录连接），最多等待 10 s 让每条连接自行写 session `DISCONNECTED` 与连接记录 `SERVER_SHUTDOWN`，再统一收尾仍打开的记录，最后才停后台任务；启动时按 Java/Go 把遗留打开记录记 `SERVER_RESTARTED`。`specus_c_session_lifecycle_tests` 以真实 server 进程和 socket 覆盖上述路径。
  - SQLite 模式下已补 Java-shaped 客户端凭证管理、客户端应用包下载链接管理、客户端管理、TCP 映射管理、HTTP route 管理、连接记录分页查询、连接归档统计查询和流量汇总查询：`POST /api/admin/database/initialize`、`GET/POST /api/admin/client-credentials`、`PUT/DELETE /api/admin/client-credentials/{id}`、`GET /api/public/client-downloads`、`GET/POST /api/admin/client-downloads`、`PUT/DELETE /api/admin/client-downloads/{id}`、`GET/POST /api/admin/clients`、`PUT/DELETE /api/admin/clients/{id}`、`GET /api/admin/specus-mappings`、`POST /api/admin/clients/{id}/specus-mappings`、`POST /api/admin/clients/{id}/nat-control`、`PUT/DELETE /api/admin/specus-mappings/{id}`、`GET /api/admin/http-routes`、`POST /api/admin/clients/{id}/http-routes`、`PUT/DELETE /api/admin/http-routes/{id}`、`GET /api/admin/connections?clientId=&success=&from=&to=&page=&size=`、`GET /api/admin/connection-stats?clientName=&limit=`、`GET /api/admin/traffic?clientId=&limit=`、`GET /api/admin/traffic/resources?type=&clientId=&limit=`。这些查询在 SQL 层按当前管理上下文过滤，分页 total 也是过滤后的结果；数据库初始化接口仅 admin 可调用，响应包含 `initialized`、`tenantId`、`orm=sqlite3`、`dialect=sqlite` 和当前租户客户端数；`nat-control` 会校验客户端权限并向在线 control session 推送重载后的完整 mapping/route 快照，成功返回 `200`，离线返回 Java-shaped `409`。客户端应用包下载链接按 Java 当前语义作为全局资源维护，仅 admin 可增删改查，公开接口只返回启用项。HTTP/TCP 明细接口在 SQLite 模式下已接入真实表查询：HTTP exchange 和 TCP frame 支持分页，TCP frame 详情按 id 查询，TCP stream 按 channel 串流；无匹配记录时才返回空分页、`404` 或空串流对象。未配置 `SPECUS_DATABASE_PATH` 时资源列表返回环境变量快照，下载链接和连接记录返回空列表/空分页，连接统计和流量统计返回空数组，mutation 返回 `503`。
  - `/api/admin/overview` 与 `/api/admin/metrics` 使用同一套 SQLite + `SPECUS_TCP_MAPPINGS` 快照，返回当前管理上下文可见的 TCP 映射数量。
  - 管理 HTTP socket 的 `/ws/connections` 使用两步一次性 ticket：先 `POST /api/admin/ws-tickets` `{"endpoint":"connections"}`，再 `GET /ws/connections?ticket=...` Upgrade；JWT query 与重用 ticket 返回 `403 X-Auth-Reason`，并处理 ping/pong 和 close 帧。源码在运行时登录成功/失败时广播 Java-shaped `created` 事件，已认证控制连接断开时广播同一记录的 `updated` 事件，并按租户/owner 过滤。测试只覆盖 ticket 签发（含匿名拒绝、未知 endpoint 拒绝）与非 Upgrade 请求的 `426`；Upgrade 后的事件推送和过滤没有测试，对应 Java `ConnectionEventsWebSocketHandlerTests` 未覆盖。
  - Peer Mesh 管理与运行时已按 Java 语义接通：status/device/ACL/session/stats、service-sharing、service CRUD/import/audit 均使用区分大小写的 tenant/owner 可见性；认证 `PEER_CONTROL` 会处理 roster、offer/answer/candidates/close、路径/流量/虚拟设备报告并创建真实 session。客户端/设备/ACL/共享/服务 mutation 后立即向在线租户推新配置、roster 和 catalog，撤权时发送空 catalog 清除陈旧可见性。

## 阶段 3：HTTP 直转与流量观测

状态：Go / .NET / C 已推进到数据库 / Elasticsearch 双后端；前端预览体验仍可继续细化。

- Go client 与 .NET client 已补齐 Java `DirectHttpForwarder` 语义：内网 HTTPS upstream 允许使用自签证书；请求体上限 16 MiB、响应体上限 64 MiB；单段 `Range` 会按 8 MiB 窗口收窄，复杂 multi-range 保持原样交由 upstream 处理；默认不自动重定向、不自动解压；`relativePath` 中的 `//` 按 Java 一样作为同 host 下的普通双斜线路径保留；请求体超限、响应体超限、未配置 route、非法 route 目标、非法/越界转发路径等用户可见错误文案已收敛为 Java 中文消息。
- Go client 与 .NET client 已补齐 Java HTTP route WebSocket 隧道语义：识别 NAT `OPEN source=ws`，按当前 HTTP route 快照构造 `ws://` / `wss://` 上游地址，`relativePath` 中的 `//` 作为同 host 下普通双斜线路径保留；过滤 hop-by-hop 与 WebSocket 握手头；WebSocket target 构造失败时的未配置 route、非法 scheme、非法 route 地址和非法 `relativePath` 等错误文案已收敛为 Java 中文消息；内网 `wss` upstream 按 Direct HTTP 的运维场景信任自签证书；本地 WebSocket frame 使用 SWS2 envelope 封装进 NAT `DATA`，服务端回传的 `DATA` 按同一 envelope 还原，任一侧断开都会通过 `FIN/RST` 清理 stream。
- Java client 已用 frame-preserving Netty protocol handler 关闭默认的 Ping 自动应答、Pong 丢弃与 Close 消费；Java、Go、.NET 与 Android client 因而都会把 upstream continuation/text/binary/ping/pong/close 原样送入 SWS2。最多 16 MiB 的原始 data frame 会在需要时规范化为不超过 NAT DATA 上限的 continuation envelopes，控制帧保持原子性。
- .NET server 的 `/http/{clientName}/{route}/**` 已补齐 Java/Go WebSocket Upgrade 分流：逐 route Basic 在 `101` 前校验，受保护 route 消费并移除入口 Authorization；Upgrade 后发送 `OPEN source=ws`，双向使用 SWS2 `DATA`，按实际写入返还 `WINDOW_UPDATE`。公网浏览器 Ping 由入口本地串行回复同 payload Pong，不进入 SWS2；浏览器 Pong 仍透传到 upstream。浏览器关闭传播 `CLOSE + FIN`，客户端 `FIN/RST` 只关闭浏览器侧并幂等释放 stream。
- Go server 与 .NET server 的 Direct HTTP 入口已按 Java `request.getRequestURI()` 语义保留原始路径编码：服务端从 raw path 截取 `/http/{clientName}/{route}` 后的部分，`%2F` 不会变成真实斜线，中文等非 ASCII 字符会保持/恢复为 UTF-8 percent-encoding，`rawQuery` 仍保留原始查询字符串。
- Go server 与 .NET server 已对齐管理契约：
  - `specus_mapping.detail_capture_enabled`。
  - `http_route_mapping.detail_capture_enabled`。
  - `http_route_mapping.path_rewrite_enabled`。
  - 管理 API 创建、列表、更新均返回/接收 `detailCaptureEnabled`，HTTP 路由额外返回/接收 `pathRewriteEnabled`。
  - 新库 schema 默认关闭这些开关；Go server 与 .NET server 启动初始化会给老库幂等补列。
- Go server 的 TCP 转发背压已补齐 Java/.NET high/low watermark 语义：控制通道写入与外部 socket 写入都会按 `SPECUS_NETTY_WRITE_BUFFER_LOW_WATER_MARK` / `SPECUS_NETTY_WRITE_BUFFER_HIGH_WATER_MARK` 统计待写字节；超过高水位暂停对应读循环，回落到低水位后恢复，不再仅依赖同步写的自然 TCP 回压。
- Go server、.NET server 与 C server 已接入 HTTP 响应路径改写行为：当 `pathRewriteEnabled=true` 时，服务端会在回写浏览器前尝试改写 `text/html` / `text/css` 中的绝对路径，并在 HTML 中注入 Java 对齐、同源外链的 `/specus-http-route-runtime.js?v=4`，避免上游 CSP 阻止 inline script；runtime 覆盖 `fetch`、`XMLHttpRequest`、`history.pushState/replaceState`、动态 DOM/CSS、`EventSource` 和 `WebSocket`，并处理同源双斜线与 query 裸大括号。改写后返回给浏览器的响应会剥离失效的 `Content-Encoding` / `Content-Length`，但 HTTP 明细采集仍保留客户端原始响应头，便于排查上游真实行为；C server 当前支持 `gzip`、zlib `deflate` 与 raw `deflate` 解码后改写。
- Java、Go、.NET 与 C server 的持久化 HTTP route 已对齐可选 Basic 入口认证：管理 API 使用
  `authEnabled/authUsername/authPassword` 写入，只返回 `authPasswordConfigured`；密码只保存哈希。HTTP 与支持
  WebSocket 的实现均在打开隧道/Upgrade 前校验，受保护 route 的入口 Authorization 不透传 upstream 或写入明细。
  四个 server 的入口都 fail closed：没有服务端记录的 route（含已删除但客户端仍在转发的 route）、未启用的 route
  与已停用客户端的 route 一律 `404`，不再按"未持久化即公开"放行；C server 的 `SPECUS_HTTP_ROUTES` 作为服务端
  配置的公开 route 保留。`NAT_CONTROL` 始终携带完整 `httpSpecusConfigList`，删除最后一条 route 时下发空数组。
- Go server 与 .NET server 已补齐数据库版 HTTP/TCP 明细采集链路：
  - 新增 `specus_resource_traffic_usage`，并按 TCP 映射 / HTTP route 聚合资源级每日流量。
  - 资源级流量和每日总流量均带 `tenant_id`，管理查询按当前租户和可见客户端收敛。
  - 新增 `specus_http_traffic_exchange` 和 `specus_tcp_traffic_frame` 表。
  - Direct HTTP 成功、错误响应和 TCP 双向 payload 都会按通道开关写入明细。
  - HTTP 记录保留完整请求/响应 body、Header、响应类型、耗时、状态码和来源信息。
  - TCP 记录保留完整二进制 payload、预览文本、方向、源/目的地址、channelId、streamId、streamIndex 和 streamOffset。
  - 管理 API 已支持资源级流量列表、HTTP/TCP 分页查询、HTTP 字段搜索、TCP 单帧详情和 TCP 串流查询。
  - DB / Elasticsearch HTTP 明细搜索已对齐 Java 语义：`q` 按空白分词，每个 token 必须命中；同一个 token 可在所选字段组内 OR 匹配；默认 `summary` 不扫 header/body，`all` 才包含 header/body；`method`、`status`、`responseBodyType/responseDataType` 使用精确匹配；支持 `id`、`client/clientId`、`resource/resourceId`、`remote`、`contentType`、`error`、`requestHeaders`、`responseHeaders`、`requestBody`、`responseBody` 等字段别名。
  - DB / Elasticsearch HTTP 明细 `responseBodyType/responseDataType` 过滤已补齐 Java 老数据兼容：不支持的类型值视为未指定过滤条件；历史记录缺少 `response_body_type` 时，会按 `response_content_type` 和 `response_bytes=0` 推断 `json/html/xml/image/video/audio/form/script/text/binary/empty`。
  - Direct HTTP 入口请求体超过上限时，Go server 与 .NET server 已和 Java 一样返回 `413` 的同时写入 HTTP 明细记录，保留请求行、headers、已读取 body、错误响应和错误原因，避免超限请求在观测页面消失。
  - Direct HTTP 客户端离线、控制通道写出失败、控制通道等待异常、客户端返回 `error` 时，Go server 与 .NET server 已和 Java 一样把最终回写浏览器的纯文本错误响应写入 HTTP 明细：`Content-Type:text/plain;charset=UTF-8`、错误 body 和错误原因保持一致；Go server 离线文案已对齐 Java 的 `客户端不在线: {clientName}`，写出失败文案已对齐 Java 的 `HTTP 转发请求发送失败`。写出失败在 Java 中属于已得到客户端 error response 的路径，因此 Go server 也已对齐为仍记录 HTTP upload、download 记 0，而不是按 dispatcher exception 跳过汇总记账。
- Go server 与 .NET server 已补齐 Java 风格 Elasticsearch 可选存储：配置 `SPECUS_ELASTICSEARCH_URIS` 后，HTTP/TCP 明细写入 ES，管理查询从 ES 读取，并按 HTTP 100GB / TCP 10GB 默认体积上限清理最旧记录；未配置时仍使用数据库。
- Go server 与 .NET server 的 HTTP/TCP 明细采集热路径已对齐 Java 队列模型：转发线程只做通道开关判定与入队，后台按 `SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` 周期批量 flush，单类队列由 `SPECUS_TRAFFIC_CAPTURE_MAX_PENDING` 限制，单次 flush 由 `SPECUS_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` 限制；管理明细查询默认不强制 flush，需要追最新数据时可显式传 `flush=true`。
- Go server 与 .NET server 已对齐 `gzip`、`deflate` 的 zlib / raw deflate 兼容解码；两者均已支持 `br` 预览解码。后续仍可继续细化更复杂内容类型的前端预览体验。
- Go server 与 .NET server 已补齐 Java 的逐 HTTP route 媒体采集：`mediaCaptureEnabled` 默认关闭，原始响应通过有界并发 multipart 上传到专用 RustFS/S3 兼容存储；支持 HLS/DASH/渐进式媒体分类、清单引用和改写、Range 去重、中断区间保留、跨对象连续区间回放、短期 tenant 绑定播放票据、可选缺失区间回源，以及对象和数据库过期清理。完整 RustFS 配置初始化失败会阻止启动；配置关闭或不完整时安全禁用。
- Go server 与 .NET server 的媒体管理/公开端点已按 Java 对齐：管理列表、播放、manifest、asset 和播放票据先做 tenant/owner 可见性过滤；公开 `play/manifest/asset` 只接受内存短期票据并支持 GET/HEAD，Range 空洞返回 `416`，无效或过期票据返回 `404`。
- C server 的 Direct HTTP/WS v2 bridge：`OPEN/DATA/FIN/WINDOW_UPDATE` 流转、query 大括号编码、百分号编码路径、chunked 请求体、6 MiB 下载/2 MiB 上传和 WebSocket/SWS2 由 `nat_e2e_smoke.sh`、`direct_route_e2e.sh` 对真实客户端进程验证；route Basic 鉴权（`test_direct_http_route_authentication`）、HTML/CSS 改写与有界 gzip/deflate（`admin_http_tests`、`decompression_limits_tests`）、`RST` 与 SWS2 违规（`direct_websocket_tests`）只有单测，不在 E2E 内。Java、Go、.NET client 的三条脚本均在 CI 中通过（PR #127 的 run 37387624598，见[环境验证](environment-verification.md)）。mapping/route mutation 会热推权威全集（`runtime_config_e2e.sh`），手工 push 在线 `200`（`runtime_config_e2e.sh`）、离线 `409`（`admin_http_tests`）。
- C server 的 WebSocket/SWS2 已补齐与 Java/Go/.NET 对齐的严格状态机，由 `direct_websocket_tests.c` 经真实监听端口驱动：中央 SWS2 向量的 canonical 与全部 malformed 样例既做编解码重放、也作为客户端 DATA 送入 stream；浏览器侧校验 mask、RSV（未协商扩展必须为 0）、opcode、最短长度编码、控制帧、continuation/FIN 序列、UTF-8 与 close code/reason，单个原始 data frame 在 16 MiB 内规范化为 SWS2（首段保留 opcode、其余为 continuation、仅末段继承 FIN），违规以 `1002`/`1007`/`1009` 关闭浏览器并把同一 close code 作为终止 SWS2 CLOSE 发给客户端；客户端侧按 Go/Java 重组时的消息规则（孤立 continuation、未完消息中的新消息、16 MiB、RSV、UTF-8）逐帧校验，与 .NET 一样保留分片边界写给浏览器，违规回 `RST 30`（FIN 后 DATA 为 `RST 7`）并以 `1002` 关闭浏览器。close 握手两向闭环：浏览器 CLOSE 立即回显并转为 SWS2 CLOSE + FIN；客户端 CLOSE 或无 CLOSE 的 FIN（浏览器收到 `1001`）最多等待 5 秒浏览器回复再回送 SWS2 CLOSE + FIN；CLOSE 之后同方向不再收发任何帧，客户端 CLOSE 后的帧回 `RST`，客户端 RST 以 `1011` 关闭浏览器，CLOSE 拿不到 NAT credit 时 5 秒后改发 `RST 31`。各语言在违规时的具体 close/RST 码并不完全相同（例如 Go 对浏览器协议错误向客户端回 `1011`），C 采用 RFC 6455 码并向客户端镜像同一码。
- C server 已补可选 Elasticsearch HTTP/TCP 明细写入、查询和容量清理（`elasticsearch_traffic_tests`，对 fake ES）；未配置时继续使用 SQLite。逐 route 媒体采集已支持专用 S3-compatible/RustFS 校验、HLS/DASH/渐进式对象、multipart、Range 去重与跨对象连续区间、incomplete 稀疏回放、可选回源、tenant ticket、manifest/asset 和定时过期清理（`media_capture_tests`，对 fake S3；未接真实 RustFS）。公共 discovery 已通过 C↔C 双实例（`public_discovery_cluster_e2e`）和 C↔Java Redis（CI 中的 `java_c_discovery_interop.sh`）的 roster/名称/双向信令混部门禁；Go/.NET server 与 C 的混部没有证据。

## 阶段 4：Peer Mesh 控制面与数据面

状态：Go、.NET server 的控制面和标准 STUN/TURN relay 已对齐 Java；C server 的同类能力只有进程内测试证据（`peer_mesh_tests`、`stun_turn_tests`，TURN Refresh/ChannelBind/ChannelData/过期清理未测），没有任何客户端（包括 Android）× C server 的 Peer Mesh 或 TURN 端到端运行；Go client 与 .NET client 已补齐 Linux TUN / Windows Wintun / macOS utun、X25519/HKDF/AES-GCM frame 与 UDP 数据面接入；Android client 已完成控制通道、VpnService、加密 UDP direct/TURN relay 的源码与 JVM 协议测试，真机验收仍单列保留。

- Go server：
  - 新增 `Specus:PeerMesh` / `SPECUS_PEER_MESH_*` 配置，默认关闭，默认网段 `100.96.0.0/11`。
  - HTTP 登录响应下发 Java-shaped `peerMesh` 配置。
  - 新增 `peer_mesh_device`、`peer_mesh_acl`、`peer_mesh_session` schema。
  - 实现虚拟 IP 分配、同租户同 owner 默认放行、显式 ACL、会话授权、设备上报、路径/流量上报、强制关闭、roster/config 下发。
  - 已实现 Java 兼容标准 STUN/TURN UDP 服务：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、ChannelBind/ChannelData、`SPM2` frame relay 授权和 relay 字节计量；allocation 过期后按 Java 语义拒绝 refresh 并由新 Allocate 重建。
  - 管理 API 已支持状态、设备、ACL、会话查询与清理，并补齐 `/api/admin/peer-mesh/stats`：按 Java 规则统计 `reportedSessions=count(rttMillis)`、`activeDirectRatio`、`pathType × status` 明细和 NAT 类型分布。
- .NET server：
  - 新增 `PeerMeshOptions`、环境变量映射、EF entity、三套 provider migration 与启动兼容建表。
  - 控制通道识别并转发 `PEER_CONTROL`，登录成功后推送 config / roster。
  - 已实现 Java 兼容标准 STUN/TURN UDP HostedService：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、ChannelBind/ChannelData、`SPM2` frame relay 授权和 relay 字节计量；allocation 过期后拒绝 refresh 并由新 Allocate 重建。
  - HTTP 登录响应与公开 `/api/public/peer-mesh/stun-config` 均下发自建 STUN/TURN 与公共 STUN 列表。
  - 管理 API 与 Go/Java 对齐，并补齐 `/api/admin/peer-mesh/stats`：按 Java 规则统计 `reportedSessions=count(rttMillis)`、`activeDirectRatio`、`pathType × status` 明细和 NAT 类型分布。
- Go client：
  - 已读取 Java 启动配置里的 `peerMeshDevice`、`peerMeshTunName`、`peerMeshMtu`。
  - 登录时生成并持久化 X25519 peer key；上报格式已改为 Java 兼容的 X.509 DER public key，同时保留读取旧 raw key 文件能力。
  - 已识别 HTTP 登录响应与 `PEER_CONTROL` 下发，支持 `peer-config`、`roster`、`session-grant`、`candidates`、`close`。
  - 已实现 Peer Mesh UDP 控制面：标准 STUN/TURN `Binding` / `Allocate` / `Refresh` / `CreatePermission` / `Send` / `Data Indication`、host/srflx/public-stun/relay candidate 上报、UDP connectivity check、`path-report`。
  - 已实现固定 `SPM2` 数据帧：X25519 + HKDF-SHA256 按方向派生 traffic key/nonce prefix，AES-GCM AAD 绑定 session/sequence，使用单调 64 位 counter nonce 与 4096 包 replay window。
  - 已实现 Linux `/dev/net/tun` 虚拟网卡：配置 /32 虚拟 IP 与 MTU；TUN 出站 IPv4 packet 按目标虚拟 IP 查 peer session 后走 direct UDP 或标准 TURN relay；入站 frame 解密后写回 TUN。
  - 已实现 Windows Wintun 随包加载：Go client 通过 `go:embed` 内置 `native/windows/<arch>/wintun.dll`，运行时解压到本地缓存后加载；仍可通过 `SPECUS_PEER_MESH_WINTUN_DLL` 或可执行文件旁 native 目录覆盖，配置 /32 虚拟 IP 与 MTU，并接入同一套加密数据帧。
  - 已实现 macOS `utun`：通过 `com.apple.net.utun_control` 创建 utun 设备，配置 /32 虚拟 IP 与 MTU，读写时处理 Darwin utun 4 字节地址族前缀，并接入同一套加密数据帧。
  - 已对齐 Java per-peer OS 路由同步（`syncPeerRoutes`）：虚拟网卡不再安装 mesh 网段路由（配置时会静默清理残留网段路由），startOrUpdate（含配置未变的轻量刷新）、roster 更新和 candidates 信令合并时按在线 peer 虚拟 IP 增删 /32 host 路由，设备关闭时清理全部已同步路由；Linux TUN / Windows Wintun / macOS utun 三个平台实现，noop 设备保持 no-op。
  - 已对齐 Java 虚拟包目标过滤：TUN 出站包目标为组播/保留段/受限广播、mesh 网段 network/broadcast 边界地址、本机虚拟 IP，或不属于任何在线 peer 时早期丢弃并按 30 秒节流记录 debug 日志，不再进入 pending 队列或按 flow 告警。
  - roster 删除语义已对齐 Java `updateRoster` 清空重建：被移出 roster 的 peer 立即从 peers 表消失（对应 host 路由同步移除），仍在 roster 中的 peer 保留已学 candidates，`probeKnownCandidates` 不受 roster 推送影响。
  - 已按 Java 语义在 token 快过期前主动刷新 HTTP 登录态，刷新成功后热更新 TCP 映射、HTTP route 和 Peer Mesh 配置，不中断当前控制连接。
  - 已按 Java 语义周期上报 `traffic-report` 增量 direct 字节；relay 字节由 server 的标准 TURN relay 热路径计量，避免重复统计。
  - NAT 探测上报值已收敛为 Java 枚举：`NO_NAT`、`PORT_PRESERVED_NAT`、`PORT_RESTRICTED_NAT`、`FULL_CONE_OR_RESTRICTED_NAT`、`SYMMETRIC_NAT`、`NAT`；已消费 server 主端口、备用端口和公共 STUN 观测。与当前 Java 语义一致，`SYMMETRIC_NAT` 只作为观测结果，不再一票否决 direct candidate/check/data；直连失败后再回退标准 TURN relay。
  - relay candidate 请求节流已对齐 Java：allocation 新鲜时 60 秒内不重复请求，allocation 缺失或快过期时 15 秒内不重复请求；alternate NAT probe 15 秒内不重复发送。
  - 收到对端 connectivity check 时会和 Java 一样立即记录入站 direct/relay 路径；relay data 入站时同步刷新 `relayTargetAllocationId`，避免只能等本端主动探测成功后才可回包。
  - 路径选择细节已对齐 Java：已绑定 `relayTargetAllocationId` 时数据面优先走 relay；direct 路径 45 秒内仍健康时不会被本端 relay check-response 抢占；收到 direct 数据帧会清理旧 relay allocation，避免路径状态残留。
  - `path-report` 与 active path 日志节流已对齐 Java：路径变化立即上报；路径不变时 60 秒内不重复刷控制面。
  - TUN 出站虚拟包在 session/path 未就绪时会按 Java 策略短暂排队：每个 peer 最多 32 个、30 秒 TTL；路径准备会主动重新上报 candidates / 触发 connectivity check，主动探测或收到对端数据导致路径就绪后都会 flush，避免 TCP SYN 等第一批包被直接丢弃。
  - UDP 数据报分类已对齐 Java/.NET 的“解析成功才归类”口径：`SPM2` magic `0x53504d32` 的高 16 位 `0x5350` 落在 TURN ChannelData 通道号区间 `0x4000-0x7fff`，此前 Go 只按通道号区间判断，导致所有 direct 数据帧被误判为 ChannelData 并在长度校验失败后丢弃；现改为先尝试 `parseTurnChannelData`，失败再依次判断 STUN、`SPM2` 数据帧、probe。与 Java/.NET 的唯一有意差异：ChannelData 解析成功但通道未绑定或来源不是 relay 时，Go 会继续向下分类而不是直接返回，以覆盖上述 magic 碰撞。
  - 已对齐 Java `DataPlaneWorker` 有界数据面：`SPM2` 数据帧按 session id 分片提交给 2-8 个 worker（随 CPU 数收敛）、每片队列 2048，队列满即丢帧并按 session 30 秒节流记日志；解密与虚拟网卡写入不再占用 UDP 接收循环，慢 TUN 写或数据帧洪泛不会阻塞 STUN、TURN、保活与路径切换。
  - 已对齐 Java/.NET probe 限速（`PeerUdpProbeRateLimiter`）：1 秒固定窗口，全局 2000 包、单源 100 包，最多跟踪 4096 个源，60 秒未见即回收；direct 与 relay 两条 probe 路径共用同一预算，未知来源直接拒绝。
  - 当虚拟设备为 `noop` 时，收到目标为本机虚拟 IP 的 ICMP echo request 会和 Java 一样在应用层构造 echo reply 并加密发回；真实 TUN / Wintun / utun 路径仍交给系统协议栈处理。
- .NET client：
  - 已读取 Java 启动配置里的 `peerMeshDevice`、`peerMeshTunName`、`peerMeshMtu`。
  - 登录环境已生成并上报 Java 兼容的 X25519 X.509 DER public key；key 文件使用 `.specus/peer-public.x25519` 与 `.specus/peer-private.x25519`。
  - 已补固定 `SPM2` AES-GCM frame codec、X25519/HKDF 方向密钥派生、counter nonce 和 4096 包 replay window 单测。
  - 已识别 HTTP 登录响应与 `PEER_CONTROL` 下发，支持 `peer-config`、`roster`、`session-grant`、`candidates`、`close`。
  - 已实现 Peer Mesh UDP 控制面：标准 STUN/TURN `Binding` / `Allocate` / `Refresh` / `CreatePermission` / `Send` / `Data Indication`、host/srflx/public-stun/relay candidate 上报、UDP connectivity check、`path-report` 和 direct-only traffic-report 增量上报；relay 字节由 server relay 热路径计量，避免重复统计。
  - 已实现 Linux `/dev/net/tun` 虚拟网卡：配置 /32 虚拟 IP 与 MTU；TUN 出站 IPv4 packet 按目标虚拟 IP 查 peer session 后走 direct UDP 或标准 TURN relay；入站 frame 解密后写回 TUN。
  - 已实现 Windows Wintun 随包加载：.NET client 项目文件会把 Java 参考资源里的 `native/windows/<arch>/wintun.dll` 复制到 build / publish 输出目录，运行时优先从输出目录 native 路径加载；仍可通过 `SPECUS_PEER_MESH_WINTUN_DLL` 覆盖，配置 /32 虚拟 IP 与 MTU，并接入同一套加密数据帧。
  - 已实现 macOS `utun`：通过 `com.apple.net.utun_control` 创建 utun 设备，配置 /32 虚拟 IP 与 MTU，读写时处理 Darwin utun 4 字节地址族前缀，并接入同一套加密数据帧。
  - 已对齐 Java per-peer OS 路由同步（`IPeerVirtualDevice.SyncPeerRoutesAsync`，接口默认 no-op）：虚拟网卡不再安装 mesh 网段路由（配置时会静默清理残留网段路由），StartAsync（含配置未变的轻量刷新）、roster 更新和 candidates 信令合并时按在线 peer 虚拟 IP 增删 /32 host 路由，设备 DisposeAsync 时清理全部已同步路由；Linux TUN / Windows Wintun / macOS utun 三个平台实现。
  - 已对齐 Java 虚拟包目标过滤：TUN 出站包目标为组播/保留段/受限广播、mesh 网段 network/broadcast 边界地址、本机虚拟 IP，或不属于任何在线 peer 时早期丢弃并按 30 秒节流记录 debug 日志，不再进入 pending 队列或按 flow 告警。
  - roster 删除语义已对齐 Java `updateRoster` 清空重建：被移出 roster 的 peer 立即从 peers 表消失（对应 host 路由同步移除），仍在 roster 中的 peer 保留已学 candidates，周期性 probe 探测不受 roster 推送影响。
  - 已按 Java 语义在 token 快过期前主动刷新 HTTP 登录态，刷新成功后热更新 TCP 映射、HTTP route 和 Peer Mesh 配置，不中断当前控制连接。
  - NAT 探测上报值已收敛为 Java 枚举：`NO_NAT`、`PORT_PRESERVED_NAT`、`PORT_RESTRICTED_NAT`、`FULL_CONE_OR_RESTRICTED_NAT`、`SYMMETRIC_NAT`、`NAT`；已消费 server 主端口、备用端口和公共 STUN 观测。与当前 Java 语义一致，`SYMMETRIC_NAT` 只作为观测结果，不再一票否决 direct candidate/check/data；直连失败后再回退标准 TURN relay。
  - relay candidate 请求节流已对齐 Java：allocation 新鲜时 60 秒内不重复请求，allocation 缺失或快过期时 15 秒内不重复请求；alternate NAT probe 15 秒内不重复发送。
  - 收到对端 connectivity check 时会和 Java 一样立即记录入站 direct/relay 路径，避免只能等本端主动探测成功后才可回包。
  - STUN Binding Success 已消费 `XOR-MAPPED-ADDRESS` 与 `OTHER-ADDRESS`，并支持公共 STUN 观测补充 srflx candidate，便于更复杂 NAT 下提高 direct 探测覆盖面。
  - 路径选择细节已对齐 Java：已绑定 `relayTargetAllocationId` 时数据面优先走 relay；direct 路径 45 秒内仍健康时不会被本端 relay check-response 抢占；收到 direct 数据帧会清理旧 relay allocation，避免路径状态残留。
  - `path-report` 与 active path 日志节流已对齐 Java：路径变化立即上报；路径不变时 60 秒内不重复刷控制面。
  - TUN 出站虚拟包在 session/path 未就绪时会按 Java 策略短暂排队：每个 peer 最多 32 个、30 秒 TTL；路径准备会主动重新上报 candidates / 触发 connectivity check，主动探测或收到对端数据导致路径就绪后都会 flush，避免 TCP SYN 等第一批包被直接丢弃。
  - 当虚拟设备为 `noop` 时，收到目标为本机虚拟 IP 的 ICMP echo request 会和 Java 一样在应用层构造 echo reply 并加密发回；真实 TUN / Wintun / utun 路径仍交给系统协议栈处理。
  - 当前 .NET 数据面已经接通协议和虚拟设备，仍需要真实 Windows / Linux / macOS 双机环境做 ping、HTTP、relay fallback 手工验收。
- Android client：
  - 已实现 HTTP API-key 登录、runtime token 控制通道登录、按写空闲触发的 5 秒心跳、60 秒读空闲和 Java 分类语义的指数退避重连；普通断线复用当前 `clientSessionId + accessToken`，只有 token 过期或 `LOGOUT_REQUEST` 才立即重新 HTTP 登录，busy/rate-limit 退避，其它认证或策略拒绝停止重连；重复 `LOGIN_RESPONSE` 会关闭 control，不能二次创建 data 连接。
  - 已实现 TCP NAT 注册与 v2 `OPEN/DATA/FIN/RST/WINDOW_UPDATE` 双向转发；OPEN 到本地建连期间按序缓存且每流限制为 1 MiB，TCP/WebSocket 全局 pending 建连上限为 1024，最近关闭流 tombstone 使迟到 RST 幂等，双方严格半关闭；重复 OPEN、未知 DATA/FIN 与无效半关闭只复位对应 stream，从未打开过的 RST 才按 data-connection 协议违规拒绝。Direct HTTP route 已改为受 VPN protect 的 Netty 流，支持任意 method request body、request/response trailers、early response、64 KiB DATA、每流 4 MiB pending 与 1–16 MiB credit；HTTP route WebSocket 使用 Netty 原始 frame，完整保留 continuation/FIN/RSV/close code 及 ping/pong payload，并把最多 16 MiB 的原始 data frame 规范化成有界 SWS2 continuation envelopes。HTTP/WS close-before-start、已在途 FIN 后的 RST 都由显式代际/状态门禁保证不被吞掉。
  - 已接入 Android `VpnService` 权限与 TUN 生命周期，使用登录/运行时 `peerMesh.virtualIp`、`peerMesh.cidr` 配置 VPN 地址和路由，并保护控制、本地与 Peer Mesh UDP socket 避免流量回灌；`peerMeshDevice=noop` 不申请或建立 VPN，不阻塞 TCP/HTTP，同时保留控制面和 UDP 探测。
  - 已实现 roster/session/candidates/close 信令、X25519/HKDF/AES-GCM `SPM2` frame、4096 包 replay protection、host/srflx/relay candidates、公共 STUN hostname 全 A/AAAA、标准 TURN allocation/permission/send/data indication/ChannelData、同 nonce probe burst、自适应端口预测、25 秒 direct keepalive、UPnP/NAT-PMP/PCP 显式映射、direct UDP 与 relay fallback，以及设备/路径/direct-only 流量上报；端口映射 acquire/renew 与 stop 使用 generation gate，停止后的迟到成功会释放而不会复活映射。relay 字节只由服务端 TURN 热路径计量。
  - JVM 测试覆盖 32 MiB 完整帧及超限拒绝、HMAC 登录、运行时配置三态、控制重连分类、严格 stream flow、WebSocket 16 MiB 原始 frame 规范化、close-before-start 与 pending-write、HTTP early response/双向 trailers、真实测试 CA/hostname TLS 握手、UDP probe 严格预检/限流/nonce/session/endpoint、全地址 STUN、端口预测、端口映射 stop 竞态和三类映射 wire/service。自动化不能替代真实设备；VPN 双机 ping、业务流量和跨 NAT relay fallback 仍待端到端验收。
- C server：
  - `/api/client/auth/login` 按 `SPECUS_PEER_MESH_ENABLED` 返回完整 Java-shaped Peer Mesh 配置，包括 virtual IP/CIDR、STUN/TURN、server public key、session/catalog TTL；control 登录后推 peer-config、roster 和授权 service catalog。
  - `PEER_CONTROL` 数据面校验 source/target/tenant/ACL 后转发 offer/answer/candidates/close，持久化 session、path/traffic/NAT/virtual-device report；未知 route、过期 session、禁用设备与撤销 ACL 均失败关闭。service catalog 带 revision/TTL，管理 mutation 会即时 refresh，断线会撤销 publisher catalog。
  - 内置 UDP listener 支持 RFC 5389 Binding、RFC 5780 `CHANGE-REQUEST`/`OTHER-ADDRESS` NAT probe，以及 RFC 5766 Allocate/Refresh/CreatePermission/ChannelBind/Send/Data/ChannelData。TURN 使用 long-term credential、realm/nonce、MESSAGE-INTEGRITY、relay 端口池、每地址/全局 allocation 与字节配额，支持同客户端两个 allocation，并定时清理 allocation/permission/channel。
  - 证据：`peer_mesh_tests` 以回调替身覆盖登录配置/roster 推送、虚拟 IP 分配、service catalog 推送/撤回/权限刷新/过期、candidate/session 转发、path/traffic/device 报告、拒绝 ACL 与离线目标、close 和 logout；`stun_turn_tests` 在回环 UDP 上覆盖 Binding、RFC 5780 change-request、401 challenge、Allocate、CreatePermission、跨 allocation relay、Send/Data indication 与 allocation 配额。TURN Refresh、ChannelBind/ChannelData 与 allocation/permission/channel 过期清理只有源码。
  - C server 不提供 C client 或虚拟网卡；SPM2 加密数据、TUN/VPN、direct 打洞与 relay fallback 由客户端负责，但还没有任何客户端（Java/Go/.NET/Android）对 C server 跑过 Peer Mesh 信令、打洞或 relay。真实跨 NAT、真机 VPN/TUN 和长流量仍属于发布环境门禁。

### 打洞成功率优化对齐（H-1 / H-2 / H-3 / H-6）

状态：已完成。Java / Go / .NET / Android 四端均已落地 H-1 / H-2 / H-3 / H-6，并附带对齐单测；真实 NAT 环境的 `activeDirectRatio` 收益验证仍属发布门禁。

Java 客户端在 2026-07-22 完成了 [`peer-mesh-hole-punching-audit-2026-07.md`](../../peer-mesh/peer-mesh-hole-punching-audit-2026-07.md) 中的 H-1 / H-2 / H-3 / H-6 四项打洞成功率优化。初始复核发现这四项仅存在于 Java 客户端，Go / .NET / Android 未对齐；同日已按下列清单完成三端移植。移植前应以 `/api/admin/peer-mesh/stats` 的 `activeDirectRatio` 与 `natTypes` 分布建立基线，移植后用同一指标验证收益。

| 项 | Java 参考位置 | 移植结果 |
| --- | --- | --- | --- |
| H-1 候选回礼 | `PeerMeshClient.reciprocateCandidates`（约 L587），2s 节流 | 三端在候选接收路径末尾新增 reciprocate 调用：本端无健康 direct 路径时立即回发自身候选，带每 peer 2s 节流防信令循环。Go `reciprocateCandidates` + `announceCandidatesToPeer`；.NET `ReciprocateCandidatesAsync` + `AnnounceCandidatesToPeerAsync`；Android `reciprocateCandidates` 复用 `sendCandidatesToPeer` |
| H-2 密集退避重试 | `scheduleHolePunchRetries`（约 L1157），`HOLE_PUNCH_RETRY_DELAYS_MILLIS={1k,2k,4k,8k}` | 三端在 `sendConnectivityChecks` 末尾排程 1s/2s/4s/8s 退避重试，打通或过期即停，本轮结束后释放 per-session 标记。Go 用 `time.AfterFunc`；.NET 用 `Task.Run`+`Task.Delay`；Android 复用 `pathMtuScheduler` |
| H-3 priority 降序排序 | `sortedCandidates`（约 L3839），priority 降序 | Go `sendConnectivityChecks` 增加 `sort.SliceStable`（priority 降序）；.NET `SendConnectivityChecksAsync` 增加 `OrderByDescending`；Android `directCandidates` 原已对齐，移植时重构为静态 `sortedDirectCandidateEndpoints` 便于单测 |
| H-6 同 NAT reflexive 降权 | `demoteSameNatReflexiveCandidates`（约 L605），降到 priority=1 | 三端新增同 NAT 检测：对端 srflx/port-map 地址与本端 STUN 观测公网地址相同时降到 priority=1 而非剪除。Go `demoteSameNatReflexiveCandidates`；.NET `DemoteSameNatReflexiveCandidates`；Android 静态 `demoteSameNatReflexiveCandidates` |

常量对齐：四端统一 `{1s,2s,4s,8s}` 退避、`2s` 候选回礼节流、`priority=1` 同 NAT 降权，与 Java 完全一致。健康 direct 判定复用各端既有 `hasHealthyDirect`（45s 阈值）。每端新增对齐单测覆盖排序、降权不剪除、退避打通即停、回礼节流四类语义。

验证（2026-07-22，开发机）：
- Go：`cd implementations/go/client && go build ./... && go test ./internal/client/...` 通过，新增 7 个用例（H-3 排序、H-6 降权含 port-map、H-1 节流+健康 direct 跳过、H-2 退避打通即停+不重复排程）。
- .NET：`dotnet test implementations\csharp\client\tests\Specus.Client.Tests\Specus.Client.Tests.csproj` 通过，`112/112`（含新增 6 个 `...LikeJava` 用例）。
- Android：`gradlew testDebugUnitTest` 通过，`PeerMeshProtocolTest` `19/19`（含新增 5 个 H-3/H-6 静态逻辑用例）。
- 仍需环境验收：真实跨 NAT 双机的 `activeDirectRatio` 与收敛时间基线，源码自动化通过不替代这些外部系统与硬件验证。

H-4 / H-5 / H-7 仍按打洞审计文档列为 OPEN，待基线数据确认对称 NAT 占比后再投入。

端到端手工验收计划（代码能力已具备，需要真实网络环境验证）：

1. Go client：用真实 macOS / Windows / Linux 双机验证 ping、HTTP 和 relay fallback，并根据验收结果细化虚拟网卡错误恢复。
2. Go server：和 Java 标准 STUN/TURN relay 做真实跨 NAT 压测，重点验证 direct 失败后 relay fallback、relay 计量和管理页面链路展示。
3. .NET client：用真实 Windows / Linux / macOS 双机验证 ping、HTTP、relay fallback，并根据验收结果细化 Wintun/TUN/utun 错误恢复。
4. Android client：先完成真机安装与控制通道/TCP/Direct HTTP smoke test，再用两台真实 Android/混合桌面客户端验证 VPN 虚拟 IP、业务流量和 relay fallback。
5. .NET server/client：做真实跨 NAT 压测，验证 direct 失败后的标准 TURN relay fallback、relay 计量和管理统计。
6. C server：计划内 Peer Mesh server 源码能力已完成；仓库仍没有 C client。下一步只保留真实跨 NAT、Java/Go/.NET/Android 混部、真机 VPN/TUN、长流量和故障注入等发布环境验收。
