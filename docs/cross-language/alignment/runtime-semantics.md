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
  - `/auth/login` 会校验内置 admin 密码；配置 `SPECUS_DATABASE_PATH` 后，也会校验启用状态的 `specus_management_user`，密码哈希使用 Java 兼容 SHA-256 hex。响应返回 Java-shaped `accessToken/tokenType/expiresIn`，token 为 HS256 JWT，包含 `iss=specus`、`sub`、`tenant_id`、`role`、`iat`、`exp`。
  - 真实 C 管理 HTTP socket 已对 `/api/admin/**` 和 `/auth/refresh` 校验 `Authorization: Bearer <token>`；`/auth/refresh` 会基于当前本地 JWT 上下文续期。C 单测用的直接 response builder 仍保留内置 admin 便捷上下文，方便 smoke-test endpoint body。
  - `/oidc-config` 返回 Java-shaped 浏览器登录配置：`configured`、`authorizationEndpoint`、`endSessionEndpoint`、`clientId`、`redirectUri`、`scope` 和 `passwordLoginEnabled`；`/oidc/token` 已补 Authorization Code + PKCE 代理交换的基础契约，支持 `http://` token endpoint、可选 Basic client secret，并返回 `accessToken/idToken/tokenType/expiresIn`，`https://` token endpoint 会明确返回 `502`，待 C 侧 TLS HTTP client 补齐。
  - `/api/admin/me` 返回内置 admin 视图；`/api/admin/users` 返回内置 admin 加当前租户 DB 管理用户，`POST /api/admin/users`、`PUT /api/admin/users/{username}`、`DELETE /api/admin/users/{username}` 在 SQLite 模式下可用，内置 admin 不允许被 DB mutation 修改。
  - 客户端、TCP 映射、HTTP route、连接记录、连接归档统计、日流量汇总和资源流量汇总接口已接入基础 Java-shaped 可见性规则：admin 访问当前租户所有客户端，普通用户只访问自己创建的客户端及其下属数据。
  - `connection_record` 已补齐物理 `tenant_id` 字段、启动兼容补列和历史行回填；运行时登录成功/失败写入真实租户，分页查询优先按记录租户过滤，WebSocket 连接事件继续使用 Java-shaped 顶层 `tenantId`。
  - `/api/client/auth/login` 在 SQLite 模式下会读取 `specus_client_credential`，按 Java canonical HMAC 校验 `apiKey/timestamp/nonce/machineFingerprint/osUser`，为 `credential + machineFingerprint + osUser` 创建或复用唯一客户端身份，写入 `specus_client_session=HTTP_AUTHENTICATED`，并返回 Java-shaped `tenantId`、`clientId`、`clientName`、`clientSessionId`、`accessToken`、`tokenTtlSeconds`、`maxOnlineInstances`、`policy`、TCP 映射和 HTTP route。Netty 控制通道随后按 `clientSessionId + accessToken` 验证该 session，检查过期、客户端/凭证启用状态、同机单实例和凭证最大在线实例数，登录成功标记 `NETTY_ONLINE`，断开标记 `DISCONNECTED`，启动时会清理上一进程遗留的 `NETTY_ONLINE`。无匹配 SQLite 凭证时仍保留环境变量驱动的 smoke-test token 模式；只要配置了任意 `SPECUS_CLIENT_API_KEY` / `SPECUS_CLIENT_SECRET` / `SPECUS_CLIENT_SECRET_HASH`，就要求配置完整并校验签名，避免半配置时静默降级。
  - 当前阶段补齐 Java `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` 与 `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` 环境变量别名，旧的 `SPECUS_CLIENT_TOKEN_TTL_SECONDS` / `SPECUS_CLIENT_MAX_ONLINE_INSTANCES` 仍保留为兼容别名；`SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` 仅作为 Java 兼容配置名记录，C 控制通道当前仍固定同机用户单实例。
  - SQLite 模式下已补 Java-shaped 客户端凭证管理、客户端应用包下载链接管理、客户端管理、TCP 映射管理、HTTP route 管理、连接记录分页查询、连接归档统计查询和流量汇总查询：`POST /api/admin/database/initialize`、`GET/POST /api/admin/client-credentials`、`PUT/DELETE /api/admin/client-credentials/{id}`、`GET /api/public/client-downloads`、`GET/POST /api/admin/client-downloads`、`PUT/DELETE /api/admin/client-downloads/{id}`、`GET/POST /api/admin/clients`、`PUT/DELETE /api/admin/clients/{id}`、`GET /api/admin/specus-mappings`、`POST /api/admin/clients/{id}/specus-mappings`、`POST /api/admin/clients/{id}/nat-control`、`PUT/DELETE /api/admin/specus-mappings/{id}`、`GET /api/admin/http-routes`、`POST /api/admin/clients/{id}/http-routes`、`PUT/DELETE /api/admin/http-routes/{id}`、`GET /api/admin/connections?clientId=&success=&from=&to=&page=&size=`、`GET /api/admin/connection-stats?clientName=&limit=`、`GET /api/admin/traffic?clientId=&limit=`、`GET /api/admin/traffic/resources?type=&clientId=&limit=`。这些查询在 SQL 层按当前管理上下文过滤，分页 total 也是过滤后的结果；数据库初始化接口仅 admin 可调用，响应包含 `initialized`、`tenantId`、`orm=sqlite3`、`dialect=sqlite` 和当前租户客户端数；`nat-control` 会校验客户端权限，当前 C 轻量实现未接入完整在线主动推送，离线或无法下发时返回 Java-shaped `409`。客户端应用包下载链接按 Java 当前语义作为全局资源维护，仅 admin 可增删改查，公开接口只返回启用项。HTTP/TCP 明细接口在 SQLite 模式下已接入真实表查询：HTTP exchange 和 TCP frame 支持分页，TCP frame 详情按 id 查询，TCP stream 按 channel 串流；无匹配记录时才返回空分页、`404` 或空串流对象。未配置 `SPECUS_DATABASE_PATH` 时资源列表返回环境变量快照，下载链接和连接记录返回空列表/空分页，连接统计和流量统计返回空数组，mutation 返回 `503`。
  - `/api/admin/overview` 与 `/api/admin/metrics` 使用同一套 SQLite + `SPECUS_TCP_MAPPINGS` 快照，返回当前管理上下文可见的 TCP 映射数量。
  - 管理 HTTP socket 已支持 `GET /ws/connections?token=<management-jwt>` 的 WebSocket Upgrade、管理 JWT 鉴权、`403 X-Auth-Reason`、ping/pong 和 close 帧处理；运行时登录成功/失败会广播 Java-shaped `created` 事件，已认证控制连接断开会广播同一记录的 `updated` 事件。
  - `/api/admin/peer-mesh/status` 返回与 Java 一致的 `enabled` 字段，可由 `SPECUS_PEER_MESH_ENABLED` 驱动；设备列表会把当前可见 SQLite client 投影为 disabled/offline 的 Java-shaped device view；SQLite 模式下 ACL 支持 Java-shaped list/create/delete 和 `OUTBOUND/INBOUND/BOTH` direction，并复用区分大小写的租户/owner 可见性规则：source 必须当前用户可见、target 必须同租户、普通用户不能创建跨用户 ACL；SQLite 模式下已创建 `peer_mesh_session` 表，并支持 `GET /api/admin/peer-mesh/sessions?limit=`、`DELETE /api/admin/peer-mesh/sessions/{id}`、`DELETE /api/admin/peer-mesh/sessions`，查询和关闭都按租户/owner 可见性过滤。C 目前仍不会由数据面主动创建真实 peer session，其他 Peer Mesh mutation 仍返回 `501`。

## 阶段 3：HTTP 直转与流量观测

状态：Go / .NET 已推进到 DB / Elasticsearch 双后端；前端预览体验仍可继续细化。

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
- Go server、.NET server 与 C server 已接入 HTTP 响应路径改写行为：当 `pathRewriteEnabled=true` 时，服务端会在回写浏览器前尝试改写 `text/html` / `text/css` 中的绝对路径，并在 HTML 中注入 Java 对齐的运行时 polyfill，覆盖 `fetch`、`XMLHttpRequest`、`history.pushState/replaceState`、动态元素属性、`EventSource` 和 `WebSocket` 的绝对路径；改写后返回给浏览器的响应会剥离失效的 `Content-Encoding` / `Content-Length`，但 HTTP 明细采集仍保留客户端原始响应头，便于排查上游真实行为；C server 当前支持 `gzip`、zlib `deflate` 与 raw `deflate` 解码后改写。
- Java、Go、.NET 与 C server 的持久化 HTTP route 已对齐可选 Basic 入口认证：管理 API 使用
  `authEnabled/authUsername/authPassword` 写入，只返回 `authPasswordConfigured`；密码只保存哈希。HTTP 与支持
  WebSocket 的实现均在打开隧道/Upgrade 前校验，受保护 route 的入口 Authorization 不透传 upstream 或写入明细，
  未持久化的 legacy 客户端本地 route 仍保持公开兼容。
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
- C server 已补 Direct HTTP 的 v2 NAT bridge：管理监听的 `/http/{clientName}/{route}/...` 使用 `OPEN/DATA/FIN/RST/WINDOW_UPDATE` 与在线 data 连接交换请求/响应，WebSocket 双向使用 SWS2 envelope，不再使用 `DIRECT_HTTP_REQUEST/RESPONSE`、`CONNECTED` 或 1 字节 frame 前缀。它仍是兼容子集：SWS2 close-code 校验尚未拒绝 `1004/1005/1006/1015`，也未直接读取中央 `application-protocol-v2.json`，因此不纳入完整 SWS2/严格状态机门禁。
- C server 的 `SPECUS_HTTP_ROUTES` 会同时出现在 `/api/client/auth/login` 和 `NAT_CONTROL.httpSpecusConfigList`；转发前校验在线 session 的 route，未配置返回 `404`。当前已具备 Java-shaped 流量汇总、SQLite HTTP/TCP 明细与分页搜索、TCP frame/串流查询、HTML/CSS 路径改写、runtime polyfill、按 clientName 分发的多在线连接，以及带鉴权和连接事件广播的管理 WebSocket；仍不包含 Java 的 ES 明细存储。

## 阶段 4：Peer Mesh 控制面与数据面

状态：Go server 与 .NET server 控制面和标准 STUN/TURN relay 已对齐 Java；Go client 与 .NET client 已补齐 Linux TUN / Windows Wintun / macOS utun、X25519/HKDF/AES-GCM frame 与 UDP 数据面接入；Android client 已完成控制通道、VpnService、加密 UDP direct/TURN relay 的源码与 JVM 协议测试，真机验收仍单列保留。

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
  - `/api/client/auth/login` 返回 disabled `peerMesh` block。
  - `/api/client/auth/login` 同步返回 TCP 映射快照，便于非 Java 客户端在 HTTP 登录阶段按 Java 响应结构获取配置。
  - SQLite `http_route_mapping` 和 `SPECUS_HTTP_ROUTES` 会合并下发为 `httpSpecusConfigList`，管理 HTTP listener 已能在校验 route 存在后把 `/http/{clientName}/{route}/...` 转发到当前在线控制连接，形成最小 Direct HTTP 数据面。
  - SQLite `traffic_usage` / `resource_traffic_usage` 已支持 Java-shaped 查询；TCP 隧道按 `TCP_SPECUS` + `tcp:{listenPort}` 写汇总，Direct HTTP 按 `HTTP_ROUTE` + `http:{route}` 写汇总。
  - 管理面补齐 Peer Mesh 管理契约：设备列表会为可见 SQLite client 幂等创建轻量 `peer_mesh_device` 行并返回 offline view，`PUT /api/admin/peer-mesh/devices/{clientId}` 可在租户/owner 权限内持久化 `enabled`，但虚拟网卡状态仍固定为 `UNSUPPORTED`；SQLite ACL 可 list/create/delete，持久化 `OUTBOUND/INBOUND/BOTH` direction，tenant/owner 权限比较区分大小写，ACL 输入已按 Java 侧 `long` clientId 语义解析 64 位 ID；SQLite `peer_mesh_session` 可 list/close/close-open，并按租户/owner 可见性过滤，未知单个 session 返回 `404`；C 数据面仍不主动创建真实 peer session，其余 mutation 返回 `501`。
  - `/api/admin/peer-mesh/status` 已收敛为 Java-shaped `{ "enabled": boolean }`，不再额外暴露 C 专属 stub 字段。

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
6. C server：当前阶段冻结在轻量管理面和最小兼容数据面，不继续扩展 Peer Mesh 数据面；仓库当前没有 C client。
