# 多语言实现对齐 Java 计划

本文以 `implementations/java/server` 和 `implementations/java/client` 为参考实现，记录 Go、.NET、C 实现的对齐阶段和剩余缺口。

## 阶段 1：协议与启动登录兼容

状态：已完成。

- Go / .NET / C 同步 `MessageType.PEER_CONTROL=4`。
- Go / .NET 的 CompactBinary UUID 字符串编码已对齐 Java 的严格规则：只有小写 canonical UUID 会走 16 字节二进制分支，非 canonical 或大写 UUID 保留为普通字符串，避免跨语言 round-trip 时大小写漂移。
- Go server / .NET protocol 的 CompactBinary HTTP Method 编码已对齐 Java 的精确匹配规则：只有 `GET` / `POST` / `PUT` / `DELETE` 原样大写值会走枚举短编码，小写或混合大小写 method 保留为普通字符串，避免跨语言转发时把原始请求方法静默改写。
- Go client / Go server / .NET protocol 已补齐 CompactBinary 空字符串边界：空 UUID 和空 HTTP Method 按 Java 语义写成普通字符串 marker，而不是退化成 wire-level null，保留协议层 null / empty 的区别。
- Go client / Go server 已补齐 CompactBinary collection 边界：`nil` slice 写成 Java null marker，空 slice 写成 empty marker，避免 byte array / string list 在跨语言转发时丢失 null / empty 区别。
- Go client / Go server / .NET protocol 已补齐 CompactBinary nullable Long 边界：`0L` 按 Java 语义写成非空 long marker + zigzag 0，不再退化成 wire-level null。
- Go client 的 `DirectHTTPResponse.error` 已改为 nullable string，成功响应写 null，非空或空字符串错误按 Java String marker 保留，避免响应错误字段丢失 null / empty 区别。
- .NET protocol 的 CompactBinary NumericString 已对齐 Java `Long.parseLong`：只允许前导正负号和数字，不接受首尾空白，避免 `" 123"` 被静默归一化成 `"123"`。
- Go / .NET 客户端启动配置支持 `apiKey/secret`、`peerMeshDevice`、`peerMeshTunName` 和 `peerMeshMtu`，并会按 Java 规则归一化 MTU 到 `576..1280`；`serverBaseUrl` 统一要求为 http/https 绝对地址。
- Go / .NET 客户端环境上报会把 Windows `DOMAIN\user` / 路径式用户名归一化为 Java 风格裸用户名，避免服务端按 `machineFingerprint + osUser` 分配客户端身份时产生跨语言漂移。
- Go / .NET 客户端识别 HTTP 登录响应里的 `peerMesh` 配置，并支持 Java 兼容 Peer Mesh UDP 控制面、数据帧和虚拟设备状态上报。
- Go / .NET 客户端已补齐运行时 token 主动刷新：长连接不断开时会在过期前重新 HTTP 登录，热更新 TCP 映射、HTTP route 和 Peer Mesh 配置；刷新失败会延迟重试，不主动打断已有控制连接。
- Go / .NET 客户端已补齐 Java 服务端踢线语义：收到 `LOGOUT_REQUEST` 后关闭当前控制连接，由外层 reconnect loop 重新 HTTP 登录并获取最新运行时策略。
- Go / .NET 客户端控制连接重连策略已对齐 Java：失败后按 `2s -> 4s -> 8s -> 16s -> 32s -> 60s` 指数退避，且只在服务端 `LOGIN_RESPONSE.success=true` 后重置退避计数，TCP 连接建立本身不算登录成功；`访问令牌已过期` 会立即重新 HTTP 登录并重连，`服务器繁忙` / `连接频率超过限制` 走退避，其它认证或策略拒绝会停止重连。
- Go / .NET 客户端控制连接心跳空闲策略已对齐 Java：普通业务写出会刷新写空闲时间，5 秒没有任何写出才发送 `HEARTBEAT_REQUEST`，60 秒读空闲关闭当前连接并进入重连状态机。
- Go / .NET 客户端普通 TCP 映射的 `CONNECTED` 异常分支已对齐 Java：缺少 `port`、缺少 `channelId` 或端口不在当前配置中时只记录并忽略，不额外回发 `DISCONNECTED`；只有本地真实拨号失败或已建立通道断开时才通知服务端断开。
- Go / .NET 客户端与服务端 NAT metadata 读取已对齐 Java 容错语义：字符串字段对非空值使用 `toString` / `fmt.Sprint`，布尔值按 Java 小写 `true/false` 保留，整数字段接受数字值和数字字符串，`float64` / `double` 等 JSON 数字按 Java `Number.intValue()` 风格截断。
- C server 的 `/api/client/auth/login` 已支持两条路径：SQLite 模式下读取 `tunnel_client_credential`、按 Java canonical HMAC 校验、创建/复用机器用户身份、写入 `tunnel_client_session=HTTP_AUTHENTICATED` 并签发 `cs_` token；无匹配 DB 凭证时保留环境变量 smoke-test token 模式。响应保持 Java 当前客户端可解析的 `peerMesh.enabled=false`、`tunnelConfigList` 和 `httpTunnelConfigList` 结构。

## 阶段 2：管理用户、多租户和 owner 权限

状态：本阶段已完成 Go server 与 .NET server 基础对齐；C server 已从 smoke-test stub 推进到轻量 SQLite 管理用户、多租户和 owner 可见性。

- Go server：
  - 新增 `tunnel_management_user` schema 与 store CRUD。
  - 本地 JWT 写入 `tenant_id` / `role`，刷新时保留 claim。
  - 新增 `/api/admin/me`、`/api/admin/users`。
  - 新增 Java-shaped 客户端应用包下载链接管理：`GET /api/public/client-downloads` 返回启用项，`GET/POST /api/admin/client-downloads`、`PUT/DELETE /api/admin/client-downloads/{id}` 仅 admin 可维护。
  - OIDC RS256 管理 token 支持 `TUNNEL_OIDC_TENANT_CLAIM`，默认读取 `tenant_id`，缺失时回退默认租户。
  - `/api/admin/database/initialize` 响应已补齐 Java-shaped `tenantId`，`clients` 按当前管理租户统计。
  - HTTP 启动登录响应的 `tenantId` 已改为返回凭证所属租户，避免非 default 租户客户端拿到错误运行时上下文。
  - Netty 运行时登录已按 Java 语义检查同一机器/用户单实例与凭证 `maxOnlineInstances`，并在连接断开时回收内存会话在线状态。
  - `tunnel.client-auth.*` 已独立于管理端 `tunnel.auth.*`：HTTP 启动登录 token TTL 使用 `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS`，同机用户在线实例数使用 `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES`，凭证默认最大在线数使用 `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES`；同时补齐 Java 当前 `TUNNEL_LOGIN_EXECUTOR_MAX` / `TUNNEL_LOGIN_EXECUTOR_QUEUE` 环境变量别名。
  - 连接记录后台归档已改为读取 Java 同名配置：`TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` 控制明细保留天数，`TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` 控制归档间隔；保留天数小于等于 0 时关闭归档，归档 cutoff 使用 UTC 自然日边界。
  - 新增 `tunnel_client_session` schema 与 store 操作；HTTP 启动登录写入 `HTTP_AUTHENTICATED`，Netty 登录成功改为 `NETTY_ONLINE`，断开和过期改为 `DISCONNECTED`，启动时会清理上一进程遗留的在线会话。
  - admin 可管理用户和查看当前租户内全部资源。
  - 普通用户只能看到自己创建的客户端、启动凭证、TCP 映射、HTTP route、连接记录、流量和归档统计。
  - `tunnel_traffic_usage` 已补齐 `tenant_id`，每日总流量写入、列表和历史空租户行兼容读取与 Java 租户归属一致。
  - `tunnel_connection_record` 已补齐 `tenant_id`，连接记录写入、overview 统计、分页查询和 `/ws/connections` 事件广播均按租户收敛；WebSocket 事件携带 Java-shaped `tenantId`，普通用户只接收自己 owner 客户端的连接事件。
  - `tunnel_connection_stat` 已补齐 `tenant_id`，归档聚合按 `tenantId + clientName + statMonth` 分组；管理查询先按租户收敛，再按普通用户可见 clientId 过滤，避免不同租户同名客户端的月度统计互相污染。
- .NET server：
  - 新增 `ManagementUser` EF entity、`ManagementContext`、`ManagementUserService`。
  - 初始化时幂等创建 `tunnel_management_user` 表。
  - 本地 JWT 写入 `tenant_id` / `role`。
  - OIDC RS256 管理 token 支持 `Tunnel:Oidc:TenantClaim` / `TUNNEL_OIDC_TENANT_CLAIM`，统一归一化为内部 `tenant_id` claim。
  - 管理 API 使用 `ManagementContext` 过滤客户端、凭证、映射、连接记录、流量和统计。
  - 新增 `Tunnel:ClientAuth` / `TUNNEL_CLIENT_AUTH_*` 配置组：HTTP 启动登录 token TTL、同机用户在线实例上限和凭证默认最大在线数均从该组读取；`TUNNEL_LOGIN_EXECUTOR_CORE`、`TUNNEL_LOGIN_EXECUTOR_MAX`、`TUNNEL_LOGIN_EXECUTOR_QUEUE` 已显式映射到 .NET 配置键。
  - 新增 `Tunnel:ConnectionRecord` / `TUNNEL_CONNECTION_*` 配置组与 `ConnectionArchiveService` 后台任务：按 Java 语义把早于保留窗口的连接明细聚合到 `tunnel_connection_stat` 后删除，默认保留 60 天、每小时执行一次，保留天数小于等于 0 时关闭归档。
  - `/api/admin/database/initialize` 会使用当前 admin 管理上下文执行幂等初始化，响应包含 `tenantId`，`clients` 按当前租户统计。
  - 新增 Java-shaped 客户端应用包下载链接管理：公开启用项列表不需要登录，admin CRUD 使用 EF Core 持久化并补齐 SQLite / MySQL / PostgreSQL migration。
  - `tunnel_traffic_usage` EF model、启动兼容补列、flush 写入和管理查询已补齐 `tenant_id`；旧库空租户行会在后续 flush 时归属到客户端租户。
  - `tunnel_connection_record` EF model、provider snapshot、启动兼容补列、写入和管理查询已补齐 `tenant_id`；`/ws/connections` 事件携带 Java-shaped `tenantId`，并按租户与 owner 权限过滤订阅者。
  - `tunnel_connection_stat` EF model、provider snapshot、启动兼容补列、历史行回填和管理查询已补齐 `tenant_id`；fresh migration 后由启动兼容 SQL 幂等补列，旧库按 clientId / clientName 回填到客户端所属租户。
- C server：
  - SQLite 初始化时幂等创建 `tunnel_management_user`，并提供 store CRUD。
  - `/auth/login` 会校验内置 admin 密码；配置 `TUNNEL_DATABASE_PATH` 后，也会校验启用状态的 `tunnel_management_user`，密码哈希使用 Java 兼容 SHA-256 hex。响应返回 Java-shaped `accessToken/tokenType/expiresIn`，token 为 HS256 JWT，包含 `iss=shuai-tunnel`、`sub`、`tenant_id`、`role`、`iat`、`exp`。
  - 真实 C 管理 HTTP socket 已对 `/api/admin/**` 和 `/auth/refresh` 校验 `Authorization: Bearer <token>`；`/auth/refresh` 会基于当前本地 JWT 上下文续期。C 单测用的直接 response builder 仍保留内置 admin 便捷上下文，方便 smoke-test endpoint body。
  - `/oidc-config` 返回 Java-shaped 浏览器登录配置：`configured`、`authorizationEndpoint`、`endSessionEndpoint`、`clientId`、`redirectUri`、`scope` 和 `passwordLoginEnabled`；`/oidc/token` 已补 Authorization Code + PKCE 代理交换的基础契约，支持 `http://` token endpoint、可选 Basic client secret，并返回 `accessToken/idToken/tokenType/expiresIn`，`https://` token endpoint 会明确返回 `502`，待 C 侧 TLS HTTP client 补齐。
  - `/api/admin/me` 返回内置 admin 视图；`/api/admin/users` 返回内置 admin 加当前租户 DB 管理用户，`POST /api/admin/users`、`PUT /api/admin/users/{username}`、`DELETE /api/admin/users/{username}` 在 SQLite 模式下可用，内置 admin 不允许被 DB mutation 修改。
  - 客户端、TCP 映射、HTTP route、连接记录、连接归档统计、日流量汇总和资源流量汇总接口已接入基础 Java-shaped 可见性规则：admin 访问当前租户所有客户端，普通用户只访问自己创建的客户端及其下属数据。
  - `connection_record` 已补齐物理 `tenant_id` 字段、启动兼容补列和历史行回填；运行时登录成功/失败写入真实租户，分页查询优先按记录租户过滤，WebSocket 连接事件继续使用 Java-shaped 顶层 `tenantId`。
  - `/api/client/auth/login` 在 SQLite 模式下会读取 `tunnel_client_credential`，按 Java canonical HMAC 校验 `apiKey/timestamp/nonce/machineFingerprint/osUser`，为 `credential + machineFingerprint + osUser` 创建或复用唯一客户端身份，写入 `tunnel_client_session=HTTP_AUTHENTICATED`，并返回 Java-shaped `tenantId`、`clientId`、`clientName`、`clientSessionId`、`accessToken`、`tokenTtlSeconds`、`maxOnlineInstances`、`policy`、TCP 映射和 HTTP route。Netty 控制通道随后按 `clientSessionId + accessToken` 验证该 session，检查过期、客户端/凭证启用状态、同机单实例和凭证最大在线实例数，登录成功标记 `NETTY_ONLINE`，断开标记 `DISCONNECTED`，启动时会清理上一进程遗留的 `NETTY_ONLINE`。无匹配 SQLite 凭证时仍保留环境变量驱动的 smoke-test token 模式；只要配置了任意 `TUNNEL_CLIENT_API_KEY` / `TUNNEL_CLIENT_SECRET` / `TUNNEL_CLIENT_SECRET_HASH`，就要求配置完整并校验签名，避免半配置时静默降级。
  - 当前阶段补齐 Java `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` 与 `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` 环境变量别名，旧的 `TUNNEL_CLIENT_TOKEN_TTL_SECONDS` / `TUNNEL_CLIENT_MAX_ONLINE_INSTANCES` 仍保留为兼容别名；`TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` 仅作为 Java 兼容配置名记录，C 控制通道当前仍固定同机用户单实例。
  - SQLite 模式下已补 Java-shaped 客户端凭证管理、客户端应用包下载链接管理、客户端管理、TCP 映射管理、HTTP route 管理、连接记录分页查询、连接归档统计查询和流量汇总查询：`POST /api/admin/database/initialize`、`GET/POST /api/admin/client-credentials`、`PUT/DELETE /api/admin/client-credentials/{id}`、`GET /api/public/client-downloads`、`GET/POST /api/admin/client-downloads`、`PUT/DELETE /api/admin/client-downloads/{id}`、`GET/POST /api/admin/clients`、`PUT/DELETE /api/admin/clients/{id}`、`GET /api/admin/tunnels`、`POST /api/admin/clients/{id}/tunnels`、`POST /api/admin/clients/{id}/nat-control`、`PUT/DELETE /api/admin/tunnels/{id}`、`GET /api/admin/http-routes`、`POST /api/admin/clients/{id}/http-routes`、`PUT/DELETE /api/admin/http-routes/{id}`、`GET /api/admin/connections?clientId=&success=&from=&to=&page=&size=`、`GET /api/admin/connection-stats?clientName=&limit=`、`GET /api/admin/traffic?clientId=&limit=`、`GET /api/admin/traffic/resources?type=&clientId=&limit=`。这些查询在 SQL 层按当前管理上下文过滤，分页 total 也是过滤后的结果；数据库初始化接口仅 admin 可调用，响应包含 `initialized`、`tenantId`、`orm=sqlite3`、`dialect=sqlite` 和当前租户客户端数；`nat-control` 会校验客户端权限，当前 C 轻量实现未接入完整在线主动推送，离线或无法下发时返回 Java-shaped `409`。客户端应用包下载链接按 Java 当前语义作为全局资源维护，仅 admin 可增删改查，公开接口只返回启用项。HTTP/TCP 明细接口已返回 Java-shaped 空分页、TCP frame 详情返回 `404`、TCP stream 返回空串流对象。未配置 `TUNNEL_DATABASE_PATH` 时资源列表返回环境变量快照，下载链接和连接记录返回空列表/空分页，连接统计和流量统计返回空数组，mutation 返回 `503`。
  - `/api/admin/overview` 与 `/api/admin/metrics` 使用同一套 SQLite + `TUNNEL_TCP_MAPPINGS` 快照，返回当前管理上下文可见的 TCP 映射数量。
  - 管理 HTTP socket 已支持 `GET /ws/connections?token=<management-jwt>` 的 WebSocket Upgrade、管理 JWT 鉴权、`403 X-Auth-Reason`、ping/pong 和 close 帧处理；运行时登录成功/失败会广播 Java-shaped `created` 事件，已认证控制连接断开会广播同一记录的 `updated` 事件。
  - `/api/admin/peer-mesh/status` 返回与 Java 一致的 `enabled` 字段，可由 `TUNNEL_PEER_MESH_ENABLED` 驱动；设备列表会把当前可见 SQLite client 投影为 disabled/offline 的 Java-shaped device view；SQLite 模式下 ACL 支持 Java-shaped list/create/delete，并复用租户/owner 可见性规则：source 必须当前用户可见、target 必须同租户、普通用户不能创建跨用户 ACL；SQLite 模式下已创建 `peer_mesh_session` 表，并支持 `GET /api/admin/peer-mesh/sessions?limit=`、`DELETE /api/admin/peer-mesh/sessions/{id}`、`DELETE /api/admin/peer-mesh/sessions`，查询和关闭都按租户/owner 可见性过滤。C 目前仍不会由数据面主动创建真实 peer session，其他 Peer Mesh mutation 仍返回 `501`。

## 阶段 3：HTTP 直转与流量观测

状态：Go / .NET 已推进到 DB / Elasticsearch 双后端；前端预览体验仍可继续细化。

- Go client 与 .NET client 已补齐 Java `DirectHttpForwarder` 语义：内网 HTTPS upstream 允许使用自签证书；请求体上限 16 MiB、响应体上限 64 MiB；单段 `Range` 会按 8 MiB 窗口收窄，复杂 multi-range 保持原样交由 upstream 处理；默认不自动重定向、不自动解压；`relativePath` 中的 `//` 按 Java 一样作为同 host 下的普通双斜线路径保留；请求体超限、响应体超限、未配置 route、非法 route 目标、非法/越界转发路径等用户可见错误文案已收敛为 Java 中文消息。
- Go client 与 .NET client 已补齐 Java HTTP route WebSocket 隧道语义：识别 NAT `CONNECTED source=ws`，按当前 HTTP route 快照构造 `ws://` / `wss://` 上游地址，`relativePath` 中的 `//` 作为同 host 下普通双斜线路径保留；过滤 hop-by-hop 与 WebSocket 握手头；WebSocket target 构造失败时的未配置 route、非法 scheme、非法 route 地址和非法 `relativePath` 等错误文案已收敛为 Java 中文消息；内网 `wss` upstream 按 Direct HTTP 的运维场景信任自签证书；本地 WebSocket text/binary frame 会封装为首字节 `0x01/0x02` 的 NAT `DATA source=ws`，服务端回传的 `DATA` 也会按同一前缀还原为 text/binary frame，任一侧断开都会清理 channel 并回发 `DISCONNECTED source=ws`。
- Go server 与 .NET server 的 Direct HTTP 入口已按 Java `request.getRequestURI()` 语义保留原始路径编码：服务端从 raw path 截取 `/http/{clientName}/{route}` 后的部分，`%2F` 不会变成真实斜线，中文等非 ASCII 字符会保持/恢复为 UTF-8 percent-encoding，`rawQuery` 仍保留原始查询字符串。
- Go server 与 .NET server 已对齐管理契约：
  - `tunnel_mapping.detail_capture_enabled`。
  - `http_route_mapping.detail_capture_enabled`。
  - `http_route_mapping.path_rewrite_enabled`。
  - 管理 API 创建、列表、更新均返回/接收 `detailCaptureEnabled`，HTTP 路由额外返回/接收 `pathRewriteEnabled`。
  - 新库 schema 默认关闭这些开关；Go server 与 .NET server 启动初始化会给老库幂等补列。
- Go server 的 TCP 转发背压已补齐 Java/.NET high/low watermark 语义：控制通道写入与外部 socket 写入都会按 `TUNNEL_NETTY_WRITE_BUFFER_LOW_WATER_MARK` / `TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK` 统计待写字节；超过高水位暂停对应读循环，回落到低水位后恢复，不再仅依赖同步写的自然 TCP 回压。
- Go server、.NET server 与 C server 已接入 HTTP 响应路径改写行为：当 `pathRewriteEnabled=true` 时，服务端会在回写浏览器前尝试改写 `text/html` / `text/css` 中的绝对路径，并在 HTML 中注入 Java 对齐的运行时 polyfill，覆盖 `fetch`、`XMLHttpRequest`、`history.pushState/replaceState`、动态元素属性、`EventSource` 和 `WebSocket` 的绝对路径；改写后返回给浏览器的响应会剥离失效的 `Content-Encoding` / `Content-Length`，但 HTTP 明细采集仍保留客户端原始响应头，便于排查上游真实行为；C server 当前支持 `gzip`、zlib `deflate` 与 raw `deflate` 解码后改写。
- Go server 与 .NET server 已补齐数据库版 HTTP/TCP 明细采集链路：
  - 新增 `tunnel_resource_traffic_usage`，并按 TCP 映射 / HTTP route 聚合资源级每日流量。
  - 资源级流量和每日总流量均带 `tenant_id`，管理查询按当前租户和可见客户端收敛。
  - 新增 `tunnel_http_traffic_exchange` 和 `tunnel_tcp_traffic_frame` 表。
  - Direct HTTP 成功、错误响应和 TCP 双向 payload 都会按通道开关写入明细。
  - HTTP 记录保留完整请求/响应 body、Header、响应类型、耗时、状态码和来源信息。
  - TCP 记录保留完整二进制 payload、预览文本、方向、源/目的地址、channelId、streamId、streamIndex 和 streamOffset。
  - 管理 API 已支持资源级流量列表、HTTP/TCP 分页查询、HTTP 字段搜索、TCP 单帧详情和 TCP 串流查询。
  - DB / Elasticsearch HTTP 明细搜索已对齐 Java 语义：`q` 按空白分词，每个 token 必须命中；同一个 token 可在所选字段组内 OR 匹配；默认 `summary` 不扫 header/body，`all` 才包含 header/body；`method`、`status`、`responseBodyType/responseDataType` 使用精确匹配；支持 `id`、`client/clientId`、`resource/resourceId`、`remote`、`contentType`、`error`、`requestHeaders`、`responseHeaders`、`requestBody`、`responseBody` 等字段别名。
  - DB / Elasticsearch HTTP 明细 `responseBodyType/responseDataType` 过滤已补齐 Java 老数据兼容：不支持的类型值视为未指定过滤条件；历史记录缺少 `response_body_type` 时，会按 `response_content_type` 和 `response_bytes=0` 推断 `json/html/xml/image/video/audio/form/script/text/binary/empty`。
  - Direct HTTP 入口请求体超过上限时，Go server 与 .NET server 已和 Java 一样返回 `413` 的同时写入 HTTP 明细记录，保留请求行、headers、已读取 body、错误响应和错误原因，避免超限请求在观测页面消失。
  - Direct HTTP 客户端离线、控制通道写出失败、控制通道等待异常、客户端返回 `error` 时，Go server 与 .NET server 已和 Java 一样把最终回写浏览器的纯文本错误响应写入 HTTP 明细：`Content-Type:text/plain;charset=UTF-8`、错误 body 和错误原因保持一致；Go server 离线文案已对齐 Java 的 `客户端不在线: {clientName}`，写出失败文案已对齐 Java 的 `HTTP 转发请求发送失败`。写出失败在 Java 中属于已得到客户端 error response 的路径，因此 Go server 也已对齐为仍记录 HTTP upload、download 记 0，而不是按 dispatcher exception 跳过汇总记账。
- Go server 与 .NET server 已补齐 Java 风格 Elasticsearch 可选存储：配置 `TUNNEL_ELASTICSEARCH_URIS` 后，HTTP/TCP 明细写入 ES，管理查询从 ES 读取，并按 HTTP 100GB / TCP 10GB 默认体积上限清理最旧记录；未配置时仍使用数据库。
- Go server 与 .NET server 的 HTTP/TCP 明细采集热路径已对齐 Java 队列模型：转发线程只做通道开关判定与入队，后台按 `TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` 周期批量 flush，单类队列由 `TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING` 限制，单次 flush 由 `TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` 限制；管理明细查询默认不强制 flush，需要追最新数据时可显式传 `flush=true`。
- Go server 与 .NET server 已对齐 `gzip`、`deflate` 的 zlib / raw deflate 兼容解码；两者均已支持 `br` 预览解码。后续仍可继续细化更复杂内容类型的前端预览体验。
- C server 已补 Direct HTTP bridge：管理监听的 `/http/{clientName}/{route}/...` 会把普通 HTTP 请求封装为 `DIRECT_HTTP_REQUEST` 发给匹配 `clientName` 的在线控制连接，并等待 `DIRECT_HTTP_RESPONSE` 回写浏览器。WebSocket upgrade 请求会走 Java 兼容的 `source=ws` NAT 通道：server 发送 `CONNECTED`，浏览器 text/binary frame 被封装为带 1 字节类型前缀的 `DATA`，客户端回传同样前缀后由 C server 写回浏览器，任一侧断开都会清理对应 channel。`TUNNEL_HTTP_ROUTES` 会同时出现在 `/api/client/auth/login` 和 `NAT_CONTROL` 的 `httpTunnelConfigList`，让 Java / Go / .NET 客户端能建立 HTTP route 表；服务端转发前也会校验当前在线 session 的 route 必须存在，未配置 route 返回 `404`。当前已具备 Java-shaped 流量汇总查询、SQLite 汇总表，以及 TCP/Direct HTTP 成功传输的热路径汇总记账；SQLite 模式下也已补 `tunnel_http_traffic_exchange` 和 `tunnel_tcp_traffic_frame` 明细表、分页查询、HTTP 字段搜索、TCP frame 详情和 TCP 串流查询；HTTP 字段搜索已按 Java 规则支持空白分词、method/status 精确匹配和常用字段别名；当 SQLite HTTP route 开启 `pathRewriteEnabled` 时，也会对 HTML/CSS 响应做路径改写和 HTML runtime polyfill 注入；在线控制连接已由单个全局指针改为按 clientName 查询的链表，避免后登录客户端覆盖其他在线客户端的 Direct HTTP 分发；管理事件 WebSocket 已支持 Upgrade / token 鉴权 / ping-pong / close，并能广播连接 created/updated 事件。仍不包含 Java 的 ES 明细存储。

## 阶段 4：Peer Mesh 控制面与数据面

状态：Go server 与 .NET server 控制面和标准 STUN/TURN relay 已对齐 Java；Go client 与 .NET client 已补齐 Linux TUN / Windows Wintun / macOS utun、X25519/HKDF/AES-GCM frame 与 UDP 数据面接入。

- Go server：
  - 新增 `Tunnel:PeerMesh` / `TUNNEL_PEER_MESH_*` 配置，默认关闭，默认网段 `100.96.0.0/11`。
  - HTTP 登录响应下发 Java-shaped `peerMesh` 配置。
  - 新增 `peer_mesh_device`、`peer_mesh_acl`、`peer_mesh_session` schema。
  - 实现虚拟 IP 分配、同租户同 owner 默认放行、显式 ACL、会话授权、设备上报、路径/流量上报、强制关闭、roster/config 下发。
  - 已实现 Java 兼容标准 STUN/TURN UDP 服务：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、`SPM1` frame relay 授权和 relay 字节计量；allocation 过期后按 Java 语义拒绝 refresh 并由新 Allocate 重建。
  - 管理 API 已支持状态、设备、ACL、会话查询与清理，并补齐 `/api/admin/peer-mesh/stats`：按 Java 规则统计 `reportedSessions=count(rttMillis)`、`activeDirectRatio`、`pathType × status` 明细和 NAT 类型分布。
- .NET server：
  - 新增 `PeerMeshOptions`、环境变量映射、EF entity、三套 provider migration 与启动兼容建表。
  - 控制通道识别并转发 `PEER_CONTROL`，登录成功后推送 config / roster。
  - 已实现 Java 兼容标准 STUN/TURN UDP HostedService：Binding、alternate port NAT 探测、Allocate/Refresh、CreatePermission、Send/Data Indication、`SPM1` frame relay 授权和 relay 字节计量；allocation 过期后拒绝 refresh 并由新 Allocate 重建。
  - HTTP 登录响应与公开 `/api/public/peer-mesh/stun-config` 均下发自建 STUN/TURN 与公共 STUN 列表。
  - 管理 API 与 Go/Java 对齐，并补齐 `/api/admin/peer-mesh/stats`：按 Java 规则统计 `reportedSessions=count(rttMillis)`、`activeDirectRatio`、`pathType × status` 明细和 NAT 类型分布。
- Go client：
  - 已读取 Java 启动配置里的 `peerMeshDevice`、`peerMeshTunName`、`peerMeshMtu`。
  - 登录时生成并持久化 X25519 peer key；上报格式已改为 Java 兼容的 X.509 DER public key，同时保留读取旧 raw key 文件能力。
  - 已识别 HTTP 登录响应与 `PEER_CONTROL` 下发，支持 `peer-config`、`roster`、`session-grant`、`candidates`、`close`。
  - 已实现 Peer Mesh UDP 控制面：标准 STUN/TURN `Binding` / `Allocate` / `Refresh` / `CreatePermission` / `Send` / `Data Indication`、host/srflx/public-stun/relay candidate 上报、UDP connectivity check、`path-report`。
  - 已实现 Java 兼容的数据帧：`SPM1` header、X25519 + HKDF-SHA256 会话密钥、AES-GCM payload 加密、AAD 绑定 session/client/sequence/nonce、64 包 replay window。
  - 已实现 Linux `/dev/net/tun` 虚拟网卡：配置 /32 虚拟 IP 与 MTU；TUN 出站 IPv4 packet 按目标虚拟 IP 查 peer session 后走 direct UDP 或标准 TURN relay；入站 frame 解密后写回 TUN。
  - 已实现 Windows Wintun 随包加载：Go client 通过 `go:embed` 内置 `native/windows/<arch>/wintun.dll`，运行时解压到本地缓存后加载；仍可通过 `SHUAI_PEER_MESH_WINTUN_DLL` 或可执行文件旁 native 目录覆盖，配置 /32 虚拟 IP 与 MTU，并接入同一套加密数据帧。
  - 已实现 macOS `utun`：通过 `com.apple.net.utun_control` 创建 utun 设备，配置 /32 虚拟 IP 与 MTU，读写时处理 Darwin utun 4 字节地址族前缀，并接入同一套加密数据帧。
  - 已对齐 Java per-peer OS 路由同步（`syncPeerRoutes`）：虚拟网卡不再安装 mesh 网段路由（配置时会静默清理残留网段路由），startOrUpdate（含配置未变的轻量刷新）、roster 更新和 candidates 信令合并时按在线 peer 虚拟 IP 增删 /32 host 路由，设备关闭时清理全部已同步路由；Linux TUN / Windows Wintun / macOS utun 三个平台实现，noop 设备保持 no-op。
  - 已对齐 Java 虚拟包目标过滤：TUN 出站包目标为组播/保留段/受限广播、mesh 网段 network/broadcast 边界地址、本机虚拟 IP，或不属于任何在线 peer 时早期丢弃并按 30 秒节流记录 debug 日志，不再进入 pending 队列或按 flow 告警。
  - roster 删除语义已对齐 Java `updateRoster` 清空重建：被移出 roster 的 peer 立即从 peers 表消失（对应 host 路由同步移除），仍在 roster 中的 peer 保留已学 candidates，`probeKnownCandidates` 不受 roster 推送影响。
  - 已按 Java 语义在 token 快过期前主动刷新 HTTP 登录态，刷新成功后热更新 TCP 映射、HTTP route 和 Peer Mesh 配置，不中断当前控制连接。
  - 已按 Java 语义周期上报 `traffic-report` 增量 direct 字节；relay 字节由 server 的标准 TURN relay 热路径计量，避免重复统计。
  - NAT 探测上报值已收敛为 Java 枚举：`NO_NAT`、`PORT_PRESERVED_NAT`、`PORT_RESTRICTED_NAT`、`FULL_CONE_OR_RESTRICTED_NAT`、`SYMMETRIC_NAT`、`NAT`；已消费 server 主端口、备用端口和公共 STUN 观测；当探测为 `SYMMETRIC_NAT` 时不再上报 host / srflx direct candidate，不再接受 direct check / data frame，优先等待标准 TURN relay。
  - relay candidate 请求节流已对齐 Java：allocation 新鲜时 60 秒内不重复请求，allocation 缺失或快过期时 15 秒内不重复请求；alternate NAT probe 15 秒内不重复发送。
  - 收到对端 connectivity check 时会和 Java 一样立即记录入站 direct/relay 路径；relay data 入站时同步刷新 `relayTargetAllocationId`，避免只能等本端主动探测成功后才可回包。
  - 路径选择细节已对齐 Java：已绑定 `relayTargetAllocationId` 时数据面优先走 relay；direct 路径 45 秒内仍健康时不会被本端 relay check-response 抢占；收到 direct 数据帧会清理旧 relay allocation，避免路径状态残留。
  - `path-report` 与 active path 日志节流已对齐 Java：路径变化立即上报；路径不变时 60 秒内不重复刷控制面。
  - TUN 出站虚拟包在 session/path 未就绪时会按 Java 策略短暂排队：每个 peer 最多 32 个、8 秒 TTL；路径准备会主动重新上报 candidates / 触发 connectivity check，主动探测或收到对端数据导致路径就绪后都会 flush，避免 TCP SYN 等第一批包被直接丢弃。
  - 当虚拟设备为 `noop` 时，收到目标为本机虚拟 IP 的 ICMP echo request 会和 Java 一样在应用层构造 echo reply 并加密发回；真实 TUN / Wintun / utun 路径仍交给系统协议栈处理。
- .NET client：
  - 已读取 Java 启动配置里的 `peerMeshDevice`、`peerMeshTunName`、`peerMeshMtu`。
  - 登录环境已生成并上报 Java 兼容的 X25519 X.509 DER public key；key 文件使用 `.shuai-tunnel/peer-public.x25519` 与 `.shuai-tunnel/peer-private.x25519`。
  - 已补 Java 兼容的 `SPM1` AES-GCM frame codec、X25519/HKDF 会话密钥派生和 replay window 单测。
  - 已识别 HTTP 登录响应与 `PEER_CONTROL` 下发，支持 `peer-config`、`roster`、`session-grant`、`candidates`、`close`。
  - 已实现 Peer Mesh UDP 控制面：标准 STUN/TURN `Binding` / `Allocate` / `Refresh` / `CreatePermission` / `Send` / `Data Indication`、host/srflx/public-stun/relay candidate 上报、UDP connectivity check、`path-report` 和 direct-only traffic-report 增量上报；relay 字节由 server relay 热路径计量，避免重复统计。
  - 已实现 Linux `/dev/net/tun` 虚拟网卡：配置 /32 虚拟 IP 与 MTU；TUN 出站 IPv4 packet 按目标虚拟 IP 查 peer session 后走 direct UDP 或标准 TURN relay；入站 frame 解密后写回 TUN。
  - 已实现 Windows Wintun 随包加载：.NET client 项目文件会把 Java 参考资源里的 `native/windows/<arch>/wintun.dll` 复制到 build / publish 输出目录，运行时优先从输出目录 native 路径加载；仍可通过 `SHUAI_PEER_MESH_WINTUN_DLL` 覆盖，配置 /32 虚拟 IP 与 MTU，并接入同一套加密数据帧。
  - 已实现 macOS `utun`：通过 `com.apple.net.utun_control` 创建 utun 设备，配置 /32 虚拟 IP 与 MTU，读写时处理 Darwin utun 4 字节地址族前缀，并接入同一套加密数据帧。
  - 已对齐 Java per-peer OS 路由同步（`IPeerVirtualDevice.SyncPeerRoutesAsync`，接口默认 no-op）：虚拟网卡不再安装 mesh 网段路由（配置时会静默清理残留网段路由），StartAsync（含配置未变的轻量刷新）、roster 更新和 candidates 信令合并时按在线 peer 虚拟 IP 增删 /32 host 路由，设备 DisposeAsync 时清理全部已同步路由；Linux TUN / Windows Wintun / macOS utun 三个平台实现。
  - 已对齐 Java 虚拟包目标过滤：TUN 出站包目标为组播/保留段/受限广播、mesh 网段 network/broadcast 边界地址、本机虚拟 IP，或不属于任何在线 peer 时早期丢弃并按 30 秒节流记录 debug 日志，不再进入 pending 队列或按 flow 告警。
  - roster 删除语义已对齐 Java `updateRoster` 清空重建：被移出 roster 的 peer 立即从 peers 表消失（对应 host 路由同步移除），仍在 roster 中的 peer 保留已学 candidates，周期性 probe 探测不受 roster 推送影响。
  - 已按 Java 语义在 token 快过期前主动刷新 HTTP 登录态，刷新成功后热更新 TCP 映射、HTTP route 和 Peer Mesh 配置，不中断当前控制连接。
  - NAT 探测上报值已收敛为 Java 枚举：`NO_NAT`、`PORT_PRESERVED_NAT`、`PORT_RESTRICTED_NAT`、`FULL_CONE_OR_RESTRICTED_NAT`、`SYMMETRIC_NAT`、`NAT`；已消费 server 主端口、备用端口和公共 STUN 观测；当探测为 `SYMMETRIC_NAT` 时不再上报 host / srflx direct candidate，不再接受 direct check / data frame，优先等待标准 TURN relay。
  - relay candidate 请求节流已对齐 Java：allocation 新鲜时 60 秒内不重复请求，allocation 缺失或快过期时 15 秒内不重复请求；alternate NAT probe 15 秒内不重复发送。
  - 收到对端 connectivity check 时会和 Java 一样立即记录入站 direct/relay 路径，避免只能等本端主动探测成功后才可回包。
  - STUN Binding Success 已消费 `XOR-MAPPED-ADDRESS` 与 `OTHER-ADDRESS`，并支持公共 STUN 观测补充 srflx candidate，便于更复杂 NAT 下提高 direct 探测覆盖面。
  - 路径选择细节已对齐 Java：已绑定 `relayTargetAllocationId` 时数据面优先走 relay；direct 路径 45 秒内仍健康时不会被本端 relay check-response 抢占；收到 direct 数据帧会清理旧 relay allocation，避免路径状态残留。
  - `path-report` 与 active path 日志节流已对齐 Java：路径变化立即上报；路径不变时 60 秒内不重复刷控制面。
  - TUN 出站虚拟包在 session/path 未就绪时会按 Java 策略短暂排队：每个 peer 最多 32 个、8 秒 TTL；路径准备会主动重新上报 candidates / 触发 connectivity check，主动探测或收到对端数据导致路径就绪后都会 flush，避免 TCP SYN 等第一批包被直接丢弃。
  - 当虚拟设备为 `noop` 时，收到目标为本机虚拟 IP 的 ICMP echo request 会和 Java 一样在应用层构造 echo reply 并加密发回；真实 TUN / Wintun / utun 路径仍交给系统协议栈处理。
  - 当前 .NET 数据面已经接通协议和虚拟设备，仍需要真实 Windows / Linux / macOS 双机环境做 ping、HTTP、relay fallback 手工验收。
- C server：
  - `/api/client/auth/login` 返回 disabled `peerMesh` block。
  - `/api/client/auth/login` 同步返回 TCP 映射快照，便于非 Java 客户端在 HTTP 登录阶段按 Java 响应结构获取配置。
  - SQLite `http_route_mapping` 和 `TUNNEL_HTTP_ROUTES` 会合并下发为 `httpTunnelConfigList`，管理 HTTP listener 已能在校验 route 存在后把 `/http/{clientName}/{route}/...` 转发到当前在线控制连接，形成最小 Direct HTTP 数据面。
  - SQLite `traffic_usage` / `resource_traffic_usage` 已支持 Java-shaped 查询；TCP 隧道按 `TCP_TUNNEL` + `tcp:{listenPort}` 写汇总，Direct HTTP 按 `HTTP_ROUTE` + `http:{route}` 写汇总。
  - 管理面补齐 Peer Mesh 管理契约：设备列表会为可见 SQLite client 幂等创建轻量 `peer_mesh_device` 行并返回 offline view，`PUT /api/admin/peer-mesh/devices/{clientId}` 可在租户/owner 权限内持久化 `enabled`，但虚拟网卡状态仍固定为 `UNSUPPORTED`；SQLite ACL 可 list/create/delete，ACL 输入已按 Java 侧 `long` clientId 语义解析 64 位 ID；SQLite `peer_mesh_session` 可 list/close/close-open，并按租户/owner 可见性过滤，未知单个 session 返回 `404`；C 数据面仍不主动创建真实 peer session，其余 mutation 返回 `501`。
  - `/api/admin/peer-mesh/status` 已收敛为 Java-shaped `{ "enabled": boolean }`，不再额外暴露 C 专属 stub 字段。

端到端手工验收计划（代码能力已具备，需要真实网络环境验证）：

1. Go client：用真实 macOS / Windows / Linux 双机验证 ping、HTTP 和 relay fallback，并根据验收结果细化虚拟网卡错误恢复。
2. Go server：和 Java 标准 STUN/TURN relay 做真实跨 NAT 压测，重点验证 direct 失败后 relay fallback、relay 计量和管理页面链路展示。
3. .NET client：用真实 Windows / Linux / macOS 双机验证 ping、HTTP、relay fallback，并根据验收结果细化 Wintun/TUN/utun 错误恢复。
4. .NET server/client：做真实跨 NAT 压测，验证 direct 失败后的标准 TURN relay fallback、relay 计量和管理统计。
5. C server/client：当前阶段冻结在轻量管理面和最小兼容数据面，不继续扩展 Peer Mesh 数据面。

## 阶段 5：TLS、数据库和端到端验证

状态：部分完成。

- Java 是参考实现。
- Go server 支持控制通道与管理 HTTP TLS，`file` 模式已对齐 Java/.NET 的 PKCS12 / PFX keystore 读取；未配置 keystore 时仍兼容 PEM 证书和私钥文件。
- .NET server 支持 EF Core 多库和 TLS 配置；管理用户、流量明细、总流量租户字段、Peer Mesh 表均已补齐 provider-specific migration，并保留启动时幂等 SQL 兼容历史库。
- C server 尚未实现 TLS、HTTPS OIDC token exchange、ES 明细存储和 Peer Mesh 数据面；`/oidc-config` 已按 Java 前端契约返回浏览器登录配置，`/oidc/token` 已支持 HTTP token endpoint 的 Authorization Code + PKCE 代理交换，管理用户、客户端凭证、客户端应用包下载链接、客户端、映射、route、连接记录、流量汇总、SQLite 明细查询、SQLite 客户端启动凭证登录和 Direct HTTP 响应路径改写已具备基础租户/owner 过滤或 route 开关控制。

## 当前验证

- Go server：`go test ./...` 历史通过；本轮补充执行 `GOCACHE=.gocache go test ./internal/peermesh ./internal/store ./internal/management` 通过，覆盖 Java 对齐的控制通道/外部 socket high-low watermark 背压门控、HTTP/TCP 明细采集队列、`TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING` / `TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` / `TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` 配置映射、管理明细查询默认不 flush 且支持 `flush=true`、HTTP 登录租户返回、`/api/admin/database/initialize` 的 `tenantId` 与租户内客户端计数、连接记录 `tenant_id` 写入/查询、连接归档统计 `tenant_id` 聚合隔离、`TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS` / `TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS` 归档配置映射与 UTC 自然日 cutoff、`TUNNEL_CLIENT_AUTH_*` 与 Java login executor 环境变量别名、运行时会话持久化、HTTP 启动登录 token TTL 使用 `client-auth` 配置、同机单实例、凭证最大在线实例、协议 fixtures、CompactBinary UUID 非 canonical 大小写保真、CompactBinary HTTP Method 非 canonical 大小写保真、空 UUID / 空 HTTP Method 按 Java 语义保留为普通字符串 marker、nil / empty byte array 与 string list marker 区分、`clientSessionId=0L` 按 Java 语义保留为非空 long marker、`MessageResponse + PEER_CONTROL` 编解码、NAT metadata 字符串 `toString` / 整数数字字符串容错、HTTP 启动登录、控制通道登录/心跳、NAT 回环、admin API、Direct HTTP 服务端入口 raw encoded `relativePath` 保真、HTTP route 响应路径改写与 Java 对齐 runtime polyfill 注入、HTTP 明细搜索字段语义、`responseBodyType` 老数据 Content-Type fallback、Direct HTTP 超限 413 明细记录、Direct HTTP 离线、控制通道写出失败与客户端 error 的 Java-shaped 纯文本错误明细记录、Direct HTTP 写出失败仍记录 upload/download=0 的 Java 汇总语义、`/ws/connections` WebSocket 鉴权、Java-shaped `tenantId` 事件与端到端事件订阅、OIDC、TLS、客户端应用包下载链接 admin CRUD / public enabled-list，以及 Peer Mesh `candidates -> session-grant -> signal forward`、设备禁用关闭 open session 并通知两端、`SPM1` relay frame 只允许 active 且 peer pair 匹配的 session、成功 relay 计量、过期 session 自动关闭、negotiating / 错 peer 拒绝、标准 TURN allocation 过期重建、CreatePermission、Send/Data Indication、relay 转发和 `/api/admin/peer-mesh/stats` 聚合统计的 Java 语义。
- Go client：本轮在 `implementations/go/client` 重新执行 `go build ./...` 与 `go test ./...` 通过（覆盖 per-peer OS 路由同步、虚拟包目标过滤与 roster 清空重建改动后的回归），并执行 `GOOS=linux GOARCH=amd64 go test -c ./internal/client`、`GOOS=darwin GOARCH=arm64 go test -c ./internal/client`、`GOOS=darwin GOARCH=amd64 go test -c ./internal/client` 覆盖 Linux TUN 与 macOS utun 路由同步的 build tag 编译；包含启动配置 http/https `serverBaseUrl` 校验、CompactBinary UUID 非 canonical 大小写保真、空 UUID 按 Java 语义保留为普通字符串 marker、nil / empty byte array 与 string list marker 区分、`clientSessionId=0L` 按 Java 语义保留为非空 long marker、`DirectHTTPResponse.error` null / empty string marker 区分、Direct HTTP 自签 HTTPS upstream、8 MiB Range 裁剪、双斜线 `relativePath` 保留、编码 `..` 段拒绝、请求体/响应体超限与 route/path 错误的 Java 中文文案、`MessageResponse + PEER_CONTROL` 解码、`NAT_CONTROL.httpTunnelConfigList` 缺省保留 / 空数组清空 / 有值替换三态语义、NAT metadata 字符串 `toString` / 整数数字字符串容错、HTTP route WebSocket target 双斜线路径保留 / target 构造错误 Java 中文文案 / 握手头过滤 / 本地 text frame 转 NAT `DATA source=ws`、普通 TCP `CONNECTED` 无效端口/元数据忽略语义、`LOGOUT_REQUEST` 关闭控制连接、Java 风格重连指数退避、控制登录失败分类、5 秒心跳 / 60 秒读空闲、Java NAT 枚举值、`changed-port` 分类、relay candidate / alternate NAT probe 节流、relay allocation 优先发送、健康 direct 不被 relay probe 抢占、`SYMMETRIC_NAT` direct candidate 抑制、pending virtual packet 队列、noop 虚拟设备 ICMP echo 应用层响应、X25519/HKDF/AES-GCM frame、raw/DER public key 兼容、replay window、public STUN candidate 生命周期、运行时 token 主动刷新和内置 Wintun 资源解压相关编译覆盖；历史交叉编译命令 `GOOS=linux GOARCH=amd64 go test -c ./internal/client`、`GOOS=darwin GOARCH=arm64 go test -c ./internal/client`、`GOOS=darwin GOARCH=amd64 go test -c ./internal/client` 用于覆盖 Linux TUN 与 macOS utun build tag。
- .NET server：本轮执行 `dotnet build implementations\csharp\server\src\ShuaiTunnel.Server\ShuaiTunnel.Server.csproj --no-restore -p:TunnelServerWebSkip=true -v minimal` 通过；`dotnet test implementations\csharp\server\tests\ShuaiTunnel.IntegrationTests\ShuaiTunnel.IntegrationTests.csproj --no-restore -p:TunnelServerWebSkip=true -v minimal --filter "FullyQualifiedName~StunTurnServerTests"` 通过，覆盖标准 STUN/TURN allocation 过期重建、Refresh error、CreatePermission、Send Indication 和 Data Indication；`dotnet test implementations\csharp\server\tests\ShuaiTunnel.IntegrationTests\ShuaiTunnel.IntegrationTests.csproj --no-restore -p:TunnelServerWebSkip=true -v minimal --filter "FullyQualifiedName~PeerMeshServiceTests"` 通过，当前 7 个用例，覆盖 peer session 授权、关闭、relay frame 授权和 `/api/admin/peer-mesh/stats` 同口径聚合。AdminApiTests 在当前环境因测试配置里的 PostgreSQL connection string 不完整报 `Couldn't set data source`，未作为本轮回归结论。
- .NET client / protocol：本轮执行 `dotnet build implementations\csharp\client\src\ShuaiTunnel.Client\ShuaiTunnel.Client.csproj -v minimal` 通过；`dotnet test implementations\csharp\client\tests\ShuaiTunnel.Client.Tests\ShuaiTunnel.Client.Tests.csproj` 通过，当前 69 个用例（覆盖 per-peer OS 路由同步、虚拟包目标过滤与 roster 清空重建改动后的回归），包含标准 STUN/TURN Binding、Allocate、Refresh、CreatePermission、Send Indication、relay candidate / alternate NAT probe 节流、relay allocation 优先发送、健康 direct 不被 relay probe 抢占、pending virtual packet 队列、Peer Mesh frame/replay/key 派生、IPv4 packet 解析、noop 虚拟设备 ICMP echo 应用层响应、macOS utun 路由 CIDR 计算与运行时 token 主动刷新编译覆盖；protocol 测试沿用此前通过结论。
- C server：本机未安装 `make` / C 编译器，`make test` 未执行成功；当前补齐了 Java `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` 与 `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` 配置别名及测试用例，旧变量仍兼容；同时补齐了 SQLite `/api/client/auth/login` 的 Java 兼容 HMAC 校验、机器用户身份创建/复用、`tunnel_client_session` 写入、Netty 登录校验与 `HTTP_AUTHENTICATED -> NETTY_ONLINE -> DISCONNECTED` 状态迁移、本地 HS256 管理 token 签发/刷新/校验、Direct HTTP 普通请求 bridge、Direct HTTP WebSocket upgrade bridge、管理 `/ws/connections` WebSocket Upgrade 鉴权入口和连接事件广播、SQLite 管理用户 / 数据库初始化 / 客户端凭证 / 客户端应用包下载链接 / 客户端 / TCP 映射 / HTTP route 管理、`GET /api/admin/connections` Java-shaped 分页查询、`GET /api/admin/connection-stats` 归档统计查询、`GET /api/admin/traffic` 和 `GET /api/admin/traffic/resources` 流量汇总查询代码与单测用例，并已将这些查询切到租户/owner 过滤后的 SQL 口径；TCP 隧道与 Direct HTTP 成功传输已接入汇总记账和 SQLite 明细采集，HTTP/TCP 明细分页、TCP frame 详情、TCP 串流查询已从空分页推进到真实 DB 查询；Peer Mesh 管理面已支持设备列表、设备 enabled 持久化、ACL list/create/delete、session list/close/close-open 与 64 位 clientId JSON 解析；Direct HTTP 响应路径改写已补 HTML/CSS、runtime polyfill 和 gzip/deflate 解码用例，仍待 Linux/C 工具链环境实际编译和 Java client 联调验证。
