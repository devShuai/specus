# 跨语言对齐：C server API 盘点

> 本文属于 [跨语言对齐](../cross-language-java-alignment-plan.md) 系列，为 Issue #35 的三项而写：「Elasticsearch HTTP/TCP 明细存储、搜索与归档语义」「live client-message 与管理/客户端 WebSocket 事件」「客户端发布、下载链接、审计及剩余 Java 管理 API 契约」。与 [c-server-test-map.md](c-server-test-map.md) 互补：那份按 Java 测试类对照，本文按 Java 端点对照。

清单按 2026-10-08 `fix/c-server-api-inventory` 分支（已合入 `main` `9deb086`）的源码逐项核对，最后 27 个 Peer Mesh / Egress 端点由 `fix/c-server-parity-peer-api` 逐项对照（第 9 节第 8 项）：Java 端点取自 `implementations/java/server` 中全部 `@RequestMapping/@GetMapping/@PostMapping/@PutMapping/@DeleteMapping` 与两个 `WebSocketConfigurer` 的 `addHandler` 注册，鉴权取自 `SecurityConfig`；C 端点取自 `src/admin_http.c` 的 `st_admin_build_response_internal`、监听器分发（`admin_handle_client`）与 `src/main.c`。`fix/c-server-parity-peer`、`fix/c-server-parity-rest` 尚未合入，合入后涉及的行要复核（见各行说明）。

## 读法

- **一致**：C 有对应实现，行为与 Java 一致，并有测试依据（下列 C 测试、中央向量，或 `c-server-test-map.md` 中记为「覆盖」的 Java 测试类）。
- **有差异**：C 有对应实现，但有已知的行为差异，“说明”写出差异；平台差异另在第 8 节列明原因。
- **没有**：C 没有对应实现。
- **未逐项对照**：C 有对应路由，鉴权与主要形状已核对，但请求校验、状态码等细节没有逐项对照 Java，也没有对照测试；列为待办（第 9 节），不算作一致。
- **本分支**：本分支修正过的行，提交见第 10 节。
- Spring 在进入 controller 之前拒绝的请求（必填参数缺失、参数转不成 `Long`/`int`、必需的请求体缺失或不是对象）回 400，Spring Boot 的错误体以 `"error":"Bad Request"` 表示状态；C 回同样的 400 与 `{"error":"Bad Request"}`，不带 `timestamp`、`path` 等字段。`fix/c-server-parity-crud` 按此处理了它对照的端点；`fix/c-server-parity-peer-api` 补齐其余：带类型的查询参数（`Long`/`Integer`/`boolean`）在分发前按 Spring 的规则转换（空白去掉、可带 `0x`/`#` 的十六进制；布尔认 true/false/on/off/yes/no/1/0），转不了或必需参数缺失即 400；Peer Mesh、映射新增、客户端新增与修改、HTTP 路由新增与修改、凭据的 `enabled` 与客户端下载链接的请求体按 Jackson 绑定（缺请求体或不是对象 400；数字字符串可转 `Long`/`Integer`，带小数的数截断，`"TRUE"`、整数可转 `Boolean`，`"1"`、`"yes"` 不行，对象或数组不能转 `String`）；Peer Mesh 的路径变量转不了 400，0 与负数照样交给服务回它的「找不到」。
- 鉴权：「公开」= `SecurityConfig` 中 `permitAll`；「Bearer」= 需要管理端本地 HS256 token（C 每次请求按 SQLite 重新读取用户）；「Bearer（任意）」= `/api/public/transfer/attachments/**`，任何已认证主体；「ticket」= WebSocket 一次性 ticket。

## 汇总

Java server 共 **141** 个端点：136 个 HTTP 映射（`/http/**` 与 `/http-share/**` 各计 1 个）和 5 个 WebSocket 端点。

| 状态 | 数量 | 说明 |
| --- | ---: | --- |
| 一致 | 126 | 其中 10 个是本分支修正后才一致，2 个是 #191 修正后才一致，2 个是 `fix/c-server-parity-edges` 修正后才一致，12 个是 `fix/c-server-parity-crud` 逐项对照（多数先修正）后才一致，24 个是 `fix/c-server-parity-peer-api` 逐项对照（多数先修正）后才一致（Peer Mesh / Egress 22 个，映射新增，HTTP 明细详情的 `br`） |
| 有差异 | 15 | 见各节“说明”，可修的列入第 9 节；`fix/c-server-parity-crud` 对照的 14 个里有 2 个（`/auth/register`、`database/initialize`）；`fix/c-server-parity-peer-api` 对照的 27 个里有 5 个（服务新增与更新的名称字节上限、服务审计存库、`stun-config` 与 `ice-config` 不发布没有服务在听的备用地址） |
| 没有 | 0 | 每个 Java 端点在 C 都有对应路由 |
| 未逐项对照 | 0 | 最后 27 个（Peer Mesh / Egress）已由 `fix/c-server-parity-peer-api` 逐项对照 |

C 独有、Java 没有的端点：`GET /health`（`{"status":"ok"}`）、`GET /api/admin/metrics`（C 的映射计数快照）。

本分支修正的偏差（第 10 节有提交）：Elasticsearch 搜索、可见范围、写入队列、节点列表与 `tcp-streams` 契约；TCP 帧采集顺序；超过 32 KiB 的管理读应答被静默丢弃；客户端、映射、路由、凭据、用户、客户端目录列表的固定行数上限（超过后 500 或静默截断，目录截断后客户端看不到最新版本）；概览字段；管理员看不到已删除客户端和未知名称的连接记录；流量统计 `limit` 上限；客户端到管理员消息不检查来源账号；写入失败回执；命令 JSON 映射严格性；`/ws/connections` 的二进制与未掩码帧。

`fix/c-server-parity-crud` 修正的偏差（第 9 节第 5、7 项，提交见第 10 节末）：凭据与映射的找不到、apiKey 重复原先回 404/409，Java 是 400 并带 id；凭据的 `maxOnlineInstances` 不限范围、生成的 apiKey 与 secret 形状不同、更新应答不带 `"secret":null`；映射更新的字段原先可省略、省略 `enabled` 时保留原值、公网端口只在同一客户端内查重；映射列表与两个流量统计的 `clientId` ≤ 0 不过滤，非数字参数被忽略；名称可用性的 `excludeClientId` 不可见时 404；`/me` 的时间戳为空串；初始化把演示客户端写进固定的 `default` 租户；管理员看不到已删除客户端的流量统计，资源类型不规范化；注册先校验字段再做人机验证、文案与 Java 不同、长度按字节计；Peer 服务导入按整个租户去重；这几类视图的时间戳是 SQLite 的 `YYYY-MM-DD HH:MM:SS`。

`fix/c-server-parity-peer-api` 修正的偏差（第 9 节第 8 项，提交见第 10 节末）：Peer Mesh / Egress 27 个端点的请求绑定、检查顺序、文案、状态码（新增回 200、删除回 200 无正文、找不到回 Java 的 400 或 404）、视图字段（设备只列已有的、`null` 而非占位值、会话的 `lastKeepaliveAt`、开关的 `null`）与 ISO-8601 时间；管理端关闭会话、关闭设备、改 ACL 后通知两端（`close`）；服务目标与导入候选按 `requireTargetHost`；映射新增不再是同客户端同端口的 upsert，公网端口全局唯一，客户端找不到 400；客户端、路由、下载链接、连接记录、月度统计、用户、流程图、ACL、设备、会话、服务、出口策略与开关、共享与审计视图的时间由 SQLite 的 `YYYY-MM-DD HH:MM:SS` 改为 ISO-8601；其余带类型的查询参数按 Spring 转换；`X-Forwarded-Host` 取第一个；构建带 libbrotlidec 时解码 `br`。

`fix/c-server-parity-edges` 修正的偏差（第 9 节第 2、3、6 项，提交见第 10 节末）：Peer Mesh 列表与全库客户端列表的固定行数上限、会话列表缺 Java 的分页形式；SQLite 流量搜索的字段、通配与 WHERE 长度，管理员看不到已删除客户端的流量；普通用户看到按名称匹配的失败登录；`listenPort=0`、`clientId` ≤ 0 不过滤；裁剪时 `total_data_set_size_in_bytes` 为 0 改读 `size_in_bytes`；`/ws/connections` 文本上限与 UTF-8 校验；命令成员为数字或布尔值时读作缺失。

## 1. 认证、身份与管理用户

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/login` | 公开 | `{username,password,turnstileToken?,tenantId?}` → 本地 token | 一致 | test-map 第 1 节 `LoginRateLimiterTests`、`PasswordServiceTests`、`TurnstileVerifierTests`、`ManagementContextResolverTests` 均为覆盖 |
| POST | `/auth/register` | 公开 | 注册申请（邮箱验证码），202 `{registrationId,emailMasked,expiresAt,resendAfterSeconds}` | 有差异 | `fix/c-server-parity-crud` 对照 `AuthController.register` 与 `RegistrationService.requestRegistration`（ctest `management_crud_tests`）：原先先校验字段、最后才做人机验证，现与 Java 相同先验证 Turnstile，再依次查用户名、保留名、口令、邮箱；超长用户名与口令原先报 `… cannot be blank`、空邮箱报格式无效、已有登录名不带名字，现为 Java 的 `username is too long`、`password is too long`、`邮箱不能为空`、`用户名已存在: <名>`；长度按 Java 的 UTF-16 单元计；邮箱原先接受多个 `@`、`a@.com`、连续的点，现按 Java 的正则与 `InternetAddress` 严格解析的规则拒绝。剩余差异：C 的登录名在存储与 token 中占 80 字节（`POST /api/admin/users` 同样），超过 80 字节但不超过 80 个字符的非 ASCII 用户名 Java 接受、C 回 `username is too long`；带引号的本地部分与 `[…]` 域名 Java 接受、C 拒绝；`expiresAt` 精确到秒（Java 的 `Instant.toString` 可带小数秒） |
| POST | `/auth/register/verify` | 公开 | `{registrationId,code}` → 本地 token | 一致 | `fix/c-server-parity-crud`（`management_crud_tests`）：`registrationId` 按发送的原文限 64 个字符再 trim（原先先 trim 再计长）；登录名与邮箱都已被占用时先报 `用户名已存在: <名>`（原先先报邮箱） |
| POST | `/auth/refresh` | Bearer | 续期本地 token；IdP token 400 | 一致 | `AuthControllerRefreshTests` 覆盖 |
| GET | `/oidc-config` | 公开 | OIDC、注册、Turnstile 配置 | 一致 | `OidcControllerTests` 覆盖 |
| POST | `/oidc/token` | 公开 | code → 本地 token | 一致 | `OidcControllerTests`、`SecurityConfigOidcTests` 覆盖（ctest `oidc_tests`） |
| POST | `/api/client/auth/login` | 公开（HMAC 签名） | 客户端 HTTP 登录，返回会话 token 与配置 | 有差异 | 已消费的 nonce 存进程内存，多实例不共享（`ClientAuthNonceServiceIntegrationTests` 部分）。`fix/c-server-parity-rest` 改为存库，合入后复核 |
| GET | `/api/admin/me` | Bearer | 当前管理用户 | 一致 | `fix/c-server-parity-crud` 对照 `ManagementUserService.currentUser`（`management_crud_tests`）：内置管理员以配置的用户名、调用者的租户、`ADMIN`、创建与更新时间为当前时刻；数据库用户取其账号行（含 `createdAt`/`updatedAt`）。原先两个时间戳都是空串 |
| GET | `/api/admin/users` | Bearer | 本租户用户列表 | 有差异 | **本分支**去掉 128 行上限（ctest `management_lists_tests`）。差异同 test-map `ManagementUserServiceTests`：username 是全局主键，不同租户同名用户不存在 |
| POST | `/api/admin/users` | Bearer（admin） | 创建用户 | 有差异 | 其他租户已有同名用户时 C 回 409，Java 允许（同上） |
| PUT | `/api/admin/users/{username}` | Bearer（admin） | 改角色、启用、口令 | 有差异 | 其他租户的用户 C 回 404，Java 回 400（`ManagementUserServiceIntegrationTests` 部分） |
| DELETE | `/api/admin/users/{username}` | Bearer（admin） | 删除用户 | 有差异 | 同上 |

## 2. 客户端账号、凭据与 TCP 映射

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/admin/clients` | Bearer | 可见客户端列表（管理员为本租户） | 一致 | `ClientAccountServiceTests` 覆盖可见性；**本分支**去掉 128 行上限（原先全库超过 128 个客户端时所有租户都得 500），`management_lists_tests`。`fix/c-server-parity-peer-api`：时间为 ISO-8601（原先 SQLite 的 `YYYY-MM-DD HH:MM:SS`，`peer_mesh_api_tests`） |
| GET | `/api/admin/clients/name-availability` | Bearer | 名称是否可用 | 一致 | `fix/c-server-parity-crud`（`management_crud_tests`，规则另见 `ClientAccountServiceTests` 行）：缺 `clientName`、`excludeClientId` 不是数字时 400；空白名称为 `clientName cannot be blank`（原先 `clientName is required`）；`excludeClientId` 不可见（含 0 与负数）时 400 `client not found: <id>`（原先 404，0 与负数被忽略） |
| GET | `/api/admin/clients/{id}` | Bearer | `{client, specusMappings, httpRoutes}` | 一致 | 原先单个客户端超过 64 条 TCP 映射或 64 条 HTTP 路由时读取失败；#191 起不限条数（`client_route_scale_tests`） |
| POST | `/api/admin/clients/{id}/force-refresh-port-mapping` | Bearer | 推送 NAT_CONTROL，回 `{specusMappings,httpRoutes}` | 有差异 | C 多回一个 `pushed`（兼容字段，无害）；每客户端 64 条的上限已在 #191 去掉 |
| POST | `/api/admin/clients` | Bearer | 创建客户端，201 | 一致 | `ClientAccountServiceTests` 覆盖 |
| PUT | `/api/admin/clients/{id}` | Bearer | 改名、停用（踢下线） | 一致 | `ClientAccountServiceTests` 覆盖 |
| DELETE | `/api/admin/clients/{id}` | Bearer | 删除并踢下线，204 | 一致 | `ClientAccountServiceTests` 覆盖 |
| GET | `/api/admin/client-credentials` | Bearer | 本租户凭据 | 一致 | **本分支**修正：原先超过 128 条时静默截断（`management_lists_tests`）。`fix/c-server-parity-crud` 对照 `ClientCredentialService.list`（`management_crud_tests`）：管理员看本租户全部、其他人只看自己的，按 id 倒序；视图七个字段同 `ClientCredentialView`，时间戳原先是 SQLite 的 `YYYY-MM-DD HH:MM:SS`，现为 ISO-8601（`…T…Z`） |
| POST | `/api/admin/client-credentials` | Bearer | 创建凭据，201 `{credential,secret}` | 一致 | `fix/c-server-parity-crud`（`management_crud_tests`）：没有请求体或不是对象 400；apiKey 按 Java trim 后 3–120 个字符（UTF-16），省略时生成 `ck_` + UUID v4 的 32 位小写十六进制（原先 120 字符的哈希串）；secret 省略时生成 Java 字母表的 18 个字符（原先 `sk_` + 哈希串）；`maxOnlineInstances` 须在 1–10000（原先 ≤ 0 回落到默认值、不设上限），不是数字 400；apiKey 已存在 400 `apiKey already exists`（原先 409）；与并发创建争同一 apiKey 时不再覆盖对方（原先 `ON CONFLICT` 改写已有凭据的租户与 secret），回 Java 唯一约束的 400。凭据 id 是 SQLite 自增，Java 是随机的 53 位整数（不透明，客户端不解析） |
| PUT | `/api/admin/client-credentials/{id}` | Bearer | 更新凭据，回 `{credential,secret}` | 一致 | `fix/c-server-parity-crud`（`management_crud_tests`）：只改请求带来的字段；没换 secret 时应答 `"secret":null`（原先省略该字段）；找不到或不可见 400 `credential not found: <id>`（原先 404 不带 id）；apiKey 重复 400（原先 409）；`maxOnlineInstances` 越界 400（原先 ≤ 0 回落到默认值、不设上限） |
| DELETE | `/api/admin/client-credentials/{id}` | Bearer | 删除，204 | 一致 | 同上：找不到或不可见 400 `credential not found: <id>` |
| GET | `/api/admin/specus-mappings` | Bearer | 可见 TCP 映射，可按 `clientId` | 一致 | **本分支**修正：原先全库超过 64 条映射时 500（`management_lists_tests`）。`fix/c-server-parity-crud` 对照 `NatControlService.listMappings`（`management_crud_tests`）：`clientId` 为 0、负数或不可见时为空列表（原先 ≤ 0 当作不过滤），不是数字 400，空值与 Spring 一样当作未给；时间戳为 ISO-8601 |
| POST | `/api/admin/clients/{id}/specus-mappings` | Bearer | 创建映射，201，推送 NAT_CONTROL | 一致 | 不限条数（#191）；会让该客户端的 `NAT_CONTROL` 超过单条消息 1 MiB 上限的新增或启用以 400 拒绝，Java `requireNatControlFits` 同样拒绝（#197）。`fix/c-server-parity-peer-api` 对照 `NatControlService.createMapping`：原先是同一客户端同一端口的 upsert、公网端口只在同一客户端内唯一，现为纯插入，任何映射（任何客户端、任何租户）占用的公网端口 400 `公网端口 N 已被占用`；客户端找不到或不可见 400 `client not found: <id>`（原先 404）；必需请求体与 `enabled`/`detailCaptureEnabled` 按 Jackson 绑定，三个字段的校验与文案同更新；并发插入撞上唯一约束为 Java 的 400 `客户端名称已存在或数据不符合约束`（`peer_mesh_api_tests`、`admin_http_tests`） |
| PUT | `/api/admin/specus-mappings/{specusId}` | Bearer | 更新映射并推送 | 一致 | `fix/c-server-parity-crud` 对照 `NatControlService.updateMapping`（`management_crud_tests`；推送另见 `session_lifecycle_tests`、`runtime_config_e2e.sh`）：三个字段都必填，按 Java 的顺序与文案校验（端口 1–65535、`targetAddress` trim 后非空且不超过 255 个字符），原先省略的字段保留原值；省略 `enabled` 时启用（原先保留原值），`detailCaptureEnabled` 省略时不变；换到其他映射（任何客户端、任何租户）占用的公网端口 400 `公网端口 N 已被占用`（原先只在同一客户端内由唯一约束拦下，回 409）；找不到或不可见 400 `mapping not found: <id>`（原先 404） |
| DELETE | `/api/admin/specus-mappings/{specusId}` | Bearer | 删除并推送，204 | 一致 | 同上：找不到或不可见 400 `mapping not found: <id>`；同一事务删掉工作台引用（Java `workbenchReferences.forgetObject`） |
| POST | `/api/admin/clients/{id}/nat-control` | Bearer | 手动推送，回 `{pushed,specusMappings,httpRoutes}` | 一致 | 每客户端 64 条的上限已在 #191 去掉 |

## 3. HTTP 路由、临时分享、访问审计与连通性检查

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/admin/http-routes` | Bearer | 可见 HTTP 路由 | 一致 | `HttpRouteServiceTests` 覆盖；**本分支**去掉全库 64 条上限。`fix/c-server-parity-peer-api`：`clientId` 不是数字 400，时间为 ISO-8601（`peer_mesh_api_tests`） |
| POST | `/api/admin/clients/{id}/http-routes` | Bearer | 创建路由 | 有差异 | 不限条数（#191）；会让 `NAT_CONTROL` 超过 1 MiB 的新增或启用以 400 拒绝，Java 不检查（#197） |
| PUT | `/api/admin/http-routes/{routeId}` | Bearer | 更新路由 | 一致 | `HttpRouteServiceTests` 覆盖；中央向量 `http-route-lifecycle-v1.json`（ctest `http_route_lifecycle_tests`） |
| DELETE | `/api/admin/http-routes/{routeId}` | Bearer | 删除路由 | 一致 | 同上 |
| POST | `/api/admin/http-routes/{routeId}/shares` | Bearer | 创建临时分享 | 一致 | 中央向量 `temporary-http-share-v1.json`（ctest `http_share_tests`）；Java `HttpShareHttpTests`/`HttpShareVectorTests` 消费同一向量 |
| GET | `/api/admin/http-routes/{routeId}/shares` | Bearer | 分享列表 | 一致 | 同上 |
| GET | `/api/admin/http-routes/{routeId}/shares/{shareId}` | Bearer | 单个分享 | 一致 | 同上 |
| POST | `/api/admin/http-routes/{routeId}/shares/{shareId}/revoke` | Bearer | 撤销 | 一致 | 同上；`test_revoke_then_gone`、`test_remote_revoke_cuts_stream` |
| GET | `/api/admin/http-routes/{routeId}/access-audit` | Bearer | 路由访问审计，`limit`/`before`，`{entries,nextBefore}` | 一致 | 同上（`http_share_tests` 断言审计条目与翻页） |
| GET | `/api/admin/http-access-audit` | Bearer（admin） | 租户访问审计，可按 `routeId` | 一致 | 同上；非管理员 403 |
| POST | `/api/public/http-shares/exchange` | 公开 | fragment token 换分享 cookie | 一致 | 同上（`test_exchange`、`test_exchange_cookie_attributes`） |
| POST | `/api/admin/http-routes/{routeId}/connectivity-check` | Bearer | 端到端连通性检查 | 一致 | 中央向量 `service-connectivity-check-v1.json`（ctest `connectivity_check_tests`） |

## 4. 连接记录、概览与流量

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/admin/connections` | Bearer | `clientId/success/from/to/page/size`（1..500），`{items,total,page,size,totalPages}` | 一致 | **本分支**修正管理员视图：原先连接客户端表，已删除客户端的记录和未知名称的失败登录不显示，Java 按记录的租户过滤（`management_overview_tests`）。`fix/c-server-parity-edges`：普通用户原先还能看到按名称匹配到自己客户端的失败登录（`client_id` 为空），现与 Java `clientId IN visibleClientIds` 相同，只按 `clientId` 匹配（`management_lists_tests`） |
| GET | `/api/admin/connection-stats` | Bearer | 月度归档统计，`clientName`/`limit`（1..500） | 一致 | `ConnectionArchiveServiceTests` 覆盖（ctest `connection_archive_tests`） |
| GET | `/api/admin/overview` | Bearer | Java `OverviewService` 八个字段 | 一致 | **本分支**：原先只回 `{server,status,onlineClients:0,tcpMappings}`，管理端界面读的八个字段都缺；现按 Java 计算，并在运行时维护每租户的公网连接计数（`management_overview_tests`，真实进程） |
| POST | `/api/admin/database/initialize` | Bearer（admin） | 初始化演示数据，`{initialized,tenantId,orm,dialect,clients}` | 有差异 | `fix/c-server-parity-crud` 对照 `DatabaseInitializer.initialize(tenant)`（`management_crud_tests`、`admin_http_tests`）：允许演示数据时把 `Demo client`（属内置管理员）建在调用者的租户，名字已被其他租户占用时与 Java 的唯一约束一样回 400 `客户端名称已存在或数据不符合约束`；原先只在固定的 `default` 租户建、属固定的 `admin`。启动时的种子同样改为 `SPECUS_AUTH_TENANT_ID` 租户、`SPECUS_AUTH_USERNAME` 所有。非管理员 403 `需要 admin 权限`。剩余差异见第 8 节：`orm`/`dialect` 报 C 自己的实现（`sqlite3`/`sqlite`），不建 Java 的公开演示凭据 `demo-client` |
| GET | `/api/admin/traffic` | Bearer | 流量统计，`clientId`/`limit` | 一致 | **本分支**把 `limit` 改为 Java 的 1..500（原先最多 1000，超过 1000 回落到 100）。`fix/c-server-parity-crud` 对照 `TrafficResource` 与 `TrafficViewService.listTraffic`（`management_crud_tests`）：`clientId` 为 0、负数或调用者看不到的客户端（含已删除的）时为空列表（原先 ≤ 0 当作不过滤），`clientId`、`limit` 不是数字 400；管理员按记录的租户列出，已删除客户端的统计也在内（原先连接客户端表，删了就看不到），为此两张统计表补 `tenant_id` 列，旧行在加列时按客户端回填；视图七个字段同 `TrafficUsageView`，`updatedAt` 为 ISO-8601。`flush=true` 在 C 无事可做（第 8 节） |
| GET | `/api/admin/traffic/resources` | Bearer | 按资源的流量统计，`type`/`clientId`/`limit` | 一致 | 同上；`type` 按 Java trim 并转大写（原先区分大小写、不 trim） |
| GET | `/api/admin/traffic/http-exchanges` | Bearer | 明细摘要分页 | 一致 | **本分支**（第 5 节）；ctest `traffic_detail_api_tests`、`elasticsearch_traffic_tests` |
| GET | `/api/admin/traffic/http-exchanges/{id}` | Bearer | 明细含表头、预览与 body | 一致 | body 存储与 `data:` URL 显示已随 `fix/c-server-parity-rest` 对齐（test-map `HttpTrafficExchangeStoreTests` 覆盖），已存在的 Elasticsearch 索引补 binary 映射见第 5 节；`fix/c-server-parity-edges`：SQLite 下管理员原先读不到已删除客户端的明细，现按记录的租户查（`traffic_detail_api_tests`）。`fix/c-server-parity-peer-api`：`br` 编码的 body 与预览照 Java `HttpBodyDataCodec`/`TrafficInspectionService` 用 brotli 解码（同一套 `DecompressionLimits` 上限），前提是构建找到 libbrotlidec，CI 与发布构建已装 `libbrotli-dev`；没装的构建仍按解不开处理，见第 8 节（ctest `decompression_limits_tests`、`traffic_capture_tests`） |
| GET | `/api/admin/traffic/tcp-frames` | Bearer | 帧摘要分页，`clientId`/`listenPort`/`page`/`size\|limit` | 一致 | **本分支**；`traffic_detail_api_tests`。`fix/c-server-parity-edges`：`listenPort=0` 与 `clientId` ≤ 0 照 Java 过滤（空页），SQLite 下管理员看得到已删除客户端的帧 |
| GET | `/api/admin/traffic/tcp-frames/{id}` | Bearer | 帧详情含 `payloadBase64` | 一致 | `elasticsearch_traffic_tests`、`traffic_capture_tests` |
| GET | `/api/admin/traffic/tcp-streams` | Bearer | 按 `channelId` 的帧流 | 一致 | **本分支**（第 5 节） |
| GET | `/api/admin/traffic/inspection-status` | Bearer | `{enabled,pendingHttp,pendingTcp,droppedHttp,droppedTcp,lastFlushedAt}` | 一致 | **本分支**：Elasticsearch 下为写入队列的真实计数；SQLite 同步写入，计数恒为 0（第 8 节） |
| POST | `/api/admin/traffic/media-captures/{id}/playback-ticket` | Bearer | 回放票据 | 一致 | test-map 媒体 5 个类均为覆盖（ctest `media_capture_tests`） |
| GET | `/api/admin/traffic/media-captures` | Bearer | 媒体采集分页 | 一致 | 同上 |
| GET/HEAD | `/api/admin/traffic/media-captures/{id}/play` | Bearer | Range 回放 | 一致 | 同上 |
| GET | `/api/admin/traffic/media-captures/{id}/manifest` | Bearer | 清单 | 一致 | 同上 |
| GET/HEAD | `/api/admin/traffic/media-captures/{id}/asset` | Bearer | 分片资源 | 一致 | 同上 |
| GET/HEAD | `/api/public/media-playback/{ticket}/play` | 公开（票据） | 公开回放 | 一致 | `PublicHttpMediaPlaybackResourceTests` 覆盖 |
| GET/HEAD | `/api/public/media-playback/{ticket}/manifest` | 公开（票据） | 公开清单 | 一致 | 同上 |
| GET/HEAD | `/api/public/media-playback/{ticket}/asset` | 公开（票据） | 公开资源 | 一致 | 同上 |

## 5. Elasticsearch HTTP/TCP 明细存储、搜索与归档

对照 Java `SpringDataElasticsearchHttpTrafficExchangeStore`、`SpringDataElasticsearchTcpTrafficFrameStore`、`HttpTrafficSearchField`、`TrafficResource`、`TrafficViewService`、`TrafficInspectionService` 与 `ElasticsearchConnectionDetailsConfig`，C 为 `src/elasticsearch_traffic.c`。测试：ctest `elasticsearch_traffic_tests`（存取往返与按大小裁剪）与 `traffic_detail_api_tests`（经进程内管理监听器的真实 HTTP、真实 `specus-server-c` 进程采集），两者都跑在 `scripts/elasticsearch_traffic_test.sh` 的 fake Elasticsearch 上；fake 按真实集群的语义求值 bool/term/terms/wildcard/multi_match/match_phrase 与 `_bulk`。

| 语义 | Java | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- |
| 启用条件 | `SPECUS_ELASTICSEARCH_URIS` 有文本 | 一致 | 空白视为未配置 |
| 节点列表 | 逗号分隔多节点；只取 scheme/host/port，无端口时 http 9200、https 443 | 有差异 | **本分支**：原先只用第一个节点、保留路径、无端口时连 80。现按 Java 解析，最多 8 个节点，连不上时按顺序换下一个；Java 客户端在节点间轮询，C 不轮询（第 8 节） |
| 认证 | API key 或用户名口令 | 一致 | API key 优先 |
| 索引名与映射 | `specus-http-traffic`/`specus-tcp-traffic`，字段类型同 `@Document` | 一致 | 同名环境变量；首次使用时建索引 |
| 已存在 HTTP 索引补 body 的 binary 映射 | `putBinaryBodyMapping` | 一致 | `es_ensure_index` 在索引已存在时 PUT `_mapping` 补上 `requestBodyData`/`responseBodyData` 的 binary 映射，被拒时记日志、照用原索引（#204）；`elasticsearch_traffic_tests` 用 fake 预置的两个旧索引验证 |
| 文档 id | `(毫秒 << 20) \| 序号` | 一致 | `es_new_id` |
| 写入路径 | 采集线程入队，后台每 2 s 以批（1000）写入，每类最多 20000 条待写，超出丢弃计数 | 一致 | **本分支**：原先每条明细、每个 TCP 帧在转发线程上同步 PUT（集群慢时每帧最多等 15 s）。现为同样的队列（`_bulk`），环境变量同名；C 另加 256 MiB 总量上限（第 8 节）。`traffic_detail_api_tests`：入队计数、未 flush 前搜不到 |
| `flush=true` | 立即写一批 | 一致 | **本分支**；http-exchanges、tcp-frames、tcp-streams 都接受 |
| 关停 | `flushBeforeShutdown` 写一批 | 一致 | **本分支**：SIGTERM 后写出队列中全部文档（Java 只写一批，第 8 节）；`traffic_detail_api_tests` 真实进程断言关停前入队的帧已在集群 |
| 采集顺序 | 两个方向都在转发前采集，同一事件循环 | 一致 | **本分支**：原先公网到客户端的帧在转发与流量统计写库之后才采集，负载下帧序号会颠倒（实测 P0、C0、P1） |
| 摘要排除大字段 | `SUMMARY_SOURCE_EXCLUDES` | 一致 | 表头、预览与 `requestBodyData`/`responseBodyData` 都已排除，摘要不读 |
| 搜索字段 | `HttpTrafficSearchField.fromCode`：代码或常量名，忽略大小写，未知回落 summary | 一致 | **本分支**：原先自有别名（`headers`、`body`、`query`），`all` 不含表头与正文 |
| 关键词 | 按空白切 token，每个 token 都须命中；text 字段 `multi_match`，keyword 字段大小写不敏感 `*token*` 通配（转义 `\ * ?`），数字匹配 id/clientId/statusCode/resourceId，method 为大写 term，无可匹配字段时不匹配 | 一致 | **本分支**：原先一个 `simple_query_string`，其运算符会改变语义，keyword 字段只能整值大小写敏感匹配，数字不匹配状态码 |
| `responseBodyType` | 规范化（trim、小写、未知不过滤），匹配存储类型、空 body 或对应 Content-Type；空白时取 `responseDataType` | 一致 | **本分支**（SQLite 同样修正） |
| `route` | trim 后精确过滤 | 一致 | **本分支** |
| 可见范围 | 管理员只按租户（含已删除客户端），其他人按拥有的客户端，`clientId` 不可见时空页 | 一致 | **本分支**：原先管理员也只看 SQLite 现存客户端 |
| 分页 | `page>=0`，`size` 1..500，按 id 倒序，`total` 取 hits.total | 一致 | `from` 改为 64 位计算 |
| 明细 | 租户 + id（+可见客户端），含表头与预览 | 一致 | body 见上 |
| TCP 列表 | `clientId`、`listenPort`、分页、id 倒序 | 一致 | `fix/c-server-parity-edges`：`listenPort` 给出即过滤，0 也一样（原先 0 视为不过滤）；`elasticsearch_traffic_tests` |
| TCP 流 | `exactText(channelId)`（term、`.keyword`、match_phrase），id 正序，`page`/`size`（默认 `limit` 500，1..1000），回 `channelId,items,total,page,size,limit,totalPages(>=1),truncated`；空白 channelId 为空页 | 一致 | **本分支**：原先忽略分页、`total` 为条数、缺 `page/size/totalPages`、按各方向的帧序号排序、SQLite 下 `limit` 超过 500 回 500 |
| 保留期（按大小裁剪） | 每分钟最多一次；超过上限按 id 升序每批删 500 条、最多 20 批；`total_data_set_size_in_bytes` 优先 | 一致 | 语义相同（C 用 `_bulk` 删除）。`fix/c-server-parity-edges`：`total_data_set_size_in_bytes` 只要存在就用，0 也用（原先 0 时改读 `size_in_bytes`），缺字段才读 `size_in_bytes`；fake 对 `*-zero-dataset`、`*-no-dataset` 两种索引给出这两种回答，`elasticsearch_traffic_tests` 验证 |
| 归档 | 流量明细没有归档，只有按大小裁剪；连接记录的月度归档见第 4 节 | 一致 | — |
| SQLite 后端（对照 JPA store） | `JpaHttpTrafficExchangeStore`：字段同 `HttpTrafficSearchField`，字符串列 `lower(col) LIKE`、预览列 `col LIKE`，`% _ \` 转义；管理员按租户 | 一致 | `fix/c-server-parity-edges`：原先自有字段别名、`% _` 当通配符、WHERE 缓冲 4 KiB（十来个 token 后 SQL 被截断），管理员视图连接客户端表、看不到已删除客户端的流量。现按 JPA 的谓词逐条生成（`traffic_detail_api_tests` 的 SQLite 段）。大小写折叠只覆盖 ASCII，与 SQLite 自身的 `LOWER`/`LIKE` 相同 |

## 6. client-message 与 WebSocket 事件

对照 `protocol/spec/client-messages.md`、`ClientMessagesWebSocketHandler`、`MessageRequestHandler`、`ConnectionEventsWebSocketHandler`、`WebSocketTicketHandshakeInterceptor`。测试：ctest `client_messages_tests`（真实 `specus-server-c` 进程 + 按协议登录的客户端，及进程内监听器）、`admin_http_tests` 的 `test_client_messages_websocket` 与 `test_connection_events_websocket`、`public_transfer_tests`。

| 方法 | 路径 | 鉴权 | 要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/admin/ws-tickets` | Bearer | `{"endpoint":"connections"\|"client-messages"}` → 45 s 单次 ticket，`no-store` | 一致 | `WebSocketTicketServiceTests` 覆盖 |
| WS | `/ws/connections` | ticket | 推送 `{tenantId,type:created\|updated,connection}`，管理员收本租户全部，其他人只收自己客户端的 | 有差异 | 差异仅为 Redis 集群扇出（第 8 节平台差异）。**本分支**：二进制帧 1003、未掩码帧 1002（`client_messages_tests`）。`fix/c-server-parity-edges`：文本消息按 Tomcat 默认缓冲 8192 个字符（UTF-16 code unit）计，超过 1009、非 UTF-8 1007（原先上限 1 MiB、不校验 UTF-8），`client_messages_tests` |
| WS | `/ws/client-messages` | ticket | 见下表 | 一致 | `fix/c-server-parity-edges`：原先 `messageId` 为数字时回显空串；现与 Jackson 相同，四个成员为数字或布尔值时读作其字面文本 |
| WS | `/ws/public-transfer/discovery` | 公共 ticket | 互传发现 | 一致 | `PublicTransferDiscoveryWebSocketHandlerTests` 覆盖 |
| WS | `/http/**`（Upgrade） | 路由认证 | Direct WebSocket（SWS2） | 一致 | `WebSocketSpecusHandlerTests`、`WebSocketSpecusHandshakeInterceptorAuthenticationTests` 覆盖 |
| WS | `/http-share/**`（Upgrade） | 分享 cookie | 分享 WebSocket | 一致 | 中央向量 `temporary-http-share-v1.json` |

`/ws/client-messages` 逐条：

| 契约 | C 状态 | C 证据 / 说明 |
| --- | --- | --- |
| Upgrade 只接受恰好一个 `ticket` 参数，失败 403 + `X-Auth-Reason`（`single-use ticket required` / `invalid or consumed ticket`） | 一致 | `admin_http_tests`；本分支把协议文档里的原因文本改成 Java 与 C 实际发送的值 |
| hello `{type,channel,username,tenantId}` | 一致 | `client_messages_tests` 逐字比较 |
| 同一管理员多个连接都收到客户端消息 | 一致 | `client_messages_tests` 两个会话 |
| 管理端发送：`type` 须为 `message`，目标与正文 trim 后非空；账号存在、启用、同租户、可访问统一 `target-not-found`；任一 `NETTY_ONLINE` 会话声明接收能力；有活动 control | 一致 | `admin_http_tests`、`client_messages_tests` |
| 写入 `MessageResponsePacket(CLIENT_TO_CLIENT, admin:<user> → 规范名, trim 正文)`，写成功后回 `written` | 一致 | `client_messages_tests` 读真实 control 帧 |
| 写入异步，不阻塞后续命令 | 一致 | `test_client_messages_websocket` |
| 检查通过后写入失败回 `failed`/`target-write-failed` | 一致 | **本分支**：原先目标连接在检查后消失时回 `error`/`target-offline` |
| 无法映射的命令（未知成员、对象/数组值、非对象）回 `invalid-json`，不带 messageId | 一致 | **本分支**：原先忽略未知成员、把非字符串值当缺失 |
| 数字或布尔成员按 Jackson 转成字面文本（`42`、`-1.50`、`true`）：数字 `messageId` 原样回显，数字正文照常发送；`null` 视为缺失 | 一致 | `fix/c-server-parity-edges`：原先读作缺失，回显空串、数字正文当作空正文；`client_messages_tests` |
| 客户端到管理员：`admin:` 前缀不区分大小写，用户名 trim，同租户；来源账号存在且启用；无订阅不持久化 | 一致 | **本分支**：原先不查来源账号，停用（未踢线）的账号仍能发给管理员；`client_messages_tests` |
| 客户端到客户端备用通道：双方启用、Peer ACL、目标在线 | 一致 | 代码对照 `forward_runtime_client_message` 与 `MessageRequestHandler.clientToClient`；无单独测试 |
| 65,536 UTF-16 code unit 上限（1009），二进制 1003 | 一致 | `test_client_messages_websocket` |
| 管理端附件 REST（第 7 节表中三条） | 一致 | `TransferAttachmentServiceTests` 覆盖 |

## 7. 公共互传、客户端发布、工作台、产品指标、流程图、Peer Mesh

| 方法 | 路径 | 鉴权 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- |
| GET | `/api/public/transfer/clients/name-availability` | 公开 | 一致 | `PublicTransferDiscoveryWebSocketHandlerTests` 覆盖 |
| POST | `/api/public/transfer/ws-tickets` | 公开 | 一致 | `WebSocketTicketServiceTests` 覆盖 |
| POST | `/api/public/transfer/rooms/access-tokens/list`、`/access-tokens`、`/access-tokens/{accessId}/revoke`、`/pairing-codes`、`/pairing-codes/redeem`、`/diagram/versions/list`、`/diagram/versions`、`/diagram/versions/{versionId}`、`/diagram/versions/{versionId}/delete`（9 个） | 公开（房间凭据） | 一致 | `PublicTransferRoomResourceTests`、`PublicTransferRoomServiceTests`、`PublicTransferRateLimiterTests` 覆盖 |
| GET | `/api/public/transfer/attachments/capabilities` | Bearer（任意） | 一致 | `TransferCapabilitiesVectorTests` 覆盖（中央向量） |
| POST | `/api/public/transfer/attachments/presign-upload`、`/{attachmentId}/complete`、`/{attachmentId}/presign-download` | Bearer（任意） | 一致 | `TransferAttachmentServiceTests` 覆盖 |
| POST | `/api/public/transfer/oss-callback` | 公开（OSS 签名） | 一致 | `AliyunOssObjectStorageServiceTests` 覆盖 |
| GET | `/api/public/transfer/downloads/{token}` | 公开 | 一致 | `TransferAttachmentServiceTests` 覆盖 |
| POST | `/api/admin/client-messages/attachments/presign-upload`、`/{attachmentId}/complete`、`/{attachmentId}/presign-download` | Bearer | 一致 | `TransferAttachmentServiceTests` 覆盖（管理端隔离） |
| GET | `/api/admin/client-downloads` | Bearer（admin） | 一致 | `ClientDownloadLinkServiceTests` 覆盖；**本分支**修正 128 行静默截断（`management_lists_tests`） |
| POST | `/api/admin/client-downloads` | Bearer（admin） | 一致 | 同上 |
| POST | `/api/admin/client-packages`（multipart） | Bearer（admin） | 一致 | `ClientPackageLifecycleTests`、`ClientPackageStorageTests` 覆盖 |
| PUT | `/api/admin/client-downloads/{id}` | Bearer（admin） | 一致 | `ClientDownloadLinkServiceTests` 覆盖 |
| POST | `/api/admin/client-downloads/{id}/latest` | Bearer（admin） | 一致 | 同上 |
| DELETE | `/api/admin/client-downloads/{id}` | Bearer（admin） | 一致 | 同上 |
| GET | `/api/public/client-downloads` | 公开（来源限流） | 一致 | 同上 + `GitHubReleaseCatalogTests`、`ClientPackageRateLimiterTests`；**本分支**：目录超过 128 行后最新发布不再出现，`management_lists_tests` 以第 140 个版本断言 |
| GET | `/api/public/client-version-check` | 公开（来源限流） | 一致 | 同上（第 140 个版本） |
| GET | `/api/public/client-packages/{id}/download` | 公开（来源限流） | 一致 | `ClientDownloadLinkResourceTests` 覆盖 |
| GET/PUT/DELETE/POST/DELETE | `/api/admin/workbench`、`/favorites/{kind}/{id}`（PUT、DELETE）、`/favorites`（DELETE）、`/recents/{kind}/{id}`（POST、DELETE）、`/recents`（DELETE）（7 个） | Bearer | 一致 | 中央向量 `service-workbench-v1.json`（ctest `workbench_tests`），Java `WorkbenchVectorTests` 消费同一向量 |
| GET/PUT/DELETE/POST/GET | `/api/admin/product-metrics/settings`（GET、PUT）、`/data`、`/transfer-outcomes`、`/summary`（5 个） | Bearer | 一致 | 中央向量 `product-metrics-v1.json`（ctest `product_metrics_tests`） |
| GET/GET/POST/PUT/DELETE | `/api/admin/diagrams`、`/api/admin/diagrams/{id}`（5 个） | Bearer | 一致 | `UserDiagramDocumentServiceTests` 覆盖 |
| GET | `/api/admin/peer-mesh/status` | Bearer | 一致 | `fix/c-server-parity-peer-api`逐项对照 `PeerMeshResource.status`：`{"enabled":<SPECUS_PEER_MESH_ENABLED>}`（`admin_http_tests` "peer mesh status response mismatch"） |
| GET | `/api/admin/peer-mesh/devices` | Bearer | 一致 | `fix/c-server-parity-peer-api`：Java `listDevices` 只列已有的设备行（客户端带着 Peer Mesh 登录或说过 Peer Mesh 才建），管理员看本租户、其他人看设备属于自己的，按客户端名排序；C 原先给每个可见客户端现场建设备行。视图为 `PeerMeshDeviceView` 的 21 个字段：原先多出 5 个消息能力字段，未上报的 `natType`、`virtualDeviceMode`、`virtualDeviceStatus` 原先填 `UNKNOWN`/`AUTO`/`DOWN`，现为 `null`；三个时间为 ISO-8601（ctest `peer_mesh_api_tests`） |
| PUT | `/api/admin/peer-mesh/devices/{clientId}` | Bearer | 一致 | `fix/c-server-parity-peer-api`：`DeviceMutation` 的必需请求体与 `Boolean enabled` 按 Jackson 绑定（缺请求体、不是对象、`"maybe"` 之类为 Spring 的 400，`"TRUE"` 照 Jackson 读作 true），路径变量不是数字 400；找不到设备或不是自己的 400 `peer device not found: <id>`（原先 404，且会给没登录过的客户端建设备）；省略 `enabled` 只更新时间。`PeerSignalService.refreshDevice`：关闭设备时关掉它的打开会话，并给两端各发一条 `close`（`admin-force-close`），原先只推配置（`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/acls` | Bearer | 一致 | `PeerMeshAclView` 九个字段；`fix/c-server-parity-peer-api`时间改为 ISO-8601（`peer_mesh_api_tests`） |
| POST | `/api/admin/peer-mesh/acls` | Bearer | 一致 | `fix/c-server-parity-peer-api`对照 `PeerMeshService.createAcl`：按 Java 的顺序与文案逐项检查（`sourceClientId is required`、`client not found: <id>`、`targetClientId is required`、`source and target cannot be the same client`、`普通用户不能创建跨用户 peer ACL`、`invalid direction: <原文>`），原先找不到客户端回 404 且不带 id、跨用户为英文文案；成功回 200（原先 201）；类型不符为 Spring 的 400。之后照 `refreshAuthorization` 关闭不再允许的打开会话并通知两端（`peer_mesh_api_tests`、`admin_http_tests`） |
| DELETE | `/api/admin/peer-mesh/acls/{id}` | Bearer | 一致 | `fix/c-server-parity-peer-api`：找不到或不可见 400 `peer ACL not found: <id>`（原先 404，id ≤ 0 落到通用 404）；成功回 200、无正文（Java 的 void，原先 204）；删除后关闭不再允许的会话并通知两端（`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/stats` | Bearer | 一致 | `fix/c-server-parity-rest` 已逐字节对照 `pathStats`（test-map `PeerMeshServiceTests` 行） |
| GET | `/api/admin/peer-mesh/sessions` | Bearer | 一致 | `fix/c-server-parity-edges` 补上分页形式；`fix/c-server-parity-peer-api`：`limit`/`page`/`size`/`openOnly` 按 Spring 转换，转不了 400，空值视为未给（原先 `page=` 也算分页）、`openOnly` 认 Spring 的 yes/on/1；视图补上 Java 的 `lastKeepaliveAt`（`peer_mesh_session` 加列，path-report、带字节的 traffic-report 与中继激活会话时更新，同 Java），时间为 ISO-8601（`peer_mesh_api_tests`） |
| DELETE | `/api/admin/peer-mesh/sessions/{id}` | Bearer | 一致 | `fix/c-server-parity-peer-api`：找不到或不可见 400 `peer session not found: <id>`（原先 404）；`forceClose` 给两端各发 `close`，原先只改库，客户端不知道会话已关（`peer_mesh_api_tests`） |
| DELETE | `/api/admin/peer-mesh/sessions` | Bearer | 一致 | `fix/c-server-parity-peer-api`：`forceCloseOpenSessions` 给每个被关会话的两端发 `close`（`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/service-sharing` | Bearer | 一致 | `PeerMeshServiceSharingView`；`fix/c-server-parity-peer-api` `updatedAt` 为 ISO-8601 |
| PUT | `/api/admin/peer-mesh/service-sharing` | Bearer | 一致 | `fix/c-server-parity-peer-api`对照 `updateServiceSharing`：请求体按 `Map` 绑定（缺失或不是对象 400），两个开关只认 JSON 布尔值（原先 `"true"`、`"1"` 字符串也算）；绑定在 ADMIN 检查之前；审计原因补上 Java 的 `,mdns` 后缀（`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/services` | Bearer | 一致 | 管理员看本租户、其他人看自己客户端的，后者不带 `targetHost`/`targetPort`；`fix/c-server-parity-peer-api`时间为 ISO-8601 |
| POST | `/api/admin/peer-mesh/services` | Bearer | 有差异 | `fix/c-server-parity-peer-api`对照 `createService` 与 `applyDefinition`：`ServiceMutation` 按 Jackson 绑定（类型不符 400）；`clientId is required`、`client not found: <id>`（原先 404）、`invalid serviceId`、`serviceId already exists on this client`，然后按 Java 的顺序给出 `PeerServiceDiscovery` 的各条文案（原先一律 `invalid peer service definition`）；省略 serviceId 时生成 UUID（原先 `svc-<id>-<毫秒>`）；新实体的 transport 是 Java 默认的 `tcp`，所以 udp 应用不写 transport 被拒（同 Java）；成功回 200（原先 201）。剩余差异：名称与描述在 C 的存储字段按字节（80/200 字节）限长，较长的非 ASCII 名称 Java 接受、C 回同一句 `name exceeds 80 characters`（test-map `PeerServiceDiscoveryServiceTests` 行） |
| PUT | `/api/admin/peer-mesh/services/{id}` | Bearer | 有差异 | `fix/c-server-parity-peer-api`：找不到 400 `service not found: <id>`（原先 404），校验同上；路径变量不是数字 400（`PUT /services/import` 亦然，同 Spring）。剩余差异同上一行 |
| DELETE | `/api/admin/peer-mesh/services/{id}` | Bearer | 一致 | `fix/c-server-parity-peer-api`：找不到 400 `service not found: <id>`（原先 404）；成功回 200、无正文（原先 204）；同一事务删掉工作台引用（`peer_mesh_api_tests`、`workbench_tests`） |
| POST | `/api/admin/peer-mesh/services/import` | Bearer | 一致 | `fix/c-server-parity-crud` 修正去重范围；`fix/c-server-parity-peer-api`对照 `importServices`/`importCandidates`：请求体按 `Map` 绑定，`clientId` 只认 JSON 数字（字符串 `"5"` 为 `clientId is required`），找不到 400 `client not found: <id>`（原先 404），mDNS 未开启为 `mDNS 候选导入未开启`；候选目标先过 `requireTargetHost`（公网目标跳过，原先照样导入），服务 id 为 UUID（原先 `import-tcp-<id>` 等），HTTP 路由的 path 不含 query（`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/service-audit` | Bearer | 有差异 | 字段同 `AuditEvent`，`fix/c-server-parity-peer-api` `at` 为 ISO-8601。差异见第 8 节：C 的审计存库，按租户列最近 50 条且重启后仍在；Java 在进程内存只保留全局最近 80 条 |
| GET | `/api/admin/peer-mesh/egress/switch` | Bearer | 一致 | `fix/c-server-parity-peer-api`：租户没设过开关时 `updatedAt`/`updatedBy` 为 `null`（原先空串），时间为 ISO-8601（`peer_mesh_api_tests`） |
| PUT | `/api/admin/peer-mesh/egress/switch` | Bearer | 一致 | `fix/c-server-parity-peer-api`：`SwitchMutation` 先绑定（坏请求体为 Spring 的 400 `{"error":"Bad Request"}`，原先 `invalid request body`，且原先先查 ADMIN），再 403、`enabled is required`、部署未启用 Peer Mesh 的 400（`peer_mesh_api_tests`、`admin_http_tests`） |
| GET | `/api/admin/peer-mesh/egress/policies` | Bearer | 一致 | `PeerMeshEgressPolicyView`；`fix/c-server-parity-peer-api`时间为 ISO-8601 |
| POST | `/api/admin/peer-mesh/egress/policies` | Bearer | 一致 | `fix/c-server-parity-peer-api`对照 `upsertPolicy`：`PolicyMutation` 先绑定（字段类型不符、规则不是数组或元素不是对象为 Spring 的 400），再 403；`egressClientId` 为 0 或负数是 404 `client not found: <id>`（原先当作缺失）；`scope` 先 trim，错误为 `invalid scope: <原文>`；`allowedConsumerClientIds` 去重后才数 32 个、文案 `at most 32 allowedClientIds`；规则错误给出 Java 的逐条文案（`destinationRules[0].cidr is not an IPv4 or IPv6 address or CIDR: …`、`…portRanges entries must be [low, high] integers …: [443, 80]`、`domainRules[0].match must be …` 等，原先两句概括）。Java 用 `List.toString` 显示端口对，C 对数字、字符串、布尔与 null 写法相同，对象与嵌套数组按原 JSON 写出（`admin_http_tests`、`peer_mesh_api_tests`） |
| GET | `/api/admin/peer-mesh/egress/activity` | Bearer | 一致 | `PeerMeshEgressActivityView`，`online` 取自实时控制连接，`reportedAt` 本来就是 ISO-8601（`admin_http_tests` 端点矩阵） |
| DELETE | `/api/admin/peer-mesh/egress/policies/{id}` | Bearer | 一致 | `fix/c-server-parity-peer-api`：成功回 200、无正文（原先 `{}`）；找不到 404 `egress policy not found: <id>`，路径变量不是数字 400 |
| GET | `/api/public/peer-mesh/stun-config` | 公开 | 有差异 | test-map `PublicPeerMeshResourceTests` 覆盖；`fix/c-server-parity-peer-api`：`X-Forwarded-Host` 取逗号前第一个并 trim（同 Java `forwardedHost`）。差异见第 8 节：Peer Mesh 关闭且没有 standalone STUN 时，Java 仍把备用地址列进 `stunServers`，C 不发布没有服务在听的端点 |
| GET | `/api/public/transfer/ice-config` | 公开 | 有差异 | `fix/c-server-parity-peer-api`逐项对照 `iceConfig`：STUN 列表同上一行（差异亦同），Peer Mesh 开启时加一条 `turn:` 及 `public-transfer` 临时凭证，`turnAuthRequired` 默认 true，`stunTurnPort` 为内置端口 |
| GET | `/api/public/peer-mesh/nat-probe-config` | 公开 | 一致 | test-map `PublicPeerMeshResourceTests` 覆盖（BASIC_STUN 与 RFC 5780 四个端点） |
| 全部 | `/http/{clientName}/{route}/**` | 路由认证 | 一致 | test-map 第 3 节 `HttpSpecusController*`、`HttpSpecusBodyLimitFilterTests` 等覆盖 |
| 全部 | `/http-share/**` | 分享 cookie | 一致 | 中央向量 `temporary-http-share-v1.json` |

## 8. 平台差异（不实现）

| 差异 | 原因 |
| --- | --- |
| `/ws/connections` 与公共互传的管理事件不经 Redis 跨实例扇出 | C 管理面按单实例部署；跨实例事件归 Issue #35 的「HA/跨实例事件语义」一项，不在本文三项内 |
| SQLite 明细同步写入，没有待写队列；`inspection-status` 在 SQLite 下 pending/dropped 恒为 0 | 本地写库不阻塞网络；Java 的队列为保护转发线程，C 只对 Elasticsearch（网络写入）使用 |
| Elasticsearch 待写队列另有 256 MiB 总量上限 | C 服务常跑在小内存设备上；Java 只按条数（每类 20000）限制 |
| 关停时写出全部待写文档，Java 只写一批 | 只会少丢数据 |
| Elasticsearch 节点按顺序故障转移，不轮询 | libcurl 单连接；轮询只影响负载分布，不影响结果 |
| 没有 libbrotlidec 的构建不解码 `br`（brotli）：HTTP 明细的预览与详情按解不开处理（显示原字节），媒体清单按存储的原字节处理 | `fix/c-server-parity-peer-api` 已按方案接入：`CMakeLists.txt` 用 `pkg_check_modules(BROTLIDEC libbrotlidec)`、`Makefile` 用 `pkg-config` 可选检测，找到时定义 `ST_HAVE_BROTLI` 并链接；`decompression_limits.c` 以 `BrotliDecoderDecompressStream` 按 `decompression_limits` 的同一上限流式解码（预览只读前缀，同 Java `readLimited`），`traffic_capture.c`（预览与详情）与 `media_capture.c`（清单）在 gzip/deflate 旁加 `br`。CI（`protocol-v2.yml` 的 C server 任务）与发布（`release.yml`）的 apt 依赖已加 `libbrotli-dev`，这些构建与 Java 一致；只有自行构建且没装 `libbrotli-dev` 的环境（如本机 WSL）走「未检测到」分支，保持原状。libbrotlienc 也在时，`decompression_limits_tests` 另测压缩炸弹与往返 |
| `/api/admin/peer-mesh/service-audit` 的审计存在 SQLite，按租户列最近 50 条，重启后仍在 | Java 把审计放在进程内存的一个队列里，全局只留最近 80 条（各租户共用），重启即清空。C 写进 `peer_mesh_service_audit` 表：同样的字段与顺序，多租户时不会被别的租户的事件挤掉，也不随重启丢失；改成内存队列只会丢数据 |
| Peer Mesh 关闭且没有 standalone STUN 时，`stun-config`/`ice-config` 不把 `STUN_ALTERNATE_PUBLIC_ADDRESS` 列进 STUN 服务器 | Java 的 `standaloneAlternateStunServer` 不看 Peer Mesh 开关，这时内置 STUN/TURN 没在监听，列出的是一个没有服务的端点；C 只在发布自托管 STUN 时列出备用地址（`fix/c-server-parity-peer` 起的取舍，test-map `PublicPeerMeshResourceTests` 行） |
| `database/initialize` 的 `orm`/`dialect` 为 `sqlite3`/`sqlite` | 报的是实际实现：C 直接用 sqlite3 API，没有 JPA 与 Hibernate 方言 |
| 不建 Java 的演示凭据 `demo-client`（secret `test1234`） | 公开的固定凭据，C 从不写入（test-map `LegacyDemoCredentialSanitizerIntegrationTests` 行）；演示客户端照常建 |
| 流量统计同步写库，`/api/admin/traffic*` 的 `flush=true` 无事可做 | Java 在内存累计、定时写库，`flush` 先写出；C 每次转发即写 SQLite |

## 9. 待办（按影响排序）

1. ~~**每客户端 64 条 TCP 映射 / 64 条 HTTP 路由**~~（已完成，#191）：登录配置、`NAT_CONTROL` 推送、客户端详情与运行时会话里的映射和路由都改为动态分配；唯一的边界是单条 `NAT_CONTROL` 1 MiB，超出的新增或启用在创建时拒绝，其余三端的同一检查见 #197。
2. ~~**Peer Mesh 管理列表的固定上限**~~（已完成，`fix/c-server-parity-edges`）：ACL（256 行）、服务（256 行，超过后连保存都失败，因为保存后从截断的列表里读回）、出口策略（管理列表 128 行、目录推送 64 行）、出口活动（128 行）、一次关闭全部打开会话（200 个，应答又受 32 KiB 缓冲限制），以及登录配置、roster、服务目录与出口策略视图读取的全库客户端列表（256、512、1024 个，跨租户合计），都改为按需扩容、不限行数；会话列表补上 Java 的 `page/size/openOnly` 分页形式（管理端界面用的就是它，C 原先只回数组），`limit` 按 Java 夹到 1..200，列表前先关闭本租户的过期会话（Java `expireIfStale`）。ctest `management_lists_tests`（300 条 ACL 与服务、140 条策略与活动、260 个会话、另一租户 1100 个客户端）、`peer_mesh_tests`（库里多 1100 个客户端时的登录配置与推送）。服务目录的内存表（4096 个在线发布方，每个 32 个服务）与 Java 的同一上限一致，未改。
3. ~~**SQLite 流量明细搜索对照 JPA**~~（已完成，`fix/c-server-parity-edges`）：按 `JpaHttpTrafficExchangeStore.httpExchangePredicate` 逐条生成 SQL：字段表即 `HttpTrafficSearchField`（代码或常量名、忽略大小写、未知回落 summary），字符串列 `lower(col) LIKE`、预览列 `col LIKE`，`\ % _` 按字面转义，数字按字段匹配 id/clientId/statusCode/resourceId，`method` 整值比较，每个 token 都须命中且个数不限；HTTP、TCP 的列表与明细都按记录的租户过滤，管理员看得到已删除客户端的流量。ctest `traffic_detail_api_tests` 的 SQLite 段（与 ES 段同一组记录，逐个查询对照 Java 的结果）。
4. ~~**`fix/c-server-parity-rest` 合入后复核**~~（已完成）：HTTP body 存储与详情显示、客户端登录 nonce 存库，以及 test-map 中 `TrafficInspectionServiceTests`、`HttpTrafficExchangeStoreTests` 两行都已对应；已存在的 Elasticsearch HTTP 索引原先不补 binary body 映射，`fix/c-es-existing-index-body-mapping` 已按 Java `putBinaryBodyMapping` 补上（被拒时记日志、照用原索引），`elasticsearch_traffic_tests` 用 fake 预置的两个旧索引验证。
5. ~~**未逐项对照的 14 个管理端点**~~（已完成，`fix/c-server-parity-crud`）：注册两条、`/api/admin/me`、凭据 CRUD 四条、映射列表与改删三条、`database/initialize`、客户端名称可用性、流量统计两条，逐项对照了 Java 的 controller、service、DTO、校验与 `GlobalExceptionHandler` 的映射，差异见第 1、2、4 节各行。12 个改为一致；`/auth/register` 剩 C 登录名 80 字节的存储上限与少数邮箱写法，`database/initialize` 剩第 8 节的两项。ctest `management_crud_tests`（新增，经进程内管理监听器的真实 HTTP 与真实 token），`admin_http_tests` 的租户范围与初始化断言随之改为 Java 的 400 与调用者租户。对照中发现但不在本项内、未改的：映射新增的 upsert 与公网端口唯一范围（第 2 节该行）；客户端、路由、ACL 等其余视图的时间戳仍是 SQLite 的 `YYYY-MM-DD HH:MM:SS`（本项只改了凭据、映射与流量统计三类视图）。这两项已由第 8 项修正。
6. ~~边缘差异~~（已完成，`fix/c-server-parity-edges`）：连接记录普通用户只看 `clientId` 属于自己客户端的记录（`management_lists_tests`）；`listenPort` 给出即过滤、`clientId` ≤ 0 为空页，ES 与 SQLite 相同（`elasticsearch_traffic_tests`、`traffic_detail_api_tests`）；裁剪时 `total_data_set_size_in_bytes` 只要存在就用（`elasticsearch_traffic_tests`）；`/ws/connections` 与 `/ws/client-messages` 共用一个读帧循环，文本按 Tomcat 默认的 8192 个字符限长（1009）并校验 UTF-8（1007）；命令成员为数字或布尔值时按 Jackson 读作字面文本，数字 `messageId` 原样回显（`client_messages_tests`）。都不是平台差异。
7. ~~**Peer 服务导入的目标去重范围**~~（已完成，`fix/c-server-parity-crud`）：Java `importCandidates` 与 `importMdns` 只拿本客户端已有服务的 `host:port` 去重，C 原先拿整个租户的服务，别的客户端已发布同一目标时 C 会跳过而 Java 会导入；现在两条导入路径都只看本客户端的服务。ctest `management_crud_tests`：另一客户端已发布同一目标时照常导入，第二次导入因本客户端已有而跳过。
8. ~~**最后 27 个 Peer Mesh / Egress 端点与 `fix/c-server-parity-crud` 的遗留**~~（已完成，`fix/c-server-parity-peer-api`）：逐个对照了 `PeerMeshResource`、`PeerEgressResource`、`PublicPeerMeshResource` 与其服务（`PeerMeshService`、`PeerSignalService`、`PeerServiceDiscoveryService`、`PeerServiceDiscovery`、`PeerEgressService`）、DTO、`GlobalExceptionHandler` 与 Spring 的绑定，第 7 节逐行写出；22 个一致，5 个有差异（服务名称的字节上限、审计存库、两个公共 STUN 配置不列无服务的备用地址，后两项见第 8 节）。遗留三项：映射新增改为 Java 的纯插入与全局公网端口、客户端找不到 400；其余视图的时间改为 ISO-8601；其余端点带类型的查询参数与上述请求体按 Spring 转换（读法第 6 条）。`br` 按第 8 节的方案接入。ctest `peer_mesh_api_tests`（新增，经进程内管理监听器的真实 HTTP 与真实 token，另捕获管理端发给客户端的 `close`），`admin_http_tests`、`management_crud_tests`、`management_lists_tests`、`workbench_tests` 随之改为 Java 的状态码与文案，`decompression_limits_tests`、`traffic_capture_tests` 补 `br`（有 libbrotlidec 时才解码，本机 WSL 没有，以 CI 为准）。对照中发现、未改的：其余 Java 路径变量（客户端、凭据、映射、路由等）仍按 C 原来的方式只认正整数，非数字或 0 落到通用 404，Java 为 400；管理用户新增与修改的请求体沿用 #183/#199 账号向量的检查，`enabled` 的类型不符仍被忽略。

## 10. 本分支提交

| 提交 | 内容 |
| --- | --- |
| `fix(c-server): Elasticsearch traffic detail with Java's search, queue and stream semantics` | 第 5 节搜索、可见范围、写入队列、节点、`tcp-streams` |
| `fix(c-server): answer management reads larger than the listener's 32 KiB buffer` | 管理读应答超过 32 KiB 时原先无状态关闭连接；SQLite 分页偏移 64 位 |
| `test(c-server): traffic detail API over Elasticsearch, a real server and SQLite` | ctest `traffic_detail_api_tests`；fake Elasticsearch 按查询 DSL 求值 |
| `fix(c-server): client messages and /ws/connections frames as Java` | 来源账号检查、写入失败回执、二进制与未掩码帧 |
| `test(c-server): the management message channel on a real server process` | ctest `client_messages_tests` |
| `fix(c-server): management lists without a fixed row bound` | 客户端、映射、路由、凭据、用户、客户端目录 |
| `test(c-server): management lists with more rows than the old arrays` | ctest `management_lists_tests` |
| `fix(c-server): overview, connection list and traffic usage limits as Java` | 概览八个字段与公网连接计数、管理员连接记录范围、流量统计 `limit` |
| `test(c-server): the management overview on a real server process` | ctest `management_overview_tests` |
| `fix(c-server): capture a TCP frame before it is relayed, as Java` | 采集顺序 |
| `fix(c-server): client-message commands map like Java's ObjectMapper` | `invalid-json` 严格性 |
| `test(c-server): unmappable client-message commands on a real server` | `client_messages_tests` 补充 |

`fix/c-server-parity-edges`（第 9 节第 2、3、6 项）的提交：

| 提交 | 内容 |
| --- | --- |
| `fix(c-server): Peer Mesh lists, SQLite traffic search and edge cases as Java` | Peer Mesh 列表与全库客户端列表不限行数、会话分页；SQLite 搜索按 JPA 谓词、按记录租户的可见范围；连接记录、`listenPort`/`clientId`、裁剪字段、两个 WebSocket 的文本读取与命令成员 |
| `test(c-server): Peer Mesh lists, SQLite search, WebSocket text limits and scalar commands` | `management_lists_tests`、`traffic_detail_api_tests`、`elasticsearch_traffic_tests`、`client_messages_tests`、`peer_mesh_tests` 补充 |
| `docs(alignment): C inventory items 2, 3 and 6 done` | 本文与 test-map |

`fix/c-server-parity-crud`（第 9 节第 5、7 项）的提交：

| 提交 | 内容 |
| --- | --- |
| `fix(c-server): management CRUD endpoints and Peer service import as Java` | 凭据、映射列表与改删、名称可用性、`/me`、`database/initialize`、两个流量统计（统计表补 `tenant_id`）；Peer 服务导入的去重范围 |
| `fix(c-server): self-registration checks in Java's order and wording` | `/auth/register` 与 `/verify` |
| `test(c-server): the management CRUD endpoints against Java` | ctest `management_crud_tests`；`admin_http_tests` 随之调整 |
| `docs(alignment): C inventory items 5 and 7 done` | 本文与 test-map |

`fix/c-server-parity-peer-api`（第 9 节第 8 项）的提交：

| 提交 | 内容 |
| --- | --- |
| `fix(c-server): Peer Mesh and Egress endpoints, mapping create, view times and parameters as Java` | 27 个端点的绑定、检查、文案、状态码与视图；管理端关会话后通知两端；会话 `lastKeepaliveAt`；映射新增；ISO-8601 时间；Spring 参数转换；`X-Forwarded-Host` |
| `test(c-server): the Peer Mesh and Egress endpoints against Java` | ctest `peer_mesh_api_tests`（新增）；`admin_http_tests` 等随之调整；构建文件登记新测试并可选检测 libbrotlidec |
| `feat(c-server): decode Content-Encoding br when the build has libbrotlidec` | `decompression_limits`、明细预览与详情、媒体清单；两个工作流加 `libbrotli-dev`；`br` 测试 |
| `docs(alignment): the last 27 C inventory endpoints compared with Java` | 本文与 test-map |
