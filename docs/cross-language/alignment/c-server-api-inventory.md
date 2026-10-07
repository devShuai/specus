# 跨语言对齐：C server API 盘点

> 本文属于 [跨语言对齐](../cross-language-java-alignment-plan.md) 系列，为 Issue #35 的三项而写：「Elasticsearch HTTP/TCP 明细存储、搜索与归档语义」「live client-message 与管理/客户端 WebSocket 事件」「客户端发布、下载链接、审计及剩余 Java 管理 API 契约」。与 [c-server-test-map.md](c-server-test-map.md) 互补：那份按 Java 测试类对照，本文按 Java 端点对照。

清单按 2026-10-08 `fix/c-server-api-inventory` 分支（已合入 `main` `9deb086`）的源码逐项核对：Java 端点取自 `implementations/java/server` 中全部 `@RequestMapping/@GetMapping/@PostMapping/@PutMapping/@DeleteMapping` 与两个 `WebSocketConfigurer` 的 `addHandler` 注册，鉴权取自 `SecurityConfig`；C 端点取自 `src/admin_http.c` 的 `st_admin_build_response_internal`、监听器分发（`admin_handle_client`）与 `src/main.c`。`fix/c-server-parity-peer`、`fix/c-server-parity-rest` 尚未合入，合入后涉及的行要复核（见各行说明）。

## 读法

- **一致**：C 有对应实现，行为与 Java 一致，并有测试依据（下列 C 测试、中央向量，或 `c-server-test-map.md` 中记为「覆盖」的 Java 测试类）。
- **有差异**：C 有对应实现，但有已知的行为差异，“说明”写出差异；平台差异另在第 8 节列明原因。
- **没有**：C 没有对应实现。
- **未逐项对照**：C 有对应路由，鉴权与主要形状已核对，但请求校验、状态码等细节没有逐项对照 Java，也没有对照测试；列为待办（第 9 节），不算作一致。
- **本分支**：本分支修正过的行，提交见第 10 节。
- 鉴权：「公开」= `SecurityConfig` 中 `permitAll`；「Bearer」= 需要管理端本地 HS256 token（C 每次请求按 SQLite 重新读取用户）；「Bearer（任意）」= `/api/public/transfer/attachments/**`，任何已认证主体；「ticket」= WebSocket 一次性 ticket。

## 汇总

Java server 共 **141** 个端点：136 个 HTTP 映射（`/http/**` 与 `/http-share/**` 各计 1 个）和 5 个 WebSocket 端点。

| 状态 | 数量 | 说明 |
| --- | ---: | --- |
| 一致 | 86 | 其中 10 个是本分支修正后才一致 |
| 有差异 | 14 | 见各节“说明”，可修的列入第 9 节 |
| 没有 | 0 | 每个 Java 端点在 C 都有对应路由 |
| 未逐项对照 | 41 | Peer Mesh / Egress 27 个由 `fix/c-server-parity-peer` 对照；其余 14 个是管理 CRUD 等，见第 9 节 |

C 独有、Java 没有的端点：`GET /health`（`{"status":"ok"}`）、`GET /api/admin/metrics`（C 的映射计数快照）。

本分支修正的偏差（第 10 节有提交）：Elasticsearch 搜索、可见范围、写入队列、节点列表与 `tcp-streams` 契约；TCP 帧采集顺序；超过 32 KiB 的管理读应答被静默丢弃；客户端、映射、路由、凭据、用户、客户端目录列表的固定行数上限（超过后 500 或静默截断，目录截断后客户端看不到最新版本）；概览字段；管理员看不到已删除客户端和未知名称的连接记录；流量统计 `limit` 上限；客户端到管理员消息不检查来源账号；写入失败回执；命令 JSON 映射严格性；`/ws/connections` 的二进制与未掩码帧。

## 1. 认证、身份与管理用户

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| POST | `/auth/login` | 公开 | `{username,password,turnstileToken?,tenantId?}` → 本地 token | 一致 | test-map 第 1 节 `LoginRateLimiterTests`、`PasswordServiceTests`、`TurnstileVerifierTests`、`ManagementContextResolverTests` 均为覆盖 |
| POST | `/auth/register` | 公开 | 注册申请（邮箱验证码） | 未逐项对照 | `src/registration.c`；`admin_http_tests` 有 C 侧断言，Java 没有对应测试类 |
| POST | `/auth/register/verify` | 公开 | `{registrationId,code}` | 未逐项对照 | 同上 |
| POST | `/auth/refresh` | Bearer | 续期本地 token；IdP token 400 | 一致 | `AuthControllerRefreshTests` 覆盖 |
| GET | `/oidc-config` | 公开 | OIDC、注册、Turnstile 配置 | 一致 | `OidcControllerTests` 覆盖 |
| POST | `/oidc/token` | 公开 | code → 本地 token | 一致 | `OidcControllerTests`、`SecurityConfigOidcTests` 覆盖（ctest `oidc_tests`） |
| POST | `/api/client/auth/login` | 公开（HMAC 签名） | 客户端 HTTP 登录，返回会话 token 与配置 | 有差异 | 已消费的 nonce 存进程内存，多实例不共享（`ClientAuthNonceServiceIntegrationTests` 部分）。`fix/c-server-parity-rest` 改为存库，合入后复核 |
| GET | `/api/admin/me` | Bearer | 当前管理用户 | 未逐项对照 | `admin_http_tests`、`oidc_tests` 有 C 侧断言 |
| GET | `/api/admin/users` | Bearer | 本租户用户列表 | 有差异 | **本分支**去掉 128 行上限（ctest `management_lists_tests`）。差异同 test-map `ManagementUserServiceTests`：username 是全局主键，不同租户同名用户不存在 |
| POST | `/api/admin/users` | Bearer（admin） | 创建用户 | 有差异 | 其他租户已有同名用户时 C 回 409，Java 允许（同上） |
| PUT | `/api/admin/users/{username}` | Bearer（admin） | 改角色、启用、口令 | 有差异 | 其他租户的用户 C 回 404，Java 回 400（`ManagementUserServiceIntegrationTests` 部分） |
| DELETE | `/api/admin/users/{username}` | Bearer（admin） | 删除用户 | 有差异 | 同上 |

## 2. 客户端账号、凭据与 TCP 映射

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/admin/clients` | Bearer | 可见客户端列表（管理员为本租户） | 一致 | `ClientAccountServiceTests` 覆盖可见性；**本分支**去掉 128 行上限（原先全库超过 128 个客户端时所有租户都得 500），`management_lists_tests` |
| GET | `/api/admin/clients/name-availability` | Bearer | 名称是否可用 | 未逐项对照 | `admin_http_tests` 有 C 侧断言 |
| GET | `/api/admin/clients/{id}` | Bearer | `{client, specusMappings, httpRoutes}` | 有差异 | 单个客户端超过 64 条 TCP 映射或 64 条 HTTP 路由时读取失败（`ST_ADMIN_MAX_TCP_MAPPINGS`），Java 无上限；第 9 节 |
| POST | `/api/admin/clients/{id}/force-refresh-port-mapping` | Bearer | 推送 NAT_CONTROL，回 `{specusMappings,httpRoutes}` | 有差异 | C 多回一个 `pushed`（兼容字段，无害）；同样受每客户端 64 条上限限制 |
| POST | `/api/admin/clients` | Bearer | 创建客户端，201 | 一致 | `ClientAccountServiceTests` 覆盖 |
| PUT | `/api/admin/clients/{id}` | Bearer | 改名、停用（踢下线） | 一致 | `ClientAccountServiceTests` 覆盖 |
| DELETE | `/api/admin/clients/{id}` | Bearer | 删除并踢下线，204 | 一致 | `ClientAccountServiceTests` 覆盖 |
| GET | `/api/admin/client-credentials` | Bearer | 本租户凭据 | 未逐项对照 | **本分支**修正：原先超过 128 条时静默截断（`management_lists_tests`）；可见性规则未对照 Java |
| POST | `/api/admin/client-credentials` | Bearer | 创建凭据，201 | 未逐项对照 | `admin_http_tests` 有 C 侧断言 |
| PUT | `/api/admin/client-credentials/{id}` | Bearer | 更新凭据 | 未逐项对照 | 同上 |
| DELETE | `/api/admin/client-credentials/{id}` | Bearer | 删除，204 | 未逐项对照 | 同上 |
| GET | `/api/admin/specus-mappings` | Bearer | 可见 TCP 映射，可按 `clientId` | 未逐项对照 | **本分支**修正：原先全库超过 64 条映射时 500（`management_lists_tests`） |
| POST | `/api/admin/clients/{id}/specus-mappings` | Bearer | 创建映射，201，推送 NAT_CONTROL | 有差异 | 创建不限数量，但单客户端超过 64 条后登录配置与 NAT_CONTROL 构建失败（`load_database_tcp_mappings`），Java 无上限；第 9 节 |
| PUT | `/api/admin/specus-mappings/{specusId}` | Bearer | 更新映射并推送 | 未逐项对照 | `session_lifecycle_tests`、`runtime_config_e2e.sh` 覆盖推送 |
| DELETE | `/api/admin/specus-mappings/{specusId}` | Bearer | 删除并推送，204 | 未逐项对照 | 同上 |
| POST | `/api/admin/clients/{id}/nat-control` | Bearer | 手动推送，回 `{pushed,specusMappings,httpRoutes}` | 有差异 | 每客户端 64 条上限（同上） |

## 3. HTTP 路由、临时分享、访问审计与连通性检查

| 方法 | 路径 | 鉴权 | 请求 / 响应要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| GET | `/api/admin/http-routes` | Bearer | 可见 HTTP 路由 | 一致 | `HttpRouteServiceTests` 覆盖；**本分支**去掉全库 64 条上限 |
| POST | `/api/admin/clients/{id}/http-routes` | Bearer | 创建路由 | 有差异 | 每客户端 64 条上限（同第 2 节） |
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
| GET | `/api/admin/connections` | Bearer | `clientId/success/from/to/page/size`（1..500），`{items,total,page,size,totalPages}` | 有差异 | **本分支**修正管理员视图：原先连接客户端表，已删除客户端的记录和未知名称的失败登录不显示，Java 按记录的租户过滤（`management_overview_tests`）。剩余差异：普通用户还能看到按名称匹配到自己客户端的失败登录（`client_id` 为空），Java 只按 `clientId` 匹配 |
| GET | `/api/admin/connection-stats` | Bearer | 月度归档统计，`clientName`/`limit`（1..500） | 一致 | `ConnectionArchiveServiceTests` 覆盖（ctest `connection_archive_tests`） |
| GET | `/api/admin/overview` | Bearer | Java `OverviewService` 八个字段 | 一致 | **本分支**：原先只回 `{server,status,onlineClients:0,tcpMappings}`，管理端界面读的八个字段都缺；现按 Java 计算，并在运行时维护每租户的公网连接计数（`management_overview_tests`，真实进程） |
| POST | `/api/admin/database/initialize` | Bearer（admin） | 初始化演示数据 | 未逐项对照 | `admin_http_tests` 有 C 侧断言 |
| GET | `/api/admin/traffic` | Bearer | 流量统计，`clientId`/`limit` | 未逐项对照 | **本分支**把 `limit` 改为 Java 的 1..500（原先最多 1000，超过 1000 回落到 100）；字段未逐项对照 |
| GET | `/api/admin/traffic/resources` | Bearer | 按资源的流量统计，`type`/`clientId`/`limit` | 未逐项对照 | 同上 |
| GET | `/api/admin/traffic/http-exchanges` | Bearer | 明细摘要分页 | 一致 | **本分支**（第 5 节）；ctest `traffic_detail_api_tests`、`elasticsearch_traffic_tests` |
| GET | `/api/admin/traffic/http-exchanges/{id}` | Bearer | 明细含表头、预览与 body | 有差异 | `main` 上 C 只存预览不存 body，二进制 body 不显示为 `data:` URL；`fix/c-server-parity-rest` 补 body，合入后复核 |
| GET | `/api/admin/traffic/tcp-frames` | Bearer | 帧摘要分页，`clientId`/`listenPort`/`page`/`size\|limit` | 一致 | **本分支**；`traffic_detail_api_tests` |
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
| 已存在 HTTP 索引补 body 的 binary 映射 | `putBinaryBodyMapping` | 有差异 | `main` 上 C 不存 body；`fix/c-server-parity-rest` 存 body 但只在建索引时带映射，合入后补（第 9 节） |
| 文档 id | `(毫秒 << 20) \| 序号` | 一致 | `es_new_id` |
| 写入路径 | 采集线程入队，后台每 2 s 以批（1000）写入，每类最多 20000 条待写，超出丢弃计数 | 一致 | **本分支**：原先每条明细、每个 TCP 帧在转发线程上同步 PUT（集群慢时每帧最多等 15 s）。现为同样的队列（`_bulk`），环境变量同名；C 另加 256 MiB 总量上限（第 8 节）。`traffic_detail_api_tests`：入队计数、未 flush 前搜不到 |
| `flush=true` | 立即写一批 | 一致 | **本分支**；http-exchanges、tcp-frames、tcp-streams 都接受 |
| 关停 | `flushBeforeShutdown` 写一批 | 一致 | **本分支**：SIGTERM 后写出队列中全部文档（Java 只写一批，第 8 节）；`traffic_detail_api_tests` 真实进程断言关停前入队的帧已在集群 |
| 采集顺序 | 两个方向都在转发前采集，同一事件循环 | 一致 | **本分支**：原先公网到客户端的帧在转发与流量统计写库之后才采集，负载下帧序号会颠倒（实测 P0、C0、P1） |
| 摘要排除大字段 | `SUMMARY_SOURCE_EXCLUDES` | 一致 | 表头、预览不读（body 字段随 parity-rest） |
| 搜索字段 | `HttpTrafficSearchField.fromCode`：代码或常量名，忽略大小写，未知回落 summary | 一致 | **本分支**：原先自有别名（`headers`、`body`、`query`），`all` 不含表头与正文 |
| 关键词 | 按空白切 token，每个 token 都须命中；text 字段 `multi_match`，keyword 字段大小写不敏感 `*token*` 通配（转义 `\ * ?`），数字匹配 id/clientId/statusCode/resourceId，method 为大写 term，无可匹配字段时不匹配 | 一致 | **本分支**：原先一个 `simple_query_string`，其运算符会改变语义，keyword 字段只能整值大小写敏感匹配，数字不匹配状态码 |
| `responseBodyType` | 规范化（trim、小写、未知不过滤），匹配存储类型、空 body 或对应 Content-Type；空白时取 `responseDataType` | 一致 | **本分支**（SQLite 同样修正） |
| `route` | trim 后精确过滤 | 一致 | **本分支** |
| 可见范围 | 管理员只按租户（含已删除客户端），其他人按拥有的客户端，`clientId` 不可见时空页 | 一致 | **本分支**：原先管理员也只看 SQLite 现存客户端 |
| 分页 | `page>=0`，`size` 1..500，按 id 倒序，`total` 取 hits.total | 一致 | `from` 改为 64 位计算 |
| 明细 | 租户 + id（+可见客户端），含表头与预览 | 一致 | body 见上 |
| TCP 列表 | `clientId`、`listenPort`、分页、id 倒序 | 有差异 | `listenPort=0` 时 Java 按 0 过滤（空结果），C 视为不过滤；边缘 |
| TCP 流 | `exactText(channelId)`（term、`.keyword`、match_phrase），id 正序，`page`/`size`（默认 `limit` 500，1..1000），回 `channelId,items,total,page,size,limit,totalPages(>=1),truncated`；空白 channelId 为空页 | 一致 | **本分支**：原先忽略分页、`total` 为条数、缺 `page/size/totalPages`、按各方向的帧序号排序、SQLite 下 `limit` 超过 500 回 500 |
| 保留期（按大小裁剪） | 每分钟最多一次；超过上限按 id 升序每批删 500 条、最多 20 批；`total_data_set_size_in_bytes` 优先 | 有差异 | 语义相同（C 用 `_bulk` 删除）；边缘：`total_data_set_size_in_bytes` 为 0 时 C 改读 `size_in_bytes`，Java 只要字段存在就用它 |
| 归档 | 流量明细没有归档，只有按大小裁剪；连接记录的月度归档见第 4 节 | 一致 | — |
| SQLite 后端（对照 JPA store） | 与 ES 同一套字段与 token 语义；管理员按租户 | 有差异 | 不属于 ES 本身：C 的 SQLite 搜索保留自有字段别名，管理员视图连接客户端表，看不到已删除客户端的流量（第 9 节） |

## 6. client-message 与 WebSocket 事件

对照 `protocol/spec/client-messages.md`、`ClientMessagesWebSocketHandler`、`MessageRequestHandler`、`ConnectionEventsWebSocketHandler`、`WebSocketTicketHandshakeInterceptor`。测试：ctest `client_messages_tests`（真实 `specus-server-c` 进程 + 按协议登录的客户端，及进程内监听器）、`admin_http_tests` 的 `test_client_messages_websocket` 与 `test_connection_events_websocket`、`public_transfer_tests`。

| 方法 | 路径 | 鉴权 | 要点 | C 状态 | C 证据 / 说明 |
| --- | --- | --- | --- | --- | --- |
| POST | `/api/admin/ws-tickets` | Bearer | `{"endpoint":"connections"\|"client-messages"}` → 45 s 单次 ticket，`no-store` | 一致 | `WebSocketTicketServiceTests` 覆盖 |
| WS | `/ws/connections` | ticket | 推送 `{tenantId,type:created\|updated,connection}`，管理员收本租户全部，其他人只收自己客户端的 | 有差异 | 差异仅为 Redis 集群扇出（第 8 节平台差异）。**本分支**：二进制帧 1003、未掩码帧 1002（`client_messages_tests`）；边缘：Tomcat 文本消息超过 8 KiB 以 1009 关闭，C 的上限为 1 MiB |
| WS | `/ws/client-messages` | ticket | 见下表 | 有差异 | 唯一剩余差异：`messageId` 为数字时 Java 读作字符串并回显，C 回显空串（边缘） |
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
| GET/PUT/GET/POST/DELETE/GET/GET/DELETE/DELETE/GET/PUT/GET/POST/PUT/DELETE/POST/GET | `/api/admin/peer-mesh/status`、`/devices`、`/devices/{clientId}`、`/acls`、`/acls/{id}`、`/stats`、`/sessions`、`/sessions/{id}`、`/service-sharing`、`/services`、`/services/{id}`、`/services/import`、`/service-audit`（18 个） | Bearer | 未逐项对照 | 由 `fix/c-server-parity-peer` 对照（test-map `PeerMeshServiceTests`、`PeerServiceDiscoveryServiceTests` 为部分）。另见第 9 节：C 的 Peer 列表仍有固定上限 |
| GET/PUT/GET/POST/GET/DELETE | `/api/admin/peer-mesh/egress/switch`（GET、PUT）、`/policies`（GET、POST）、`/activity`、`/policies/{id}`（6 个） | Bearer | 未逐项对照 | 同上（`PeerEgressResourceTests` 部分） |
| GET | `/api/public/peer-mesh/stun-config`、`/api/public/transfer/ice-config`、`/api/public/peer-mesh/nat-probe-config`（3 个） | 公开 | 未逐项对照 | `PublicPeerMeshResourceTests` 部分（standalone STUN 三项未测） |
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

## 9. 待办（按影响排序）

1. **每客户端 64 条 TCP 映射 / 64 条 HTTP 路由**（`admin_http.c` `ST_ADMIN_MAX_TCP_MAPPINGS`、`main.c` `ST_MAX_TCP_MAPPINGS`）：创建不受限，但超过后该客户端的登录配置、NAT_CONTROL 推送与 `GET /api/admin/clients/{id}` 失败；Java 无上限。需要把运行时会话里的映射数组改为动态分配。
2. **Peer Mesh 管理列表的固定上限**（`peer_mesh.c` 256 个客户端、`append_peer_mesh_egress_policy_view` 512 个客户端）：与上面已修的列表同类，留给 `fix/c-server-parity-peer` 合入后处理。
3. **SQLite 流量明细搜索对照 JPA**：字段代码按 `HttpTrafficSearchField`、未知代码回落 summary、管理员按记录租户（看得到已删除客户端的流量）。
4. **`fix/c-server-parity-rest` 合入后复核**：HTTP body 存储与详情显示、已存在 Elasticsearch HTTP 索引补 binary body 映射、客户端登录 nonce 存库，以及 test-map 中 `TrafficInspectionServiceTests`、`HttpTrafficExchangeStoreTests` 两行。
5. **未逐项对照的 14 个管理端点**：注册两条、`/api/admin/me`、凭据 CRUD 四条、映射列表与改删三条、`database/initialize`、客户端名称可用性、流量统计两条——逐项对照校验规则、状态码与字段。
6. 边缘差异：连接记录普通用户可见范围（按名称匹配的失败登录）、`listenPort=0`、裁剪时 `total_data_set_size_in_bytes` 为 0 的回退、`/ws/connections` 文本上限、数字 `messageId` 的回显。

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
