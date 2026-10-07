# 跨语言对齐：C server 测试对照

> 本文属于 [跨语言对齐](../cross-language-java-alignment-plan.md) 系列，为 Issue #35 验收项“Java 参考测试均有对应 C 单测/集成测试或书面平台差异说明”而写。

本文逐个列出 `implementations/java/server/src/test` 下的 Java server 测试类，说明 C server（`implementations/c/server`）里哪一项测试验证了同样的行为。没有对应测试时，写明原因：C 没有这项能力（平台或范围差异），或者能力在 C 源码里但没有测试。

清单按 2026-10-06 `docs/c-server-claims` 分支（已合入 `main` `5394a3b`）的源码树逐项核对，不是从既有文档转抄。2026-10-07 `fix/c-server-test-gaps` 补齐了 TURN 对端策略、浏览器头改写、Turnstile、SemVer、流量明细采集与摘要查询几行，并按当时的源码重新核对了这几行和平台差异行。

基线之后 Java 又新增了 16 个测试类，本表尚未逐行对照：`HttpRouteConnectivityCheckRateTests`、`HttpRouteConnectivityCheckVectorTests`、`NatConnectivityProbeTests`、`HttpRouteConnectivityCheckResourceTests`（连通性检查）、`HttpShareHttpTests`、`HttpShareVectorTests`（临时 HTTP 分享）、`HttpSpecusControllerFailClosedTests`、`HttpSpecusControllerStreamResetTests`、`NatControlServiceHttpRoutesTests`、`WorkbenchCascadeTests`、`WorkbenchResourceTests`、`WorkbenchVectorTests`（服务工作台）、`ManagedLoginProductMetricsTests`、`ProductMetricsModelTests`、`ProductMetricsVectorTests`、`ProductMetricsWritePathTests`（产品指标）。下文的计数只含基线的 79 个类。

## 读法

- **覆盖**：C 测试验证了该 Java 测试类断言的行为。
- **部分**：只有一部分行为有 C 测试，“说明”列写出缺的部分。
- **无**：没有 C 测试，“说明”列写原因。
- **C 证据**的写法：
  - `文件:函数`：`tests/` 下的 C 测试函数。
  - 带引号的字符串：`tests/admin_http_tests.c` 的检查大多直接写在 `main()` 里，引号内是该检查失败时打印的 `fprintf` 文本，可以直接 grep 定位。写在其它文件里的会注明文件名。
  - ctest 名：`CMakeLists.txt` 注册的测试。
  - `scripts/*.sh`：端到端脚本。其中 `nat_e2e_smoke.sh`、`runtime_config_e2e.sh`、`direct_route_e2e.sh` 和 `java_c_discovery_interop.sh` 只由 CI 的「C server (Linux)」任务运行，不在 ctest 里。
- 单个 Java 测试类的 `@Test` 数含 `@ParameterizedTest`。

## 汇总

79 个 Java 测试类中，**覆盖 20 个，部分 50 个，无 9 个**（2026-10-07 随 `fix/c-server-test-gaps` 更新；此前为覆盖 17、部分 47、无 15）。

审计点名的类目前的状态如下：

| Java 测试类 | 状态 | 一句话 |
| --- | --- | --- |
| `NatServerHandlerTests` | 覆盖 | 6 项断言均由 `nat_stream_tests` 对真实进程验证；原先未知流静默丢弃、HTTP `DATA\|END_STREAM` 被忽略两处差异已修正 |
| `TcpServerHalfCloseTests` | 覆盖 | `nat_stream_tests` 让公网侧先 `shutdown(SHUT_WR)`，客户端在其 EOF 之后仍能回写并收尾 |
| `HttpStreamExchangeTests` | 部分 | 帧顺序（响应头唯一且在 body 之前、FIN 之后无帧）与 `DATA\|END_STREAM` 已有测试；trailer 过滤 C 未实现，窗口上限没有确定性测试 |
| `HttpSpecusBodyLimitFilterTests` | 部分 | `413 HTTP 请求体超过限制`（Content-Length 与 chunked）和恰好 16 MiB 放行已有测试；C 不记录被拒请求，且对整个管理监听生效 |
| `OidcControllerTests` | 无 | C 的 `/oidc/token` 只代理 code 交换：不校验 ID Token，不绑定本地用户，也不签发本地 token |
| `SecurityConfigOidcTests` | 无 | C 不接受外部 issuer 签发的 JWT，所以 issuer 校验在 C 不存在 |
| `ClientAuthNonceServiceTests`、`ClientAuthNonceServiceIntegrationTests`、`ClientAuthNonceRepositoryCustomImplTests` | 覆盖 / 部分 / 无 | C 已原子消费 nonce（`client_auth_nonce_tests`），但存储在进程内存，多实例不共享；仓库方言测试不适用 |
| `TrafficInspectionServiceTests` | 部分 | 默认关闭、gzip 解码后的文本预览、二进制无文本预览、按预览长度截断、TCP 全量保存均有测试（`traffic_capture_tests`、`nat_stream_tests`）；C 存预览不存 HTTP body |
| `StunTurnServerMetricsTests` | 部分 | 目的地址策略的全部用例（含 IPv6 与 IPv4-mapped）由 `stun_turn_tests` 对 CreatePermission 与 ChannelBind 验证；C 没有 relay 工作队列与指标 |
| `ConnectionEventsWebSocketHandlerTests` | 部分 | #132 补了真实 socket 的 created/updated 事件、租户与归属过滤、ticket 规则；C 没有集群扇出 |

全部 9 个“无”：`SpecusServerApplicationTests`、`SecurityConfigOidcTests`、`OidcControllerTests`、`GlobalExceptionHandlerTests`、`ClientDownloadSchemaMigratorTests`、`LegacyDemoCredentialSanitizerIntegrationTests`、`ManagementUserSchemaMigratorTests`、`ClientAuthNonceRepositoryCustomImplTests`、`JpaHttpTrafficExchangeStoreIntegrationTests`。除两个 OIDC 类外都是书面平台差异，见各行说明。

## 1. 启动、认证与安全规则

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `SpecusServerApplicationTests` | 1 | 无 | — | Spring 上下文加载测试，C 没有对应结构。真实进程启动由 `session_lifecycle_tests` 和各 E2E 脚本间接覆盖。 |
| `config/SecurityBaselineValidatorTests` | 6 | 覆盖 | `tests/security_baseline_tests.c:main`（ctest `security_baseline_tests`） | 覆盖环境解析、同一组 11 个弱口令、prod 拒绝 JWT 占位值、演示数据开关。未断言两项：test 环境允许演示数据，prod 接受非占位 JWT secret。 |
| `config/SecurityConfigOidcTests` | 2 | 无 | — | C 不存在这项能力。`src/security.c:st_security_validate_local_token` 只接受 `alg=HS256`、`iss=specus` 的本地 token，没有外部 issuer、JWKS 或 RS256 验签。 |
| `management/controller/OidcControllerTests` | 4 | 无 | 只有代理部分有测试：`security_tests.c` "OIDC configured response mismatch"；"oidc http token exchange response mismatch"（明文 HTTP mock endpoint） | C 不存在这项能力。`/oidc/token` 原样返回 IdP 的 token，不校验 ID Token 的 nonce 和 audience，不解析或开通本地用户，也不签发 Specus token。见 [安全差异](security-differences.md)。 |
| `management/controller/AuthControllerRefreshTests` | 3 | 部分 | "refresh response mismatch"；`admin_http_tests.c:test_management_token_follows_user_record`："demoted admin was not refreshed as USER"、"disabled user, refresh"、"deleted user, refresh"；`security_tests.c` "local token accepted wrong secret" | 前两项有对应：`/auth/refresh` 与其他鉴权请求走同一个 `admin_context_from_authorization`，按当前 SQLite 记录重新读取用户，`handle_management_auth_refresh` 用读到的 tenant/role 签发；降权的 admin 续期为 USER，已禁用或删除的用户得到 `401`。差异：外部 issuer 签发的 token 在 C 不是有效凭据，刷新得到 `401`，Java 是 `400`。（本行原先写“不回查数据库”，与当时的代码不符，已更正。） |
| `management/security/ManagementContextResolverTests` | 3 | 部分 | `admin_http_tests.c`：降级 admin 失去 admin 端点且续期为 USER、禁用用户请求 403/续期 401 且重新启用后恢复、删除与不存在的用户被拒、关闭密码登录后内置 admin 被拒 | 每个鉴权请求与 `/auth/refresh` 都按当前 SQLite 记录重新读取管理用户（只读、无缓存）。C 没有外部身份绑定，这部分不适用。 |
| `management/controller/GlobalExceptionHandlerTests` | 1 | 无 | — | 这是 Spring 的统一异常映射层，C 没有对应结构；C 各 handler 直接写错误 JSON。 |
| `security/ClientAddressResolverTests` | 11 | 覆盖 | `tests/client_address_tests.c:main`（逐用例 `expect_address`）：直连伪造、不可信 peer、可信代理、多跳、伪造前导跳、畸形跳、`X-Real-IP` 回退、IPv6、无效 CIDR 等 | — |
| `security/LoginRateLimiterTests` | 5 | 覆盖 | `tests/login_rate_limiter_tests.c:main`；"per-IP login rate limit response mismatch"、"per-account login rate limit response mismatch"、"successful login did not clear account rate-limit budget" | 未断言关闭限流后跳过计数。 |
| `security/PasswordServiceTests` | 7 | 覆盖 | `tests/password_hash_tests.c:main`（共享向量、低成本升级、旧 SHA-256 迁移、畸形哈希拒绝、错误口令）；"management user password was not stored with PBKDF2"、"legacy management user hash was not upgraded on login" | 未断言同一口令两次哈希的 salt 不同。 |
| `security/SecurityRulesTests` | 19 | 部分 | "unauthenticated admin api response mismatch"、"authenticated admin api response mismatch"、"database user client download admin-only response mismatch"、"oidc config response mismatch"、"invalid login response mismatch"、"http route authentication storage mismatch"；`object_storage_tests.c:test_capabilities_requires_authentication`；`object_storage_e2e`（匿名 capabilities `401`、grant 重放 `410`、`HEAD` `405`） | 以下规则在 C 没有测试：未知 grant 直接 `410`、OSS callback 匿名访问但签名无效时拒绝、外来 Bearer 不影响公开 HTTP 代理、ingress 不继承管理端 CSP、管理页 CSP 放行 GitHub API、云端流程图鉴权。 |
| `security/TurnstileVerifierTests` | 4 | 覆盖 | ctest `turnstile_verifier_tests`（不装测试替身，生产路径经 HTTP 请求 loopback 上的假 siteverify）："login with the expected action and hostname"、"register token answered for login"、"unexpected hostname"、"enabled without keys or hostnames"；门禁本身另见 "turnstile-protected login accepted a missing token" | 三项行为用例逐一对应（表单含 `secret` 与 `response`、action 或 hostname 不符 `400`、启用但缺 key 或 hostname 时 `503` 且不发请求）。第四项检查 Spring 的注入构造器，C 没有对应结构。另测了 hostname 规范化、空 token 不发请求、siteverify 非 2xx 与不可达 `503`。补测时修正两处：2xx 但正文不是 JSON 对象时 C 回 `400`，Java 视为服务不可用回 `503`；token 经 const 指针被原地 trim，传入只读字符串会崩溃。 |

## 2. 数据库迁移

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `database/ClientDownloadSchemaMigratorTests` | 1 | 无 | — | 平台差异，经核对不影响 C 的行为正确性。Java 的迁移器为旧 Java 库补 `catalog_key`/`latest_slot` 唯一槽、把重复的版本与 latest 去重、把 `v1.2.3` 归一为 `1.2.3`；C 只给 `client_download_link` 补列（`src/storage.c`），但 C 自己的写路径维持同样的不变式：写入前去掉一个 `v`（`admin_http.c` 读取客户端包请求处），latest 只允许已启用且有版本的行，设为 latest 时在同一事务里清掉同一 implementation/platform/arch 槽的其他 latest（`st_storage_upsert_client_download_link_extended`）。读路径也容忍遗留数据：`parse_admin_semver` 接受一个 `v` 前缀，版本检查在同槽多个 latest 中按 SemVer 取最高。C 写出的数据因此不需要这次迁移。剩下的差异：没有数据库级唯一约束，库外写入或并发创建仍可能产生重复目录项；把 Java 未迁移的旧库交给 C 时，重复行不会被清理（公开目录里同一目标可能出现多个 latest）。补列路径本身没有测试。 |
| `database/LegacyDemoCredentialSanitizerIntegrationTests` | 4 | 无 | 相关但不等价：`security_baseline_tests` 断言未设置环境时禁止演示数据 | C 不存在这项能力，也不需要：C 从不写入公开的演示凭据，只在 dev/test 下创建一个没有 api key 的 `Demo client`。 |
| `database/ManagementUserSchemaMigratorTests` | 3 | 无 | — | C 不存在这项能力：`specus_management_user` 以全局 `username` 为主键，没有 login_name 列和租户内唯一索引。另外 C 只用 SQLite，MySQL/PostgreSQL 迁移不适用。 |
| `database/PeerServiceDiscoverySchemaMigratorTests` | 2 | 部分 | `storage_tests.c:test_peer_mesh_egress_domain_rules_migration`、`storage_tests.c:test_client_session_domain_targets_migration` | 未测：sharing/shared_service 表的默认值，以及给旧 session 表补 `peer_service_discovery_version`、`client_egress_version` 两列。 |
| `management/repository/ClientAuthNonceRepositoryCustomImplTests` | 3 | 无 | — | 平台差异：C 的 nonce 存储在进程内存（`client_auth_nonce.c`），没有 nonce 表，MySQL/PostgreSQL 方言不适用。 |

## 3. 控制连接、NAT 与端到端

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `handler/ConnectionRoleHandlerTests` | 2 | 部分 | `session_lifecycle_tests.c`：`expect_channel_alive`（control 与 data 的 HEARTBEAT 都有应答）、`test_second_login_on_one_connection_closes_it`；`nat_stream_tests.c:check_heartbeat_response`（control 与 data 上的 `HEARTBEAT_RESPONSE` 被接受） | 以下角色错配逻辑写在 `src/main.c` 但没有测试：control 上收到 NAT 帧、data 上收到 MESSAGE_REQUEST。 |
| `handler/NatServerHandlerTests` | 6 | 覆盖 | `nat_stream_tests.c`：`check_heartbeat_response`（KEEPALIVE）、`check_unknown_streams`（未知流的 DATA/FIN 回 `RST 7`，连接保留）、`check_rst_for_never_opened_stream`、`check_tcp_data_after_fin` 与 `check_http_data_before_head`（迟到的 RST 被忽略）、`check_register_bind_failure`、`check_http_end_stream` | 均对真实进程与 socket。C 另把每条流违规只复位该流（`RST 7/8/4/6`）的规则逐条测到，见 [运行时语义](runtime-semantics.md)。 |
| `server/TcpServerHalfCloseTests` | 1 | 覆盖 | `nat_stream_tests.c:check_tcp_public_half_close`（公网侧先半关闭，客户端在 EOF 后回写并 FIN）、`check_tcp_data_after_fin`（客户端先 FIN，公网侧收到 EOF） | — |
| `integration/EndToEndSpecusIT` | 1 | 覆盖 | `scripts/runtime_config_e2e.sh`（API key 登录、在线投影、建 mapping 后经公网端口走 TCP、建/改 route 后经 NAT_CONTROL 热推并跑 Direct HTTP）、`scripts/nat_e2e_smoke.sh`、`scripts/direct_route_e2e.sh` | 由 CI 对 Java/Go/.NET 三个客户端各跑一次。 |

## 4. Direct HTTP / WebSocket

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `http/DecompressionLimitsTests` | 4 | 覆盖 | `tests/decompression_limits_tests.c`：`main`、`expect_round_trip`、`expect_bomb_rejected`、`expect_exact_allowance` | `limitFor(-1)` 在 C 不适用（参数是 `size_t`）。 |
| `http/HttpQueryStringCodecTests` | 2 | 部分 | "direct HTTP raw path or query brace encoding mismatch"；`nat_e2e_smoke.sh`、`runtime_config_e2e.sh` 的 `%7Bok%7D` | 未测：query 中的 `/`、`?` 原样保留，null 与空 query 的区分。 |
| `http/HttpRouteAuthenticationServiceTests` | 4 | 覆盖 | `admin_http_tests.c:test_direct_http_route_authentication`："protected route missing basic credentials mismatch"、"protected route invalid basic credentials mismatch"、"malformed protected route policy should fail closed"、"route auth database failure should fail closed"、"database-unmanaged environment route compatibility mismatch" | 未测的小分支：`Bearer` scheme、口令中含 `:`。 |
| `http/HttpSpecusBodyLimitFilterTests` | 3 | 部分 | `nat_stream_tests.c:test_request_body_limit`（Content-Length 与 chunked 超过 16 MiB 得 `413 HTTP 请求体超过限制`，恰好 16 MiB 照常转发） | 未测也未实现：被拒请求不写 HTTP 明细；限制对整个管理监听生效、不限于 `/http/**`。 |
| `http/HttpSpecusControllerAuthenticationTests` | 8 | 部分 | `test_direct_http_route_authentication`："protected route successful auth or authorization stripping mismatch"、`route_auth_detail_is_sanitized` | 4 个 trailer 用例没有 C 测试。C 丢弃全部请求 trailers；响应 trailers 只检查 CR/LF，不按声明名和禁用字段过滤。 |
| `http/HttpStreamExchangeTests` | 5 | 部分 | `protocol_fixture_tests.c:test_nat_decode`（trailerNames、FIN trailers 编解码）；`direct_route_e2e.sh` 的 "GET (6 MiB)"、"GET (streamed)"；`nat_stream_tests.c`：`check_http_data_before_head`、`check_http_second_head`、`check_http_end_stream`（响应头唯一且先于 body、FIN 之后的帧复位该流）、`check_http_response_limit`（按窗口收发 64 MiB） | 窗口上限的拒绝写在 `process_direct_http_message` 但没有确定性测试（服务端在交付后即回补 credit）。trailer 过滤 C 未实现。 |
| `http/HttpWebSocketRoutingTests` | 5 | 部分 | 路由认证测试的 `ws_calls`/`http_calls` 计数；`nat_e2e_smoke.sh` 的 WS `101`；"route runtime static asset path mismatch" | 未测：客户端离线时 `502 客户端不在线`、polyfill 正文内容。query 中裸 `\|` 返回 `400` 是 Tomcat 特有行为，C 不适用。 |
| `http/ResponseRewriterTests` | 2 | 部分 | "direct http html rewrite response mismatch"、"bounded gzip response rewrite mismatch"、"gzip decompression bomb was not safely passed through without rewrite" | 未测：协议相对 URL 和绝对 URL 保持不变。Java 在 Node 下运行 polyfill 的用例在 C 没有对应，C 只负责提供同一个静态文件。 |
| `http/UpstreamBrowserHeadersTests` | 3 | 覆盖 | ctest `upstream_browser_headers_tests`（Java 三个用例逐一对应，另有 origin 与 Referer 的边界）；`admin_http_tests.c`："direct HTTP browser headers were not moved onto the route target"、"protected websocket successful auth or authorization stripping mismatch"；`http_share_tests.c` "cookie strip test: browser headers"、"websocket test: browser headers"；`nat_stream_tests.c:check_upstream_browser_headers`（真实进程的 NAT OPEN 元数据） | `src/upstream_browser_headers.c` 移植 `originOf`/`rewriteReferer`/`rewrite`，在 `/http/` 与 `/http-share/` 的 HTTP 和 WebSocket 四个入口收集请求头后立即改写，所以发给设备的 OPEN 元数据和记录的 HTTP 明细都是改写后的头（与 Java 相同）。目标取自授权 `/http/` 的路由行（或 `SPECUS_HTTP_ROUTES` 条目）和分享对应的路由。两处有意的差异：Referer 中的 `%` 保持原样，Java 的 `URI` 多参数构造器会把它再编码成 `%25`；Referer 的 user info 被丢弃（与 Go 客户端相同），Java 会保留。Go/.NET 服务端不做这项改写；Java/Go/.NET/Android 客户端在设备侧本来就会做同样的改写。 |
| `http/WebSocketSpecusHandlerTests` | 4 | 覆盖 | `direct_websocket_tests.c`：`test_client_violations`、`test_client_fragments_and_control`、`test_round_trip_and_browser_close`、`test_close_credit_timeout` | 违规码与 Java 不同：C 以 `1002` 关闭浏览器并发 `RST 30`，credit 超时发 `RST 31`。各语言的取码差异已记录在 [运行时语义](runtime-semantics.md)。 |
| `http/WebSocketSpecusHandshakeInterceptorAuthenticationTests` | 5 | 覆盖 | "protected websocket missing basic credentials mismatch"、"protected websocket successful auth or authorization stripping mismatch"、"disabled database route should fail before websocket dispatch"、"route auth database failure should fail closed" | 未断言 WS `401` 的 `WWW-Authenticate` 头和 WS `404` 的 `Cache-Control` 头。 |

## 5. 管理 API：客户端、凭据、路由、客户端包、用户

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `management/service/ClientAccountServiceTests` | 2 | 部分 | "client update response mismatch"（改名） | `/api/admin/clients/name-availability` 在源码里但没有测试；改名后运行期引用同步更新也没有断言。 |
| `management/service/ClientAuthNonceServiceTests` | 1 | 覆盖 | ctest `client_auth_nonce_tests`；`admin_http_tests.c` 两条登录路径的重放；`session_lifecycle_tests` 对真实进程重放 | 摘要与 Java 同算法、保留 120 s；另覆盖到期边界、32 线程竞争恰一胜出、容量满 503、时钟回拨。 |
| `management/service/ClientAuthNonceServiceIntegrationTests` | 1 | 部分 | 同上 | C 的存储在进程内，多实例不共享、重启后清空（重启后可重放的只限前 60 s 内签名的请求），Java 存数据库。 |
| `management/service/ClientAuthServiceEgressLoginTests` | 4 | 覆盖 | "client egress capability negotiation mismatch"；`peer_egress_tests.c:run_domain_target_declaration`；`storage_tests.c:test_client_session_domain_targets_migration` | — |
| `management/controller/ClientDownloadLinkResourceTests` | 1 | 部分 | "hosted client package download mismatch"（`200`、类型、`X-Checksum-SHA256`、正文）、"hosted client package catalogue/file mismatch"（`Specus Android.apk`） | 未测：`no-store`、`Content-Disposition`、`ETag`、`nosniff`、`HEAD`、`Range`。 |
| `management/service/ClientDownloadLinkServiceTests` | 15 | 部分 | "client download disabled create response mismatch"、"unpublished client download leaked into public list"、"client download latest response mismatch"、"client version check response mismatch"、"client download admin list order mismatch"；`github_release_tests.c:main` | 未测：旧版 target 兼容、Android `any`、已配置 target 时屏蔽 GitHub fallback、外链 latest 必须有已验证的 HTTPS 元数据、标记 latest 必须是合法 SemVer。 |
| `management/service/ClientPackageLifecycleTests` | 2 | 部分 | "hosted client package upload mismatch"、"hosted client package catalogue/file mismatch"、"hosted client package delete mismatch" | 未测：目录写入失败后清理暂存文件。 |
| `management/service/ClientPackageRateLimiterTests` | 1 | 部分 | "client package shared rate limit rejection mismatch"（同一来源第 3 次请求返回 `429` 并带 `Retry-After`） | 未测：不同来源独立计数、未知来源失败关闭。 |
| `management/service/ClientPackageStorageTests` | 2 | 部分 | "hosted client package upload mismatch"（`fileSize`）、下载响应的 SHA-256 头 | 未测：按实际流大小限额、空文件和非法 id 的拒绝。 |
| `management/service/GitHubReleaseCatalogTests` | 2 | 部分 | `github_release_tests.c:main`："trusted GitHub release mapping mismatch"、"invalid GitHub release tag was accepted" | 成功响应的缓存没有测试。 |
| `management/service/SemanticVersionTests` | 2 | 覆盖 | ctest `semantic_version_tests`（经测试钩子 `st_admin_semver_compare_for_testing` 调用 `parse_admin_semver`/`compare_admin_semver`） | Java 两个用例的全部断言都有对应，另测 SemVer 2.0 第 11 节的优先级链与 32 字符上限。补测时修正：`strtok_r` 会跳过空段，C 原先接受 `1.0.0+build..1`（Java 用例中的拒绝项）、`1.0.0-alpha..1`、`1..0.0`、`1.0.0.` 等空标识符；首尾空白按 Java `String.trim` 处理。 |
| `management/service/HttpRouteServiceTests` | 22 | 部分 | "http route create response mismatch"、"http route filtered list response mismatch"、"http route update response mismatch"、"http route delete response mismatch"、"HTTP media capture route create mismatch"、"http route missing authentication password was not rejected"、"blank http route auth password should retain the configured digest"、"http route authentication storage mismatch" | 未测：同客户端重复 route、空 route、含 `/`、超长 route、非 http target、target 缺 host、未知客户端，以及租户隔离查询。 |
| `management/service/ConnectionArchiveServiceTests` | 1 | 部分 | "connection archive failed"、"connection stats response mismatch" | 测试直接调用 `st_storage_archive_connections` 后查询统计。60 天保留窗口与定时调度没有测试；测试里 `month` 字段的值是日期 `2026-06-20`，而 Java 按月汇总。 |
| `management/service/ManagementUserServiceTests` | 11 | 部分 | "management user create response mismatch"、"management user update response mismatch"、"management user delete response mismatch"、"disabled database user login response mismatch"、`test_tenant_scoped_admin_mutations`（"PUT of another tenant's user"、"DELETE of another tenant's user"、"another tenant's user answered unlike a missing one"）、`storage_tests.c` "management user crossed its tenant" | 前 7 项是 OIDC 身份开通与绑定，C 不存在这项能力；不同租户同登录名在 C 也不存在（username 是全局主键），大小写不敏感旧登录的歧义因此无从出现。改删只在调用者租户内查找：其他租户的用户回 404 且与不存在的用户逐字节相同、数据库行不变（Java 对应 `mutationLookupsAreTenantScopedAndDoNotRevealForeignUsers`，Java 的状态码是 400）。 |
| `management/service/ManagementUserServiceIntegrationTests` | 6 | 部分 | "tenant scoped user create response mismatch"、"tenant scoped user login response mismatch"、`test_tenant_scoped_admin_mutations`（跨租户改/删/读与本租户改删） | `adminCannotReadResetOrDeleteUsersFromAnotherTenant` 与 `adminManagesUsersInsideOwnTenant` 有对应断言。C 不存在三项能力：OIDC 绑定、不同租户同登录名（C 的 username 是全局主键，跨租户同名创建得到 409）、按租户限定的登录/刷新。 |
| `management/service/UserDiagramDocumentServiceTests` | 4 | 部分 | "diagram create response mismatch"、"diagram detail response mismatch"、"diagram optimistic-lock response mismatch"、"diagram list response mismatch"、"diagram delete response mismatch" | 只在单个账号下测试，跨账号读不到对方文档没有测试。 |

## 6. 流量观测与管理事件

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `management/service/TrafficInspectionServiceTests` | 6 | 部分 | ctest `traffic_capture_tests`（`test_capture_switch_and_preview_size`、`test_java_preview_cases`、`test_text_sanitizing`、`test_body_types`、`test_store`）；`admin_http_tests.c` "HTTP detail captured with SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED unset"；`nat_stream_tests.c`：`check_tcp_capture_off_by_default`、`check_tcp_capture_enabled`（真实进程） | 有对应：通道开关与全局开关缺一不采（HTTP 与 TCP）、文本预览按预览长度截断（`01234567`/`response`）、gzip 先解码再生成预览而十六进制预览保留原字节、PNG 等二进制 body 不生成文本预览且类型为 `image`、TCP 帧全量保存、预览截为 4 字节、偏移与帧序号。补测时修正三处：全局开关 `SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED` 原先只影响状态接口，HTTP/TCP 照样采集；预览原先是前 1024 字节的小写十六进制和只保留 ASCII 的文本，现按 Java 的预览长度（默认 256）、大写空格分隔十六进制、UTF-8 文本；SQLite 侧 body 类型原先自成一套（`unknown`，html 归为 `text`），现与 `HttpBodyTypeClassifier` 一致。未对应：C 存预览不存 HTTP body，所以 Java 对 body 字节的断言、外置媒体不重复存 body 两项没有对应，`requestTruncated`/`responseTruncated` 在 C 表示预览短于 body；`br` 不解码；C 同步写库，没有待写队列与批量 flush。 |
| `management/storage/HttpTrafficExchangeStoreTests` | 3 | 部分 | `traffic_capture_tests.c:test_store`（SQLite 摘要不读表头与预览，详情按 id 读取且受租户与归属限制）；`elasticsearch_traffic_tests` 的 "Elasticsearch HTTP summary carried headers or previews"、"Elasticsearch HTTP detail lookup mismatch"；`admin_http_tests.c` "http exchange page response mismatch"（摘要 JSON 六个字段为 `null`）、"http exchange detail response mismatch" | 摘要不读取、不返回表头与预览，详情才返回，SQLite 与 ES 两侧都有断言。补测时修正：SQLite 列表原先读出并返回每行的表头与预览；详情接口原先翻列表找行，ES 模式下列表不带这些字段，详情也就没有。未对应：Java 详情里二进制 body 显示为 `data:<type>;base64,…`，C 不存 body，二进制 body 的文本预览为空。 |
| `management/storage/JpaHttpTrafficExchangeStoreIntegrationTests` | 1 | 无 | 相关：上行的 SQLite 摘要断言 | 平台差异：这是 JPA 仓库对真实数据库的集成测试，C 没有 JPA。它要求的“摘要不读大字段”在 C 由上行 `test_store` 对 SQLite 断言。 |
| `websocket/ConnectionEventsWebSocketHandlerTests` | 2 | 部分 | `admin_http_tests.c`（#132）：管理员收到本租户全部事件、普通用户只收到自己客户端的、其他租户收不到，普通 HTTP 426，缺/重用/错用 ticket 403 | C 不存在 Redis 集群扇出，跨实例部分不适用。 |

## 7. HTTP 媒体采集

均由 ctest `media_capture_tests` 经 `scripts/media_capture_test.sh` 对 fake S3 运行；没有接过真实 RustFS。

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `management/service/HttpMediaCaptureServiceTests` | 10 | 部分 | `media_capture_tests.c`："completed media capture database mismatch"、"first/second sparse media range capture failed"、"expired media capture cleanup mismatch" | 未测：无 Content-Length 的流、大文件 multipart、播放器取消后保留已收区间、跳过重复区间、部分区间重试、唯一键竞争、源 URL 去 token、提高保留期后延长。 |
| `management/service/HttpMediaManifestSupportTests` | 4 | 部分 | "rewritten HLS manifest response mismatch"、"public rewritten HLS manifest response mismatch" | 未测：媒体响应分类、DASH 模板 token、非法 Content-Range。 |
| `management/service/HttpMediaPlaybackServiceTests` | 8 | 部分 | "public media ranged playback mismatch"、"sparse media range stitching mismatch" | 未测：在首个未缓存字节处截断、起点落在空洞时拒绝、离线合并、后缀 Range、保留 Content-Encoding。 |
| `management/service/HttpMediaPlaybackTicketServiceTests` | 2 | 部分 | "sparse media playback ticket mismatch" | 未测：回源开关写入 ticket。 |
| `management/controller/PublicHttpMediaPlaybackResourceTests` | 5 | 部分 | "public media ranged playback mismatch" | 未测：Range 未命中不回退、开启回源时重定向、manifest 资源未采集时返回 `404` 或重定向。 |

## 8. Peer Mesh、Egress、STUN/TURN

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `management/controller/PeerEgressResourceTests` | 12 | 部分 | `admin_http_tests.c:test_peer_mesh_egress_policy_validation`："egress policy save did not store the normalised rules"、"a refused egress policy request changed what was stored"、"null domainRules did not keep the stored rules"、"egress policy for an unknown client was not 404"、"deleting a missing egress policy was not 404"；`peer_egress_tests.c:run_management_edges`、`run_domain_policy_edges` | 未测：非 admin 写入返回 `403`、Peer Mesh 关闭时启用策略。 |
| `management/service/PeerEgressServiceTests` | 20 | 部分 | `peer_egress_tests.c`（授权向量、规则向量、configValidation、跨语言 sweep）；`peer_mesh_tests.c:test_egress_catalog_domain_targets`、`test_egress_config_domain_rules`、`test_egress_catalog_egress_version`；`storage_tests.c:test_peer_egress_known_codes`、`test_peer_mesh_egress_activity_round_trip` | `egress-report` 的处理（`src/peer_mesh.c:pm_handle_egress_report`）没有测试，包括信封字段拒绝、上报限流和旧快照不覆盖新快照。 |
| `management/service/PeerMeshServiceTests` | 22 | 部分 | `peer_mesh_tests.c`："peer mesh virtual IP allocation mismatch"、"peer mesh candidate/session forwarding mismatch"、"peer mesh denied target was accepted"、"peer mesh traffic report mismatch"、"peer mesh close mismatch"；`admin_http_tests` 的 ACL 大小写与 "peer mesh stats response mismatch" | 未测：TURN 热路径上 relay frame 与 session 的绑定、复用缓存的 open session、standalone STUN 写入登录配置、过期流量报告关闭 session。 |
| `management/service/PeerServiceDiscoveryServiceTests` | 13 | 部分 | `peer_mesh_tests.c`："peer service catalog fanout mismatch"、"peer service report revision/envelope validation mismatch"、"peer service catalog withdrawal mismatch"、"peer service permission revocation refresh mismatch"、"peer service catalog expiry mismatch"；`admin_http_tests`："peer service sharing update mismatch"、"peer TCP service import mismatch" | 未测：上报速率与状态表有界、拒绝公网 target 和不安全路径、UDP 应用配 TCP 传输时拒绝。 |
| `management/service/PeerSignalServiceEnvelopeTests` | 3 | 部分 | "peer service report revision/envelope validation mismatch"（拒绝客户端自带 `sourceClientId`） | 未测：超大原始消息和反序列化后集合超限。 |
| `management/service/PeerSignalServiceLogoutTests` | 2 | 覆盖 | `peer_mesh_tests.c`："peer mesh logout push failed"、"peer mesh logout push reached the departed client"、"peer mesh logout did not tell the peer the device is offline"、"peer mesh logout announced a device that is still online" | — |
| `management/controller/PublicPeerMeshResourceTests` | 5 | 部分 | "disabled public stun config mismatch"、"disabled public fallback stun config mismatch"、"enabled public stun config mismatch"、"disabled public NAT probe config mismatch"、"RFC5780 public NAT probe config mismatch" | 未测 `stun-config` 的三项：standalone 优先、Peer Mesh 关闭时仍发布 standalone、standalone 配置不全时回退。 |
| `peer/TurnCredentialServiceTests` | 3 | 部分 | `stun_turn_tests.c`："TURN credential generation mismatch"、"TURN general relay allocation quota mismatch"；"temporary turn credential mismatch" | 未测：从 `pm-<clientId>` 解析 subject，以及未知 subject 的处理。 |
| `peer/StunTurnServerMetricsTests` | 2 | 部分 | `stun_turn_tests.c`：`test_default_private_peer_refusal`（不设开关：Java 用例中的每个 IPv4/IPv6 拒绝地址与 IPv4-mapped 形式经 CreatePermission 和 ChannelBind 都得 `403`，端口 0 拒绝，公网与 CGNAT `100.64/10`、`2001:db8::10` 放行，公网与私网混在一个 CreatePermission 里整体拒绝，被拒的 loopback 对端收不到 Send 与 ChannelData，身份不符 `437`）、`test_private_peers_allowed_by_switch`（开关为 true 时同样的地址放行，一个请求里的两个 loopback 对端都能收发） | 第一项（目的地址策略）有对应；IPv6 判定与默认开启的测试已在 #132 补上（`peer_address_allowed`）。本分支补测时修正两处：CreatePermission 原先只检查第一个 XOR-PEER-ADDRESS，公网在前、私网在后的请求得到成功（Java/Go 整体拒绝），现逐个检查后再安装全部许可；Refresh、CreatePermission、ChannelBind 原先不核对签名身份是否与 allocation 一致，通用中继凭据可以在策略豁免的 Peer Mesh allocation 上装许可、或把对方的 allocation 刷新掉，现按 Java `matchesClient` 回 `437`。拒绝时写与 Java/Go 相同的 `[peer-mesh][audit]` 日志。未对应：第二项的 relay 工作队列丢弃数与高水位指标，以及被拒目的地址计数，C 没有工作线程池和指标注册表。`SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS` 是 C 独有的开关，Java/Go/.NET 没有。 |

`stun_turn_tests` 另外覆盖 TURN Refresh、ChannelBind/ChannelData、438 Stale Nonce 与各类过期（#132），这些不对应单独的 Java 测试类。

## 9. 公共互传：发现、房间、附件

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `websocket/PublicTransferDiscoveryWebSocketHandlerTests` | 14 | 部分 | `admin_http_tests.c:test_public_discovery_websocket`："public discovery duplicate peer was not rejected"、"public discovery occupied name availability mismatch"、"public discovery merged-net roster mismatch"、"public discovery merged-net targeted route mismatch"、"public discovery room capacity was not enforced"、"public discovery viewer write was not rejected" | 未测：同网不同房间重复 peer、发给不可见 peer 的信令被丢弃、`unknown` 地址、广播限定在分组内、roster 过滤隐藏 peer、presence 刷新跳过隐藏参与者。 |
| `websocket/PublicTransferCoordinationRedisIT` | 2 | 部分 | ctest `public_coordination_tests`（单进程连真实 Redis）："registration policy mismatch"、"merged same-room/same-net roster mismatch"、"global name availability mismatch"、"distributed rate limit mismatch"、"refresh/unregister mismatch"；ctest `public_discovery_cluster_e2e`（两个 C 进程）；`java_c_discovery_interop.sh` | 未测：两个实例共享的限流、注销后 revision 严格递增、其它网段的 peer 查不到。管理事件扇出 C 不存在这项能力。 |
| `websocket/PublicTransferCoordinationServiceTests` | 4 | 部分 | 间接："merged same-room/same-net roster mismatch"、"public discovery different-address isolation mismatch" | 未测：netId/groupId 的 sha256 向量，以及空白地址和 `unknown` 不归入同网（`public_same_net` 只拒绝 `""` 和 `"unknown"`，不拒绝纯空白）。 |
| `websocket/PublicTransferClusterFrameTests` | 4 | 部分 | `public_coordination_tests` "STCE Pub/Sub event mismatch"；`public_discovery_cluster_e2e` | 没有 C 测试读取 `protocol/test-vectors/public-transfer-cluster-v2.json`。未测：解码时拒绝尾随字节、拒绝无目标的二进制帧。管理事件 C 不存在这项能力。 |
| `websocket/PublicTransferRelayFrameTests` | 2 | 部分 | "public discovery STWR2 relay mismatch"；`public_discovery_cluster_e2e` "cross-instance binary envelope mismatch" | 伪造来源和尾随应用字节的拒绝写在源码里（`public_route_binary`、`public_validate_stap2`），但没有测试。 |
| `websocket/WebSocketTicketServiceTests` | 1 | 部分 | "public discovery ticket reuse was not rejected"、"websocket ticket response mismatch" | 未测：scope 不符时拒绝，以及地址绑定（错配的尝试不消费 ticket）。 |
| `management/controller/PublicTransferRoomResourceTests` | 2 | 部分 | 房间响应的 `Cache-Control: no-store` 断言；兑换用 `st_admin_build_response_with_remote` 传入来源地址 | 未测：兑换接口忽略不可信 peer 的 `X-Forwarded-For`。通用解析器由 `client_address_tests` 覆盖。 |
| `management/service/PublicTransferRoomServiceTests` | 12 | 部分 | `admin_http_tests.c:test_public_room_access_contract`："public room access token create mismatch"、"public room persistent credential resolution mismatch"、"public room pairing redemption mismatch"、"public room exhausted pairing code was accepted"、"public room viewer diagram write was not rejected"、"public room access revoke mismatch"、"public room active invitation capacity mismatch"；`security_tests.c` "pairing-code HMAC vector mismatch" | 未测：邀请形状的未知 token 不得创建影子 OWNER 房间、过期邀请返回 forbidden、有效期限定在 5 分钟到 7 天、兑换得到的 token 有效期 24 小时、快照在持久化前解码。 |
| `management/repository/PublicTransferRoomPairingCodeRepositoryTests` | 1 | 覆盖 | "public room exhausted pairing code was accepted"；"public room atomic pairing code create mismatch" 及其后的双线程并发兑换（恰好一个成功） | — |
| `management/service/PublicTransferRateLimiterTests` | 1 | 覆盖 | "public room pairing redemption rate limit mismatch" | — |
| `management/service/TransferAttachmentServiceTests` | 19 | 部分 | `object_storage_tests.c`：`test_capabilities_*`、`test_expiration_cleanup`；`object_storage_e2e`（文件名归一、presign、HEAD complete 写回实际大小、一次性 grant、限流、下载计费） | 未测：房间 PENDING 配额、VIEWER 不能上传、账号存储额度、Unicode 文件名边界、id 冲突重试、PENDING 附件禁止下载、受邀 VIEWER 下载、月流量超额、complete 时对象缺失或超限要先删除再拒绝、callback 与 complete 的幂等。管理端附件路径只测了未配置时的 `409`。 |
| `management/service/TransferCapabilitiesVectorTests` | 1 | 覆盖 | `object_storage_tests.c:test_capabilities_shared_vector`（`protocol/test-vectors/transfer-capabilities-v1.json`） | — |
| `management/storage/object/AliyunOssObjectStorageServiceTests` | 3 | 部分 | `object_storage_tests.c:test_download_vector`、`test_upload_callback_header`；`object_storage_e2e` 的 `x-st-grant` | 未测：OSS callback 验签，包括公钥 URL 固定与缓存。 |

## 对照中发现的 C 行为差异

以下差异都在源码中逐处核实过。它们也是上表中若干“无”或“部分”的原因。原第 4–6 项（HTTP 流忽略 `DATA|END_STREAM`、未知流上的 DATA/FIN/RST 被静默丢弃、入站 `HEARTBEAT_RESPONSE` 被当作协议违规）已由 `fix/c-server-stream-semantics` 修正，并由 `nat_stream_tests` 覆盖。原第 7 项（TURN 私网 peer 策略放行全部 IPv6，且测试从未在策略开启时运行）已由 #132 修正；`fix/c-server-test-gaps` 又修正了同一策略只查第一个对端地址、以及不核对 allocation 身份两处，见第 8 节。

3. **OIDC 只代理 code 交换**：见第 1 节。C 管理 API 只接受本地 HS256 JWT，所以通过 OIDC 登录拿不到 C 管理 API 的访问权限。

`fix/c-server-test-gaps` 补测时发现并修正的其他差异（详见各行）：转发给设备前不改写 `Origin`/`Referer`/`Sec-Fetch-Site`（第 4 节）；Turnstile siteverify 返回非 JSON 时回 `400`、token 被原地改写（第 1 节）；SemVer 解析接受空标识符（第 5 节）；全局采集开关不起作用、预览格式与 body 类型和 Java 不同、摘要列表返回表头与预览（第 6 节）。
