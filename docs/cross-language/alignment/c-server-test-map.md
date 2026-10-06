# 跨语言对齐：C server 测试对照

> 本文属于 [跨语言对齐](../cross-language-java-alignment-plan.md) 系列，为 Issue #35 验收项“Java 参考测试均有对应 C 单测/集成测试或书面平台差异说明”而写。

本文逐个列出 `implementations/java/server/src/test` 下的 Java server 测试类，说明 C server（`implementations/c/server`）里哪一项测试验证了同样的行为。没有对应测试时，写明原因：C 没有这项能力（平台或范围差异），或者能力在 C 源码里但没有测试。

清单按 2026-10-06 `docs/c-server-claims` 分支（已合入 `main` `5394a3b`）的源码树逐项核对，不是从既有文档转抄。

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

79 个 Java 测试类中，**覆盖 15 个，部分 46 个，无 18 个**（2026-10-06 随 C 认证修复与 #132 更新）。

审计点名的类目前的状态如下：

| Java 测试类 | 状态 | 一句话 |
| --- | --- | --- |
| `NatServerHandlerTests` | 无 | 6 项断言没有一项有 C 测试；其中两项 C 的行为与 Java 不同：未知流的 DATA/FIN/RST 被静默丢弃，HTTP 流的 `DATA\|END_STREAM` 也被忽略（见文末“对照中发现的 C 行为差异”） |
| `TcpServerHalfCloseTests` | 无 | 半关闭逻辑在 `src/main.c` 里，但没有任何测试或脚本对公网 socket 做 `shutdown(SHUT_WR)` |
| `HttpStreamExchangeTests` | 部分 | 只覆盖 trailer 字段的编解码和 E2E 正常路径；trailer 过滤、窗口上限、帧顺序都没有测试 |
| `HttpSpecusBodyLimitFilterTests` | 无 | C 对超过 16 MiB 的请求返回同样文案的 `413`，但不记录被拒请求，也没有测试 |
| `OidcControllerTests` | 无 | C 的 `/oidc/token` 只代理 code 交换：不校验 ID Token，不绑定本地用户，也不签发本地 token |
| `SecurityConfigOidcTests` | 无 | C 不接受外部 issuer 签发的 JWT，所以 issuer 校验在 C 不存在 |
| `ClientAuthNonceServiceTests`、`ClientAuthNonceServiceIntegrationTests`、`ClientAuthNonceRepositoryCustomImplTests` | 覆盖 / 部分 / 无 | C 已原子消费 nonce（`client_auth_nonce_tests`），但存储在进程内存，多实例不共享；仓库方言测试不适用 |
| `TrafficInspectionServiceTests` | 无 | C 只测了直接写入的明细能否查询；采集逻辑（默认关闭、gzip 解码、预览截断）没有测试 |
| `ConnectionEventsWebSocketHandlerTests` | 部分 | #132 补了真实 socket 的 created/updated 事件、租户与归属过滤、ticket 规则；C 没有集群扇出 |

全部 18 个“无”：`SpecusServerApplicationTests`、`SecurityConfigOidcTests`、`OidcControllerTests`、`GlobalExceptionHandlerTests`、`TurnstileVerifierTests`、`ClientDownloadSchemaMigratorTests`、`LegacyDemoCredentialSanitizerIntegrationTests`、`ManagementUserSchemaMigratorTests`、`ClientAuthNonceRepositoryCustomImplTests`、`NatServerHandlerTests`、`TcpServerHalfCloseTests`、`HttpSpecusBodyLimitFilterTests`、`UpstreamBrowserHeadersTests`、`SemanticVersionTests`、`TrafficInspectionServiceTests`、`HttpTrafficExchangeStoreTests`、`JpaHttpTrafficExchangeStoreIntegrationTests`、`StunTurnServerMetricsTests`。

## 1. 启动、认证与安全规则

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `SpecusServerApplicationTests` | 1 | 无 | — | Spring 上下文加载测试，C 没有对应结构。真实进程启动由 `session_lifecycle_tests` 和各 E2E 脚本间接覆盖。 |
| `config/SecurityBaselineValidatorTests` | 6 | 覆盖 | `tests/security_baseline_tests.c:main`（ctest `security_baseline_tests`） | 覆盖环境解析、同一组 11 个弱口令、prod 拒绝 JWT 占位值、演示数据开关。未断言两项：test 环境允许演示数据，prod 接受非占位 JWT secret。 |
| `config/SecurityConfigOidcTests` | 2 | 无 | — | C 不存在这项能力。`src/security.c:st_security_validate_local_token` 只接受 `alg=HS256`、`iss=specus` 的本地 token，没有外部 issuer、JWKS 或 RS256 验签。 |
| `management/controller/OidcControllerTests` | 4 | 无 | 只有代理部分有测试：`security_tests.c` "OIDC configured response mismatch"；"oidc http token exchange response mismatch"（明文 HTTP mock endpoint） | C 不存在这项能力。`/oidc/token` 原样返回 IdP 的 token，不校验 ID Token 的 nonce 和 audience，不解析或开通本地用户，也不签发 Specus token。见 [安全差异](security-differences.md)。 |
| `management/controller/AuthControllerRefreshTests` | 3 | 部分 | "refresh response mismatch"；`security_tests.c` "local token accepted wrong secret" | 刷新的正常路径有测试，C 也只接受本地 token。但 C 刷新时直接复制旧 token 里的 tenant/role（`handle_management_auth_refresh`），不回查数据库：已禁用、删除、降权的 SQLite 用户仍能刷新。 |
| `management/security/ManagementContextResolverTests` | 3 | 部分 | `admin_http_tests.c`：降级 admin 失去 admin 端点且续期为 USER、禁用用户请求 403/续期 401 且重新启用后恢复、删除与不存在的用户被拒、关闭密码登录后内置 admin 被拒 | 每个鉴权请求与 `/auth/refresh` 都按当前 SQLite 记录重新读取管理用户（只读、无缓存）。C 没有外部身份绑定，这部分不适用。 |
| `management/controller/GlobalExceptionHandlerTests` | 1 | 无 | — | 这是 Spring 的统一异常映射层，C 没有对应结构；C 各 handler 直接写错误 JSON。 |
| `security/ClientAddressResolverTests` | 11 | 覆盖 | `tests/client_address_tests.c:main`（逐用例 `expect_address`）：直连伪造、不可信 peer、可信代理、多跳、伪造前导跳、畸形跳、`X-Real-IP` 回退、IPv6、无效 CIDR 等 | — |
| `security/LoginRateLimiterTests` | 5 | 覆盖 | `tests/login_rate_limiter_tests.c:main`；"per-IP login rate limit response mismatch"、"per-account login rate limit response mismatch"、"successful login did not clear account rate-limit budget" | 未断言关闭限流后跳过计数。 |
| `security/PasswordServiceTests` | 7 | 覆盖 | `tests/password_hash_tests.c:main`（共享向量、低成本升级、旧 SHA-256 迁移、畸形哈希拒绝、错误口令）；"management user password was not stored with PBKDF2"、"legacy management user hash was not upgraded on login" | 未断言同一口令两次哈希的 salt 不同。 |
| `security/SecurityRulesTests` | 19 | 部分 | "unauthenticated admin api response mismatch"、"authenticated admin api response mismatch"、"database user client download admin-only response mismatch"、"oidc config response mismatch"、"invalid login response mismatch"、"http route authentication storage mismatch"；`object_storage_tests.c:test_capabilities_requires_authentication`；`object_storage_e2e`（匿名 capabilities `401`、grant 重放 `410`、`HEAD` `405`） | 以下规则在 C 没有测试：未知 grant 直接 `410`、OSS callback 匿名访问但签名无效时拒绝、外来 Bearer 不影响公开 HTTP 代理、ingress 不继承管理端 CSP、管理页 CSP 放行 GitHub API、云端流程图鉴权。 |
| `security/TurnstileVerifierTests` | 4 | 无 | 只有门禁本身有测试："turnstile-protected login accepted a missing token"（verifier 换成了测试替身 `test_registration_turnstile`） | `src/registration.c` 中 siteverify 响应的 action/hostname 校验，以及缺 key 时失败关闭，都没有测试。 |

## 2. 数据库迁移

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `database/ClientDownloadSchemaMigratorTests` | 1 | 无 | — | C 只给 `client_download_link` 补列（`src/storage.c`），没有 catalog/latest 唯一槽、旧数据去重和 `v1.2.3` 归一化；补列路径本身也没有测试。 |
| `database/LegacyDemoCredentialSanitizerIntegrationTests` | 4 | 无 | 相关但不等价：`security_baseline_tests` 断言未设置环境时禁止演示数据 | C 不存在这项能力，也不需要：C 从不写入公开的演示凭据，只在 dev/test 下创建一个没有 api key 的 `Demo client`。 |
| `database/ManagementUserSchemaMigratorTests` | 3 | 无 | — | C 不存在这项能力：`specus_management_user` 以全局 `username` 为主键，没有 login_name 列和租户内唯一索引。另外 C 只用 SQLite，MySQL/PostgreSQL 迁移不适用。 |
| `database/PeerServiceDiscoverySchemaMigratorTests` | 2 | 部分 | `storage_tests.c:test_peer_mesh_egress_domain_rules_migration`、`storage_tests.c:test_client_session_domain_targets_migration` | 未测：sharing/shared_service 表的默认值，以及给旧 session 表补 `peer_service_discovery_version`、`client_egress_version` 两列。 |
| `management/repository/ClientAuthNonceRepositoryCustomImplTests` | 3 | 无 | — | 平台差异：C 的 nonce 存储在进程内存（`client_auth_nonce.c`），没有 nonce 表，MySQL/PostgreSQL 方言不适用。 |

## 3. 控制连接、NAT 与端到端

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `handler/ConnectionRoleHandlerTests` | 2 | 部分 | `session_lifecycle_tests.c`：`expect_channel_alive`（control 与 data 的 HEARTBEAT 都有应答）、`test_second_login_on_one_connection_closes_it` | 以下角色错配逻辑写在 `src/main.c` 但没有测试：control 上收到 NAT 帧、data 上收到 MESSAGE_REQUEST、收到服务端响应包。 |
| `handler/NatServerHandlerTests` | 6 | 无 | — | Java 断言 6 项：KEEPALIVE 保持连接；未知流的 DATA/FIN 回 RST；从未打开的流收到 RST 时按协议违规断开；已关闭流迟到的 RST 被忽略；REGISTER 绑定失败时回 `success=false`；HTTP `DATA\|END_STREAM`。C 没有任何测试发送这些帧。其中两项与 Java 行为不同，见文末。 |
| `server/TcpServerHalfCloseTests` | 1 | 无 | — | 能力在源码里但没有测试：`external_conn_thread` 在公网 EOF 后发 FIN，待客户端 FIN 写完再 `shutdown(SHUT_WR)`。没有测试或脚本做公网侧半关闭。 |
| `integration/EndToEndSpecusIT` | 1 | 覆盖 | `scripts/runtime_config_e2e.sh`（API key 登录、在线投影、建 mapping 后经公网端口走 TCP、建/改 route 后经 NAT_CONTROL 热推并跑 Direct HTTP）、`scripts/nat_e2e_smoke.sh`、`scripts/direct_route_e2e.sh` | 由 CI 对 Java/Go/.NET 三个客户端各跑一次。 |

## 4. Direct HTTP / WebSocket

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `http/DecompressionLimitsTests` | 4 | 覆盖 | `tests/decompression_limits_tests.c`：`main`、`expect_round_trip`、`expect_bomb_rejected`、`expect_exact_allowance` | `limitFor(-1)` 在 C 不适用（参数是 `size_t`）。 |
| `http/HttpQueryStringCodecTests` | 2 | 部分 | "direct HTTP raw path or query brace encoding mismatch"；`nat_e2e_smoke.sh`、`runtime_config_e2e.sh` 的 `%7Bok%7D` | 未测：query 中的 `/`、`?` 原样保留，null 与空 query 的区分。 |
| `http/HttpRouteAuthenticationServiceTests` | 4 | 覆盖 | `admin_http_tests.c:test_direct_http_route_authentication`："protected route missing basic credentials mismatch"、"protected route invalid basic credentials mismatch"、"malformed protected route policy should fail closed"、"route auth database failure should fail closed"、"database-unmanaged environment route compatibility mismatch" | 未测的小分支：`Bearer` scheme、口令中含 `:`。 |
| `http/HttpSpecusBodyLimitFilterTests` | 3 | 无 | — | 能力部分在源码里：`src/admin_http.c` 对超过 16 MiB 的请求体返回 `413 HTTP 请求体超过限制`。但不写 HTTP 明细，且对整个管理监听生效、不限于 `/http/**`。没有测试发送超限请求体。 |
| `http/HttpSpecusControllerAuthenticationTests` | 8 | 部分 | `test_direct_http_route_authentication`："protected route successful auth or authorization stripping mismatch"、`route_auth_detail_is_sanitized` | 4 个 trailer 用例没有 C 测试。C 丢弃全部请求 trailers；响应 trailers 只检查 CR/LF，不按声明名和禁用字段过滤。 |
| `http/HttpStreamExchangeTests` | 5 | 部分 | `protocol_fixture_tests.c:test_nat_decode`（trailerNames、FIN trailers 编解码）；`direct_route_e2e.sh` 的 "GET (6 MiB)"、"GET (streamed)" | 以下检查写在 `process_direct_http_message` 但没有测试：先 OPEN 后 DATA 的顺序、窗口上限、FIN/RST 之后的帧。trailer 过滤 C 未实现。 |
| `http/HttpWebSocketRoutingTests` | 5 | 部分 | 路由认证测试的 `ws_calls`/`http_calls` 计数；`nat_e2e_smoke.sh` 的 WS `101`；"route runtime static asset path mismatch" | 未测：客户端离线时 `502 客户端不在线`、polyfill 正文内容。query 中裸 `\|` 返回 `400` 是 Tomcat 特有行为，C 不适用。 |
| `http/ResponseRewriterTests` | 2 | 部分 | "direct http html rewrite response mismatch"、"bounded gzip response rewrite mismatch"、"gzip decompression bomb was not safely passed through without rewrite" | 未测：协议相对 URL 和绝对 URL 保持不变。Java 在 Node 下运行 polyfill 的用例在 C 没有对应，C 只负责提供同一个静态文件。 |
| `http/UpstreamBrowserHeadersTests` | 3 | 无 | — | C 不存在这项能力：不改写 `Origin`、`Referer`、`Sec-Fetch-Site`。 |
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
| `management/service/SemanticVersionTests` | 2 | 无 | — | 能力在源码里但没有直接测试（`src/admin_http.c:parse_admin_semver/compare_admin_semver`），只经版本检查用例间接用到。 |
| `management/service/HttpRouteServiceTests` | 22 | 部分 | "http route create response mismatch"、"http route filtered list response mismatch"、"http route update response mismatch"、"http route delete response mismatch"、"HTTP media capture route create mismatch"、"http route missing authentication password was not rejected"、"blank http route auth password should retain the configured digest"、"http route authentication storage mismatch" | 未测：同客户端重复 route、空 route、含 `/`、超长 route、非 http target、target 缺 host、未知客户端，以及租户隔离查询。 |
| `management/service/ConnectionArchiveServiceTests` | 1 | 部分 | "connection archive failed"、"connection stats response mismatch" | 测试直接调用 `st_storage_archive_connections` 后查询统计。60 天保留窗口与定时调度没有测试；测试里 `month` 字段的值是日期 `2026-06-20`，而 Java 按月汇总。 |
| `management/service/ManagementUserServiceTests` | 11 | 部分 | "management user create response mismatch"、"management user update response mismatch"、"management user delete response mismatch"、"disabled database user login response mismatch"、`test_tenant_scoped_admin_mutations`（"PUT of another tenant's user"、"DELETE of another tenant's user"、"another tenant's user answered unlike a missing one"）、`storage_tests.c` "management user crossed its tenant" | 前 7 项是 OIDC 身份开通与绑定，C 不存在这项能力；不同租户同登录名在 C 也不存在（username 是全局主键），大小写不敏感旧登录的歧义因此无从出现。改删只在调用者租户内查找：其他租户的用户回 404 且与不存在的用户逐字节相同、数据库行不变（Java 对应 `mutationLookupsAreTenantScopedAndDoNotRevealForeignUsers`，Java 的状态码是 400）。 |
| `management/service/ManagementUserServiceIntegrationTests` | 6 | 部分 | "tenant scoped user create response mismatch"、"tenant scoped user login response mismatch"、`test_tenant_scoped_admin_mutations`（跨租户改/删/读与本租户改删） | `adminCannotReadResetOrDeleteUsersFromAnotherTenant` 与 `adminManagesUsersInsideOwnTenant` 有对应断言。C 不存在三项能力：OIDC 绑定、不同租户同登录名（C 的 username 是全局主键，跨租户同名创建得到 409）、按租户限定的登录/刷新。 |
| `management/service/UserDiagramDocumentServiceTests` | 4 | 部分 | "diagram create response mismatch"、"diagram detail response mismatch"、"diagram optimistic-lock response mismatch"、"diagram list response mismatch"、"diagram delete response mismatch" | 只在单个账号下测试，跨账号读不到对方文档没有测试。 |

## 6. 流量观测与管理事件

| Java 测试类 | @Test | 状态 | C 证据 | 说明 |
| --- | ---: | --- | --- | --- |
| `management/service/TrafficInspectionServiceTests` | 6 | 无 | 只有查询侧：明细先用 `st_storage_record_http_exchange`/`st_storage_record_tcp_frame` 直接写入，再由 "http exchange page response mismatch"、"tcp frame detail response mismatch" 查询；ES 侧见 `elasticsearch_traffic_tests` | Java 断言的是采集逻辑：通道默认不采集、gzip 先解码再存、二进制 body 不生成文本预览、外置媒体不重复存 body、TCP 全量保存但预览截短。C 的采集路径没有任何测试。 |
| `management/storage/HttpTrafficExchangeStoreTests` | 3 | 无 | 相关：上行的摘要查询 | 摘要查询不读取、不编码大字段和二进制 body，这一约束没有断言。 |
| `management/storage/JpaHttpTrafficExchangeStoreIntegrationTests` | 1 | 无 | — | JPA 专属；同一约束在 C 也没有断言。 |
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
| `peer/StunTurnServerMetricsTests` | 2 | 无 | — | 私网 peer 拒绝写在 `src/stun_turn.c:peer_address_allowed`，但 `stun_turn_tests` 设置了 `SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS=true`，从未经过这段代码；且 C 放行全部 IPv6。relay worker 队列与丢弃指标 C 不存在这项能力。 |

`stun_turn_tests` 另外覆盖 TURN Refresh、ChannelBind/ChannelData、438 Stale Nonce、默认的私网对端拒绝与各类过期（#132），这些不对应单独的 Java 测试类。

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

以下差异都在源码中逐处核实过，没有在本分支修改代码。它们也是上表中若干“无”或“部分”的原因。

3. **OIDC 只代理 code 交换**：见第 1 节。C 管理 API 只接受本地 HS256 JWT，所以通过 OIDC 登录拿不到 C 管理 API 的访问权限。
4. **HTTP 流的 `DATA|END_STREAM` 被忽略**：`src/main.c:process_direct_http_message` 不读 `ST_NAT_FLAG_END_STREAM`（TCP 和 WebSocket 路径会读），空的 `DATA|END_STREAM` 还会被判为非法。这与 [control-protocol.md](../../../protocol/spec/control-protocol.md) 中“`DATA|END_STREAM` 等同于 DATA 后再发 FIN”不一致。
5. **未知流上的 DATA/FIN/RST 被静默丢弃**：Java 对 DATA/FIN 回 RST，对从未打开过的流上的 RST 按协议违规断开。
6. **入站 `HEARTBEAT_RESPONSE` 按协议违规断开**：Java 在两种角色上都接受它。正常客户端不发送这个包。
7. **TURN 私网 peer 策略放行全部 IPv6**，而且测试从未在策略开启时运行。
