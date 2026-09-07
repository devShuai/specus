# 跨语言对齐：环境验证

> 本文是从 `cross-language-java-alignment-plan.md` 拆分出来的四篇之一。索引与拆分理由见 [该文件](../cross-language-java-alignment-plan.md)。

本篇记录实际跑过什么、以及哪些结论必须在真实环境里才能得到。源码自动化通过不能替代外部系统与硬件验证，这条边界写在这里，是为了让引用结论的人看得见它。

## 阶段 6：TLS、数据库和端到端验证

状态：源码主路径已完成，外部数据库与真实部署矩阵仍待验收。

- Java 是参考实现。
- Go server 支持控制通道与管理 HTTP TLS，`file` 模式已对齐 Java/.NET 的 PKCS12 / PFX keystore 读取；未配置 keystore 时仍兼容 PEM 证书和私钥文件。
- .NET server 支持 EF Core 多库和 TLS 配置；管理用户、流量明细、总流量租户字段、Peer Mesh、`transfer_attachment`、房间/流程图、HTTP 媒体采集、session 消息能力与 ACL direction 均已补齐 SQLite/MySQL/PostgreSQL provider-specific migration，并保留启动时幂等 SQL 兼容历史库。
- Java、Go、.NET server 的启动登录响应统一返回 `nettyTls`；Java、Go、.NET、Android 四种客户端在未显式覆盖时跟随该信号，并统一支持 PEM CA、证书主机名覆盖、系统信任与仅开发使用的跳过校验。管理 HTTPS 不再被误当成 control/data 原始 TCP TLS。
- C server 的源码能力已覆盖 control/data TLS、严格 HTTPS OIDC、密码/邮件验证注册、Direct HTTP/WS/SWS2、客户端消息、Redis 多实例 discovery、持久房间/流程图、S3-compatible/Aliyun OSS 附件、HTTP 媒体采集、可选 Elasticsearch 明细、托管客户端包/GitHub fallback，以及 Peer Mesh roster/session/service signalling 与内置 RFC 5389/5780 STUN、RFC 5766 TURN relay。管理、对象、媒体和 Peer Mesh 路径共享 SQLite tenant/owner/client/session 身份与失败关闭策略；定时维护会清理注册验证码、对象下载授权/过期附件、媒体对象/分片和 Peer Mesh session/catalog/relay lease。TLS 1.2+ 支持 PKCS#12/PEM，prod 拒绝自签和公网明文监听；HTTPS/OIDC/GitHub/对象存储请求默认验证证书链和主机名。

## 当前验证（2026-08-28）

- Java：`mvn -pl implementations/java/server -am -Dspecus.server.web.skip=true test` 全量通过；common `32/32`、client `69/69`、server `228/228`，合计 `329/329`。覆盖 control/data 角色、严格 RST/tombstone、TCP half-close、HTTP `DATA|END_STREAM`/trailers、SWS2 close 生命周期、frame-preserving upstream 控制帧、客户端 TLS，以及 OIDC issuer/audience/azp/nonce、本地身份绑定和当前权限重解析。
- Go：server 执行 `go test ./... -count=1`、`go vet ./...`、`go mod tidy -diff`、全量 `gofmt` 与差异检查通过；client 执行 `go test ./...` 通过。覆盖 v2 控制协议、SPM2/SPMTU2、TURN、HTTP/NAT stream、原始 WebSocket/SWS2、control/data TLS、公共互传 Redis 协调、管理事件 Hub、OIDC 本地身份绑定与有界 JWKS 轮换。
- .NET：server protocol `45/45`、server integration 在最终源码上连续两遍 `241/241`、client `155/155` 全部通过；server/client solution build 均为 0 warning、0 error，SQLite/PostgreSQL/MySQL 三套 EF model `3/3` 无待生成变更。覆盖 strict stream state、TCP half-close、HTTP `DATA|END_STREAM`、大请求流式 trailers、原始 RFC 6455/SWS2 控制帧、control/data TLS、持久化互传房间角色与附件授权、HTTP 媒体采集/离线回放、OIDC 本地身份绑定与有界 JWKS 轮换。
- Android：`gradlew test assembleDebug lintDebug --no-daemon --no-problems-report` 通过，14 个 suite、`121/121`；`assembleDebug` 与 `lintDebug` 均成功（Lint 0 error）。覆盖 v2 控制帧、runtime-session 重连、严格 TCP half-close、pending/tombstone、round-robin stream credit、FIN/RST 竞态、HTTP early response/带 body GET/双向 trailers、WebSocket 16 MiB frame 规范化与 pre-start 取消、真实测试 CA/hostname TLS、SPM2/SPMTU2、严格 UDP probe、全 A/AAAA、端口预测、端口映射 stop 竞态、UPnP/NAT-PMP/PCP、TURN、STMSG2 和地址族逻辑。该结果不替代真机 VPN、生产证书与跨 NAT 双机验收。
- 管理前端：`npm test -- --run` 为 30 个文件、`191/191` 项通过，`npm run build` 通过。
- C server：在宿主机 `Ubuntu-24.04` WSL 的全新临时目录执行 Release CMake configure/build，附加 `-Wall -Wextra -Wpedantic -Werror`，CTest `22/22` 通过；同一最终源码的严格 `make -C implementations/c/server test` 通过。覆盖 admin、GitHub release、client address、crypto、decompression、Elasticsearch、JSON、HTTP client、登录限流、对象存储单元/真实 S3-compatible E2E、媒体采集、密码哈希、Peer Mesh、公共协调/双进程 Redis discovery、协议、安全基线、SQLite、STUN/TURN 与 TLS。`java_c_discovery_interop.sh` 使用 Java reference server 与 C server 共享 Redis，roster、全局名称占用和双向定向信令通过；`nat_e2e_smoke.sh` 使用 Windows JDK 21 Java client 完成 control/data、TCP 小包/1 MiB/重连、Direct HTTP 与 WebSocket/SWS2；`runtime_config_e2e.sh` 完成 SQLite 客户端在线投影、mapping/route 创建/删除/重建与无重连热更新。三条脚本最终均返回 0。
- C server 的 `protocol-v2` Ubuntu job 已配置 OpenSSL/libcurl/hiredis/utf8proc/Redis 依赖、CMake/CTest、Java reference server/client 构建、C↔Java Redis discovery 混部和上述两套 Java client E2E；该 workflow 修改尚未合入运行，因此这里只记录“门禁已配置”，不记录为 GitHub Actions 已通过。
- C server 另在全新临时目录以 AddressSanitizer + UBSan、`-Werror` 构建并执行同一套 CTest；对使用 `stdbuf` 的对象存储脚本设置 `verify_asan_link_order=0` 后，开启 leak detector 的 `22/22` 单次全绿，未报告内存泄漏或未定义行为错误。该轮同时发现并修复 `realpath` 在非优化严格 C11 下缺少 X/Open 声明的可移植性问题。
- 仍需环境验收：真实 MySQL/PostgreSQL、真实私有 OSS/ES、Windows/Linux/macOS/Android 双机、跨 NAT direct/relay fallback、长时间压力与真实 TLS/OIDC。源码自动化通过不能替代这些外部系统与硬件验证。

## 当前仍存在的不一致与环境门禁

- Go 标准库不暴露逐 listener backlog，也没有与 Netty event-loop 一一对应的 worker thread 数；对应配置保持 Java 兼容，实际 backlog 使用操作系统 `somaxconn`，连接并发由 goroutine 调度。功能与安全门禁已对齐，但调优旋钮不是同构实现。
- .NET 的内存 TestServer/TestHost 不提供生产 Kestrel 使用的原始 HTTP Upgrade feature；生产路径使用自实现 RFC 6455 transport，控制帧与边界由低层确定性测试覆盖，仍需在部署环境补 Kestrel 端到端 Upgrade 验收。
- Android 已补真实测试 CA/hostname TLS 握手；生产 CA、L4 TLS 终止与多平台证书存储仍需环境验收。
- 真实 MySQL/PostgreSQL、RustFS/OSS/Elasticsearch、跨 NAT direct/relay、真机 VPN/TUN 和长时间压力仍属于发布验收，不作为源码单测通过的替代结论。
- C server 本轮计划内源码能力与本地可构造门禁已完成；剩余项是发布环境矩阵，而不是把已实现能力重新记为源码缺口：真实私有 OSS/Elasticsearch、Go/.NET client × C server、Go/.NET server 与 C 的 Redis 混部、跨 NAT direct/relay、长时间/多客户端压力和真实 TLS/OIDC。Java/C Redis discovery 已通过，但在这些外部门禁完成前仍不能并入 Java/Go/.NET 的完整互换与生产替换结论。

## 此前轮次历史验证记录（已被上节替代，仅供追溯）

- Go server：历史记录显示 `go test ./...` 曾通过；本轮实际补充命令为 `GOCACHE=.gocache go test ./internal/peermesh ./internal/store ./internal/management`，只复核 Peer Mesh、store 和 management 三个 package。控制通道/外部 socket 背压、配置映射、协议 fixtures、登录/NAT/Direct HTTP、WebSocket、OIDC 与 TLS 等测试位于其它 package，不应归入这条定向命令的本轮覆盖；需要当前全量结论时应另行执行并记录 `go test ./...`。
- Go client：本轮在 `implementations/go/client` 重新执行 `go build ./...` 与 `go test ./...` 通过（覆盖 per-peer OS 路由同步、虚拟包目标过滤与 roster 清空重建改动后的回归），并执行 `GOOS=linux GOARCH=amd64 go test -c ./internal/client`、`GOOS=darwin GOARCH=arm64 go test -c ./internal/client`、`GOOS=darwin GOARCH=amd64 go test -c ./internal/client` 覆盖 Linux TUN 与 macOS utun 路由同步的 build tag 编译；包含启动配置 http/https `serverBaseUrl` 校验、CompactBinary UUID 非 canonical 大小写保真、空 UUID 按 Java 语义保留为普通字符串 marker、nil / empty byte array 与 string list marker 区分、`clientSessionId=0L` 按 Java 语义保留为非空 long marker、`DirectHTTPResponse.error` null / empty string marker 区分、Direct HTTP 自签 HTTPS upstream、8 MiB Range 裁剪、双斜线 `relativePath` 保留、编码 `..` 段拒绝、请求体/响应体超限与 route/path 错误的 Java 中文文案、`MessageResponse + PEER_CONTROL` 解码、`NAT_CONTROL.httpSpecusConfigList` 缺省保留 / 空数组清空 / 有值替换三态语义、NAT metadata 字符串 `toString` / 整数数字字符串容错、HTTP route WebSocket target 双斜线路径保留 / target 构造错误 Java 中文文案 / 握手头过滤 / 本地 text frame 转 NAT `DATA source=ws`、普通 TCP `OPEN` 无效端口/元数据忽略语义、`LOGOUT_REQUEST` 关闭控制连接、Java 风格重连指数退避、控制登录失败分类、5 秒心跳 / 60 秒读空闲、Java NAT 枚举值、`changed-port` 分类、relay candidate / alternate NAT probe 节流、relay allocation 优先发送、健康 direct 不被 relay probe 抢占、`SYMMETRIC_NAT` 下仍尝试 direct candidate、pending virtual packet 队列、noop 虚拟设备 ICMP echo 应用层响应、X25519/HKDF/AES-GCM frame、raw/DER public key 兼容、replay window、public STUN candidate 生命周期、运行时 token 主动刷新和内置 Wintun 资源解压相关编译覆盖；历史交叉编译命令 `GOOS=linux GOARCH=amd64 go test -c ./internal/client`、`GOOS=darwin GOARCH=arm64 go test -c ./internal/client`、`GOOS=darwin GOARCH=amd64 go test -c ./internal/client` 用于覆盖 Linux TUN 与 macOS utun build tag。
- .NET server：本轮执行 `dotnet build implementations\csharp\server\src\Specus.Server\Specus.Server.csproj --no-restore -p:SpecusServerWebSkip=true -v minimal` 通过；`dotnet test implementations\csharp\server\tests\Specus.IntegrationTests\Specus.IntegrationTests.csproj --no-restore -p:SpecusServerWebSkip=true -v minimal --filter "FullyQualifiedName~StunTurnServerTests"` 通过，覆盖标准 STUN/TURN allocation 过期重建、Refresh error、CreatePermission、Send Indication 和 Data Indication；`dotnet test implementations\csharp\server\tests\Specus.IntegrationTests\Specus.IntegrationTests.csproj --no-restore -p:SpecusServerWebSkip=true -v minimal --filter "FullyQualifiedName~PeerMeshServiceTests"` 通过，当前源码包含 9 个用例，覆盖 peer session 授权、关闭、roster 刷新、relay frame 授权、有效路径判定和 `/api/admin/peer-mesh/stats` 同口径聚合。AdminApiTests 在当前环境因测试配置里的 PostgreSQL connection string 不完整报 `Couldn't set data source`，未作为本轮回归结论。
- .NET client / protocol：该历史轮次执行 `dotnet build implementations\csharp\client\src\Specus.Client\Specus.Client.csproj -v minimal` 通过；`dotnet test implementations\csharp\client\tests\Specus.Client.Tests\Specus.Client.Tests.csproj` 当时通过 69 个用例（覆盖 per-peer OS 路由同步、虚拟包目标过滤与 roster 清空重建改动后的回归），包含标准 STUN/TURN Binding、Allocate、Refresh、CreatePermission、Send Indication、relay candidate / alternate NAT probe 节流、relay allocation 优先发送、健康 direct 不被 relay probe 抢占、pending virtual packet 队列、Peer Mesh frame/replay/key 派生、IPv4 packet 解析、noop 虚拟设备 ICMP echo 应用层响应、macOS utun 路由 CIDR 计算与运行时 token 主动刷新编译覆盖；protocol 测试沿用当时通过结论。当前结果以上节为准。
- C server：历史轮次因 Windows 本机没有 `make` / C 编译器而未能执行 POSIX suite；2026-08-27 起改由 `Ubuntu-24.04` WSL 实际运行。该历史缺口已被上节的严格 Make、Release/ASan CTest 22/22、Java client NAT/runtime E2E 和 Java/C Redis discovery 混部门禁替代。
