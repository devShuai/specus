# tunnel-server C# 重写计划

## Context

`tunnel-server` 是这个项目里基于 Spring Boot + Netty 实现的 NAT 隧道服务端 — 5005 行 Java、65 个文件,功能涵盖:

- 自研二进制 wire protocol (`tunnel-common/protocol/PacketCodec`),NAT 控制通道 + 13 种命令包,默认 `CompactBinarySerializer` + 自动 deflate
- 控制通道默认监听 7010,每个注册隧道再开一个 TCP listener,把外部 TCP 流量转发到 client→上游
- 一条 HTTP "direct" 通道:server 收外部 HTTP→打包 `DIRECT_HTTP_REQUEST` 走控制通道→client 回 `DIRECT_HTTP_RESPONSE`
- Spring MVC 管理后台 (`/api/admin/*`),JPA + SQLite 七张表,WebSocket `/ws/connections` 实时广播
- 双 JWT 验证(本地 HS256 admin + OIDC RS256),OIDC token-exchange 反代,可选 TLS

需求:用 .NET 10 (Kestrel + System.IO.Pipelines + EF Core) 重写整个 server。Java tunnel-client / tunnel-common 保持不变,wire protocol 必须 byte-for-byte 兼容。

用户决定:
- **节奏**: 分阶段 PR 交付,每个 PR 可独立运行可联调
- **数据库**: 新代码不读老 SQLite — EF Core Migrations 重建 schema (字段名/列对齐 Java DTO 即可,不强求与 JPA 生成的 DDL 同型)
- **验证**: 每阶段写 .NET 集成测试,启动现有 Java tunnel-client 进程连 C# server 跑端到端
- **TLS**: 只支持 PKCS12 / PEM

## 项目布局

新建并行目录,Java 模块原地保留:

```
csharp/
├── ShuaiTunnel.sln
├── src/
│   ├── ShuaiTunnel.Protocol/          # tunnel-common 等价物 (codec + packets)
│   ├── ShuaiTunnel.Server/            # ASP.NET Core 主程序
│   └── ShuaiTunnel.Server.Data/       # EF Core DbContext + entities
└── tests/
    ├── ShuaiTunnel.Protocol.Tests/    # CompactBinary round-trip + 与 Java 字节级对照
    ├── ShuaiTunnel.Server.Tests/      # 单元测试
    └── ShuaiTunnel.IntegrationTests/  # Java client × C# server E2E
```

`tunnel-server/` Java 目录在 C# 版本完全验证通过、用户确认前不动。

## 阶段拆分

### Phase 1 — Wire Protocol + Codec 库 (`ShuaiTunnel.Protocol`)

**目标**: 拿到一份能跟 `tunnel-common/.../codec/PacketCodec.java` 字节级互通的 .NET 库,作为后续所有阶段的基石。

**核心实现**:

- 11 字节帧头:`MAGIC=0x14353565` + ver=1 + serializer + command + len(BE int32)
  - 参考: [PacketCodec.java](tunnel-common/src/main/java/com/theshuai/common/protocol/PacketCodec.java)、[Spliter.java](tunnel-common/src/main/java/com/theshuai/common/codec/Spliter.java)
- `CompactBinarySerializer` 完整移植(field codec 字典 + zigzag varint + 2 字节 type prefix + ≥64 B 自动 raw deflate)
  - 参考: [CompactBinarySerializer.java](tunnel-common/src/main/java/com/theshuai/common/serialize/impl/CompactBinarySerializer.java)
  - .NET: `System.IO.Compression.DeflateStream` (raw deflate, 与 Java `Deflater(nowrap=true)` 可互解；压缩器输出字节不作为跨运行时稳定契约)
- 13 种 packet record(11 个普通命令 + NAT_MESSAGE + DIRECT_HTTP)
- NAT_MESSAGE 特殊 body 布局:`int32 type | int32 metaLen | utf8 fastjson meta | bytes payload`,metadata 用 `System.Text.Json` (camelCase)
- HMAC-SHA256 签名:`message = clientName \n timestamp \n nonce`,key = `SHA256(plaintext password)` 的 32 raw bytes
  - 参考: [HmacSigner.java](tunnel-common/src/main/java/com/theshuai/common/security/HmacSigner.java)
- `IDuplexPipe` 上的帧读取器:在 `PipeReader` 之上做长度切分 → 解码 → 派发

**测试**(关键):
- `ShuaiTunnel.Protocol.Tests` 里写 fixture 测试 — 把 Java 端 (写一个一次性的 `main` 或临时测试用 Java 把每种 packet 编码后落到 `tests/fixtures/*.bin`) 产生的字节文件读进来,断言 .NET decoder 解出的对象与人手填的期望对象逐字段相等;反向 — 非压缩 case 要求 .NET 编出来的字节与 fixture 文件 SHA256 一致
- 每种 command 至少一个 fixture,NAT_MESSAGE 的 6 种 type 各一个,DATA 加一个 ≥64 B 触发 deflate 的 case；deflate case 断言 Java→.NET 解压 payload 一致、.NET 自编码可自解码,不要求压缩字节完全一致

**验收**: `dotnet test ShuaiTunnel.Protocol.Tests` 全绿。fixture 文件落盘进 git,后续阶段如果改了 codec 就立刻发现 regression。

### Phase 2 — 控制通道 + Auth + 持久化骨架 (`ShuaiTunnel.Server`)

**目标**: Java client 能连上 C# server、HMAC 登录成功、心跳维持,管理库表存在但接口先不开。

**核心实现**:

- ASP.NET Core minimal host,`IHostedService` 启动 Kestrel-style TCP listener (用 `SocketTransportFactory` + 自定义 `IConnectionListener`)
- 控制通道 pipeline 等价物:idle 检测 (60 s 读 / 30 s 写,见 [SocketIdleStateHandler.java](tunnel-common/src/main/java/com/theshuai/common/handler/SocketIdleStateHandler.java)) → 帧切分 → codec → 派发
- 配置类: `NettyServerOptions`、`AuthOptions` 等,`appsettings.json` 里 key 用 PascalCase (`Tunnel:Netty:Port`),env 变量映射支持 Java 风格 `TUNNEL_NETTY_PORT` / `TUNNEL_DB_SEED_DEMO_CLIENT` 以及 .NET 风格 `TUNNEL_Tunnel__Netty__Port`
- EF Core + SQLite:
  - DbContext + 7 个 entity (`ClientAccount`、`ConnectionRecord`、`TunnelMapping`、`HttpRouteMapping`、`TrafficUsage`、`ConnectionStat`)
  - 时间戳一律 `DateTimeOffset` 存 ISO-8601 TEXT(让字典序 = 时序),自定义 `ValueConverter` 控制格式
  - 用 EF Core Migrations 生成 schema(不要求与 JPA DDL 一致)
  - 参考 entity: [ClientAccount.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/model/ClientAccount.java) 等
- HMAC 登录处理(等价 [ManagedLoginRequestHandler.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/ManagedLoginRequestHandler.java)):
  - 限流: `tunnel_connection_record` COUNT 最近 1 分钟,默认 30/min,见 [ClientAccountService.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/ClientAccountService.java)
  - 验签 `±30_000ms` 时间窗 + `CryptographicOperations.FixedTimeEquals`
  - 写 `ConnectionRecord` placeholder、把 id 放进 `ConnectionContext.Items[CONNECTION_RECORD_ID]`
  - 登录线程池: `Channel<LoginTask>` + N 个 worker(对齐 [ServerExecutorConfig.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/config/ServerExecutorConfig.java) 的 8/32/20000),队满返回 `SERVER_BUSY`
- `SessionRegistry`:`ConcurrentDictionary<string, ClientSession>`,重复登录踢旧连接(`REPLACED_BY_NEW_LOGIN`),参考 [SessionUtil.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/session/SessionUtil.java)
- 心跳响应 + Logout

**测试**:
- `ShuaiTunnel.IntegrationTests`: `[Fact] async Task JavaClient_CanLoginAndHeartbeat()`
  - `Process.Start("java -jar tunnel-client.jar")`(参考 [EndToEndTunnelIT.java](tunnel-server/src/test/java/com/theshuai/tunnelserver/integration/EndToEndTunnelIT.java) 的启动方式;若直接起 jar 太重,从 [NettyClient.java](tunnel-client/src/main/java/com/theshuai/tunnelclient/client/NettyClient.java) 抽出最小 client 用作测试 fixture 也行)
  - 起 C# server 监 random port,用 EF Core 在 in-memory/temp file SQLite 上 seed 一个 client account
  - 等待 client 上报 ONLINE → 断言 `ConnectionRecord` 行 `success=true`

**验收**: 集成测试通过,Java client 在 C# server 上保持 60+ 秒心跳不断。

### Phase 3 — NAT TCP 转发 + 背压

**目标**: 注册一条 TCP 隧道、外部连接打通、双向流通过、断连干净。

**核心实现**:

- `RemotePortServerManager`(等价 [Java 同名](tunnel-server/src/main/java/com/theshuai/tunnelserver/server/RemotePortServerManager.java)):管理每客户端的 TCP listener,共享 socket transport
- `NatServerHandler` 等价物:接 `NAT_MESSAGE`,处理 REGISTER / DATA / DISCONNECTED / UNREGISTER / KEEPALIVE
  - 三层 admission:全局 / per-client / per-port,见 [NatServerHandler.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/NatServerHandler.java)
  - `externalChannels: ConcurrentDictionary<string, ExternalConnection>` 按 channelId 索引
- `RemoteTunnelHandler` 等价物([RemoteTunnelHandler.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/handler/RemoteTunnelHandler.java)):每个外部 TCP 连接的入站读循环,把字节切片打包 NAT_MESSAGE/DATA → 控制通道
- 背压:对 Pipelines `PauseWriterThreshold=64KiB / ResumeWriterThreshold=32KiB`,任一方写满时暂停另一方读循环,等价 [ChannelBackpressure.java](tunnel-common/src/main/java/com/theshuai/common/handler/ChannelBackpressure.java)
- TrafficUsageService:`ConcurrentDictionary<long, (long up, long down)>` in-memory,每 5 s `BackgroundService` flush 进 `tunnel_traffic_usage`(以 `Task.Delay` 模拟 fixed-delay 语义),参考 [TrafficUsageService.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/TrafficUsageService.java)
- `NatControlService` 登录后下发 MESSAGE_RESPONSE/NAT_CONTROL,让 Java client 在 Phase 3 就挂载 `NatClientHandler` 并发起 REGISTER；JSON 体严格按 [NatControlService.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/NatControlService.java) 的字段顺序和"未配 HTTP 路由就省略 `httpTunnelConfigList`"语义。Phase 4 再补 CRUD 后热更新 push

**测试**:
- E2E:Java client 注册一个隧道,本机起一个 mock TCP echo server 当上游,在测试里发 TCP 流量验证回环
- 背压用例:大文件方向阻塞下游,断言上游 read 暂停

**验收**: Java client 配一条 TCP 隧道指向本机 mock server,外部能连上、能传 1 MB 数据回环。

### Phase 4 — 管理 API + WebSocket + Direct HTTP

**目标**: SPA 全功能可用。

**核心实现**:

- 控制器(每个独立小文件,对齐 [management/controller/](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/controller/) 7 个 resource):
  - `OverviewResource`、`ClientResource`、`TunnelResource`、`HttpRouteResource`、`ConnectionResource`、`TrafficResource`、`AuthController`、`OidcController`
- `GlobalExceptionHandler` 等价 → ASP.NET Core middleware/`IExceptionHandler`(400/409/422 映射,见 [GlobalExceptionHandler.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/controller/GlobalExceptionHandler.java))
- 本地 admin JWT (`LocalTokenService` 等价):HS256, `iss=shuai-tunnel`, 8h TTL, `JwtBearerOptions` + 自写 `ISecurityTokenValidator` 路由 HS/RS
- `ConnectionEventBroadcaster`:用 EF Core `ISaveChangesInterceptor.SavedChangesAsync` hook,只在 commit 后把事件写进 `Channel<ConnectionEvent>`
- `/ws/connections`:`app.UseWebSockets()`,握手时从 query 读 `?token=`,用同一个 JwtBearer 校验,失败返回 403 + `X-Auth-Reason`
- Direct HTTP:`HttpTunnelController` 路由 `/http/{client}/{route}/{**rest}`,用 `ConcurrentDictionary<Guid, TaskCompletionSource<DirectHttpResponsePacket>>` + `WaitAsync(timeout)` 替代 [SyncFuture](tunnel-common/src/main/java/com/theshuai/common/future/SyncFuture.java)
- 静态资源:从 Java 项目复制 `static/index.html`、`app.js`、`app.css` 到 `csharp/src/ShuaiTunnel.Server/wwwroot/`,`UseStaticFiles` + `UseDefaultFiles`
- CSP / 安全头:中间件等价 [SecurityConfig.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/config/SecurityConfig.java)
- `ConnectionArchiveService`:每小时 `BackgroundService`,把 60 天前的 `ConnectionRecord` 聚合到 `ConnectionStat` 后删除,参考 [ConnectionArchiveService.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/service/ConnectionArchiveService.java)
- `NatControlService` push:管理 CRUD 后下发 MESSAGE_RESPONSE/NAT_CONTROL 热更新(登录后初始 push 已在 Phase 3 完成)

**测试**:
- 控制器单测覆盖每个 endpoint
- E2E:Java client 上线 → SPA(用 HttpClient 模拟)login → list clients 看到、ws 收到 created 事件 → 创建 tunnel → push 到 client → 实际可达

**验收**: 浏览器打开 `http://localhost:8088/`,完整 SPA 流程跑通。

### Phase 5 — OIDC + TLS

**目标**: 部署可选项(可后置,不挡 Phase 1-4 上线)。

**核心实现**:

- OIDC token exchange (`/oidc/token`):`HttpClient` 走 `tokenEndpoint`,confidential client 用 `Authorization: Basic`,public client 把 `client_id` 放表单。参考 [OidcController.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/management/controller/OidcController.java)
- `/oidc-config` 公开返回 `{configured, authorizationEndpoint, ...}`(`configured = !string.IsNullOrEmpty(ClientId)`)
- JwtBearer 多 scheme:HS256(本地)+ RS256(OIDC,`Authority`/`MetadataAddress` 走 `OidcOptions.JwkSetUri`),用 `ForwardDefaultSelector` 按 token header `alg` 路由
- TLS:`KestrelServerOptions.ConfigureEndpoint`(管理 HTTP)+ 控制通道用 `SslStream`,从 PKCS12 / PEM 加载,参考 [TlsContextFactory.java](tunnel-server/src/main/java/com/theshuai/tunnelserver/security/TlsContextFactory.java)
- Self-signed mode:进程启动时若配 `Tunnel:Tls:Mode=self-signed`,用 `CertificateRequest` 现场生成

**测试**:
- TLS:E2E 改用 self-signed 模式,Java client 跑 [EndToEndTunnelIT](tunnel-server/src/test/java/com/theshuai/tunnelserver/integration/EndToEndTunnelIT.java) 同款 trust-all SslContext
- OIDC:本地 `WireMock.Net` 模拟 IdP,断言 token-exchange 流程

**验收**: TLS 集成测试通过,OIDC 通过 mock IdP token-exchange 成功获取 admin token。

## 关键风险与应对

收录在审计报告 §7,迁移时挂在每个相关 PR 描述里:

1. **Netty `ByteBuf` 引用计数 → .NET Pipelines `ReadResult/AdvanceTo`**: 不引入手动 refcount,buffer 仅在 read 循环局部存在
2. **EventLoop 亲和性**: .NET 没等价语义,所有需要"投递到固定线程"的代码改为 channel 异步消息
3. **`@TransactionalEventListener(AFTER_COMMIT)`**: 用 EF Core `ISaveChangesInterceptor.SavedChangesAsync` 等价
4. **`@Scheduled fixedDelay`**: `BackgroundService` + `await Task.Delay`,不要用 `PeriodicTimer`(默认 fixedRate)
5. **ISO timestamp 字典序排序**: `DateTimeOffset` + `ValueConverter` 强制写入 `O` 格式 + Z offset,column collation 用 BINARY
6. **JPA `save()` upsert 语义 ≠ EF `Add/Update`**: 显式区分新增/更新,负责到 entity tracking
7. **Constant-time compare**: 全用 `CryptographicOperations.FixedTimeEquals`
8. **Compact binary 字段顺序**: 改包结构会破协议 — fixture 测试是底线

## 验证(总览)

每个 PR 都跑:

1. `dotnet build csharp/ShuaiTunnel.sln` — 无 warning/error
2. `dotnet test` — protocol fixture + 单测 + 集成测试全绿
3. 当前阶段对应的 Java client × C# server 集成测试场景跑通
4. Phase 4 起,启动 server (`dotnet run --project csharp/src/ShuaiTunnel.Server`),浏览器手动验:登录 → 列表 → 创建/编辑 tunnel → 看到 WS 事件
5. Phase 5 起,加测 self-signed TLS 与 OIDC mock

最终验收:Java tunnel-server 与 C# 版本可以互换部署,跑同一份 SPA、同一批 Java tunnel-client,行为等价。
