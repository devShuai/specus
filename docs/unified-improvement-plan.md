# 统一改进计划（5 Sprint）

> 目标：在「服务端性能 / 管理界面清晰度 / peer 直连成功率」三条线上分阶段落地改造，每轮 Sprint 独立可编译、可部署、可回滚。
>
> 本文件是执行口径与进度跟踪文档，代码改造在各自 Sprint 里完成，本文件只记录范围、落点、验收口径与进度。

## 0. 背景与口径

三条线来自三份独立评审：

1. **服务端性能**：数据面 hot path 每帧分配、流量落库走 select-then-save、`TrafficInspectionService.flush` 单锁串行。
2. **管理界面清晰度**：导航分组混乱、`TrafficPanel` 单页承载 HTTP+TCP+搜索过于密集、空状态缺失、页头菜单扁平。
3. **peer 直连成功率**：复杂 NAT 网络下 direct 候选打洞成功率低，原因是候选收集不全、无端口映射、对称 NAT 被一票否决、无保活、探针不够鲁棒。

约束：

- 客户端改造必须 **零协议变更、向后兼容**，老服务端与新客户端要能互通。
- 服务端改造不破坏现有 API 契约，Dialect 适配 Postgres / MySQL / SQLite 三套。
- 前端改造不引入新 UI 框架，基于现有 HeroUI + Tailwind。

## 1. Sprint 总览

| Sprint | 主题 | 工期 | 状态 |
|--------|------|------|------|
| Sprint 0 | peer 直连快速收益（客户端 only） | 1 天 | ✅ 已完成并推送 |
| Sprint 1 | 服务端 hot path + 流量持久化 | 2 天 | 🚧 进行中 |
| Sprint 2 | 导航重组 + 流量面板拆分 + 空状态 | 4 天 | ⏳ 待启动 |
| Sprint 3 | 私有组网面板重构 + 客户端详情抽屉 + 双向同时打洞 | 4 天 | ⏳ 待启动 |
| Sprint 4 | RTT 感知选路 + TCP 采样 + 日志降级 + ACL 方向性 + 窄屏 SVG | 3 天 | ⏳ 待启动 |

---

## 2. Sprint 0 — peer 直连快速收益（已完成）

> 提交：`9aa6da2`（显式 NAT 端口映射）+ `d9dd9d2`（S0.1–S0.4 直连改进）
>
> 全部客户端 only，零协议变更，向后兼容。

### S0.0 显式 NAT 端口映射（UPnP / NAT-PMP / PCP）

- 新增包 `com.theshuai.tunnelclient.peer.portmap`，9 个文件：
  - `PortMappingProtocol` / `NatPortMapping` / `NatPortMapper` / `PortMappingException`
  - `DefaultGatewayDiscovery`：UDP connect 探测 1.1.1.1 / 223.5.5.5，取 /24 的 .1 与 .254 作为候选网关
  - `UpnpPortMapper`：weupnp 0.1.4 封装，`GatewayDiscover.discover()`，端口映射带试错回退
  - `NatPmpPortMapper`：RFC 6886 裸实现，UDP 5351，12 字节请求 / 16 字节响应
  - `PcpPortMapper`：RFC 6887 裸实现，UDP 5351，60 字节帧，12 字节 nonce，IPv4-mapped IPv6 客户端 IP
  - `NatPortMappingService`：3 个 mapper 并发，4s 整体超时，先成功者胜，含续期 / 释放
- 依赖：`implementations/java/client/pom.xml` 增加 `weupnp 0.1.4`（Apache 2.0，零运行时依赖）

### S0.1 解除对称 NAT 一票否决

- `PeerMeshClient.shouldAvoidDirectPath()` 恒返回 `false`（原为 `"SYMMETRIC_NAT".equalsIgnoreCase(natType)`）
- 理由：对称 NAT 仍可能存在端口映射或 lucky punch，一票否决过于保守

### S0.2 host 候选补齐 IPv6 与 ULA

- `gatherHostCandidates()` 去掉 `!(address instanceof Inet4Array)` 过滤
- 新增 IPv6 ULA（`fc00::/7`）与 IPv4-compatible 过滤
- 移除 `Inet4Address` import

### S0.3 直连探针突发

- `sendUdpProbe()` 对 direct 候选发送 3 包突发（`PROBE_BURST_COUNT=3`，`PROBE_BURST_INTERVAL_MILLIS=30`）
- `scheduleProbeBurst()` 用 `maintenanceExecutor` 调度，relay 候选不突发

### S0.4 直连保活独立周期

- `keepaliveDirectPaths()` 由独立 5s `scheduleAtFixedRate` 调度，`sendDirectKeepalive()` 发单包
- `PeerSession.lastDirectKeepaliveMillis` 字段，在两处 state-transfer 块里传播

### 验收

- 客户端能单独编译、单独部署，与现有服务端互通
- 端口映射在支持 UPnP/NAT-PMP/PCP 的网关上能拿到外网映射
- 直连探针突发与保活不引入额外 CPU 峰值

---

## 3. Sprint 1 — 服务端 hot path + 流量持久化（进行中）

> 落点文件：
> - `handler/ChannelAttributes.java`（新增）
> - `handler/RemoteTunnelHandler.java`
> - `handler/NatServerHandler.java`
> - `management/service/TrafficUsageService.java`
> - `management/service/ClientAccountService.java`
> - `management/service/TrafficInspectionService.java`（S1.4）

### S1.1 Channel.attr 缓存 channelId + 静态 listener + 减少每帧分配 ✅

- 新增 `ChannelAttributes`：
  - `AttributeKey`：`CHANNEL_ID` / `REMOTE_ENDPOINT` / `LOCAL_ENDPOINT`
  - `initHotPath(Channel)`：channelActive 时一次性算好 `asLongText()` 与 endpoint 字符串
  - `channelId / remoteEndpoint / localEndpoint`：读 attr，未初始化 fallback 现算（不缓存）
  - `CLOSE_ON_FAILURE`：静态 `ChannelFutureListener` 单例，替代每帧 lambda
  - `closeOnFailureOf(Channel)`：channel-scoped listener 工厂，listener 实例缓存到 attr
  - `EndpointSnapshot` record（address, port）+ `of(SocketAddress)` 工厂
- `RemoteTunnelHandler`：channelActive 调 `initHotPath`，channelRead/channelInactive 用缓存 channelId + EndpointSnapshot，HashMap 容量预算（4/2/2, loadFactor 0.75f）
- `NatServerHandler.processData`：用 `ChannelAttributes.localEndpoint/remoteEndpoint/channelId` 替代 `endpointAddress/endpointPort`

验收：编译通过，转发链路无回归。

### S1.2 TrafficUsage UPSERT（Postgres / MySQL / SQLite 方言）✅

- `TrafficUsageService` 注入 `JdbcTemplate` + `DataSource`，`@Slf4j`
- `@PostConstruct detectDialect()`：`Connection.getMetaData().getDatabaseProductName()` 识别
- 常量：`DIALECT_POSTGRES / MYSQL / SQLITE / UNKNOWN`
- `upsertTrafficUsage()`：Postgres/SQLite 走 `ON CONFLICT (client_id, usage_date)`，MySQL 走 `ON DUPLICATE KEY UPDATE`
- `upsertResourceTrafficUsage()`：Postgres/SQLite 走 `ON CONFLICT (tenant_id, client_id, resource_type, resource_key, usage_date)`，MySQL 走 `ON DUPLICATE KEY UPDATE`
- `flushCounter / flushResourceCounter`：先 UPSERT，失败 fallback JPA find-then-save

验收：三方言下 `client_account` 与 `resource_traffic_usage` 表能正确 upsert，不出现重复行。

### S1.3 ResourceCounterKey 零分配 + ClientAccount 缓存 ✅

- **ClientAccount TTL 缓存** ✅：
  - `CachedClient` record（account, expiresAtMillis），`NAME_CACHE_TTL_MILLIS = 60_000`
  - `nameCache` ConcurrentHashMap，`findClientByName` 先查缓存再回库
  - `invalidateNameCache(String)`，在 5 个变更点调用（2 create / 1 update / 2 delete）
- **ResourceCounterKey 零分配** ✅：
  - 原 `Map<ResourceCounterKey, TrafficCounter>` 每次 record 都 `new` 一个三字段 record 做 lookup
  - 改两级 `Map<clientName, Map<resourceKey, TrafficCounter>>`：外层 key 复用调用方 `clientName`，内层 key 复用 `tcpKey/httpKey` 已拼好的 `resourceKey`（前缀 `tcp:`/`http:` 天然不冲突）
  - 删除 `ResourceCounterKey` record，新增 `inferResourceType(resourceKey)` 在 flush 时反推类型

验收：`ClientAccountService` 与 `TrafficUsageService` 编译通过；recordResource* 不再分配 record。

### S1.4 TrafficInspection flush 拆分 + 去 synchronized ✅

- 原状：`TrafficInspectionService.flush` 单方法 + `synchronized`，HTTP 与 TCP 共用一把 monitor 锁
- 拆为 `flushHttp()` 与 `flushTcp()` 两个独立 `@Scheduled @Transactional` 公开方法，各自调 `flushHttpInternal`/`flushTcpInternal`
- 保留无注解 `flush()` 给 `flushBeforeShutdown()` 与单测调用
- `drain` 走 `ConcurrentLinkedQueue.poll()` + `AtomicInteger.decrementAndGet()`，天然线程安全，去掉 `synchronized`
- `application.yml` 设 `spring.task.scheduling.pool.size=2`，让两条 flush 路径真正并发，TCP 落库慢不再阻塞 HTTP

验收：`TrafficInspectionServiceTests`（5 用例）全绿；HTTP 与 TCP 落库互不阻塞。

### Sprint 1 收尾 ✅

- 全量编译通过；测试 40 项，2 项 `PeerMeshServiceTests` 失败为并行 peer-mesh 工作遗留（非 Sprint 1 引入），Sprint 1 相关测试全绿
- 提交：`6ec2a1b`（含并行会话的流量捕获/peer-mesh WIP，按用户要求一并提交）
- 部署到 ali2

---

## 4. Sprint 2 — 导航重组 + 流量面板拆分 + 空状态（待启动）

> 落点：`apps/admin-web/src/pages/Dashboard.tsx`、`pages/panels/TrafficPanel.tsx`、空状态组件、页头菜单

### S2.1 侧边导航分组

- 现状：所有面板平铺，找功能靠肉眼
- 按「概览 / 接入 / 流量 / 组网 / 系统」分组，组内按使用频率排序
- 活动态面板（如正在跑的 peer 会话）给角标

### S2.2 TrafficPanel 拆分

- 现状：HTTP 路由 + TCP 帧 + 搜索控件挤在一页，窄屏搜索字段排列错乱
- 拆为 `HttpTrafficTab` / `TcpTrafficTab`，共享搜索 bar 抽到子 tab 内
- 搜索控件在窄屏折叠为单行 + 展开按钮

### S2.3 空状态与引导

- 无客户端、无流量、无 peer 会话时给插画 + 引导按钮（「新增客户端」「查看帮助」）
- 帮助链接沿用 hash tab（与 `HelpPanel` 对齐）

### S2.4 页头菜单

- 现状：页头菜单扁平，主题切换、文档、登出散落
- 收敛为右上角下拉，主题切换放显眼位

验收：窄屏（375px）下流量页搜索不溢出；空状态有引导；导航分组清晰。

---

## 5. Sprint 3 — 私有组网面板重构 + 客户端详情抽屉 + 双向同时打洞（待启动）

> 落点：`PeerMeshPanel.tsx`、客户端详情抽屉（新）、`PeerMeshClient.java` 打洞逻辑

### S3.1 PeerMesh 面板重构

- 现状：会话列表 + 详情 + NAT 文档混在一页，信息密度高
- 列表 / 详情分栏，NAT 文档已在 S0 前移入 `HelpPanel`，面板只留类型 chip + 跳转
- 会话行展示：peer 对、路径类型（direct/relay）、RTT、last keepalive

### S3.2 客户端详情抽屉

- 右侧抽屉展示单个客户端：基本信息、在线状态、流量、peer 会话、端口映射状态
- 抽屉内可触发「强制续期端口映射」「重试打洞」

### S3.3 双向同时打洞（simultaneous bidirectional hole-punching）

- 现状：探针是单端发起，对侧被动响应
- 两端同时在 direct 候选上发探针，提高 NAT 映射对齐概率
- 需要与现有探针突发（S0.3）协调，避免探针风暴

验收：peer 直连成功率在复 NAT 网络下提升；面板信息密度下降；抽屉可触发运维动作。

---

## 6. Sprint 4 — RTT 感知选路 + TCP 采样 + 日志降级 + ACL 方向性 + 窄屏 SVG（待启动）

### S4.1 RTT 感知路径选择

- 收集 direct / relay 两条路径的 RTT，择优切换，避免 direct 抖动时仍走直连
- 切换带滞回（hysteresis），避免频繁抖动

### S4.2 TCP 流量采样

- 现状：TCP 帧全量落库，高吞吐下 ES / DB 压力大
- 改为可配采样率（如 1/100），保留首包 + 尾包 + 错误包

### S4.3 日志降级

- hot path 上的 INFO 日志降为 DEBUG，避免大流量下日志风暴
- 保留 error / warn 与关键状态切换

### S4.4 ACL 方向性

- 明确 ACL 是「允许 peer」还是「允许被 peer」，避免语义歧义
- UI 上对方向有可视化标识

### S4.5 窄屏 SVG

- landing / peer 直连示意图在窄屏下 SVG 箭头错位，做响应式适配

验收：大流量下日志与 TCP 落库压力下降；选路稳定不抖动；ACL 语义清晰。

---

## 7. 进度跟踪

- Sprint 0：✅ 完成（`9aa6da2` + `d9dd9d2`，已推送）
- Sprint 1：
  - S1.1 ✅
  - S1.2 ✅
  - S1.3 ✅
  - S1.4 ✅
  - 收尾（编译 + 测试 + 提交 + 部署）✅ 提交 `50af83f`
- Sprint 2–4：⏳ 待启动

> 本文件随 Sprint 推进同步更新状态列；代码落点以实际提交为准。
