# Peer Mesh Java 客户端打洞审计与修复记录

本文记录 2026-07-05 对 Java 客户端 peer 实现(`implementations/java/client/.../peer/PeerMeshClient.java`,约 2600 行)的一次完整审计:发现的问题、已落地的修复、以及仍待处理的事项。审计动因是回答"打洞成功率高不高、还有没有优化空间"。

结论摘要:

* 打洞机制设计本身完善(多源候选、burst 探测、自适应端口预测、端口映射、TURN 兜底),理论覆盖面高。
* 找到 5 个会实际影响连通性/稳定性的缺陷 + 1 个慢性内存泄漏,均已修复。
* 此前**没有任何聚合统计**,"成功率"无法用数据回答;本次补了服务端聚合端点,部署后以 `activeDirectRatio` 作为打洞成功率的代理指标。

## 审计时确认的机制强项

以下能力在审计前已存在,列出以免后人重复怀疑:

* direct 路径在所有 NAT 组合下都会尝试(`shouldAvoidDirectPath` 恒 false,S0.1),不再按 NAT 类型预判放弃;relay 自动兜底。
* 连通性探测做 burst(3 发 × 30ms 同 nonce,S0.3),对抗 NAT conntrack race。
* 触发式双向探测(P1-5):收到入站探针且 direct 未建立时,立刻反向扫描对端候选。
* 自适应对称 NAT 端口预测:基于多 STUN srflx 观测的端口 delta 补探,上限 16 个端口、delta ≤ 512,无观测依据不盲扫。
* UPnP / NAT-PMP / PCP 端口映射做成 priority 900 的 srflx candidate,对称 NAT 也能被直连命中;30s 失败退避,lease 自动续期。
* 公网 IPv6 host candidate、公共 STUN 多源观测、hairpin 同 NAT 检测(优先 LAN host、保留 relay 防 CGNAT 误判)。
* direct keepalive 25s 打底,压在国内宽带 NAT 30~60s 映射 TTL 之内;RTT 滞回(100ms)做 direct/relay 择优。

按 NAT 组合的理论预期:Cone×Cone、Cone×Symmetric 成功率高;PortRestricted×Symmetric 中等(依赖端口预测);Symmetric×Symmetric 仅靠端口映射或 IPv6,否则落 TURN。

## 问题与修复明细

以下 6 项均已于 2026-07-05 修复并通过编译与测试(客户端 24/24,服务端 `PeerMeshServiceTests` 通过)。

### 1. roster 刷新丢弃全部已学候选(影响:探测中断)

`updateRoster` 先 `peers.clear()`,再用空 `candidates` 列表重建 PeerInfo。roster 由服务端在**任意客户端上下线时**推送,每次推送都会清空所有对端已交换到的候选,`probeKnownCandidates` 随之失效,必须等下一轮候选交换才能恢复直连探测。

修复:重建前快照旧 map,仍在 roster 中的 peer 沿用既有 candidates。

### 2. 单个 keepalive 丢包即拆除 direct 路径(影响:路径抖动)

keepalive 间隔 25s、stale 阈值 45s,两者之间只容得下一次探测机会:t=25s 的 keepalive(单包,无重发)或其 ACK 丢失 → t=45s 判 stale → `keepaliveDirectPaths` 因要求 `hasHealthyDirect` 不再补发 → `fallbackStaleDirectPaths` 拆路径重打,流量抖到 relay。一次普通 UDP 丢包就触发完整的 direct→relay→direct 翻转。

修复:`sendDirectKeepalive` 复用 `scheduleProbeBurst`(同 nonce 3 发 × 30ms,收到 ACK 后自动停发)。原注释"已建路径无 NAT race、单包足够"的判断只考虑了 race,没考虑丢包容错。

### 3. 最慢探测响应者抢占 remoteEndpoint(影响:选路劣化、endpoint 摆动)

`completeUdpProbe` 对每个 direct 探测响应**无条件覆盖** `session.remoteEndpoint`。多个候选同时可达时(LAN host、srflx、预测端口),RTT 最大的响应最后到达、最后写入——劣质路径胜出;叠加 30s 周期重探,发送目标会在多个可达 endpoint 之间持续摆动。`markPathFromInboundCheck`(入站探针侧)有同样问题,对称 NAT 对端的多个映射地址会来回翻转本端目标。

修复:`PeerSession` 新增 endpoint 级 `endpointSuccessMillis` / `endpointRtt`(S4.2);现有 endpoint 仍健康(keepalive ACK 持续刷新)且新响应 RTT 没有 100ms 滞回优势时保持不动。endpoint 失效(45s 无响应)后自动放行下一个响应者接管,故障切换语义不变。session 迁移路径(`withAesKey`、`rememberSession`)同步携带新字段。

### 4. 候选无变化也触发全员广播(影响:信令与 UDP 噪声)

`handleStunBindingSuccess` / `handleTurnAllocated` / `attemptPortMapping` 每次都调 `announceCandidatesToOnlinePeers`。配置 N 个公共 STUN 时,每轮观测到达 N+1 个 binding success,即 N+1 次向所有在线 peer 的候选广播,对端每次都会回一整轮 connectivity check(含 burst 与端口预测)。

修复:三个触发点均改为"端点实际变化才广播"(srflx 以 `type:addr:port` key 判新旧,TURN/端口映射比对 relayId/地址/端口)。maintenance 30s 周期广播保留,作为信令丢失的兜底重试。

### 5. `pendingStunBindings` 慢性泄漏

STUN binding 事务 entry 只在收到 success 响应时移除;STUN 服务器不可达时以每 60s × N 个 server 的速度永久累积。

修复:值类型改为带时间戳的 `PendingStunBinding` record,`cleanupPendingProbes`(maintenance 30s tick)按 15s TTL 清理——binding 响应正常亚秒级到达,15s 足够宽裕。

### 6. 打洞成功率无数据可查(可观测性缺口)

服务端 `PeerMeshSession` 一直存有每会话 `pathType`(由客户端 PATH_REPORT 更新)、`rttMillis`、`natType`(设备维度),但没有任何聚合查询,管理台只能逐条看会话,"成功率高不高"无法回答。

修复:新增 `GET /api/admin/peer-mesh/stats`,可见性与 sessions 接口一致(admin 全租户,普通用户仅自己客户端参与的会话与名下设备):

* `activeDirectRatio` — 当前活跃会话中 DIRECT 占比,**打洞成功率的代理指标**。
* `pathTypes[]` — 按 `pathType × status` 的会话数、已上报路径数、平均 RTT、direct/relay 字节。
* `natTypes[]` — 设备 NAT 类型分布(空值归并为 `UNKNOWN`),用于定位失败集中在哪类 NAT 组合。
* `reportedSessions` 用 `count(rttMillis)` 统计:rtt 只由 PATH_REPORT 写入,非空即"至少确立过一次路径",排除 `createSession` 默认 `pathType=DIRECT` 造成的直连占比虚高。

涉及文件:`PeerMeshSessionRepository`(聚合投影)、`PeerMeshDeviceRepository`(NAT 分布)、`PeerMeshPathStatsView`(新)、`PeerMeshService.pathStats`、`PeerMeshResource`。

管理台已配套展示(`apps/admin-web`,私有组网面板):顶部指标卡新增「直连占比」;「活跃会话」页顶部新增「打洞 / 路径统计」卡片,含直连占比进度条、`pathType × status` 明细表与设备 NAT 分布。Go / C# 服务端已补齐同名 `/api/admin/peer-mesh/stats` 端点,返回结构和 Java `PeerMeshPathStatsView` 保持一致;前端仍保留失败降级逻辑,避免非 Java 历史部署未升级时影响面板其余部分。

## 使用建议

启用 peer mesh 的环境部署后运行数天,定期抓取 `/api/admin/peer-mesh/stats`:

* `activeDirectRatio` 持续偏低时,先看 `natTypes` 分布——SYMMETRIC_NAT 设备占比高属预期,应引导用户开启路由器 UPnP 或 IPv6;分布正常但占比仍低,再排查探测参数。
* 平均 RTT 的 DIRECT/RELAY 对比可验证 RTT 滞回选路是否符合预期。
* 有数据基线后再做探测参数调优,否则改动无法验证效果。

## 已知未修复事项

审计中发现但本次未处理,按建议优先级排列。2026-07-05 已继续补齐 Java 端低风险项:

* RTT 选路由历史最小值改为 EWMA,避免网络变化后长期使用过时的最优 RTT。
* 数据面先读取加密 frame AAD 中的 sessionId,通过 `sessionsById` 直接定位会话,不再线性遍历全部 session 逐个试解密。
* connectivity check 增加 20ms 候选级 pacing,避免所有候选和端口预测 burst 在同一瞬间打出。
* `PeerMeshServiceTests` 增加 `pathStatsAggregatesDirectRatioAndNatTypes`,覆盖 `activeDirectRatio`、`reportedSessions` 和 NAT 类型归并。

本次补齐项已通过 Java client/server 主代码编译:`mvn -f implementations\java\client\pom.xml -DskipTests compile`、`mvn -f implementations\java\server\pom.xml "-Dspecus.server.web.skip=true" -DskipTests compile`。定向测试当前被既有 testCompile 问题拦截:client 旧 handler 测试仍引用已移除的 `bean/client` 包,server 多个测试仍引用重组前的 `management` / `server` 包路径,需后续单独修复测试目录。

2026-07-06 已继续对齐 Go / C# 客户端同源实现:

* Go / C# frame codec 均可从 AAD 读取 `sessionId`,客户端维护 `sessionsById` / `_sessionsById`,数据面不再遍历所有 session 逐个试解密。
* Go / C# connectivity check 增加 20ms 候选级 pacing;direct keepalive 复用 3 发 burst。
* Go / C# STUN pending binding 增加 30s TTL 清理;srflx / relay / port-map 候选只有端点实际变化时才广播。
* Go / C# direct endpoint 增加健康窗口粘滞与 RTT EWMA 字段;C# session grant 刷新同步保留 nominated path 状态。
* Go client public STUN candidate 生命周期对齐 Java:每轮公网 STUN 探测前清理 `foundation=public-stun` 的旧 candidate,避免三端候选集合语义漂移。
* Go / C# server 均已补齐 `/api/admin/peer-mesh/stats`,并按 Java 规则统计 `reportedSessions=count(rttMillis)`、`activeDirectRatio`、`pathType × status` 明细和 NAT 类型分布。
* C# client tests 通过: `dotnet test implementations\csharp\client\tests\Specus.Client.Tests\Specus.Client.Tests.csproj --no-restore` 69/69。
* C# server 后端编译通过: `dotnet build implementations\csharp\server\src\Specus.Server\Specus.Server.csproj --no-restore -p:SpecusServerWebSkip=true -v minimal`。未加 `SpecusServerWebSkip=true` 时会触发前端 `npm run deploy:csharp`,当前沙箱因 esbuild 读取外层目录权限失败而中断,不作为后端代码结论。
* C# server PeerMeshService 定向测试通过: `dotnet test implementations\csharp\server\tests\Specus.IntegrationTests\Specus.IntegrationTests.csproj --no-restore -p:SpecusServerWebSkip=true -v minimal --filter "FullyQualifiedName~PeerMeshServiceTests"` 7/7,覆盖 session grant、关闭通知、relay 授权和路径统计聚合。
* Go 测试通过:设置 `GOCACHE=.gocache` 后,`go test ./internal/client`、`go test ./internal/peermesh ./internal/store ./internal/management` 均通过。

1. **数据面进一步性能优化**(影响吞吐,不影响打洞):Java 仍是单线程阻塞式 `DatagramSocket` 收包,解析/AES-GCM 解密/TUN 写入同线程;每包仍 `Cipher.getInstance`,还有多次数组拷贝。三端 sessionId 索引已消除线性试解码,后续可继续拆 UDP worker / TUN writer 与 Cipher 复用。

## 相关文档

* 实现全貌与部署验收:`docs/peer-mesh/peer-mesh-implementation.md`
* 打洞技术调研:`docs/peer-mesh/direct-connect-hole-punching-research.md`
* 跨语言对齐计划:`docs/cross-language/cross-language-java-alignment-plan.md`
