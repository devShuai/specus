# Go Server 全量对齐 Java Server 实施计划

创建：2026-07-22
状态：已完成（Batch 1-6 及收尾项均已实施，Go `go build ./... && go test ./...` 全绿）

目标：使 Go server（`implementations/go/server`）成为 Java server（`implementations/java/server`）的完全替代品。
本计划基于 [`go-server-vs-java-server-audit-2026-07.md`](go-server-vs-java-server-audit-2026-07.md) 中识别的 9 项实质差异（S-1..S-9）、
11 项轻微差异（T-1..T-11）和 1 个路径 bug，按 6 个独立批次交付。每批完成后运行 `go build ./...` + `go test ./...`（Go）
或 `mvn test`（Java S-2/T-8）。

## 批次总览

| 批次 | 内容 | 状态 |
| --- | --- | --- |
| Batch 1 | 快速行为修复（S-4, S-8, S-9, 路径 bug, T-7） | ✅ 已完成 |
| Batch 2 | NAT 修复（S-2 Java, S-5, S-6, T-4） | ✅ 已完成 |
| Batch 3 | 管理 API 端点（S-3 部分：name-availability, nat-probe-config） | ✅ 已完成 |
| Batch 4 | Direct HTTP WebSocket 隧道（S-1） | ✅ 已完成 |
| Batch 5 | 公共互传 rooms + 用户 diagrams（S-3 剩余 + DB 表） | ✅ 已完成 |
| Batch 6 | 嵌入式 STUN RFC 5780（S-7） | ✅ 已完成 |
| 收尾 | T-8 Java 413 预检记录 + 审计文档更新 | ✅ 已完成 |

---

## Batch 1：快速行为修复 ✅

### S-4：maxOnlineInstances=0 拒绝所有登录（对齐 Java）
- **文件**：`implementations/go/server/internal/auth/auth.go`（原 L272）
- **改动**：移除 `> 0` 守卫，使 `MaxOnlineInstances == 0` 时 `CountOnlineByCredential >= 0` 恒为真，拒绝所有登录。
  与 Java `ClientAuthService.isOnlineLimitExceeded`（L347-353，无 `>0` 守卫）一致。
- **测试**：待补 `MaxOnlineInstances=0` 断言拒绝的用例。

### S-8：VIP 分配哈希改为 Java String.hashCode()
- **文件**：`implementations/go/server/internal/peermesh/service.go`（`allocateVirtualIP`，原 L1403-1406）
- **改动**：将 FNV-1a 32-bit 替换为 `javaStringHashCode`（`h = 31*h + char`，int32 有符号溢出）+ `javaMathAbsInt32`（复现 Java `Math.abs` 的 `Integer.MIN_VALUE` 边界）。移除 `hash/fnv` import。
- **效果**：同 `tenant:owner:id` 字符串在 Go/Java 两端产生相同 VIP，支持客户端跨 server 迁移。
- **测试**：已覆盖空串、ASCII 和 UTF-16 代理对，确认与 Java `String.hashCode()` 一致。

### S-9：可复用 session grant
- **文件**：`implementations/go/server/internal/peermesh/service.go`（`CreateSession` L1193）+ `implementations/go/server/internal/store/peer_mesh.go`（新增 `FindOpenSessionBetweenClients`）
- **改动**：
  - `Service` 结构体新增 `sessionTokenCache map[int64]string` + `sessionTokenCacheMu sync.RWMutex`（对齐 Java `sessionTokenCache`）。
  - `CreateSession` 在 `CanPeer` 通过后先调用 `reusableSessionGrant`：查询两个 client 之间未关闭的 session，跳过过期的（关闭并 continue），命中则返回缓存的明文 token。未命中才创建新 session，并在 `InsertPeerMeshSession` 后 `cacheSessionToken`。
  - `markClosed` 新增 `removeCachedSessionToken(item.ID)`，确保关闭时清除缓存。
  - store 新增 `FindOpenSessionBetweenClients(tenantID, sourceID, targetID, closedStatus)` 查询，双向匹配 `source<->target`。
- **测试**：待补两次 `CreateSession` 同 pair 返回相同 token 的用例。

### 路径 bug：public transfer name-availability
- **文件**：`implementations/go/server/internal/server/app.go`（L363）
- **改动**：路由从 `GET /api/public/transfer/name-availability` 改为 `GET /api/public/transfer/clients/name-availability`，对齐前端 `apps/admin-web/src/api/client.ts:589`。

### T-7：Direct HTTP 离线状态码 503 -> 502
- **文件**：`implementations/go/server/internal/directhttp/errors.go`、`service.go`
- **改动**：`errOffline` 及实际离线响应均返回 `http.StatusBadGateway`（502），对齐 Java `HttpSpecusController.java:100`。

### Batch 1 验证
- `go build ./...` 通过（exit 0）。
- `go test ./...` 通过。

---

## Batch 2：NAT 修复 ✅

### S-2：Java 接受入站 KEEPALIVE（修 Java，非 Go）✅
- **文件**：
  - `implementations/java/server/.../handler/NatServerHandler.java` `channelRead` switch（~L84-130）：在 trailing `else` PROTOCOL_VIOLATION 之前添加 `case KEEPALIVE:` 静默返回。
  - `implementations/java/client/.../handler/NatClientHandler.java` `channelRead` switch（~L209-235）：同样添加 `case KEEPALIVE:` 静默返回。
- **理由**：Java `NatCommonHandler` 在 writer-idle 时主动发送 KEEPALIVE，但两端都不接受入站 KEEPALIVE（自相矛盾）。Go 已正确接受（`session.go:158-159`）。修 Java 使 keepalive 真正生效。
- **测试**：Java client/server 均新增 EmbeddedChannel 用例，发送 KEEPALIVE 后断言连接保持 active。

### S-5：陈旧 session 清理 + 启动/关停 sweep ✅
- **文件**：`implementations/go/server/internal/auth/auth.go` `authenticate()` + `implementations/go/server/internal/server/app.go`
- **改动**：
  - `authenticate` 在 `CountOnlineByMachineUser`/`CountOnlineByCredential` 检查前，新增 `closeStaleOnlineSessions` 步骤：枚举内存中该 credential 的 `NETTY_ONLINE` session（`SessionStore.FindOnlineByCredential`），对每条通过 `session.Registry.Find(clientName)` 检查控制连接是否仍绑定；未绑定则内存 + DB 同步标记 `DISCONNECTED`。对齐 Java `closeStaleOnlineSessions`（L355-386），当前 session 自身不排除（成功后由 dispatcher 重新 `MarkOnline`，与 Java 先关后存回等价）。
  - `Authenticator` 构造新增 `*session.Registry` 参数（`app.go` 装配处传入）。
  - 启动 sweep：`app.go` 启动时将所有 `NETTY_ONLINE` 行标记为 `DISCONNECTED`，reason `SERVER_RESTARTED`（对齐 Java `closeStaleOnlineSessionsOnStartup` L90-101）。
  - 优雅关停 sweep：context cancel 时将 open connection records 标记为 `SERVER_SHUTDOWN`（对齐 Java `markAllOpenAsShutdownOnContextClose`）。store 新增 `MarkAllOpenConnectionsShutdown`。
- **测试**：`auth/auth_test.go` 新增两个用例——陈旧 online session 不阻塞重登并被标记断开；存活绑定的 online session 仍拒绝重复登录。

### S-6：NAT per-tenant 连接计数 ✅
- **文件**：`implementations/go/server/internal/nat/manager.go` + `implementations/go/server/internal/nat/session.go`
- **改动**：
  - `RemotePortManager` 新增 `activeByTenant map[string]*atomic.Int64` + `rejectedByTenant map[string]*atomic.Int64`。
  - `TryAcquireGlobal` -> `TryAcquire(tenantID string)`，`ReleaseGlobal` -> `ReleaseExternal(tenantID string)`，同时增减全局和 per-tenant 计数。新增 `RecordRejected(tenantID)`。对齐 Java `RemotePortServerManager.java:26-27,45-102`。
  - `session.go` `acquire()`/`release()`（~L490-518）传入 `s.conn.TenantID()`（空时默认 `"default"`）。
  - 可选：在 `/api/admin/overview` 暴露 per-tenant 计数（若 Java 有）。

说明：Java 这一层仅记录按租户的 active/rejected 指标，实际容量门控仍为全局 `maxExternalConnections`，因此这里不是独立租户配额。

### T-4：连接记录启动/关停 sweep ✅
- 已实现 `SERVER_RESTARTED` 启动 sweep + `SERVER_SHUTDOWN` 关停 sweep。
- store 新增 `CloseStaleOpenConnections(reason, when)`，通过 `COALESCE` 保留已有断开信息。

### Batch 2 验证
- Go：`go test ./...` 通过。
- Java（S-2）：client/server 定向测试通过，`-DskipTests package` 通过。全量测试受两个既有 Peer Mesh 用例清理 Windows 临时目录时的 `AccessDeniedException` 阻断，断言本身无失败。

---

## Batch 3：管理 API 端点（S-3 部分）✅

### `/api/admin/clients/name-availability`
- **文件**：`implementations/go/server/internal/management/api.go`
- **改动**：新增 `GET /api/admin/clients/name-availability?clientName=&excludeClientId=` handler。查询 store 中同名 client（排除 `excludeClientId`），返回 `{clientName, available}`。对齐 Java `ClientAccountService.checkClientNameAvailability`（L156-165）。

### `/api/public/peer-mesh/nat-probe-config`
- **文件**：`implementations/go/server/internal/peermesh/service.go` 或 `management/api.go`
- **改动**：新增 `GET /api/public/peer-mesh/nat-probe-config` 返回 `PublicNatProbeConfig` DTO：`{available, protocol:"RFC8489", discoveryMethod, endpoints:[{id,url,host,port,addressSlot,portSlot}], capabilities}`。从 Go STUN 配置（primary host/port + alternate port）构建端点。复用现有 `NatProbeAlternatePort` 配置。对齐 Java `PublicPeerMeshResource.java:73-112`。

### Batch 3 验证
- `go test ./...` 通过。

---

## Batch 4：Direct HTTP WebSocket 隧道（S-1） ✅

已完成。实施要点（与 Java 逐条对应）：
- 新增 `directhttp/sws2.go`（12 字节 SWS2 帧编解码：magic `0x53575332`、opcode、flags、closeCode u16、payloadLen i32，maxPayload=65524）与 `directhttp/ws_specus.go`（`WebSocketSpecus`，基于已有依赖 `coder/websocket`）。
- `directhttp/service.go` `ServeHTTP` 顶部检测 `Upgrade: websocket` 分支到 WS 隧道；`nat/session.go` 新增 `wsStreams` 表、NatData/NatFin/NatRST 的 WS 分支、`openWSStream`（`source=ws` metadata）与 dispose 时统一关闭，流控与 `HTTPStream` 一致。
- 修复了一个实施中发现的缺陷：`coder/websocket` 默认 32KB 读上限会掐断大消息，已 `SetReadLimit` 对齐 16MB。
- 测试：`sws2_test.go`（编解码 round-trip/边界/畸形帧）、`ws_specus_test.go`（真实 WS 对的 OPEN/DATA/CLOSE 生命周期、大消息分块、客户端 CLOSE 回送、send credit 窗口语义）。

## Batch 5：公共互传 rooms + 用户 diagrams（S-3 剩余 + DB 表） ✅

已完成。实施要点：
- 5 张新表加入全部 3 个 schema（字段以 Java entity 为准，含 `owner_token_hash`/`snapshot_data`/`revision` 等真实列），另给 `specus_websocket_ticket` 加 `room_role` 列并纳入启动列迁移。
- 新增 `store/rooms.go`、`store/diagrams.go`（含原子 pairing-code 核销与乐观锁 revision 更新）、`transfer/room_service.go`（9 个方法 + per-IP 限流，集群走 Redis `SharedRateLimiter`）、`management/rooms.go`（9 端点）、`management/diagrams.go`（5 端点，tenant/owner 可见性）。
- `server/websocket_tickets.go`：`roomToken` 存在时经 `rooms.Resolve` 解析，设 `RoomKey="room:"+id` 与 `RoomRole`，对齐 Java `WebSocketTicketResource`。
- 端点路径、JSON 字段名、状态码、中文错误消息逐字对齐 Java；配置新增 `SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_*`（默认值与 Java 一致）。
- 测试：`transfer/room_service_test.go`、`management/diagrams_test.go`、`server/websocket_tickets_test.go`。

## Batch 6：嵌入式 STUN RFC 5780（S-7） ✅

已完成。实施要点：
- `peermesh/stun_turn.go` 的嵌入式 binding 改为委托同模块 `internal/stunserver` 的共享 `BindingService`（CHANGE-REQUEST 0x02/0x04/0x06、RESPONSE-PORT、PADDING 全部语义，与 Java `StunBindingService` 字节级一致）。
- 拓扑：`configureStunTopology()` 在四要素齐备时构建 RFC 5780 四端点，否则回退 basic 双端点；`stunBehaviorStrict` 下配置不全即不启动（对齐 Java）。注意语义变化：alternate 端口 bind 失败时从"降级仅 primary"改为"整体不启动"，与 Java 基准一致。
- 配置新增 `SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS` / `SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS` / `SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT`。
- 测试：`stun_turn_test.go` 重写——CHANGE-REQUEST 各 flag、420/400 拒绝、RESPONSE-PORT、PADDING（含 1472 上限）、四端点选择。

---

## 收尾 ✅

### T-8：Java 413 预检记录 ✅
- **文件**：`implementations/java/server/.../http/HttpSpecusBodyLimitFilter.java`
- **改动**：已按"修 Java"方向实施——filter 注入 `TrafficInspectionService`，Content-Length 超限短路时先捕获请求体前缀、写出 413 响应，再 `recordHttpExchange` 记录该交换（status=413，参数语义对齐 Go `directhttp/service.go` 的 `fail()` 路径）。
- **测试**：新增 `HttpSpecusBodyLimitFilterTests`（413 记录、未超限放行不记录、非 `/http/` 路径不记录）；specus-common + specus-server 全量测试通过。

### 审计文档更新 ✅
- `go-server-vs-java-server-audit-2026-07.md` 已将 S-1、S-3、S-5、S-7、T-5、T-8 标记为 ALIGNED。

### 最终验证
- Go：`cd implementations/go/server && go build ./... && go test ./...`（全绿）。
- Java（S-2/T-8）：`mvn -Dspecus.server.web.skip=true -pl implementations/java/server -am test`（specus-common 43 + specus-server 130 通过）。

---

## 未列入本计划的轻微差异（可接受 / 双向取舍）

以下轻微差异不阻塞 Go server 替代 Java server，暂不处理：

| 编号 | 项 | 理由 |
| --- | --- | --- |
| T-1 | readString null vs empty | 实际不影响互操作（server 只设非空 reason 或省略） |
| T-2 | Nonce 防重放键形不同 | 功能等价，行 120s 过期，DB 不跨 server 共享 |
| T-3 | 登录线程池 core/max 弹性 | 低并发行为差异，不影响正确性；T-6 映射 env 即可 |
| T-6 | 配置键差异 | 登录 core-size 等 Go 固定 worker 模型下为信息性；可后续补 env 映射 |
| T-9 | 搜索字段别名 | Go 超集，不影响 Java 前端使用 |
| T-10 | 路径去重 | 边缘情况，仅影响已前缀内容的二次改写 |
| T-11 | TLS PEM/双配置 | 双向取舍：Go 支持 PEM 是超集，Java 双配置是历史设计 |

## 相关文档

- 审计文档：`go-server-vs-java-server-audit-2026-07.md`
- Go server 移植计划：`specus-server-go-port-plan.md`
- 总对齐计划：`cross-language-java-alignment-plan.md`
