# Go Server 全量对齐 Java Server 实施计划

创建：2026-07-22
状态：进行中（Batch 1、Batch 3 已完成；Batch 2 部分完成；Batch 4-6 待实施）

目标：使 Go server（`implementations/go/server`）成为 Java server（`implementations/java/server`）的完全替代品。
本计划基于 [`go-server-vs-java-server-audit-2026-07.md`](go-server-vs-java-server-audit-2026-07.md) 中识别的 9 项实质差异（S-1..S-9）、
11 项轻微差异（T-1..T-11）和 1 个路径 bug，按 6 个独立批次交付。每批完成后运行 `go build ./...` + `go test ./...`（Go）
或 `mvn test`（Java S-2/T-8）。

## 批次总览

| 批次 | 内容 | 状态 |
| --- | --- | --- |
| Batch 1 | 快速行为修复（S-4, S-8, S-9, 路径 bug, T-7） | ✅ 已完成 |
| Batch 2 | NAT 修复（S-2 Java, S-5, S-6, T-4） | 🟡 S-2、S-6、T-4 已完成，S-5 待实施 |
| Batch 3 | 管理 API 端点（S-3 部分：name-availability, nat-probe-config） | ✅ 已完成 |
| Batch 4 | Direct HTTP WebSocket 隧道（S-1） | ⬜ 待实施 |
| Batch 5 | 公共互传 rooms + 用户 diagrams（S-3 剩余 + DB 表） | ⬜ 待实施 |
| Batch 6 | 嵌入式 STUN RFC 5780（S-7） | ⬜ 待实施 |
| 收尾 | T-8 Java 413 预检记录 + 审计文档更新 | ⬜ 待实施 |

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
- **改动**：`errOffline` 及实际离线响应均返回 `http.StatusBadGateway`（502），对齐 Java `HttpTunnelController.java:100`。

### Batch 1 验证
- `go build ./...` 通过（exit 0）。
- `go test ./...` 通过。

---

## Batch 2：NAT 修复 🟡

### S-2：Java 接受入站 KEEPALIVE（修 Java，非 Go）✅
- **文件**：
  - `implementations/java/server/.../handler/NatServerHandler.java` `channelRead` switch（~L84-130）：在 trailing `else` PROTOCOL_VIOLATION 之前添加 `case KEEPALIVE:` 静默返回。
  - `implementations/java/client/.../handler/NatClientHandler.java` `channelRead` switch（~L209-235）：同样添加 `case KEEPALIVE:` 静默返回。
- **理由**：Java `NatCommonHandler` 在 writer-idle 时主动发送 KEEPALIVE，但两端都不接受入站 KEEPALIVE（自相矛盾）。Go 已正确接受（`session.go:158-159`）。修 Java 使 keepalive 真正生效。
- **测试**：Java client/server 均新增 EmbeddedChannel 用例，发送 KEEPALIVE 后断言连接保持 active。

### S-5：陈旧 session 清理 + 启动/关停 sweep
- **文件**：`implementations/go/server/internal/auth/auth.go` `authenticate()`（~L234-288）+ `implementations/go/server/internal/server/app.go`
- **改动**：
  - `authenticate` 在 `CountOnlineByMachineUser`/`CountOnlineByCredential` 检查前，新增 `closeStaleOnlineSessions` 步骤：查询 DB 中该 credential（+machine+osUser）的 `NETTY_ONLINE` 行，对每行通过 `session.Registry.Find(clientName)` 检查内存中控制连接是否存活；若不存在/已断开，调用 `MarkClientSessionDisconnected` 标记该行。对齐 Java `closeStaleOnlineSessions`（L355-386）。
  - 启动 sweep：`app.go` 启动时将所有 `NETTY_ONLINE` 行标记为 `DISCONNECTED`，reason `SERVER_RESTARTED`（对齐 Java `closeStaleOnlineSessionsOnStartup` L90-101）。
  - 优雅关停 sweep：context cancel 时将 open connection records 标记为 `SERVER_SHUTDOWN`（对齐 Java `markAllOpenAsShutdownOnContextClose`）。store 新增 `MarkAllOpenConnectionsShutdown`。
  - `session.Session` 接口可能需要新增 `IsActive() bool` 方法（或复用 `Registry.IsBound`）。

当前状态：登录限额检查前的陈旧 `NETTY_ONLINE` session 清理尚未实施；连接记录的启动/关停 sweep 已按 T-4 完成。

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

## Batch 4：Direct HTTP WebSocket 隧道（S-1） ⬜

Java 使用 12 字节 SWS2 帧封装（magic `0x53575332`、opcode、flags、closeCode u16、payloadLen i32、payload），非 1 字节前缀。

### 新文件 `implementations/go/server/internal/directhttp/`
- **`sws2.go`**：SWS2 编解码。`encodeSWS2(opcode, final, rsv, closeCode, payload) []byte` + `decodeSWS2(frame) (opcode, final, rsv, closeCode, payload, error)`。常量：`magicSWS2=0x53575332`、`headerBytes=12`、`maxPayload=64*1024-12`。Opcodes：CONTINUATION=0, TEXT=1, BINARY=2, CLOSE=8, PING=9, PONG=10。
- **`ws_tunnel.go`**：`WebSocketTunnel` 结构体（持有 `*websocket.Conn`、streamID、clientName）。方法：`OPEN`（发送 `NatOpen` 含 `source=ws` metadata 到客户端控制通道）、`handleBrowserFrame`（WS 消息 -> SWS2 封装 -> `NatData`）、`writeFrame`（解码 SWS2 -> 重建 WS 消息 -> 发往浏览器）、`close`。

### 修改 `directhttp/service.go` `ServeHTTP`
- 顶部检测 `Upgrade: websocket`（大小写不敏感），若为 WS 则分支到 WS 隧道 handler（`websocket.Accept` + 创建 `WebSocketTunnel` + 读循环），否则继续现有 HTTP 路径。

### 修改 `nat/session.go`
- `clientSession` 新增 `wsStreams map[uint32]*directhttp.WebSocketTunnel`。
- `NatData` case（~L160-168）：`handleHTTPData` 返回 false 后检查 `wsStreams[streamID]`；命中则转发 SWS2 字节到 `wsStream.writeFrame` 并发 `WINDOW_UPDATE`；否则 fall through 到 TCP `handleData`。
- `NatFin`/`NatRST` case（~L169-177）：`handleHTTPEnd` 返回 false 后检查 wsStreams；命中则关闭 WS 隧道；否则 TCP。
- `dispose`（~L520-544）：关闭所有 wsStreams（对齐 Java `onControlChannelInactive` -> `closeAll`）。
- 新增 `openWSStream`（类似 `openHTTPStream`）：分配 streamID、注册、发送 `NatOpen` 含 `source=ws` metadata。
- WS 流需要流控（send credit + 接收时 `WINDOW_UPDATE`），对齐 `HTTPStream`。

### 测试
- `sws2_test.go`：SWS2 编解码 round-trip、分块、opcode 重建。
- `ws_tunnel_test.go`：WS 隧道 OPEN/DATA/CLOSE 生命周期（使用测试 NAT session）。

### Batch 4 验证
- `go build ./...` + `go test ./...`。

---

## Batch 5：公共互传 rooms + 用户 diagrams（S-3 剩余 + DB 表） ⬜

### 新 DB 表（添加到全部 3 个 schema 文件：`store/schema/{sqlite,mysql,postgres}.sql`）
- `public_transfer_room`（id, room_id, display_name, owner_peer_id, created_at, expires_at, tenant_id）
- `public_transfer_room_access`（id, room_id, access_id, peer_id, display_name, role, created_at, revoked_at）
- `public_transfer_room_pairing_code`（id, room_id, code, created_at, expires_at, redeemed_by, redeemed_at）
- `public_transfer_diagram_version`（id, room_id, version_id, version, content, created_at, created_by）
- `user_diagram_document`（id, tenant_id, owner_username, name, content, created_at, updated_at）

### 新 store 层：`store/rooms.go` + `store/diagrams.go`
- 每张表的 CRUD（对齐 Java repository）。幂等 `CREATE TABLE IF NOT EXISTS` 已在 schema 中。

### 新 service：`transfer/room_service.go`
- `PublicTransferRoomService` 对齐 Java：listAccessTokens、createAccessToken、revokeAccessToken、createPairingCode、redeemPairingCode（含限流）、listVersions、createVersion、getVersion、deleteVersion。
- `PublicTransferRateLimiter` 用于 pairing-code redeem（per-IP）。

### 新管理 handler（`management/api.go`）
- `/api/public/transfer/rooms/**`（9 个端点）- 注册路由，委托 room_service。
- `/api/admin/diagrams/**`（5 个端点）- 注册路由，委托 diagram store，含 tenant/owner 可见性过滤。

### 修改 `/api/public/transfer/ws-tickets` handler
- `server/websocket_tickets.go` `handlePublicWebSocketTicket`：当 `roomToken` 存在时，通过 `roomService.resolve(roomId, roomToken, peerId)` 解析（替代当前 `token:<sha256>` 自计算）。设置 `roomKey = "room:" + roomId` 和 `roomRole`。对齐 Java `WebSocketTicketResource.java:74-81`。

### 测试
- `room_service_test.go`、`diagrams_test.go`：CRUD、pairing-code redeem/限流、tenant/owner 可见性。

### Batch 5 验证
- `go build ./...` + `go test ./...`。

---

## Batch 6：嵌入式 STUN RFC 5780（S-7） ⬜

### `implementations/go/server/internal/peermesh/stun_turn.go` `binding()`
- 解析 CHANGE-REQUEST 属性（RFC 5780）：存在时按 flag 改变响应源端口/地址（0x02 = change port, 0x04 = change address, 0x06 = both）。需要 4 端点拓扑（PRIMARY, PRIMARY_ALTERNATE_PORT, ALTERNATE_PRIMARY_PORT, ALTERNATE）。
- 解析 RESPONSE-PORT 属性：从请求端口响应。
- 解析 PADDING 属性：在响应中添加填充字节。
- 此逻辑已存在于独立 `stunserver/binding.go` - 提取/复用 CHANGE-REQUEST/RESPONSE-PORT/PADDING 处理到共享 helper 或内联到嵌入式 `binding()`。
- 将嵌入式拓扑从 2 socket（primary/alternate）扩展到 4 端点（当配置提供 alternate host + 不同 port 时）。对齐 Java `StunEndpointTopology.rfc5780`（4 端点）+ `StunBindingService.java:54-156`。

### 配置
- `config.go`：新增 `standaloneAlternateStunHost`/`standaloneAlternateStunPort`（若尚不存在，供 Batch 3 `nat-probe-config` 构建 4 端点）。

### 测试
- `stun_turn_test.go`：CHANGE-REQUEST 各 flag 值、RESPONSE-PORT、PADDING、无 alternate 端点时 420 unsupported。

### Batch 6 验证
- `go build ./...` + `go test ./...`。

---

## 收尾

### T-8：Java 413 预检记录
- **文件**：`implementations/java/server/.../http/HttpTunnelBodyLimitFilter.java`
- **改动**：在 `Content-Length` 超限短路前调用 `trafficInspectionService.recordHttpExchange` 记录 413 交换（对齐 Go 已有的记录行为）。或反过来让 Go 不记录以匹配 Java--推荐修 Java（记录更有用）。

### 审计文档更新
- 更新 `go-server-vs-java-server-audit-2026-07.md`：将每个已修复项标记为 FIXED。
- 更新 `tunnel-server-go-port-plan.md`：记录最终状态。

### 最终验证
- Go：`cd implementations/go/server && go build ./... && go test ./...`（全绿）。
- Java（S-2/T-8）：`cd implementations/java/server && mvn -Dtunnel.server.web.skip=true test`（184+ 通过）。

---

## 未列入本计划的轻微差异（可接受 / 双向取舍）

以下轻微差异不阻塞 Go server 替代 Java server，暂不处理：

| 编号 | 项 | 理由 |
| --- | --- | --- |
| T-1 | readString null vs empty | 实际不影响互操作（server 只设非空 reason 或省略） |
| T-2 | Nonce 防重放键形不同 | 功能等价，行 120s 过期，DB 不跨 server 共享 |
| T-3 | 登录线程池 core/max 弹性 | 低并发行为差异，不影响正确性；T-6 映射 env 即可 |
| T-5 | DB 表集合差异 | Batch 5 补齐 5 张表后消除 |
| T-6 | 配置键差异 | 登录 core-size 等 Go 固定 worker 模型下为信息性；可后续补 env 映射 |
| T-9 | 搜索字段别名 | Go 超集，不影响 Java 前端使用 |
| T-10 | 路径去重 | 边缘情况，仅影响已前缀内容的二次改写 |
| T-11 | TLS PEM/双配置 | 双向取舍：Go 支持 PEM 是超集，Java 双配置是历史设计 |

## 相关文档

- 审计文档：`go-server-vs-java-server-audit-2026-07.md`
- Go server 移植计划：`tunnel-server-go-port-plan.md`
- 总对齐计划：`cross-language-java-alignment-plan.md`
