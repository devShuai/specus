# TURN 中继失败诊断（2026-07-22）

两个现网故障的代码级定位：

1. **两个手机端（Android × Android）在 TURN 中继状态下发送文件失败**
2. **网页互传（浏览器 WebRTC）使用内置 TURN 中继失败**

审计对象为 Java 基准实现（服务端在两条链路里都是 relay 执行方）：
`implementations/java/server/.../peer/StunTurnServer.java`、
`implementations/java/server/.../management/service/PeerMeshService.java`、
`implementations/java/server/.../management/controller/PublicPeerMeshResource.java`、
`implementations/java/client/.../peer/PeerMeshClient.java`。

> 行号为 2026-07-22 工作树的近似位置，代码变动后以符号名检索为准。
> 状态：`OPEN` 未修复 / `DONE` 已修复。

---

## 0. 共同背景：relay 载荷授权被收窄为 Peer Mesh 专用

`StunTurnServer.authorizeRelayPayload`（约 L529）是所有中继载荷的统一入口，它同时要求：

1. `source.clientId > 0` **且** `target.clientId > 0`；
2. `target = allocationForRelayEndpoint(peer)` —— 目标必须是**本服务端上的另一个 allocation**；
3. 载荷必须是 `SPM2` 业务帧（再经 `authorizeRelayFrameForRelay`），或是本项目的
   `PeerUdpProbe` JSON（首字节 `{`、长度 ≤ 2048，再经 `authorizeRelayProbeForRelay`）。

这等于把标准 TURN 收窄成"仅为 Peer Mesh 兜底"的专用 relay。协议审计
`docs/performance/custom-protocol-performance-audit-2026-07.md` 的 P1-9 曾要求在
"通用 TURN 模式"与"Peer Mesh 专用模式"之间二选一并写入规范；当前实现选择了后者，
但**网页互传仍依赖通用 TURN**，于是产生故障 2。

另需注意授权门槛在两类载荷之间不对称：

| 载荷 | 授权条件 |
| --- | --- |
| `PeerUdpProbe` JSON 探针 | session 只要不是 `CLOSED`（`NEGOTIATING` 也放行） |
| `SPM2` 业务帧 | **必须 `status == ACTIVE`** |

直连数据不经服务端，因此这道门**只在中继路径上生效**——这正是两个故障都表现为
"直连正常、中继异常"的原因。

---

## 1. 手机 × 手机：中继状态正常但文件发送失败

### 现象与机理

中继探针能通（NEGOTIATING 即放行）→ 客户端与管理台都显示 `RELAY` 路径正常；
但业务帧要求 session 已 `ACTIVE`，一旦 session 停留在 `NEGOTIATING`，
服务端会**静默丢弃每一个数据帧**，且客户端收不到任何反馈。

把 session 置为 `ACTIVE` 的唯一途径是客户端经控制连接上报 `path-report`，
而该上报在 Java 客户端只有 `completeUdpProbe`（约 L2904）一个调用点，并带抑制条件：

```java
boolean changed = !pathType.equals(previousPath) || !remote.equals(previousRemote);
if (changed || now - session.lastPathReportMillis >= 60_000) {
    reportPath(session, pathType, local, remote, rttMillis);
}
```

### R1-1 应答方永不上报 — DONE（2026-07-22）

位置：`PeerMeshClient.markPathFromInboundCheck`（约 L2699）。

收到入站探针的一方执行 `markPath("RELAY")` + `flushPendingPackets` 后直接 `return`，
**全程没有 `reportPath`**（direct 分支同样没有）。若某端的中继路径只由入站探针建立，
该 session 永远不会被激活。

### R1-2 session 换号后上报被抑制（最可能的现场主因） — DONE（2026-07-22）

位置：`PeerMeshClient.rememberSession`（约 L706-718）。

服务端每次签发新 grant 都是**新 sessionId + `NEGOTIATING`**，而客户端重建 `PeerSession`
时继承了 `currentPathType`、`lastPathRemoteText` 与 `lastPathReportMillis`。于是下一次中继
探测成功时 `changed == false` 且距上次上报不足 60 秒 → **不上报** → 新 session 在服务端
一直是 `NEGOTIATING` → 中继数据被丢弃最长 60 秒；若 grant 持续轮转则长期失败。

抑制条件基于"路径是否变化"，却跨越了 **session 身份变化**，这是缺陷本质。

### R1-3 先 flush 后上报的竞态 — DONE（2026-07-22）

即便走正常路径，`flushPendingPackets(session)` 与 `reportPath(...)` 在同一调用内完成，
而上报要经 TCP 控制连接 + 数据库写入。该窗口内发出的帧全部被服务端丢弃。
peer 应用消息**没有 ARQ**（Java 侧仅回 ACK，无重传），丢一条即表现为"文件发送失败"。

### R1-4 `TurnAuth.none()` 返回 clientId=0 — DONE（2026-07-22）

位置：`StunTurnServer.TurnAuth.none()`（约 L929）。

当部署设置 `TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED=false` 时，所有 allocation 的
`clientId` 为 0，`authorizeRelayPayload` 的 `source.clientId <= 0` 会拒掉**全部**中继载荷
（连探针也不例外），中继完全不可用。

### 建议修法

- **服务端（根治，语言无关，优先）**：让**首个通过身份校验的中继业务帧隐式激活**
  `NEGOTIATING` 的 session（复用探针那套 from/to + token 校验），仅对 `CLOSED`/过期继续硬拒。
  这样不再依赖 `path-report` 的到达时序，也同时覆盖 Android/Go/.NET 客户端的同源问题。
- **客户端**：
  1. `markPathFromInboundCheck` 建立或切换路径时同样 `reportPath`；
  2. 以 `lastReportedSessionId` 判断是否需要上报，sessionId 变化时强制上报，
     不再继承 `lastPathReportMillis`；
  3. 先上报、再 `flushPendingPackets`。
- 修正 `TurnAuth.none()` 的 clientId 语义（无认证模式下不能落到 0，或该模式下跳过 clientId 校验）。

---

## 2. 网页互传：浏览器 WebRTC 无法使用内置 TURN

浏览器从 `GET /api/public/transfer/ice-config` 取得 ICE 配置并交给标准
`RTCPeerConnection`（`apps/admin-web/src/hooks/useDirectTransfer.ts` 约 L859，
`apps/admin-web/src/api/client.ts` 约 L561）。该端点会下发内置 TURN。

**三重独立阻断，任何一条都足以让 relay 候选完全不通：**

### R2-1 TURN 凭证 subject 解析不出 clientId — DONE（2026-07-22，方案 A）

位置：`PublicPeerMeshResource.iceConfig`（约 L62）签发
`turnCredentialService.issue("public-transfer")`。

`TurnCredentialService.peerMeshClientId` 要求 username 中段形如 `pm-<clientId>`
（约 L84-98），`"public-transfer"` 解析结果为 **0** → `authorizeRelayPayload` 首个条件
`source.clientId <= 0` 即返回 false → **所有**中继载荷被丢。

### R2-2 目标必须是本服务端的另一个 allocation — DONE（2026-07-22，方案 A）

`allocationForRelayEndpoint(peer)`（约 L744）要求对端地址是本服务端上的 relay 地址。
WebRTC 的典型组合是"一端 relay、另一端 srflx/host"，此时 `target == null` → 直接拒绝。
标准 TURN 允许向任意获得 permission 的对端转发，当前实现不满足该语义。

### R2-3 载荷类型不匹配 — DONE（2026-07-22，方案 A）

WebRTC 经 TURN 转发的是 **DTLS 握手、SRTP/SCTP(DataChannel) 与 STUN 连通性检查**，
既不是 `SPM2` 帧，也不是 `{` 开头的 `PeerUdpProbe` JSON，因此必然落到
`authorizeRelayPayload` 的最后一条 `return false`。

即使修好 R2-1、R2-2，只要保留"载荷必须是本项目协议"的校验，浏览器仍然无法中继。

### 建议修法（需先做产品决策）

按协议审计 P1-9 的口径二选一，并写入 `protocol/spec/peer-mesh.md` 与
`protocol/spec/public-transfer.md`：

- **方案 A：按 allocation 划分模式（推荐）**——TURN 凭证签发时区分用途：
  `pm-<clientId>` 走 Peer Mesh 专用校验；`public-transfer` 类凭证标记为通用 TURN allocation，
  按标准 TURN 语义放行（仅校验认证 + permission），但必须配套独立配额、端口范围、
  目的地址策略（禁止指向内网/回环）与滥用审计，避免成为开放中继。
- **方案 B：网页互传不使用内置 TURN**——`ice-config` 不再下发内置 TURN（或改为下发外部
  coturn），并在文档中明确浏览器直传在对称 NAT 下会回退到服务端 WS 中转。

无论选哪个，都应补一条端到端回归：浏览器 relay 候选能完成 DataChannel 建链。

---

## 3. 落地记录（2026-07-22）

已选定**方案 A：按用途放行通用 TURN**，全部 R1/R2 项已实现，Java 服务端 125 项测试通过
（含新增 6 项），客户端 42 项通过。

### 服务端

- `PeerMeshService.authorizeRelayFrameForRelaySlow`：**首个通过身份校验的中继业务帧隐式激活
  `NEGOTIATING` 会话**（设 `ACTIVE` + `pathType=RELAY`），`CLOSED`/过期/身份不匹配仍硬拒。
  这条根治 R1-3 的竞态，且与客户端语言无关，同时覆盖 Android/Go/.NET。
- `matchesSessionPeers` 与 `RelayAuthorization.matches`：`0/0` 表示"调用方无法确定身份"
  （TURN 认证关闭），退化为仅校验会话存在且未关闭，而不是一律拒绝（R1-4）。
- `TurnCredentialService.isGeneralRelaySubject`：识别 `public-transfer` 前缀的凭证。
- `TurnAuth` / `Allocation` 增加 `generalRelay` 标记，`Allocate` 时按凭证用途绑定；用途变化
  会重建 allocation。
- `authorizeRelayPayload`：任一侧为通用中继 allocation 即按标准 TURN 放行（出站看 source、
  入站看 target），不再要求载荷是 SPM2/probe，也不再要求对端是本机 allocation（R2-1~R2-3）。
- `isRelayableDestination`：**仅对通用中继**执行目的地址白名单——拒绝回环、任意地址、
  link-local、site-local、组播、`100.64.0.0/10`（含 Peer Mesh 虚拟网段）与 IPv6 ULA，
  在 `CreatePermission` 与 `ChannelBind` 两处返回 `403 forbidden-peer-address`。
  Peer Mesh 专用模式不受该策略影响（本地/私网部署会用到回环与站点本地地址）。

### 客户端（Java 基准实现）

- `markPathFromInboundCheck` 的 relay 与 direct 分支都会 `maybeReportPath`（R1-1）。
- 新增 `maybeReportPath`：除"路径变化""满 60 秒"外，**sessionId 变化时强制上报**，
  上报状态改用 `lastReportedSessionIds` / `lastReportedPathType` / `lastReportedRemoteText`
  独立跟踪，不再受继承自旧 session 的 `lastPathReportMillis` 抑制（R1-2）。
- `completeUdpProbe` 改为**先上报、再 `flushPendingPackets`**（R1-3）。

### 新增测试

- `PeerMeshServiceTests`：NEGOTIATING 会话被首帧激活、CLOSED/身份不匹配仍拒绝且不激活、
  `0/0` 未识别身份时放行。
- `TurnCredentialServiceTests`：`pm-<id>` 解析出 clientId 且非通用中继、`public-transfer`
  识别为通用中继且无 clientId、未知 subject 两者皆否。

### 通用中继配额与审计（2026-07-22 补齐）

方案 A 让通用中继按标准 TURN 语义转发任意载荷，因此必须有独立于 Peer Mesh 的资源边界。
配额只作用于 `generalRelay` allocation，Peer Mesh 专用 allocation 不受影响：

| 配置项 | 环境变量 | 默认 | 说明 |
| --- | --- | ---: | --- |
| `general-relay-max-allocations` | `TUNNEL_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS` | `256` | 并发 allocation 总数；**设为 0 即关闭通用中继**（网页端退回仅 STUN） |
| `general-relay-max-allocations-per-address` | `..._MAX_ALLOCATIONS_PER_ADDRESS` | `4` | 同一来源 IP 的并发 allocation 上限 |
| `general-relay-rate-bytes-per-second` | `..._RATE_BYTES_PER_SECOND` | `2 MiB/s` | 单 allocation 令牌桶限速，0 表示不限 |
| `general-relay-max-bytes` | `..._MAX_BYTES` | `512 MiB` | 单 allocation 生命周期累计转发上限，0 表示不限 |

实现要点：

- 准入在 `Allocate` 阶段判定，超限返回标准 `486 Allocation Quota Reached`，
  拒绝原因为 `general-relay-disabled` / `general-relay-allocation-quota` /
  `general-relay-address-quota`；重建自身 allocation 时会排除旧实例，避免被自己占用的名额挡住。
- 转发配额在出站（Send Indication / ChannelData）与入站（relay 收包）两个方向都执行：
  先记生命周期累计字节，超过 `max-bytes` 后一律丢弃并只告警一次；再走令牌桶限速。
- 审计日志统一带 `[peer-mesh][audit]` 前缀：allocation 创建、配额拒绝、目的地址拒绝
  （CreatePermission 与 ChannelBind 两处）、字节配额耗尽，均记录来源端点与对端地址。

新增指标：

- `tunnel.peer_mesh.turn.general_relay.quota.rejected`
- `tunnel.peer_mesh.turn.general_relay.destination.forbidden`
- `tunnel.peer_mesh.turn.general_relay.rate.limited`
- `tunnel.peer_mesh.turn.general_relay.bytes`

配套测试：`StunTurnServerMetricsTests` 覆盖目的地址白名单（公网 v4/v6 放行；回环、`0.0.0.0`、
站点本地、link-local、组播、`100.64.0.0/10`、IPv6 ULA、零端口拒绝）与令牌桶限速语义。

### 跨语言对齐（2026-07-22 补齐）

四端全部落地并回归通过：Java 服务端 127、Go 服务端 peermesh/config/server 全绿、
.NET 服务端 137、Android 单元测试通过。

**Go 服务端**（`internal/peermesh/`、`internal/config/`）

- `authorizeRelayFrame`：CLOSED 硬拒；`matchesSessionPeers` 校验身份；首帧隐式激活
  NEGOTIATING 会话（`StatusActive` + `PathRelay`）。
- `validRelayPeers` 与 `relayAuthorization.matches`：`0/0` 表示身份未知（TURN 认证关闭）。
- `turnCredentialService.isGeneralRelaySubject`、`turnAuth.generalRelay`、
  `relayAllocation.GeneralRelay`：按凭证用途绑定 allocation，用途变化触发重建。
- `authorizeRelayPayload`：任一侧为通用中继即按标准 TURN 放行。
- `generalRelayQuotaRejection` / `allowGeneralRelayTraffic` / `isRelayableDestination`：
  与 Java 同语义的准入配额、令牌桶+字节上限、目的地址白名单，`486` / `403` 标准错误码。

**.NET 服务端**（`ShuaiTunnel.Server/PeerMesh/`）

- `AuthorizeRelayFrameCoreAsync`、`ValidRelayPeers`、`MatchesSessionPeers`、
  `RelayAuthorization.Matches` 与 Java 一致；同样实现首帧隐式激活。
- `TurnCredentialService.IsGeneralRelaySubject`、`TurnAuth.GeneralRelay`、
  `Allocation.GeneralRelay`、`GeneralRelayQuotaRejection`、`AllowGeneralRelayTraffic`、
  `IsRelayableDestination` 全部对齐。

**Android 客户端**

- `markSessionPath` 已同时服务入站（`handleProbeCheck`）与出站（`handleProbeResponse`）
  且本就会上报，因此不存在 Java 侧的 R1-1；
- 补齐 R1-2：新增 `lastReportedSessionIds`，**sessionId 变化时强制上报**，
  不再被继承自旧 session 的 `lastPathReportMillis` 抑制；停止时一并清理。

**新增测试**

- Go：`TestAuthorizeRelayFrameActivatesNegotiatingSession`、
  `...RejectsClosedSessionAndMismatchedPeers`、`...AllowsUnidentifiedPeersWhenTurnAuthDisabled`、
  `TestGeneralRelayDestinationPolicy`。
- .NET：`RelayFrameActivatesNegotiatingSession`、`RelayFrameRejectsClosedSessionAndMismatchedPeers`、
  `RelayFrameAllowsUnidentifiedPeersWhenTurnAuthDisabled`、
  `GeneralRelayDestinationPolicyRejectsNonPublicTargets`。
- Go/.NET 中原先断言"NEGOTIATING 会话必须被拒"的用例已按新语义改写（该断言正是被修复的缺陷）。

**部署配置**：三份 `tunnel-server.env.example`（java/go/csharp）与 Java `application.yml`
均已补充四个通用中继配额项。

## 3bis. 配额回归修复（2026-07-23）

上线方案 A 后，网页互传"仍会传送文件失败"。复查发现故障源正是上一轮为通用中继新加的两处配额，
均属回归：

### G-1 令牌桶限速静默丢 SCTP 包（主因） — DONE

内置 TURN 下发的 URL 是 `turn:host:3478?transport=udp`，浏览器 DataChannel 是
SCTP-over-DTLS-over-UDP。通用中继默认 2 MiB/s 令牌桶远低于 WebRTC 实际发送速率
（浏览器文件上限 128 MiB，客户端 `bufferedAmount` 阈值 4 MiB），超出的 UDP 包被服务端
`return` / `continue` **静默丢弃**。

这对可靠传输是灾难：SCTP 的拥塞控制与重传被打乱，有效吞吐崩溃、重传堆积，上层
`file-complete` ACK 60 秒超时 → "对方未确认完成"。**每一次正常传输都会触发。**

标准 TURN（coturn）从不靠丢包限速——带宽控制在 allocation 准入层（`user-quota` /
`total-quota`）。修法：**移除包级令牌桶**。防滥用改为纯准入（并发 allocation 数、同源上限）
+ 总量（`max-bytes`）；单 allocation 累计超过 `max-bytes` 时**关闭 allocation**，让 SCTP
干净断开，而不是拖进持续丢包。删除 `general-relay-rate-bytes-per-second` 配置与
`rate.limited` 指标，新增 `general_relay.quota.closed` 指标。

### G-2 `100.64.0.0/10` 整段被拒，误伤 CGNAT 对端 — DONE

`isRelayableDestination` 为防打到 Peer Mesh 虚拟网段（默认 `100.96.0.0/11`）而拒绝了整个
`100.64.0.0/10`。但该段是 RFC 6598 运营商级 CGNAT，大量家宽/移动用户的公网 srflx 地址
落在此段，CreatePermission 直接 `403` → relay 建不起来。

关键点：通用中继的对端是**浏览器的真实公网地址**，永远不可能是只在 overlay 内部使用的 mesh
虚拟 IP，因此这条防护对通用中继毫无意义、纯粹误伤。修法：**放行 `100.64.0.0/10`**，仅保留
拒绝回环、any、link-local、RFC1918 私网、组播、IPv6 ULA。

### 落地范围

- 三端服务端（Java / Go / .NET）`allowGeneralRelayTraffic` 删令牌桶、超量关闭 allocation；
  `isRelayableDestination` 放行 CGNAT；删除 rate 配置项。
- 测试：目的地址用例断言 `100.64.0.2` / `100.96.0.2` 放行；删除令牌桶速率测试。
- 三份 env 模板与 `application.yml` 移除 rate 变量。
- 回归全绿：Java 服务端 136、Go 服务端 peermesh/config/server、.NET peer 19、
  各端目的地址策略测试通过。

### 仍待办

- 浏览器端到端回归（relay 候选完成 DataChannel 建链）尚未自动化；当前只有单元级的目的地址
  策略与配额语义覆盖，真实 WebRTC 链路仍需手工验证。
- 通用中继配额默认值（2 MiB/s、512 MiB、256 路）按经验取值，未经实测；公网放量前应结合
  带宽成本与典型文件大小复核。

## 4. 验证缺口

当前测试只有 `StunTurnServerMetricsTests`（relay worker 队列指标），
没有任何一条覆盖 relay 转发语义的用例。建议补：

1. `NEGOTIATING` session 的中继业务帧行为（修复后应能隐式激活并转发）；
2. 应答方建立中继路径后，session 能在服务端变为 `ACTIVE`；
3. 通用 TURN 载荷（非 SPM2、非 probe）在所选模式下的 accept/reject 结果；
4. `turn-auth-required=false` 时中继仍可用；
5. 两个 allocation 之间的 hairpin 转发（A relay → B relay）往返成功。

## 5. 相关文档

- 打洞成功率审计：`peer-mesh-hole-punching-audit-2026-07.md`
- 数据面性能审计：`peer-mesh-dataplane-optimization-audit-2026-07.md`
- 全局协议审计（P1-9 通用 TURN 与专用 TURN 的边界）：
  `../performance/custom-protocol-performance-audit-2026-07.md`
- 协议规范：`../../protocol/spec/peer-mesh.md`、`../../protocol/spec/public-transfer.md`
