# Go Server vs Java Server 实现比对审计（2026-07-22）

最后复核：2026-07-22（含本轮 Go/Java 对齐改动，全部计划批次已实施）

本文记录 Go server（`implementations/go/server`）与 Java server（`implementations/java/server`）在全部 6 个阶段、
十几个子系统上的逐项代码级比对结果，并跟踪修复状态。验证结果：Go server `go build ./... && go test ./...` 全部通过；
Java `mvn -Dtunnel.server.web.skip=true -pl implementations/java/server -am test`（tunnel-common 43 + tunnel-server 130）通过。
已知噪声：Go `internal/server` 部分测试在 macOS 上偶发 TempDir 清理竞态（HEAD 基线即有，与对齐改动无关）。

状态标记：`ALIGNED` 已对齐 / `PARTIAL` 部分对齐 / `MINOR` 轻微差异 / `MATERIAL` 实质性差异。

## 1. 总体结论

两端在协议编解码、HMAC 登录、控制通道心跳、写背压、连接归档、WebSocket 事件、Elasticsearch、TURN 认证、
SPM2 relay 计量、Peer Mesh stats、公共互传附件/OSS、客户端消息、OIDC、帧边界等核心路径上已对齐。

原始比对列出 9 处实质性差异和 11 处轻微差异。截至本轮，S-1..S-9 全部修复（含 Direct HTTP WebSocket 隧道、
公共互传 rooms/用户 diagrams 端点、陈旧 session 清理、嵌入式 STUN RFC 5780），轻微差异中 T-4、T-5、T-7、T-8
已消除。当前剩余 7 处轻微差异（T-1、T-2、T-3、T-6、T-9、T-10、T-11），均为可接受的双向取舍，不阻塞
Go server 替代 Java server。

## 2. 实质性差异（MATERIAL，按优先级排序）

| 编号 | 状态 | 子系统 | 当前结论 |
| --- | --- | --- | --- |
| S-1 | ALIGNED | Direct HTTP WebSocket 隧道 | Go 已补齐 `/http/**` WS upgrade 与 12 字节 SWS2 帧隧道（`directhttp/sws2.go`、`ws_tunnel.go`），含流控与 16MB 读上限，生命周期与 Java `WebSocketTunnelHandler` 逐条对应。 |
| S-2 | ALIGNED | NAT KEEPALIVE 处理 | Java client/server 已显式接受入站 KEEPALIVE，行为与 Go 一致，并新增双方定向测试。 |
| S-3 | ALIGNED | 管理 API 端点缺口 | 公共互传 rooms 9 个端点与用户 diagrams 5 个端点已补齐（`management/rooms.go`、`diagrams.go`），路径/字段/状态码/错误消息逐字对齐 Java；ws-ticket 走 `rooms.Resolve`。 |
| S-4 | ALIGNED | `maxOnlineInstances=0` 语义 | Go 已移除 `> 0` 守卫，0 与 Java 一致表示拒绝所有登录。 |
| S-5 | ALIGNED | 陈旧 session 清理时机 | Go `authenticate` 在限额检查前对未绑定控制连接的 `NETTY_ONLINE` session 做内存+DB 清理（`closeStaleOnlineSessions`），幽灵记录不再拒绝合法重连。 |
| S-6 | ALIGNED | NAT per-tenant 遥测 | 原审计误写为独立租户限额；Java 实际只保留全局容量门控并按租户统计 active/rejected。Go 已补齐同等计数。 |
| S-7 | ALIGNED | 嵌入式 STUN RFC 5780 | Go 嵌入式 binding 委托共享 `stunserver.BindingService`，支持 CHANGE-REQUEST/RESPONSE-PORT/PADDING 与四端点拓扑，字节级对齐 Java `StunBindingService`。 |
| S-8 | ALIGNED | Peer Mesh VIP 分配哈希 | Go 已改为按 Java UTF-16 code unit 计算 `String.hashCode()`，含代理对测试。 |
| S-9 | ALIGNED | Peer Mesh 可复用 session | Go 已查询双向 open session、复用内存明文 token，并在关闭时清理 token cache。 |

补充：TLS 也有实质差异（双向各有缺失）--Java `TlsContextFactory` 不支持裸 PEM cert+key（仅 PKCS12/JKS），且 TLS
配置分散在 `tunnel.tls.*`（控制通道/Netty）和 `server.ssl.*`（管理 HTTP/Tomcat）两处；Go 单配置覆盖两端且支持 PEM。
此差异归入轻微差异 T-11，因两端各有取舍而非单方缺失。

### S-3 管理 API 端点明细（已全部补齐）

- `POST /api/public/transfer/rooms/**`（access-tokens、pairing-codes、diagram/versions，共 9 个端点）已实施。
- `GET/POST/PUT/DELETE /api/admin/diagrams/**`（共 5 个端点）已实施。
- 此前已补齐：`GET /api/admin/clients/name-availability`、`GET /api/public/peer-mesh/nat-probe-config`，并修正
  `GET /api/public/transfer/clients/name-availability` 的注册路径。

## 3. 轻微差异（当前剩余 7 项）

| 编号 | 状态 | 子系统 | 差异 |
| --- | --- | --- | --- |
| T-1 | MINOR | 协议 `readString` | Go marker-0 返回 `""`；Java 返回 `null`（`LoginResponse.reason` 的 null≠"" 不对称，实际不影响互操作） |
| T-2 | MINOR | Nonce 防重放键 | Go `(sha256(apiKey), sha256(nonce))` 复合键；Java `sha256(sha256(apiKey)+"\n"+nonce)` 单键（功能等价，DB 键形不同，行 120s 过期） |
| T-3 | MINOR | 登录线程池 | Go 固定 32 worker；Java 弹性 core 8->max 32（低并发时 Java 线程更少） |
| T-4 | ALIGNED | 连接记录启动/关停清理 | Go 已增加 `SERVER_RESTARTED` 启动 sweep 和 `SERVER_SHUTDOWN` 优雅关停 sweep。 |
| T-5 | ALIGNED | DB 表集合 | 5 张房间/流程图表已补齐到全部 3 个 schema，`tunnel_websocket_ticket.room_role` 纳入启动列迁移。 |
| T-6 | MINOR | 配置键 | 登录 core-size、DB 连接模型、Netty 调优旋钮、route-cache-ttl 各有缺失。 |
| T-7 | ALIGNED | Direct HTTP 离线状态码 | Go 实际响应路径已改为 502，并有 handler 测试覆盖。 |
| T-8 | ALIGNED | 413 预检 | Java `HttpTunnelBodyLimitFilter` 已在 Content-Length 短路时记录 413 交换，与 Go 行为一致。 |
| T-9 | MINOR | 搜索字段别名 | Go 有 `headers`/`body` 组合别名 + `_`/`-` 归一化；Java 无 |
| T-10 | MINOR | 路径去重 | Java 全 body placeholder 防双前缀；Go 属性级 `shouldRewritePath`（JS 字面量可能双前缀） |
| T-11 | MINOR | TLS PEM/双配置 | Java 不支持裸 PEM cert+key 且 TLS 配置分散两处；Go 单配置覆盖两端且支持 PEM（双向各有取舍） |

## 4. 已对齐的核心子系统

以下子系统经代码级比对确认对齐：

- **协议编解码**：11 字节帧头、varint/zigzag、UUID canonical-lowercase-only、HTTP method exact-match、
  nil-vs-empty-slice、nullable-long-0L、NAT_MESSAGE 16 字节头、尾随字节检查。
- **HMAC 登录签名**：HMAC-SHA256、sha256(secret) 密钥、canonical message、±60s 窗口、每分钟 30 次限流、
  machineFingerprint+osUser 身份、REPLACED_BY_NEW_LOGIN 顶替、常量时间比较、`cs_`+64hex token。
- **控制通道**：TCP 帧、60s 读空闲断开、30s 写空闲发 HeartbeatResponse、心跳写失败断开、
  SERVER_BUSY 队满、pre-auth 16KiB 帧限、未认证即断、连接审计落库、断开原因 first-wins。
- **写背压**：高低水位默认 32KB/64KB、`TUNNEL_NETTY_WRITE_BUFFER_*`、控制/外部读写联动暂停恢复、
  WINDOW_UPDATE 优先写旁路。
- **NAT TCP 转发**：per-port listener、REGISTER/UNREGISTER/DATA/DISCONNECTED、FIN/RST 处理、
  WINDOW_UPDATE 信用门控、NAT_CONTROL 登录后推送 + CRUD 变更推送、流量 5s 刷盘 + 失败回补。
- **Direct HTTP**：`/http/{client}/{route}/{**rest}` 原始路径编码保留（`%2F` 不折叠、UTF-8 保留）、
  hop-by-hop 头过滤、timeout 30s、请求体 16MB、响应体 64MB。
- **响应改写**：pathRewriteEnabled、HTML/CSS 属性改写、polyfill 脚本（fetch/XHR/history/
  EventSource/WebSocket）、Content-Encoding/Length 剥离、gzip/deflate/raw-deflate 解码（br 改写路径两端都不支持）。
- **流量明细采集**：三张明细表、队列模型（MAX_PENDING/FLUSH_BATCH_SIZE/FLUSH_INTERVAL_MS）、
  flush=true、2s 决策缓存、采样率、`q` 空白分词 AND、method/status 精确匹配、头掩码、
  gzip/deflate/raw-deflate/br 预览解码（多编码链）。
- **连接归档**：ArchiveOldConnections、保留天数 60、UTC 日边界、tenantId+clientName+statMonth 聚合、
  upsert+同事务删除、failure=total-success。
- **WebSocket 事件**：`/ws/connections`、403+X-Auth-Reason、tenant/owner 过滤、created/updated 事件、集群扇出。
- **Elasticsearch**：`TUNNEL_ELASTICSEARCH_URIS`、DB->ES 后端切换、index ensure、100GB/10GB 清理、
  查询 DSL、文档 ID 生成（millis<<20|seq）。
- **TURN 认证**：temp HMAC-SHA1 credential、realm/nonce、MESSAGE-INTEGRITY、401/438、有效期窗口、
  clientID 提取。
- **Peer Mesh 控制面**：device/acl/session schema、默认 CIDR 100.96.0.0/11、同租户/owner 默认放行、
  ACL 方向（OUTBOUND/INBOUND/BOTH）、session 授权、roster/config 推送、设备/路径/流量上报、force-close。
- **Peer Mesh stats**：reportedSessions=count(rttMillis)、activeDirectRatio、pathType×status、natTypes 分布。
- **SPM2 relay 计量**：Send Indication + ChannelData 热路径计量、relay-receive 不重复计、
  pendingRelayBytes 累积、5s flush、失败回补、饱和加法。
- **公共互传**：6 附件 REST、Aliyun OSS V4 预签名、一次性下载授权、HEAD 校验、过期清理、
  discovery roomToken 隔离/同 IP 邻近房间/限流/roster/定向 signal。
- **客户端消息**：`/ws/client-messages`、mgmt JWT 鉴权、case-sensitive tenant/owner、
  NETTY_ONLINE 接收能力检查、CLIENT_TO_CLIENT fallback、64K UTF-16 限制。
- **OIDC**：RS256/JWKS 校验+缓存+轮换重取、iss/aud/exp/nbf+60s skew、`/oidc/token` 授权码交换、
  `TUNNEL_OIDC_TENANT_CLAIM`。
- **帧边界**：11 字节头 + body = 32MiB、max body = config - 11、pre-auth 16KiB。

## 5. 修复优先级

原优先级队列已全部清零：P0 S-1、P1 S-3/S-5、P2 S-7 均已修复并验证。剩余 7 项轻微差异
（见第 3 节）不计划处理，理由见 `go-server-parity-implementation-plan.md` 末尾的取舍说明。

## 6. 相关文档

- Go server 移植计划：`tunnel-server-go-port-plan.md`
- 总对齐计划：`cross-language-java-alignment-plan.md`
- E2E 验收矩阵：`cross-language-e2e-acceptance-matrix.md`
