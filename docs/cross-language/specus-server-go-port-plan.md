# specus-server Go 移植计划与状态

Go 实现的 specus 服务端(`implementations/go/server/`),module 为 `github.com/devShuai/specus/implementations/go/server`,Go 1.26。与 Java / Go / .NET / Android client 线协议兼容。分 6 个阶段交付；下述“全绿”是阶段交付时的历史记录，当前验证结果以 `cross-language-java-alignment-plan.md` 的“当前验证”为准。

与 Java server 的逐项对齐：2026-07-22 完成 `go-server-parity-implementation-plan.md` 全部 6 个批次（S-1..S-9、T-4/T-5/T-7/T-8 修复），实质差异清零，仅剩 7 项可接受的轻微差异；明细见 `go-server-vs-java-server-audit-2026-07.md`。

## 项目布局

```
implementations/go/server/
├── cmd/specus-server/main.go
├── web/static/{index.html,assets/**,...}    # 内嵌 SPA(同 Java/C#)
└── internal/{protocol,config,store,auth,session,control,nat,directhttp,management,transfer,security,wsevents,server}
```

直接依赖:`modernc.org/sqlite`(纯 Go)、`github.com/jackc/pgx/v5`、`github.com/go-sql-driver/mysql`、`github.com/coder/websocket`、`github.com/andybalholm/brotli` 和 `golang.org/x/crypto`。JWT(HS256/RS256)与 OIDC 核心逻辑基于 stdlib 实现；TLS 的 PEM/自签路径使用 stdlib，PKCS12/PFX 读取使用 `golang.org/x/crypto/pkcs12`。

## 阶段

### G1 — 协议库 ✅
- 双向编解码：v2 11 字节帧头、无压缩 envelope 的固定 schema CompactBinary、16 字节 NAT stream 头、JSON metadata 与原始 data、control/data 连接角色及 HMAC 登录签名。
- **验收**：`go test ./internal/protocol`；直接读取 `protocol/test-vectors/control-v2/frames` 的 34 个合法/非法 fixture，覆盖错误 version、serializer、command、长度、截断和尾随字节拒绝。

### G2 — 控制通道 + 登录 + 多库持久化 ✅
- TCP 监听、帧读写、60s 读 / 30s 写空闲心跳看门狗、有界登录线程池(满则 SERVER_BUSY)、HMAC 校验 + ±60s 窗口 + 每分钟频率限制、会话顶替(REPLACED_BY_NEW_LOGIN)、连接审计落库。
- 多库 store:sqlite/postgres/mysql,embed schema 幂等建表,六表对齐。
- **验收**:登录成功 / 错密码拒绝 / 未认证即断开 / 心跳回环 / 连接记录落库。

### G3 — NAT TCP 转发 + 背压 + 流量 ✅
- 每端口 listener、外部连接读循环→DATA、REGISTER/REGISTER_RESULT/OPEN/DATA/FIN/RST/WINDOW_UPDATE/UNREGISTER/KEEPALIVE、三级连接限额 + 全局计数、登录后推 NAT_CONTROL、流量 5s 刷盘。
- 背压:控制通道和外部 socket 写入都按 Java/.NET 对齐的 high/low watermark 统计待写字节；超过高水位暂停对应读循环，回落到低水位后恢复，避免慢 client 或慢公网连接造成无界积压。
- **验收**:REGISTER → 外部连入 → 8KiB + 1MiB 双向回环 → 流量计数双向 > 0。

### G4 — 管理 API + JWT + WebSocket + Direct HTTP + SPA + 归档 ✅
- 全量 `/auth/*`、`/api/admin/*`(overview/clients/specus-mappings/http-routes/connections/traffic/connection-stats/nat-control/database-initialize)、`/oidc-config`、`/health`。
- 本地 HS256 JWT;`/ws/connections`(?token,403+X-Auth-Reason)连接事件广播;Direct HTTP `/http/{client}/{route}/{**rest}`;CRUD 后热推 NAT_CONTROL;改名/停用/删除踢线;CSP/安全头;SPA go:embed;连接明细默认每小时归档 60 天前记录→月度统计，可通过 Java 同名 `SPECUS_CONNECTION_*` 环境变量调整。
- HTTP/TCP 明细采集热路径已改为 Java 对齐的队列模型：通道开启时先入队，后台按 `SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS` 批量写入 DB/ES，`SPECUS_TRAFFIC_CAPTURE_MAX_PENDING` 和 `SPECUS_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE` 控制积压与批量大小；明细查询默认不强制 flush，需要追最新数据时可显式传 `flush=true`。
- **验收**:admin 鉴权 / 登录 / overview / client+specus CRUD / nat-control 离线 409 / 路由校验 / Direct HTTP 离线 503。

### G5 — OIDC + TLS ✅
- OIDC:RS256/JWKS 校验(缓存 + 轮换重取,iss/aud/exp/nbf + 60s skew),`/oidc/token` 授权码交换(confidential→Basic,public→client_id 表单);admin 鉴权本地 HS256 优先、OIDC RS256 兜底。
- TLS:`disabled`/`file`(PKCS12/PFX 或 PEM)/`self-signed`(启动生成),作用于控制通道 + 管理 HTTP。
- **验收**:本地 JWT 往返、OIDC 交换(mock IdP)、TLS 模式加载(disabled→nil / self-signed→证书 / 未知→报错)。

### G6 — 公共互传、客户端消息、TURN 认证与帧边界 ✅
- `/api/public/transfer/ice-config`、6 个附件 REST 路径、Aliyun OSS 预签名/HEAD 校验/过期清理，以及按 IP/roomToken 的有界限流。
- `/ws/public-transfer/discovery` 按 roomToken 哈希或同公网 IP 隔离，支持 roster、定向 signal、房间人数与单连接消息限流；`/ws/client-messages` 支持 query-first/Bearer JWT、tenant/owner 和任一在线 receive-capable session 校验。
- TURN 临时 credential、realm/nonce、MESSAGE-INTEGRITY、401/438；完整帧上限包含 11 字节 header，非法配置拒绝。
- **验收**：server/client 全量 `go test -count=1 ./...` 与 `go build ./...` 通过；精确结果见总对齐计划“当前验证”。

## 能力 × 验证矩阵

| 能力 | 验证方式 | 状态 |
| --- | --- | --- |
| 线协议字节兼容 | `internal/protocol` golden fixtures | ✅ |
| HMAC 登录 + 限流 + 心跳 | `internal/server` 集成测试 | ✅ |
| 多库(sqlite/pg/mysql) | schema 幂等建表 + sqlite 集成测试 | ✅(sqlite 跑测试;pg/mysql 编译+SQL 就绪) |
| NAT TCP 转发 + 背压 + 流量 | NAT 回环集成测试(含 1MiB) | ✅ |
| admin API + JWT | httptest 集成测试 | ✅ |
| WebSocket 事件 | hub 实现 + 登录/断开广播接线 + 租户/owner 过滤 + 端到端 WS 客户端订阅测试 | ✅ |
| Direct HTTP | 离线 503 测试 + 转发实现 | ✅ |
| SPA | go:embed + `/` 文件服务 | ✅ |
| 连接归档 | `ArchiveOldConnections` + 定时 + `SPECUS_CONNECTION_*` 配置 | ✅ |
| OIDC | mock IdP 交换测试 + RS256 校验 | ✅ |
| TLS | 模式加载测试(PKCS12/PEM/自签) | ✅ |
| 公共发现 + 6 个附件接口 | WebSocket 隔离/限流测试 + OSS service/HTTP 集成测试 | ✅ |
| client-messages | Bearer/query 鉴权、多 session 能力、双向 fallback 测试 | ✅ |
| TURN auth | credential + MESSAGE-INTEGRITY + 401/438 测试 | ✅ |
| 完整帧边界 | 32 MiB header+body 等号/超限测试 | ✅ |

## 常用命令

```bash
cd implementations/go/server
go build ./...
go test ./...
go vet ./...
go run ./cmd/specus-server
```

## 已知简化 / 待办

- TLS 支持 PKCS12/PFX、PEM 和自签；真实生产证书链仍建议做环境级手工验收。
- Java client × Go server 的 jar 级 E2E 尚未形成持续执行证据；fixtures 只验证编解码，不能替代真实登录、心跳、TCP、HTTP 和 Peer Mesh 行为。它属于跨语言 P0 必测项，不是可选验收。
