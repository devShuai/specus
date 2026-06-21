# tunnel-server Go 移植计划与状态

Go 实现的 shuai-tunnel 服务端(`tunnel-server-go/`),module `github.com/devShuai/shuai-tunnel/tunnel-server-go`,Go 1.26。与 Java client / C# server 线协议字节兼容。分 5 个阶段交付,每阶段 `go build ./... && go test ./... && go vet ./...` 全绿。

## 项目布局

```
tunnel-server-go/
├── cmd/shuai-tunnel-server/main.go
├── web/static/{index.html,app.js,app.css}   # 内嵌 SPA(同 Java/C#)
└── internal/{protocol,config,store,auth,session,control,nat,directhttp,management,security,wsevents}
```

依赖:`modernc.org/sqlite`(纯 Go)、`github.com/jackc/pgx/v5`、`github.com/go-sql-driver/mysql`、`github.com/coder/websocket`;JWT(HS256/RS256)、OIDC、TLS(PEM/自签)均 stdlib 手写。

## 阶段

### G1 — 协议库 ✅
- 双向编解码:11 字节帧头、CompactBinary(varint/zigzag/UUID/枚举/字符串表 + ≥64B 自动 raw deflate)、NAT_MESSAGE(`type|metaLen|json meta|payload`)、HMAC 登录签名。
- **验收**:`go test ./internal/protocol`;21 个 golden fixtures 全部交叉校验(非压缩字节级一致,deflate 语义自洽)。

### G2 — 控制通道 + 登录 + 多库持久化 ✅
- TCP 监听、帧读写、60s 读 / 30s 写空闲心跳看门狗、有界登录线程池(满则 SERVER_BUSY)、HMAC 校验 + ±30s 窗口 + 每分钟频率限制、会话顶替(REPLACED_BY_NEW_LOGIN)、连接审计落库。
- 多库 store:sqlite/postgres/mysql,embed schema 幂等建表,六表对齐。
- **验收**:登录成功 / 错密码拒绝 / 未认证即断开 / 心跳回环 / 连接记录落库。

### G3 — NAT TCP 转发 + 背压 + 流量 ✅
- 每端口 listener、外部连接读循环→DATA、REGISTER/UNREGISTER/DATA/DISCONNECTED/KEEPALIVE、三级连接限额 + 全局计数、登录后推 NAT_CONTROL、流量 5s 刷盘。
- 背压:控制通道写串行化 → 慢 client 自然回压外部读循环(无丢字节、内存有界)。
- **验收**:REGISTER → 外部连入 → 8KiB + 1MiB 双向回环 → 流量计数双向 > 0。

### G4 — 管理 API + JWT + WebSocket + Direct HTTP + SPA + 归档 ✅
- 全量 `/auth/*`、`/api/admin/*`(overview/clients/tunnels/http-routes/connections/traffic/connection-stats/nat-control/database-initialize)、`/oidc-config`、`/health`。
- 本地 HS256 JWT;`/ws/connections`(?token,403+X-Auth-Reason)连接事件广播;Direct HTTP `/http/{client}/{route}/{**rest}`;CRUD 后热推 NAT_CONTROL;改名/停用/删除踢线;CSP/安全头;SPA go:embed;每小时归档 60 天前连接→月度统计。
- **验收**:admin 鉴权 / 登录 / overview / client+tunnel CRUD / nat-control 离线 409 / 路由校验 / Direct HTTP 离线 503。

### G5 — OIDC + TLS ✅
- OIDC:RS256/JWKS 校验(缓存 + 轮换重取,iss/aud/exp/nbf + 60s skew),`/oidc/token` 授权码交换(confidential→Basic,public→client_id 表单);admin 鉴权本地 HS256 优先、OIDC RS256 兜底。
- TLS:`disabled`/`file`(PEM)/`self-signed`(启动生成),作用于控制通道 + 管理 HTTP。
- **验收**:本地 JWT 往返、OIDC 交换(mock IdP)、TLS 模式加载(disabled→nil / self-signed→证书 / 未知→报错)。

## 能力 × 验证矩阵

| 能力 | 验证方式 | 状态 |
| --- | --- | --- |
| 线协议字节兼容 | `internal/protocol` golden fixtures | ✅ |
| HMAC 登录 + 限流 + 心跳 | `internal/server` 集成测试 | ✅ |
| 多库(sqlite/pg/mysql) | schema 幂等建表 + sqlite 集成测试 | ✅(sqlite 跑测试;pg/mysql 编译+SQL 就绪) |
| NAT TCP 转发 + 背压 + 流量 | NAT 回环集成测试(含 1MiB) | ✅ |
| admin API + JWT | httptest 集成测试 | ✅ |
| WebSocket 事件 | hub 实现 + 登录/断开广播接线 | ✅(端到端 WS 客户端测试待补) |
| Direct HTTP | 离线 503 测试 + 转发实现 | ✅ |
| SPA | go:embed + `/` 文件服务 | ✅ |
| 连接归档 | `ArchiveOldConnections` + 定时 | ✅ |
| OIDC | mock IdP 交换测试 + RS256 校验 | ✅ |
| TLS | 模式加载测试(PEM/自签) | ✅(PKCS12 未实现) |

## 常用命令

```bash
cd tunnel-server-go
go build ./...
go test ./...
go vet ./...
go run ./cmd/shuai-tunnel-server
```

## 已知简化 / 待办

- 背压用"同步写 + 自然 TCP 回压"代替 C# 的显式 high/low watermark 门控:正确且内存有界,但单 client 多隧道间可能存在队头阻塞;如需可后续引入按隧道独立的 gate。
- TLS 仅 PEM / 自签,PKCS12 未实现。
- WebSocket 已接线广播,端到端 WS 客户端订阅测试待补。
- Java client × Go server 的 jar 级 E2E 可作为可选手动验证(协议已由 fixtures 保证字节兼容)。
