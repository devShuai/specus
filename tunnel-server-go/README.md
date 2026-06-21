# tunnel-server-go

Go 实现的 shuai-tunnel 服务端,与 Java client / C# server **线协议字节兼容**(11 字节帧头 + CompactBinary + NAT_MESSAGE + HMAC 登录)。纯 Go 实现,依赖仅限数据库驱动与 WebSocket 库。

## 运行

```bash
cd tunnel-server-go
go build ./cmd/shuai-tunnel-server
./shuai-tunnel-server                 # 默认 SQLite + 控制端口 7010 + 管理端口 8088
./shuai-tunnel-server -config cfg.json
```

- 控制通道(Netty 等价)默认监听 `7010`,Java/Go client 连这里。
- 管理后台 + Direct HTTP + WebSocket 默认监听 `:8088`,浏览器访问 `http://127.0.0.1:8088/`。
- 默认 seed 演示客户端 `Demo client / test1234`(可关)。
- 管理后台默认账号 `admin / admin`。

## 配置

可用 JSON 文件(`-config`)或 `TUNNEL_*` 环境变量(env 覆盖文件)。

| 环境变量 | 说明 | 默认 |
| --- | --- | --- |
| `TUNNEL_NETTY_PORT` | 控制通道端口 | 7010 |
| `TUNNEL_MANAGEMENT_ADDR` | 管理 HTTP 监听地址 | `:8088` |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | sqlite |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | 数据库连接串 | `./shuai-tunnel.db` |
| `TUNNEL_DB_SEED_DEMO_CLIENT` | 是否 seed 演示客户端 | true |
| `TUNNEL_AUTH_USERNAME` / `TUNNEL_AUTH_PASSWORD` | 管理后台账号 | admin / admin |
| `TUNNEL_AUTH_JWT_SECRET` | 本地 JWT 签名密钥(空则随机,重启失效) | - |
| `TUNNEL_PUBLIC_ADDRESS` | 下发给 client 的公网地址 | - |
| `TUNNEL_HTTP_TIMEOUT_MS` / `TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE` | Direct HTTP 超时 / 体积上限 | 30000 / 16MiB |
| `TUNNEL_TLS_MODE` | `disabled` / `file` / `self-signed` | disabled |
| `TUNNEL_TLS_CERT_FILE` / `TUNNEL_TLS_KEY_FILE` | PEM 证书/私钥(mode=file) | - |
| `TUNNEL_OIDC_CLIENT_ID` / `TUNNEL_OIDC_CLIENT_SECRET` / `TUNNEL_OIDC_TOKEN_ENDPOINT` / `TUNNEL_OIDC_JWK_SET_URI` … | OIDC 单点登录 | - |

### 切换数据库

```bash
# PostgreSQL
TUNNEL_DB_PROVIDER=postgres \
TUNNEL_CONNECTIONSTRINGS_TUNNEL="postgres://user:pass@localhost:5432/shuai?sslmode=disable" \
./shuai-tunnel-server

# MySQL
TUNNEL_DB_PROVIDER=mysql \
TUNNEL_CONNECTIONSTRINGS_TUNNEL="user:pass@tcp(localhost:3306)/shuai?parseTime=true" \
./shuai-tunnel-server
```

启动时按 dialect 用 `CREATE TABLE IF NOT EXISTS` 幂等建表(`internal/store/schema/*.sql`),六张表与 C#/Java 对齐;时间戳统一存 ISO-8601 字符串以保证字典序=时序。

### TLS

```bash
TUNNEL_TLS_MODE=self-signed ./shuai-tunnel-server     # 启动时现场生成自签证书
TUNNEL_TLS_MODE=file TUNNEL_TLS_CERT_FILE=cert.pem TUNNEL_TLS_KEY_FILE=key.pem ./shuai-tunnel-server
```

TLS 同时作用于控制通道与管理 HTTP。当前仅支持 PEM / 自签(PKCS12 暂未实现)。

## 测试

```bash
go test ./...    # 协议 fixtures、登录/心跳、NAT 回环、admin API、OIDC、TLS
go vet ./...
```

协议层用仓库内 `csharp/tests/fixtures/*.bin`(已复制进 `internal/protocol/testdata`)做 golden 交叉校验:非压缩帧字节级一致,deflate 帧因 Go `compress/flate` 与 Java/.NET zlib 输出不同改为语义自洽校验(可互相解压,完全互通)。

## 包结构

- `internal/protocol` — 双向编解码(帧 + CompactBinary + NAT + HMAC)
- `internal/config` — 配置 + `TUNNEL_*` 映射
- `internal/store` — 多库抽象 + schema + 查询/CRUD/归档
- `internal/auth` — HMAC 登录校验、密码 hash、限流、id 生成
- `internal/session` — 会话注册表(同名登录顶替)
- `internal/control` — 监听器、连接、帧读写、空闲/心跳看门狗、登录线程池
- `internal/nat` — 远端端口管理、外部连接桥接、NAT_CONTROL 下发、流量统计
- `internal/directhttp` — Direct HTTP 转发 + 入口
- `internal/management` — admin REST API + DTO
- `internal/security` — 本地 JWT(HS256)、OIDC(RS256/JWKS + token 交换)、TLS
- `internal/wsevents` — `/ws/connections` 事件广播
- `web` — 内嵌 SPA 静态资源
