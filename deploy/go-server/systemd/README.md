# Go Server systemd Deployment

## Prerequisites

- **Go 1.26+** installed on build machine
- **Node.js** (for building admin SPA, `npm run deploy:go`)
- Target host: Linux amd64/arm64 with systemd

## Build

Windows PowerShell 一键交叉编译（默认包含管理前端和 Go 测试）：

```powershell
.\deploy\go-server\build-linux.ps1 -Architecture amd64
```

产物位于 `deploy/go-server/out/shuai-tunnel-server-linux-amd64`，并同时生成
`tar.gz`、SHA-256 校验文件和构建清单。

手工构建：

```bash
# From repo root, build the Go binary with embedded SPA
cd implementations/go/server
go generate ./web              # builds admin SPA into web/static via npm run deploy:go
go build -o shuai-tunnel-server ./cmd/shuai-tunnel-server
```

The binary `shuai-tunnel-server` is statically linked (pure Go, no CGO). Its size depends on
the embedded management SPA and diagram stencil library.

## Remote deployment

从 Windows 通过 SSH 首次安装或滚动更新（默认目标 `ali2`）：

```powershell
.\deploy\go-server\remote\deploy.ps1 -HostName ali2 -Yes
```

首次安装建议传入 `-EnvFile`；未传时只安装模板，不启动默认配置。详细说明见
[`../remote/README.md`](../remote/README.md)。

## First-time Install

```bash
sudo bash deploy/go-server/systemd/install.sh /path/to/shuai-tunnel-server
```

## Rolling Update

```bash
sudo bash deploy/go-server/systemd/update.sh /path/to/shuai-tunnel-server
```

## Files layout on target

| Path | Purpose |
|------|---------|
| `/opt/tunnel-server-go/shuai-tunnel-server` | Binary (mode 0755, root:root) |
| `/etc/tunnel-server-go/tunnel-server.env` | Runtime environment variables (0640, root:tunnel) |
| `/etc/tunnel-server-go/tunnel-server.env.example` | Template, never overwrites live env |
| `/var/lib/tunnel-server-go/` | Working directory (SQLite default path, 0750, tunnel:tunnel) |
| `/var/log/tunnel-server-go/tunnel-server.log` | Complete process output: slog, standard log, stdout/stderr, HTTP access/error logs and panics |
| `/etc/logrotate.d/tunnel-server-go` | Daily/50 MiB rotation, 14 compressed generations |

## Environment variables

The same `TUNNEL_*` naming as Java server. Key variables:

| Variable | Example | Description |
|----------|---------|-------------|
| `TUNNEL_MANAGEMENT_ADDR` | `:8088` | Management HTTP listen address |
| `TUNNEL_LOG_FILE` | empty | Standalone-binary file tee; the systemd unit forces this empty because it captures stdout/stderr directly |
| `TUNNEL_NETTY_PORT` | `7010` | Control channel TCP port |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | `host=...` | Database connection string |
| `TUNNEL_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | Enable or disable local password login |
| `TUNNEL_AUTH_REGISTRATION_ENABLED` | `false` in deploy template | Enable verified self-registration after Turnstile and SMTP are configured |
| `TUNNEL_AUTH_USERNAME` | `admin` | Management UI local-login username |
| `TUNNEL_AUTH_PASSWORD` | `change-me` | Management UI local-login plaintext password; protect the env file and change it before exposure |
| `TUNNEL_AUTH_TENANT_ID` | `default` | Tenant id for the built-in administrator |
| `TUNNEL_AUTH_JWT_SECRET` | long random value | Stable HS256 signing secret; if omitted, a random in-memory key invalidates tokens after every restart |
| `TUNNEL_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management JWT lifetime |
| `TUNNEL_AUTH_TURNSTILE_ENABLED` | `false` | Require Cloudflare Turnstile for local password login; must be enabled for self-registration |
| `TUNNEL_AUTH_TURNSTILE_SITE_KEY` / `TUNNEL_AUTH_TURNSTILE_SECRET_KEY` | provider values | Browser site key and server-only verification secret |
| `TUNNEL_AUTH_TURNSTILE_ALLOWED_HOSTNAMES` | deployment hostnames | Required hostname allowlist checked after Siteverify |
| `TUNNEL_AUTH_EMAIL_VERIFICATION_ENABLED` | `false` | Require a one-time email code before creating a self-registered account |
| `TUNNEL_AUTH_SMTP_HOST` / `TUNNEL_AUTH_SMTP_PORT` | provider values | SMTP endpoint used to send registration codes |
| `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default online-instance limit per client credential |
| `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Online-instance limit for the same machine fingerprint and OS user |
| `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Client runtime token lifetime |

The complete deploy-time variable list, including Peer Mesh, TURN authentication, traffic-capture
limits, object storage, and public transfer, is maintained in
[`tunnel-server.env.example`](./tunnel-server.env.example).

systemd `EnvironmentFile` does not perform shell command substitution. Generate a JWT secret separately (for example,
`openssl rand -base64 48`) and paste the resulting literal value into `TUNNEL_AUTH_JWT_SECRET`.

## Network ports

- TCP `7010` is the client control channel and TCP `8088` is the default management HTTP listener.
- When Peer Mesh is enabled, allow UDP `3478` for STUN/TURN and UDP `3479` for the alternate NAT probe. Both ports are configurable through the environment template.
- TURN relay allocations bind UDP ports from `49152-65535` by default. Open the configured inclusive range from `TUNNEL_PEER_MESH_RELAY_MIN_PORT` through `TUNNEL_PEER_MESH_RELAY_MAX_PORT`; narrowing the range also limits concurrent relay allocations.

The install scripts do not modify the host firewall or cloud security-group rules.

## systemd unit

Installed as `tunnel-server-go.service`. Hardened with:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/tunnel-server-go /var/log/tunnel-server-go`
- `LimitNOFILE=65536`
- Runs as `tunnel` user, `tunnel` group
- Captures complete stdout/stderr in `/var/log/tunnel-server-go/tunnel-server.log`; logrotate uses `copytruncate`

## Logs

```bash
sudo tail -F /var/log/tunnel-server-go/tunnel-server.log
sudo grep 'level=ERROR' /var/log/tunnel-server-go/tunnel-server.log
```

Every management HTTP response records only its method, route template, status, response size and
duration. Request bodies, headers, query strings and concrete URL path parameters are excluded so
passwords, bearer credentials and transfer tokens do not enter the access log. HTTP panics include
a stack trace. `journalctl -u tunnel-server-go` still reports systemd lifecycle events, but process
output is intentionally routed to the file instead of duplicated in journald.

## Health check

`GET /health` is the public liveness endpoint and is the default used by `update.sh`. Set
`TUNNEL_HEALTH_URL` only when the service is exposed on a different local address or path.
