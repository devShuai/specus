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

产物位于 `deploy/go-server/out/specus-server-linux-amd64`，并同时生成
`tar.gz`、SHA-256 校验文件和构建清单。

手工构建：

```bash
# From repo root, build the Go binary with embedded SPA
cd implementations/go/server
go generate ./web              # builds admin SPA into web/static via npm run deploy:go
go build -o specus-server ./cmd/specus-server
```

The binary `specus-server` is statically linked (pure Go, no CGO). Its size depends on
the embedded management SPA and diagram stencil library.

## Remote deployment

从 Windows 通过 SSH 首次安装或滚动更新（默认目标 `ali2`）：

```powershell
.\deploy\go-server\remote\deploy.ps1 -HostName ali2 -Yes
```

该入口默认同时更新 Go 服务和 OpenResty 管理前端，并验证公网首页及 hash 静态资源。
仅需更新后端时可显式传入 `-SkipFrontend`。

首次安装建议传入 `-EnvFile`；未传时只安装模板，不启动默认配置。详细说明见
[`../remote/README.md`](../remote/README.md)。

## First-time Install

```bash
sudo bash deploy/go-server/systemd/install.sh /path/to/specus-server
```

安装器只注册并 enable systemd unit，不会启动或重启服务，也不会覆盖已有的
`/etc/specus-server-go/specus-server.env`。模板显式使用 `SPECUS_ENV=prod`，关闭 demo seed
和本地密码登录，管理密码与 JWT 密钥保持为空。需要本地登录时，先生成独立强口令和稳定
JWT 密钥，再写入受保护的 env 并启用登录开关。

### Upgrading from an older release

On the first `prod` startup after upgrading, two enabled legacy rows are matched and disabled
independently: the client account whose exact name is `Demo client` and whose password digest still
matches historical value `test1234`, and the credential whose exact API key is `demo-client` and
whose secret digest still matches `test1234`. Rotated credentials, rows that only share the name/key
but have another digest, and already-disabled rows are unchanged. These historical values describe
migration matching, not production credential examples. The cleanup is idempotent, and production
never re-seeds demo data.

## Rolling Update

```bash
sudo bash deploy/go-server/systemd/update.sh /path/to/specus-server
```

## Files layout on target

| Path | Purpose |
|------|---------|
| `/opt/specus-server-go/specus-server` | Binary (mode 0755, root:root) |
| `/etc/specus-server-go/specus-server.env` | Runtime environment variables (0640, root:specus) |
| `/etc/specus-server-go/specus-server.env.example` | Template, never overwrites live env |
| `/var/lib/specus-server-go/` | Working directory (SQLite default path, 0750, specus:specus) |
| `/var/log/specus-server-go/specus-server.log` | Complete process output: slog, standard log, stdout/stderr, HTTP access/error logs and panics |
| `/etc/logrotate.d/specus-server-go` | Daily/50 MiB rotation, 14 compressed generations |

## Environment variables

The same `SPECUS_*` naming as Java server. Key variables:

| Variable | Example | Description |
|----------|---------|-------------|
| `SPECUS_MANAGEMENT_ADDR` | `:8088` | Management HTTP listen address |
| `SPECUS_LOG_FILE` | empty | Standalone-binary file tee; the systemd unit forces this empty because it captures stdout/stderr directly |
| `SPECUS_NETTY_PORT` | `7010` | Control channel TCP port |
| `SPECUS_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `SPECUS_CONNECTIONSTRINGS_SPECUS` | `host=...` | Database connection string |
| `SPECUS_ENV` | `prod` | Deployment environment; empty or unknown values are treated as production |
| `SPECUS_DB_SEED_DEMO_CLIENT` | `false` | Production template never seeds demo credentials |
| `SPECUS_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` | `false` | Local password login is safe-off in the production template |
| `SPECUS_AUTH_REGISTRATION_ENABLED` | `false` in deploy template | Enable verified self-registration after Turnstile and SMTP are configured |
| `SPECUS_AUTH_USERNAME` | `admin` | Management UI local-login username |
| `SPECUS_AUTH_PASSWORD` | empty | Management UI local-login password; generate a unique strong value before enabling login |
| `SPECUS_AUTH_TENANT_ID` | `default` | Tenant id for the built-in administrator |
| `SPECUS_AUTH_JWT_SECRET` | empty | Generate a stable HS256 secret before enabling login; an empty value uses an in-memory key and invalidates tokens after restart |
| `SPECUS_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management JWT lifetime |
| `SPECUS_AUTH_TURNSTILE_ENABLED` | `false` | Require Cloudflare Turnstile for local password login; must be enabled for self-registration |
| `SPECUS_AUTH_TURNSTILE_SITE_KEY` / `SPECUS_AUTH_TURNSTILE_SECRET_KEY` | provider values | Browser site key and server-only verification secret |
| `SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES` | deployment hostnames | Required hostname allowlist checked after Siteverify |
| `SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED` | `false` | Require a one-time email code before creating a self-registered account |
| `SPECUS_AUTH_SMTP_HOST` / `SPECUS_AUTH_SMTP_PORT` | provider values | SMTP endpoint used to send registration codes |
| `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default online-instance limit per client credential |
| `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Online-instance limit for the same machine fingerprint and OS user |
| `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Client runtime token lifetime |

The complete deploy-time variable list, including Peer Mesh, TURN authentication, traffic-capture
limits, object storage, and public transfer, is maintained in
[`specus-server.env.example`](./specus-server.env.example).

systemd `EnvironmentFile` does not perform shell command substitution. Generate a JWT secret separately (for example,
`openssl rand -base64 48`) and paste the resulting literal value into `SPECUS_AUTH_JWT_SECRET`.

## Network ports

- TCP `7010` is the client control channel and TCP `8088` is the default management HTTP listener.
- When Peer Mesh is enabled, allow UDP `3478` for STUN/TURN and UDP `3479` for the alternate NAT probe. Both ports are configurable through the environment template.
- TURN relay allocations bind UDP ports from `49152-65535` by default. Open the configured inclusive range from `SPECUS_PEER_MESH_RELAY_MIN_PORT` through `SPECUS_PEER_MESH_RELAY_MAX_PORT`; narrowing the range also limits concurrent relay allocations.

The install scripts do not modify the host firewall or cloud security-group rules.

## systemd unit

Installed as `specus-server-go.service`. Hardened with:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/specus-server-go /var/log/specus-server-go`
- `LimitNOFILE=65536`
- Runs as `specus` user, `specus` group
- Captures complete stdout/stderr in `/var/log/specus-server-go/specus-server.log`; logrotate uses `copytruncate`

## Logs

```bash
sudo tail -F /var/log/specus-server-go/specus-server.log
sudo grep 'level=ERROR' /var/log/specus-server-go/specus-server.log
```

Every management HTTP response records only its method, route template, status, response size and
duration. Request bodies, headers, query strings and concrete URL path parameters are excluded so
passwords, bearer credentials and transfer tokens do not enter the access log. HTTP panics include
a stack trace. `journalctl -u specus-server-go` still reports systemd lifecycle events, but process
output is intentionally routed to the file instead of duplicated in journald.

## Health check

`GET /health` is the public liveness endpoint and is the default used by `update.sh`. Set
`SPECUS_HEALTH_URL` only when the service is exposed on a different local address or path.
