# Go Server systemd Deployment

## Prerequisites

- **Go 1.26+** installed on build machine
- **Node.js** (for building admin SPA, `npm run deploy:go`)
- Target host: Linux amd64/arm64 with systemd

## Build

```bash
# From repo root, build the Go binary with embedded SPA
cd implementations/go/server
go generate ./web              # builds admin SPA into web/static via npm run deploy:go
go build -o shuai-tunnel-server ./cmd/shuai-tunnel-server
```

The binary `shuai-tunnel-server` is statically linked (pure Go, no CGO), ~20 MB.

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
| `/var/log/tunnel-server-go/` | Journald only (binary logs to stderr) |

## Environment variables

The same `TUNNEL_*` naming as Java server. Key variables:

| Variable | Example | Description |
|----------|---------|-------------|
| `TUNNEL_MANAGEMENT_ADDR` | `:8088` | Management HTTP listen address |
| `TUNNEL_NETTY_PORT` | `7010` | Control channel TCP port |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | `host=...` | Database connection string |
| `TUNNEL_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | Enable or disable local password login |
| `TUNNEL_AUTH_USERNAME` | `admin` | Management UI local-login username |
| `TUNNEL_AUTH_PASSWORD` | `change-me` | Management UI local-login plaintext password; protect the env file and change it before exposure |
| `TUNNEL_AUTH_TENANT_ID` | `default` | Tenant id for the built-in administrator |
| `TUNNEL_AUTH_JWT_SECRET` | long random value | Stable HS256 signing secret; if omitted, a random in-memory key invalidates tokens after every restart |
| `TUNNEL_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management JWT lifetime |
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

## Health check

`GET /health` is the public liveness endpoint and is the default used by `update.sh`. Set
`TUNNEL_HEALTH_URL` only when the service is exposed on a different local address or path.
