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
| `TUNNEL_AUTH_ADMIN_USERNAME` | `admin` | Management UI admin username |
| `TUNNEL_AUTH_ADMIN_PASSWORD_HASH` | `$2a$10$...` | bcrypt hash |

## systemd unit

Installed as `tunnel-server-go.service`. Hardened with:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/tunnel-server-go /var/log/tunnel-server-go`
- `LimitNOFILE=65536`
- Runs as `tunnel` user, `tunnel` group