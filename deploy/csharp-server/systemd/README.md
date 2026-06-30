# C# Server systemd Deployment

## Prerequisites

- **.NET 10.0 SDK** on build machine (see `src/ShuaiTunnel.Server/ShuaiTunnel.Server.csproj`, target `net10.0`)
- **Node.js** (for building admin SPA, `npm run deploy:csharp`)
- Target host: Linux amd64/arm64 with systemd + **ASP.NET Core Runtime 10.0** (framework-dependent) or no runtime (self-contained)

## Build

```bash
# Framework-dependent (requires ASP.NET Core Runtime on host)
dotnet publish implementations/csharp/server/src/ShuaiTunnel.Server/ShuaiTunnel.Server.csproj \
  -c Release -o publish/shua-tunnel-csharp

# Self-contained (no runtime needed on host, larger binary)
dotnet publish implementations/csharp/server/src/ShuaiTunnel.Server/ShuaiTunnel.Server.csproj \
  -c Release -o publish/shua-tunnel-csharp \
  -r linux-x64 --self-contained true

# If building without Node.js, add: -p:TunnelServerWebSkip=true
# (admin-web must be pre-built into wwwroot/ separately)
```

Publish output:
- `ShuaiTunnel.Server.dll` (main assembly)
- `ShuaiTunnel.Server.deps.json`, `ShuaiTunnel.Server.runtimeconfig.json`
- `appsettings.json`, `appsettings.Production.json`
- `wwwroot/` (admin SPA static files)
- `runtimes/` (SQLite native binaries)
- Various dependency `.dll` files

## First-time Install

```bash
sudo bash deploy/csharp-server/systemd/install.sh /path/to/publish-output
```

## Rolling Update

```bash
sudo bash deploy/csharp-server/systemd/update.sh /path/to/publish-output
```

## Files layout on target

| Path | Purpose |
|------|---------|
| `/opt/tunnel-server-csharp/` | Publish output root (mode 0755, root:root) |
| `/etc/tunnel-server-csharp/tunnel-server.env` | Runtime environment variables (0640, root:tunnel) |
| `/etc/tunnel-server-csharp/tunnel-server.env.example` | Template, never overwrites live env |
| `/var/lib/tunnel-server-csharp/` | Working directory (SQLite default path, 0750, tunnel:tunnel) |
| `/var/log/tunnel-server-csharp/` | Logs (if file logging configured; default goes to journald) |

## Environment variables

Uses `TUNNEL_*` naming (translated to `Tunnel:*` config path by `TunnelEnvironmentVariables.cs`).
Overrides `appsettings.json` values.

| Variable | Example | Description |
|----------|---------|-------------|
| `ASPNETCORE_URLS` | `http://0.0.0.0:8088` | Kestrel listen address |
| `ASPNETCORE_ENVIRONMENT` | `Production` | Environment name |
| `TUNNEL_NETTY_PORT` | `7010` | Control channel TCP port |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | `host=...` | Database connection string |
| `TUNNEL_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `TUNNEL_AUTH_ADMIN_USERNAME` | `admin` | Management UI admin username |
| `TUNNEL_AUTH_ADMIN_PASSWORD_HASH` | `$2a$10$...` | bcrypt hash |

## systemd unit

Installed as `tunnel-server-csharp.service`. Hardened identically to the Java unit:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/tunnel-server-csharp /var/log/tunnel-server-csharp`
- `LimitNOFILE=65536`
- Runs as `tunnel` user, `tunnel` group

## Health check

`GET /health` returns `{"status":"ok"}` on HTTP 200. The `update.sh` script polls this endpoint.