# C# Server systemd Deployment

## Prerequisites

- **.NET 10.0 SDK** on build machine (see `src/ShuaiTunnel.Server/ShuaiTunnel.Server.csproj`, target `net10.0`)
- **Node.js** (for building admin SPA, `npm run deploy:csharp`)
- Target host: Linux amd64/arm64 with systemd + **ASP.NET Core Runtime 10.0**.

The supplied `install.sh` and systemd unit support the framework-dependent publish layout only: they require
`ShuaiTunnel.Server.dll` and start it with `/usr/bin/dotnet`. A self-contained publish needs a different unit and
is not handled by these scripts.

## Build

```bash
# Framework-dependent (requires ASP.NET Core Runtime on host)
dotnet publish implementations/csharp/server/src/ShuaiTunnel.Server/ShuaiTunnel.Server.csproj \
  -c Release -o publish/shuai-tunnel-csharp

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

Start from [`tunnel-server.env.example`](./tunnel-server.env.example). Its checked-in defaults keep
password login, Peer Mesh, and object storage disabled and contain no usable credential. To enable
local management login, generate a unique password and JWT secret first, write both into the
root-owned `0640` environment file, and only then set `TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED=true`.
Self-service registration additionally requires Cloudflare Turnstile, verified-email settings,
and SMTP. The C# server supports implicit TLS on port 465 and STARTTLS on port 587 through MailKit.

| Variable | Example | Description |
|----------|---------|-------------|
| `ASPNETCORE_URLS` | `http://0.0.0.0:8088` | Kestrel listen address |
| `ASPNETCORE_ENVIRONMENT` | `Production` | Environment name |
| `TUNNEL_NETTY_PORT` | `7010` | Control channel TCP port |
| `TUNNEL_NETTY_MAX_FRAME_SIZE` | `33554432` | Complete control-frame cap including the 11-byte header (max body `33554421`) |
| `TUNNEL_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `TUNNEL_CONNECTIONSTRINGS_TUNNEL` | `host=...` | Database connection string |
| `TUNNEL_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED` | `false` | Enable or disable local password login; template default is safe-off |
| `TUNNEL_AUTH_REGISTRATION_ENABLED` | `false` | Enable verified-email self-service registration after all dependencies are configured |
| `TUNNEL_AUTH_USERNAME` | `admin` | Management UI local-login username |
| `TUNNEL_AUTH_PASSWORD` | `change-me` | Management UI local-login plaintext password; protect the env file and change it before exposure |
| `TUNNEL_AUTH_TENANT_ID` | `default` | Tenant id for the built-in administrator |
| `TUNNEL_AUTH_JWT_SECRET` | long random value | Stable HS256 signing secret; if omitted, a random in-memory key invalidates tokens after every restart |
| `TUNNEL_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management JWT lifetime |
| `TUNNEL_AUTH_TURNSTILE_*` | disabled | Cloudflare site key, server secret, Siteverify URL, and exact hostname allowlist |
| `TUNNEL_AUTH_EMAIL_*` | disabled | Verification sender, code TTL, attempt limit, resend cooldown, and cleanup interval |
| `TUNNEL_AUTH_SMTP_*` | disabled | SMTP endpoint, credentials, authentication, STARTTLS, or implicit TLS settings |
| `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default online-instance limit per client credential |
| `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Online-instance limit for the same machine fingerprint and OS user |
| `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Client runtime token lifetime |

systemd `EnvironmentFile` does not perform shell command substitution. Generate a JWT secret separately (for example,
`openssl rand -base64 48`) and paste the resulting literal value into `TUNNEL_AUTH_JWT_SECRET`.

## Peer Mesh / TURN firewall

When `TUNNEL_PEER_MESH_ENABLED=true`, publish the configured UDP listeners and relay range in the
host firewall/security group:

- `TUNNEL_PEER_MESH_STUN_TURN_PORT` (default UDP `3478`) for STUN/TURN;
- `TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` (default UDP `3479`) for alternate-address NAT probes;
- every UDP port from `TUNNEL_PEER_MESH_RELAY_MIN_PORT` through
  `TUNNEL_PEER_MESH_RELAY_MAX_PORT` (default `49152-65535`) for TURN relays.

Also set `TUNNEL_PEER_MESH_PUBLIC_ADDRESS` to the externally reachable host/address and configure a
non-empty `TUNNEL_PEER_MESH_TURN_SHARED_SECRET` before exposing TURN. The complete option mapping is
kept in [`tunnel-server.env.example`](./tunnel-server.env.example).

## systemd unit

Installed as `tunnel-server-csharp.service`. Hardened identically to the Java unit:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/tunnel-server-csharp /var/log/tunnel-server-csharp`
- `LimitNOFILE=65536`
- Runs as `tunnel` user, `tunnel` group

## Health check

`GET /health` returns `{"status":"ok"}` on HTTP 200. The `update.sh` script polls this endpoint.
