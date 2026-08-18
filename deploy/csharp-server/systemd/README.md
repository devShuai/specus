# C# Server systemd Deployment

## Prerequisites

- **.NET 10.0 SDK** on build machine (see `src/Specus.Server/Specus.Server.csproj`, target `net10.0`)
- **Node.js** (for building admin SPA, `npm run deploy:csharp`)
- Target host: Linux amd64/arm64 with systemd + **ASP.NET Core Runtime 10.0**.

The supplied `install.sh` and systemd unit support the framework-dependent publish layout only: they require
`Specus.Server.dll` and start it with `/usr/bin/dotnet`. A self-contained publish needs a different unit and
is not handled by these scripts.

## Build

```bash
# Framework-dependent (requires ASP.NET Core Runtime on host)
dotnet publish implementations/csharp/server/src/Specus.Server/Specus.Server.csproj \
  -c Release -o publish/specus-csharp

# If building without Node.js, add: -p:SpecusServerWebSkip=true
# (admin-web must be pre-built into wwwroot/ separately)
```

Publish output:
- `Specus.Server.dll` (main assembly)
- `Specus.Server.deps.json`, `Specus.Server.runtimeconfig.json`
- `appsettings.json`, `appsettings.Production.json`
- `wwwroot/` (admin SPA static files)
- `runtimes/` (SQLite native binaries)
- Various dependency `.dll` files

## First-time Install

```bash
sudo bash deploy/csharp-server/systemd/install.sh /path/to/publish-output
```

The installer registers and enables the systemd unit but does not start or restart it, and it never
overwrites an existing `/etc/specus-server-csharp/specus-server.env`. The production template sets
`SPECUS_ENV=prod`, disables demo seeding and local password login, and leaves the password and JWT
secret empty. Generate strong, deployment-specific credentials before enabling local login.

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
sudo bash deploy/csharp-server/systemd/update.sh /path/to/publish-output
```

## Files layout on target

| Path | Purpose |
|------|---------|
| `/opt/specus-server-csharp/` | Publish output root (mode 0755, root:root) |
| `/etc/specus-server-csharp/specus-server.env` | Runtime environment variables (0640, root:specus) |
| `/etc/specus-server-csharp/specus-server.env.example` | Template, never overwrites live env |
| `/var/lib/specus-server-csharp/` | Working directory (SQLite default path, 0750, specus:specus) |
| `/var/log/specus-server-csharp/` | Logs (if file logging configured; default goes to journald) |

## Environment variables

Uses `SPECUS_*` naming (translated to `Specus:*` config path by `SpecusEnvironmentVariables.cs`).
Overrides `appsettings.json` values.

Start from [`specus-server.env.example`](./specus-server.env.example). Its checked-in defaults keep
password login, Peer Mesh, and object storage disabled and contain no usable credential. To enable
local management login, generate a unique password and JWT secret first, write both into the
root-owned `0640` environment file, and only then set `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED=true`.
Self-service registration additionally requires Cloudflare Turnstile, verified-email settings,
and SMTP. The C# server supports implicit TLS on port 465 and STARTTLS on port 587 through MailKit.

| Variable | Example | Description |
|----------|---------|-------------|
| `ASPNETCORE_URLS` | `http://0.0.0.0:8088` | Kestrel listen address |
| `ASPNETCORE_ENVIRONMENT` | `Production` | Environment name |
| `SPECUS_NETTY_PORT` | `7010` | Control channel TCP port |
| `SPECUS_NETTY_MAX_FRAME_SIZE` | `33554432` | Complete control-frame cap including the 11-byte header (max body `33554421`) |
| `SPECUS_DB_PROVIDER` | `sqlite` / `postgres` / `mysql` | Database provider |
| `SPECUS_CONNECTIONSTRINGS_SPECUS` | `host=...` | Database connection string |
| `SPECUS_ENV` | `prod` | Deployment environment; empty or unknown values are treated as production |
| `SPECUS_DB_SEED_DEMO_CLIENT` | `false` | Production template never seeds demo credentials |
| `SPECUS_PEER_MESH_ENABLED` | `true` | Peer mesh toggle |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` | `false` | Enable or disable local password login; template default is safe-off |
| `SPECUS_AUTH_REGISTRATION_ENABLED` | `false` | Enable verified-email self-service registration after all dependencies are configured |
| `SPECUS_AUTH_USERNAME` | `admin` | Management UI local-login username |
| `SPECUS_AUTH_PASSWORD` | empty | Management UI local-login password; generate a unique strong value before enabling login |
| `SPECUS_AUTH_TENANT_ID` | `default` | Tenant id for the built-in administrator |
| `SPECUS_AUTH_JWT_SECRET` | empty | Generate a stable HS256 secret before enabling login; an empty value uses an in-memory key and invalidates tokens after restart |
| `SPECUS_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management JWT lifetime |
| `SPECUS_AUTH_TURNSTILE_*` | disabled | Cloudflare site key, server secret, Siteverify URL, and exact hostname allowlist |
| `SPECUS_AUTH_EMAIL_*` | disabled | Verification sender, code TTL, attempt limit, resend cooldown, and cleanup interval |
| `SPECUS_AUTH_SMTP_*` | disabled | SMTP endpoint, credentials, authentication, STARTTLS, or implicit TLS settings |
| `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default online-instance limit per client credential |
| `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Online-instance limit for the same machine fingerprint and OS user |
| `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Client runtime token lifetime |

systemd `EnvironmentFile` does not perform shell command substitution. Generate a JWT secret separately (for example,
`openssl rand -base64 48`) and paste the resulting literal value into `SPECUS_AUTH_JWT_SECRET`.

## Peer Mesh / TURN firewall

When `SPECUS_PEER_MESH_ENABLED=true`, publish the configured UDP listeners and relay range in the
host firewall/security group:

- `SPECUS_PEER_MESH_STUN_TURN_PORT` (default UDP `3478`) for STUN/TURN;
- `SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT` (default UDP `3479`) for alternate-address NAT probes;
- every UDP port from `SPECUS_PEER_MESH_RELAY_MIN_PORT` through
  `SPECUS_PEER_MESH_RELAY_MAX_PORT` (default `49152-65535`) for TURN relays.

Also set `SPECUS_PEER_MESH_PUBLIC_ADDRESS` to the externally reachable host/address and configure a
non-empty `SPECUS_PEER_MESH_TURN_SHARED_SECRET` before exposing TURN. The complete option mapping is
kept in [`specus-server.env.example`](./specus-server.env.example).

## systemd unit

Installed as `specus-server-csharp.service`. Hardened identically to the Java unit:
- `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`, `ProtectHome=true`
- `ReadWritePaths=/var/lib/specus-server-csharp /var/log/specus-server-csharp`
- `LimitNOFILE=65536`
- Runs as `specus` user, `specus` group

## Health check

`GET /health` returns `{"status":"ok"}` on HTTP 200. The `update.sh` script polls this endpoint.
