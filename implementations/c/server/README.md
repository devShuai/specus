# shuai-tunnel-server-c

Experimental C port of `tunnel-server`.

Full migration plan: [docs/tunnel-server-c-port-plan.md](../../../docs/tunnel-server-c-port-plan.md).

This version implements the Java-compatible core server path:

- TCP listener on `TUNNEL_NETTY_PORT` (default `7010`)
- Java wire frame header (`0x14353565`, version `1`, compact-binary serializer `4`)
- compact-binary subset for `LoginRequest`, `LoginResponse`, `MessageResponse`, and heartbeat packets
- control-channel token verification compatible with the current Java client runtime login packet
- a minimal `/api/client/auth/login` stub for local smoke tests
- `NAT_CONTROL` push after login
- TCP tunnel `REGISTER`, `CONNECTED`, `DATA`, `DISCONNECTED`, and `UNREGISTER` flow
- heartbeat responses after successful login

It intentionally does not implement the full Java management/authentication surface, persistence,
the SPA, OIDC, direct HTTP routes, or TLS yet. The `/api/client/auth/login` endpoint is a local
stub that issues the runtime control-channel token from environment variables; it does not validate
apiKey signatures or manage tenants/credentials like the Java server.

## Build

```bash
make -C implementations/c/server test
```

The C build uses pthreads and zlib.

## Run

```bash
TUNNEL_NETTY_PORT=7010 \
TUNNEL_CLIENT_NAME="Demo client" \
TUNNEL_CLIENT_SESSION_ID=1 \
TUNNEL_CLIENT_ACCESS_TOKEN="dev-runtime-token" \
TUNNEL_ADMIN_PORT=8088 \
TUNNEL_TCP_MAPPINGS="18080=127.0.0.1:8080" \
implementations/c/server/build/shuai-tunnel-server-c
```

Instead of `TUNNEL_CLIENT_ACCESS_TOKEN`, you may set `TUNNEL_CLIENT_ACCESS_TOKEN_HASH` to the
64-character lowercase SHA-256 hex hash of an already-issued runtime access token. When using the
HTTP login stub, `TUNNEL_CLIENT_ACCESS_TOKEN` must be set because the stub has to return the token
to the client.

Additional runtime knobs:

| Variable | Default | Description |
| --- | --- | --- |
| `TUNNEL_PUBLIC_ADDRESS` | `127.0.0.1` | Public address included in `NAT_CONTROL`. |
| `TUNNEL_CLIENT_NAME` | `Demo client` | Runtime client name expected in the Netty login packet. |
| `TUNNEL_CLIENT_SESSION_ID` | `1` | Runtime client session id expected in the Netty login packet. |
| `TUNNEL_CLIENT_ACCESS_TOKEN` | unset | Runtime access token returned by the C auth-login stub and accepted by the control channel. |
| `TUNNEL_CLIENT_ACCESS_TOKEN_HASH` | unset | SHA-256 hex hash of the runtime access token when the plaintext token should not be kept in env. |
| `TUNNEL_CONTROL_READ_IDLE_SECONDS` | `60` | Control-channel read idle timeout. |
| `TUNNEL_MAX_GLOBAL_EXTERNAL_CONNECTIONS` | `4096` | Global external TCP connection cap. |
| `TUNNEL_MAX_CLIENT_EXTERNAL_CONNECTIONS` | `1024` | Per-control-session external TCP connection cap. |
| `TUNNEL_MAX_PORT_EXTERNAL_CONNECTIONS` | `512` | Per-public-port external TCP connection cap. |
| `TUNNEL_DATABASE_PATH` | unset | Optional SQLite database path for clients and mappings. |
| `TUNNEL_DB_SEED_DEMO_CLIENT` | `true` | Seed enabled `Demo client` metadata when initializing SQLite. |
| `TUNNEL_ADMIN_PORT` | `0` | Optional lightweight management API listener; `0` disables it. |
| `TUNNEL_STATIC_ROOT` | `implementations/java/server/src/main/resources/static` | Static SPA root used by the management listener. |

`TUNNEL_TCP_MAPPINGS` is a comma-separated list of server listen ports mapped to client-side targets:

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

The C server sends those mappings to the Java client via `NAT_CONTROL`; the client then registers
each port back to the server, and external connections on the public port are bridged over the
control channel.

When `TUNNEL_DATABASE_PATH` is set, the server initializes a small SQLite schema and checks that the
selected `TUNNEL_CLIENT_NAME` is enabled in `client_account`; enabled rows in `tunnel_mapping`
become the initial `NAT_CONTROL` TCP mappings. `TUNNEL_TCP_MAPPINGS` can still be used to append
local development mappings.

The management API skeleton is enabled by setting `TUNNEL_ADMIN_PORT`. It currently exposes
`GET /health`, `POST /auth/login`, and `GET /api/admin/overview`. The same listener also serves
`index.html`, `app.js`, and `app.css` from `TUNNEL_STATIC_ROOT`.

Requests under `/http/...` are recognized by the management listener and currently return `501`
until the Direct HTTP dispatcher is connected to the control channel.

`GET /ws/connections` is reserved for the management WebSocket event stream and currently returns
`426 Upgrade Required` until the broadcaster is wired.

Security skeleton endpoints:

- `GET /oidc-config` returns OIDC configuration derived from `TUNNEL_OIDC_*` variables.
- `POST /oidc/token` is reserved for token exchange and currently returns `501`.

TLS configuration is parsed through `TUNNEL_TLS_MODE`-style values in the security module, but TLS
handshake wiring is not enabled yet.

## Smoke Test

When local port binding is available, run:

```bash
bash implementations/c/server/scripts/nat_e2e_smoke.sh
```

The script starts a local echo server, this C server, and the existing Java client, then verifies a
payload through the mapped public port.

## Release Build

```bash
make -C implementations/c/server release
```

The release target rebuilds the server with `-O3 -DNDEBUG` and strips the binary when `strip` is
available. Example systemd files live under `implementations/c/server/deploy/systemd/`.
