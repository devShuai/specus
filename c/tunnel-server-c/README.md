# shuai-tunnel-server-c

Experimental C port of `tunnel-server`.

Full migration plan: [docs/tunnel-server-c-port-plan.md](../../docs/tunnel-server-c-port-plan.md).

This version implements the Java-compatible core server path:

- TCP listener on `TUNNEL_NETTY_PORT` (default `7010`)
- Java wire frame header (`0x14353565`, version `1`, compact-binary serializer `4`)
- compact-binary subset for `LoginRequest`, `LoginResponse`, `MessageResponse`, and heartbeat packets
- HMAC-SHA256 login verification compatible with Java/Go clients
- `NAT_CONTROL` push after login
- TCP tunnel `REGISTER`, `CONNECTED`, `DATA`, `DISCONNECTED`, and `UNREGISTER` flow
- heartbeat responses after successful login

It intentionally does not implement the management API, persistence, the SPA, OIDC, direct HTTP
routes, or TLS yet. Those need separate phases because the Java server combines protocol,
persistence, dynamic listeners, SPA hosting, JWT/OIDC, and TLS in one service.

## Build

```bash
make -C c/tunnel-server-c test
```

The C build uses pthreads and zlib.

## Run

```bash
TUNNEL_NETTY_PORT=7010 \
TUNNEL_CLIENT_NAME="Demo client" \
TUNNEL_CLIENT_PASSWORD="test1234" \
TUNNEL_TCP_MAPPINGS="18080=127.0.0.1:8080" \
c/tunnel-server-c/build/shuai-tunnel-server-c
```

Instead of `TUNNEL_CLIENT_PASSWORD`, you may set `TUNNEL_CLIENT_PASSWORD_HASH` to the 64-character
lowercase SHA-256 hex hash stored by the Java management database.

Additional runtime knobs:

| Variable | Default | Description |
| --- | --- | --- |
| `TUNNEL_PUBLIC_ADDRESS` | `127.0.0.1` | Public address included in `NAT_CONTROL`. |
| `TUNNEL_LOGIN_TIME_WINDOW_MS` | `30000` | Allowed login timestamp skew in milliseconds. |
| `TUNNEL_CONTROL_READ_IDLE_SECONDS` | `60` | Control-channel read idle timeout. |

`TUNNEL_TCP_MAPPINGS` is a comma-separated list of server listen ports mapped to client-side targets:

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

The C server sends those mappings to the Java client via `NAT_CONTROL`; the client then registers
each port back to the server, and external connections on the public port are bridged over the
control channel.
