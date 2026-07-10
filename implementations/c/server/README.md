# shuai-tunnel-server-c

Experimental C port of `tunnel-server`.

Full migration plan: [docs/cross-language/tunnel-server-c-port-plan.md](../../../docs/cross-language/tunnel-server-c-port-plan.md).

This version implements the Java-compatible core server path:

- TCP listener on `TUNNEL_NETTY_PORT` (default `7010`)
- Java wire frame header (`0x14353565`, version `1`, compact-binary serializer `4`)
- compact-binary subset for `LoginRequest`, `LoginResponse`, `MessageResponse`, heartbeat, and `DirectHttpRequest/Response` packets
- control-channel token verification compatible with the current Java client runtime login packet
- a Java-compatible `/api/client/auth/login` endpoint: SQLite credential login writes `tunnel_client_session`, returns a runtime `cs_` access token, and falls back to the older environment-token smoke-test mode when no matching DB credential exists
- a lightweight management HTTP skeleton with Java-shaped `/auth/login`, `/oidc-config`, HTTP-only `/oidc/token` exchange, `/api/admin/me`, database initialization, management user CRUD, `/api/admin/overview`, client CRUD, TCP mapping CRUD, connection record pagination, traffic summaries, SQLite HTTP/TCP traffic detail queries, and Peer Mesh management contract responses
- Java-shaped client package download metadata: public enabled-list endpoint plus admin-only CRUD backed by SQLite
- Java-shaped public ICE discovery at `/api/public/peer-mesh/stun-config` and `/api/public/transfer/ice-config`, including time-limited HMAC-SHA1 TURN credentials for an explicitly configured external STUN/TURN service
- a Direct HTTP bridge for `/http/{clientName}/{route}/...` on the management listener, forwarding ordinary HTTP requests with `DIRECT_HTTP_REQUEST/RESPONSE` and WebSocket upgrades with Java-compatible `source=ws` NAT frames
- `NAT_CONTROL` push after login
- TCP tunnel `REGISTER`, `CONNECTED`, `DATA`, `DISCONNECTED`, and `UNREGISTER` flow
- heartbeat responses after successful login

It intentionally does not implement the SPA build pipeline, HTTPS OIDC token exchange, Elasticsearch
traffic detail storage, Peer Mesh data plane, or TLS yet. With `TUNNEL_DATABASE_PATH` configured,
`/api/client/auth/login` can authenticate rows in `tunnel_client_credential`, create or reuse a
machine/user-bound client identity, write a `HTTP_AUTHENTICATED` row to `tunnel_client_session`,
and issue a runtime `cs_` token that the control-channel login later promotes to `NETTY_ONLINE`.
The older environment-token mode remains available for local smoke tests.

## Build

```bash
make -C implementations/c/server test
```

The C build uses pthreads, zlib, and SQLite3.

## Run

```bash
TUNNEL_NETTY_PORT=7010 \
TUNNEL_CLIENT_NAME="Demo client" \
TUNNEL_CLIENT_SESSION_ID=1 \
TUNNEL_CLIENT_ACCESS_TOKEN="dev-runtime-token" \
TUNNEL_CLIENT_API_KEY="demo-client" \
TUNNEL_CLIENT_SECRET="test1234" \
TUNNEL_ADMIN_PORT=8088 \
TUNNEL_TCP_MAPPINGS="18080=127.0.0.1:8080" \
TUNNEL_HTTP_ROUTES="api=http://127.0.0.1:8080" \
implementations/c/server/build/shuai-tunnel-server-c
```

Instead of `TUNNEL_CLIENT_ACCESS_TOKEN`, you may set `TUNNEL_CLIENT_ACCESS_TOKEN_HASH` to the
64-character lowercase SHA-256 hex hash of an already-issued runtime access token. When using the
environment-token compatibility login mode, `TUNNEL_CLIENT_ACCESS_TOKEN` must be set because that
mode has to return the plaintext token to the client.

Additional runtime knobs:

| Variable | Default | Description |
| --- | --- | --- |
| `TUNNEL_PUBLIC_ADDRESS` | `127.0.0.1` | Public address included in `NAT_CONTROL`. |
| `TUNNEL_CLIENT_NAME` | `Demo client` | Runtime client name expected in the Netty login packet. |
| `TUNNEL_CLIENT_TENANT_ID` | `TUNNEL_AUTH_TENANT_ID` or `default` | Tenant id returned by the C `/api/client/auth/login` compatibility response. |
| `TUNNEL_CLIENT_ID` | `1` | Client id returned by the C auth-login compatibility response. |
| `TUNNEL_CLIENT_SESSION_ID` | `1` | Runtime client session id expected in the Netty login packet. |
| `TUNNEL_CLIENT_ACCESS_TOKEN` | unset | Runtime access token used by the environment-token compatibility path. Not required when SQLite credential login is used. |
| `TUNNEL_CLIENT_ACCESS_TOKEN_HASH` | unset | SHA-256 hex hash of the environment runtime access token when the plaintext token should not be kept in env. |
| `TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Runtime token TTL returned by the auth-login compatibility response. Legacy alias: `TUNNEL_CLIENT_TOKEN_TTL_SECONDS`. |
| `TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default max online instances returned by the auth-login compatibility response and used when creating credentials without an explicit value. Legacy alias: `TUNNEL_CLIENT_MAX_ONLINE_INSTANCES`. |
| `TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Java-compatible same-machine/user online-instance limit name. The current C stage still enforces one instance in the control-channel path. |
| `TUNNEL_CLIENT_POLICY_ENABLED` | `true` | Client policy enabled flag returned by the auth-login compatibility response. |
| `TUNNEL_CLIENT_BILLING_STATUS` | `ACTIVE` | Client billing status returned by the auth-login compatibility response. |
| `TUNNEL_CLIENT_RETRY_AFTER_SECONDS` | `0` | Retry-after hint returned by the auth-login compatibility response. |
| `TUNNEL_CLIENT_API_KEY` | unset | Optional Java-compatible client startup API key. When set with a secret, `/api/client/auth/login` verifies the request signature. |
| `TUNNEL_CLIENT_SECRET` | unset | Optional plaintext client startup secret used as `SHA256(secret)` HMAC key material, matching the Java client signing algorithm. |
| `TUNNEL_CLIENT_SECRET_HASH` | unset | Optional 64-character SHA-256 hex hash of the client startup secret; preferred over plaintext `TUNNEL_CLIENT_SECRET` when set. |
| `TUNNEL_AUTH_USERNAME` | `admin` | Built-in management admin username used by `/auth/login`, `/api/admin/me`, and `/api/admin/users`. |
| `TUNNEL_AUTH_PASSWORD` | `admin` | Built-in management admin password used by local password login. |
| `TUNNEL_AUTH_TENANT_ID` | `default` | Built-in management tenant returned by management user endpoints and used for DB management users created by the C API. |
| `TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | Password-login visibility flag returned by the Java-shaped `/oidc-config` response. |
| `TUNNEL_AUTH_JWT_SECRET` | unset | Optional HS256 signing secret for local management Bearer JWTs; when unset the C process uses an ephemeral in-memory key and old tokens fail after restart. |
| `TUNNEL_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management Bearer JWT lifetime; values below 60 seconds are normalized to 60. |
| `TUNNEL_PEER_MESH_ENABLED` | `false` | Java-shaped `enabled` flag returned by the Peer Mesh status and public discovery endpoints. It does not enable a C Peer Mesh data plane. |
| `TUNNEL_PEER_MESH_PUBLIC_ADDRESS` | unset | Explicit host of an externally deployed STUN/TURN service. C never derives this from the HTTP host because it has no built-in UDP Peer Mesh listener. |
| `TUNNEL_PEER_MESH_STUN_TURN_PORT` | `3478` | Port published in self-hosted/external STUN and TURN URLs. |
| `TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS` | unset | Optional comma-separated public STUN URLs appended to the discovery response; missing ports default to `3478` and duplicates are removed. |
| `TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | Authentication flag returned by the public ICE response. |
| `TUNNEL_PEER_MESH_TURN_SHARED_SECRET` | unset | Shared secret used for temporary TURN HMAC-SHA1 credentials. When auth is required, C omits the TURN URL until this is explicitly set so it cannot advertise unusable credentials. |
| `TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | Temporary public-transfer TURN credential lifetime, clamped to at least 60 seconds. |
| `TUNNEL_OIDC_CLIENT_ID` | unset | OIDC browser client id returned by `/oidc-config`; a non-empty value marks OIDC as configured. |
| `TUNNEL_OIDC_AUTHORIZATION_ENDPOINT` | unset | OIDC authorization endpoint returned by `/oidc-config`. |
| `TUNNEL_OIDC_TOKEN_ENDPOINT` | unset | HTTP token endpoint used by the C `/oidc/token` proxy. `https://` endpoints currently return `502` because the C server has no TLS HTTP client. |
| `TUNNEL_OIDC_END_SESSION_ENDPOINT` | unset | OIDC logout endpoint returned by `/oidc-config`. |
| `TUNNEL_OIDC_CLIENT_SECRET` | unset | Optional confidential-client secret. When set, `/oidc/token` sends HTTP Basic auth and omits `client_id` from the form. |
| `TUNNEL_OIDC_REDIRECT_URI` | unset | Browser redirect URI returned by `/oidc-config`. |
| `TUNNEL_OIDC_SCOPE` | unset | OIDC scope returned by `/oidc-config`. |
| `TUNNEL_CONTROL_READ_IDLE_SECONDS` | `60` | Control-channel read idle timeout. |
| `TUNNEL_MAX_GLOBAL_EXTERNAL_CONNECTIONS` | `4096` | Global external TCP connection cap. |
| `TUNNEL_MAX_CLIENT_EXTERNAL_CONNECTIONS` | `1024` | Per-control-session external TCP connection cap. |
| `TUNNEL_MAX_PORT_EXTERNAL_CONNECTIONS` | `512` | Per-public-port external TCP connection cap. |
| `TUNNEL_DATABASE_PATH` | unset | Optional SQLite database path for clients and mappings. |
| `TUNNEL_DB_SEED_DEMO_CLIENT` | `true` | Seed enabled `Demo client` metadata when initializing SQLite. |
| `TUNNEL_ADMIN_PORT` | `0` | Optional lightweight management API listener; `0` disables it. |
| `TUNNEL_STATIC_ROOT` | `implementations/java/server/src/main/resources/static` | Static SPA root used by the management listener. |
| `TUNNEL_HTTP_ROUTES` | unset | Optional comma-separated HTTP route snapshot, `route=targetBaseUrl,route2=https://host/base`, returned from client auth login and pushed in `NAT_CONTROL`. |
| `TUNNEL_HTTP_REWRITE_MAX_BODY_BYTES` | `10485760` | Max Direct HTTP response body size eligible for path rewriting when the SQLite HTTP route has `pathRewriteEnabled=true`; `0` disables rewriting. |

`TUNNEL_TCP_MAPPINGS` is a comma-separated list of server listen ports mapped to client-side targets:

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

The C server sends those mappings to the Java client via both `/api/client/auth/login` and
`NAT_CONTROL`; the client then registers each port back to the server, and external connections on
the public port are bridged over the control channel.

`TUNNEL_HTTP_ROUTES` is a comma-separated list of Direct HTTP routes:

```text
route=targetBaseUrl,route2=https://target.example/base
```

The C server returns these routes in `/api/client/auth/login` and pushes them in `NAT_CONTROL`, so
Java / Go / .NET clients can populate their in-memory Direct HTTP route table before `/http/...`
traffic arrives. The management listener only forwards `/http/{clientName}/{route}/...` when
`route` exists in this configured snapshot; unknown routes return `404` instead of being sent to
the control channel.

When `TUNNEL_DATABASE_PATH` is set, the server initializes a small SQLite schema and checks that the
selected `TUNNEL_CLIENT_NAME` is enabled in `client_account`; enabled rows in `tunnel_mapping`
become the initial `NAT_CONTROL` TCP mappings. `TUNNEL_TCP_MAPPINGS` can still be used to append
local development mappings.

The management API skeleton is enabled by setting `TUNNEL_ADMIN_PORT`. It currently exposes
`GET /health`, `POST /auth/login`, `GET /api/admin/me`, `GET /api/admin/users`,
`POST /api/admin/users`, `PUT/DELETE /api/admin/users/{username}`,
`GET /api/admin/overview`, `GET /api/admin/metrics`, `POST /api/admin/database/initialize`, Java-shaped client endpoints
`GET/POST /api/admin/clients`, `PUT/DELETE /api/admin/clients/{id}`, startup credential endpoints
`GET/POST /api/admin/client-credentials`, `PUT/DELETE /api/admin/client-credentials/{id}`,
client package download endpoints `GET /api/public/client-downloads`,
`GET/POST /api/admin/client-downloads`, `PUT/DELETE /api/admin/client-downloads/{id}`,
TCP mapping endpoints `GET /api/admin/tunnels`, `POST /api/admin/clients/{id}/tunnels`,
`POST /api/admin/clients/{id}/nat-control`, `PUT/DELETE /api/admin/tunnels/{id}`, HTTP route endpoints
`GET /api/admin/http-routes`, `POST /api/admin/clients/{id}/http-routes`,
`PUT/DELETE /api/admin/http-routes/{id}`, connection record endpoints
`GET /api/admin/connections?clientId=&success=&from=&to=&page=&size=`,
`GET /api/admin/connection-stats?clientName=&limit=`, traffic endpoints
`GET /api/admin/traffic?clientId=&limit=`,
`GET /api/admin/traffic/resources?type=&clientId=&limit=`,
`GET /api/admin/traffic/http-exchanges`, `GET /api/admin/traffic/tcp-frames`,
`GET /api/admin/traffic/tcp-frames/{id}`, `GET /api/admin/traffic/tcp-streams`,
public ICE discovery endpoints `GET /api/public/peer-mesh/stun-config` and
`GET /api/public/transfer/ice-config`,
and Peer Mesh management endpoints:
`GET /api/admin/peer-mesh/status`, `GET /api/admin/peer-mesh/devices`,
`GET/POST /api/admin/peer-mesh/acls`, `DELETE /api/admin/peer-mesh/acls/{id}`,
`GET /api/admin/peer-mesh/sessions`, `DELETE /api/admin/peer-mesh/sessions/{id}`, and
`DELETE /api/admin/peer-mesh/sessions`.
`GET /api/admin/peer-mesh/devices` ensures a lightweight `peer_mesh_device` row for each visible
SQLite client and returns Java-shaped disabled/offline device views, so the management page can show
which clients would participate once the C data plane exists. `PUT /api/admin/peer-mesh/devices/{clientId}`
persists the device `enabled` flag after applying the same tenant/owner visibility rule as clients;
the returned `virtualDeviceStatus` remains `UNSUPPORTED` because C still has no Peer Mesh data plane.
SQLite mode supports Java-shaped ACL list/create/delete, including `OUTBOUND` / `INBOUND` / `BOTH`
direction persistence. A new ACL without `direction` defaults to `OUTBOUND`; updating an existing ACL
without `direction` preserves its current value. Tenant and owner authorization comparisons are
case-sensitive, matching Java: the source must be visible to the caller, the target must be in the
same tenant, and non-admin users cannot create cross-user ACLs. SQLite mode also creates
`peer_mesh_session` and supports
`GET /api/admin/peer-mesh/sessions?limit=`, `DELETE /api/admin/peer-mesh/sessions/{id}`, and
`DELETE /api/admin/peer-mesh/sessions` against persisted rows with the same tenant/owner visibility
rule as Java. The C data plane still does not create real peer sessions by itself; the endpoint support
only keeps the management contract and schema aligned. Other unsupported Peer Mesh mutations still
return `501`.
`GET /api/admin/peer-mesh/status` only mirrors the Java-shaped `enabled` flag from
`TUNNEL_PEER_MESH_ENABLED`; it does not imply that the C Peer Mesh data plane is implemented.
The public discovery endpoints likewise publish a self-hosted-looking STUN/TURN URL only when
`TUNNEL_PEER_MESH_PUBLIC_ADDRESS` explicitly identifies an external compatible service. The C
process itself does not bind a STUN/TURN UDP port, perform hole punching, or relay peer traffic.
Startup login persists the wire-level `clientMessageCapabilities` on each SQLite session. Because
the lightweight C management views currently report these clients/devices as offline, their public
capability fields are zeroed just like Java's offline views; persistence is not a claim that C
implements the live peer roster or message transport.
The exact Java attachment paths—public/admin `presign-upload`, `/{attachmentId}/complete`, and
`/{attachmentId}/presign-download` under `/api/public/transfer/attachments` or
`/api/admin/client-messages/attachments`—return Java-compatible `409 Conflict` with
`object storage is not configured` / `OBJECT_STORAGE_DISABLED`. The C
server has no object-storage abstraction, so these routes never return successful placeholder URLs.
The management auth login endpoint validates the built-in admin password from
`TUNNEL_AUTH_USERNAME` / `TUNNEL_AUTH_PASSWORD`; when `TUNNEL_DATABASE_PATH` is configured, it also
validates enabled rows in `tunnel_management_user` using the Java-compatible SHA-256 password hash.
The login and refresh responses use the Java-shaped `accessToken/tokenType/expiresIn` fields. The
token is a local HS256 JWT with `iss=shuai-tunnel`, `sub`, `tenant_id`, `role`, `iat`, and `exp`;
real HTTP requests to `/api/admin/**` and `/auth/refresh` must include it as
`Authorization: Bearer <token>`. The C unit-test convenience wrappers still allow an implicit
built-in admin context so existing smoke tests can exercise endpoint bodies without hand-building
headers.
Client, startup credential, TCP mapping, HTTP route, connection record, archived connection-stat,
daily traffic, and resource traffic endpoints use the local management context for a
basic Java-shaped visibility rule: admin sees all rows in the current tenant, while ordinary users
only see or mutate clients/credentials they own and the records under those clients. The paged connection API
computes `total` after this visibility filter, matching the Java management page behavior. New
connection records persist `tenant_id` directly, and startup backfills older SQLite rows from the
matched client when possible; the public response body still follows Java's `ConnectionRecordView`
shape and keeps tenant information on the surrounding WebSocket event / management context.
`POST /api/admin/database/initialize` requires admin rights and returns Java-shaped
`initialized`, `tenantId`, `orm=sqlite3`, `dialect=sqlite`, and the visible tenant client count.
`POST /api/admin/clients/{id}/nat-control` validates client visibility and currently returns
`409 Conflict` when the C lightweight implementation cannot actively push a fresh mapping snapshot
to an online control connection, matching the Java/Go/.NET offline-client behavior instead of
returning a missing endpoint.
Management user, client, TCP mapping, and HTTP route mutation endpoints require `TUNNEL_DATABASE_PATH`; without a database, list
endpoints still return the current environment-driven client/mapping snapshot but mutations return
`503` instead of pretending to persist state.
`GET /api/admin/connections` follows the Java page shape:
`items`, `total`, `page`, `size`, and `totalPages`; `size` is clamped to `1..500`.
Without `TUNNEL_DATABASE_PATH` it returns an empty page, because connection records are persisted
only in SQLite. Existing rows created before the newer Java fields were added are still returned,
with missing `clientId`, `channelId`, `remoteAddress`, `disconnectedAt`, and disconnect reason
fields represented as `null`.
`GET /api/admin/connection-stats` follows Java's monthly archive view shape and returns an array of
`id`, `clientId`, `clientName`, `month`, `total`, `success`, `failure`, and `updatedAt`. Existing
archive rows without `client_id` or `updated_at` are returned with nullable compatibility fields.
`GET /api/admin/traffic` and `GET /api/admin/traffic/resources` follow the Java summary view
shapes for daily client traffic and per-resource traffic. When `TUNNEL_DATABASE_PATH` is set, the
C server records successful TCP tunnel bytes as `TCP_TUNNEL` resources with keys such as
`tcp:18080`, and successful Direct HTTP body bytes as `HTTP_ROUTE` resources with keys such as
`http:api`.

SQLite traffic detail capture is available when the corresponding TCP mapping or HTTP route has
`detailCaptureEnabled=true`. TCP frames are written to `tunnel_tcp_traffic_frame` with the full
binary payload, Java-compatible directions `PUBLIC_TO_CLIENT` / `CLIENT_TO_PUBLIC`, source and
destination endpoint fields, per-channel stream offsets, and preview text/hex. HTTP exchanges are
written to `tunnel_http_traffic_exchange` with request/response headers, body previews, status,
content types, response body type, and elapsed time. The management endpoints
`GET /api/admin/traffic/http-exchanges`, `GET /api/admin/traffic/tcp-frames`,
`GET /api/admin/traffic/tcp-frames/{id}`, and `GET /api/admin/traffic/tcp-streams` now query these
SQLite tables with the same basic tenant/owner visibility rule as other management APIs. HTTP
exchange search follows the Java keyword behavior: `q` is split by whitespace, each token must
match at least one selected field, `field=method` and `field=status` use exact matches, and Java
field aliases such as `responseDataType`, `contentType`, `requestHeaders`, and `responseBody` are
accepted. The default summary search does not scan headers or body; `field=all` includes those
large text fields. C does not yet implement Java's Elasticsearch-backed detail store.
The client auth-login endpoint returns `tenantId`, runtime client identity, control-channel token,
disabled `peerMesh`, TCP `tunnelConfigList`, and `httpTunnelConfigList`. In SQLite mode it first
looks up `tunnel_client_credential` by `apiKey`, verifies the same canonical HMAC signature
documented in `protocol/spec/client-auth.md`, creates or reuses the machine/user-bound client
identity, writes `tunnel_client_session` as `HTTP_AUTHENTICATED`, and returns a freshly generated
`cs_` runtime token. The following Netty control-channel login verifies
`clientSessionId + accessToken`, checks expiry, enabled client/credential state, same-machine
single-instance state, and `maxOnlineInstances`, then marks the row `NETTY_ONLINE`; disconnects
mark it `DISCONNECTED`. When no matching SQLite credential exists, the older environment-token
smoke-test path is still available. Partial environment client-auth configuration is treated as a
server misconfiguration and returns `503` instead of silently falling back. The same listener also
serves `index.html`, `app.js`, and `app.css` from `TUNNEL_STATIC_ROOT`.
`/api/admin/overview` and `/api/admin/metrics` use the same SQLite plus environment mapping snapshot
as client auth login, and count only the current management context's visible TCP mappings.

Requests under `/http/{clientName}/{route}/...` are recognized by the management listener and are
forwarded to the active control session whose `clientName` matches the path and whose `route`
exists in the configured HTTP route snapshot. Active control sessions are indexed by client name
instead of being kept as a single global pointer, so a later login no longer hides other online
clients from the Direct HTTP dispatcher. Ordinary HTTP requests use the Java-compatible
`DIRECT_HTTP_REQUEST` / `DIRECT_HTTP_RESPONSE` path. WebSocket upgrade requests on the same route
are accepted by the C management listener, opened as `NAT CONNECTED` with `source=ws`, and bridged
bidirectionally with the same one-byte text/binary frame prefix used by the Java server. The C
implementation currently provides the basic data bridge, summary traffic accounting,
SQLite-backed detail capture/query path, Java-shaped DB credential startup login, and
Java-shaped response path rewriting for `text/html`
and `text/css` when the SQLite HTTP route has `pathRewriteEnabled=true`. Rewriting handles HTML URL
attributes, `srcset`, CSS `url(...)`, CSS `@import`, HTML runtime polyfill injection, and `gzip` /
zlib or raw `deflate` response decompression before returning an uncompressed rewritten body. It
does not yet implement Java's Elasticsearch detail persistence, Peer Mesh data plane, TLS, or
HTTPS OIDC token exchange.

The real admin socket listener accepts `GET /ws/connections?token=<management-jwt>` WebSocket
upgrades for the management connection event stream. The token is validated with the same local
management JWT rules as `/api/admin/**`, invalid tokens return `403` with `X-Auth-Reason`, and the
connection handles WebSocket close / ping / pong frames. The C server broadcasts Java-shaped
`created` events for runtime login success/failure and `updated` events when an authenticated
control connection disconnects. Plain non-upgrade HTTP requests to `/ws/connections` still return
`426 Upgrade Required`.

Security skeleton endpoints:

- `GET /oidc-config` returns the Java-shaped browser login config:
  `configured`, `authorizationEndpoint`, `endSessionEndpoint`, `clientId`, `redirectUri`,
  `scope`, and `passwordLoginEnabled`.
- `POST /oidc/token` mirrors Java's Authorization Code + PKCE proxy contract. It validates
  `code` and `codeVerifier`, posts `grant_type=authorization_code`, `redirect_uri`, and
  `code_verifier` to `TUNNEL_OIDC_TOKEN_ENDPOINT`, and returns Java-shaped
  `accessToken`, `idToken`, `tokenType`, and `expiresIn`. This C implementation only supports
  plain `http://` token endpoints; `https://` returns `502` until a TLS-capable HTTP client is
  wired in.

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
