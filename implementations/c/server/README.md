# specus-server-c

Experimental C port of `specus-server`.

Full migration plan: [docs/cross-language/specus-server-c-port-plan.md](../../../docs/cross-language/specus-server-c-port-plan.md).

This version implements the v2 core server path:

- TCP listener on `SPECUS_NETTY_PORT` (default `7010`)
- mandatory v2 wire frame header (`0x14353565`, version `2`, compact-binary serializer `4`), with no v1 decoder or serializer fallback
- compact-binary schemas for `LoginRequest`, `LoginResponse`, `MessageResponse`, heartbeat, and `NAT_MESSAGE`
- separate authenticated `control` and `data` connections for each runtime session
- runtime-token verification using the same v2 login schema as the Java, Go, and .NET clients
- `/api/client/auth/login`: SQLite credential login writes `specus_client_session` and returns a runtime `cs_` access token; an explicitly configured environment-token path is available only for local smoke tests
- a lightweight management HTTP skeleton with Java-shaped `/auth/login`, `/oidc-config`, HTTP-only `/oidc/token` exchange, `/api/admin/me`, database initialization, management user CRUD, `/api/admin/overview`, client CRUD, TCP mapping CRUD, connection record pagination, traffic summaries, SQLite HTTP/TCP traffic detail queries, and Peer Mesh management contract responses
- Java-shaped client package download metadata: public enabled-list endpoint plus admin-only CRUD backed by SQLite
- Java-shaped public ICE discovery at `/api/public/peer-mesh/stun-config` and `/api/public/transfer/ice-config`, including time-limited HMAC-SHA1 TURN credentials for an explicitly configured external STUN/TURN service
- an HTTP stream bridge for `/http/{clientName}/{route}/...` using NAT `OPEN/DATA/FIN/RST/WINDOW_UPDATE`; WebSocket frames use the mandatory `SWS2` envelope
- `NAT_CONTROL` push after login
- TCP specus `REGISTER`, `REGISTER_RESULT`, `OPEN`, `DATA`, `FIN`, `RST`, `WINDOW_UPDATE`, and `UNREGISTER` flow
- heartbeat responses after successful login

It intentionally does not implement the SPA build pipeline, HTTPS OIDC token exchange, Elasticsearch
traffic detail storage, Peer Mesh data plane, or TLS yet. With `SPECUS_DATABASE_PATH` configured,
`/api/client/auth/login` can authenticate rows in `specus_client_credential`, create or reuse a
machine/user-bound client identity, write a `HTTP_AUTHENTICATED` row to `specus_client_session`,
and issue a runtime `cs_` token that the control-channel login later promotes to `NETTY_ONLINE`.
The environment-token mode is a local smoke-test fixture, not an alternate wire protocol.

## Build

```bash
make -C implementations/c/server test
```

The C build uses pthreads, zlib, and SQLite3.

## Run

```bash
SPECUS_NETTY_PORT=7010 \
SPECUS_CLIENT_NAME="Demo client" \
SPECUS_CLIENT_SESSION_ID=1 \
SPECUS_CLIENT_ACCESS_TOKEN="dev-runtime-token" \
SPECUS_CLIENT_API_KEY="demo-client" \
SPECUS_CLIENT_SECRET="test1234" \
SPECUS_ADMIN_PORT=8088 \
SPECUS_TCP_MAPPINGS="18080=127.0.0.1:8080" \
SPECUS_HTTP_ROUTES="api=http://127.0.0.1:8080" \
implementations/c/server/build/specus-server-c
```

Instead of `SPECUS_CLIENT_ACCESS_TOKEN`, you may set `SPECUS_CLIENT_ACCESS_TOKEN_HASH` to the
64-character lowercase SHA-256 hex hash of an already-issued runtime access token. When using the
environment-token smoke-test login mode, `SPECUS_CLIENT_ACCESS_TOKEN` must be set because that
mode has to return the plaintext token to the client.

Additional runtime knobs:

| Variable | Default | Description |
| --- | --- | --- |
| `SPECUS_PUBLIC_ADDRESS` | `127.0.0.1` | Public address included in `NAT_CONTROL`. |
| `SPECUS_CLIENT_NAME` | `Demo client` | Runtime client name expected in the Netty login packet. |
| `SPECUS_CLIENT_TENANT_ID` | `SPECUS_AUTH_TENANT_ID` or `default` | Tenant id returned by the C `/api/client/auth/login` smoke-test response. |
| `SPECUS_CLIENT_ID` | `1` | Client id returned by the C auth-login smoke-test response. |
| `SPECUS_CLIENT_SESSION_ID` | `1` | Runtime client session id expected in the Netty login packet. |
| `SPECUS_CLIENT_ACCESS_TOKEN` | unset | Runtime access token used by the environment-token smoke-test path. Not required when SQLite credential login is used. |
| `SPECUS_CLIENT_ACCESS_TOKEN_HASH` | unset | SHA-256 hex hash of the environment runtime access token when the plaintext token should not be kept in env. |
| `SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS` | `28800` | Runtime token TTL returned by the auth-login response. Legacy alias: `SPECUS_CLIENT_TOKEN_TTL_SECONDS`. |
| `SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES` | `2` | Default max online instances returned by auth login and used when creating credentials without an explicit value. Legacy alias: `SPECUS_CLIENT_MAX_ONLINE_INSTANCES`. |
| `SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES` | `1` | Same-machine/user online-instance limit. The current C stage still enforces one instance in the control-channel path. |
| `SPECUS_CLIENT_POLICY_ENABLED` | `true` | Client policy enabled flag returned by auth login. |
| `SPECUS_CLIENT_BILLING_STATUS` | `ACTIVE` | Client billing status returned by auth login. |
| `SPECUS_CLIENT_RETRY_AFTER_SECONDS` | `0` | Retry-after hint returned by auth login. |
| `SPECUS_CLIENT_API_KEY` | unset | Optional client startup API key. When set with a secret, `/api/client/auth/login` verifies the request signature. |
| `SPECUS_CLIENT_SECRET` | unset | Optional plaintext client startup secret used as `SHA256(secret)` HMAC key material, matching the Java client signing algorithm. |
| `SPECUS_CLIENT_SECRET_HASH` | unset | Optional 64-character SHA-256 hex hash of the client startup secret; preferred over plaintext `SPECUS_CLIENT_SECRET` when set. |
| `SPECUS_AUTH_USERNAME` | `admin` | Built-in management admin username used by `/auth/login`, `/api/admin/me`, and `/api/admin/users`. |
| `SPECUS_AUTH_PASSWORD` | `admin` | Built-in management admin password used by local password login. |
| `SPECUS_AUTH_TENANT_ID` | `default` | Built-in management tenant returned by management user endpoints and used for DB management users created by the C API. |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | Password-login visibility flag returned by the Java-shaped `/oidc-config` response. |
| `SPECUS_AUTH_JWT_SECRET` | unset | Optional HS256 signing secret for local management Bearer JWTs; when unset the C process uses an ephemeral in-memory key and old tokens fail after restart. |
| `SPECUS_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management Bearer JWT lifetime; values below 60 seconds are normalized to 60. |
| `SPECUS_PEER_MESH_ENABLED` | `false` | Java-shaped `enabled` flag returned by the Peer Mesh status and public discovery endpoints. It does not enable a C Peer Mesh data plane. |
| `SPECUS_PEER_MESH_PUBLIC_ADDRESS` | unset | Explicit host of an externally deployed STUN/TURN service. C never derives this from the HTTP host because it has no built-in UDP Peer Mesh listener. |
| `SPECUS_PEER_MESH_STUN_TURN_PORT` | `3478` | Port published in self-hosted/external STUN and TURN URLs. |
| `SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS` | unset | Optional comma-separated public STUN URLs appended to the discovery response; missing ports default to `3478` and duplicates are removed. |
| `SPECUS_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | Authentication flag returned by the public ICE response. |
| `SPECUS_PEER_MESH_TURN_SHARED_SECRET` | unset | Shared secret used for temporary TURN HMAC-SHA1 credentials. When auth is required, C omits the TURN URL until this is explicitly set so it cannot advertise unusable credentials. |
| `SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | Temporary public-transfer TURN credential lifetime, clamped to at least 60 seconds. |
| `SPECUS_OIDC_CLIENT_ID` | unset | OIDC browser client id returned by `/oidc-config`; a non-empty value marks OIDC as configured. |
| `SPECUS_OIDC_AUTHORIZATION_ENDPOINT` | unset | OIDC authorization endpoint returned by `/oidc-config`. |
| `SPECUS_OIDC_TOKEN_ENDPOINT` | unset | HTTP token endpoint used by the C `/oidc/token` proxy. `https://` endpoints currently return `502` because the C server has no TLS HTTP client. |
| `SPECUS_OIDC_END_SESSION_ENDPOINT` | unset | OIDC logout endpoint returned by `/oidc-config`. |
| `SPECUS_OIDC_CLIENT_SECRET` | unset | Optional confidential-client secret. When set, `/oidc/token` sends HTTP Basic auth and omits `client_id` from the form. |
| `SPECUS_OIDC_REDIRECT_URI` | unset | Browser redirect URI returned by `/oidc-config`. |
| `SPECUS_OIDC_SCOPE` | unset | OIDC scope returned by `/oidc-config`. |
| `SPECUS_CONTROL_READ_IDLE_SECONDS` | `60` | Control-channel read idle timeout. |
| `SPECUS_MAX_GLOBAL_EXTERNAL_CONNECTIONS` | `4096` | Global external TCP connection cap. |
| `SPECUS_MAX_CLIENT_EXTERNAL_CONNECTIONS` | `1024` | Per-control-session external TCP connection cap. |
| `SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS` | `512` | Per-public-port external TCP connection cap. |
| `SPECUS_DATABASE_PATH` | unset | Optional SQLite database path for clients and mappings. |
| `SPECUS_DB_SEED_DEMO_CLIENT` | `true` | Seed enabled `Demo client` metadata when initializing SQLite. |
| `SPECUS_ADMIN_PORT` | `0` | Optional lightweight management API listener; `0` disables it. |
| `SPECUS_STATIC_ROOT` | `implementations/java/server/src/main/resources/static` | Static SPA root used by the management listener. |
| `SPECUS_HTTP_ROUTES` | unset | Optional comma-separated HTTP route snapshot, `route=targetBaseUrl,route2=https://host/base`, returned from client auth login and pushed in `NAT_CONTROL`. |
| `SPECUS_HTTP_REWRITE_MAX_BODY_BYTES` | `10485760` | Max streamed HTTP response body size eligible for path rewriting when the SQLite HTTP route has `pathRewriteEnabled=true`; `0` disables rewriting. |

`SPECUS_TCP_MAPPINGS` is a comma-separated list of server listen ports mapped to client-side targets:

```text
publicPort=targetHost:targetPort,publicPort2=targetHost2:targetPort2
```

The C server sends those mappings to the Java client via both `/api/client/auth/login` and
`NAT_CONTROL`; the client then registers each port back to the server, and external connections on
the public port are bridged over the authenticated data connection.

`SPECUS_HTTP_ROUTES` is a comma-separated list of Direct HTTP routes:

```text
route=targetBaseUrl,route2=https://target.example/base
```

The C server returns these routes in `/api/client/auth/login` and pushes them in `NAT_CONTROL`, so
Java / Go / .NET clients can populate their in-memory Direct HTTP route table before `/http/...`
traffic arrives. The management listener only forwards `/http/{clientName}/{route}/...` when
`route` exists in this configured snapshot; unknown routes return `404` instead of being sent to
the data connection.

When `SPECUS_DATABASE_PATH` is set, the server initializes a small SQLite schema and checks that the
selected `SPECUS_CLIENT_NAME` is enabled in `client_account`; enabled rows in `specus_mapping`
become the initial `NAT_CONTROL` TCP mappings. `SPECUS_TCP_MAPPINGS` can still be used to append
local development mappings.

The management API skeleton is enabled by setting `SPECUS_ADMIN_PORT`. It currently exposes
`GET /health`, `POST /auth/login`, `GET /api/admin/me`, `GET /api/admin/users`,
`POST /api/admin/users`, `PUT/DELETE /api/admin/users/{username}`,
`GET /api/admin/overview`, `GET /api/admin/metrics`, `POST /api/admin/database/initialize`, Java-shaped client endpoints
`GET/POST /api/admin/clients`, `PUT/DELETE /api/admin/clients/{id}`, startup credential endpoints
`GET/POST /api/admin/client-credentials`, `PUT/DELETE /api/admin/client-credentials/{id}`,
client package download endpoints `GET /api/public/client-downloads`,
`GET/POST /api/admin/client-downloads`, `PUT/DELETE /api/admin/client-downloads/{id}`,
TCP mapping endpoints `GET /api/admin/specus-mappings`, `POST /api/admin/clients/{id}/specus-mappings`,
`POST /api/admin/clients/{id}/nat-control`, `PUT/DELETE /api/admin/specus-mappings/{id}`, HTTP route endpoints
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
`SPECUS_PEER_MESH_ENABLED`; it does not imply that the C Peer Mesh data plane is implemented.
The public discovery endpoints likewise publish a self-hosted-looking STUN/TURN URL only when
`SPECUS_PEER_MESH_PUBLIC_ADDRESS` explicitly identifies an external STUN/TURN service. The C
process itself does not bind a STUN/TURN UDP port, perform hole punching, or relay peer traffic.
Startup login persists the wire-level `clientMessageCapabilities` on each SQLite session. Because
the lightweight C management views currently report these clients/devices as offline, their public
capability fields are zeroed just like Java's offline views; persistence is not a claim that C
implements the live peer roster or message transport.
The exact Java attachment paths—public/admin `presign-upload`, `/{attachmentId}/complete`, and
`/{attachmentId}/presign-download` under `/api/public/transfer/attachments` or
`/api/admin/client-messages/attachments`—return the specified `409 Conflict` response with
`object storage is not configured` / `OBJECT_STORAGE_DISABLED`. The C
server has no object-storage abstraction, so these routes never return successful placeholder URLs.
The management auth login endpoint validates the built-in admin password from
`SPECUS_AUTH_USERNAME` / `SPECUS_AUTH_PASSWORD`; when `SPECUS_DATABASE_PATH` is configured, it also
validates enabled rows in `specus_management_user` using the shared SHA-256 password-hash contract.
The login and refresh responses use the Java-shaped `accessToken/tokenType/expiresIn` fields. The
token is a local HS256 JWT with `iss=specus`, `sub`, `tenant_id`, `role`, `iat`, and `exp`;
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
Management user, client, TCP mapping, and HTTP route mutation endpoints require `SPECUS_DATABASE_PATH`; without a database, list
endpoints still return the current environment-driven client/mapping snapshot but mutations return
`503` instead of pretending to persist state.
`GET /api/admin/connections` follows the Java page shape:
`items`, `total`, `page`, `size`, and `totalPages`; `size` is clamped to `1..500`.
Without `SPECUS_DATABASE_PATH` it returns an empty page, because connection records are persisted
only in SQLite. Existing rows created before the newer Java fields were added are still returned,
with missing `clientId`, `channelId`, `remoteAddress`, `disconnectedAt`, and disconnect reason
fields represented as `null`.
`GET /api/admin/connection-stats` follows Java's monthly archive view shape and returns an array of
`id`, `clientId`, `clientName`, `month`, `total`, `success`, `failure`, and `updatedAt`. Existing
archive rows without `client_id` or `updated_at` are returned with nullable fields.
`GET /api/admin/traffic` and `GET /api/admin/traffic/resources` follow the Java summary view
shapes for daily client traffic and per-resource traffic. When `SPECUS_DATABASE_PATH` is set, the
C server records successful TCP specus bytes as `TCP_SPECUS` resources with keys such as
`tcp:18080`, and successful Direct HTTP body bytes as `HTTP_ROUTE` resources with keys such as
`http:api`.

SQLite traffic detail capture is available when the corresponding TCP mapping or HTTP route has
`detailCaptureEnabled=true`. TCP frames are written to `specus_tcp_traffic_frame` with the full
binary payload, canonical directions `PUBLIC_TO_CLIENT` / `CLIENT_TO_PUBLIC`, source and
destination endpoint fields, per-channel stream offsets, and preview text/hex. HTTP exchanges are
written to `specus_http_traffic_exchange` with request/response headers, body previews, status,
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
disabled `peerMesh`, TCP `specusConfigList`, and `httpSpecusConfigList`. In SQLite mode it first
looks up `specus_client_credential` by `apiKey`, verifies the same canonical HMAC signature
documented in `protocol/spec/client-auth.md`, creates or reuses the machine/user-bound client
identity, writes `specus_client_session` as `HTTP_AUTHENTICATED`, and returns a freshly generated
  `cs_` runtime token. The following v2 control/data login verifies
`clientSessionId + accessToken`, checks expiry, enabled client/credential state, same-machine
single-instance state, and `maxOnlineInstances`, then marks the row `NETTY_ONLINE`; disconnects
  mark it `DISCONNECTED`. When no matching SQLite credential exists, the explicitly configured environment-token
  smoke-test path is available. Partial environment client-auth configuration is treated as a
server misconfiguration and returns `503` instead of silently falling back. The same listener also
serves `index.html`, `app.js`, and `app.css` from `SPECUS_STATIC_ROOT`.
`/api/admin/overview` and `/api/admin/metrics` use the same SQLite plus environment mapping snapshot
as client auth login, and count only the current management context's visible TCP mappings.

Requests under `/http/{clientName}/{route}/...` are recognized by the management listener and are
forwarded to the active runtime session whose `clientName` matches the path and whose `route`
exists in the configured HTTP route snapshot. Runtime sessions are indexed by client name, and
each binds one control connection plus one data connection. Ordinary HTTP requests use NAT stream v2 on the authenticated
data connection: request/response metadata is carried once in `OPEN`, body bytes are streamed with
`DATA`, and `FIN`, `RST`, and `WINDOW_UPDATE` propagate half-close, cancellation, and flow control.
WebSocket upgrades use the same NAT stream and preserve frame semantics in the mandatory 12-byte
`SWS2` envelope. The C
implementation currently provides the basic data bridge, summary traffic accounting,
SQLite-backed detail capture/query path, Java-shaped DB credential startup login, and
Java-shaped response path rewriting for `text/html`
and `text/css` when the SQLite HTTP route has `pathRewriteEnabled=true`. Rewriting handles HTML URL
attributes, `srcset`, CSS `url(...)`, CSS `@import`, HTML runtime polyfill injection, and `gzip` /
zlib or raw `deflate` response decompression before returning an uncompressed rewritten body. It
does not yet implement Java's Elasticsearch detail persistence, Peer Mesh data plane, TLS, or
HTTPS OIDC token exchange.

The real admin socket listener requires a two-step WebSocket upgrade for the management connection
event stream. An authenticated caller first posts `{"endpoint":"connections"}` to
`/api/admin/ws-tickets`, then connects to `GET /ws/connections?ticket=<single-use-ticket>`. The
random ticket is valid for 45 seconds, bound to the endpoint, management identity, tenant, and
source address, stored only as a SHA-256 digest, and removed atomically during a successful
upgrade. JWT query parameters and reused tickets return `403` with `X-Auth-Reason`. The C server
broadcasts `created` events for runtime login success/failure and `updated` events when an
authenticated control connection disconnects; delivery is filtered by tenant and, for non-admin
users, client ownership. Plain non-upgrade HTTP requests to `/ws/connections` return
`426 Upgrade Required`.

Security skeleton endpoints:

- `GET /oidc-config` returns the Java-shaped browser login config:
  `configured`, `authorizationEndpoint`, `endSessionEndpoint`, `clientId`, `redirectUri`,
  `scope`, and `passwordLoginEnabled`.
- `POST /oidc/token` mirrors Java's Authorization Code + PKCE proxy contract. It validates
  `code` and `codeVerifier`, posts `grant_type=authorization_code`, `redirect_uri`, and
  `code_verifier` to `SPECUS_OIDC_TOKEN_ENDPOINT`, and returns Java-shaped
  `accessToken`, `idToken`, `tokenType`, and `expiresIn`. This C implementation only supports
  plain `http://` token endpoints; `https://` returns `502` until a TLS-capable HTTP client is
  wired in.

TLS configuration is parsed through `SPECUS_TLS_MODE`-style values in the security module, but TLS
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
