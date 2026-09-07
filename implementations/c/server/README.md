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
- Java-shaped management/auth APIs, including password and email-verification registration, OIDC configuration/token exchange, tenant/owner-filtered users, clients, mappings, routes, connection records, traffic, packages, object storage, media capture, and Peer Mesh resources
- client package metadata plus hosted multipart upload/download, shared public rate limiting, full SemVer selection, and a validated/cached official GitHub latest-release fallback
- Java-shaped public ICE discovery and an in-process RFC 5389/5780 STUN plus RFC 5766 TURN UDP service with long-term credentials, allocations, permissions, ChannelData/indications, relay quotas, alternate-address NAT probing, and expiry cleanup
- public-transfer discovery at `POST /api/public/transfer/ws-tickets`, `GET /api/public/transfer/clients/name-availability`, and `/ws/public-transfer/discovery`, including source-bound one-time tickets, token/same-address merged visibility, hello/roster, signalling, ping, rate/size gates, STWR2 relay, and optional Redis multi-instance coordination
- an HTTP stream bridge for `/http/{clientName}/{route}/...` using NAT `OPEN/DATA/FIN/RST/WINDOW_UPDATE`; WebSocket frames use the mandatory `SWS2` envelope
- `NAT_CONTROL` push after login, after SQLite mapping/route mutations, and through the manual admin endpoint
- `/ws/client-messages` with endpoint-bound one-time tickets, admin/client fan-out, online capability checks, and ACL-gated client fallback over the control channel
- Peer Mesh login configuration, roster, service catalog, offer/answer/candidate/close signalling, persisted session/path/traffic state, management service sharing/import/audit/stats, and immediate roster/catalog refresh after mutations
- Java-compatible attachment presign/complete/download flows for S3-compatible or Aliyun OSS storage, plus route-level HTTP media capture, sparse Range stitching/backfill, ticketed playback, and scheduled expiry cleanup
- optional Elasticsearch HTTP/TCP detail persistence/query/retention, with SQLite as the default detail backend
- TCP specus `REGISTER`, `REGISTER_RESULT`, `OPEN`, `DATA`, `FIN`, `RST`, `WINDOW_UPDATE`, and `UNREGISTER` flow
- heartbeat responses after successful login

It intentionally does not build the SPA or provide a C client/virtual network device; it serves an existing SPA
from `SPECUS_STATIC_ROOT`. Server-side Peer Mesh signalling and STUN/TURN relay are implemented, while virtual IP
traffic is terminated by Java/Go/.NET/Android clients. Control/data TLS and verified HTTPS OIDC exchange are implemented. With `SPECUS_DATABASE_PATH` configured,
`/api/client/auth/login` can authenticate rows in `specus_client_credential`, create or reuse a
machine/user-bound client identity, write a `HTTP_AUTHENTICATED` row to `specus_client_session`,
and issue a runtime `cs_` token that the control-channel login later promotes to `NETTY_ONLINE`.
The environment-token mode is a local smoke-test fixture, not an alternate wire protocol.

## Build

```bash
make -C implementations/c/server test
```

The C build uses pthreads, zlib, SQLite3, OpenSSL, libcurl, hiredis, and utf8proc. The full test target
also starts an isolated `redis-server` for coordination and two-process WebSocket coverage.

## Run

```bash
SPECUS_NETTY_PORT=7010 \
SPECUS_ENV=dev \
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
| `SPECUS_ENV` | `prod` | Deployment policy (`prod`, `dev`/`development`/`local`, or `test`/`testing`). Blank and unknown values fail safe to `prod`. Production rejects known default management credentials and disables demo-data seeding. |
| `SPECUS_NETTY_BIND_ADDRESS` | `0.0.0.0` | Numeric or resolvable bind address for the control/data listener. Production upstream-terminated plaintext must bind a numeric loopback/private address. |
| `SPECUS_TLS_MODE` | `disabled` | Control/data TLS mode: `disabled`, `file`, or `self-signed`. Self-signed is development/test only. |
| `SPECUS_TLS_KEYSTORE` | unset | PKCS#12/PFX bundle used by `file` mode. |
| `SPECUS_TLS_KEYSTORE_PASSWORD` | unset | PKCS#12/PFX password. |
| `SPECUS_TLS_CERTIFICATE` / `SPECUS_TLS_PRIVATE_KEY` | unset | PEM certificate chain and private key alternative for `file` mode. |
| `SPECUS_TLS_KEY_PASSWORD` | keystore password | PEM private-key password, or PKCS#12 fallback password. |
| `SPECUS_TLS_REQUIRE_ENCRYPTION` | `false` | Explicitly require listener TLS. Production applies the same gate even when this is false. |
| `SPECUS_TLS_TERMINATED_UPSTREAM` | `false` | Allow disabled listener TLS in production only behind a trusted L4 terminator and on loopback/private bind space. |
| `SPECUS_AUTH_USERNAME` | `admin` | Built-in management admin username used by `/auth/login`, `/api/admin/me`, and `/api/admin/users`. |
| `SPECUS_AUTH_PASSWORD` | unset | Built-in management admin password. Blank/unset disables built-in password login; there is no shipped `admin/admin` credential. |
| `SPECUS_AUTH_TENANT_ID` | `default` | Built-in management tenant returned by management user endpoints and used for DB management users created by the C API. |
| `SPECUS_AUTH_PASSWORD_LOGIN_ENABLED` | `true` | Built-in password-login switch. `/oidc-config.passwordLoginEnabled` is true only when this switch is true and `SPECUS_AUTH_PASSWORD` contains non-whitespace text. SQLite management users keep their own password-login path, matching Java. |
| `SPECUS_AUTH_LOGIN_RATE_LIMIT_ENABLED` | `true` | Enables application-level management login throttling independently of captcha/OIDC. |
| `SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP` | `20` | Attempts allowed per source IP in one fixed window. |
| `SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT` | `10` | Attempts allowed per case-insensitive target username in one fixed window. |
| `SPECUS_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS` | `300` | Fixed login-rate-limit window and maximum `Retry-After`. |
| `SPECUS_AUTH_JWT_SECRET` | unset | Optional HS256 signing secret for local management Bearer JWTs and the domain-separated pairing-code HMAC. When unset the process uses an ephemeral key: old JWTs and persisted pairing codes fail after restart, so configure a stable high-entropy value when pairing codes are enabled. |
| `SPECUS_AUTH_TOKEN_TTL_SECONDS` | `28800` | Local management Bearer JWT lifetime; values below 60 seconds are normalized to 60. |
| `SPECUS_TRUSTED_PROXIES` | unset | Comma-separated trusted reverse-proxy CIDRs. Forwarded headers are ignored unless the socket peer matches; trusted chains use right-to-left `X-Forwarded-For` parsing with `X-Real-IP` fallback. |
| `SPECUS_PEER_MESH_ENABLED` | `false` | Enables Java-shaped Peer Mesh login/control behaviour and starts the built-in STUN/TURN UDP listener. |
| `SPECUS_PEER_MESH_PUBLIC_ADDRESS` | unset | Public address advertised for the built-in STUN/TURN service and relay candidates. |
| `SPECUS_PEER_MESH_BIND_ADDRESS` | `0.0.0.0` | Bind address for the built-in STUN/TURN UDP listener. |
| `SPECUS_PEER_MESH_STUN_TURN_PORT` | `3478` | Built-in STUN/TURN UDP listen port and published URL port. |
| `SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS` | unset | Optional comma-separated public STUN URLs appended to the discovery response; missing ports default to `3478` and duplicates are removed. |
| `SPECUS_PEER_MESH_TURN_AUTH_REQUIRED` | `true` | Authentication flag returned by the public ICE response. |
| `SPECUS_PEER_MESH_TURN_SHARED_SECRET` | unset | Shared secret used for temporary TURN HMAC-SHA1 credentials. When auth is required, C omits the TURN URL until this is explicitly set so it cannot advertise unusable credentials. |
| `SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS` | `3600` | Temporary public-transfer TURN credential lifetime, clamped to at least 60 seconds. |
| `SPECUS_PEER_MESH_CIDR` | `100.96.0.0/11` | Virtual address pool advertised to Peer Mesh clients. |
| `SPECUS_PEER_MESH_SESSION_TTL_SECONDS` | `120` | Peer session negotiation/idle expiry used by the signalling state machine. |
| `SPECUS_PEER_MESH_CATALOG_TTL_SECONDS` | `90` | Live service-catalog lease before stale withdrawal. |
| `SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM` | `32` | Maximum discoverable peers in one token/public room. |
| `SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED` | `false` | Enables Java-compatible Redis presence, merged roster revisions, Pub/Sub routing, global name checks, and shared discovery-message limits. Redis failure closes discovery sockets; there is no process-local fallback. |
| `SPECUS_PUBLIC_TRANSFER_REDIS_URI` | unset | Required in cluster mode. Supports `redis://[user[:password]@]host[:port][/0..15]`; TLS `rediss://` is intentionally rejected until a verified TLS transport is added. |
| `SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX` | `specus:v2:public-transfer` | Redis keys/channel prefix. Use a distinct value per environment. |
| `SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS` | `30` | Shared discovery presence TTL. |
| `SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS` | `10000` | Presence refresh period; must be positive and less than half the lease TTL. |
| `SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS` | `2000` | Redis connect/read/write timeout in milliseconds. |
| `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION` | `360` | Messages accepted from one discovery socket in a fixed window. |
| `SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS` | `60` | Discovery connection rate-limit window in seconds. |
| `SPECUS_PUBLIC_TRANSFER_DISCOVERY_WRITE_TIMEOUT_SECONDS` | `5` | Maximum blocking discovery-socket write time, clamped to at most 300 seconds. |
| `SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_TTL_SECONDS` | `300` | Pairing-code lifetime, clamped to `60..900` seconds. |
| `SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP` | `10` | Pairing-code redemption attempts per resolved source address in one fixed window. |
| `SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_WINDOW_SECONDS` | `300` | Pairing-code redemption fixed-window duration. |
| `SPECUS_OBJECT_STORAGE_PROVIDER` | unset | Attachment provider (`s3-compatible` or `aliyun-oss`); unset keeps attachment APIs fail-closed. |
| `SPECUS_OBJECT_STORAGE_ENDPOINT` / `REGION` / `BUCKET` | unset | Object-storage endpoint, region and bucket. |
| `SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID` / `ACCESS_KEY_SECRET` | unset | Object-storage credentials; keep them outside checked-in configuration. |
| `SPECUS_MEDIA_CAPTURE_ENABLED` | `false` | Enables route-level media capture after its S3-compatible endpoint/bucket/credentials validate. |
| `SPECUS_MEDIA_CAPTURE_ENDPOINT` / `REGION` / `BUCKET` | unset | Dedicated RustFS/S3-compatible media store. |
| `SPECUS_ELASTICSEARCH_URIS` | unset | Enables Elasticsearch HTTP/TCP detail storage and management queries; unset keeps SQLite details. |
| `SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY` | `data/client-packages` | Root for hosted client-package artifacts. |
| `SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED` | `true` | Merges validated official GitHub latest-release assets for targets without any configured row. |
| `SPECUS_AUTH_REGISTRATION_ENABLED` | `false` | Enables `/auth/register`; optional SMTP verification and Turnstile use the `SPECUS_AUTH_EMAIL_*`, `SPECUS_AUTH_SMTP_*`, and `SPECUS_AUTH_TURNSTILE_*` groups. |
| `SPECUS_OIDC_CLIENT_ID` | unset | OIDC browser client id returned by `/oidc-config`; a non-empty value marks OIDC as configured. |
| `SPECUS_OIDC_AUTHORIZATION_ENDPOINT` | unset | OIDC authorization endpoint returned by `/oidc-config`. |
| `SPECUS_OIDC_TOKEN_ENDPOINT` | unset | HTTP or HTTPS token endpoint used by the C `/oidc/token` proxy. HTTPS verifies the trust chain and endpoint hostname. |
| `SPECUS_OIDC_CA_CERTIFICATE_PATH` | unset | Optional PEM CA bundle for a private HTTPS OIDC issuer. Verification remains enabled; there is no insecure-skip switch. |
| `SPECUS_OIDC_END_SESSION_ENDPOINT` | unset | OIDC logout endpoint returned by `/oidc-config`. |
| `SPECUS_OIDC_CLIENT_SECRET` | unset | Optional confidential-client secret. When set, `/oidc/token` sends HTTP Basic auth and omits `client_id` from the form. |
| `SPECUS_OIDC_REDIRECT_URI` | unset | Browser redirect URI returned by `/oidc-config`. |
| `SPECUS_OIDC_SCOPE` | unset | OIDC scope returned by `/oidc-config`. |
| `SPECUS_CONTROL_READ_IDLE_SECONDS` | `60` | Control-channel read idle timeout. |
| `SPECUS_CONTROL_WRITE_TIMEOUT_SECONDS` | `30` | Maximum blocking control/data socket write time before the affected session is closed. |
| `SPECUS_MAX_GLOBAL_EXTERNAL_CONNECTIONS` | `4096` | Global external TCP connection cap. |
| `SPECUS_MAX_CLIENT_EXTERNAL_CONNECTIONS` | `1024` | Per-control-session external TCP connection cap. |
| `SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS` | `512` | Per-public-port external TCP connection cap. |
| `SPECUS_DATABASE_PATH` | unset | Optional SQLite database path for clients and mappings. |
| `SPECUS_DB_SEED_DEMO_CLIENT` | `true` | Request enabled `Demo client` metadata when initializing SQLite. Honoured only in `dev`/`test`; production always disables seeding. |
| `SPECUS_ADMIN_PORT` | `0` | Optional lightweight management API listener; `0` disables it. |
| `SPECUS_STATIC_ROOT` | `implementations/java/server/src/main/resources/static` | Static SPA root used by the management listener. |
| `SPECUS_HTTP_ROUTES` | unset | Optional comma-separated HTTP route snapshot, `route=targetBaseUrl,route2=https://host/base`, returned from client auth login and pushed in `NAT_CONTROL`. |
| `SPECUS_HTTP_REWRITE_MAX_BODY_BYTES` | `10485760` | Max streamed HTTP response body size eligible for path rewriting when the SQLite HTTP route has `pathRewriteEnabled=true`; `0` disables rewriting. |

Compressed response rewriting has an additional non-configurable safety boundary shared with Java:
decompressed output may not exceed 64 MiB or `max(64 KiB, compressed size × 100)`, whichever is
smaller. Gzip/x-gzip, zlib deflate, and raw deflate use the same bounded implementation. Invalid or
over-limit input is passed through unchanged and is never partially rewritten.

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

SQLite-backed routes can independently enable HTTP Basic ingress authentication through the
management API fields `authEnabled`, `authUsername`, and write-only `authPassword`. Passwords are
stored only as SHA-256 digests; management responses expose `authPasswordConfigured` instead of the
password or digest. Authentication runs before HTTP request bodies and WebSocket upgrades, and a
successful protected request has its outer `Authorization` header removed before tunnel forwarding
and traffic-detail capture. Environment-only routes remain public for compatibility.
SQLite-backed routes also persist the Java-compatible `insecureSkipVerify` flag. It is returned by
the management API and included in both `/api/client/auth/login.httpSpecusConfigList` and
`NAT_CONTROL.httpSpecusConfigList`; omitted values and environment-only routes default to `false`.
When media capture is disabled, route views return `mediaCaptureEnabled=false` and enabling it fails
closed. With a validated `SPECUS_MEDIA_CAPTURE_*` configuration, the same field activates the Java-shaped
capture, manifest/asset, Range playback, ticket, backfill, retention, and cleanup paths.

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
client package endpoints `GET /api/public/client-downloads`, `GET /api/public/client-version-check`,
`GET/HEAD /api/public/client-packages/{id}/download`, `GET/POST /api/admin/client-downloads`,
`POST /api/admin/client-packages`, `POST /api/admin/client-downloads/{id}/latest`, and
`PUT/DELETE /api/admin/client-downloads/{id}`,
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
public discovery ticket/name endpoints `POST /api/public/transfer/ws-tickets` and
`GET /api/public/transfer/clients/name-availability`, plus the upgraded
`/ws/public-transfer/discovery` socket,
public persistent-room endpoints `POST /api/public/transfer/rooms/access-tokens/list`,
`POST /api/public/transfer/rooms/access-tokens`,
`POST /api/public/transfer/rooms/access-tokens/{accessId}/revoke`,
`POST /api/public/transfer/rooms/pairing-codes`, and
`POST /api/public/transfer/rooms/pairing-codes/redeem`,
public diagram-version endpoints `POST /api/public/transfer/rooms/diagram/versions/list`,
`POST /api/public/transfer/rooms/diagram/versions`,
`POST /api/public/transfer/rooms/diagram/versions/{versionId}`, and
`POST /api/public/transfer/rooms/diagram/versions/{versionId}/delete`,
and Peer Mesh management endpoints:
`GET /api/admin/peer-mesh/status`, `GET /api/admin/peer-mesh/devices`,
`GET/POST /api/admin/peer-mesh/acls`, `DELETE /api/admin/peer-mesh/acls/{id}`,
`GET /api/admin/peer-mesh/sessions`, `DELETE /api/admin/peer-mesh/sessions/{id}`, and
`DELETE /api/admin/peer-mesh/sessions`, plus stats, service sharing, service CRUD/import, and service audit.
`GET /api/admin/peer-mesh/devices` ensures a lightweight `peer_mesh_device` row for each visible
SQLite client and returns Java-shaped device views whose online state follows the active control session, so the management page can show
which clients participate. `PUT /api/admin/peer-mesh/devices/{clientId}`
persists the device `enabled` flag after applying the same tenant/owner visibility rule as clients;
runtime device/NAT/virtual-interface status is updated from authenticated client reports.
SQLite mode supports Java-shaped ACL list/create/delete, including `OUTBOUND` / `INBOUND` / `BOTH`
direction persistence. A new ACL without `direction` defaults to `OUTBOUND`; updating an existing ACL
without `direction` preserves its current value. Tenant and owner authorization comparisons are
case-sensitive, matching Java: the source must be visible to the caller, the target must be in the
same tenant, and non-admin users cannot create cross-user ACLs. SQLite mode also creates
`peer_mesh_session` and supports
`GET /api/admin/peer-mesh/sessions?limit=`, `DELETE /api/admin/peer-mesh/sessions/{id}`, and
`DELETE /api/admin/peer-mesh/sessions` against persisted rows with the same tenant/owner visibility
rule as Java. Authenticated `PEER_CONTROL` messages create and advance peer sessions, relay
offer/answer/candidates/close, persist path/traffic reports, and fan out roster/service catalogs. Management
mutations immediately refresh online tenant clients so revoked devices, ACLs, sharing, and services do not
leave stale visibility. When `SPECUS_PEER_MESH_ENABLED=true`, the process also binds the configured STUN/TURN
UDP port, supports RFC 5780 alternate-address probes, allocates relay ports, enforces permissions/quotas, and
expires sessions, catalogs, allocations, permissions, and channels.
The public-transfer discovery WebSocket works in process-local mode by default and can use Redis for
multi-instance presence, revisioned merged rosters, global peer/name/capacity checks, distributed message
limits, and STCE2 Pub/Sub text/binary routing. Redis outages fail closed by terminating local discovery
sockets rather than falling back to divergent local state. In SQLite mode it resolves
owner, editor, and viewer credentials to one persistent room; access-token creation/list/revocation and
domain-separated HMAC pairing-code creation/atomic redemption follow the Java API. Plaintext credentials
are returned only at creation/redemption and are never persisted. The roster merges same-room peers across
addresses and same-address peers across rooms, while untargeted application signalling stays room-scoped.
Public diagram versions are SQLite-backed: OWNER/EDITOR can create, VIEWER is read-only, only OWNER can delete,
decoded snapshots are limited to 3 MiB, and each room retains its newest 50 versions. Attachment APIs use the
same resolved room role and tenant/owner rules, with presigned upload/download, HEAD completion checks, one-time
download grants, quotas, rate limits, and scheduled expiry cleanup when object storage is configured.
Startup login persists the wire-level `clientMessageCapabilities` and client version on each SQLite
session. Client and device management views expose these fields only while the control session is
online, and zero/null them after disconnect, matching Java. Client views also aggregate persisted
upload/download totals. The same capability projection gates live peer roster and client-message delivery.
The exact Java attachment paths—public/admin `presign-upload`, `/{attachmentId}/complete`, and
`/{attachmentId}/presign-download` under `/api/public/transfer/attachments` or
`/api/admin/client-messages/attachments`—return `409 OBJECT_STORAGE_DISABLED` only when no provider is
configured. Configured S3-compatible and Aliyun OSS providers return signed URLs and enforce ownership,
room role, size, quota, state, and expiry semantics.
The management auth login endpoint validates the built-in admin password from
`SPECUS_AUTH_USERNAME` / `SPECUS_AUTH_PASSWORD`; when `SPECUS_DATABASE_PATH` is configured, it also
validates enabled rows in `specus_management_user` using the shared
`$pbkdf2-sha256$v=1$i=...` human-password contract. New and changed management passwords use a
random 16-byte salt and 210,000 iterations. Legacy unsalted SHA-256 rows remain valid and are
rewritten to the current format after a successful login. High-entropy client credentials and
per-route Basic secrets intentionally remain single-round SHA-256 digests.
The built-in password is blank by default, so `admin/admin` is never implicitly accepted. Every
non-null login request is counted in fixed windows by source IP and case-insensitive username;
defaults are 20/IP and 10/account per 300 seconds. Either budget exceeding its limit returns the
same `429 Too Many Requests` body plus `Retry-After`, and a successful login clears only the account
budget so the source-IP budget cannot be bypassed by cracking one account.
Blank or unknown `SPECUS_ENV` values resolve to production. Production startup rejects the same
published weak management passwords and JWT placeholder as Java, and every SQLite initialization
path suppresses demo-client seeding. Forwarded client-address headers are ignored by default; after
an operator configures `SPECUS_TRUSTED_PROXIES`, login throttling and WebSocket ticket binding share
the same right-to-left trusted-proxy resolver.
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
`POST /api/admin/clients/{id}/nat-control` validates client visibility, reloads enabled SQLite TCP
mappings and HTTP routes, and pushes a fresh full snapshot to the active control connection. It
returns `200` after a successful push and `409 Conflict` when the client is offline. SQLite mapping
and route create/update/delete operations perform the same best-effort live refresh automatically;
an offline client receives the current snapshot on its next login.
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
large text fields. When `SPECUS_ELASTICSEARCH_URIS` is configured, the same management queries use the optional
Elasticsearch HTTP/TCP indices and configured retention caps; otherwise SQLite remains authoritative.
The client auth-login endpoint returns `tenantId`, runtime client identity, control-channel token,
Java-shaped `peerMesh`, TCP `specusConfigList`, and `httpSpecusConfigList`. In SQLite mode it first
looks up `specus_client_credential` by `apiKey`, verifies the same canonical HMAC signature
documented in `protocol/spec/client-auth.md`, creates or reuses the machine/user-bound client
identity, writes `specus_client_session` as `HTTP_AUTHENTICATED`, and returns a freshly generated
  `cs_` runtime token. The following v2 control/data login verifies
`clientSessionId + accessToken`, checks expiry, enabled client/credential state, same-machine
single-instance state, and `maxOnlineInstances`, then marks the row `NETTY_ONLINE`; disconnects
  mark it `DISCONNECTED`. When no matching SQLite credential exists, the explicitly configured environment-token
  smoke-test path is available. Partial environment client-auth configuration is treated as a
server misconfiguration and returns `503` instead of silently falling back. The same listener also
serves the SPA and `/specus-http-route-runtime.js` from `SPECUS_STATIC_ROOT`.
`/api/admin/overview` and `/api/admin/metrics` use the same SQLite plus environment mapping snapshot
as client auth login, and count only the current management context's visible TCP mappings.

Requests under `/http/{clientName}/{route}/...` are recognized by the management listener and are
forwarded to the active runtime session whose `clientName` matches the path and whose `route`
exists in the configured HTTP route snapshot. Runtime sessions are indexed by client name, and
each binds one control connection plus one data connection. Ordinary HTTP requests use NAT stream v2 on the authenticated
data connection: request/response metadata is carried once in `OPEN`, body bytes are streamed with
`DATA`, and `FIN`, `RST`, and `WINDOW_UPDATE` propagate half-close, cancellation, and flow control.
WebSocket upgrades use the same NAT stream and preserve frame semantics in the mandatory 12-byte
`SWS2` envelope. The validator consumes the shared `application-protocol-v2.json` vectors and rejects
bad magic, truncation, trailing bytes, reserved flag bits, unknown opcodes, and forbidden close codes
`1004/1005/1006/1015`. The C
implementation currently provides the basic data bridge, summary traffic accounting,
SQLite-backed detail capture/query path, Java-shaped DB credential startup login, and
Java-shaped response path rewriting for `text/html`
and `text/css` when the SQLite HTTP route has `pathRewriteEnabled=true`. Rewriting handles HTML URL
attributes, `srcset`, CSS `url(...)`, CSS `@import`, CSP-compatible injection of the shared same-origin
runtime polyfill, and `gzip` / zlib or raw `deflate` response decompression before returning an
uncompressed rewritten body. Raw `{` / `}` in public HTTP and WebSocket query strings are encoded as
`%7B` / `%7D` before NAT `OPEN`, matching the Java forwarding contract without re-encoding other query
bytes. Optional Elasticsearch detail persistence and the server-side Peer Mesh signalling/STUN/TURN paths use
the same tenant/client/session identities.

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

The client-message stream uses the same ticket endpoint with `{"endpoint":"client-messages"}` and
upgrades at `GET /ws/client-messages?ticket=<single-use-ticket>`. It sends the Java-shaped `hello`,
accepts masked JSON text up to 65,536 UTF-16 code units (including fragmented frames), validates the
target tenant/owner and every online session's receive capability, and reports `written` only after
the target control-frame write succeeds. Target writes run asynchronously with a 64-pending limit
per management socket and a 1,024-pending process limit, so a slow client does not block that
management WebSocket from consuming later commands. Client `MESSAGE_REQUEST` packets addressed to
`admin:<username>` fan out to matching management subscriptions; other client targets use the
Peer device/ACL permission check before control-channel fallback. Offline outbox is not part of this live
fallback. Attachments use the configured S3-compatible/Aliyun OSS provider and return the documented
`OBJECT_STORAGE_DISABLED` contract only while no provider is configured.

Security skeleton endpoints:

- `GET /oidc-config` returns the Java-shaped browser login config:
  `configured`, `authorizationEndpoint`, `endSessionEndpoint`, `clientId`, `redirectUri`,
  `scope`, and `passwordLoginEnabled`.
- `POST /oidc/token` mirrors Java's Authorization Code + PKCE proxy contract. It validates
  `code` and `codeVerifier`, posts `grant_type=authorization_code`, `redirect_uri`, and
  `code_verifier` to `SPECUS_OIDC_TOKEN_ENDPOINT`, and returns Java-shaped
  `accessToken`, `idToken`, `tokenType`, and `expiresIn`. Both HTTP and HTTPS are supported;
  HTTPS validates the certificate chain and hostname, with an optional private CA from
  `SPECUS_OIDC_CA_CERTIFICATE_PATH`.

The control/data listener supports disabled, PKCS#12/PEM file, and ephemeral self-signed TLS modes.
TLS 1.2 is the minimum. Production rejects self-signed TLS and plaintext public binds; plaintext
behind a trusted L4 TLS terminator is accepted only when the process binds loopback/private space and
`SPECUS_TLS_TERMINATED_UPSTREAM=true` is explicit.

## End-to-End Smoke Tests

When local port binding is available, run:

```bash
bash implementations/c/server/scripts/nat_e2e_smoke.sh
```

The script starts local TCP/HTTP/WebSocket upstreams, this C server, and the existing Java client.
It verifies TCP small payloads, 1 MiB transfer and reconnect, Direct HTTP POST/path/query, plus
WebSocket/SWS2 text, continuation, ping/pong and close handling.

To validate database-backed Java startup login and live configuration changes without reconnecting:

```bash
bash implementations/c/server/scripts/runtime_config_e2e.sh
```

This second script creates a SQLite credential, starts the Java client, waits for the management
online/version projection, then creates, deletes, and recreates a TCP mapping and a Direct HTTP
route while the client remains connected.

When WSL runs the C server but `java.exe` runs the client in the Windows network namespace, both
scripts automatically advertise the WSL interface address for upstream targets instead of assuming
that Windows `127.0.0.1` reaches a WSL listener.

## Release Build

```bash
make -C implementations/c/server release
```

The release target rebuilds the server with `-O3 -DNDEBUG` and strips the binary when `strip` is
available. Example systemd files live under `implementations/c/server/deploy/systemd/`.
