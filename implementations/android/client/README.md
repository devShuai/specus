# Android client

`implementations/android/client` is the Android implementation of the specus client.

The first Android version focuses on the normal specus-client path:

- HTTP API-key login through `serverBaseUrl + /api/client/auth/login`
- Binary control/data-channel login with `clientName/clientSessionId/accessToken` and explicit connection roles
- optional TLS for both raw TCP channels, following login `nettyTls` by default with system trust, a PEM CA, a hostname override, or development-only insecure verification
- proactive access-token refresh using the Java client's 10% / 30-300s lead-time rules
- heartbeat only after five seconds with no control-channel writes, a 60-second read-idle timeout, and capped exponential reconnect backoff; ordinary disconnects reuse the current runtime session/token instead of creating a new HTTP session
- control-login failure classification: expired tokens trigger immediate HTTP re-login, busy/rate-limit failures back off, and terminal authentication or policy rejection stops reconnecting
- server `LOGOUT_REQUEST` handling that closes the current control socket and immediately performs a fresh HTTP login
- TCP NAT registration plus v2 `OPEN/DATA/FIN/RST/WINDOW_UPDATE` forwarding, including independent directional half-close
- invalid or duplicate `OPEN`, unknown `DATA/FIN`, and invalid per-stream half-close transitions emit a stream-level `RST` without closing unrelated streams; local dial/I/O failure also emits `RST`, pending TCP/WebSocket dials are globally capped at 1024, recent closed-stream tombstones make late `RST` idempotent, while a `RST` for a never-opened stream remains a data-connection protocol violation
- Direct HTTP route forwarding from public route to Android-reachable upstreams; `DATA|END_STREAM` delivers the payload before end-of-request, and response trailers are restricted to the safe declared-name intersection
- Direct HTTP-route WebSocket proxying over `ws://` and `wss://`, including forwarded handshake headers and validated `SWS2` envelopes; incoming tunneled `PING` is terminated locally with an equal-payload `PONG`, incoming `PONG` is consumed idempotently, and OkHttp manages its upstream heartbeat internally
- JSONC config editing inside the app, using the public schema URL
- dashboard-style control UI with connection actions, config summary, JSONC editor, and runtime events
- ForegroundService runtime with status updates in the app UI
- Android `VpnService` permission flow and TUN lifecycle only for non-`noop` virtual-device modes; `peerMeshDevice=noop` starts TCP/HTTP and the peer control/UDP path without requesting VPN permission or establishing a TUN
- peer mesh VPN address setup as `{virtualIp}/32` plus dynamic `/32` routes for online roster peers; the whole mesh CIDR and default route are not installed
- app traffic is excluded from the VPN with `addDisallowedApplication(...)`, and control/local sockets are protected with `VpnService.protect(...)`
- peer mesh control messages for roster, candidate exchange, session grants, and close notifications
- provider-independent X25519 peer key publishing, directional HKDF-derived AES-GCM traffic keys, 4096-packet replay protection, and `SPM2` data frames
- direct UDP host-candidate probes and encrypted IPv4 packet delivery between peer mesh devices
- standard STUN server-reflexive candidates from the server/public STUN list
- TURN allocation, permission refresh, send/data indication, and encrypted relay fallback; Allocate/Refresh/CreatePermission use long-term HMAC-SHA1 MESSAGE-INTEGRITY and retry one `401`/`438` challenge with the returned realm/nonce
- peer mesh device, path, and direct-only traffic reports for the management UI; TURN relay bytes are counted only by the server relay path
- session refresh before grant expiry and direct-stale relay fallback
- peer text, ACK, and attachment metadata use the mandatory `STMSG2` envelope; attachment download/media preview remain disabled and are not advertised

The VPN data path now has a peer mesh loop: packets captured from Android TUN are routed by virtual IPv4 destination, encrypted, sent over direct UDP when available, fall back to TURN relay when a relay path is learned, decrypted on receive, and written back to TUN. Port-mapping prediction, local ACL mirroring, and full real-device end-to-end validation are still pending.
The normal TURN path pre-authenticates with the realm/nonce returned by HTTP login. If the server returns `401 Unauthorized` or `438 Stale Nonce`, Android updates the challenge values and retries that Allocate, Refresh, or CreatePermission transaction once with a new transaction ID.

### Control/data TLS

`controlTls.enabled` is a nullable override. When omitted or `null`, Android enables raw TCP TLS when the login response advertises `nettyTls: true`, or when `caCertificatePath`, `serverName`, or `insecureSkipVerify` requires TLS. An explicit `false` wins over the runtime signal and cannot be combined with TLS-only options. The scheme of `serverBaseUrl` controls only HTTP login and never implicitly enables raw TCP TLS.

Both control and data connections create and protect their underlying TCP socket first, connect it to `nettyHost:nettyPort`, then perform a TLS handshake when enabled. A failed `VpnService.protect()` aborts the connection, and both connect and TLS handshake have finite timeouts so stopping the service can release an in-progress socket. The default uses Android system trust and hostname verification. `caCertificatePath` replaces the trust roots with PEM certificates; `serverName` overrides the verified peer name; `insecureSkipVerify` disables certificate and hostname verification and is intended only for development.

The Android path forwards only declared, safe response trailer fields that `HttpURLConnection` exposes after the response body, but that API has no facility for emitting HTTP request trailers. A tunneled request with non-empty `trailerNames` or `FIN.metadata.trailers` is therefore rejected explicitly with `RST`; it is never advertised as supported or silently converted into ordinary headers. `HttpURLConnection` also rewrites or rejects `GET`/`HEAD` requests with bodies and does not expose a fully duplex request/early-response exchange, so Android explicitly rejects body DATA for those two methods and waits for request completion before reading the upstream response. Use a body-capable method such as `POST`, `PUT`, or `PATCH` when Android is the route client.

## Build

Install Android SDK 35, then build:

```powershell
cd implementations/android/client
.\gradlew.bat :app:assembleDebug
```

The wrapper is pinned to Gradle 9.4.1 for the Android Gradle Plugin used by this module.

Run the local JVM protocol suite with:

```powershell
.\gradlew.bat clean test --no-problems-report
```

Current local JVM result: 86/86 tests. This covers protocol/codec, runtime-session reconnect policy, bounded pre-connect buffering/tombstones, half-close concurrency, locally terminated SWS2 ping/pong, TLS timeout/cancellation, and state-machine behavior, not Android hardware/VPN or cross-NAT validation.

## Run

Install `app/build/outputs/apk/debug/app-debug.apk`, open **specus**, paste a `client.jsonc`-compatible config, save, then press **Start**. Android shows the system VPN permission dialog only when `peerMeshDevice` is not `noop`; TCP/HTTP-only and `noop` starts go directly to the foreground service.

The app requests network access and runs as a foreground service while the specus is connected or reconnecting. If the server enables peer mesh for the client, the service establishes a VPN interface using the returned virtual IP and CIDR.
