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
- Direct HTTP route forwarding from public route to Android-reachable upstreams through a protected streaming Netty transport; request bodies are preserved for every method, early responses are read while upload is still active, and request/response trailers are restricted to the safe declared-name intersection
- Direct HTTP-route WebSocket proxying over `ws://` and `wss://`, including protected sockets, filtered handshake headers and `SWS2` envelopes for continuation/text/binary/close/ping/pong with original message FIN/RSV and close semantics; physical data frames up to 16 MiB are normalized into `64 KiB - 12` continuation chunks, control frames remain atomic, pending Netty writes are bounded, and receive credit is returned only after the write future completes
- JSONC config editing inside the app, using the public schema URL
- dashboard-style control UI with connection actions, config summary, JSONC editor, and runtime events
- ForegroundService runtime with status updates in the app UI
- a non-blocking update check at app start and at most once every 24 hours; a newer catalogued Android APK is shown in a user-confirmed system download flow and never silently installed
- Android `VpnService` permission flow and TUN lifecycle only for non-`noop` virtual-device modes; `peerMeshDevice=noop` starts TCP/HTTP and the peer control/UDP path without requesting VPN permission or establishing a TUN
- peer mesh VPN address setup as `{virtualIp}/32` plus dynamic `/32` routes for online roster peers; the whole mesh CIDR and default route are not installed
- app traffic is excluded from the VPN with `addDisallowedApplication(...)`, and control/local sockets are protected with `VpnService.protect(...)`
- peer mesh control messages for roster, candidate exchange, session grants, and close notifications
- provider-independent X25519 peer key publishing, directional HKDF-derived AES-GCM traffic keys, 4096-packet replay protection, and `SPM2` data frames
- direct UDP host-candidate probes and encrypted IPv4 packet delivery between peer mesh devices
- standard STUN server-reflexive candidates from every A/AAAA address resolved for each server/public STUN hostname
- TURN allocation, permission refresh, send/data indication, and encrypted relay fallback; Allocate/Refresh/CreatePermission use long-term HMAC-SHA1 MESSAGE-INTEGRITY and retry one `401`/`438` challenge with the returned realm/nonce
- peer mesh device, path, and direct-only traffic reports for the management UI; TURN relay bytes are counted only by the server relay path
- session refresh before grant expiry and direct-stale relay fallback
- peer text, ACK, and attachment metadata use the mandatory `STMSG2` envelope; attachment download/media preview remain disabled and are not advertised

The VPN data path now has a peer mesh loop: packets captured from Android TUN are routed by virtual IPv4 destination, encrypted, sent over direct UDP when available, fall back to TURN relay when a relay path is learned, decrypted on receive, and written back to TUN. Hole punching uses replay-safe unique-nonce probe bursts with a 15-second clock window, paced adaptive port prediction (up to 16 extra ports), sticky direct endpoints with 100 ms RTT hysteresis, 25-second direct keepalives, and explicit UPnP IGD / NAT-PMP / PCP mappings with protected discovery/control sockets, bounded retry, renewal, late-winner cleanup, and shutdown release. Peer ACL and session authorization are enforced by the server before roster/grant delivery, matching the Java client; there is no separate Java-client local ACL mirror to reproduce. Local JVM tests cannot replace real-device validation of `VpnService.protect`, TUN routing, physical-gateway port mappings, STUN/TURN across real NATs, and long-running HTTP/WebSocket backpressure.
The normal TURN path pre-authenticates with the realm/nonce returned by HTTP login. If the server returns `401 Unauthorized` or `438 Stale Nonce`, Android updates the challenge values and retries that Allocate, Refresh, or CreatePermission transaction once with a new transaction ID.

### Control/data TLS

`controlTls.enabled` is a nullable override. When omitted or `null`, Android enables raw TCP TLS when the login response advertises `nettyTls: true`, or when `caCertificatePath`, `serverName`, or `insecureSkipVerify` requires TLS. An explicit `false` wins over the runtime signal and cannot be combined with TLS-only options. The scheme of `serverBaseUrl` controls only HTTP login and never implicitly enables raw TCP TLS.

Both control and data connections create and protect their underlying TCP socket first, connect it to `nettyHost:nettyPort`, then perform a TLS handshake when enabled. A failed `VpnService.protect()` aborts the connection, and both connect and TLS handshake have finite timeouts so stopping the service can release an in-progress socket. The default uses Android system trust and hostname verification. `caCertificatePath` replaces the trust roots with PEM certificates; `serverName` overrides the verified peer name; `insecureSkipVerify` disables certificate and hostname verification and is intended only for development.

Direct HTTP uses a protected Netty HTTP/1.1 stream instead of `HttpURLConnection`. It sends request DATA and declared trailers without rewriting the method, can deliver an upstream response before request upload finishes, and forwards only declared safe response trailers. Each NAT DATA chunk remains bounded at 64 KiB, per-stream pending output at 4 MiB, send credit at 1–16 MiB, request bodies at 16 MiB, and response bodies at 64 MiB.

## Build

Install Android SDK 35, then build:

```powershell
cd implementations/android/client
.\gradlew.bat :app:assembleDebug
```

The wrapper is pinned to Gradle 9.4.1 for the Android Gradle Plugin used by this module.

Release builds receive both Android version fields from the release pipeline:

```powershell
.\gradlew.bat :app:assembleRelease -PreleaseVersion=1.4.0 -PreleaseVersionCode=1400
```

Signed release builds read `SPECUS_ANDROID_KEYSTORE`, `SPECUS_ANDROID_KEYSTORE_PASSWORD`,
`SPECUS_ANDROID_KEY_ALIAS`, and `SPECUS_ANDROID_KEY_PASSWORD`. GitHub Actions restores the keystore
from the `SPECUS_ANDROID_KEYSTORE_BASE64` secret and refuses to publish an unsigned APK. Keep the
same signing key for every release so Android can install upgrades over an existing app.

The app queries the configured server's anonymous `/api/public/client-version-check` endpoint with
`implementation=android`, `platform=android`, and `arch=any`. It accepts only HTTPS downloads (or
loopback HTTP for development) and opens the returned URL through Android's normal download/install
confirmation; the application itself never bypasses package verification.

Run the local JVM protocol suite with:

```powershell
.\gradlew.bat clean test --no-problems-report
```

Current local JVM result: 121/121 tests across 14 suites. This covers protocol/codec, runtime-session reconnect policy, bounded pre-connect buffering/tombstones, strict stream credit/outstanding accounting, DATA/FIN/RST ordering and identity reuse, 16 MiB WebSocket frame normalization, pending-write bounds and pre-start cancellation, UDP probe time/replay checks and endpoint hysteresis, port-mapping stop/acquire/renew races and late-winner cleanup, TLS timeout/cancellation, and state-machine behavior. `assembleDebug` and `lintDebug` also pass with zero lint errors. It does not cover Android hardware/VPN or cross-NAT validation.

## Run

Install `app/build/outputs/apk/debug/app-debug.apk`, open **specus**, paste a `client.jsonc`-compatible config, save, then press **Start**. Android shows the system VPN permission dialog only when `peerMeshDevice` is not `noop`; TCP/HTTP-only and `noop` starts go directly to the foreground service.

The app requests network access and runs as a foreground service while the specus is connected or reconnecting. If the server enables peer mesh for the client, the service establishes a VPN interface using the returned virtual IP and CIDR.
