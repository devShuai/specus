# Android client

`implementations/android/client` is the Android implementation of the specus client.

The first Android version focuses on the normal specus-client path:

- HTTP API-key login through `serverBaseUrl + /api/client/auth/login`
- Binary control-channel login with `clientName/clientSessionId/accessToken`
- proactive access-token refresh using the Java client's 10% / 30-300s lead-time rules
- heartbeat only after five seconds with no control-channel writes, a 60-second read-idle timeout, and capped exponential reconnect backoff
- control-login failure classification: expired tokens trigger immediate HTTP re-login, busy/rate-limit failures back off, and terminal authentication or policy rejection stops reconnecting
- server `LOGOUT_REQUEST` handling that closes the current control socket and immediately performs a fresh HTTP login
- TCP NAT specus registration and bidirectional `DATA` forwarding
- malformed/unknown TCP `CONNECTED` notifications are logged and ignored; only an actual local dial/established-channel failure returns `DISCONNECTED`
- Direct HTTP route forwarding from public route to Android-reachable upstreams
- Direct HTTP-route WebSocket proxying over `ws://` and `wss://`, including forwarded handshake headers, text/binary frame prefixes, automatic ping/pong handling, and VPN-protected local sockets
- JSONC config editing inside the app, using the public schema URL
- dashboard-style control UI with connection actions, config summary, JSONC editor, and runtime events
- ForegroundService runtime with status updates in the app UI
- Android `VpnService` permission flow and TUN lifecycle
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

Current local JVM result: 34/34 tests. This covers protocol/codec and state-machine behavior, not Android hardware/VPN or cross-NAT validation.

## Run

Install `app/build/outputs/apk/debug/app-debug.apk`, open **specus**, paste a `client.jsonc`-compatible config, save, then press **Start**. Android will show the system VPN permission dialog before the foreground service starts.

The app requests network access and runs as a foreground service while the specus is connected or reconnecting. If the server enables peer mesh for the client, the service establishes a VPN interface using the returned virtual IP and CIDR.
