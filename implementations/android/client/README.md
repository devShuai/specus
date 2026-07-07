# Android client

`implementations/android/client` is the Android implementation of the shuai-tunnel client.

The first Android version focuses on the normal tunnel-client path:

- HTTP API-key login through `serverBaseUrl + /api/client/auth/login`
- Binary control-channel login with `clientName/clientSessionId/accessToken`
- heartbeat and reconnect with capped exponential backoff
- TCP NAT tunnel registration and bidirectional `DATA` forwarding
- Direct HTTP route forwarding from public route to Android-reachable upstreams
- JSONC config editing inside the app, using the public schema URL
- dashboard-style control UI with connection actions, config summary, JSONC editor, and runtime events
- ForegroundService runtime with status updates in the app UI
- Android `VpnService` permission flow and TUN lifecycle
- peer mesh VPN address/route setup from login/runtime `peerMesh.virtualIp` and `peerMesh.cidr`
- app traffic is excluded from the VPN with `addDisallowedApplication(...)`, and control/local sockets are protected with `VpnService.protect(...)`
- peer mesh control messages for roster, candidate exchange, session grants, and close notifications
- provider-independent X25519 peer key publishing, HKDF-derived AES-GCM session keys, replay protection, and `SPM1` data frames
- direct UDP host-candidate probes and encrypted IPv4 packet delivery between peer mesh devices
- standard STUN server-reflexive candidates from the server/public STUN list
- TURN allocation, permission refresh, send/data indication, and encrypted relay fallback
- peer mesh device, path, and traffic reports for the management UI
- session refresh before grant expiry and direct-stale relay fallback

The VPN data path now has a peer mesh loop: packets captured from Android TUN are routed by virtual IPv4 destination, encrypted, sent over direct UDP when available, fall back to TURN relay when a relay path is learned, decrypted on receive, and written back to TUN. Port-mapping prediction, local ACL mirroring, and full real-device end-to-end validation are still pending.

## Build

Install Android SDK 35, then build:

```powershell
cd implementations/android/client
.\gradlew.bat :app:assembleDebug
```

The wrapper is pinned to Gradle 9.4.1 for the Android Gradle Plugin used by this module.

## Run

Install `app/build/outputs/apk/debug/app-debug.apk`, open **Shuai Tunnel**, paste a `client.jsonc`-compatible config, save, then press **Start**. Android will show the system VPN permission dialog before the foreground service starts.

The app requests network access and runs as a foreground service while the tunnel is connected or reconnecting. If the server enables peer mesh for the client, the service establishes a VPN interface using the returned virtual IP and CIDR.
