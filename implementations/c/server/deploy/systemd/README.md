# systemd deployment

Install runtime/build dependencies including hiredis and utf8proc (`libhiredis-dev` and
`libutf8proc-dev` on Ubuntu). Redis itself may run on a separate host; install `redis-server` only
when this machine owns that service or when running the integration tests.

```bash
make -C implementations/c/server release
sudo install -m 0755 implementations/c/server/build/specus-server-c /usr/local/bin/specus-server-c
sudo install -d /etc/specus
sudo install -m 0644 implementations/c/server/deploy/systemd/server-c.env.example /etc/specus/server-c.env
sudoedit /etc/specus/server-c.env

# Optional: serve the admin SPA from the C management listener.
cd apps/admin-web
npm ci
npm run build
cd ../..
sudo install -d -m 0755 /opt/specus-c/admin-web
sudo cp -a apps/admin-web/dist/. /opt/specus-c/admin-web/

sudo install -m 0644 implementations/c/server/deploy/systemd/specus-server-c.service /etc/systemd/system/specus-server-c.service
sudo systemctl daemon-reload
sudo systemctl enable --now specus-server-c
```

Edit `/etc/specus/server-c.env` **before** enabling the service. The checked-in values are examples,
including a placeholder runtime token, and are not production credentials. The unit has no repository working
directory, so `SPECUS_STATIC_ROOT` must be an absolute installed path; omit it only when another server such as
OpenResty serves the SPA and the C process is used for APIs/control traffic.

The production template deliberately refuses plaintext control/data traffic. Install a PKCS#12 bundle at the
configured `SPECUS_TLS_KEYSTORE` path and replace both example passwords. PEM certificate/private-key pairs are
also supported through `SPECUS_TLS_CERTIFICATE` and `SPECUS_TLS_PRIVATE_KEY`. If a trusted L4 proxy terminates TLS,
bind the C process to loopback/private space and set `SPECUS_TLS_MODE=disabled` plus
`SPECUS_TLS_TERMINATED_UPSTREAM=true`; a public plaintext bind is rejected.

When any SQLite HTTP route enables `pathRewriteEnabled`, the same origin must serve
`/specus-http-route-runtime.js`. A source build gets it from `apps/admin-web/dist`; the release archive also
contains a minimal `admin-web/specus-http-route-runtime.js` that can be installed under
`/opt/specus-c/admin-web` when the full management SPA is not needed.

When `SPECUS_PEER_MESH_ENABLED=true`, the C process binds the configured UDP STUN/TURN port and provides the
Java-compatible Peer Mesh signalling/relay service. Publish `SPECUS_PEER_MESH_PUBLIC_ADDRESS`, open the primary
UDP port plus the configured relay range, set a high-entropy TURN shared secret, and configure the alternate
RFC 5780 address/port only when the host actually owns those public endpoints. Keep the feature disabled until
those values and firewall rules are complete; startup fails on invalid required configuration.

The public-transfer discovery WebSocket runs in-process and binds its 45-second one-time ticket to the resolved
source address. If the management listener is behind a reverse proxy, configure `SPECUS_TRUSTED_PROXIES` only
for that proxy's CIDRs and make the proxy overwrite `X-Real-IP` and append `X-Forwarded-For`; leaving it unset
correctly ignores client-supplied forwarding headers. SQLite-backed room invitations and pairing codes use
`SPECUS_AUTH_JWT_SECRET` for the pairing-code HMAC; configure a stable high-entropy secret or persisted codes
become invalid after restart. Persistent invitation/pairing-code and diagram-version workflows remain
SQLite-backed. Discovery writes use a five-second socket timeout by default so one slow browser cannot
block roster delivery indefinitely; tune `SPECUS_PUBLIC_TRANSFER_DISCOVERY_WRITE_TIMEOUT_SECONDS` if needed.
For multiple C server instances, set `SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true`, configure the same
`SPECUS_PUBLIC_TRANSFER_REDIS_URI` and key prefix on every instance, and isolate prefixes between environments.
Startup fails when Redis is missing or invalid; a later Redis/Pub/Sub failure closes local discovery sockets
instead of silently replacing shared state with process-local state. The current URI parser supports
`redis://`; deploy Redis on a private trusted network because `rediss://` is not yet supported.
