# systemd deployment

Install runtime/build dependencies including hiredis and utf8proc (`libhiredis-dev` and
`libutf8proc-dev` on Ubuntu). hiredis 0.14 is enough for `redis://`; `rediss://` needs hiredis 1.0 or
later with `hiredis_ssl` (Ubuntu 24.04's `libhiredis-dev`; not the 0.14 of Ubuntu 22.04 or Debian 12),
otherwise such a URI fails startup. Redis itself may run on a separate host; install `redis-server` only
when this machine owns that service or when running the integration tests. `libbrotli-dev` is
optional: with it the build decodes `Content-Encoding: br` in traffic details and media manifests,
as the Java server does; without it those bodies are shown as stored.

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

Each public TCP connection runs two threads. The unit raises `LimitNOFILE` and keeps systemd's `TasksMax=15%`,
so a flood of one public port ends at the service's task limit instead of `kernel.threads-max`, which the whole
host shares. The example sizes `SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS*` for a device of about 1 GiB; on a larger
host raise those limits and `TasksMax` together (twice the global limit plus some control and management threads).

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
SQLite-backed. Each discovery frame must be written within five seconds by default; a browser that does not
read is closed instead of delaying anyone else. Tune `SPECUS_PUBLIC_TRANSFER_DISCOVERY_WRITE_TIMEOUT_SECONDS`
if needed.
For multiple C server instances, set `SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true`, configure the same
`SPECUS_PUBLIC_TRANSFER_REDIS_URI` and key prefix on every instance, and isolate prefixes between environments.
Startup fails when Redis is missing or invalid. Later Redis failures fail the affected operations and close
local discovery sockets at the next presence refresh, instead of silently replacing shared state with
process-local state; the connections come back by themselves once Redis does. The URI takes the forms the
Java server's Lettuce accepts: `redis://`, `rediss://` for TLS (verified against OpenSSL's default CA store;
set `SSL_CERT_FILE=/path/to/ca.pem` in the environment file for a private CA, and add `?verifyPeer=CA` only
when the certificate cannot name the host), `redis-sentinel://` or `rediss-sentinel://` with
`#masterName` (the password in the URI is for the Redis nodes; Sentinels are reached without one), and
`redis-socket:///path`. With Sentinel every reconnect asks the Sentinels again, so after a failover the
instances follow the promoted master as soon as the old one drops their connections; Sentinels report
nodes by IP address, so with `rediss-sentinel://` and full verification each node's certificate needs
its IP address. A listed Sentinel that accepts but never answers costs up to one command timeout per
reconnect. Redis must not require client certificates (`tls-auth-clients no` or `optional`).
When upgrading from an older C build, note that the URI is now read exactly as Java reads it: a host
name with `_` cannot take a port (use `redis://redis_cache` or a name without `_`), and `@`, `#`, `?`
and `/` in a password must be percent-encoded (`%40`, `%23`, `%3F`, `%2F`). Startup then fails with a
message that says so, without printing the host it derived (it may contain part of the password).
