# systemd deployment

```bash
make -C implementations/c/server release
sudo install -m 0755 implementations/c/server/build/shuai-tunnel-server-c /usr/local/bin/shuai-tunnel-server-c
sudo install -d /etc/shuai-tunnel
sudo install -m 0644 implementations/c/server/deploy/systemd/server-c.env.example /etc/shuai-tunnel/server-c.env
sudoedit /etc/shuai-tunnel/server-c.env

# Optional: serve the admin SPA from the C management listener.
cd apps/admin-web
npm ci
npm run build
cd ../..
sudo install -d -m 0755 /opt/shuai-tunnel-c/admin-web
sudo cp -a apps/admin-web/dist/. /opt/shuai-tunnel-c/admin-web/

sudo install -m 0644 implementations/c/server/deploy/systemd/shuai-tunnel-server-c.service /etc/systemd/system/shuai-tunnel-server-c.service
sudo systemctl daemon-reload
sudo systemctl enable --now shuai-tunnel-server-c
```

Edit `/etc/shuai-tunnel/server-c.env` **before** enabling the service. The checked-in values are examples,
including a placeholder runtime token, and are not production credentials. The unit has no repository working
directory, so `TUNNEL_STATIC_ROOT` must be an absolute installed path; omit it only when another server such as
OpenResty serves the SPA and the C process is used for APIs/control traffic.

The `TUNNEL_PEER_MESH_*` STUN/TURN values in the env template only publish ICE information for an explicitly
configured external compatible service. The C process does not bind UDP 3478/3479, allocate relay ports, or
provide a Peer Mesh data plane; do not open those ports expecting the C binary itself to act as TURN.
