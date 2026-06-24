# systemd deployment

```bash
make -C implementations/c/server release
sudo install -m 0755 implementations/c/server/build/shuai-tunnel-server-c /usr/local/bin/shuai-tunnel-server-c
sudo install -d /etc/shuai-tunnel
sudo install -m 0644 implementations/c/server/deploy/systemd/server-c.env.example /etc/shuai-tunnel/server-c.env
sudo install -m 0644 implementations/c/server/deploy/systemd/shuai-tunnel-server-c.service /etc/systemd/system/shuai-tunnel-server-c.service
sudo systemctl daemon-reload
sudo systemctl enable --now shuai-tunnel-server-c
```

Edit `/etc/shuai-tunnel/server-c.env` before enabling the service on a public host.
