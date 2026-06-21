# systemd deployment

```bash
make -C tunnel-server-c release
sudo install -m 0755 tunnel-server-c/build/shuai-tunnel-server-c /usr/local/bin/shuai-tunnel-server-c
sudo install -d /etc/shuai-tunnel
sudo install -m 0644 tunnel-server-c/deploy/systemd/server-c.env.example /etc/shuai-tunnel/server-c.env
sudo install -m 0644 tunnel-server-c/deploy/systemd/shuai-tunnel-server-c.service /etc/systemd/system/shuai-tunnel-server-c.service
sudo systemctl daemon-reload
sudo systemctl enable --now shuai-tunnel-server-c
```

Edit `/etc/shuai-tunnel/server-c.env` before enabling the service on a public host.
