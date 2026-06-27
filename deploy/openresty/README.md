# OpenResty 前端加速部署

本目录用于把管理前端从应用进程里拆出来，由 OpenResty 直接服务静态资源，并把动态请求反代到
`tunnel-server`。这样可以把首屏、缓存、压缩和 WebSocket 长连接交给更擅长这类工作的边缘层。

## 架构

```text
Internet
  |
  | 80 / 443
  v
OpenResty
  |-- /assets/*、favicon、robots、sitemap  直接读磁盘
  |-- /、/#/...、/index.html             SPA fallback
  |-- /api、/auth、/oidc、/http          proxy -> tunnel-server:8088
  `-- /ws                                WebSocket proxy -> tunnel-server:8088

tunnel-server
  |-- 7010/tcp  客户端控制连接，不经过 OpenResty
  `-- 3478/3479/udp Peer Mesh STUN/TURN-lite，不经过 OpenResty
```

默认配置按当前公网域名写成：

```nginx
server_name tunnel.devshuai.com;
root /opt/shuai-tunnel/admin-web;
upstream shuai_tunnel_backend { server 127.0.0.1:8088; }
```

## 前端构建

在本地或目标机器构建：

```bash
cd apps/admin-web
npm ci
npm run build:openresty
```

`build:openresty` 会执行：

1. `tsc --noEmit && vite build`
2. `scripts/precompress.mjs` 为 `html/js/css/json/svg/xml/txt` 生成 `.gz` 和 `.br`

OpenResty 默认使用 `gzip_static on`，如果你的 OpenResty 编译了 `ngx_brotli`，可以在
`shuai-tunnel.conf` 中打开 `brotli_static on`，直接服务 `.br` 文件。

## 安装静态文件与配置

```bash
sudo bash deploy/openresty/install-admin-web.sh
sudo openresty -s reload
```

脚本默认：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_WEB_DIST` | `apps/admin-web/dist` | 本次构建产物 |
| `ADMIN_WEB_ROOT` | `/opt/shuai-tunnel/admin-web` | OpenResty 静态根目录 |
| `OPENRESTY_CONF_DIR` | `/usr/local/openresty/nginx/conf/conf.d` | OpenResty include 目录 |
| `OPENRESTY_BIN` | `openresty` | OpenResty 命令 |

如果发行版路径不同，可以覆盖变量：

```bash
sudo ADMIN_WEB_ROOT=/data/shuai-tunnel/admin-web \
     OPENRESTY_CONF_DIR=/etc/nginx/conf.d \
     OPENRESTY_BIN=nginx \
     bash deploy/openresty/install-admin-web.sh
```

## 缓存策略

`shuai-tunnel.conf` 的关键策略：

| 路径 | Cache-Control | 说明 |
| --- | --- | --- |
| `/assets/*` | `public, max-age=31536000, immutable` | Vite 带 hash 的 JS/CSS，长期强缓存 |
| `/index.html`、`/`、SPA fallback | `no-cache, no-store, must-revalidate` | 每次检查入口，避免发版后引用旧 chunk |
| `favicon/logo/robots/sitemap/gtag-init.js` | `public, max-age=3600` | 小静态资源短缓存 |
| `/api`、`/auth`、`/oidc`、`/http`、`/ws` | 不设置静态缓存 | 动态请求直接反代 |

## HTTPS

建议生产启用 HTTPS + HTTP/2：

1. 用 `certbot`、云厂商证书或自己的证书签发 `tunnel.devshuai.com`。
2. 把配置里的 `listen 80;` 改成 `listen 443 ssl http2;`。
3. 在同一个 `server` 内加入：

   ```nginx
   ssl_certificate /etc/letsencrypt/live/tunnel.devshuai.com/fullchain.pem;
   ssl_certificate_key /etc/letsencrypt/live/tunnel.devshuai.com/privkey.pem;
   ssl_session_timeout 1d;
   ssl_session_cache shared:SSL:10m;
   ssl_session_tickets off;
   ```

4. 另建一个 80 端口 server 做跳转：

   ```nginx
   server {
       listen 80;
       server_name tunnel.devshuai.com;
       return 301 https://$host$request_uri;
   }
   ```

## 验证

```bash
openresty -t
curl -I http://tunnel.devshuai.com/
curl -I http://tunnel.devshuai.com/assets/index-xxxx.js
curl -I -H 'Accept-Encoding: gzip' http://tunnel.devshuai.com/assets/index-xxxx.js
curl -I http://tunnel.devshuai.com/api/admin/overview
```

预期：

* `/` 返回 `Cache-Control: no-cache, no-store, must-revalidate`
* `/assets/*.js` 返回 `Cache-Control: public, max-age=31536000, immutable`
* 带 `Accept-Encoding: gzip` 请求 hash 资源时返回 `Content-Encoding: gzip`
* `/api/...` 能被反代到后端，未登录时通常返回 `401`

## 注意事项

* OpenResty 只代理 HTTP 管理面和 HTTP route；客户端控制连接 `7010/tcp`、Peer Mesh UDP
  `3478/3479` 仍需防火墙直接放行到 `tunnel-server`。
* 如果后端开启了自签 TLS，OpenResty 到后端建议仍用本机明文 `127.0.0.1:8088`，公网 TLS
  在 OpenResty 终止即可。
* 如果管理页部署在 OpenResty 下，应用进程内的静态资源服务可以保留作为回退，但生产流量应走
  OpenResty。
