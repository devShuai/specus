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
  |-- /api、/auth、/oidc、/oidc-config、/http、/actuator、/health、/.well-known
  |                                         proxy -> tunnel-server:8088
  `-- /ws                                WebSocket proxy -> tunnel-server:8088

tunnel-server
  |-- 7010/tcp  客户端控制连接，不经过 OpenResty
  |-- 3478/3479/udp Peer Mesh 标准 STUN/TURN 控制与 NAT 探测，不经过 OpenResty
  `-- 49152-65535/udp TURN relay 分配端口，不经过 OpenResty
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

1. `sync:schemas` 从 `protocol/schemas` 重新同步公开 Schema。
2. `tsc --noEmit && vite build`。
3. `scripts/precompress.mjs` 对不少于 1024 字节的
   `css/html/js/json/map/mjs/svg/txt/webmanifest/xml` 文件生成 `.gz` 和 `.br`；压缩后不变小的副本会被丢弃。

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
| `OPENRESTY_CONF_NAME` | `tunnel.devshuai.com.conf` | 安装后的配置文件名 |
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
| `/api`、`/auth`、`/oidc`、`/oidc-config`、`/http`、`/actuator`、`/health`、`/.well-known`、`/ws` | 不设置静态缓存 | 动态请求直接反代 |

## HTTPS

当前 `shuai-tunnel.conf` 已同时定义 `80` 的 HTTP server 和 `443` 的 HTTPS/HTTP2 server；两者目前都会
直接服务页面与代理请求，HTTP **不会**自动跳转到 HTTPS。安装前必须把 HTTPS server 中的证书路径改成
目标机器上的真实文件：

```nginx
ssl_certificate_key /usr/local/openresty/nginx/certs/devshuai.com.key.pem;
ssl_certificate /usr/local/openresty/nginx/certs/devshuai.com.cert.pem;
```

如果生产策略要求强制 HTTPS，把 80 端口 server 的业务 `location` 改成单一
`return 301 https://$host$request_uri;`，不要再新增第二个冲突的 80 端口 server。证书可来自 certbot、
云厂商或内部 CA；修改后先执行 `openresty -t` 再 reload。

## 验证

```bash
openresty -t
curl -I http://tunnel.devshuai.com/
curl -Ik https://tunnel.devshuai.com/
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
  `3478/3479` 以及默认 TURN relay 范围 `49152-65535/udp` 仍需防火墙直接放行到 `tunnel-server`。
  如果调整了 `TUNNEL_PEER_MESH_RELAY_MIN_PORT` / `TUNNEL_PEER_MESH_RELAY_MAX_PORT`，防火墙范围必须同步调整。
* 如果后端开启了自签 TLS，OpenResty 到后端建议仍用本机明文 `127.0.0.1:8088`，公网 TLS
  在 OpenResty 终止即可。
* 如果管理页部署在 OpenResty 下，应用进程内的静态资源服务可以保留作为回退，但生产流量应走
  OpenResty。
