# apps/admin-web

shuai-tunnel 管理后台前端,使用 **React + TypeScript + HeroUI + Vite** 实现。构建产物拷入
各服务端(Go / C# / Java)的静态目录,三端共用同一套 UI。

## 开发

```bash
cd apps/admin-web
npm install
npm run dev          # http://localhost:5173,代理后端到 127.0.0.1:8088
```

`npm run dev` 会把 `/api`、`/auth`、`/oidc-config`、`/oidc`、`/http`、`/health`、`/ws` 代理到后端。
后端地址可用环境变量覆盖:

```bash
VITE_API_TARGET=http://127.0.0.1:8088 npm run dev
```

任意一个 tunnel-server(Go/C#/Java)在 8088 端口跑起来即可联调。

## 构建与部署

```bash
npm run build        # 同步 protocol/schemas + 类型检查 + 产出 dist/(index.html + assets/)
npm run build:openresty # build 后额外生成 .gz/.br 预压缩文件，供 OpenResty 静态服务
npm run deploy:java  # build 后只写 implementations/java/server/src/main/resources/static/
npm run deploy:go     # build 后只写 implementations/go/server/web/static/
npm run deploy:csharp # build 后只写 implementations/csharp/server/src/ShuaiTunnel.Server/wwwroot/
npm run deploy:all   # build 后写入三端静态目录（手动同步用）
```

`dist/` 和三端静态同步目录都是构建产物,已被 `.gitignore` 忽略,只在本地构建/打包时生成,不要提交。

Java `tunnel-server` 的 Maven 构建已经接入该流程：执行 `mvn package` / `mvn install`
时，会在 `generate-resources` 阶段调用这里的 `npm run deploy:java`，让 Spring 资源复制前拿到
最新管理后台产物，且不会改动 Go/C# 静态目录。需要纯后端构建时可加 `"-Dtunnel.server.web.skip=true"` 跳过。

C# `ShuaiTunnel.Server` 的 MSBuild 构建会调用 `npm run deploy:csharp`，可用
`/p:TunnelServerWebSkip=true` 跳过。Go server 没有 `go build` 前置生命周期，使用
`go generate ./web` 调用 `npm run deploy:go` 后再构建。

如果生产环境使用 OpenResty 前置加速，推荐不要让应用进程直接承担静态资源流量：

```bash
npm run build:openresty
sudo bash ../../deploy/openresty/install-admin-web.sh
sudo openresty -s reload
```

OpenResty 会对 `/assets/*` 启用长期强缓存和 `gzip_static`，并把 `/api`、`/auth`、
`/oidc`、`/oidc-config`、`/http`、`/actuator`、`/health`、`/.well-known`、`/ws` 反代到后端 `tunnel-server:8088`。完整配置见
`deploy/openresty/README.md`。

`scripts/deploy.mjs` 会按 `--target` 清空并写入目标目录，只有 `deploy:all` 才会写入三端：

- `implementations/go/server/web/static/`(go:embed —— 之后需 `go build` 重新嵌入)
- `implementations/csharp/server/src/ShuaiTunnel.Server/wwwroot/`(下次 `dotnet build`/运行生效)
- `implementations/java/server/src/main/resources/static/`(Spring 静态,下次构建/运行生效)

## 测试

```bash
npm run test         # Vitest:格式化、PKCE 与流式 SHA-256 工具单测
npm run typecheck    # tsc --noEmit
```

## 功能

当前主要能力：

- 登录:用户名/密码 + OIDC(PKCE S256);token 存 `sessionStorage`,密码登录自动续期,401 统一登出。
- 概览、客户端/凭证、端口映射、HTTP 路由、客户端应用包下载和系统管理。
- 客户端消息与附件、免登录房间互传（文件、剪贴板、同步白板；白板包含自由绘制与基于 maxGraph + Yjs 的专业流程图模式，支持 `.stwb` / `.stdg` 导入导出；文件传送优先 WebRTC 直连、OSS 分享兜底）。
- 连接记录:筛选 + 分页 + WebSocket 实时(created/updated)+ 活动连接 1Hz 时长刷新。
- 流量观测:客户端 / TCP 映射 / HTTP 路由聚合，HTTP 协议记录和 TCP 数据帧分页查看。
- HTTP 协议详情:请求/响应两列展示，Header 支持表单与 Raw 切换，常见 Header 带中文说明和规范链接。
- Body 预览:JSON 高亮、表单、Multipart、HTML、XML、图片和文本预览；`Content-Encoding: gzip` / `deflate` 会在旧记录展示时尝试浏览器侧解压，新记录由服务端入库前解压，`br` 新记录由服务端处理。
- TCP 详情:保留完整二进制 payload，前端按 HTTP、JSON、图片、文本或 hexdump 做 best-effort 解析。
- Peer Mesh 设备、ACL、会话、NAT/路径/RTT/流量展示，以及公开免登录 NAT 检测页。
- 内置帮助页、响应式分组导航、客户端详情抽屉和客户端下载入口。
- 全中文、HeroUI 深浅主题，落地页与后台均支持主题切换。

## 结构

```
src/
├── api/{client.ts,types.ts}                       # fetch 封装 + DTO
├── auth/AuthContext.tsx                           # token / 刷新 / OIDC PKCE / 401
├── hooks/{useConnectionsFeed,useNowTick,useClients,useDirectTransfer}.ts
├── lib/{format,nat,pkce,qr,seo,sha256,transferPreview}.ts
├── components/{Sidebar,EmptyState,ClientDetailDrawer,...}.tsx
└── pages/{LoginPage,Dashboard,PublicTransferPage}.tsx
    └── panels/{Overview,Clients,AdminMessages,Tunnels,HttpRoutes,Connections,Traffic,PeerMesh,ClientDownloads,System,Help,NatDetection}Panel.tsx
```
