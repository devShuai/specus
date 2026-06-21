# tunnel-server-web

shuai-tunnel 管理后台前端,使用 **React + TypeScript + HeroUI + Vite** 实现。构建产物拷入
各服务端(Go / C# / Java)的静态目录,三端共用同一套 UI。

## 开发

```bash
cd tunnel-server-web
npm install
npm run dev          # http://localhost:5173,代理后端到 127.0.0.1:8088
```

`npm run dev` 会把 `/api`、`/auth`、`/oidc-config`、`/oidc`、`/http`、`/ws` 代理到后端。
后端地址可用环境变量覆盖:

```bash
VITE_API_TARGET=http://127.0.0.1:8088 npm run dev
```

任意一个 tunnel-server(Go/C#/Java)在 8088 端口跑起来即可联调。

## 构建与部署

```bash
npm run build        # 类型检查 + 产出 dist/(index.html + assets/)
npm run deploy       # build 后把 dist 拷入三端静态目录
```

`scripts/deploy.mjs` 会清空并写入:
- `tunnel-server-go/web/static/`(go:embed —— 之后需 `go build` 重新嵌入)
- `tunnel-server-csharp/src/ShuaiTunnel.Server/wwwroot/`(下次 `dotnet build`/运行生效)
- `tunnel-server/src/main/resources/static/`(Spring 静态,下次构建/运行生效)

## 测试

```bash
npm run test         # Vitest:格式化与 PKCE 工具单测
npm run typecheck    # tsc --noEmit
```

## 功能

复刻原 vanilla SPA 全部能力:
- 登录:用户名/密码 + OIDC(PKCE S256);token 存 `sessionStorage`,密码登录自动续期,401 统一登出。
- 概览、客户端(增改删 + 下发映射 + 一次性密码)、端口映射(增改删 + 状态切换)、HTTP 路由(增改删 + 筛选 + 切换)。
- 连接记录:筛选 + 分页 + WebSocket 实时(created/updated)+ 活动连接 1Hz 时长刷新。
- 流量使用、数据库初始化。
- 全中文、HeroUI 暗色主题跟随系统。

## 结构

```
src/
├── api/{client.ts,types.ts}   # fetch 封装 + DTO
├── auth/AuthContext.tsx        # token / 刷新 / OIDC PKCE / 401
├── hooks/{useConnectionsFeed,useNowTick,useClients}.ts
├── lib/{format,pkce}.ts
├── components/toast.ts
└── pages/{LoginPage,Dashboard}.tsx + pages/panels/*Panel.tsx
```
