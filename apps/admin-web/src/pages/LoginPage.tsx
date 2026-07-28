import { useEffect, useState, type CSSProperties, type MouseEvent as ReactMouseEvent, type ReactNode } from "react";
import { useAuth } from "../auth/AuthContext";
import { AppLogo } from "../components/AppLogo";
import { SpecusAqueduct } from "../components/SpecusAqueduct";
import { PublicToolsMenu } from "../components/PublicToolsMenu";
import { UserMenuButton } from "../components/UserMenuButton";
import type { ClientDownloadLink, ClientImplementation } from "../api/types";
import { usePageSeo } from "../lib/seo";

const metrics = [
  { value: "TCP", label: "公网端口映射" },
  { value: "HTTP", label: "域名路由转发" },
  { value: "Peer", label: "客户端互联" },
  { value: "观测", label: "连接与流量审计" },
];

const featureCards = [
  {
    label: "多语言",
    title: "跨实现客户端",
    description: "Java / Go / .NET / C 四种实现共享同一份二进制协议，字节级兼容，可按团队技术栈与部署形态任意选型混搭。",
  },
  {
    label: "身份",
    title: "OIDC + 本地账号双登录",
    description: "本地用户名密码与 OIDC 单点登录可同时开启。PKCE、JWT 与 OIDC claim 一同驱动多租户权限隔离。",
  },
  {
    label: "隔离",
    title: "多租户与路由级 ACL",
    description: "一套 Server 承载多组团队。客户端、HTTP 路由、端口映射、连接记录全部按租户隔离展示。",
  },
  {
    label: "改写",
    title: "HTTP 路径与流量自适应",
    description: "内网 SPA 的绝对路径自动加前缀，运行时拦截 fetch / XHR / WebSocket，让既有应用不改一行代码即可走隧道。",
  },
  {
    label: "观测",
    title: "实时连接与流量审计",
    description: "在线连接、HTTP 协议记录、TCP 帧追踪、流量趋势与 WebSocket 推送，运维问题在管理台内一站式定位。",
  },
  {
    label: "自托管",
    title: "TLS / 数据库 / 部署可选",
    description: "TLS 三模式（明文 / 文件 / 自签）、SQLite / MySQL / PostgreSQL 任选其一、systemd 滚动升级与失败自动回滚。",
  },
];

const flowNodes = ["公网入口", "控制面鉴权", "策略编排", "内网服务"];

const httpRouteNodes = [
  { eyebrow: "公网用户", title: "app.example.com", meta: "GET /api/orders" },
  { eyebrow: "Server", title: "HTTP 网关", meta: "解析 Host / Path" },
  { eyebrow: "路由规则", title: "Route: app", meta: "命中 Demo client" },
  { eyebrow: "内网服务", title: "127.0.0.1:8080", meta: "客户端回连转发" },
];

const portMappingNodes = [
  { eyebrow: "公网用户", title: "server:9000", meta: "TCP stream" },
  { eyebrow: "Server", title: "监听 9000", meta: "端口规则匹配" },
  { eyebrow: "隧道连接", title: "Demo client", meta: "复用已登录长连接" },
  { eyebrow: "内网目标", title: "127.0.0.1:22", meta: "转发到真实服务" },
];

const peerNodes = [
  { eyebrow: "发起方", title: "客户端 A", meta: "X25519 公钥已登记" },
  { eyebrow: "控制面", title: "PEER_CONTROL 通道", meta: "ACL 校验 + 信令转发" },
  { eyebrow: "协商", title: "设备清单 + 会话凭证", meta: "iceUsername / iceCredential" },
  { eyebrow: "对端", title: "客户端 B", meta: "按 virtualIp 路由 · 加密 frame 直达" },
];

const implementationChips = [
  { name: "Java", note: "Spring Boot · 跨平台 jar" },
  { name: "Go", note: "单二进制 · 各 OS/架构" },
  { name: ".NET", note: "自包含或运行时" },
  { name: "C", note: "实验性 · 资源最小" },
];

export function LoginPage() {
  return <LoginPageContent />;
}

function LoginPageContent() {
  const { oidcConfig, openLogin } = useAuth();

  usePageSeo({
    title: "specus · 自托管内网穿透 / HTTP 反向代理 / 对端互联控制面",
    description:
      "specus 是一套自托管的内网穿透控制面，支持 TCP 端口映射、HTTP 反向代理（含路径改写）、私有组网对端互联与浏览器 NAT 类型检测，自带 Java / Go / .NET 多语言客户端。",
    canonical: "https://specus.devshuai.com/",
    keywords:
      "内网穿透,NAT 检测,STUN 探测,Symmetric NAT,WebRTC,HTTP 反向代理,对端互联,Peer Mesh,P2P 打洞,frp 替代,自托管,specus",
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      "name": "specus",
      "url": "https://specus.devshuai.com/",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "Linux, Windows, macOS",
      "description":
        "自托管内网穿透与对端互联控制面：TCP 端口映射、HTTP 反向代理（含路径改写）、Peer Mesh 私有组网与浏览器 NAT 类型检测。",
      "offers": { "@type": "Offer", "price": "0", "priceCurrency": "CNY" },
      "creator": { "@type": "Person", "name": "devShuai" },
    },
  });

  const registrationEnabled = (oidcConfig?.registrationEnabled ?? false)
    && (oidcConfig?.passwordLoginEnabled ?? true);

  return (
    <main className="app-apple landing-shell landing-apple min-h-screen text-zinc-950 dark:text-white">
      <section className="landing-apple-hero relative z-10 mx-auto flex w-full max-w-[1440px] flex-col px-5 pb-10 pt-5 sm:px-8 lg:min-h-[88vh]">
        <header className="landing-apple-header flex items-center justify-between gap-3">
          <AppLogo className="min-w-0 flex-1" label="specus" subtitle="内网服务接入控制面" />
          <div className="public-header-actions flex shrink-0 items-center gap-2">
            <PublicToolsMenu />
            <UserMenuButton className="public-header-theme-button" />
          </div>
        </header>

        <div className="landing-apple-hero-layout grid flex-1 items-center gap-10 py-10">
          <div className="landing-apple-copy flex min-w-0 flex-col items-center gap-8 text-center">
            <span className="landing-apple-eyebrow w-fit text-small font-semibold">
              specus · 拉丁语「地道 / 引水渠」
            </span>

            <div className="max-w-3xl">
              <h1 className="landing-apple-title mx-auto font-semibold text-zinc-950 dark:text-white">specus</h1>
              <p className="specus-tagline mt-4">
                <b>引水渠</b>
                <span aria-hidden="true">·</span>
                <b>打洞</b>
                <span aria-hidden="true">·</span>
                <b>观测</b>
              </p>
              <p className="landing-apple-lead mx-auto mt-5 max-w-2xl text-zinc-700 dark:text-zinc-300">
                古人架渠引水跨越山谷，把远处的水送到城里。specus 做同一件事：为内网服务架一条可控的渠，
                在 NAT 之间打通洞口，并让每一段水流都看得见。
              </p>
            </div>

            <SpecusAqueduct className="mx-auto" />

            <div className="flex flex-wrap items-center justify-center gap-3">
              <button type="button" className="landing-primary-button" onClick={() => openLogin()}>
                登录管理台
              </button>
              {registrationEnabled && (
                <button type="button" className="landing-secondary-button" onClick={() => openLogin("register")}>
                  注册账号
                </button>
              )}
            </div>

            <div className="landing-apple-metrics mx-auto grid w-full max-w-3xl grid-cols-2 sm:grid-cols-4">
              {metrics.map((item) => (
                <div key={item.label} className="landing-apple-metric py-3">
                  <p className="text-xl font-semibold text-zinc-950 dark:text-white">{item.value}</p>
                  <p className="mt-1 text-tiny text-zinc-600 dark:text-zinc-400">{item.label}</p>
                </div>
              ))}
            </div>

            <div className="landing-apple-flow mx-auto flex w-full max-w-3xl flex-col gap-3 p-4 sm:flex-row sm:items-center">
              {flowNodes.map((node, index) => (
                <div key={node} className="flex min-w-0 flex-1 items-center gap-3">
                  <span className="landing-apple-step flex h-8 w-8 shrink-0 items-center justify-center text-small">
                    {index + 1}
                  </span>
                  <span className="truncate text-small text-zinc-700 dark:text-zinc-200">{node}</span>
                  {index < flowNodes.length - 1 && <span className="landing-route-line hidden h-px flex-1 sm:block" />}
                </div>
              ))}
            </div>
          </div>

        </div>
      </section>

      <section className="landing-apple-content relative z-10 px-5 py-16 sm:px-8">
        <div className="mx-auto max-w-[1440px]">
          <div className="mb-6 max-w-2xl">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-950 dark:text-white">一水两路 · 组网形态</h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              一套控制面承担两类流量：公网用户经 Server 中继访问内网服务，受控客户端之间在控制面协调下走对端互联通道。
            </p>
          </div>
          <TopologyDiagram />

          <div className="mb-6 mt-12 max-w-2xl">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-950 dark:text-white">
              架渠与打洞
            </h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              HTTP 路由与端口映射是<b className="font-semibold text-zinc-800 dark:text-zinc-200">渠</b>——
              流量沿既定渠道从公网流进内网；客户端互联是<b className="font-semibold text-zinc-800 dark:text-zinc-200">洞</b>——
              控制面撮合信令，加密 frame 走 UDP 直连，打不通时回退 TURN。
            </p>
          </div>

          <div className="mb-10 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            <PrincipleCard
              badge="HTTP route"
              index="01"
              motif="渠"
              title="HTTP 路由：按 Host 与 Path 进入内网 Web 服务"
              description="请求先进 Server 的 HTTP 网关，管理端配置决定命中哪个租户、客户端和目标地址，再把请求沿客户端长连接送回内网。"
              accent="blue"
            >
              <FlowDiagram nodes={httpRouteNodes} variant="http" />
              <div className="principle-note">
                <span>Host: app.example.com</span>
                <span>Route: /api → Demo / 127.0.0.1:8080</span>
              </div>
            </PrincipleCard>

            <PrincipleCard
              badge="Port mapping"
              className="2xl:mt-12"
              index="02"
              motif="引"
              title="公网端口映射：按监听端口进入内网 TCP 服务"
              description="Server 先占用公网端口，外部连接到来后查找端口映射，把字节流封装进客户端隧道，再落到指定内网 IP 和端口。"
              accent="amber"
            >
              <FlowDiagram nodes={portMappingNodes} variant="port" />
              <div className="principle-note">
                <span>Listen: 0.0.0.0:9000</span>
                <span>Target: Demo → 127.0.0.1:22</span>
              </div>
            </PrincipleCard>

            <PrincipleCard
              badge="Peer mesh"
              index="03"
              motif="洞"
              title="客户端互联：受控对端之间的直连通道"
              description="客户端登录时上报 X25519 公钥并接收 roster；控制面校验 ACL 后撮合两端通过 PEER_CONTROL 通道协商身份与会话凭证。"
              accent="emerald"
            >
              <FlowDiagram nodes={peerNodes} variant="peer" />
              <div className="principle-note">
                <span>Specus CIDR: 100.96.0.0/11</span>
                <span>Identity: X25519 公钥 + iceCredential</span>
              </div>
            </PrincipleCard>
          </div>

          <div className="mb-6 mt-12 max-w-2xl">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-950 dark:text-white">平台特性</h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              从协议字节级兼容到部署形态，specus 把传统反向隧道工具缺失的工程化关切补齐。
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {featureCards.map((feature) => (
              <article
                key={feature.title}
                className="app-apple-landing-surface landing-apple-feature text-zinc-950 dark:text-white"
              >
                <div className="grid gap-3 p-4">
                  <span className="landing-apple-kicker w-fit text-tiny font-semibold">
                    {feature.label}
                  </span>
                  <h3 className="text-base font-semibold text-zinc-950 dark:text-white">{feature.title}</h3>
                  <p className="text-small leading-6 text-zinc-600 dark:text-zinc-400">{feature.description}</p>
                </div>
              </article>
            ))}
          </div>

          <div className="app-apple-landing-surface landing-apple-protocol mt-12 flex flex-col gap-3 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-base font-semibold text-zinc-950 dark:text-white">四种实现 · 一份协议</span>
              <span className="rounded-md border border-emerald-500/25 bg-emerald-300/15 px-2 py-0.5 text-tiny text-emerald-700 dark:border-emerald-300/25 dark:bg-emerald-300/10 dark:text-emerald-100">
                字节级兼容
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              {implementationChips.map((chip) => (
                <span
                  key={chip.name}
                  className="glass-chip glass-border inline-flex items-baseline gap-1.5 rounded-md border px-3 py-1.5 text-tiny text-zinc-700 dark:text-zinc-300"
                >
                  <span className="font-semibold text-primary-700 dark:text-primary-400">{chip.name}</span>
                  <span className="text-zinc-500 dark:text-zinc-500">·</span>
                  <span>{chip.note}</span>
                </span>
              ))}
            </div>
            <p className="text-tiny leading-5 text-zinc-600 dark:text-zinc-400">
              控制连接 11 字节定长包头（magic / version / serializer / command / length）+ 紧凑二进制载荷。
              不同语言客户端登录到同一台 Server，无须任何字段适配。
            </p>
          </div>

          <ClientDownloadsSection />
        </div>
      </section>

    </main>
  );
}
/**
 * 拓扑总览图：左 公网用户 / 中 Server 控制面 / 右上 客户端 A / 右下 客户端 B。
 *
 * 视觉约定：
 *  - 水蓝渐变实线：经 Server 中继的反向隧道（HTTP/TCP 主路径），与主视觉的渠水同源。
 *  - emerald 虚线：客户端互联（信令 + 加密 frame 直连 / TURN 回退）。
 *
 * 暗色协调：节点 fill/stroke 走 CSS class `.topo-card-fill / .topo-card-stroke`，
 * 由 index.css 通过 .light/.dark 切换，避免硬编码白底在暗色下扎眼。
 * 文字一律 fill="currentColor" 跟随主题。
 */
function TopologyDiagram() {
  return (
    <div className="topology-panel glass glass-border rounded-md border p-5">
      <MobileTopologyDiagram />
      <svg
        className="topology-svg hidden sm:block"
        viewBox="0 0 1080 440"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="组网形态：公网用户经 Server 中继到客户端 A 内网服务，客户端 A 与客户端 B 之间走对端直连通道"
      >
        <defs>
          <marker id="topo-arrow-blue" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" fill="var(--landing-action)" />
          </marker>
          <marker id="topo-arrow-emerald" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" fill="rgb(16,185,129)" />
          </marker>
          {/* 中继路径 = 渠：描边从动作蓝渐到水蓝，与主视觉的槽中活水同源 */}
          <linearGradient id="topo-water" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="var(--landing-action)" />
            <stop offset="1" stopColor="var(--specus-water)" />
          </linearGradient>
        </defs>

        {/* 左节点：公网用户 (x: 30-230, y 居中于 220 附近) */}
        <g>
          <rect className="topo-card" x="30" y="170" width="200" height="100" rx="10" />
          <text x="130" y="208" textAnchor="middle" fontSize="14" fill="currentColor" fontWeight="600">公网用户 / API</text>
          <text x="130" y="232" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.72">浏览器 · curl · SSH 等</text>
          <text x="130" y="252" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.55">无须感知隧道存在</text>
        </g>

        {/* 中节点：Server 控制面 (x: 420-660, y: 80-360, 宽 240, 高 280) */}
        <g>
          <rect className="topo-server" x="420" y="80" width="240" height="280" rx="12" fill="var(--landing-action)" />
          <text x="540" y="122" textAnchor="middle" fontSize="15" fill="#ffffff" fontWeight="700">Server 控制面</text>
          <line x1="450" y1="138" x2="630" y2="138" stroke="rgba(255,255,255,0.35)" strokeWidth="1" />
          <text x="540" y="166" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.92">7010 控制连接</text>
          <text x="540" y="186" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.92">8088 管理 / HTTP 网关</text>
          <line x1="450" y1="206" x2="630" y2="206" stroke="rgba(255,255,255,0.22)" strokeWidth="1" />
          <text x="540" y="232" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.92">TCP 端口映射</text>
          <text x="540" y="252" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.92">租户 · ACL · 路由</text>
          <text x="540" y="272" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.92">PEER_CONTROL 信令</text>
          <line x1="450" y1="292" x2="630" y2="292" stroke="rgba(255,255,255,0.22)" strokeWidth="1" />
          <text x="540" y="318" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.86">STUN / TURN</text>
          <text x="540" y="338" textAnchor="middle" fontSize="12" fill="#ffffff" opacity="0.86">实时观测 · 流量审计</text>
        </g>

        {/* 右上节点：客户端 A (x: 850-1050, y: 90-200) */}
        <g>
          <rect className="topo-card" x="850" y="90" width="200" height="110" rx="10" />
          <text x="950" y="128" textAnchor="middle" fontSize="14" fill="currentColor" fontWeight="600">客户端 A</text>
          <text x="950" y="152" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.72">内网服务 · 反向隧道</text>
          <text x="950" y="172" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.55">127.0.0.1:8080 等</text>
        </g>

        {/* 右下节点：客户端 B (x: 850-1050, y: 240-360) */}
        <g>
          <rect className="topo-card-peer" x="850" y="240" width="200" height="120" rx="10" />
          <text x="950" y="278" textAnchor="middle" fontSize="14" fill="currentColor" fontWeight="600">客户端 B</text>
          <text x="950" y="302" textAnchor="middle" fontSize="11.5" fill="rgb(5,150,105)" fontWeight="600" className="dark:opacity-[0.95]" opacity="0.95">对端互联</text>
          <text x="950" y="322" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.62">virtualIp 100.96.0.0/11</text>
          <text x="950" y="342" textAnchor="middle" fontSize="11.5" fill="currentColor" opacity="0.5">UDP 直连 / TURN 回退</text>
        </g>

        {/* === 中继路径：公网用户 ↔ Server （上下分开，避免重合） === */}
        {/* 公网请求：左下 → Server 左上 */}
        <line x1="232" y1="205" x2="418" y2="170" stroke="url(#topo-water)" strokeWidth="2" markerEnd="url(#topo-arrow-blue)" className="topology-relay-flow" />
        <text x="320" y="178" textAnchor="middle" fontSize="11.5" fill="var(--landing-action)" fontWeight="600">公网请求</text>
        {/* 响应：Server 左下 → 公网用户右下 */}
        <line x1="418" y1="270" x2="232" y2="240" stroke="url(#topo-water)" strokeWidth="2" markerEnd="url(#topo-arrow-blue)" className="topology-relay-flow" opacity="0.6" />
        <text x="320" y="270" textAnchor="middle" fontSize="11.5" fill="var(--landing-action)" opacity="0.78" fontWeight="600">响应</text>

        {/* === 中继路径：Server ↔ 客户端 A === */}
        <line x1="662" y1="160" x2="848" y2="130" stroke="url(#topo-water)" strokeWidth="2" markerEnd="url(#topo-arrow-blue)" className="topology-relay-flow" />
        <text x="755" y="135" textAnchor="middle" fontSize="11.5" fill="var(--landing-action)" fontWeight="600">下发 / 转发</text>
        <line x1="848" y1="180" x2="662" y2="195" stroke="url(#topo-water)" strokeWidth="2" markerEnd="url(#topo-arrow-blue)" className="topology-relay-flow" opacity="0.6" />
        <text x="755" y="205" textAnchor="middle" fontSize="11.5" fill="var(--landing-action)" opacity="0.78" fontWeight="600">上行字节</text>

        {/* === 信令路径：Server ↔ 客户端 B（emerald 虚线，label 放线上方留白处） === */}
        <line x1="662" y1="290" x2="848" y2="280" stroke="rgb(16,185,129)" strokeWidth="2" strokeDasharray="6 5" markerEnd="url(#topo-arrow-emerald)" className="topology-peer-flow" />
        <text x="755" y="270" textAnchor="middle" fontSize="11.5" fill="rgb(5,150,105)" fontWeight="700">信令 · ACL</text>
        <line x1="848" y1="320" x2="662" y2="330" stroke="rgb(16,185,129)" strokeWidth="2" strokeDasharray="6 5" markerEnd="url(#topo-arrow-emerald)" className="topology-peer-flow" opacity="0.6" />
        <text x="755" y="350" textAnchor="middle" fontSize="11.5" fill="rgb(5,150,105)" opacity="0.78" fontWeight="600">心跳 · 设备上报</text>

        {/* === Peer 直连：客户端 A ↔ 客户端 B（垂直方向，靠右走，远离 Server 边） === */}
        <path
          d="M 1010 200 C 1080 215, 1080 235, 1010 250"
          fill="none"
          stroke="rgb(16,185,129)"
          strokeWidth="2"
          strokeDasharray="5 6"
          markerEnd="url(#topo-arrow-emerald)"
          className="topology-peer-flow"
        />
        <path
          d="M 890 250 C 870 235, 870 215, 890 200"
          fill="none"
          stroke="rgb(16,185,129)"
          strokeWidth="2"
          strokeDasharray="5 6"
          markerEnd="url(#topo-arrow-emerald)"
          className="topology-peer-flow"
          opacity="0.7"
        />
        <text x="950" y="226" textAnchor="middle" fontSize="11.5" fill="rgb(5,150,105)" fontWeight="700">Peer 直连</text>
      </svg>
      <p className="mt-3 text-tiny leading-5 text-zinc-600 dark:text-zinc-400">
        实线（蓝）= 经 Server 中继的反向隧道，HTTP 路由与 TCP 端口映射走这条主路径；
        虚线（绿）= 客户端互联，控制面下发设备清单与会话凭证后，两端在 UDP 直连或 TURN 回退上跑加密 frame 数据面。
      </p>
    </div>
  );
}

function MobileTopologyDiagram() {
  return (
    <div
      className="topology-mobile sm:hidden"
      role="img"
      aria-label="组网形态移动端动画：公网用户经 Server 中继到客户端 A 内网服务，客户端 A 与客户端 B 之间走对端直连或 TURN 回退"
    >
      <div className="topology-mobile-section topology-mobile-section-relay">
        <div className="topology-mobile-heading">
          <span>公网访问路径</span>
          <strong>Relay</strong>
        </div>
        <div className="topology-mobile-chain">
          <MobileTopologyNode title="公网用户 / API" meta="浏览器、curl、SSH 等" />
          <MobileTopologyEdge label="公网请求 / 响应" tone="relay" />
          <MobileTopologyNode title="Server" meta="HTTP 网关 · TCP 映射 · 租户 ACL" tone="server" />
          <MobileTopologyEdge label="反向隧道" tone="relay" />
          <MobileTopologyNode title="客户端 A" meta="访问内网服务 127.0.0.1:8080" />
        </div>
      </div>

      <div className="topology-mobile-section topology-mobile-section-peer">
        <div className="topology-mobile-heading">
          <span>客户端互联路径</span>
          <strong>Peer / TURN</strong>
        </div>
        <div className="topology-mobile-signal">Server 只负责 ACL 校验、设备清单与 PEER_CONTROL 信令</div>
        <div className="topology-mobile-peer-row">
          <MobileTopologyNode title="客户端 A" meta="100.96.0.0/11" compact />
          <div className="topology-mobile-peer-link" aria-hidden="true">
            <span>直连</span>
            <span>TURN 回退</span>
          </div>
          <MobileTopologyNode title="客户端 B" meta="加密 frame 数据面" tone="peer" compact />
        </div>
      </div>

      <div className="topology-mobile-note">
        蓝色表示公网访问经 Server 中继；绿色表示客户端之间的数据面直连，失败后回退 TURN。
      </div>
    </div>
  );
}

function MobileTopologyNode({
  compact = false,
  meta,
  title,
  tone = "default",
}: {
  compact?: boolean;
  meta: string;
  title: string;
  tone?: "default" | "peer" | "server";
}) {
  return (
    <div className={`topology-mobile-node topology-mobile-node-${tone} ${compact ? "topology-mobile-node-compact" : ""}`}>
      <strong>{title}</strong>
      <span>{meta}</span>
    </div>
  );
}

function MobileTopologyEdge({ label, tone }: { label: string; tone: "peer" | "relay" }) {
  return (
    <div className={`topology-mobile-edge topology-mobile-edge-${tone}`} aria-hidden="true">
      <span>{label}</span>
    </div>
  );
}

const IMPL_LABELS: Record<ClientImplementation, string> = {
  java: "Java 客户端",
  go: "Go 客户端",
  csharp: ".NET 客户端",
};

const IMPL_ORDER: ClientImplementation[] = ["java", "go", "csharp"];

async function fetchLandingClientDownloads(): Promise<ClientDownloadLink[]> {
  try {
    const response = await fetch("/api/public/client-downloads");
    if (!response.ok) {
      return [];
    }
    const data = await response.json();
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function ClientDownloadsSection() {
  const [links, setLinks] = useState<ClientDownloadLink[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let cancelScheduledLoad = () => {};
    const load = async () => {
      const data = await fetchLandingClientDownloads();
      if (!cancelled) {
        setLinks(data);
        setLoaded(true);
      }
    };
    if ("requestIdleCallback" in window && "cancelIdleCallback" in window) {
      const handle = window.requestIdleCallback(() => void load(), { timeout: 2200 });
      cancelScheduledLoad = () => window.cancelIdleCallback(handle);
    } else {
      const handle = globalThis.setTimeout(() => void load(), 1200);
      cancelScheduledLoad = () => globalThis.clearTimeout(handle);
    }
    return () => {
      cancelled = true;
      cancelScheduledLoad();
    };
  }, []);

  // 未加载完不渲染；加载完无数据也不渲染，避免空白 section 干扰未登录用户
  if (!loaded || links.length === 0) {
    return null;
  }

  const grouped = IMPL_ORDER
    .map((impl) => ({ implementation: impl, items: links.filter((l) => l.implementation === impl) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="mt-10">
      <div className="mb-6 max-w-2xl">
        <h2 className="text-2xl font-semibold tracking-tight text-zinc-950 dark:text-white">获取客户端</h2>
        <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
          选择对应的实现下载，所有客户端共享同一份 JSON 配置格式。详细启动方法见登录后的「帮助文档」。
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {grouped.map(({ implementation, items }) => (
          <section
            key={implementation}
            className="app-apple-landing-surface glass glass-border rounded-md border text-zinc-950 shadow-sm dark:text-white dark:shadow-none"
          >
            <div className="grid gap-3 p-4">
              <span className="w-fit rounded-md bg-primary-100 px-2 py-1 text-tiny text-primary-700 dark:bg-primary-500/15 dark:text-primary-300">
                {IMPL_LABELS[implementation]}
              </span>
              <div className="flex flex-col gap-2">
                {items.map((link) => (
                  <a
                    key={link.id}
                    className="glass-chip glass-border group flex items-start justify-between gap-2 rounded-md border p-2.5 transition hover:border-primary-500/40 hover:bg-white/85 dark:hover:bg-white/[0.08]"
                    href={link.downloadUrl}
                    rel="noopener noreferrer"
                    target="_blank"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-small font-medium text-zinc-950 group-hover:text-primary-700 dark:text-white dark:group-hover:text-primary-400">
                        {link.displayName}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1 text-tiny text-zinc-600 dark:text-zinc-400">
                        <span>{shortPlatform(link.platform)}</span>
                        <span>·</span>
                        <span>{shortArch(link.arch)}</span>
                      </div>
                    </div>
                    <span className="shrink-0 text-tiny text-zinc-500 group-hover:text-primary-700 dark:group-hover:text-primary-400">↗</span>
                  </a>
                ))}
              </div>
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

function shortPlatform(platform: string): string {
  switch (platform) {
    case "windows": return "Windows";
    case "linux": return "Linux";
    case "macos": return "macOS";
    case "any": return "跨平台";
    default: return platform;
  }
}

function shortArch(arch: string): string {
  switch (arch) {
    case "x64": return "x86_64";
    case "arm64": return "ARM64";
    case "any": return "跨架构";
    default: return arch;
  }
}

function PrincipleCard({
  accent,
  badge,
  children,
  className = "",
  description,
  index,
  motif,
  preview,
  title,
}: {
  accent: "amber" | "blue" | "emerald";
  badge: string;
  children: ReactNode;
  className?: string;
  description: string;
  index: string;
  /** 意象小章：渠 / 引 / 洞，与主视觉三连拱一一对应 */
  motif?: string;
  preview?: boolean;
  title: string;
}) {
  const handleMouseMove = (event: ReactMouseEvent<HTMLElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty("--spotlight-x", `${event.clientX - rect.left}px`);
    event.currentTarget.style.setProperty("--spotlight-y", `${event.clientY - rect.top}px`);
  };

  return (
    <article
      className={`principle-card principle-card-${accent} glass glass-border rounded-md border text-zinc-950 shadow-sm dark:text-white dark:shadow-none ${className}`}
      onMouseMove={handleMouseMove}
    >
      <span className="principle-card-accent" aria-hidden="true" />
      <span className="principle-card-index" aria-hidden="true">{index}</span>
      <div className="principle-card-body grid gap-5 p-5">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            {motif && <span className="principle-motif" aria-hidden="true">{motif}</span>}
            <span className="principle-badge w-fit rounded-md px-2 py-1 text-tiny">{badge}</span>
            {preview && <span className="preview-badge">Preview</span>}
          </div>
          <h3 className="text-lg font-semibold text-zinc-950 dark:text-white">{title}</h3>
          <p className="text-small leading-6 text-zinc-600 dark:text-zinc-400">{description}</p>
        </div>
        {children}
      </div>
    </article>
  );
}

function FlowDiagram({
  nodes,
  variant,
}: {
  nodes: Array<{ eyebrow: string; title: string; meta: string }>;
  variant: "http" | "port" | "peer";
}) {
  return (
    <div className={`principle-flowgrid principle-flowgrid-${variant}`} aria-label={`${variant} 转发流程`}>
      {nodes.map((node, index) => (
        <FlowStep
          key={node.title}
          index={index}
          isFirst={index === 0}
          isLast={index === nodes.length - 1}
          node={node}
          showEdge={index < nodes.length - 1}
        />
      ))}
    </div>
  );
}

function FlowStep({
  index,
  isFirst,
  isLast,
  node,
  showEdge,
}: {
  index: number;
  isFirst: boolean;
  isLast: boolean;
  node: { eyebrow: string; title: string; meta: string };
  showEdge: boolean;
}) {
  const nodeStyle = { "--node-delay": `${index * 1.55}s` } as CSSProperties;
  const edgeStyle = { "--edge-delay": `${index * 1.55 + 0.55}s` } as CSSProperties;
  const nodeClass = `principle-node${isFirst ? " principle-node-first" : ""}${isLast ? " principle-node-last" : ""}`;

  return (
    <>
      <div className={nodeClass} style={nodeStyle}>
        <span className="principle-node-android-glow" aria-hidden="true" />
        <span className="principle-node-index">{index + 1}</span>
        <span className="principle-node-eyebrow">{node.eyebrow}</span>
        <strong>{node.title}</strong>
        <span className="principle-node-meta">{node.meta}</span>
      </div>
      {showEdge && (
        <div
          className="principle-edge"
          style={edgeStyle}
          aria-hidden="true"
        >
          <span className="principle-edge-android-packet" />
          <span className="principle-edge-android-beam" />
        </div>
      )}
    </>
  );
}
