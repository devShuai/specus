import { useEffect, useRef, useState, type CSSProperties, type FormEvent, type ReactNode } from "react";
import { Button, Card, CardBody, CardHeader, Chip, Divider, Input } from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { notifyError } from "../components/toast";
import { ThemeToggleButton } from "../components/ThemeToggleButton";
import { AppLogo } from "../components/AppLogo";
import { HeroRuntime } from "../components/HeroRuntime";
import { fetchPublicClientDownloads } from "../api/client";
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

const inputClassNames = {
  inputWrapper:
    "landing-input-wrapper border-white/15 bg-white/[0.72] !text-zinc-950 shadow-sm hover:bg-white/[0.84] data-[hover=true]:border-cyan-500/60 group-data-[focus=true]:!border-cyan-500 group-data-[focus=true]:bg-white dark:!border-transparent dark:bg-white/[0.08] dark:!text-white dark:hover:bg-white/[0.12] dark:group-data-[focus=true]:bg-zinc-950/85 dark:group-data-[focus=true]:!border-transparent",
  label:
    "!text-zinc-700 group-data-[focus=true]:!text-cyan-700 dark:!text-zinc-300 dark:group-data-[focus=true]:!text-cyan-200",
  input: "!text-zinc-950 placeholder:text-zinc-500 dark:!text-white dark:placeholder:text-zinc-500",
} as const;

const landingDebugTargets = [
  { key: "shell", selector: ".landing-shell" },
  { key: "topology-panel", selector: ".topology-panel" },
  { key: "topology-mobile", selector: ".topology-mobile" },
  { key: "topology-peer-link", selector: ".topology-mobile-peer-link" },
  { key: "topology-peer-label", selector: ".topology-mobile-peer-link span" },
  { key: "principle-card", selector: ".principle-card" },
  { key: "principle-card-body", selector: ".principle-card-body" },
  { key: "principle-flowgrid", selector: ".principle-flowgrid" },
  { key: "principle-node", selector: ".principle-node" },
  { key: "principle-note", selector: ".principle-note span" },
] as const;

type LandingDebugRect = {
  bottom: number;
  height: number;
  left: number;
  right: number;
  top: number;
  width: number;
  x: number;
  y: number;
};

type LandingDebugAncestor = {
  className: string;
  css: Pick<LandingDebugElement["css"], "clipPath" | "contain" | "maskImage" | "overflow" | "overflowX" | "overflowY" | "transform">;
  rect: LandingDebugRect;
  tagName: string;
};

type LandingDebugElement = {
  ancestorClips: LandingDebugAncestor[];
  css: {
    backfaceVisibility: string;
    clipPath: string;
    contain: string;
    contentVisibility: string;
    display: string;
    filter: string;
    isolation: string;
    maskImage: string;
    opacity: string;
    overflow: string;
    overflowX: string;
    overflowY: string;
    position: string;
    transform: string;
    visibility: string;
    webkitBackfaceVisibility: string;
    zIndex: string;
  };
  index: number;
  inViewport: boolean;
  key: string;
  rect: LandingDebugRect;
  selector: string;
  text: string;
  visibleByLayout: boolean;
};

type LandingDebugSnapshot = {
  elements: LandingDebugElement[];
  environment: {
    colorScheme: string;
    dpr: number;
    hash: string;
    prefersReducedMotion: boolean;
    screen: string;
    scroll: { x: number; y: number };
    themeClass: string;
    timestamp: string;
    url: string;
    userAgent: string;
    viewport: string;
    visualViewport: string;
  };
};

export function LoginPage() {
  return (
    <HeroRuntime>
      <LoginPageContent />
    </HeroRuntime>
  );
}

function LoginPageContent() {
  const { oidcConfig, loginHint, passwordLogin, startOidcLogin } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const loginPanelRef = useRef<HTMLDivElement>(null);
  const landingDebugEnabled = useLandingDebugEnabled();

  usePageSeo({
    title: "shuai-tunnel · 自托管内网穿透 / HTTP 反向代理 / 对端互联控制面",
    description:
      "shuai-tunnel 是一套自托管的内网穿透控制面，支持 TCP 端口映射、HTTP 反向代理（含路径改写）、私有组网对端互联与浏览器 NAT 类型检测，自带 Java / Go / .NET 多语言客户端。",
    canonical: "https://tunnel.devshuai.com/",
    keywords:
      "内网穿透,NAT 检测,STUN 探测,Symmetric NAT,WebRTC,HTTP 反向代理,对端互联,Peer Mesh,P2P 打洞,frp 替代,自托管,shuai-tunnel",
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      "name": "shuai-tunnel",
      "url": "https://tunnel.devshuai.com/",
      "applicationCategory": "DeveloperApplication",
      "operatingSystem": "Linux, Windows, macOS",
      "description":
        "自托管内网穿透与对端互联控制面：TCP 端口映射、HTTP 反向代理（含路径改写）、Peer Mesh 私有组网与浏览器 NAT 类型检测。",
      "offers": { "@type": "Offer", "price": "0", "priceCurrency": "CNY" },
      "creator": { "@type": "Person", "name": "devShuai" },
    },
  });

  const passwordEnabled = oidcConfig?.passwordLoginEnabled ?? true;
  const oidcEnabled = oidcConfig?.configured ?? false;

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      await passwordLogin(username, password);
    } catch (error) {
      notifyError(error, "登录失败");
    } finally {
      setSubmitting(false);
    }
  };

  const focusLogin = () => {
    loginPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  return (
    <main className="landing-shell min-h-screen text-zinc-950 dark:text-white">
      <SignalField />
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <section className="relative z-10 mx-auto flex w-full max-w-[1440px] flex-col px-5 pb-10 pt-5 sm:px-8 lg:min-h-[88vh]">
        <header className="flex items-center justify-between gap-4">
          <AppLogo label="shuai-tunnel" subtitle="内网服务接入控制面" />
          <div className="flex items-center gap-2">
            <ThemeToggleButton className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" />
            <Button as="a" href="#/nat-detect" radius="sm" className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" variant="flat">
              NAT 检测
            </Button>
            <Button radius="sm" className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" variant="flat" onPress={focusLogin}>
              进入控制台
            </Button>
          </div>
        </header>

        <div className="grid flex-1 items-center gap-8 py-10 lg:grid-cols-[minmax(0,1fr)_420px]">
          <div className="flex min-w-0 flex-col gap-7">
            <Chip
              className="w-fit border border-emerald-500/35 bg-emerald-300/15 px-2 text-emerald-700 dark:border-emerald-300/35 dark:bg-emerald-300/10 dark:text-emerald-100"
              radius="sm"
              variant="flat"
            >
              Secure tunnel control plane
            </Chip>

            <div className="max-w-3xl">
              <h1 className="text-5xl font-semibold leading-tight text-zinc-950 dark:text-white">shuai-tunnel</h1>
              <p className="mt-5 max-w-2xl text-lg leading-8 text-zinc-700 dark:text-zinc-300">
                把公网入口、对端互联与内网服务发布收束到一个控制面，多语言客户端、多租户、可观测，TLS 开箱即用。
              </p>
            </div>

            <div className="grid max-w-3xl grid-cols-2 gap-3 sm:grid-cols-4">
              {metrics.map((item) => (
                <div key={item.label} className="rounded-md border border-black/10 bg-white/65 p-3 shadow-sm dark:border-white/10 dark:bg-white/[0.055] dark:shadow-none">
                  <p className="text-xl font-semibold text-cyan-700 dark:text-cyan-100">{item.value}</p>
                  <p className="mt-1 text-tiny text-zinc-600 dark:text-zinc-400">{item.label}</p>
                </div>
              ))}
            </div>

            <div className="flex max-w-3xl flex-col gap-3 rounded-md border border-black/10 bg-white/70 p-4 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-black/30 dark:shadow-none sm:flex-row sm:items-center">
              {flowNodes.map((node, index) => (
                <div key={node} className="flex min-w-0 flex-1 items-center gap-3">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-amber-500/35 bg-amber-300/20 text-small text-amber-800 dark:border-amber-300/30 dark:bg-amber-300/10 dark:text-amber-100">
                    {index + 1}
                  </span>
                  <span className="truncate text-small text-zinc-700 dark:text-zinc-200">{node}</span>
                  {index < flowNodes.length - 1 && <span className="landing-route-line hidden h-px flex-1 sm:block" />}
                </div>
              ))}
            </div>
          </div>

          <div ref={loginPanelRef} id="login-panel">
            <Card shadow="none" className="landing-card rounded-md border border-black/10 bg-white/80 text-zinc-950 backdrop-blur-xl dark:border-white/15 dark:bg-white/[0.08] dark:text-white">
              <CardHeader className="flex flex-col items-start gap-2 px-5 pb-2 pt-5">
                <Chip radius="sm" className="bg-cyan-300/25 text-cyan-800 dark:bg-cyan-300/15 dark:text-cyan-100" variant="flat">
                  管理台登录
                </Chip>
                <div>
                  <h2 className="text-2xl font-semibold text-zinc-950 dark:text-white">进入控制台</h2>
                  <p className="mt-1 text-small text-zinc-600 dark:text-zinc-400">{loginHint}</p>
                </div>
              </CardHeader>
              <CardBody className="gap-4 px-5 pb-5">
                {passwordEnabled && (
                  <form className="flex flex-col gap-3" onSubmit={onSubmit}>
                    <Input
                      label="用户名"
                      value={username}
                      onValueChange={setUsername}
                      autoComplete="username"
                      variant="bordered"
                      radius="sm"
                      classNames={inputClassNames}
                      isRequired
                    />
                    <Input
                      label="密码"
                      type="password"
                      value={password}
                      onValueChange={setPassword}
                      autoComplete="current-password"
                      variant="bordered"
                      radius="sm"
                      classNames={inputClassNames}
                      isRequired
                    />
                    <Button
                      type="submit"
                      radius="sm"
                      className="bg-cyan-300 font-semibold text-zinc-950"
                      isLoading={submitting}
                      isDisabled={!username || !password}
                    >
                      登录管理台
                    </Button>
                  </form>
                )}

                {passwordEnabled && oidcEnabled && (
                  <div className="flex items-center gap-3 text-tiny text-zinc-500 dark:text-zinc-500">
                    <Divider className="flex-1 bg-black/10 dark:bg-white/10" />
                    <span>或</span>
                    <Divider className="flex-1 bg-black/10 dark:bg-white/10" />
                  </div>
                )}

                {oidcEnabled && (
                  <Button
                    radius="sm"
                    variant="bordered"
                    className="border-black/20 text-zinc-950 dark:border-white/20 dark:text-white"
                    onPress={() => void startOidcLogin()}
                  >
                    使用 OIDC 登录
                  </Button>
                )}

                {!passwordEnabled && !oidcEnabled && (
                  <p className="rounded-md border border-danger/40 bg-danger/10 p-3 text-small text-danger-100">
                    未配置任何登录方式：请设置用户名/密码或 OIDC
                  </p>
                )}
              </CardBody>
            </Card>
          </div>
        </div>
      </section>

      <section className="relative z-10 border-t border-black/10 bg-white/65 px-5 py-10 backdrop-blur-md dark:border-white/10 dark:bg-black/50 sm:px-8">
        <div className="mx-auto max-w-[1440px]">
          <div className="mb-6 max-w-2xl">
            <h2 className="text-2xl font-semibold text-zinc-950 dark:text-white">组网形态</h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              一套控制面承担两类流量：公网用户经 Server 中继访问内网服务，受控客户端之间在控制面协调下走对端互联通道。
            </p>
          </div>
          <TopologyDiagram />

          <div className="mb-6 mt-12 max-w-2xl">
            <h2 className="text-2xl font-semibold text-zinc-950 dark:text-white">三类接入能力</h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              HTTP 路由与端口映射承担反向中继；客户端互联（Peer）通过控制面信令撮合，加密 frame 走 UDP 直连或 TURN 回退。
            </p>
          </div>

          <div className="mb-10 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            <PrincipleCard
              badge="HTTP route"
              title="HTTP 路由：按 Host 与 Path 进入内网 Web 服务"
              description="请求先进 Server 的 HTTP 网关，管理端配置决定命中哪个租户、客户端和目标地址，再把请求沿客户端长连接送回内网。"
              accent="cyan"
            >
              <FlowDiagram nodes={httpRouteNodes} variant="http" />
              <div className="principle-note">
                <span>Host: app.example.com</span>
                <span>Route: /api → Demo / 127.0.0.1:8080</span>
              </div>
            </PrincipleCard>

            <PrincipleCard
              badge="Port mapping"
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
              title="客户端互联：受控对端之间的直连通道"
              description="客户端登录时上报 X25519 公钥并接收 roster；控制面校验 ACL 后撮合两端通过 PEER_CONTROL 通道协商身份与会话凭证。"
              accent="emerald"
            >
              <FlowDiagram nodes={peerNodes} variant="peer" />
              <div className="principle-note">
                <span>Tunnel CIDR: 100.96.0.0/11</span>
                <span>Identity: X25519 公钥 + iceCredential</span>
              </div>
            </PrincipleCard>
          </div>

          <div className="mb-6 mt-12 max-w-2xl">
            <h2 className="text-2xl font-semibold text-zinc-950 dark:text-white">平台特性</h2>
            <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
              从协议字节级兼容到部署形态，shuai-tunnel 把传统反向隧道工具缺失的工程化关切补齐。
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {featureCards.map((feature) => (
              <Card
                key={feature.title}
                shadow="none"
                className="rounded-md border border-black/10 bg-white/70 text-zinc-950 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-white/[0.055] dark:text-white dark:shadow-none"
              >
                <CardBody className="gap-3 p-4">
                  <span className="w-fit rounded-md border border-cyan-500/25 bg-cyan-300/15 px-2 py-1 text-tiny text-cyan-700 dark:border-cyan-300/25 dark:bg-cyan-300/10 dark:text-cyan-100">
                    {feature.label}
                  </span>
                  <h3 className="text-base font-semibold text-zinc-950 dark:text-white">{feature.title}</h3>
                  <p className="text-small leading-6 text-zinc-600 dark:text-zinc-400">{feature.description}</p>
                </CardBody>
              </Card>
            ))}
          </div>

          <div className="mt-12 flex flex-col gap-3 rounded-md border border-black/10 bg-white/70 p-5 backdrop-blur-md dark:border-white/10 dark:bg-white/[0.04]">
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
                  className="inline-flex items-baseline gap-1.5 rounded-md border border-black/10 bg-white/65 px-3 py-1.5 text-tiny text-zinc-700 dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300"
                >
                  <span className="font-semibold text-cyan-700 dark:text-cyan-200">{chip.name}</span>
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

      {landingDebugEnabled && <LandingDebugPanel />}
    </main>
  );
}

function useLandingDebugEnabled() {
  const [enabled, setEnabled] = useState(() => isLandingDebugEnabled());

  useEffect(() => {
    const update = () => setEnabled(isLandingDebugEnabled());
    window.addEventListener("hashchange", update);
    window.addEventListener("popstate", update);
    return () => {
      window.removeEventListener("hashchange", update);
      window.removeEventListener("popstate", update);
    };
  }, []);

  return enabled;
}

function isLandingDebugEnabled() {
  if (typeof window === "undefined") {
    return false;
  }

  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.get("landingDebug") === "1") {
    return true;
  }

  const hash = window.location.hash.replace(/^#/, "");
  const hashQueryIndex = hash.indexOf("?");
  const hashParamsText = hashQueryIndex >= 0 ? hash.slice(hashQueryIndex + 1) : hash;
  return new URLSearchParams(hashParamsText).get("landingDebug") === "1";
}

function LandingDebugPanel() {
  const [snapshot, setSnapshot] = useState<LandingDebugSnapshot>(() => collectLandingDebugSnapshot());
  const [collapsed, setCollapsed] = useState(false);
  const [copyLabel, setCopyLabel] = useState("复制诊断");

  useEffect(() => {
    const update = () => setSnapshot(collectLandingDebugSnapshot());
    const interval = window.setInterval(update, 1000);
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, { passive: true });
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update);
    };
  }, []);

  const suspectElements = snapshot.elements.filter(
    (element) => !element.visibleByLayout || !element.inViewport || element.ancestorClips.length > 0,
  );

  const copySnapshot = async () => {
    const text = JSON.stringify(snapshot, null, 2);
    try {
      await copyText(text);
      setCopyLabel("已复制");
    } catch {
      setCopyLabel("复制失败");
    } finally {
      window.setTimeout(() => setCopyLabel("复制诊断"), 1400);
    }
  };

  if (collapsed) {
    return (
      <button className="landing-debug-pill" type="button" onClick={() => setCollapsed(false)}>
        Landing debug
      </button>
    );
  }

  return (
    <aside className="landing-debug-panel" aria-label="Landing debug diagnostics">
      <div className="landing-debug-panel-header">
        <strong>Landing debug</strong>
        <div className="landing-debug-panel-actions">
          <button type="button" onClick={() => setSnapshot(collectLandingDebugSnapshot())}>刷新</button>
          <button type="button" onClick={() => void copySnapshot()}>{copyLabel}</button>
          <button type="button" onClick={() => setCollapsed(true)}>收起</button>
        </div>
      </div>

      <div className="landing-debug-panel-body">
        <section>
          <h4>环境</h4>
          <dl>
            <div><dt>viewport</dt><dd>{snapshot.environment.viewport}</dd></div>
            <div><dt>visual</dt><dd>{snapshot.environment.visualViewport}</dd></div>
            <div><dt>dpr</dt><dd>{snapshot.environment.dpr}</dd></div>
            <div><dt>scroll</dt><dd>{snapshot.environment.scroll.x}, {snapshot.environment.scroll.y}</dd></div>
            <div><dt>theme</dt><dd>{snapshot.environment.themeClass || "-"}</dd></div>
            <div><dt>motion</dt><dd>{snapshot.environment.prefersReducedMotion ? "reduce" : "normal"}</dd></div>
            <div><dt>ua</dt><dd>{snapshot.environment.userAgent}</dd></div>
          </dl>
        </section>

        <section>
          <h4>可疑项 {suspectElements.length}</h4>
          {suspectElements.length === 0 ? (
            <p className="landing-debug-muted">当前采样未发现 display/visibility/overflow 直接异常。</p>
          ) : (
            <ul className="landing-debug-list">
              {suspectElements.slice(0, 12).map((element) => (
                <li key={`${element.key}-${element.index}`}>
                  <strong>{element.key}[{element.index}]</strong>
                  <span>{element.visibleByLayout ? "layout ok" : "layout hidden"} · {element.inViewport ? "in viewport" : "out viewport"} · clips {element.ancestorClips.length}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h4>元素采样</h4>
          <div className="landing-debug-elements">
            {snapshot.elements.slice(0, 28).map((element) => (
              <details key={`${element.key}-${element.index}`}>
                <summary>
                  {element.key}[{element.index}] {formatDebugRect(element.rect)}
                </summary>
                <pre>{JSON.stringify(element, null, 2)}</pre>
              </details>
            ))}
          </div>
        </section>
      </div>
    </aside>
  );
}

function collectLandingDebugSnapshot(): LandingDebugSnapshot {
  if (typeof window === "undefined") {
    return {
      elements: [],
      environment: {
        colorScheme: "unknown",
        dpr: 1,
        hash: "",
        prefersReducedMotion: false,
        screen: "",
        scroll: { x: 0, y: 0 },
        themeClass: "",
        timestamp: "",
        url: "",
        userAgent: "",
        viewport: "",
        visualViewport: "",
      },
    };
  }

  const elements = landingDebugTargets.flatMap(({ key, selector }) =>
    Array.from(document.querySelectorAll(selector))
      .slice(0, selector.includes("principle-node") ? 16 : 6)
      .map((element, index) => collectLandingDebugElement(key, selector, element, index)),
  );

  const visualViewport = window.visualViewport;
  return {
    elements,
    environment: {
      colorScheme: window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light",
      dpr: window.devicePixelRatio || 1,
      hash: window.location.hash,
      prefersReducedMotion: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
      screen: `${window.screen.width}x${window.screen.height}`,
      scroll: { x: Math.round(window.scrollX), y: Math.round(window.scrollY) },
      themeClass: document.documentElement.className,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      userAgent: window.navigator.userAgent,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      visualViewport: visualViewport
        ? `${Math.round(visualViewport.width)}x${Math.round(visualViewport.height)} scale=${visualViewport.scale}`
        : "unavailable",
    },
  };
}

function collectLandingDebugElement(
  key: string,
  selector: string,
  element: Element,
  index: number,
): LandingDebugElement {
  const rect = toLandingDebugRect(element.getBoundingClientRect());
  const css = readDebugCss(element);
  const visibleByLayout =
    rect.width > 0 &&
    rect.height > 0 &&
    css.display !== "none" &&
    css.visibility !== "hidden" &&
    css.opacity !== "0";

  return {
    ancestorClips: collectDebugAncestorClips(element),
    css,
    index,
    inViewport: rect.bottom > 0 && rect.right > 0 && rect.top < window.innerHeight && rect.left < window.innerWidth,
    key,
    rect,
    selector,
    text: (element.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 180),
    visibleByLayout,
  };
}

function collectDebugAncestorClips(element: Element): LandingDebugAncestor[] {
  const ancestors: LandingDebugAncestor[] = [];
  let current = element.parentElement;

  while (current && current !== document.documentElement && ancestors.length < 8) {
    const css = readDebugCss(current);
    const overflowValues = [css.overflow, css.overflowX, css.overflowY];
    const hasOverflowClip = overflowValues.some((value) => ["auto", "clip", "hidden", "scroll"].includes(value));
    const hasPaintContain = /\b(content|paint|strict)\b/.test(css.contain);
    const hasMask = css.maskImage !== "none";
    const hasClipPath = css.clipPath !== "none";

    if (hasOverflowClip || hasPaintContain || hasMask || hasClipPath) {
      ancestors.push({
        className: current.className.toString(),
        css: {
          clipPath: css.clipPath,
          contain: css.contain,
          maskImage: css.maskImage,
          overflow: css.overflow,
          overflowX: css.overflowX,
          overflowY: css.overflowY,
          transform: css.transform,
        },
        rect: toLandingDebugRect(current.getBoundingClientRect()),
        tagName: current.tagName.toLowerCase(),
      });
    }

    current = current.parentElement;
  }

  return ancestors;
}

function readDebugCss(element: Element): LandingDebugElement["css"] {
  const style = window.getComputedStyle(element);
  return {
    backfaceVisibility: style.backfaceVisibility,
    clipPath: style.clipPath,
    contain: style.contain,
    contentVisibility: style.contentVisibility,
    display: style.display,
    filter: style.filter,
    isolation: style.isolation,
    maskImage: style.maskImage,
    opacity: style.opacity,
    overflow: style.overflow,
    overflowX: style.overflowX,
    overflowY: style.overflowY,
    position: style.position,
    transform: style.transform,
    visibility: style.visibility,
    webkitBackfaceVisibility: style.getPropertyValue("-webkit-backface-visibility"),
    zIndex: style.zIndex,
  };
}

function toLandingDebugRect(rect: DOMRect): LandingDebugRect {
  return {
    bottom: roundDebugNumber(rect.bottom),
    height: roundDebugNumber(rect.height),
    left: roundDebugNumber(rect.left),
    right: roundDebugNumber(rect.right),
    top: roundDebugNumber(rect.top),
    width: roundDebugNumber(rect.width),
    x: roundDebugNumber(rect.x),
    y: roundDebugNumber(rect.y),
  };
}

function roundDebugNumber(value: number) {
  return Math.round(value * 100) / 100;
}

function formatDebugRect(rect: LandingDebugRect) {
  return `${Math.round(rect.width)}x${Math.round(rect.height)} @ ${Math.round(rect.left)},${Math.round(rect.top)}`;
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

/**
 * 拓扑总览图：左 公网用户 / 中 Server 控制面 / 右上 客户端 A / 右下 客户端 B。
 *
 * 视觉约定：
 *  - cyan 实线：经 Server 中继的反向隧道（HTTP/TCP 主路径）。
 *  - emerald 虚线：客户端互联（信令 + 加密 frame 直连 / TURN 回退）。
 *
 * 暗色协调：节点 fill/stroke 走 CSS class `.topo-card-fill / .topo-card-stroke`，
 * 由 index.css 通过 .light/.dark 切换，避免硬编码白底在暗色下扎眼。
 * 文字一律 fill="currentColor" 跟随主题。
 */
function TopologyDiagram() {
  return (
    <div className="topology-panel rounded-md border border-black/10 bg-white/70 p-5 backdrop-blur-md dark:border-white/10 dark:bg-white/[0.04]">
      <MobileTopologyDiagram />
      <svg
        className="topology-svg hidden sm:block"
        viewBox="0 0 1080 440"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="组网形态：公网用户经 Server 中继到客户端 A 内网服务，客户端 A 与客户端 B 之间走对端直连通道"
      >
        <defs>
          <linearGradient id="topo-relay-gradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgb(6,182,212)" stopOpacity="0.92" />
            <stop offset="100%" stopColor="rgb(20,184,166)" stopOpacity="0.82" />
          </linearGradient>
          <marker id="topo-arrow-cyan" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" fill="rgb(6,182,212)" />
          </marker>
          <marker id="topo-arrow-emerald" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" fill="rgb(16,185,129)" />
          </marker>
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
          <rect className="topo-server" x="420" y="80" width="240" height="280" rx="12" fill="url(#topo-relay-gradient)" />
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
        <line x1="232" y1="205" x2="418" y2="170" stroke="rgb(6,182,212)" strokeWidth="2" markerEnd="url(#topo-arrow-cyan)" className="topology-relay-flow" />
        <text x="320" y="178" textAnchor="middle" fontSize="11.5" fill="rgb(6,182,212)" fontWeight="600">公网请求</text>
        {/* 响应：Server 左下 → 公网用户右下 */}
        <line x1="418" y1="270" x2="232" y2="240" stroke="rgb(6,182,212)" strokeWidth="2" markerEnd="url(#topo-arrow-cyan)" className="topology-relay-flow" opacity="0.6" />
        <text x="320" y="270" textAnchor="middle" fontSize="11.5" fill="rgb(6,182,212)" opacity="0.78" fontWeight="600">响应</text>

        {/* === 中继路径：Server ↔ 客户端 A === */}
        <line x1="662" y1="160" x2="848" y2="130" stroke="rgb(6,182,212)" strokeWidth="2" markerEnd="url(#topo-arrow-cyan)" className="topology-relay-flow" />
        <text x="755" y="135" textAnchor="middle" fontSize="11.5" fill="rgb(6,182,212)" fontWeight="600">下发 / 转发</text>
        <line x1="848" y1="180" x2="662" y2="195" stroke="rgb(6,182,212)" strokeWidth="2" markerEnd="url(#topo-arrow-cyan)" className="topology-relay-flow" opacity="0.6" />
        <text x="755" y="205" textAnchor="middle" fontSize="11.5" fill="rgb(6,182,212)" opacity="0.78" fontWeight="600">上行字节</text>

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
        实线（青）= 经 Server 中继的反向隧道，HTTP 路由与 TCP 端口映射走这条主路径；
        虚线（绿）= 客户端互联，控制面下发设备清单与会话凭证后，两端在 UDP 直连或 TURN 回退上跑加密 frame 数据面。
      </p>
    </div>
  );
}

function MobileTopologyDiagram() {
  return (
    <div
      className="topology-mobile sm:hidden"
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
        青色表示公网访问经 Server 中继；绿色表示客户端之间的数据面直连，失败后回退 TURN。
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

function ClientDownloadsSection() {
  const [links, setLinks] = useState<ClientDownloadLink[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const data = await fetchPublicClientDownloads();
      if (!cancelled) {
        setLinks(data);
        setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
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
        <h2 className="text-2xl font-semibold text-zinc-950 dark:text-white">获取客户端</h2>
        <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
          选择对应的实现下载，所有客户端共享同一份 JSON 配置格式。详细启动方法见登录后的「帮助文档」。
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {grouped.map(({ implementation, items }) => (
          <Card
            key={implementation}
            shadow="none"
            className="rounded-md border border-black/10 bg-white/70 text-zinc-950 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-white/[0.055] dark:text-white dark:shadow-none"
          >
            <CardBody className="gap-3 p-4">
              <Chip className="w-fit bg-cyan-300/25 text-cyan-800 dark:bg-cyan-300/15 dark:text-cyan-100" radius="sm" variant="flat">
                {IMPL_LABELS[implementation]}
              </Chip>
              <div className="flex flex-col gap-2">
                {items.map((link) => (
                  <a
                    key={link.id}
                    className="group flex items-start justify-between gap-2 rounded-md border border-black/10 bg-white/65 p-2.5 transition hover:border-cyan-500/40 hover:bg-white/85 dark:border-white/10 dark:bg-white/[0.04] dark:hover:bg-white/[0.08]"
                    href={link.downloadUrl}
                    rel="noopener noreferrer"
                    target="_blank"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-small font-medium text-zinc-950 group-hover:text-cyan-700 dark:text-white dark:group-hover:text-cyan-200">
                        {link.displayName}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1 text-tiny text-zinc-600 dark:text-zinc-400">
                        <span>{shortPlatform(link.platform)}</span>
                        <span>·</span>
                        <span>{shortArch(link.arch)}</span>
                      </div>
                    </div>
                    <span className="shrink-0 text-tiny text-zinc-500 group-hover:text-cyan-700 dark:group-hover:text-cyan-200">↗</span>
                  </a>
                ))}
              </div>
            </CardBody>
          </Card>
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
  description,
  preview,
  title,
}: {
  accent: "amber" | "cyan" | "emerald";
  badge: string;
  children: ReactNode;
  description: string;
  preview?: boolean;
  title: string;
}) {
  return (
    <Card
      shadow="none"
      className={`principle-card principle-card-${accent} rounded-md border border-black/10 bg-white/70 text-zinc-950 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-white/[0.055] dark:text-white dark:shadow-none`}
    >
      <CardBody className="principle-card-body gap-5 p-5">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="principle-badge w-fit rounded-md px-2 py-1 text-tiny">{badge}</span>
            {preview && <span className="preview-badge">Preview</span>}
          </div>
          <h3 className="text-lg font-semibold text-zinc-950 dark:text-white">{title}</h3>
          <p className="text-small leading-6 text-zinc-600 dark:text-zinc-400">{description}</p>
        </div>
        {children}
      </CardBody>
    </Card>
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
        <FlowStep key={node.title} index={index} node={node} showEdge={index < nodes.length - 1} />
      ))}
    </div>
  );
}

function FlowStep({
  index,
  node,
  showEdge,
}: {
  index: number;
  node: { eyebrow: string; title: string; meta: string };
  showEdge: boolean;
}) {
  const nodeStyle = { "--node-delay": `${index * 1.55}s` } as CSSProperties;
  const edgeStyle = { "--edge-delay": `${index * 1.55 + 0.55}s` } as CSSProperties;

  return (
    <>
      <div className="principle-node" style={nodeStyle}>
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

function SignalField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) {
      return;
    }

    type SignalNode = {
      x: number;
      y: number;
      phase: number;
      size: number;
    };

    let width = 0;
    let height = 0;
    let frame = 0;
    let raf = 0;
    let running = false;
    let visible = true;
    let nodes: SignalNode[] = [];
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // Android GPU 逐帧上传全 dpr 纹理会挤占合成器带宽（丢 tile 根因之一），钳到 1
    const dprCap = /\bAndroid\b/i.test(window.navigator.userAgent) ? 1 : 2;

    const rebuildNodes = () => {
      const count = Math.max(20, Math.min(52, Math.floor((width * height) / 32000)));
      nodes = Array.from({ length: count }, (_, index) => ({
        x: (index * 0.61803398875) % 1,
        y: (index * 0.41421356237 + 0.08) % 1,
        phase: index * 0.77,
        size: 2 + (index % 3),
      }));
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, dprCap);
      width = rect.width;
      height = rect.height;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      rebuildNodes();
    };

    const nodePosition = (node: SignalNode) => {
      const drift = reducedMotion ? 0 : frame * 0.008;
      return {
        x: node.x * width + Math.sin(drift + node.phase) * 24,
        y: node.y * height + Math.cos(drift * 0.85 + node.phase) * 18,
      };
    };

    const draw = () => {
      if (width <= 0 || height <= 0) {
        return;
      }
      context.clearRect(0, 0, width, height);
      context.lineWidth = 1;

      const points = nodes.map(nodePosition);
      for (let i = 0; i < points.length; i += 1) {
        for (let j = i + 1; j < points.length; j += 1) {
          const dx = points[i].x - points[j].x;
          const dy = points[i].y - points[j].y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          if (distance < 190) {
            const alpha = (1 - distance / 190) * 0.22;
            context.strokeStyle = `rgba(34, 211, 238, ${alpha})`;
            context.beginPath();
            context.moveTo(points[i].x, points[i].y);
            context.lineTo(points[j].x, points[j].y);
            context.stroke();
          }
        }
      }

      nodes.forEach((node, index) => {
        const point = points[index];
        context.fillStyle = index % 4 === 0 ? "rgba(251, 191, 36, 0.78)" : "rgba(94, 234, 212, 0.78)";
        context.fillRect(point.x - node.size / 2, point.y - node.size / 2, node.size, node.size);
      });

      for (let i = 0; i < 5; i += 1) {
        const y = height * (0.18 + i * 0.16) + Math.sin(frame * 0.015 + i) * 16;
        const x = ((frame * (0.85 + i * 0.12) + i * 180) % (width + 260)) - 260;
        context.strokeStyle = i % 2 === 0 ? "rgba(45, 212, 191, 0.38)" : "rgba(251, 191, 36, 0.28)";
        context.beginPath();
        context.moveTo(x, y);
        context.lineTo(x + 180, y + 26);
        context.stroke();
        context.fillStyle = "rgba(255, 255, 255, 0.72)";
        context.fillRect(x + 180, y + 24, 5, 5);
      }

      if (!reducedMotion && visible) {
        frame += 1;
        raf = window.requestAnimationFrame(draw);
        running = true;
      } else {
        running = false;
      }
    };

    // canvas 只在视口内时才跑 rAF：滚到能力卡片区后完全停画，
    // 不与卡片动画争抢 Android GPU 光栅化带宽。
    const observer = new IntersectionObserver((entries) => {
      visible = entries[0]?.isIntersecting ?? true;
      if (!visible) {
        window.cancelAnimationFrame(raf);
        running = false;
        return;
      }
      if (!running && !reducedMotion) {
        running = true;
        raf = window.requestAnimationFrame(draw);
      }
    });
    observer.observe(canvas);

    resize();
    draw();
    window.addEventListener("resize", resize);

    return () => {
      observer.disconnect();
      window.removeEventListener("resize", resize);
      window.cancelAnimationFrame(raf);
    };
  }, []);

  return <canvas ref={canvasRef} className="landing-canvas" aria-hidden="true" />;
}
