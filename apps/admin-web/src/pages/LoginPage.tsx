import { useAuth } from "../auth/AuthContext";
import { PublicPage } from "../components/PublicTopBar";
import { SpecusAqueduct } from "../components/SpecusAqueduct";
import { Card, Icon, Section, Tag, type IconName } from "../components/ui";
import { usePageSeo } from "../lib/seo";

const capabilities: Array<{ value: string; label: string; icon: IconName }> = [
  { value: "TCP", label: "公网端口映射", icon: "server" },
  { value: "HTTP", label: "域名路由转发", icon: "globe" },
  { value: "Peer", label: "客户端互联", icon: "share" },
  { value: "观测", label: "连接与流量审计", icon: "activity" },
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

type FlowNode = { eyebrow: string; title: string; meta: string };

const httpRouteNodes: FlowNode[] = [
  { eyebrow: "公网用户", title: "app.example.com", meta: "GET /api/orders" },
  { eyebrow: "Server", title: "HTTP 网关", meta: "解析 Host / Path" },
  { eyebrow: "路由规则", title: "Route: app", meta: "命中 Demo client" },
  { eyebrow: "内网服务", title: "127.0.0.1:8080", meta: "客户端回连转发" },
];

const portMappingNodes: FlowNode[] = [
  { eyebrow: "公网用户", title: "server:9000", meta: "TCP stream" },
  { eyebrow: "Server", title: "监听 9000", meta: "端口规则匹配" },
  { eyebrow: "隧道连接", title: "Demo client", meta: "复用已登录长连接" },
  { eyebrow: "内网目标", title: "127.0.0.1:22", meta: "转发到真实服务" },
];

const peerNodes: FlowNode[] = [
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
  const { oidcConfig, openLogin, startOidcRegistration } = useAuth();

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
  const certusRegistrationEnabled = Boolean(
    oidcConfig?.configured && oidcConfig.registrationEndpoint,
  );

  return (
    <PublicPage className="pub-landing">
      <section className="pub-hero" aria-labelledby="landing-title">
        <div className="pub-hero-copy">
          <p className="pub-eyebrow">specus · 拉丁语「地道 / 引水渠」</p>
          <h1 id="landing-title" className="pub-hero-title">specus</h1>
          <p className="pub-hero-tagline">
            <b>引水渠</b>
            <span aria-hidden="true">·</span>
            <b>打洞</b>
            <span aria-hidden="true">·</span>
            <b>观测</b>
          </p>
          <p className="pub-hero-lead">
            古人架渠引水跨越山谷，把远处的水送到城里。specus 做同一件事：为内网服务架一条可控的渠，
            在 NAT 之间打通洞口，并让每一段水流都看得见。
          </p>
        </div>

        {/* 通栏主视觉：横贯整个视口且天然居中（无 100vw 滚动条偏移） */}
        <div className="specus-aqueduct-bleed pub-hero-art">
          <SpecusAqueduct />
        </div>

        <div className="pub-hero-actions">
          <button type="button" className="bd-btn bd-btn--primary bd-btn--lg" onClick={() => openLogin()}>
            <Icon name="lock" />
            <span>登录管理台</span>
          </button>
          <a className="bd-btn bd-btn--secondary bd-btn--lg" href="/download">
            <Icon name="download" />
            <span>下载客户端</span>
          </a>
          {(certusRegistrationEnabled || registrationEnabled) && (
            <button
              type="button"
              className="bd-btn bd-btn--ghost bd-btn--lg"
              onClick={() => certusRegistrationEnabled
                ? void startOidcRegistration()
                : openLogin("register")}
            >
              <Icon name="user" />
              <span>{certusRegistrationEnabled ? "注册 Certus 账号" : "注册账号"}</span>
            </button>
          )}
        </div>

        <ul className="pub-capabilities" aria-label="核心能力">
          {capabilities.map((item) => (
            <li key={item.label}>
              <span className="pub-capability-icon" aria-hidden="true"><Icon name={item.icon} /></span>
              <span className="min-w-0">
                <b>{item.value}</b>
                <span>{item.label}</span>
              </span>
            </li>
          ))}
        </ul>
      </section>

      <div className="pub-container pub-landing-sections">
        <Section
          title="一水两路 · 组网形态"
          description="一套控制面承担两类流量：公网用户经 Server 中继访问内网服务，受控客户端之间在控制面协调下走对端互联通道。"
        >
          <TopologyDiagram />
        </Section>

        <Section title="架渠与打洞" description="三条产品链路对应主视觉的三连拱：渠送水，洞通流。">
          <ul className="pub-motifs">
            <li>
              <span className="pub-motif" aria-hidden="true">渠</span>
              <span><b>HTTP 路由与端口映射</b>：流量沿既定渠道，从公网流进内网。</span>
            </li>
            <li>
              <span className="pub-motif" aria-hidden="true">洞</span>
              <span><b>客户端互联</b>：控制面撮合信令，加密 frame 走 UDP 直连；打不通时回退 TURN。</span>
            </li>
          </ul>
          <div className="pub-principles">
            <PrincipleCard
              badge="HTTP route"
              motif="渠"
              title="HTTP 路由：按 Host 与 Path 进入内网 Web 服务"
              description="请求先进 Server 的 HTTP 网关，管理端配置决定命中哪个租户、客户端和目标地址，再把请求沿客户端长连接送回内网。"
              nodes={httpRouteNodes}
              notes={["Host: app.example.com", "Route: /api → Demo / 127.0.0.1:8080"]}
              flowLabel="HTTP 路由转发流程"
            />
            <PrincipleCard
              badge="Port mapping"
              motif="引"
              title="公网端口映射：按监听端口进入内网 TCP 服务"
              description="Server 先占用公网端口，外部连接到来后查找端口映射，把字节流封装进客户端隧道，再落到指定内网 IP 和端口。"
              nodes={portMappingNodes}
              notes={["Listen: 0.0.0.0:9000", "Target: Demo → 127.0.0.1:22"]}
              flowLabel="端口映射转发流程"
            />
            <PrincipleCard
              badge="Peer mesh"
              motif="洞"
              title="客户端互联：受控对端之间的直连通道"
              description="客户端登录时上报 X25519 公钥并接收 roster；控制面校验 ACL 后撮合两端通过 PEER_CONTROL 通道协商身份与会话凭证。"
              nodes={peerNodes}
              notes={["Specus CIDR: 100.96.0.0/11", "Identity: X25519 公钥 + iceCredential"]}
              flowLabel="客户端互联协商流程"
            />
          </div>
        </Section>

        <Section
          title="平台特性"
          description="从协议字节级兼容到部署形态，specus 把传统反向隧道工具缺失的工程化关切补齐。"
        >
          <div className="pub-feature-grid">
            {featureCards.map((feature) => (
              <Card key={feature.title} className="pub-feature">
                <Tag plain>{feature.label}</Tag>
                <h3 className="bd-card-title">{feature.title}</h3>
                <p>{feature.description}</p>
              </Card>
            ))}
          </div>

          <Card className="pub-protocol">
            <div className="pub-protocol-head">
              <h3 className="bd-card-title">四种实现 · 一份协议</h3>
              <Tag tone="success">字节级兼容</Tag>
            </div>
            <ul className="pub-impl-list">
              {implementationChips.map((chip) => (
                <li key={chip.name}>
                  <b>{chip.name}</b>
                  <span>{chip.note}</span>
                </li>
              ))}
            </ul>
            <p className="pub-protocol-note">
              控制连接 11 字节定长包头（magic / version / serializer / command / length）+ 紧凑二进制载荷。
              不同语言客户端登录到同一台 Server，无须任何字段适配。
            </p>
          </Card>
        </Section>

        <ClientDownloadEntry />
      </div>
    </PublicPage>
  );
}

/**
 * 拓扑总览图：左 公网用户 / 中 Server 控制面 / 右上 客户端 A / 右下 客户端 B。
 * 实线（accent）是经 Server 中继的反向隧道；虚线（success）是客户端互联。颜色全部来自设计令牌，
 * 由 public-pages.css 的 .pub-topo-* 类给出，两套主题自动切换。
 */
function TopologyDiagram() {
  return (
    <Card className="pub-topology">
      <MobileTopologyDiagram />
      <svg
        className="pub-topology-svg"
        viewBox="0 64 1080 312"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="组网形态：公网用户经 Server 中继到客户端 A 内网服务，客户端 A 与客户端 B 之间走对端直连通道"
      >
        <defs>
          <marker id="topo-arrow-relay" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" className="pub-topo-fill-relay" />
          </marker>
          <marker id="topo-arrow-peer" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto">
            <path d="M0,0 L12,6 L0,12 z" className="pub-topo-fill-peer" />
          </marker>
        </defs>

        <g>
          <rect className="pub-topo-node" x="30" y="170" width="200" height="100" rx="14" />
          <text x="130" y="208" textAnchor="middle" fontSize="14" className="pub-topo-text" fontWeight="600">公网用户 / API</text>
          <text x="130" y="232" textAnchor="middle" fontSize="12" className="pub-topo-muted">浏览器 · curl · SSH 等</text>
          <text x="130" y="252" textAnchor="middle" fontSize="12" className="pub-topo-subtle">无须感知隧道存在</text>
        </g>

        <g>
          <rect className="pub-topo-server" x="420" y="80" width="240" height="280" rx="16" />
          <text x="540" y="122" textAnchor="middle" fontSize="15" className="pub-topo-on-server" fontWeight="700">Server 控制面</text>
          <line x1="450" y1="138" x2="630" y2="138" className="pub-topo-server-rule" />
          <text x="540" y="166" textAnchor="middle" fontSize="12" className="pub-topo-on-server">7010 控制连接</text>
          <text x="540" y="186" textAnchor="middle" fontSize="12" className="pub-topo-on-server">8088 管理 / HTTP 网关</text>
          <line x1="450" y1="206" x2="630" y2="206" className="pub-topo-server-rule" />
          <text x="540" y="232" textAnchor="middle" fontSize="12" className="pub-topo-on-server">TCP 端口映射</text>
          <text x="540" y="252" textAnchor="middle" fontSize="12" className="pub-topo-on-server">租户 · ACL · 路由</text>
          <text x="540" y="272" textAnchor="middle" fontSize="12" className="pub-topo-on-server">PEER_CONTROL 信令</text>
          <line x1="450" y1="292" x2="630" y2="292" className="pub-topo-server-rule" />
          <text x="540" y="318" textAnchor="middle" fontSize="12" className="pub-topo-on-server">STUN / TURN</text>
          <text x="540" y="338" textAnchor="middle" fontSize="12" className="pub-topo-on-server">实时观测 · 流量审计</text>
        </g>

        <g>
          <rect className="pub-topo-node" x="850" y="90" width="200" height="110" rx="14" />
          <text x="950" y="128" textAnchor="middle" fontSize="14" className="pub-topo-text" fontWeight="600">客户端 A</text>
          <text x="950" y="152" textAnchor="middle" fontSize="12" className="pub-topo-muted">内网服务 · 反向隧道</text>
          <text x="950" y="172" textAnchor="middle" fontSize="12" className="pub-topo-subtle">127.0.0.1:8080 等</text>
        </g>

        <g>
          <rect className="pub-topo-node pub-topo-node-peer" x="850" y="240" width="200" height="120" rx="14" />
          <text x="950" y="278" textAnchor="middle" fontSize="14" className="pub-topo-text" fontWeight="600">客户端 B</text>
          <text x="950" y="302" textAnchor="middle" fontSize="12" className="pub-topo-peer-text" fontWeight="600">对端互联</text>
          <text x="950" y="322" textAnchor="middle" fontSize="12" className="pub-topo-muted">virtualIp 100.96.0.0/11</text>
          <text x="950" y="342" textAnchor="middle" fontSize="12" className="pub-topo-subtle">UDP 直连 / TURN 回退</text>
        </g>

        <line x1="232" y1="205" x2="418" y2="170" className="pub-topo-relay" markerEnd="url(#topo-arrow-relay)" />
        <text x="320" y="178" textAnchor="middle" fontSize="12" className="pub-topo-relay-text" fontWeight="600">公网请求</text>
        <line x1="418" y1="270" x2="232" y2="240" className="pub-topo-relay pub-topo-back" markerEnd="url(#topo-arrow-relay)" />
        <text x="320" y="272" textAnchor="middle" fontSize="12" className="pub-topo-relay-text" fontWeight="600">响应</text>

        <line x1="662" y1="160" x2="848" y2="130" className="pub-topo-relay" markerEnd="url(#topo-arrow-relay)" />
        <text x="755" y="135" textAnchor="middle" fontSize="12" className="pub-topo-relay-text" fontWeight="600">下发 / 转发</text>
        <line x1="848" y1="180" x2="662" y2="195" className="pub-topo-relay pub-topo-back" markerEnd="url(#topo-arrow-relay)" />
        <text x="755" y="207" textAnchor="middle" fontSize="12" className="pub-topo-relay-text" fontWeight="600">上行字节</text>

        <line x1="662" y1="290" x2="848" y2="280" className="pub-topo-peer" markerEnd="url(#topo-arrow-peer)" />
        <text x="755" y="270" textAnchor="middle" fontSize="12" className="pub-topo-peer-text" fontWeight="600">信令 · ACL</text>
        <line x1="848" y1="320" x2="662" y2="330" className="pub-topo-peer pub-topo-back" markerEnd="url(#topo-arrow-peer)" />
        <text x="755" y="350" textAnchor="middle" fontSize="12" className="pub-topo-peer-text" fontWeight="600">心跳 · 设备上报</text>

        <path d="M 1010 200 C 1080 215, 1080 235, 1010 250" className="pub-topo-peer" fill="none" markerEnd="url(#topo-arrow-peer)" />
        <path d="M 890 250 C 870 235, 870 215, 890 200" className="pub-topo-peer pub-topo-back" fill="none" markerEnd="url(#topo-arrow-peer)" />
        <text x="950" y="226" textAnchor="middle" fontSize="12" className="pub-topo-peer-text" fontWeight="700">Peer 直连</text>
      </svg>
      <div className="pub-topology-legend">
        <span><i className="pub-legend-relay" aria-hidden="true" />实线 = 经 Server 中继的反向隧道，HTTP 路由与 TCP 端口映射走这条主路径</span>
        <span><i className="pub-legend-peer" aria-hidden="true" />虚线 = 客户端互联，控制面下发设备清单与会话凭证后，两端在 UDP 直连或 TURN 回退上跑加密 frame 数据面</span>
      </div>
    </Card>
  );
}

function MobileTopologyDiagram() {
  return (
    <div
      className="pub-topo-mobile"
      role="img"
      aria-label="组网形态：公网用户经 Server 中继到客户端 A 内网服务，客户端 A 与客户端 B 之间走对端直连或 TURN 回退"
    >
      <div className="pub-topo-m-section">
        <div className="pub-topo-m-head">
          <span>公网访问路径</span>
          <Tag tone="info">Relay</Tag>
        </div>
        <ol className="pub-stages">
          <MobileTopologyNode title="公网用户 / API" meta="浏览器、curl、SSH 等" />
          <MobileTopologyNode title="Server" meta="HTTP 网关 · TCP 映射 · 租户 ACL" via="公网请求 / 响应" />
          <MobileTopologyNode title="客户端 A" meta="访问内网服务 127.0.0.1:8080" via="反向隧道" />
        </ol>
      </div>

      <div className="pub-topo-m-section">
        <div className="pub-topo-m-head">
          <span>客户端互联路径</span>
          <Tag tone="success">Peer / TURN</Tag>
        </div>
        <p className="pub-topo-m-note">Server 只负责 ACL 校验、设备清单与 PEER_CONTROL 信令</p>
        <ol className="pub-stages">
          <MobileTopologyNode title="客户端 A" meta="100.96.0.0/11" />
          <MobileTopologyNode title="客户端 B" meta="加密 frame 数据面" via="直连 · TURN 回退" />
        </ol>
      </div>
    </div>
  );
}

function MobileTopologyNode({ title, meta, via }: { title: string; meta: string; via?: string }) {
  return (
    <li className="pub-stage">
      <span className="pub-stage-dot" />
      <div className="pub-stage-body">
        {via ? <span className="pub-stage-via">{via}</span> : null}
        <b>{title}</b>
        <span>{meta}</span>
      </div>
    </li>
  );
}

function ClientDownloadEntry() {
  return (
    <section className="jd-section" aria-labelledby="landing-download-title">
      <Card className="pub-download-entry">
        <span className="pub-download-entry-icon" aria-hidden="true"><Icon name="download" size={22} /></span>
        <div className="min-w-0 flex-1">
          <h2 id="landing-download-title" className="bd-card-title">为这台设备选择客户端</h2>
          <p>
            独立下载页会识别 macOS、Windows 或 Linux 与处理器架构，优先给出最合适的安装方式；也可展开查看全部平台与实现。
          </p>
        </div>
        <a className="bd-btn bd-btn--primary" href="/download">
          <span>打开下载页</span>
          <Icon name="arrow-right" />
        </a>
      </Card>
    </section>
  );
}

function PrincipleCard({
  badge,
  description,
  flowLabel,
  motif,
  nodes,
  notes,
  title,
}: {
  badge: string;
  description: string;
  flowLabel: string;
  /** 意象小章：渠 / 引 / 洞，与主视觉三连拱一一对应 */
  motif: string;
  nodes: FlowNode[];
  notes: string[];
  title: string;
}) {
  return (
    <article className="bd-card pub-principle">
      <div className="pub-principle-head">
        <div className="bd-row">
          <span className="pub-motif" aria-hidden="true">{motif}</span>
          <Tag plain>{badge}</Tag>
        </div>
        <h3 className="bd-card-title">{title}</h3>
        <p>{description}</p>
      </div>
      <ol className="pub-stages pub-principle-flow" aria-label={flowLabel}>
        {nodes.map((node, index) => (
          <li key={node.title} className="pub-stage">
            <span className="pub-stage-dot bd-num">{index + 1}</span>
            <div className="pub-stage-body">
              <span className="pub-stage-via">{node.eyebrow}</span>
              <b>{node.title}</b>
              <span>{node.meta}</span>
            </div>
          </li>
        ))}
      </ol>
      <div className="pub-principle-notes">
        {notes.map((note) => <code key={note}>{note}</code>)}
      </div>
    </article>
  );
}
