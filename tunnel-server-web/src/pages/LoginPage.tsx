import { useEffect, useRef, useState, type CSSProperties, type FormEvent, type ReactNode } from "react";
import { Button, Card, CardBody, CardHeader, Chip, Divider, Input } from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { notifyError } from "../components/toast";

const metrics = [
  { value: "TCP", label: "公网端口映射" },
  { value: "HTTP", label: "域名路由转发" },
  { value: "OIDC", label: "统一身份接入" },
  { value: "实时", label: "连接与流量观测" },
];

const featureCards = [
  {
    label: "服务发布",
    title: "TCP 与 HTTP 统一暴露",
    description: "公网端口映射、HTTP 路由和内网目标地址集中编排，适合开发联调、私有 API 和内部工具访问。",
  },
  {
    label: "租户隔离",
    title: "一套 Server 承载多组团队",
    description: "管理数据按租户边界隔离，配合本地 JWT 或 OIDC claim，让不同团队看到自己的客户端、映射和连接记录。",
  },
  {
    label: "实时观测",
    title: "连接质量和流量趋势可视化",
    description: "在线连接、成功率、拒绝连接、客户端流量排行和历史统计在管理台内直接查看。",
  },
  {
    label: "集中治理",
    title: "客户端、密钥和映射策略统一维护",
    description: "客户端注册、密钥轮换、映射启停和路由推送都通过管理面完成，减少分散配置带来的运维成本。",
  },
];

const flowNodes = ["公网入口", "租户鉴权", "策略编排", "内网服务"];

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

const inputClassNames = {
  inputWrapper:
    "border-white/15 bg-white/[0.06] text-white hover:bg-white/[0.08] data-[hover=true]:border-cyan-300/50 group-data-[focus=true]:border-cyan-300",
  label: "text-zinc-300",
  input: "text-white placeholder:text-zinc-500",
} as const;

export function LoginPage() {
  const { oidcConfig, loginHint, passwordLogin, startOidcLogin } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const loginPanelRef = useRef<HTMLDivElement>(null);

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
    <main className="landing-shell min-h-screen overflow-hidden text-white">
      <SignalField />
      <div className="landing-grid" aria-hidden="true" />
      <div className="landing-scanline" aria-hidden="true" />

      <section className="relative z-10 mx-auto flex w-full max-w-[1440px] flex-col px-5 pb-10 pt-5 sm:px-8 lg:min-h-[88vh]">
        <header className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md border border-cyan-300/35 bg-cyan-300/10 text-small font-semibold text-cyan-200">
              ST
            </div>
            <div>
              <p className="text-small font-semibold text-white">shuai-tunnel</p>
              <p className="text-tiny text-zinc-400">内网服务接入控制面</p>
            </div>
          </div>
          <Button radius="sm" className="bg-white/10 text-white" variant="flat" onPress={focusLogin}>
            进入控制台
          </Button>
        </header>

        <div className="grid flex-1 items-center gap-8 py-10 lg:grid-cols-[minmax(0,1fr)_420px]">
          <div className="flex min-w-0 flex-col gap-7">
            <Chip
              className="w-fit border border-emerald-300/35 bg-emerald-300/10 px-2 text-emerald-100"
              radius="sm"
              variant="flat"
            >
              Secure tunnel control plane
            </Chip>

            <div className="max-w-3xl">
              <h1 className="text-5xl font-semibold leading-tight text-white">shuai-tunnel</h1>
              <p className="mt-5 max-w-2xl text-lg leading-8 text-zinc-300">
                把内网服务发布、客户端治理、多租户隔离和实时观测收束到一个控制面，让公网入口更可控，团队协作更清晰。
              </p>
            </div>

            <div className="grid max-w-3xl grid-cols-2 gap-3 sm:grid-cols-4">
              {metrics.map((item) => (
                <div key={item.label} className="rounded-md border border-white/10 bg-white/[0.055] p-3">
                  <p className="text-xl font-semibold text-cyan-100">{item.value}</p>
                  <p className="mt-1 text-tiny text-zinc-400">{item.label}</p>
                </div>
              ))}
            </div>

            <div className="flex max-w-3xl flex-col gap-3 rounded-md border border-white/10 bg-black/30 p-4 backdrop-blur-md sm:flex-row sm:items-center">
              {flowNodes.map((node, index) => (
                <div key={node} className="flex min-w-0 flex-1 items-center gap-3">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-amber-300/30 bg-amber-300/10 text-small text-amber-100">
                    {index + 1}
                  </span>
                  <span className="truncate text-small text-zinc-200">{node}</span>
                  {index < flowNodes.length - 1 && <span className="landing-route-line hidden h-px flex-1 sm:block" />}
                </div>
              ))}
            </div>
          </div>

          <div ref={loginPanelRef} id="login-panel">
            <Card shadow="none" className="landing-card rounded-md border border-white/15 bg-white/[0.08] text-white backdrop-blur-xl">
              <CardHeader className="flex flex-col items-start gap-2 px-5 pb-2 pt-5">
                <Chip radius="sm" className="bg-cyan-300/15 text-cyan-100" variant="flat">
                  管理台登录
                </Chip>
                <div>
                  <h2 className="text-2xl font-semibold text-white">进入控制台</h2>
                  <p className="mt-1 text-small text-zinc-400">{loginHint}</p>
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
                  <div className="flex items-center gap-3 text-tiny text-zinc-500">
                    <Divider className="flex-1 bg-white/10" />
                    <span>或</span>
                    <Divider className="flex-1 bg-white/10" />
                  </div>
                )}

                {oidcEnabled && (
                  <Button
                    radius="sm"
                    variant="bordered"
                    className="border-white/20 text-white"
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

      <section className="relative z-10 border-t border-white/10 bg-black/50 px-5 py-10 sm:px-8">
        <div className="mx-auto max-w-[1440px]">
          <div className="mb-6 max-w-2xl">
            <h2 className="text-2xl font-semibold text-white">转发原理</h2>
            <p className="mt-2 text-small leading-6 text-zinc-400">
              同一个 Server 控制面承接两类入口：HTTP 根据域名和路径选路，TCP 根据公网端口找到对应的客户端隧道。
            </p>
          </div>

          <div className="mb-10 grid gap-4 2xl:grid-cols-2">
            <PrincipleCard
              badge="HTTP route"
              title="HTTP 路由：按 Host 和 Path 进入内网 Web 服务"
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
          </div>

          <div className="mb-6 max-w-2xl">
            <h2 className="text-2xl font-semibold text-white">功能矩阵</h2>
            <p className="mt-2 text-small leading-6 text-zinc-400">
              从客户端接入到连接观测，管理端提供一套面向团队协作的隧道运维入口。
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {featureCards.map((feature) => (
              <Card
                key={feature.title}
                shadow="none"
                className="rounded-md border border-white/10 bg-white/[0.055] text-white backdrop-blur-md"
              >
                <CardBody className="gap-3 p-4">
                  <span className="w-fit rounded-md border border-cyan-300/25 bg-cyan-300/10 px-2 py-1 text-tiny text-cyan-100">
                    {feature.label}
                  </span>
                  <h3 className="text-base font-semibold text-white">{feature.title}</h3>
                  <p className="text-small leading-6 text-zinc-400">{feature.description}</p>
                </CardBody>
              </Card>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}

function PrincipleCard({
  accent,
  badge,
  children,
  description,
  title,
}: {
  accent: "amber" | "cyan";
  badge: string;
  children: ReactNode;
  description: string;
  title: string;
}) {
  return (
    <Card
      shadow="none"
      className={`principle-card principle-card-${accent} rounded-md border border-white/10 bg-white/[0.055] text-white backdrop-blur-md`}
    >
      <CardBody className="gap-5 p-5">
        <div className="flex flex-col gap-2">
          <span className="principle-badge w-fit rounded-md px-2 py-1 text-tiny">{badge}</span>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <p className="text-small leading-6 text-zinc-400">{description}</p>
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
  variant: "http" | "port";
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
        />
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
    let nodes: SignalNode[] = [];
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
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

      if (!reducedMotion) {
        frame += 1;
        raf = window.requestAnimationFrame(draw);
      }
    };

    resize();
    draw();
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      window.cancelAnimationFrame(raf);
    };
  }, []);

  return <canvas ref={canvasRef} className="landing-canvas" aria-hidden="true" />;
}
