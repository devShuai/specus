import { useMemo, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Input,
  Spinner,
  Textarea,
} from "@heroui/react";
import { AppLogo } from "../../components/AppLogo";
import { ThemeToggleButton } from "../../components/ThemeToggleButton";
import { NAT_TRAVERSAL_REFERENCE } from "../../lib/nat";

const DEFAULT_STUN_SERVERS = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
];

type BrowserNatKind =
  | "idle"
  | "checking"
  | "not-supported"
  | "udp-blocked"
  | "mapping-stable"
  | "mapping-changing"
  | "failed";

interface BrowserIceCandidate {
  raw: string;
  foundation: string;
  component: string;
  protocol: string;
  priority: string;
  address: string;
  port: number | null;
  type: string;
  relatedAddress: string | null;
  relatedPort: number | null;
}

interface StunProbeResult {
  server: string;
  candidates: BrowserIceCandidate[];
  error: string | null;
  elapsedMs: number;
}

interface BrowserNatResult {
  kind: BrowserNatKind;
  startedAt: number;
  finishedAt: number;
  probes: StunProbeResult[];
  mappedEndpoints: string[];
  hostCandidates: BrowserIceCandidate[];
  summary: string;
  recommendation: string;
}

export function NatDetectionPanel({ publicPage = false }: { publicPage?: boolean }) {
  const [serversText, setServersText] = useState(DEFAULT_STUN_SERVERS.join("\n"));
  const [timeoutMs, setTimeoutMs] = useState("7000");
  const [result, setResult] = useState<BrowserNatResult | null>(null);
  const [checking, setChecking] = useState(false);

  const servers = useMemo(
    () => serversText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [serversText],
  );

  const run = async () => {
    setChecking(true);
    const startedAt = Date.now();
    try {
      if (!("RTCPeerConnection" in window)) {
        setResult({
          kind: "not-supported",
          startedAt,
          finishedAt: Date.now(),
          probes: [],
          mappedEndpoints: [],
          hostCandidates: [],
          summary: "当前浏览器不支持 WebRTC RTCPeerConnection，无法在页面内执行 STUN 探测。",
          recommendation: "换用 Chrome、Edge、Firefox 等支持 WebRTC 的浏览器，或使用客户端侧 NAT 探测结果。",
        });
        return;
      }

      const numericTimeout = Number(timeoutMs);
      const probeTimeoutMs = Number.isFinite(numericTimeout)
        ? Math.min(15000, Math.max(3000, numericTimeout))
        : 7000;
      const selectedServers = servers.length > 0 ? servers : DEFAULT_STUN_SERVERS;
      const probes: StunProbeResult[] = [];
      for (const server of selectedServers) {
        probes.push(await probeStunServer(server, probeTimeoutMs));
      }
      setResult(classifyBrowserNatResult(startedAt, probes));
    } catch (error) {
      setResult({
        kind: "failed",
        startedAt,
        finishedAt: Date.now(),
        probes: [],
        mappedEndpoints: [],
        hostCandidates: [],
        summary: error instanceof Error ? error.message : "浏览器 NAT 检测失败。",
        recommendation: "检查浏览器是否允许 WebRTC，或尝试更换 STUN 服务地址。",
      });
    } finally {
      setChecking(false);
    }
  };

  if (publicPage) {
    return (
      <main className="landing-shell relative min-h-screen overflow-hidden text-zinc-950 dark:text-white">
        <div className="landing-grid" aria-hidden="true" />
        <div className="landing-scanline" aria-hidden="true" />

        <header className="relative z-10 mx-auto flex w-full max-w-[1080px] items-center justify-between gap-3 px-5 py-5 sm:px-8">
          <AppLogo label="shuai-tunnel" subtitle="浏览器 NAT 检测" markClassName="h-9 w-9" />
          <div className="flex items-center gap-2">
            <ThemeToggleButton className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white" />
            <Button as="a" href="/" radius="sm" variant="flat" className="bg-white/70 text-zinc-950 dark:bg-white/10 dark:text-white">
              进入控制台
            </Button>
          </div>
        </header>

        <section className="relative z-10 mx-auto w-full max-w-[1080px] px-5 pb-16 sm:px-8">
          <NatHero
            result={result}
            checking={checking}
            onRun={() => void run()}
            serversText={serversText}
            onServersTextChange={setServersText}
            timeoutMs={timeoutMs}
            onTimeoutChange={setTimeoutMs}
            onResetServers={() => setServersText(DEFAULT_STUN_SERVERS.join("\n"))}
          />

          {(result || checking) && (
            <NatResultDetails result={result} checking={checking} />
          )}

          <NatTips />
        </section>
      </main>
    );
  }

  // 控制台内嵌版（保持简洁，与原有面板风格一致）
  return (
    <div className="mt-3 flex min-w-0 flex-col gap-4">
      <NatHero
        embedded
        result={result}
        checking={checking}
        onRun={() => void run()}
        serversText={serversText}
        onServersTextChange={setServersText}
        timeoutMs={timeoutMs}
        onTimeoutChange={setTimeoutMs}
        onResetServers={() => setServersText(DEFAULT_STUN_SERVERS.join("\n"))}
      />
      {(result || checking) && <NatResultDetails result={result} checking={checking} />}
    </div>
  );
}

interface NatHeroProps {
  embedded?: boolean;
  result: BrowserNatResult | null;
  checking: boolean;
  onRun: () => void;
  serversText: string;
  onServersTextChange: (text: string) => void;
  timeoutMs: string;
  onTimeoutChange: (value: string) => void;
  onResetServers: () => void;
}

function NatHero({
  embedded = false,
  result,
  checking,
  onRun,
  serversText,
  onServersTextChange,
  timeoutMs,
  onTimeoutChange,
  onResetServers,
}: NatHeroProps) {
  const profile = browserNatProfile(result?.kind ?? (checking ? "checking" : "idle"));
  const accent = ACCENTS[profile.color];

  return (
    <section
      className={`relative overflow-hidden rounded-2xl border ${accent.border} ${accent.bg} ${embedded ? "p-5" : "p-7 sm:p-10"}`}
    >
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full blur-3xl ${accent.glow}`}
      />

      <div className="relative flex flex-col gap-5">
        <div className="flex flex-wrap items-center gap-2">
          <Chip
            radius="sm"
            variant="flat"
            className={`${accent.chipBg} ${accent.chipText} border ${accent.chipBorder}`}
          >
            {profile.badge}
          </Chip>
          {result && (
            <span className="text-tiny text-zinc-600 dark:text-zinc-400">
              耗时 {Math.max(0, result.finishedAt - result.startedAt)} ms
            </span>
          )}
        </div>

        <div className="flex flex-col gap-3">
          <h1 className={embedded ? "text-2xl font-semibold" : "text-3xl font-semibold sm:text-4xl"}>
            {profile.title}
          </h1>
          <p className="max-w-2xl text-small leading-6 text-zinc-700 dark:text-zinc-300 sm:text-medium">
            {result?.summary ?? profile.description}
          </p>
          {result?.recommendation && (
            <p className="max-w-2xl rounded-lg border border-black/5 bg-white/70 p-3 text-small leading-6 text-zinc-700 backdrop-blur dark:border-white/10 dark:bg-white/[0.04] dark:text-zinc-300">
              {result.recommendation}
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            color="primary"
            radius="sm"
            size={embedded ? "md" : "lg"}
            isLoading={checking}
            onPress={onRun}
            className="bg-cyan-500 font-medium text-white hover:bg-cyan-600 dark:bg-cyan-400 dark:text-zinc-950 dark:hover:bg-cyan-300"
          >
            {checking ? "检测中…" : result ? "重新检测" : "开始检测"}
          </Button>
          <span className="text-tiny text-zinc-500 dark:text-zinc-400">
            会创建一个空的 WebRTC data channel 触发 ICE，不读取摄像头麦克风
          </span>
        </div>

        {!embedded && (
          <MetricStrip result={result} />
        )}

        <details className="group rounded-lg border border-black/10 bg-white/60 px-3 py-2 text-small backdrop-blur dark:border-white/10 dark:bg-white/[0.04]">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-zinc-700 transition-colors hover:text-zinc-950 dark:text-zinc-300 dark:hover:text-white">
            <span className="flex items-center gap-2">
              <ChevronIcon className="h-4 w-4 transition-transform group-open:rotate-90" />
              高级设置（STUN 服务、超时时间）
            </span>
            <Button size="sm" variant="light" onPress={onResetServers}>
              恢复默认
            </Button>
          </summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_160px]">
            <Textarea
              label="STUN 服务（每行一个）"
              size="sm"
              variant="bordered"
              radius="sm"
              minRows={2}
              value={serversText}
              onValueChange={onServersTextChange}
              description="仅支持标准 STUN/TURN，浏览器不能直接连 server 内置的 TURN-lite。"
            />
            <Input
              label="单服务超时"
              size="sm"
              variant="bordered"
              radius="sm"
              value={timeoutMs}
              onValueChange={onTimeoutChange}
              endContent={<span className="text-tiny text-default-400">ms</span>}
            />
          </div>
        </details>
      </div>
    </section>
  );
}

function MetricStrip({ result }: { result: BrowserNatResult | null }) {
  const items = [
    { label: "STUN 服务", value: result?.probes.length ?? 0 },
    { label: "公网映射端点", value: result?.mappedEndpoints.length ?? 0 },
    { label: "本地候选", value: result?.hostCandidates.length ?? 0 },
    {
      label: "总耗时",
      value: result ? `${Math.max(0, result.finishedAt - result.startedAt)} ms` : "—",
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {items.map((item) => (
        <div
          key={item.label}
          className="rounded-lg border border-black/10 bg-white/65 px-3 py-2 backdrop-blur dark:border-white/10 dark:bg-white/[0.04]"
        >
          <div className="text-tiny text-zinc-500 dark:text-zinc-400">{item.label}</div>
          <div className="mt-0.5 font-mono text-lg font-semibold text-zinc-950 dark:text-white">
            {item.value === 0 ? "0" : item.value || "—"}
          </div>
        </div>
      ))}
    </div>
  );
}

function NatResultDetails({
  checking,
  result,
}: {
  checking: boolean;
  result: BrowserNatResult | null;
}) {
  if (!result) {
    return (
      <Card shadow="none" className="mt-6 rounded-xl border border-black/10 bg-white/60 backdrop-blur dark:border-white/10 dark:bg-white/[0.03]">
        <CardBody className="flex flex-row items-center gap-3 p-5">
          <Spinner size="sm" />
          <span className="text-small text-zinc-600 dark:text-zinc-400">
            {checking ? "正在收集 ICE candidates…" : "等待结果"}
          </span>
        </CardBody>
      </Card>
    );
  }

  return (
    <div className="mt-6 flex flex-col gap-4">
      <MappedEndpointsCard result={result} />
      <CandidateTableCard result={result} />
    </div>
  );
}

function MappedEndpointsCard({ result }: { result: BrowserNatResult }) {
  return (
    <Card shadow="none" className="rounded-xl border border-black/10 bg-white/60 backdrop-blur dark:border-white/10 dark:bg-white/[0.03]">
      <CardBody className="gap-4 p-5">
        <div className="flex items-center gap-2">
          <DotIcon className={result.mappedEndpoints.length ? "text-emerald-500" : "text-zinc-400"} />
          <h2 className="text-base font-semibold">公网映射端点</h2>
        </div>
        {result.mappedEndpoints.length === 0 ? (
          <p className="rounded-lg border border-dashed border-black/15 bg-white/40 p-3 text-small text-zinc-600 dark:border-white/15 dark:bg-white/[0.02] dark:text-zinc-400">
            未发现 server-reflexive 映射端点。
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {result.mappedEndpoints.map((endpoint) => (
              <code
                key={endpoint}
                className="rounded-md border border-emerald-500/25 bg-emerald-500/10 px-3 py-1.5 font-mono text-small text-emerald-700 dark:border-emerald-300/30 dark:bg-emerald-300/10 dark:text-emerald-100"
              >
                {endpoint}
              </code>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function CandidateTableCard({ result }: { result: BrowserNatResult }) {
  const candidates = result.probes.flatMap((probe) =>
    probe.candidates.map((candidate, index) => ({
      id: `${probe.server}-${index}`,
      probe,
      candidate,
    })),
  );

  return (
    <details className="rounded-xl border border-black/10 bg-white/60 backdrop-blur transition-colors open:border-black/15 dark:border-white/10 dark:bg-white/[0.03] dark:open:border-white/15">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-5 text-base font-semibold">
        <span className="flex items-center gap-2">
          <ChevronIcon className="h-4 w-4 transition-transform" />
          ICE Candidate 明细
          <span className="ml-1 text-small font-normal text-zinc-500 dark:text-zinc-400">
            ({candidates.length})
          </span>
        </span>
        <span className="text-tiny font-normal text-zinc-500 dark:text-zinc-400">点击展开</span>
      </summary>
      <div className="border-t border-black/5 px-5 pb-5 pt-3 dark:border-white/5">
        {candidates.length === 0 ? (
          <p className="text-small text-zinc-500 dark:text-zinc-400">未收集到 ICE candidate。</p>
        ) : (
          <div className="-mx-1 overflow-x-auto">
            <table className="w-full min-w-[640px] border-separate border-spacing-0 text-small">
              <thead>
                <tr className="text-tiny text-zinc-500 dark:text-zinc-400">
                  <th className="px-2 py-1.5 text-left font-medium">STUN</th>
                  <th className="px-2 py-1.5 text-left font-medium">类型</th>
                  <th className="px-2 py-1.5 text-left font-medium">协议</th>
                  <th className="px-2 py-1.5 text-left font-medium">地址</th>
                  <th className="px-2 py-1.5 text-left font-medium">关联地址</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((item) => (
                  <tr
                    key={item.id}
                    className="text-zinc-800 dark:text-zinc-200 [&>td]:border-t [&>td]:border-black/5 dark:[&>td]:border-white/5"
                  >
                    <td className="px-2 py-2 align-top">
                      <div className="flex max-w-56 flex-col break-all text-tiny">
                        <span>{item.probe.server}</span>
                        {item.probe.error ? <span className="text-danger">{item.probe.error}</span> : null}
                      </div>
                    </td>
                    <td className="px-2 py-2 align-top">
                      <Chip size="sm" color={candidateColor(item.candidate.type)} variant="flat">
                        {item.candidate.type}
                      </Chip>
                    </td>
                    <td className="px-2 py-2 align-top text-tiny uppercase text-zinc-500 dark:text-zinc-400">
                      {item.candidate.protocol}
                    </td>
                    <td className="px-2 py-2 align-top">
                      <span className="break-all font-mono text-tiny">{endpointOf(item.candidate)}</span>
                    </td>
                    <td className="px-2 py-2 align-top">
                      <span className="break-all font-mono text-tiny text-zinc-500 dark:text-zinc-400">
                        {relatedEndpointOf(item.candidate)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </details>
  );
}

function NatTips() {
  const tips = [
    { title: "可以判断", text: "UDP/STUN 是否可达；浏览器能否获得公网映射；多 STUN 映射是否一致。" },
    { title: "不能完全判断", text: "Full Cone / Restricted / Port Restricted 需服务端多 IP/多端口配合测试。" },
    { title: "与控制台 NAT 类型不同", text: "这里检测的是当前浏览器所在网络；客户端 NAT 数据来自 tunnel-client 上报。" },
  ];

  return (
    <section className="mt-10 grid gap-3 sm:grid-cols-3">
      {tips.map((tip) => (
        <div
          key={tip.title}
          className="rounded-xl border border-black/10 bg-white/55 p-4 backdrop-blur dark:border-white/10 dark:bg-white/[0.03]"
        >
          <div className="text-small font-semibold text-zinc-900 dark:text-white">{tip.title}</div>
          <p className="mt-1.5 text-small leading-6 text-zinc-600 dark:text-zinc-400">{tip.text}</p>
        </div>
      ))}
      <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/[0.05] p-4 dark:border-cyan-300/20 dark:bg-cyan-300/[0.05] sm:col-span-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-small text-zinc-700 dark:text-zinc-300">
            想看 Tailscale 关于 NAT 类型和打洞的原文？
          </div>
          <Button
            as="a"
            href={NAT_TRAVERSAL_REFERENCE.url}
            rel="noreferrer"
            target="_blank"
            size="sm"
            radius="sm"
            variant="flat"
            className="bg-white/80 text-zinc-950 dark:bg-white/10 dark:text-white"
          >
            阅读 Tailscale NAT traversal
          </Button>
        </div>
      </div>
    </section>
  );
}

const ACCENTS: Record<
  "default" | "primary" | "success" | "warning" | "danger",
  {
    border: string;
    bg: string;
    glow: string;
    chipBg: string;
    chipText: string;
    chipBorder: string;
  }
> = {
  default: {
    border: "border-black/10 dark:border-white/10",
    bg: "bg-white/60 dark:bg-white/[0.03]",
    glow: "bg-cyan-500/10 dark:bg-cyan-400/10",
    chipBg: "bg-zinc-200/70 dark:bg-white/10",
    chipText: "text-zinc-700 dark:text-zinc-200",
    chipBorder: "border-zinc-300/60 dark:border-white/10",
  },
  primary: {
    border: "border-cyan-500/25 dark:border-cyan-300/25",
    bg: "bg-cyan-500/[0.04] dark:bg-cyan-400/[0.06]",
    glow: "bg-cyan-500/15 dark:bg-cyan-400/15",
    chipBg: "bg-cyan-500/15 dark:bg-cyan-400/15",
    chipText: "text-cyan-700 dark:text-cyan-100",
    chipBorder: "border-cyan-500/30 dark:border-cyan-300/30",
  },
  success: {
    border: "border-emerald-500/25 dark:border-emerald-300/25",
    bg: "bg-emerald-500/[0.04] dark:bg-emerald-400/[0.06]",
    glow: "bg-emerald-500/15 dark:bg-emerald-400/15",
    chipBg: "bg-emerald-500/15 dark:bg-emerald-400/15",
    chipText: "text-emerald-700 dark:text-emerald-100",
    chipBorder: "border-emerald-500/30 dark:border-emerald-300/30",
  },
  warning: {
    border: "border-amber-500/25 dark:border-amber-300/25",
    bg: "bg-amber-500/[0.04] dark:bg-amber-400/[0.06]",
    glow: "bg-amber-500/15 dark:bg-amber-400/15",
    chipBg: "bg-amber-500/15 dark:bg-amber-400/15",
    chipText: "text-amber-700 dark:text-amber-100",
    chipBorder: "border-amber-500/30 dark:border-amber-300/30",
  },
  danger: {
    border: "border-rose-500/25 dark:border-rose-300/25",
    bg: "bg-rose-500/[0.04] dark:bg-rose-400/[0.06]",
    glow: "bg-rose-500/15 dark:bg-rose-400/15",
    chipBg: "bg-rose-500/15 dark:bg-rose-400/15",
    chipText: "text-rose-700 dark:text-rose-100",
    chipBorder: "border-rose-500/30 dark:border-rose-300/30",
  },
};

function ChevronIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}

function DotIcon({ className = "" }: { className?: string }) {
  return (
    <svg className={`h-2.5 w-2.5 ${className}`} viewBox="0 0 12 12" fill="currentColor">
      <circle cx="6" cy="6" r="4" />
    </svg>
  );
}

async function probeStunServer(server: string, timeoutMs: number): Promise<StunProbeResult> {
  const startedAt = performance.now();
  const candidates: BrowserIceCandidate[] = [];
  const pc = new RTCPeerConnection({
    iceServers: [{ urls: server }],
    iceCandidatePoolSize: 0,
  });

  return new Promise<StunProbeResult>((resolve) => {
    let finished = false;
    const finish = (error: string | null) => {
      if (finished) {
        return;
      }
      finished = true;
      window.clearTimeout(timer);
      pc.onicecandidate = null;
      pc.onicegatheringstatechange = null;
      pc.close();
      resolve({
        server,
        candidates,
        error,
        elapsedMs: Math.round(performance.now() - startedAt),
      });
    };

    const timer = window.setTimeout(() => {
      finish(candidates.length > 0 ? null : "超时，未收集到 candidate");
    }, timeoutMs);

    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        finish(null);
        return;
      }
      const parsed = parseCandidate(event.candidate.candidate);
      if (parsed) {
        candidates.push(parsed);
      }
    };

    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === "complete") {
        finish(null);
      }
    };

    try {
      pc.createDataChannel("shuai-tunnel-nat-check");
      void pc
        .createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch((error) => finish(error instanceof Error ? error.message : "创建 WebRTC offer 失败"));
    } catch (error) {
      finish(error instanceof Error ? error.message : "浏览器 WebRTC 初始化失败");
    }
  });
}

function classifyBrowserNatResult(startedAt: number, probes: StunProbeResult[]): BrowserNatResult {
  const allCandidates = probes.flatMap((probe) => probe.candidates);
  const srflxCandidates = allCandidates.filter((candidate) => candidate.type === "srflx");
  const hostCandidates = allCandidates.filter((candidate) => candidate.type === "host");
  const mappedEndpoints = Array.from(new Set(srflxCandidates.map(endpointOf))).sort();
  const finishedAt = Date.now();

  if (mappedEndpoints.length === 0) {
    return {
      kind: "udp-blocked",
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates,
      summary: "没有拿到 server-reflexive candidate。当前浏览器网络可能阻断 UDP/STUN，或浏览器策略禁用了 WebRTC candidate 暴露。",
      recommendation: "如果 Peer Mesh 要在这个网络下直连，建议检查防火墙和 UDP 出站策略；业务上应准备 relay 回退。",
    };
  }

  if (mappedEndpoints.length > 1) {
    return {
      kind: "mapping-changing",
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates,
      summary: "不同 STUN 探测得到多个公网映射端点，说明映射可能依赖目标地址或目标端口，接近 Symmetric NAT 行为。",
      recommendation: "这种网络下直连稳定性偏差，Peer Mesh 应快速尝试 direct，同时保留 relay 兜底，避免业务流量卡死。",
    };
  }

  return {
    kind: "mapping-stable",
    startedAt,
    finishedAt,
    probes,
    mappedEndpoints,
    hostCandidates,
    summary: "多个 STUN 探测得到的公网映射端点稳定，当前浏览器网络具备较好的 UDP 打洞基础。",
    recommendation: "这通常对 direct path 比较友好。仍需注意对端 NAT、防火墙和运营商 UDP 策略，失败时继续使用 relay 回退。",
  };
}

function parseCandidate(raw: string): BrowserIceCandidate | null {
  const parts = raw.trim().split(/\s+/);
  const typeIndex = parts.indexOf("typ");
  if (parts.length < 8 || typeIndex < 0) {
    return null;
  }
  const relatedAddressIndex = parts.indexOf("raddr");
  const relatedPortIndex = parts.indexOf("rport");
  return {
    raw,
    foundation: parts[0].replace(/^candidate:/, ""),
    component: parts[1] ?? "",
    protocol: (parts[2] ?? "").toLowerCase(),
    priority: parts[3] ?? "",
    address: parts[4] ?? "",
    port: toPort(parts[5]),
    type: parts[typeIndex + 1] ?? "unknown",
    relatedAddress: relatedAddressIndex >= 0 ? parts[relatedAddressIndex + 1] ?? null : null,
    relatedPort: relatedPortIndex >= 0 ? toPort(parts[relatedPortIndex + 1]) : null,
  };
}

function toPort(value: string | undefined) {
  const port = Number(value);
  return Number.isFinite(port) ? port : null;
}

function endpointOf(candidate: BrowserIceCandidate) {
  return `${candidate.address}:${candidate.port ?? "-"}`;
}

function relatedEndpointOf(candidate: BrowserIceCandidate) {
  if (!candidate.relatedAddress && candidate.relatedPort == null) {
    return "-";
  }
  return `${candidate.relatedAddress ?? "-"}:${candidate.relatedPort ?? "-"}`;
}

function candidateColor(type: string): "default" | "primary" | "success" | "warning" {
  if (type === "srflx") {
    return "success";
  }
  if (type === "relay") {
    return "warning";
  }
  if (type === "host") {
    return "primary";
  }
  return "default";
}

function browserNatProfile(kind: BrowserNatKind): {
  title: string;
  badge: string;
  color: "default" | "primary" | "success" | "warning" | "danger";
  description: string;
} {
  switch (kind) {
    case "checking":
      return {
        title: "正在检测",
        badge: "ICE gathering",
        color: "primary",
        description: "正在向 STUN 服务收集 ICE candidates，请稍候。",
      };
    case "not-supported":
      return {
        title: "浏览器不支持",
        badge: "unsupported",
        color: "danger",
        description: "当前浏览器没有 RTCPeerConnection 能力。",
      };
    case "udp-blocked":
      return {
        title: "UDP / STUN 不可达",
        badge: "blocked",
        color: "danger",
        description: "未拿到公网映射，当前网络可能阻断 UDP/STUN。",
      };
    case "mapping-changing":
      return {
        title: "疑似 Symmetric NAT",
        badge: "relay preferred",
        color: "warning",
        description: "不同 STUN 目标得到不同公网映射，直连可能不稳定。",
      };
    case "mapping-stable":
      return {
        title: "映射稳定 · 适合直连",
        badge: "direct friendly",
        color: "success",
        description: "公网映射端点稳定，通常比较适合 UDP 打洞。",
      };
    case "failed":
      return {
        title: "检测失败",
        badge: "failed",
        color: "danger",
        description: "检测流程异常中断。",
      };
    default:
      return {
        title: "浏览器 NAT 检测",
        badge: "ready",
        color: "primary",
        description: "检测当前设备、当前浏览器、当前网络出口的 UDP/STUN 可达性，以及多个 STUN 看到的公网映射是否一致。",
      };
  }
}
