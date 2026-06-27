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
import { HeroRuntime } from "../../components/HeroRuntime";
import { NAT_TRAVERSAL_REFERENCE, natTypeProfile } from "../../lib/nat";
import { usePageSeo } from "../../lib/seo";

const DEFAULT_STUN_SERVERS = [
  "stun:stun.miwifi.com:3478",
  "stun:stun.chat.bilibili.com:3478",
  "stun:stun.douyucdn.cn:3478",
  "stun:stun1.douyucdn.cn:3478",
  "stun:stun.dingtalk.com:3478",
];
const UNASSIGNED_STUN_SERVER = "未归属 ICE candidate";

type BrowserNatKind =
  | "idle"
  | "checking"
  | "not-supported"
  | "udp-blocked"
  | "mapping-stable"
  | "mapping-changing"
  | "failed";

type BrowserNatConfidence = "high" | "medium" | "low";

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
  sourceKnown: boolean;
}

interface BrowserNatResult {
  kind: BrowserNatKind;
  natType: string | null;
  startedAt: number;
  finishedAt: number;
  probes: StunProbeResult[];
  mappedEndpoints: string[];
  hostCandidates: BrowserIceCandidate[];
  confidence: BrowserNatConfidence;
  evidence: string;
  summary: string;
  recommendation: string;
}

export function NatDetectionPanel({ publicPage = false }: { publicPage?: boolean }) {
  const content = <NatDetectionPanelContent publicPage={publicPage} />;

  if (publicPage) {
    return <HeroRuntime>{content}</HeroRuntime>;
  }
  return content;
}

function NatDetectionPanelContent({ publicPage = false }: { publicPage?: boolean }) {
  const [serversText, setServersText] = useState(DEFAULT_STUN_SERVERS.join("\n"));
  const [timeoutMs, setTimeoutMs] = useState("9000");
  const [result, setResult] = useState<BrowserNatResult | null>(null);
  const [checking, setChecking] = useState(false);

  usePageSeo(
    publicPage
      ? {
          title: "在线 NAT 类型检测 · 浏览器 STUN 探测 · shuai-tunnel",
          description:
            "免登录在线检测当前网络的 NAT 类型：Symmetric NAT、Port Preserved NAT、Cone-like NAT、UDP 阻断。基于 WebRTC + STUN，无需安装客户端，支持 IPv4 / IPv6。",
          canonical: "https://tunnel.devshuai.com/#/nat-detect",
          keywords:
            "NAT 检测,NAT 类型,Symmetric NAT,Full Cone NAT,Port Restricted NAT,STUN,WebRTC,在线 NAT 测试,UDP 打洞,P2P 直连,IPv6 NAT",
          jsonLd: [
            {
              "@context": "https://schema.org",
              "@type": "WebApplication",
              "name": "shuai-tunnel 在线 NAT 检测",
              "url": "https://tunnel.devshuai.com/#/nat-detect",
              "applicationCategory": "UtilitiesApplication",
              "browserRequirements": "需要支持 WebRTC 的现代浏览器 (Chrome / Edge / Firefox / Safari)",
              "operatingSystem": "Web",
              "description":
                "免登录在线检测当前网络的 NAT 类型与公网映射稳定性，基于 WebRTC RTCPeerConnection + 标准 STUN 协议，识别 Symmetric NAT / Port Preserved NAT / Cone-like NAT 与 UDP 阻断。",
              "isAccessibleForFree": true,
            },
            {
              "@context": "https://schema.org",
              "@type": "FAQPage",
              "mainEntity": [
                {
                  "@type": "Question",
                  "name": "什么是 Symmetric NAT？为什么打洞会失败？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "Symmetric NAT 会根据目标地址或端口生成不同的公网映射端点。同一本机 socket 向 STUN A 与 STUN B 发送 binding 时，得到的公网 IP:Port 不同。打洞依赖对端用我们告知的公网端点回包，Symmetric NAT 让这个端点对其它对端不可用，所以打洞通常失败，必须走 relay。",
                  },
                },
                {
                  "@type": "Question",
                  "name": "浏览器为什么不能区分 Full Cone / Restricted / Port Restricted？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "区分这三类需要让 STUN 服务端从备用 IP / 备用端口主动给浏览器发包，看浏览器能否接收。WebRTC RTCPeerConnection 没有暴露这种回调接口，所以浏览器侧只能合并这三类为 Cone-like NAT。",
                  },
                },
                {
                  "@type": "Question",
                  "name": "NAT 检测时浏览器会上传哪些数据？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "检测完全在本地浏览器内进行，不向 shuai-tunnel 后端上传任何数据。浏览器会创建一个空的 WebRTC data channel，触发 ICE candidate 收集，并向你配置的多个 STUN 服务器发送 binding 请求。",
                  },
                },
              ],
            },
          ],
        }
      : {
          title: "NAT 类型检测 · shuai-tunnel 管理后台",
          description: "管理员视图：浏览器侧检测当前所在网络的 NAT 类型与公网映射稳定性。",
          canonical: "https://tunnel.devshuai.com/#/nat-detect",
        },
  );

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
          natType: null,
          startedAt,
          finishedAt: Date.now(),
          probes: [],
          mappedEndpoints: [],
          hostCandidates: [],
          confidence: "low",
          evidence: "浏览器不支持 RTCPeerConnection",
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
      const probes = await probeStunServers(selectedServers, probeTimeoutMs);
      setResult(classifyBrowserNatResult(startedAt, probes));
    } catch (error) {
      setResult({
        kind: "failed",
        natType: null,
        startedAt,
        finishedAt: Date.now(),
        probes: [],
        mappedEndpoints: [],
        hostCandidates: [],
        confidence: "low",
        evidence: "检测流程异常",
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
  const natTypeProfileEntry = result?.natType ? natTypeProfile(result.natType) : null;

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
          {natTypeProfileEntry && (
            <a
              href="#/help/peer-mesh#nat-types"
              title={`${natTypeProfileEntry.summary}（点击查看帮助文档）`}
              className="inline-flex items-center gap-1.5 rounded-md border border-black/10 bg-white/70 px-2 py-0.5 text-tiny font-medium transition-colors hover:border-black/20 hover:bg-white dark:border-white/10 dark:bg-white/[0.06] dark:hover:border-white/20 dark:hover:bg-white/[0.1]"
            >
              <span className={`inline-block h-2 w-2 rounded-full ${natToneBg(natTypeProfileEntry.tone)}`} />
              <span>{natTypeProfileEntry.label}</span>
              <span className="text-zinc-500 dark:text-zinc-400">· {natTypeProfileEntry.reachabilityLabel}</span>
            </a>
          )}
          {result && (
            <span className="text-tiny text-zinc-600 dark:text-zinc-400">
              耗时 {Math.max(0, result.finishedAt - result.startedAt)} ms
            </span>
          )}
          {result && (
            <span className="rounded-md bg-white/70 px-2 py-0.5 text-tiny text-zinc-600 dark:bg-white/[0.06] dark:text-zinc-300">
              置信度：{confidenceLabel(result.confidence)}
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
          {result?.evidence && (
            <p className="max-w-2xl text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
              证据：{result.evidence}
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
              label="STUN 服务（每行一个，默认中国节点）"
              size="sm"
              variant="bordered"
              radius="sm"
              minRows={2}
              value={serversText}
              onValueChange={onServersTextChange}
              description="默认使用国内 STUN。仅支持标准 STUN/TURN，浏览器不能直接连 server 内置的 TURN-lite。"
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
    { label: "STUN 服务", value: result?.probes.filter((probe) => probe.sourceKnown).length ?? 0 },
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

function natToneBg(tone: "default" | "primary" | "success" | "warning" | "danger"): string {
  switch (tone) {
    case "success":
      return "bg-emerald-500";
    case "primary":
      return "bg-cyan-500";
    case "warning":
      return "bg-amber-500";
    case "danger":
      return "bg-rose-500";
    default:
      return "bg-zinc-400 dark:bg-zinc-500";
  }
}

function confidenceLabel(confidence: BrowserNatConfidence): string {
  switch (confidence) {
    case "high":
      return "高";
    case "medium":
      return "中";
    default:
      return "低";
  }
}

/**
 * 同一个 RTCPeerConnection 同时挂多个 STUN 服务器，让所有 STUN 都从同一组本机
 * UDP socket 出去。只有这样浏览器返回的多个 srflx 才可比对：
 *
 * <ul>
 *   <li>相同的 (本机 IP, 本机端口) → 不同 STUN 看到不同公网端点 == Symmetric NAT</li>
 *   <li>相同的 (本机 IP, 本机端口) → 不同 STUN 看到相同公网端点 == Cone-like NAT</li>
 * </ul>
 *
 * 之前每个 STUN 各起一个 PC，源端口都不一样，永远没法证伪 Symmetric。
 */
async function probeStunServers(servers: string[], timeoutMs: number): Promise<StunProbeResult[]> {
  const startedAt = performance.now();
  const errorMap = new Map<string, string | null>();
  const candidatesByServer = new Map<string, BrowserIceCandidate[]>();
  const candidatesUnassigned: BrowserIceCandidate[] = [];

  for (const server of servers) {
    errorMap.set(server, null);
    candidatesByServer.set(server, []);
  }

  const pc = new RTCPeerConnection({
    iceServers: servers.map((urls) => ({ urls })),
    iceCandidatePoolSize: 0,
  });

  return new Promise<StunProbeResult[]>((resolve) => {
    let finished = false;
    const finalize = (timedOut: boolean) => {
      if (finished) {
        return;
      }
      finished = true;
      window.clearTimeout(timer);
      pc.onicecandidate = null;
      pc.onicegatheringstatechange = null;
      pc.close();

      const elapsedMs = Math.round(performance.now() - startedAt);
        const hostShared = candidatesUnassigned.filter((c) => c.type === "host");
        const unassignedNetworkCandidates = candidatesUnassigned.filter((c) => c.type !== "host");
        const results: StunProbeResult[] = servers.map((server) => {
          const collected = candidatesByServer.get(server) ?? [];
          const hasSrflx = collected.some((c) => c.type === "srflx");
          // host 候选不属于任何 STUN，但每个 STUN 展示时都需要看到，复制一份。
          const merged = [...collected, ...hostShared];
          const error = errorMap.get(server) ?? null;
          return {
            server,
            candidates: merged,
            error: error ?? (timedOut && !hasSrflx ? "超时，未收集到 srflx" : null),
            elapsedMs,
            sourceKnown: true,
          };
        });
        if (unassignedNetworkCandidates.length > 0) {
          results.push({
            server: UNASSIGNED_STUN_SERVER,
            candidates: unassignedNetworkCandidates,
            error: "浏览器未暴露 candidate.url，无法确认来自哪个 STUN；仅用于展示，不用于强分类。",
            elapsedMs,
            sourceKnown: false,
          });
        }
        resolve(results);
      };

    const timer = window.setTimeout(() => finalize(true), timeoutMs);

    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        finalize(false);
        return;
      }
      const parsed = parseCandidate(event.candidate.candidate);
      if (!parsed) {
        return;
      }
      // WebRTC 没有告诉我们这个 candidate 来自哪个 STUN，需要用 url 字段对齐
      const sourceUrl = (event.candidate as RTCIceCandidate & { url?: string; relayProtocol?: string }).url;
      if (sourceUrl && candidatesByServer.has(sourceUrl)) {
        candidatesByServer.get(sourceUrl)!.push(parsed);
      } else if (parsed.type === "srflx" && sourceUrl) {
        // 兼容某些浏览器把 stun:host:port?transport=udp 形式的 url 抹掉端口
        const normalized = findServerByUrl(sourceUrl, servers);
        if (normalized) {
          candidatesByServer.get(normalized)!.push(parsed);
        } else {
          candidatesUnassigned.push(parsed);
        }
      } else {
        candidatesUnassigned.push(parsed);
      }
    };

    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === "complete") {
        finalize(false);
      }
    };

    try {
      pc.createDataChannel("shuai-tunnel-nat-check");
      void pc
        .createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch((error) => {
          const message = error instanceof Error ? error.message : "创建 WebRTC offer 失败";
          servers.forEach((server) => errorMap.set(server, message));
          finalize(false);
        });
    } catch (error) {
      const message = error instanceof Error ? error.message : "浏览器 WebRTC 初始化失败";
      servers.forEach((server) => errorMap.set(server, message));
      finalize(false);
    }
  });
}

function findServerByUrl(url: string, servers: string[]): string | null {
  const normalize = (value: string) => value.replace(/\?.*$/, "").toLowerCase();
  const target = normalize(url);
  return servers.find((server) => normalize(server) === target) ?? null;
}

function classifyBrowserNatResult(startedAt: number, probes: StunProbeResult[]): BrowserNatResult {
  const finishedAt = Date.now();
  const knownProbes = probes.filter((probe) => probe.sourceKnown);
  const unknownProbes = probes.filter((probe) => !probe.sourceKnown);
  const knownSrflxAll = uniqueCandidates(
    knownProbes.flatMap((probe) => probe.candidates.filter((c) => c.type === "srflx")),
  );
  const unknownSrflxAll = uniqueCandidates(
    unknownProbes.flatMap((probe) => probe.candidates.filter((c) => c.type === "srflx")),
  );
  // 全量 srflx 用于展示；强分类只使用可归属到具体 STUN 的候选。
  const srflxAll = uniqueCandidates([...knownSrflxAll, ...unknownSrflxAll]);
  const hostAll = uniqueCandidates(
    probes.flatMap((probe) => probe.candidates.filter((c) => c.type === "host")),
  );
  const mappedEndpoints = Array.from(new Set(srflxAll.map(endpointOf))).sort();

  const knownSrflxByServer = knownProbes.filter((probe) =>
    probe.candidates.some((candidate) => candidate.type === "srflx"),
  );
  const enoughKnownStunEvidence = knownSrflxByServer.length >= 2;

  const srflxV4 = knownSrflxAll.filter(isIpv4Candidate);
  const srflxV6 = knownSrflxAll.filter(isIpv6Candidate);
  const hostV4 = hostAll.filter(isIpv4Candidate);
  const hostV6 = hostAll.filter(isIpv6Candidate);

  const groupVerdict = (group: BrowserIceCandidate[], hosts: BrowserIceCandidate[]) =>
    inferNatTypeForGroup(group, hosts);

  // 只要任何一个地址族判定为 Symmetric，整体即 Symmetric（最保守）
  const v4 = srflxV4.length > 0 ? groupVerdict(srflxV4, hostV4) : null;
  const v6 = srflxV6.length > 0 ? groupVerdict(srflxV6, hostV6) : null;

  const natType = pickWorstNatType(v4, v6);
  const evidence = `${knownSrflxByServer.length} 个 STUN 返回可归属公网映射，${unknownSrflxAll.length} 个公网映射未归属来源`;

  if (srflxAll.length === 0) {
    return {
      kind: "udp-blocked",
      natType: null,
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates: hostAll,
      confidence: "high",
      evidence,
      summary: "没有拿到 server-reflexive candidate。当前浏览器网络可能阻断 UDP/STUN，或浏览器策略禁用了 WebRTC candidate 暴露。",
      recommendation: "如果 Peer Mesh 要在这个网络下直连，建议检查防火墙和 UDP 出站策略；业务上应准备 relay 回退。",
    };
  }

  if (!enoughKnownStunEvidence) {
    const knownCount = knownSrflxByServer.length;
    const unknownCount = unknownSrflxAll.length;
    const bestEffortNatType = natType ?? inferBestEffortNatType(srflxAll, hostAll) ?? "NAT";
    const bestEffortSymmetric = bestEffortNatType === "SYMMETRIC_NAT";
    return {
      kind: bestEffortSymmetric ? "mapping-changing" : "mapping-stable",
      natType: bestEffortNatType,
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates: hostAll,
      confidence: "low",
      evidence,
      summary: bestEffortSymmetric
        ? "结论：疑似 Symmetric NAT。浏览器可见的公网映射端点出现变化，但部分 candidate 来源不完整，按低置信度处理。"
        : `结论：${natConclusionLabel(bestEffortNatType)}。当前可见公网映射未出现变化，但只有 ${knownCount} 个 STUN 返回可归属结果，按低置信度处理。`,
      recommendation: unknownCount > 0 && knownCount === 0
        ? "浏览器没有暴露 candidate.url，页面仍给出最佳判断。建议保留 relay 回退，或更换浏览器/网络后复测。"
        : "建议继续使用更多 STUN 复测；业务策略上可先尝试 direct，但必须保留 relay 回退。",
    };
  }

  if (natType === "SYMMETRIC_NAT") {
    return {
      kind: "mapping-changing",
      natType,
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates: hostAll,
      confidence: knownSrflxByServer.length >= 3 ? "high" : "medium",
      evidence,
      summary: "同一个本机 socket 在不同 STUN 服务看到了不同的公网映射端点，说明 NAT 的映射依赖目标地址或目标端口，符合 Symmetric NAT 行为。",
      recommendation: "这种网络下 UDP 打洞通常失败，Peer Mesh 应直接走 relay；只有对端是 Endpoint-Independent 类 NAT 时才有机会打洞。",
    };
  }

  return {
    kind: "mapping-stable",
    natType,
    startedAt,
    finishedAt,
    probes,
    mappedEndpoints,
    hostCandidates: hostAll,
    confidence: knownSrflxByServer.length >= 3 ? "high" : "medium",
    evidence,
    summary: natType === "NO_NAT"
      ? "公网地址端口与本机一致，没有 NAT，直接是公网出口。"
      : natType === "PORT_PRESERVED_NAT"
        ? "多个 STUN 看到的公网端点一致，且 NAT 保留了本机源端口（端口保持 NAT）。"
        : "多个 STUN 看到的公网端点一致，但端口被 NAT 改写（锥形 NAT，浏览器无法再细分 Full Cone / Restricted）。",
    recommendation: "对 direct path 比较友好。仍需注意对端 NAT、防火墙和运营商 UDP 策略，失败时继续使用 relay 回退。",
  };
}

/**
 * 基于浏览器 ICE 观测推断 NAT 类型，分类与 NAT_TYPE_PROFILES 对齐。
 *
 * <p>浏览器侧没有"服务端备用 IP 主动回包"能力，所以无法区分 Full Cone / Restricted /
 * Port Restricted，都统一展示为 cone-like。只输出能在浏览器侧严格证伪的几类：
 *
 * <ul>
 *   <li>多个 STUN 看到不同公网端点（同一 PC 共享 socket）→ SYMMETRIC_NAT</li>
 *   <li>srflx 公网地址端口完全等于 host → NO_NAT</li>
 *   <li>srflx 公网端口 == 本机源端口 → PORT_PRESERVED_NAT</li>
 *   <li>其它 → CONE_LIKE_NAT（cone 系，但无法再细分）</li>
 * </ul>
 */
function inferNatTypeForGroup(
  srflxGroup: BrowserIceCandidate[],
  hostGroup: BrowserIceCandidate[],
): string | null {
  if (srflxGroup.length === 0) {
    return null;
  }
  const endpoints = new Set(srflxGroup.map(endpointOf));
  if (endpoints.size > 1) {
    return "SYMMETRIC_NAT";
  }

  const sample = srflxGroup[0];
  const hostMatch = hostGroup.find((host) => host.address === sample.relatedAddress);
  const hostHidden = hostGroup.some((host) => /\.local$/i.test(host.address));

  if (sample.relatedAddress && sample.address === sample.relatedAddress && sample.port === sample.relatedPort) {
    return "NO_NAT";
  }
  if (sample.relatedPort != null && sample.port === sample.relatedPort) {
    return "PORT_PRESERVED_NAT";
  }
  if (hostMatch && hostMatch.port === sample.relatedPort) {
    return "CONE_LIKE_NAT";
  }
  if (hostHidden && sample.relatedPort != null) {
    return sample.port === sample.relatedPort ? "PORT_PRESERVED_NAT" : "CONE_LIKE_NAT";
  }
  return "CONE_LIKE_NAT";
}

function inferBestEffortNatType(
  srflxAll: BrowserIceCandidate[],
  hostAll: BrowserIceCandidate[],
): string | null {
  const srflxV4 = srflxAll.filter(isIpv4Candidate);
  const srflxV6 = srflxAll.filter(isIpv6Candidate);
  const hostV4 = hostAll.filter(isIpv4Candidate);
  const hostV6 = hostAll.filter(isIpv6Candidate);
  return pickWorstNatType(
    srflxV4.length > 0 ? inferNatTypeForGroup(srflxV4, hostV4) : null,
    srflxV6.length > 0 ? inferNatTypeForGroup(srflxV6, hostV6) : null,
  );
}

function natConclusionLabel(natType: string | null): string {
  switch (natType) {
    case "SYMMETRIC_NAT":
      return "疑似 Symmetric NAT";
    case "NO_NAT":
      return "无 NAT / 公网直连";
    case "PORT_PRESERVED_NAT":
      return "端口保持 NAT";
    case "CONE_LIKE_NAT":
      return "疑似 Cone-like NAT";
    case "PORT_RESTRICTED_NAT":
      return "疑似 Port Restricted NAT";
    default:
      return "疑似 NAT";
  }
}

const NAT_TYPE_SEVERITY: Record<string, number> = {
  NO_NAT: 0,
  PORT_PRESERVED_NAT: 1,
  CONE_LIKE_NAT: 2,
  NAT: 3,
  SYMMETRIC_NAT: 4,
};

function pickWorstNatType(...types: Array<string | null>): string | null {
  let worst: string | null = null;
  for (const t of types) {
    if (!t) {
      continue;
    }
    if (!worst || (NAT_TYPE_SEVERITY[t] ?? 0) > (NAT_TYPE_SEVERITY[worst] ?? 0)) {
      worst = t;
    }
  }
  return worst;
}

function uniqueCandidates(list: BrowserIceCandidate[]): BrowserIceCandidate[] {
  const seen = new Set<string>();
  const out: BrowserIceCandidate[] = [];
  for (const c of list) {
    const key = `${c.type}|${c.protocol}|${c.address}|${c.port}|${c.relatedAddress ?? ""}|${c.relatedPort ?? ""}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(c);
    }
  }
  return out;
}

function isIpv4Candidate(candidate: BrowserIceCandidate): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(candidate.address);
}

function isIpv6Candidate(candidate: BrowserIceCandidate): boolean {
  return candidate.address.includes(":");
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
