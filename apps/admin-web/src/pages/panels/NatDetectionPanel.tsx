import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Input,
  Textarea,
  Tooltip,
} from "@heroui/react";
import { AppLogo } from "../../components/AppLogo";
import { ThemeToggleButton } from "../../components/ThemeToggleButton";
import { HeroRuntime } from "../../components/HeroRuntime";
import { PublicToolsMenu } from "../../components/PublicToolsMenu";
import { notify } from "../../components/toast";
import { fetchPublicNatProbeConfig, fetchPublicPeerStunConfig } from "../../api/client";
import type { PublicNatProbeConfig, PublicNatProbeEndpoint } from "../../api/types";
import { NAT_TRAVERSAL_REFERENCE, natTypeProfile } from "../../lib/nat";
import { usePageSeo } from "../../lib/seo";

export const DEFAULT_NAT_STUN_SERVERS = [
  "stun:stun1.tunnel.devshuai.com:34780",
  "stun:stun2.tunnel.devshuai.com:34780",
];
const UNASSIGNED_STUN_SERVER = "未归属 ICE candidate";
const MIN_CHECKING_DISPLAY_MS = 900;

async function waitForMinimumCheckingDisplay(startedAt: number): Promise<void> {
  const remainingMs = MIN_CHECKING_DISPLAY_MS - (Date.now() - startedAt);
  if (remainingMs > 0) {
    await new Promise<void>((resolve) => setTimeout(resolve, remainingMs));
  }
}

export function defaultStunServers(): string[] {
  return uniqueStunServers(DEFAULT_NAT_STUN_SERVERS);
}

function uniqueStunServers(values: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const normalized = normalizeStunUrl(value);
    if (!normalized || seen.has(normalized.toLowerCase())) {
      continue;
    }
    seen.add(normalized.toLowerCase());
    result.push(normalized);
  }
  return result;
}

function normalizeStunUrl(value: string | null | undefined): string {
  if (!value) {
    return "";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }
  if (/^stuns?:/i.test(trimmed)) {
    return trimmed.replace(/^stun:\/\//i, "stun:");
  }
  return `stun:${trimmed}`;
}

function rfc5780ProbeEndpoints(config: PublicNatProbeConfig | null): PublicNatProbeEndpoint[] {
  if (!config?.available || config.discoveryMethod !== "RFC5780") {
    return [];
  }
  const endpoints = config.endpoints.filter((endpoint) =>
    ["A1P1", "A1P2", "A2P1", "A2P2"].includes(endpoint.id)
      && Boolean(normalizeStunUrl(endpoint.url)),
  );
  return new Set(endpoints.map((endpoint) => endpoint.id)).size === 4 ? endpoints : [];
}

function activeRfc5780ProbeConfig(
  config: PublicNatProbeConfig | null,
  selectedServers: string[],
): PublicNatProbeConfig | null {
  const endpoints = rfc5780ProbeEndpoints(config);
  if (!config || endpoints.length !== 4) {
    return null;
  }
  const selected = new Set(selectedServers.map((server) => normalizeStunUrl(server).toLowerCase()));
  return endpoints.every((endpoint) => selected.has(normalizeStunUrl(endpoint.url).toLowerCase()))
    ? { ...config, endpoints }
    : null;
}

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

interface StunEndpointCheck {
  endpoint: PublicNatProbeEndpoint;
  reachable: boolean;
  mappedEndpoint: string | null;
  elapsedMs: number;
  error: string | null;
}

type BrowserNatVerificationMethod = "RFC5780_WEBRTC_MAPPING" | "MULTI_STUN_WEBRTC";
type BrowserNatMappingBehavior =
  | "NO_NAT"
  | "ENDPOINT_INDEPENDENT"
  | "ADDRESS_DEPENDENT"
  | "ADDRESS_AND_PORT_DEPENDENT"
  | "TARGET_DEPENDENT"
  | "UNKNOWN";
type BrowserNatFilteringBehavior = "BROWSER_NOT_OBSERVABLE" | "UNKNOWN";

interface AttributedSrflxObservation {
  server: string;
  candidate: BrowserIceCandidate;
}

export interface BrowserNatResult {
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
  verificationMethod: BrowserNatVerificationMethod;
  mappingBehavior: BrowserNatMappingBehavior;
  filteringBehavior: BrowserNatFilteringBehavior;
  endpointChecks: StunEndpointCheck[];
}

type NatCheckProgressPhase = "idle" | "preparing" | "validating" | "probing" | "analyzing" | "complete";

interface NatCheckProgress {
  phase: NatCheckProgressPhase;
  percent: number | null;
  responded: number;
  total: number;
  unattributedMapping: boolean;
  label: string;
}

type BrowserNatLevel = 1 | 2 | 3 | 4;

interface BrowserNatExperience {
  verdict: string;
  description: string;
}

interface BrowserNatOutcome {
  level: BrowserNatLevel | null;
  title: string;
  description: string;
  reachability: string;
  tone: "default" | "primary" | "success" | "warning" | "danger";
  frameClass: string;
  markerClass: string;
  textClass: string;
  game: BrowserNatExperience;
  p2p: BrowserNatExperience;
}

const BROWSER_NAT_CLASSIFICATIONS: Record<BrowserNatLevel, BrowserNatOutcome> = {
  1: {
    level: 1,
    title: "公网直连型",
    description: "探测到本机地址与公网端点一致，本轮未观察到 NAT 地址或端口转换。本机或上游防火墙仍可能限制入站连接。",
    reachability: "直连条件最佳",
    tone: "success",
    frameClass: "border-emerald-500/35 bg-emerald-500/[0.07] dark:border-emerald-400/30 dark:bg-emerald-400/[0.09]",
    markerClass: "bg-emerald-600 text-white dark:bg-emerald-400 dark:text-zinc-950",
    textClass: "text-emerald-800 dark:text-emerald-200",
    game: {
      verdict: "联机条件优秀",
      description: "玩家间直连和作为房主的网络条件较好，通常更容易获得低延迟；实际仍受游戏服务器、对端网络和防火墙影响。",
    },
    p2p: {
      verdict: "直连成功率高",
      description: "更有机会直接建立 P2P、语音或视频连接，减少中继带来的额外延迟；双方地址族或安全策略不兼容时仍可能使用中继。",
    },
  },
  2: {
    level: 2,
    title: "端口保持型 NAT",
    description: "公网映射保持稳定，并保留了本机源端口。这通常有利于 UDP 打洞，但不能据此判断入站过滤是否宽松。",
    reachability: "直连友好",
    tone: "primary",
    frameClass: "border-blue-500/35 bg-blue-500/[0.07] dark:border-blue-400/30 dark:bg-blue-400/[0.09]",
    markerClass: "bg-blue-600 text-white dark:bg-blue-400 dark:text-zinc-950",
    textClass: "text-blue-800 dark:text-blue-200",
    game: {
      verdict: "多数联机场景友好",
      description: "P2P 组队、语音和玩家间直连的成功机会较高；遇到严格防火墙或对称型 NAT 对端时，仍可能转为中继。",
    },
    p2p: {
      verdict: "通常可以直连",
      description: "ICE 通常更容易找到直连路径；如果对端网络较严格，应用仍需使用 TURN / Relay 兜底。",
    },
  },
  3: {
    level: 3,
    title: "端点无关映射 NAT",
    description: "A1/A2、P1/P2 四端点共享探测未观察到公网映射随目标变化，但公网端口已被改写。它更接近现代术语 EIM；过滤行为仍需原生 RFC 5780 探测。",
    reachability: "条件直连",
    tone: "warning",
    frameClass: "border-amber-500/40 bg-amber-500/[0.08] dark:border-amber-400/35 dark:bg-amber-400/[0.1]",
    markerClass: "bg-amber-500 text-zinc-950 dark:bg-amber-400",
    textClass: "text-amber-900 dark:text-amber-100",
    game: {
      verdict: "联机可用但受对端影响",
      description: "多数场景可以尝试 UDP 直连，但作为房主或遇到严格对端时，成功率会受双方网络策略影响。",
    },
    p2p: {
      verdict: "需要中继兜底",
      description: "P2P、语音视频可优先尝试打洞；若双方入站过滤都较严格，可能需要中继，延迟也会相应增加。",
    },
  },
  4: {
    level: 4,
    title: "目标相关映射 NAT",
    description: "同一个本机 UDP 基址访问不同地址或端口时得到不同公网映射，属于 ADM / APDM，传统工具通常称为 Symmetric NAT。",
    reachability: "建议 Relay",
    tone: "danger",
    frameClass: "border-rose-500/40 bg-rose-500/[0.07] dark:border-rose-400/35 dark:bg-rose-400/[0.1]",
    markerClass: "bg-rose-600 text-white dark:bg-rose-400 dark:text-zinc-950",
    textClass: "text-rose-800 dark:text-rose-200",
    game: {
      verdict: "直连联机更易受限",
      description: "连接普通中心服务器通常仍可工作，但玩家间直连、作为房主或局域网式联机更容易失败或转中继，可能增加延迟。",
    },
    p2p: {
      verdict: "直接打洞可靠性较低",
      description: "更可能依赖 TURN / Relay。中继通常仍能维持可用性，但会增加链路延迟和服务端带宽消耗。",
    },
  },
};

export function NatDetectionPanel({ publicPage = false }: { publicPage?: boolean }) {
  const content = <NatDetectionPanelContent publicPage={publicPage} />;

  if (publicPage) {
    return <HeroRuntime>{content}</HeroRuntime>;
  }
  return content;
}

function NatDetectionPanelContent({ publicPage = false }: { publicPage?: boolean }) {
  const initialServers = useMemo(() => defaultStunServers(), []);
  const [defaultServers, setDefaultServers] = useState(initialServers);
  const [selfHostedStunServer, setSelfHostedStunServer] = useState(initialServers[0] ?? "");
  const [natProbeConfig, setNatProbeConfig] = useState<PublicNatProbeConfig | null>(null);
  const [serversText, setServersText] = useState(initialServers.join("\n"));
  const [timeoutMs, setTimeoutMs] = useState("9000");
  const [result, setResult] = useState<BrowserNatResult | null>(null);
  const [checking, setChecking] = useState(false);
  const activeProbeRef = useRef<AbortController | null>(null);
  const [progress, setProgress] = useState<NatCheckProgress>({
    phase: "idle",
    percent: null,
    responded: 0,
    total: initialServers.length,
    unattributedMapping: false,
    label: "等待开始检测",
  });

  useEffect(() => () => {
    activeProbeRef.current?.abort();
  }, []);

  useEffect(() => {
    let active = true;
    void Promise.all([
      fetchPublicPeerStunConfig(),
      fetchPublicNatProbeConfig(),
    ]).then(([config, probeConfig]) => {
      if (!active) {
        return;
      }
      setNatProbeConfig(probeConfig);
      const topologyServers = rfc5780ProbeEndpoints(probeConfig).map((endpoint) => endpoint.url);
      const nextServers = topologyServers.length === 4
        ? uniqueStunServers(topologyServers)
        : uniqueStunServers([
            config?.selfHostedStunServer,
            ...(config?.stunServers ?? []),
            ...DEFAULT_NAT_STUN_SERVERS,
          ]);
      if (nextServers.length === 0) {
        return;
      }
      const previousDefaultText = defaultStunServers().join("\n");
      setSelfHostedStunServer(config?.selfHostedStunServer || nextServers[0] || "");
      setDefaultServers(nextServers);
      setServersText((current) => (current === previousDefaultText ? nextServers.join("\n") : current));
    });
    return () => {
      active = false;
    };
  }, []);

  usePageSeo(
    publicPage
      ? {
          title: "在线 NAT 类型检测 · 浏览器 STUN 探测 · shuai-tunnel",
          description:
            "免登录在线检测当前网络的 NAT 映射行为：使用 RFC 5780 四端点预检与共享 WebRTC ICE 探测，识别 EIM、ADM、APDM、端口保持与 UDP 阻断。",
          canonical: "https://tunnel.devshuai.com/nat-detect",
          keywords:
            "NAT 检测,NAT 类型,EIM,ADM,APDM,Symmetric NAT,RFC 5780,RFC 8489,STUN,WebRTC,在线 NAT 测试,UDP 打洞,P2P 直连",
          jsonLd: [
            {
              "@context": "https://schema.org",
              "@type": "WebApplication",
              "name": "shuai-tunnel 在线 NAT 检测",
              "url": "https://tunnel.devshuai.com/nat-detect",
              "applicationCategory": "UtilitiesApplication",
              "browserRequirements": "需要支持 WebRTC 的现代浏览器 (Chrome / Edge / Firefox / Safari)",
              "operatingSystem": "Web",
              "description":
                "免登录在线检测当前网络的 NAT 映射行为与公网映射稳定性，基于 RFC 5780 四端点和 WebRTC 共享 ICE socket，识别 EIM、ADM、APDM、端口保持与 UDP 阻断。",
              "isAccessibleForFree": true,
            },
            {
              "@context": "https://schema.org",
              "@type": "FAQPage",
              "mainEntity": [
                {
                  "@type": "Question",
                  "name": "什么是目标相关映射？为什么打洞更困难？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "地址相关映射 ADM 或地址和端口相关映射 APDM 会根据目标地址或端口生成不同公网端点，传统工具常统称为 Symmetric NAT。一次 STUN 结果难以预测访问另一个目标时的端点，因此 UDP 打洞更困难，应保留 TURN 或 Relay 回退。",
                  },
                },
                {
                  "@type": "Question",
                  "name": "浏览器能完整判断 NAT 的映射和过滤行为吗？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "浏览器可用同一个 WebRTC ICE socket 访问 A1/A2、P1/P2 四端点来观察映射是否随目标变化，但页面不能构造 RFC 5780 CHANGE-REQUEST，因此不能完整区分 EIF、ADF、APDF 过滤行为。过滤轴需要原生客户端验证。",
                  },
                },
                {
                  "@type": "Question",
                  "name": "NAT 检测时浏览器会上传哪些数据？",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text":
                      "页面只从 shuai-tunnel 接口读取 STUN 拓扑，不上传检测结果。浏览器会创建一个空的 WebRTC data channel，触发 ICE candidate 收集，并向配置的 STUN 端点发送 Binding 请求；不会读取摄像头或麦克风。",
                  },
                },
              ],
            },
          ],
        }
      : {
          title: "NAT 类型检测 · shuai-tunnel 管理后台",
          description: "管理员视图：浏览器侧检测当前所在网络的 NAT 类型与公网映射稳定性。",
          canonical: "https://tunnel.devshuai.com/nat-detect",
        },
  );

  const servers = useMemo(
    () => serversText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [serversText],
  );

  const run = async () => {
    if (checking) {
      return;
    }
    const numericTimeout = Number(timeoutMs);
    const probeTimeoutMs = Number.isFinite(numericTimeout)
      ? Math.min(15000, Math.max(3000, numericTimeout))
      : 7000;
    const selectedServers = servers.length > 0 ? servers : defaultServers;
    const activeProbeConfig = activeRfc5780ProbeConfig(natProbeConfig, selectedServers);
    activeProbeRef.current?.abort();
    const controller = new AbortController();
    activeProbeRef.current = controller;

    setChecking(true);
    setResult(null);
    setProgress({
      phase: "preparing",
      percent: null,
      responded: 0,
      total: selectedServers.length,
      unattributedMapping: false,
      label: "正在准备 WebRTC 探针",
    });
    const startedAt = Date.now();
    try {
      if (!("RTCPeerConnection" in window)) {
        const unsupportedResult: BrowserNatResult = {
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
          verificationMethod: activeProbeConfig ? "RFC5780_WEBRTC_MAPPING" : "MULTI_STUN_WEBRTC",
          mappingBehavior: "UNKNOWN",
          filteringBehavior: "UNKNOWN",
          endpointChecks: [],
        };
        setProgress({
          phase: "analyzing",
          percent: 94,
          responded: 0,
          total: selectedServers.length,
          unattributedMapping: false,
          label: "正在确认浏览器检测能力",
        });
        await waitForMinimumCheckingDisplay(startedAt);
        if (controller.signal.aborted) {
          return;
        }
        setResult(unsupportedResult);
        setProgress({
          phase: "complete",
          percent: 100,
          responded: 0,
          total: selectedServers.length,
          unattributedMapping: false,
          label: "浏览器无法执行检测",
        });
        return;
      }

      let endpointChecks: StunEndpointCheck[] = [];
      if (activeProbeConfig) {
        setProgress({
          phase: "validating",
          percent: 12,
          responded: 0,
          total: activeProbeConfig.endpoints.length,
          unattributedMapping: false,
          label: "正在验证 RFC 5780 四端点",
        });
        endpointChecks = await validateStunEndpoints(
          activeProbeConfig.endpoints,
          Math.min(probeTimeoutMs, 7000),
          controller.signal,
        );
        const reachable = endpointChecks.filter((check) => check.reachable).length;
        setProgress({
          phase: "probing",
          percent: 30,
          responded: reachable,
          total: endpointChecks.length,
          unattributedMapping: false,
          label: `四端点预检 ${reachable}/${endpointChecks.length} 可达，正在共享映射探测`,
        });
      }
      const probes = await probeStunServers(selectedServers, probeTimeoutMs, setProgress, controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      const responded = probes.filter((probe) => probe.sourceKnown
        && probe.candidates.some((candidate) => candidate.type === "srflx")).length;
      const unattributedMapping = probes.some((probe) => !probe.sourceKnown
        && probe.candidates.some((candidate) => candidate.type === "srflx"));
      setProgress({
        phase: "analyzing",
        percent: 94,
        responded,
        total: selectedServers.length,
        unattributedMapping,
        label: "正在分析公网映射特征",
      });
      const nextResult = classifyBrowserNatResult(startedAt, probes, {
        probeConfig: activeProbeConfig,
        endpointChecks,
      });
      await waitForMinimumCheckingDisplay(startedAt);
      if (controller.signal.aborted) {
        return;
      }
      setResult(nextResult);
      setProgress({
        phase: "complete",
        percent: 100,
        responded,
        total: selectedServers.length,
        unattributedMapping,
        label: "检测完成",
      });
    } catch (error) {
      if (controller.signal.aborted || (error instanceof Error && error.name === "AbortError")) {
        return;
      }
      const failedResult: BrowserNatResult = {
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
        verificationMethod: activeProbeConfig ? "RFC5780_WEBRTC_MAPPING" : "MULTI_STUN_WEBRTC",
        mappingBehavior: "UNKNOWN",
        filteringBehavior: "UNKNOWN",
        endpointChecks: [],
      };
      await waitForMinimumCheckingDisplay(startedAt);
      if (controller.signal.aborted) {
        return;
      }
      setResult(failedResult);
      setProgress((current) => ({
        ...current,
        phase: "complete",
        percent: 100,
        label: "本次检测未完成",
      }));
    } finally {
      if (activeProbeRef.current === controller) {
        activeProbeRef.current = null;
      }
      if (!controller.signal.aborted) {
        setChecking(false);
      }
    }
  };

  if (publicPage) {
    return (
      <main className="app-apple-tool relative min-h-screen overflow-x-hidden text-zinc-950 dark:text-white">
        <header className="app-apple-tool-header relative z-40 mx-auto flex w-full max-w-[1080px] items-center justify-between gap-3 px-5 py-5 sm:px-8">
          <AppLogo className="min-w-0 flex-1" label="shuai-tunnel" subtitle="浏览器 NAT 检测" markClassName="h-9 w-9" />
          <div className="public-header-actions flex shrink-0 items-center gap-2">
            <PublicToolsMenu active="nat-detect" />
            <ThemeToggleButton className="public-header-theme-button" />
          </div>
        </header>

        <section className="app-apple-tool-content relative z-10 mx-auto w-full max-w-[1080px] px-5 pb-16 sm:px-8">
          <NatHero
            result={result}
            checking={checking}
            progress={progress}
            onRun={() => void run()}
            serversText={serversText}
            onServersTextChange={setServersText}
            timeoutMs={timeoutMs}
            onTimeoutChange={setTimeoutMs}
            selfHostedStunServer={selfHostedStunServer}
            natProbeConfig={natProbeConfig}
            onResetServers={() => setServersText(defaultServers.join("\n"))}
          />

          {result && <NatResultDetails result={result} />}

          <NatTypeGuide probeConfig={natProbeConfig} />
          <NatTips probeConfig={natProbeConfig} />
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
        progress={progress}
        onRun={() => void run()}
        serversText={serversText}
        onServersTextChange={setServersText}
        timeoutMs={timeoutMs}
        onTimeoutChange={setTimeoutMs}
        selfHostedStunServer={selfHostedStunServer}
        natProbeConfig={natProbeConfig}
        onResetServers={() => setServersText(defaultServers.join("\n"))}
      />
      {result && <NatResultDetails result={result} />}
      <NatTypeGuide probeConfig={natProbeConfig} compact />
    </div>
  );
}

interface NatHeroProps {
  embedded?: boolean;
  result: BrowserNatResult | null;
  checking: boolean;
  progress: NatCheckProgress;
  onRun: () => void;
  serversText: string;
  onServersTextChange: (text: string) => void;
  timeoutMs: string;
  onTimeoutChange: (value: string) => void;
  selfHostedStunServer: string;
  natProbeConfig: PublicNatProbeConfig | null;
  onResetServers: () => void;
}

function NatHero({
  embedded = false,
  result,
  checking,
  progress,
  onRun,
  serversText,
  onServersTextChange,
  timeoutMs,
  onTimeoutChange,
  selfHostedStunServer,
  natProbeConfig,
  onResetServers,
}: NatHeroProps) {
  const profile = browserNatProfile(checking ? "checking" : result?.kind ?? "idle");
  const accent = ACCENTS[profile.color];
  const natTypeProfileEntry = result?.natType ? natTypeProfile(result.natType) : null;
  const outcome = result ? browserNatOutcome(result) : null;
  const liveAnnouncement = checking
    ? `${progress.label}${progress.responded > 0
      ? `，${progress.responded}/${progress.total} 个 STUN 已返回映射`
      : progress.unattributedMapping
        ? "，已收到公网映射但来源未归属"
        : ""}`
    : result && outcome
      ? `检测完成：${outcome.title}，${outcome.reachability}`
      : "";
  const heroTitle = checking ? "正在检测当前网络" : result ? "检测完成" : "浏览器 NAT 检测";
  const heroDescription = checking
    ? "正在通过 WebRTC 与多个 STUN 服务比对公网映射，全程不读取摄像头或麦克风。"
    : result
      ? "已根据本轮公网映射生成网络类型判断，并说明它对游戏联机和 P2P 直连的可能影响。"
      : profile.description;

  return (
    <section
      className={embedded
        ? `app-apple-nat-hero relative overflow-hidden rounded-xl border ${accent.border} ${accent.bg} p-5`
        : "relative py-6 sm:py-8"}
    >
      <span className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {liveAnnouncement}
      </span>
      <div className="relative flex flex-col gap-6">
        <div className={`grid items-center gap-7 ${embedded ? "md:grid-cols-[minmax(0,1fr)_144px]" : "lg:grid-cols-[minmax(0,1fr)_220px] lg:gap-10"}`}>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Chip
                radius="sm"
                variant="flat"
                startContent={<StatusGlyph color={profile.color} className="ml-1" />}
                className={`${accent.chipBg} ${accent.chipText} border ${accent.chipBorder}`}
              >
                {checking ? "检测进行中" : result ? "检测完成" : "准备就绪"}
              </Chip>
              {result && (
                <span className="text-tiny text-zinc-600 dark:text-zinc-400">
                  耗时 {Math.max(0, result.finishedAt - result.startedAt)} ms
                </span>
              )}
              <span className="rounded-md border glass-chip glass-border px-2 py-0.5 text-tiny font-medium text-zinc-600 dark:text-zinc-300">
                {rfc5780ProbeEndpoints(natProbeConfig).length === 4 ? "RFC 5780 四端点" : "WebRTC 多 STUN"}
              </span>
              {result && (
                <span className="flex items-center gap-1.5 rounded-md glass-chip px-2 py-0.5 text-tiny text-zinc-600 dark:text-zinc-300">
                  <ConfidenceBars confidence={result.confidence} />
                  置信度：{confidenceLabel(result.confidence)}
                </span>
              )}
            </div>
            <div className="mt-4 flex flex-col gap-3">
              <h1 className={embedded ? "text-2xl font-semibold tracking-tight" : "text-3xl font-semibold tracking-tight sm:text-4xl"}>
                {heroTitle}
              </h1>
              <p className="max-w-2xl text-small leading-6 text-zinc-700 dark:text-zinc-300 sm:text-medium">
                {heroDescription}
              </p>
            </div>
          </div>

          <NatDetectionOrb
            embedded={embedded}
            checking={checking}
            result={result}
            progress={progress}
            onRun={onRun}
          />
        </div>

        {result && outcome && (
          <NatOutcomeCard
            result={result}
            outcome={outcome}
            technicalLabel={natTypeProfileEntry?.label ?? profile.title}
            technicalSummary={natTypeProfileEntry?.summary ?? result.summary}
          />
        )}

        {!embedded && result && <MetricStrip result={result} />}

        <details className="group rounded-lg border glass glass-border px-3 py-2 text-small">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-zinc-700 transition-colors hover:text-zinc-950 dark:text-zinc-300 dark:hover:text-white">
            <span className="flex items-center gap-2">
              <ChevronIcon className="h-4 w-4 transition-transform group-open:rotate-90" />
              高级设置（STUN 服务、超时时间）
            </span>
            <span className="text-tiny text-zinc-500 dark:text-zinc-400">点击展开</span>
          </summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(0,1fr)_160px]">
            <Textarea
              label="STUN 服务（每行一个，默认主备节点）"
              size="sm"
              variant="bordered"
              radius="sm"
              minRows={2}
              value={serversText}
              onValueChange={onServersTextChange}
              description={rfc5780ProbeEndpoints(natProbeConfig).length === 4
                ? "默认使用自建 A1/A2、P1/P2 四端点。页面先逐一验证可达性，再用同一 ICE socket 对比映射；不会使用 TURN relay。"
                : `默认使用 shuai-tunnel 主备 STUN${selfHostedStunServer ? `，首选 ${selfHostedStunServer}` : ""}。浏览器仅使用标准 STUN Binding，不使用 TURN relay。`}
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
            <div className="flex justify-end sm:col-span-2">
              <Button size="sm" variant="light" onPress={onResetServers}>
                恢复默认
              </Button>
            </div>
          </div>
        </details>
      </div>
    </section>
  );
}

function NatDetectionOrb({
  embedded,
  checking,
  result,
  progress,
  onRun,
}: {
  embedded: boolean;
  checking: boolean;
  result: BrowserNatResult | null;
  progress: NatCheckProgress;
  onRun: () => void;
}) {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const determinate = checking && progress.percent != null;
  const progressOffset = determinate
    ? circumference * (1 - Math.min(100, Math.max(0, progress.percent ?? 0)) / 100)
    : 0;
  const state = checking ? "checking" : result ? "complete" : "idle";
  const privacyId = embedded ? "embedded-nat-check-privacy" : "public-nat-check-privacy";
  const centerText = checking
    ? progress.percent != null
      ? `${progress.percent}%`
      : progress.responded > 0 && progress.total > 0
        ? `${progress.responded}/${progress.total}`
        : progress.unattributedMapping
          ? "已映射"
          : "检测中"
    : result
      ? "再测一次"
      : "点我检测";

  return (
    <div className="flex min-w-0 flex-col items-center justify-center gap-3">
      {checking && (
        <span
          className="sr-only"
          role="progressbar"
          aria-label="NAT 检测进度"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress.percent ?? undefined}
          aria-valuetext={progress.label}
        />
      )}
      <button
        type="button"
        aria-disabled={checking}
        aria-busy={checking}
        aria-describedby={checking ? undefined : privacyId}
        aria-label={checking ? "正在检测 NAT 类型" : result ? "重新检测 NAT 类型" : "点我检测 NAT 类型"}
        data-state={state}
        onClick={onRun}
        className={`nat-detect-orb group relative isolate flex shrink-0 items-center justify-center rounded-full border text-center outline-none transition duration-300 ease-out focus-visible:ring-4 focus-visible:ring-primary-500/30 focus-visible:ring-offset-4 focus-visible:ring-offset-background motion-reduce:transform-none motion-reduce:transition-none ${
          embedded ? "h-28 w-28" : "h-40 w-40"
        } ${checking ? "cursor-wait" : "cursor-pointer hover:scale-[1.025] active:scale-[0.975]"}`}
      >
        <span className="nat-detect-orbit absolute -inset-3 rounded-full border border-primary-500/20 dark:border-primary-300/20" aria-hidden="true" />
        <span className="nat-detect-orbit-secondary absolute -inset-6 rounded-full border border-dashed border-primary-500/10 dark:border-primary-300/10" aria-hidden="true" />
        {checking && (
          <svg aria-hidden="true" className={`absolute inset-0 h-full w-full -rotate-90 ${determinate ? "" : "nat-detect-progress-indeterminate"}`} viewBox="0 0 100 100">
            <circle cx="50" cy="50" r={radius} fill="none" stroke="currentColor" strokeWidth="3" className="text-primary-500/15 dark:text-primary-300/15" />
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeLinecap="round"
              strokeWidth="3"
              strokeDasharray={determinate ? circumference : `72 ${circumference - 72}`}
              strokeDashoffset={determinate ? progressOffset : 0}
              className="text-primary-600 transition-[stroke-dashoffset] duration-300 dark:text-primary-300 motion-reduce:transition-none"
            />
          </svg>
        )}
        <span className="relative z-10 flex max-w-[82%] flex-col items-center gap-1">
          {!checking && (
            <svg aria-hidden="true" className="mb-0.5 h-7 w-7 text-primary-700 dark:text-primary-200" viewBox="0 0 32 32" fill="none">
              <circle cx="16" cy="16" r="3" fill="currentColor" />
              <circle cx="16" cy="16" r="8" stroke="currentColor" strokeWidth="1.5" opacity="0.65" />
              <path d="M5.5 16a10.5 10.5 0 0 1 21 0M2.5 16a13.5 13.5 0 0 1 27 0" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.4" />
            </svg>
          )}
          <span className={`${checking ? "text-xl tabular-nums" : embedded ? "text-sm" : "text-base"} font-semibold text-zinc-950 dark:text-white`}>
            {centerText}
          </span>
          <span className="text-[10px] font-medium tracking-wide text-zinc-500 dark:text-zinc-400">
            {checking ? "STUN 探测" : result ? "更新检测结果" : "浏览器直测"}
          </span>
        </span>
      </button>
      <div className="min-h-9 text-center text-tiny leading-5 text-zinc-500 dark:text-zinc-400">
        {checking ? (
          <>
            <span className="block font-medium text-zinc-700 dark:text-zinc-200">{progress.label}</span>
            <span>
              {progress.responded > 0
                ? `${progress.responded}/${progress.total} 个 STUN 已返回映射`
                : progress.unattributedMapping
                  ? "已收到公网映射，来源未归属"
                  : "等待公网映射返回"}
            </span>
          </>
        ) : (
          <span id={privacyId}>无需安装，不读取摄像头或麦克风</span>
        )}
      </div>
    </div>
  );
}

function NatOutcomeCard({
  outcome,
  technicalLabel,
  technicalSummary,
  result,
}: {
  outcome: BrowserNatOutcome;
  technicalLabel: string;
  technicalSummary: string;
  result: BrowserNatResult;
}) {
  return (
    <article className={`nat-result-reveal relative overflow-hidden rounded-2xl border-2 p-5 shadow-lg sm:p-6 ${outcome.frameClass}`}>
      <span className={`absolute inset-x-0 top-0 h-1.5 ${natToneBg(outcome.tone)}`} aria-hidden="true" />
      <div className="flex flex-wrap items-start gap-4 pt-1">
        <div
          className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl text-base font-semibold shadow-sm ${outcome.markerClass}`}
          aria-hidden="true"
        >
          {outcome.level ? `${outcome.level}/4` : <StatusGlyph color={outcome.tone} className="h-6 w-6" />}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-tiny font-semibold uppercase tracking-[0.18em] text-zinc-500 dark:text-zinc-400">检测结果</p>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <h2 className="text-2xl font-semibold tracking-tight text-zinc-950 dark:text-white sm:text-3xl">{outcome.title}</h2>
            <Chip size="sm" radius="sm" variant="flat" className={`${outcome.textClass} bg-white/45 dark:bg-black/15`}>
              {outcome.reachability}
            </Chip>
          </div>
          {outcome.level && <p className={`mt-1 text-small font-medium ${outcome.textClass}`}>直连难度 {outcome.level}/4</p>}
        </div>
      </div>
      <p className="mt-4 max-w-3xl text-small leading-6 text-zinc-700 dark:text-zinc-300 sm:text-medium">
        {outcome.description}
      </p>

      <div className="mt-4 grid gap-px overflow-hidden rounded-lg border border-black/[0.07] bg-black/[0.07] dark:border-white/10 dark:bg-white/10 sm:grid-cols-3">
        <NatEvidenceFact label="映射行为" value={mappingBehaviorText(result.mappingBehavior)} />
        <NatEvidenceFact
          label="过滤行为"
          value={result.filteringBehavior === "BROWSER_NOT_OBSERVABLE" ? "需原生 RFC 5780 验证" : "本轮未知"}
        />
        <NatEvidenceFact label="验证方法" value={verificationMethodLabel(result.verificationMethod)} />
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <NatImpactCard title="游戏联机" experience={outcome.game} />
        <NatImpactCard title="P2P / 语音视频" experience={outcome.p2p} />
      </div>

      <div className="mt-4 rounded-xl border border-black/[0.07] bg-white/45 p-3 dark:border-white/10 dark:bg-black/15">
        <p className="text-tiny font-semibold text-zinc-500 dark:text-zinc-400">建议</p>
        <p className="mt-1 text-small leading-6 text-zinc-700 dark:text-zinc-300">{result.recommendation}</p>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-tiny text-zinc-600 dark:text-zinc-400">
        <Tooltip
          placement="bottom"
          content={<div className="max-w-64 py-0.5 text-tiny">{technicalSummary}</div>}
        >
          <a
            href="#/help/peer-mesh#nat-types"
            className="inline-flex items-center gap-1.5 font-medium text-zinc-700 underline decoration-black/20 underline-offset-4 transition-colors hover:text-zinc-950 dark:text-zinc-300 dark:decoration-white/25 dark:hover:text-white"
          >
            <span className={`inline-block h-2 w-2 rounded-full ${natToneBg(outcome.tone)}`} />
            技术判断：{technicalLabel}
          </a>
        </Tooltip>
        <span aria-hidden="true">·</span>
        <span>置信度 {confidenceLabel(result.confidence)}</span>
        <span aria-hidden="true">·</span>
        <span>{result.evidence}</span>
      </div>
    </article>
  );
}

function NatEvidenceFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white/55 px-3 py-2.5 dark:bg-zinc-950/55">
      <p className="text-tiny text-zinc-500 dark:text-zinc-400">{label}</p>
      <p className="mt-0.5 text-small font-semibold text-zinc-900 dark:text-zinc-100">{value}</p>
    </div>
  );
}

function verificationMethodLabel(method: BrowserNatVerificationMethod): string {
  return method === "RFC5780_WEBRTC_MAPPING" ? "四端点 + 共享 ICE" : "多 STUN 共享 ICE";
}

function NatImpactCard({ title, experience }: { title: string; experience: BrowserNatExperience }) {
  return (
    <section className="rounded-xl border border-black/[0.07] bg-white/55 p-4 dark:border-white/10 dark:bg-black/15">
      <p className="text-tiny font-semibold text-zinc-500 dark:text-zinc-400">{title}</p>
      <p className="mt-1 text-base font-semibold text-zinc-950 dark:text-white">{experience.verdict}</p>
      <p className="mt-2 text-small leading-6 text-zinc-700 dark:text-zinc-300">{experience.description}</p>
    </section>
  );
}

function browserNatClassification(natType: string | null | undefined): BrowserNatOutcome | null {
  switch (natType) {
    case "NO_NAT":
      return BROWSER_NAT_CLASSIFICATIONS[1];
    case "PORT_PRESERVED_NAT":
    case "FULL_CONE_OR_RESTRICTED_NAT":
      return BROWSER_NAT_CLASSIFICATIONS[2];
    case "CONE_LIKE_NAT":
    case "PORT_RESTRICTED_NAT":
      return BROWSER_NAT_CLASSIFICATIONS[3];
    case "SYMMETRIC_NAT":
      return BROWSER_NAT_CLASSIFICATIONS[4];
    default:
      return null;
  }
}

export function browserNatOutcome(result: BrowserNatResult): BrowserNatOutcome {
  const classified = browserNatClassification(result.natType);
  if (classified) {
    return classified;
  }
  if (result.kind === "udp-blocked") {
    return {
      level: null,
      title: "未获得公网 UDP 映射",
      description: "本轮没有获得 STUN 公网映射。可能是网络限制 UDP/STUN，也可能是浏览器隐私策略、VPN、代理或探测服务不可达，不能直接断言 UDP 已被封锁。",
      reachability: "直连可能受阻",
      tone: "danger",
      frameClass: "border-rose-500/45 bg-rose-500/[0.08] dark:border-rose-400/40 dark:bg-rose-400/[0.1]",
      markerClass: "bg-rose-600 text-white dark:bg-rose-400 dark:text-zinc-950",
      textClass: "text-rose-800 dark:text-rose-200",
      game: {
        verdict: "依赖 UDP 的联机可能受影响",
        description: "如果网络确实限制 UDP，玩家直连、语音或部分实时游戏可能无法直连，或改走 TCP / 中继；连接中心服务器是否受影响取决于游戏协议。",
      },
      p2p: {
        verdict: "P2P 直连可能不可用",
        description: "WebRTC / P2P 直连可能无法建立；支持 TURN over TCP / TLS 的应用仍可能连接，但延迟和稳定性可能受影响。",
      },
    };
  }
  if (result.kind === "not-supported") {
    return unavailableNatOutcome("当前浏览器无法检测", "浏览器没有提供所需的 WebRTC 能力，这不是 NAT 类型结论。", "换用支持 WebRTC 的现代浏览器后再检测。");
  }
  if (result.kind === "failed") {
    return unavailableNatOutcome("本次检测未完成", "检测流程发生异常，这不是 NAT 类型结论。", "请重试，或检查 WebRTC 权限并更换 STUN 服务。");
  }
  return {
    ...unavailableNatOutcome(
      "类型暂未细分",
      "已经获得公网映射，但本轮可归属的 STUN 证据不足，暂时不能可靠判断具体 NAT 类型。",
      "建议增加 STUN 服务或更换网络复测，同时保留 Relay / TURN 回退。",
    ),
    game: {
      verdict: "联机影响仍需复测",
      description: "本次证据不足以判断玩家直连、组房或语音条件；连接普通中心服务器不一定受到影响。",
    },
    p2p: {
      verdict: "直连能力仍需复测",
      description: "可以继续尝试 P2P 直连，但暂时无法判断公网映射策略，应用必须保留 Relay / TURN 回退。",
    },
  };
}

function unavailableNatOutcome(title: string, description: string, action: string): BrowserNatOutcome {
  return {
    level: null,
    title,
    description,
    reachability: "暂时无法判断",
    tone: "warning",
    frameClass: "border-amber-500/40 bg-amber-500/[0.07] dark:border-amber-400/35 dark:bg-amber-400/[0.09]",
    markerClass: "bg-amber-500 text-zinc-950 dark:bg-amber-400",
    textClass: "text-amber-900 dark:text-amber-100",
    game: {
      verdict: "暂时无法判断",
      description: action,
    },
    p2p: {
      verdict: "暂时无法判断",
      description: action,
    },
  };
}

function MetricStrip({ result }: { result: BrowserNatResult | null }) {
  const knownProbes = result?.probes.filter((probe) => probe.sourceKnown) ?? [];
  const respondedCount = knownProbes.filter((probe) =>
    probe.candidates.some((candidate) => candidate.type === "srflx"),
  ).length;
  const items = [
    {
      label: result?.endpointChecks.length ? "四端点预检" : "STUN 服务",
      value: result?.endpointChecks.length
        ? `${result.endpointChecks.filter((check) => check.reachable).length}/${result.endpointChecks.length}`
        : result ? `${respondedCount}/${knownProbes.length}` : "—",
      hint: result?.endpointChecks.length
        ? "先分别验证 A1:P1、A1:P2、A2:P1、A2:P2 可达，防止把服务端点不可达误判成 NAT 行为。"
        : "返回公网映射的 STUN 服务数 / 参与探测的总数。返回数越多，映射结论越可靠。",
    },
    {
      label: "映射行为",
      value: result ? mappingBehaviorShortLabel(result.mappingBehavior) : "—",
      hint: "EIM 表示映射不随目标变化；ADM/APDM 表示映射依赖目标地址或端口。映射和过滤是两个独立维度。",
    },
    {
      label: "公网映射端点",
      value: result ? String(result.mappedEndpoints.length) : "—",
      hint: "NAT 分配给本机的公网 IP:Port。同一 UDP 基址因目标变化出现多个端点，表示目标相关映射。",
    },
    {
      label: "总耗时",
      value: result ? `${Math.max(0, result.finishedAt - result.startedAt)} ms` : "—",
      hint: "从发起检测到 ICE 收集结束的总时间，受「单服务超时」设置影响。",
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {items.map((item) => (
        <Tooltip
          key={item.label}
          placement="bottom"
          content={<div className="max-w-60 py-0.5 text-tiny">{item.hint}</div>}
        >
          <div className="cursor-help rounded-lg border glass glass-border px-3 py-2">
            <div className="flex items-center gap-1 text-tiny text-zinc-500 dark:text-zinc-400">
              <span>{item.label}</span>
              <InfoIcon className="h-3 w-3 shrink-0 opacity-60" />
            </div>
            <div className="mt-0.5 font-mono text-lg font-semibold text-zinc-950 dark:text-white">
              {item.value}
            </div>
          </div>
        </Tooltip>
      ))}
    </div>
  );
}

function mappingBehaviorShortLabel(mapping: BrowserNatMappingBehavior): string {
  switch (mapping) {
    case "ENDPOINT_INDEPENDENT":
      return "EIM";
    case "ADDRESS_DEPENDENT":
      return "ADM";
    case "ADDRESS_AND_PORT_DEPENDENT":
      return "APDM";
    case "TARGET_DEPENDENT":
      return "目标相关";
    case "NO_NAT":
      return "无 NAT";
    default:
      return "未知";
  }
}

function NatResultDetails({ result }: { result: BrowserNatResult }) {
  return (
    <div className="mt-6 flex flex-col gap-4">
      {result.endpointChecks.length > 0 && <Rfc5780EndpointCard checks={result.endpointChecks} />}
      <MappedEndpointsCard result={result} />
      <StunProbesCard result={result} />
      <CandidateTableCard result={result} />
    </div>
  );
}

function MappedEndpointsCard({ result }: { result: BrowserNatResult }) {
  const groups = [
    { label: "IPv4", endpoints: result.mappedEndpoints.filter((endpoint) => !isIpv6Endpoint(endpoint)) },
    { label: "IPv6", endpoints: result.mappedEndpoints.filter((endpoint) => isIpv6Endpoint(endpoint)) },
  ].filter((group) => group.endpoints.length > 0);

  return (
    <Card shadow="none" className="rounded-xl border glass glass-border">
      <CardBody className="gap-4 p-5">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="flex items-center gap-2">
            <DotIcon className={result.mappedEndpoints.length ? "text-emerald-500" : "text-zinc-400"} />
            <h2 className="text-base font-semibold">公网映射端点</h2>
          </span>
          <span className="text-tiny text-zinc-500 dark:text-zinc-400">
            NAT 分配给本机的公网出口，点击可复制
          </span>
        </div>
        {groups.length === 0 ? (
          <p className="rounded-lg border border-dashed border-black/15 dark:border-white/15 glass-chip p-3 text-small text-zinc-600 dark:text-zinc-400">
            未发现 server-reflexive 映射端点。UDP 出站可能被阻断，或配置的 STUN 服务均不可达。
          </p>
        ) : (
          <div className="flex flex-col gap-2">
            {groups.map((group) => (
              <div key={group.label} className="flex flex-wrap items-center gap-2">
                <span className="w-10 shrink-0 text-tiny font-medium text-zinc-500 dark:text-zinc-400">
                  {group.label}
                </span>
                {group.endpoints.map((endpoint) => (
                  <button
                    key={endpoint}
                    type="button"
                    onClick={() => void copyEndpoint(endpoint)}
                    className="group/copy flex items-center gap-1.5 rounded-md border border-emerald-500/25 bg-emerald-500/10 px-3 py-1.5 font-mono text-small text-emerald-700 transition-colors hover:border-emerald-500/45 hover:bg-emerald-500/20 dark:border-emerald-300/30 dark:bg-emerald-300/10 dark:text-emerald-100 dark:hover:border-emerald-300/50 dark:hover:bg-emerald-300/20"
                  >
                    <span className="break-all text-left">{endpoint}</span>
                    <CopyIcon className="h-3.5 w-3.5 shrink-0 opacity-50 transition-opacity group-hover/copy:opacity-100" />
                  </button>
                ))}
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function StunProbesCard({ result }: { result: BrowserNatResult }) {
  const knownProbes = result.probes.filter((probe) => probe.sourceKnown);
  const respondedCount = knownProbes.filter((probe) =>
    probe.candidates.some((candidate) => candidate.type === "srflx"),
  ).length;
  const allTopologyEndpointsReachable = result.endpointChecks.length >= 4
    && result.endpointChecks.every((check) => check.reachable);
  const sharedCandidateDeduplicated = result.mappingBehavior === "ENDPOINT_INDEPENDENT"
    && allTopologyEndpointsReachable;
  const headDotClass = sharedCandidateDeduplicated
    ? "text-emerald-500"
    : respondedCount === 0
      ? "text-rose-500"
      : respondedCount < knownProbes.length
        ? "text-amber-500"
        : "text-emerald-500";

  return (
    <Card shadow="none" className="rounded-xl border glass glass-border">
      <CardBody className="gap-3 p-5">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="flex items-center gap-2">
            <DotIcon className={headDotClass} />
            <h2 className="text-base font-semibold">共享 ICE 映射归属</h2>
          </span>
          <span className="text-tiny text-zinc-500 dark:text-zinc-400">
            浏览器可能合并多个端点返回的相同公网候选
          </span>
        </div>
        {sharedCandidateDeduplicated && (
          <p className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.07] px-3 py-2 text-tiny leading-5 text-emerald-800 dark:border-emerald-300/20 dark:bg-emerald-300/[0.08] dark:text-emerald-100">
            四端点均已通过独立预检。共享 ICE 只暴露一个相同公网映射，其余端点标记为候选去重，不代表服务不可达。
          </p>
        )}
        <div className="flex flex-col gap-2">
          {result.probes.map((probe) => {
            const preflightCheck = result.endpointChecks.find(
              (check) => normalizeStunUrl(check.endpoint.url).toLowerCase()
                === normalizeStunUrl(probe.server).toLowerCase(),
            );
            const candidateDeduplicated = sharedCandidateDeduplicated
              && Boolean(preflightCheck?.reachable)
              && !probe.candidates.some((candidate) => candidate.type === "srflx");
            const status = probeStatus(probe, candidateDeduplicated);
            const endpoints = Array.from(
              new Set(
                probe.candidates
                  .filter((candidate) => candidate.type === "srflx")
                  .map(endpointOf),
              ),
            );
            return (
              <div
                key={probe.server}
                className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border glass-chip glass-border px-3 py-2"
              >
                <Chip size="sm" variant="flat" color={status.color} className="shrink-0">
                  {status.label}
                </Chip>
                <code className="break-all font-mono text-tiny text-zinc-800 dark:text-zinc-200">
                  {probe.server}
                </code>
                {endpoints.length > 0 && (
                  <span className="flex flex-wrap items-center gap-1.5 sm:ml-auto">
                    {endpoints.map((endpoint) => (
                      <code
                        key={endpoint}
                        className="rounded border border-black/10 bg-black/[0.03] px-1.5 py-0.5 font-mono text-tiny text-zinc-600 dark:border-white/10 dark:bg-white/[0.06] dark:text-zinc-300"
                      >
                        {endpoint}
                      </code>
                    ))}
                  </span>
                )}
                {probe.error && !candidateDeduplicated && (
                  <p className={`w-full text-tiny ${probe.sourceKnown ? "text-danger" : "text-zinc-500 dark:text-zinc-400"}`}>
                    {probe.error}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </CardBody>
    </Card>
  );
}

function probeStatus(probe: StunProbeResult, candidateDeduplicated = false): {
  color: "success" | "warning" | "danger" | "default";
  label: string;
} {
  if (!probe.sourceKnown) {
    return { color: "default", label: "来源未归属" };
  }
  if (probe.candidates.some((candidate) => candidate.type === "srflx")) {
    return { color: "success", label: "已返回映射" };
  }
  if (candidateDeduplicated) {
    return { color: "default", label: "预检可达 · 候选去重" };
  }
  if (probe.error) {
    return { color: "danger", label: "超时/失败" };
  }
  return { color: "warning", label: "未返回映射" };
}

async function copyEndpoint(endpoint: string) {
  try {
    if (!navigator.clipboard?.writeText) {
      throw new Error("clipboard unavailable");
    }
    await navigator.clipboard.writeText(endpoint);
    notify(`已复制 ${endpoint}`);
  } catch {
    notify("复制失败，当前浏览器环境不允许自动写入剪贴板，请手动选择文本复制", "error");
  }
}

function isIpv6Endpoint(endpoint: string): boolean {
  return (endpoint.match(/:/g) ?? []).length > 1;
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
    <details className="group rounded-xl border glass glass-border transition-colors open:border-black/15 dark:open:border-white/15">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-5 text-base font-semibold">
        <span className="flex items-center gap-2">
          <ChevronIcon className="h-4 w-4 transition-transform group-open:rotate-90" />
          ICE Candidate 明细
          <span className="ml-1 text-small font-normal text-zinc-500 dark:text-zinc-400">
            ({candidates.length})
          </span>
        </span>
        <span className="text-tiny font-normal text-zinc-500 dark:text-zinc-400">
          <span className="group-open:hidden">点击展开</span>
          <span className="hidden group-open:inline">点击收起</span>
        </span>
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
                  <th className="px-2 py-1.5 text-left font-medium">
                    <Tooltip
                      placement="top"
                      content={
                        <div className="max-w-60 py-0.5 text-tiny">
                          raddr / rport：srflx 候选对应的本机源地址与源端口，用于对照公网端口是否被 NAT 改写。
                        </div>
                      }
                    >
                      <span className="inline-flex cursor-help items-center gap-1">
                        关联地址
                        <InfoIcon className="h-3 w-3 opacity-60" />
                      </span>
                    </Tooltip>
                  </th>
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
                      <Tooltip
                        placement="top"
                        content={<div className="max-w-60 py-0.5 text-tiny">{candidateTypeHint(item.candidate.type)}</div>}
                      >
                        <Chip size="sm" color={candidateColor(item.candidate.type)} variant="flat" className="cursor-help">
                          {item.candidate.type}
                        </Chip>
                      </Tooltip>
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

const NAT_LEVEL_GUIDE = [
  {
    level: 1,
    title: "公网直连型",
    modern: "未观察到 NAT 转换",
    signal: "公网候选地址和端口与本地 UDP 基址一致。",
    detail: "这通常表示设备直接持有公网地址，但不代表入站一定开放；本机防火墙、云安全组或运营商策略仍可能拦截数据。",
    impact: "直连条件最好，仍应通过 ICE 连通性检查确认真实路径。",
    tone: "border-emerald-500/35 text-emerald-700 dark:border-emerald-300/35 dark:text-emerald-200",
  },
  {
    level: 2,
    title: "端口保持型 NAT",
    modern: "EIM + 端口保持",
    signal: "四端点共享映射稳定，公网端口与本地源端口相同。",
    detail: "端口保持是端口分配特征，不是独立的 cone 类型。它让对端更容易预测候选端口，但过滤策略仍可能很严格。",
    impact: "通常利于 UDP 打洞，遇到严格过滤或目标相关映射对端时仍可能中继。",
    tone: "border-blue-500/35 text-blue-700 dark:border-blue-300/35 dark:text-blue-200",
  },
  {
    level: 3,
    title: "端点无关映射 NAT",
    modern: "Endpoint-Independent Mapping",
    signal: "访问 A1/A2、P1/P2 时公网映射不变，但端口发生转换。",
    detail: "它可能对应旧称 Full Cone、Restricted Cone 或 Port Restricted Cone；三者的差别在过滤轴，浏览器页面不能用 ICE candidate 完整区分。",
    impact: "映射侧对直连友好，实际成功率取决于双方过滤行为和防火墙。",
    tone: "border-amber-500/40 text-amber-800 dark:border-amber-300/40 dark:text-amber-100",
  },
  {
    level: 4,
    title: "目标相关映射 NAT",
    modern: "ADM / APDM，旧称 Symmetric NAT",
    signal: "同一 UDP 基址因目标 IP 或端口不同而获得不同公网映射。",
    detail: "ADM 依赖目标地址，APDM 同时依赖目标地址和端口。对端难以通过一次 STUN 结果预测后续目标可用的公网端点。",
    impact: "直连可预测性最低，应并行尝试候选并快速准备 TURN / Relay。",
    tone: "border-rose-500/40 text-rose-700 dark:border-rose-300/40 dark:text-rose-200",
  },
] as const;

function NatTypeGuide({
  probeConfig,
  compact = false,
}: {
  probeConfig: PublicNatProbeConfig | null;
  compact?: boolean;
}) {
  const topologyAvailable = rfc5780ProbeEndpoints(probeConfig).length === 4;
  const capabilities = probeConfig?.capabilities;

  return (
    <section className={compact ? "mt-4" : "mt-10"} aria-labelledby="nat-type-guide-title">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-black/10 pb-4 dark:border-white/10">
        <div className="max-w-3xl">
          <p className="text-tiny font-semibold text-zinc-500 dark:text-zinc-400">NAT1-4 直连难度分级</p>
          <h2 id="nat-type-guide-title" className="mt-1 text-xl font-semibold text-zinc-950 dark:text-white sm:text-2xl">
            映射决定端点是否可预测，过滤决定谁能回包
          </h2>
          <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-300">
            NAT1-4 是本页面为了直观展示而使用的分级，不是 IETF 标准类型。现代诊断应把映射行为和过滤行为分开记录。
          </p>
        </div>
        <Chip size="sm" radius="sm" variant="flat" color={topologyAvailable ? "success" : "warning"}>
          {topologyAvailable ? "RFC 5780 拓扑已下发" : "基础 STUN 兼容模式"}
        </Chip>
      </div>

      <div className="grid border-b border-black/10 dark:border-white/10 md:grid-cols-2">
        <div className="py-4 pr-0 md:pr-6">
          <p className="text-small font-semibold text-zinc-900 dark:text-white">映射行为 Mapping</p>
          <p className="mt-1 text-small leading-6 text-zinc-600 dark:text-zinc-400">
            EIM 不随目标变化；ADM 随目标 IP 变化；APDM 同时随目标 IP 和端口变化。本页面用共享 ICE socket 对四端点进行这一轴的观察。
          </p>
        </div>
        <div className="border-t border-black/10 py-4 md:border-l md:border-t-0 md:pl-6 dark:border-white/10">
          <p className="text-small font-semibold text-zinc-900 dark:text-white">过滤行为 Filtering</p>
          <p className="mt-1 text-small leading-6 text-zinc-600 dark:text-zinc-400">
            EIF 接受任意来源；ADF 要求先联系过来源 IP；APDF 要求先联系过来源 IP:Port。完整判断需要原生客户端发送 CHANGE-REQUEST。
          </p>
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        {NAT_LEVEL_GUIDE.map((item) => (
          <article key={item.level} className={`rounded-lg border-l-4 border-y border-r border-black/10 bg-white/45 p-4 dark:border-y-white/10 dark:border-r-white/10 dark:bg-white/[0.025] ${item.tone}`}>
            <div className="flex items-start gap-3">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-current/25 font-mono text-small font-semibold">
                {item.level}
              </span>
              <div className="min-w-0">
                <h3 className="text-base font-semibold text-zinc-950 dark:text-white">{item.title}</h3>
                <p className="mt-0.5 font-mono text-tiny font-medium">{item.modern}</p>
              </div>
            </div>
            <dl className="mt-3 grid gap-2 text-small leading-6">
              <div><dt className="inline font-semibold text-zinc-800 dark:text-zinc-200">判断依据：</dt><dd className="inline text-zinc-600 dark:text-zinc-400">{item.signal}</dd></div>
              <div><dt className="inline font-semibold text-zinc-800 dark:text-zinc-200">含义：</dt><dd className="inline text-zinc-600 dark:text-zinc-400">{item.detail}</dd></div>
              <div><dt className="inline font-semibold text-zinc-800 dark:text-zinc-200">直连影响：</dt><dd className="inline text-zinc-600 dark:text-zinc-400">{item.impact}</dd></div>
            </dl>
          </article>
        ))}
      </div>

      {!compact && (
        <div className="mt-6 border-y border-black/10 py-4 dark:border-white/10">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-semibold text-zinc-950 dark:text-white">当前验证链路</h3>
              <p className="mt-1 text-small text-zinc-600 dark:text-zinc-400">
                端点预检 → 同一 ICE socket 比对映射 → 原生客户端 CHANGE-REQUEST 补全过滤行为。
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {[
                ["Binding", capabilities?.binding],
                ["CHANGE-REQUEST", capabilities?.changeRequest],
                ["RESPONSE-ORIGIN", capabilities?.responseOrigin],
                ["OTHER-ADDRESS", capabilities?.otherAddress],
                ["RESPONSE-PORT", capabilities?.responsePort],
                ["PADDING", capabilities?.padding],
              ].map(([label, enabled]) => (
                <Chip key={String(label)} size="sm" radius="sm" variant="flat" color={enabled ? "success" : "default"}>
                  {label}
                </Chip>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function NatTips({ probeConfig }: { probeConfig: PublicNatProbeConfig | null }) {
  const tips = [
    { title: "这是即时快照", text: "RFC 5780 描述当前路径和当前端口的可观察行为。网关可能随负载、VPN、网络切换或映射超时改变结果。" },
    { title: "浏览器只验证映射轴", text: "WebRTC 不允许页面构造 CHANGE-REQUEST，因此过滤轴不会用超时猜测；原生客户端可完成 EIF / ADF / APDF 分类。" },
    { title: "类型不等于最终路径", text: "ICE 会交换真实候选并执行连通性检查。即使 NAT4 也应尝试直连，同时准备经过认证的 TURN / Relay。" },
  ];

  return (
    <section className="mt-10 grid gap-3 sm:grid-cols-3">
      {tips.map((tip) => (
        <div
          key={tip.title}
          className="rounded-xl border glass glass-border p-4"
        >
          <div className="text-small font-semibold text-zinc-900 dark:text-white">{tip.title}</div>
          <p className="mt-1.5 text-small leading-6 text-zinc-600 dark:text-zinc-400">{tip.text}</p>
        </div>
      ))}
      <div className="rounded-lg border glass glass-border p-4 sm:col-span-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-small text-zinc-700 dark:text-zinc-300">
            当前接口：{probeConfig?.protocol ?? "RFC8489"} / {probeConfig?.discoveryMethod ?? "BASIC_STUN"}。标准原文和实践说明可用于核对术语边界。
          </div>
          <div className="flex flex-wrap gap-2">
            <Button as="a" href="https://www.rfc-editor.org/rfc/rfc5780" rel="noreferrer" target="_blank" size="sm" radius="sm" variant="light">RFC 5780</Button>
            <Button as="a" href="https://www.rfc-editor.org/rfc/rfc8489" rel="noreferrer" target="_blank" size="sm" radius="sm" variant="light">RFC 8489</Button>
            <Button as="a" href={NAT_TRAVERSAL_REFERENCE.url} rel="noreferrer" target="_blank" size="sm" radius="sm" variant="light">NAT traversal</Button>
          </div>
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
    chipBg: string;
    chipText: string;
    chipBorder: string;
  }
> = {
  default: {
    border: "border-black/10 dark:border-white/10",
    bg: "bg-white/60 dark:bg-white/[0.03]",
    chipBg: "bg-zinc-200/70 dark:bg-white/10",
    chipText: "text-zinc-700 dark:text-zinc-200",
    chipBorder: "border-zinc-300/60 dark:border-white/10",
  },
  primary: {
    border: "border-primary-500/25 dark:border-primary-300/25",
    bg: "bg-primary-500/[0.04] dark:bg-primary-400/[0.06]",
    chipBg: "bg-primary-500/15 dark:bg-primary-400/15",
    chipText: "text-primary-700 dark:text-primary-300",
    chipBorder: "border-primary-500/30 dark:border-primary-300/30",
  },
  success: {
    border: "border-emerald-500/25 dark:border-emerald-300/25",
    bg: "bg-emerald-500/[0.04] dark:bg-emerald-400/[0.06]",
    chipBg: "bg-emerald-500/15 dark:bg-emerald-400/15",
    chipText: "text-emerald-700 dark:text-emerald-100",
    chipBorder: "border-emerald-500/30 dark:border-emerald-300/30",
  },
  warning: {
    border: "border-amber-500/25 dark:border-amber-300/25",
    bg: "bg-amber-500/[0.04] dark:bg-amber-400/[0.06]",
    chipBg: "bg-amber-500/15 dark:bg-amber-400/15",
    chipText: "text-amber-700 dark:text-amber-100",
    chipBorder: "border-amber-500/30 dark:border-amber-300/30",
  },
  danger: {
    border: "border-rose-500/25 dark:border-rose-300/25",
    bg: "bg-rose-500/[0.04] dark:bg-rose-400/[0.06]",
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

function InfoIcon({ className = "h-3.5 w-3.5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" />
      <line x1="12" y1="11" x2="12" y2="16" />
      <circle cx="12" cy="8" r="0.5" fill="currentColor" />
    </svg>
  );
}

function CopyIcon({ className = "h-3.5 w-3.5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h9" />
    </svg>
  );
}

// 结果徽章上的状态图标：成功打勾、警告感叹号、失败打叉、检测中呼吸点。
function StatusGlyph({
  color,
  className = "",
}: {
  color: "default" | "primary" | "success" | "warning" | "danger";
  className?: string;
}) {
  const base = `h-3.5 w-3.5 shrink-0 ${className}`;
  switch (color) {
    case "success":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" strokeWidth="2" />
          <polyline points="8.5 12.5 11 15 15.5 9.5" />
        </svg>
      );
    case "warning":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" />
          <line x1="12" y1="7.5" x2="12" y2="13" />
          <circle cx="12" cy="16.5" r="0.5" fill="currentColor" />
        </svg>
      );
    case "danger":
      return (
        <svg className={base} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" />
          <line x1="9" y1="9" x2="15" y2="15" />
          <line x1="15" y1="9" x2="9" y2="15" />
        </svg>
      );
    case "primary":
      return (
        <span className={`relative flex h-2.5 w-2.5 shrink-0 items-center justify-center ${className}`}>
          <span className="absolute h-full w-full animate-ping rounded-full bg-current opacity-50" />
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
        </span>
      );
    default:
      return <DotIcon className={`shrink-0 ${className}`} />;
  }
}

// 置信度三格量表：高亮格数对应高/中/低。
function ConfidenceBars({ confidence }: { confidence: BrowserNatConfidence }) {
  const filled = confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
  const heights = ["h-1.5", "h-2", "h-2.5"];
  return (
    <span aria-hidden="true" className="flex items-end gap-0.5">
      {heights.map((height, index) => (
        <span
          key={height}
          className={`w-1 rounded-sm ${height} ${
            index < filled
              ? "bg-primary-500 dark:bg-primary-300"
              : "bg-zinc-300/80 dark:bg-white/15"
          }`}
        />
      ))}
    </span>
  );
}

function candidateTypeHint(type: string): string {
  switch (type) {
    case "srflx":
      return "server-reflexive：STUN 服务看到的公网映射地址，即 NAT 分配给本机的公网出口。";
    case "host":
      return "host：本机网卡上的本地地址（内网 IP，或浏览器出于隐私生成的 .local mDNS 地址）。";
    case "relay":
      return "relay：经 TURN 中继分配的地址。本页只使用标准 STUN Binding，一般不会出现。";
    case "prflx":
      return "peer-reflexive：连接检查阶段由对端观察到的地址。";
    default:
      return "浏览器上报的其他 candidate 类型。";
  }
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
      return "bg-primary-500";
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

async function validateStunEndpoints(
  endpoints: PublicNatProbeEndpoint[],
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<StunEndpointCheck[]> {
  return Promise.all(endpoints.map(async (endpoint) => {
    const startedAt = performance.now();
    try {
      const probes = await probeStunServers([endpoint.url], timeoutMs, undefined, signal);
      const candidate = probes
        .flatMap((probe) => probe.candidates)
        .find((item) => item.type === "srflx");
      return {
        endpoint,
        reachable: Boolean(candidate),
        mappedEndpoint: candidate ? endpointOf(candidate) : null,
        elapsedMs: Math.round(performance.now() - startedAt),
        error: candidate ? null : probes[0]?.error ?? "未返回公网映射",
      };
    } catch (error) {
      if (signal?.aborted || (error instanceof Error && error.name === "AbortError")) {
        throw error;
      }
      return {
        endpoint,
        reachable: false,
        mappedEndpoint: null,
        elapsedMs: Math.round(performance.now() - startedAt),
        error: error instanceof Error ? error.message : "端点验证失败",
      };
    }
  }));
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
async function probeStunServers(
  servers: string[],
  timeoutMs: number,
  onProgress?: (progress: NatCheckProgress) => void,
  signal?: AbortSignal,
): Promise<StunProbeResult[]> {
  if (signal?.aborted) {
    throw createAbortError();
  }
  const startedAt = performance.now();
  const errorMap = new Map<string, string | null>();
  const candidatesByServer = new Map<string, BrowserIceCandidate[]>();
  const candidatesUnassigned: BrowserIceCandidate[] = [];
  const respondedServers = new Set<string>();
  let sawUnassignedMapping = false;

  const reportProbeProgress = (label: string) => {
    if (signal?.aborted) {
      return;
    }
    const responded = respondedServers.size;
    onProgress?.({
      phase: "probing",
      percent: responded > 0 && servers.length > 0
        ? Math.min(88, 36 + Math.round((responded / servers.length) * 52))
        : null,
      responded,
      total: servers.length,
      unattributedMapping: sawUnassignedMapping,
      label,
    });
  };

  for (const server of servers) {
    errorMap.set(server, null);
    candidatesByServer.set(server, []);
  }

  const pc = new RTCPeerConnection({
    iceServers: servers.map((urls) => ({ urls })),
    iceCandidatePoolSize: 0,
  });

  onProgress?.({
    phase: "probing",
    percent: 34,
    responded: 0,
    total: servers.length,
    unattributedMapping: false,
    label: "正在初始化 WebRTC 探针",
  });

  return new Promise<StunProbeResult[]>((resolve, reject) => {
    let finished = false;
    let timer = 0;
    const cleanup = () => {
      window.clearTimeout(timer);
      signal?.removeEventListener("abort", handleAbort);
      pc.onicecandidate = null;
      pc.onicegatheringstatechange = null;
      pc.close();
    };
    const finalize = (timedOut: boolean) => {
      if (finished) {
        return;
      }
      finished = true;
      cleanup();

      onProgress?.({
        phase: "analyzing",
        percent: 92,
        responded: respondedServers.size,
        total: servers.length,
        unattributedMapping: sawUnassignedMapping,
        label: "正在比对公网映射特征",
      });

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
    function handleAbort() {
      if (finished) {
        return;
      }
      finished = true;
      cleanup();
      reject(createAbortError());
    }

    timer = window.setTimeout(() => finalize(true), timeoutMs);
    if (signal?.aborted) {
      handleAbort();
      return;
    }
    signal?.addEventListener("abort", handleAbort, { once: true });

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
      let attributedServer: string | null = null;
      if (sourceUrl && candidatesByServer.has(sourceUrl)) {
        candidatesByServer.get(sourceUrl)!.push(parsed);
        attributedServer = sourceUrl;
      } else if (parsed.type === "srflx" && sourceUrl) {
        // 兼容某些浏览器把 stun:host:port?transport=udp 形式的 url 抹掉端口
        const normalized = findServerByUrl(sourceUrl, servers);
        if (normalized) {
          candidatesByServer.get(normalized)!.push(parsed);
          attributedServer = normalized;
        } else {
          candidatesUnassigned.push(parsed);
        }
      } else if (parsed.type === "srflx" && servers.length === 1) {
        candidatesByServer.get(servers[0])!.push(parsed);
        attributedServer = servers[0];
      } else {
        candidatesUnassigned.push(parsed);
      }

      if (parsed.type === "srflx" && attributedServer && !respondedServers.has(attributedServer)) {
        respondedServers.add(attributedServer);
        reportProbeProgress(`已收到 ${respondedServers.size}/${servers.length} 个 STUN 公网映射`);
      } else if (parsed.type === "srflx" && !attributedServer && !sawUnassignedMapping) {
        sawUnassignedMapping = true;
        reportProbeProgress("已收到公网映射，浏览器未暴露 STUN 来源");
      }
    };

    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === "complete") {
        finalize(false);
      }
    };

    try {
      pc.createDataChannel("shuai-tunnel-nat-check");
      reportProbeProgress("正在创建 ICE 探测会话");
      void pc
        .createOffer()
        .then((offer) => {
          reportProbeProgress("正在向 STUN 服务发起请求");
          return pc.setLocalDescription(offer);
        })
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

function createAbortError(): Error {
  const error = new Error("NAT detection aborted");
  error.name = "AbortError";
  return error;
}

function findServerByUrl(url: string, servers: string[]): string | null {
  const normalize = (value: string) => value.replace(/\?.*$/, "").toLowerCase();
  const target = normalize(url);
  return servers.find((server) => normalize(server) === target) ?? null;
}

interface BrowserNatClassificationContext {
  probeConfig?: PublicNatProbeConfig | null;
  endpointChecks?: StunEndpointCheck[];
}

interface NatGroupAssessment {
  natType: string | null;
  mappingBehavior: BrowserNatMappingBehavior;
  stunCount: number;
}

export function classifyBrowserNatResult(
  startedAt: number,
  probes: StunProbeResult[],
  context: BrowserNatClassificationContext = {},
): BrowserNatResult {
  const finishedAt = Date.now();
  const probeConfig = context.probeConfig ?? null;
  const endpointChecks = context.endpointChecks ?? [];
  const topologyEndpoints = rfc5780ProbeEndpoints(probeConfig);
  const topologyReady = topologyEndpoints.length === 4
    && topologyEndpoints.every((endpoint) => endpointChecks.some(
      (check) => check.endpoint.id === endpoint.id && check.reachable,
    ));
  const verificationMethod: BrowserNatVerificationMethod = topologyEndpoints.length === 4
    ? "RFC5780_WEBRTC_MAPPING"
    : "MULTI_STUN_WEBRTC";
  const filteringBehavior: BrowserNatFilteringBehavior = topologyEndpoints.length === 4
    ? "BROWSER_NOT_OBSERVABLE"
    : "UNKNOWN";
  const knownProbes = probes.filter((probe) => probe.sourceKnown);
  const unknownProbes = probes.filter((probe) => !probe.sourceKnown);
  const knownSrflxObservations = knownProbes.flatMap((probe) =>
    probe.candidates
      .filter((candidate) => candidate.type === "srflx")
      .map((candidate) => ({ server: probe.server, candidate })),
  );
  const knownSrflxAll = uniqueCandidates(
    knownSrflxObservations.map((observation) => observation.candidate),
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
  const comparableGroups = groupComparableSrflxMappings(
    knownSrflxObservations,
    topologyReady ? 1 : 2,
  );
  const groupAssessments: NatGroupAssessment[] = comparableGroups.map((group) => {
    const candidates = group.map((observation) => observation.candidate);
    const sample = candidates[0];
    const hosts = isIpv4Candidate(sample)
      ? hostAll.filter(isIpv4Candidate)
      : isIpv6Candidate(sample)
        ? hostAll.filter(isIpv6Candidate)
        : hostAll;
    const mappingBehavior = topologyReady && probeConfig
      ? inferRfc5780MappingBehavior(group, probeConfig, endpointChecks)
      : inferGenericMappingBehavior(candidates);
    const stableType = inferNatTypeForGroup(candidates, hosts);
    return {
      natType: isTargetDependentMapping(mappingBehavior) ? "SYMMETRIC_NAT" : stableType,
      mappingBehavior,
      stunCount: new Set(group.map((observation) => observation.server)).size,
    };
  });
  // 只比较同一本地 UDP 基址访问不同 STUN 后的结果，避免把 Wi-Fi、VPN 等多网卡映射误判为 Symmetric。
  const natType = pickWorstNatType(...groupAssessments.map((assessment) => assessment.natType));
  const comparableStunCountForResult = groupAssessments.reduce(
    (max, assessment) => assessment.natType === natType ? Math.max(max, assessment.stunCount) : max,
    0,
  );
  const mappingBehavior = pickMostRestrictiveMappingBehavior(
    ...groupAssessments
      .filter((assessment) => assessment.natType === natType)
      .map((assessment) => assessment.mappingBehavior),
  );
  const enoughKnownStunEvidence = groupAssessments.some(
    (assessment) => assessment.mappingBehavior !== "UNKNOWN",
  );
  const reachableEndpoints = endpointChecks.filter((check) => check.reachable).length;
  const topologyEvidence = endpointChecks.length > 0
    ? `，RFC 5780 端点预检 ${reachableEndpoints}/${endpointChecks.length} 可达`
    : "";
  const evidence = `${knownSrflxByServer.length} 个共享 ICE 映射可归属，${comparableGroups.length} 组本地 UDP 基址可比较，${unknownSrflxAll.length} 个映射未归属来源${topologyEvidence}`;

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
      verificationMethod,
      mappingBehavior: "UNKNOWN",
      filteringBehavior,
      endpointChecks,
    };
  }

  if (!enoughKnownStunEvidence) {
    const knownCount = knownSrflxByServer.length;
    const unknownCount = unknownSrflxAll.length;
    return {
      kind: "mapping-stable",
      natType: "NAT",
      startedAt,
      finishedAt,
      probes,
      mappedEndpoints,
      hostCandidates: hostAll,
      confidence: "low",
      evidence,
      summary: `已获得公网映射，${knownCount} 个 STUN 返回可归属结果，但没有足够的同一本地 UDP 映射可跨 STUN 比较，暂时无法判断映射是否随目标变化。`,
      recommendation: unknownCount > 0 && knownCount === 0
        ? "浏览器没有暴露 candidate.url，暂时不能细分 NAT 类型。建议保留 relay 回退，或更换浏览器/网络后复测。"
        : topologyEndpoints.length === 4 && !topologyReady
          ? "四端点没有全部通过预检，本轮不能把缺失响应当作 NAT 行为。请检查 A1/A2 的 P1/P2 UDP 放行后重测。"
          : "建议继续使用更多 STUN 复测；业务策略上可先尝试 direct，但必须保留 relay 回退。",
      verificationMethod,
      mappingBehavior: "UNKNOWN",
      filteringBehavior,
      endpointChecks,
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
      confidence: topologyReady && comparableStunCountForResult >= 2
        ? "high"
        : comparableStunCountForResult >= 2 ? "medium" : "low",
      evidence,
      summary: `同一个本机 UDP 基址访问四端点时出现不同公网映射，属于${mappingBehaviorText(mappingBehavior)}。传统工具通常把这类结果统称为 Symmetric NAT。`,
      recommendation: "目标相关映射会降低 UDP 打洞可预测性，应并行尝试 direct，并准备快速切换到 TURN / Relay。",
      verificationMethod,
      mappingBehavior,
      filteringBehavior,
      endpointChecks,
    };
  }

  const reportedMappingBehavior: BrowserNatMappingBehavior = natType === "NO_NAT"
    ? "NO_NAT"
    : mappingBehavior;

  return {
    kind: "mapping-stable",
    natType,
    startedAt,
    finishedAt,
    probes,
    mappedEndpoints,
    hostCandidates: hostAll,
    confidence: topologyReady
      ? "medium"
      : comparableStunCountForResult >= 3 ? "high" : "medium",
    evidence,
    summary: natType === "NO_NAT"
      ? "公网地址端口与本机一致，没有 NAT，直接是公网出口。"
      : natType === "PORT_PRESERVED_NAT"
        ? "多个 STUN 看到的公网端点一致，且 NAT 保留了本机源端口（端口保持 NAT）。"
        : "四端点共享探测未观察到目标相关映射，但公网端口被改写，符合端点无关映射。过滤行为需要原生 RFC 5780 CHANGE-REQUEST 才能继续区分。",
    recommendation: "端点无关映射通常有利于打洞；是否能接收陌生来源回包仍取决于过滤行为，因此必须保留 TURN / Relay 回退。",
    verificationMethod,
    mappingBehavior: reportedMappingBehavior,
    filteringBehavior,
    endpointChecks,
  };
}

/**
 * 基于浏览器 ICE 观测推断 NAT 类型，分类与 NAT_TYPE_PROFILES 对齐。
 *
 * <p>浏览器无法构造 RFC 5780 CHANGE-REQUEST，因此这里只判断映射轴，不能从响应超时
 * 推断 EIF / ADF / APDF 过滤行为。只输出浏览器侧有充分证据的几类：
 *
 * <ul>
 *   <li>四端点看到不同公网端点（同一 PC 共享 socket）→ ADM / APDM</li>
 *   <li>srflx 公网地址端口完全等于 host → NO_NAT</li>
 *   <li>srflx 公网端口 == 本机源端口 → PORT_PRESERVED_NAT</li>
 *   <li>其它 → CONE_LIKE_NAT（兼容键，页面展示为 EIM NAT）</li>
 * </ul>
 */
function groupComparableSrflxMappings(
  observations: AttributedSrflxObservation[],
  minimumServerCount = 2,
): AttributedSrflxObservation[][] {
  const groups = new Map<string, AttributedSrflxObservation[]>();
  for (const observation of observations) {
    const candidate = observation.candidate;
    if (!candidate.relatedAddress || candidate.relatedPort == null) {
      continue;
    }
    const key = [
      candidate.protocol,
      candidate.component,
      candidate.relatedAddress.toLowerCase(),
      candidate.relatedPort,
    ].join("|");
    const group = groups.get(key) ?? [];
    group.push(observation);
    groups.set(key, group);
  }
  return Array.from(groups.values()).filter(
    (group) => new Set(group.map((observation) => observation.server)).size >= minimumServerCount,
  );
}

function Rfc5780EndpointCard({ checks }: { checks: StunEndpointCheck[] }) {
  return (
    <section className="rounded-xl border glass glass-border p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold">RFC 5780 四端点预检</h2>
          <p className="mt-1 text-tiny text-zinc-500 dark:text-zinc-400">
            A1/A2 是两个公网地址，P1/P2 是两个 UDP 端口。预检只确认端点可达，不跨不同浏览器 socket 比较映射。
          </p>
        </div>
        <Chip size="sm" variant="flat" color={checks.every((check) => check.reachable) ? "success" : "warning"}>
          {checks.filter((check) => check.reachable).length}/{checks.length} 可达
        </Chip>
      </div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {checks.map((check) => (
          <div key={check.endpoint.id} className="min-w-0 rounded-lg border glass-chip glass-border p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-small font-semibold">{check.endpoint.id}</span>
              <span className={`h-2 w-2 rounded-full ${check.reachable ? "bg-emerald-500" : "bg-rose-500"}`} aria-hidden="true" />
            </div>
            <code className="mt-2 block break-all font-mono text-[11px] leading-5 text-zinc-600 dark:text-zinc-300">
              {check.endpoint.url}
            </code>
            <p className="mt-1 truncate text-tiny text-zinc-500 dark:text-zinc-400" title={check.mappedEndpoint ?? check.error ?? ""}>
              {check.mappedEndpoint ?? check.error ?? "未返回映射"} · {check.elapsedMs} ms
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}

function inferRfc5780MappingBehavior(
  observations: AttributedSrflxObservation[],
  config: PublicNatProbeConfig,
  endpointChecks: StunEndpointCheck[],
): BrowserNatMappingBehavior {
  const endpointByUrl = new Map(
    rfc5780ProbeEndpoints(config).map((endpoint) => [
      normalizeStunUrl(endpoint.url).toLowerCase(),
      endpoint,
    ]),
  );
  const mappedById = new Map<string, string>();
  for (const observation of observations) {
    const endpoint = endpointByUrl.get(normalizeStunUrl(observation.server).toLowerCase());
    if (endpoint) {
      mappedById.set(endpoint.id, endpointOf(observation.candidate));
    }
  }
  const mappings = new Set(mappedById.values());
  const allReachable = rfc5780ProbeEndpoints(config).every((endpoint) =>
    endpointChecks.some((check) => check.endpoint.id === endpoint.id && check.reachable),
  );
  if (mappings.size === 1 && allReachable) {
    return "ENDPOINT_INDEPENDENT";
  }
  if (mappings.size <= 1) {
    return "UNKNOWN";
  }

  const addressSlots = ["A1", "A2"];
  for (const slot of addressSlots) {
    const values = [mappedById.get(`${slot}P1`), mappedById.get(`${slot}P2`)]
      .filter((value): value is string => Boolean(value));
    if (new Set(values).size > 1) {
      return "ADDRESS_AND_PORT_DEPENDENT";
    }
  }

  const primaryMapping = mappedById.get("A1P1") ?? mappedById.get("A1P2");
  const alternateMapping = mappedById.get("A2P1") ?? mappedById.get("A2P2");
  if (primaryMapping && alternateMapping && primaryMapping !== alternateMapping) {
    return allReachable ? "ADDRESS_DEPENDENT" : "TARGET_DEPENDENT";
  }
  return "TARGET_DEPENDENT";
}

function inferGenericMappingBehavior(candidates: BrowserIceCandidate[]): BrowserNatMappingBehavior {
  if (candidates.length === 0) {
    return "UNKNOWN";
  }
  return new Set(candidates.map(endpointOf)).size > 1
    ? "TARGET_DEPENDENT"
    : "ENDPOINT_INDEPENDENT";
}

function isTargetDependentMapping(mapping: BrowserNatMappingBehavior): boolean {
  return mapping === "ADDRESS_DEPENDENT"
    || mapping === "ADDRESS_AND_PORT_DEPENDENT"
    || mapping === "TARGET_DEPENDENT";
}

function mappingBehaviorText(mapping: BrowserNatMappingBehavior): string {
  switch (mapping) {
    case "NO_NAT":
      return "无 NAT 映射";
    case "ENDPOINT_INDEPENDENT":
      return "端点无关映射（EIM）";
    case "ADDRESS_DEPENDENT":
      return "地址相关映射（ADM）";
    case "ADDRESS_AND_PORT_DEPENDENT":
      return "地址和端口相关映射（APDM）";
    case "TARGET_DEPENDENT":
      return "目标相关映射";
    default:
      return "映射行为未知";
  }
}

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

const MAPPING_BEHAVIOR_SEVERITY: Record<BrowserNatMappingBehavior, number> = {
  NO_NAT: 0,
  ENDPOINT_INDEPENDENT: 1,
  ADDRESS_DEPENDENT: 2,
  TARGET_DEPENDENT: 3,
  ADDRESS_AND_PORT_DEPENDENT: 4,
  UNKNOWN: -1,
};

function pickMostRestrictiveMappingBehavior(
  ...behaviors: BrowserNatMappingBehavior[]
): BrowserNatMappingBehavior {
  return behaviors.reduce<BrowserNatMappingBehavior>((worst, current) =>
    MAPPING_BEHAVIOR_SEVERITY[current] > MAPPING_BEHAVIOR_SEVERITY[worst] ? current : worst,
  "UNKNOWN");
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
