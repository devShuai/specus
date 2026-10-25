import { useEffect, useId, useMemo, useRef, useState, type CSSProperties } from "react";
import { Tooltip } from "@heroui/react";
import { HeroRuntime } from "../../components/HeroRuntime";
import { PublicPage } from "../../components/PublicTopBar";
import { notify } from "../../components/toast";
import { Alert, Card, CardHeader, Icon, Tag, type IconName, type Tone } from "../../components/ui";
import { fetchPublicNatProbeConfig, fetchPublicPeerStunConfig } from "../../api/client";
import type { PublicNatProbeConfig, PublicNatProbeEndpoint } from "../../api/types";
import { NAT_TRAVERSAL_REFERENCE, natTypeProfile } from "../../lib/nat";
import { usePageSeo } from "../../lib/seo";

export const DEFAULT_NAT_STUN_SERVERS = [
  "stun:stun1.specus.devshuai.com:34780",
  "stun:stun2.specus.devshuai.com:34780",
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

function timeoutMsInputValid(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  const numeric = Number(trimmed);
  return Number.isFinite(numeric) && numeric >= 3000 && numeric <= 15000;
}

function formatElapsedMs(ms: number): string {
  const value = Math.max(0, Math.round(ms));
  return value >= 1000 ? `${(value / 1000).toFixed(1)} 秒` : `${value} 毫秒`;
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
          title: "在线 NAT 类型检测 · 浏览器 STUN 探测 · specus",
          description:
            "免登录在线检测当前网络的 NAT 映射行为：使用 RFC 5780 四端点预检与共享 WebRTC ICE 探测，识别 EIM、ADM、APDM、端口保持与 UDP 阻断。",
          canonical: "https://specus.devshuai.com/nat-detect",
          keywords:
            "NAT 检测,NAT 类型,EIM,ADM,APDM,Symmetric NAT,RFC 5780,RFC 8489,STUN,WebRTC,在线 NAT 测试,UDP 打洞,P2P 直连",
          jsonLd: [
            {
              "@context": "https://schema.org",
              "@type": "WebApplication",
              "name": "specus 在线 NAT 检测",
              "url": "https://specus.devshuai.com/nat-detect",
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
                      "页面只从 specus 接口读取 STUN 拓扑，不上传检测结果。浏览器会创建一个空的 WebRTC data channel，触发 ICE candidate 收集，并向配置的 STUN 端点发送 Binding 请求；不会读取摄像头或麦克风。",
                  },
                },
              ],
            },
          ],
        }
      : {
          title: "NAT 类型检测 · specus 管理后台",
          description: "管理员视图：浏览器侧检测当前所在网络的 NAT 类型与公网映射稳定性。",
          canonical: "https://specus.devshuai.com/nat-detect",
        },
  );

  const servers = useMemo(
    () => serversText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    [serversText],
  );

  // 与 run() 相同的数据源：徽章/描述展示与实际检测路径保持一致。
  const activeProbeConfig = useMemo(
    () => activeRfc5780ProbeConfig(natProbeConfig, servers.length > 0 ? servers : defaultServers),
    [natProbeConfig, servers, defaultServers],
  );
  // 记录本次检测使用的参数，参数变更后提示结果可能过期。
  const runParamsRef = useRef<{ serversText: string; timeoutMs: string } | null>(null);
  const resultStale = result != null
    && runParamsRef.current != null
    && (runParamsRef.current.serversText !== serversText || runParamsRef.current.timeoutMs !== timeoutMs);

  const cancel = () => {
    activeProbeRef.current?.abort();
    activeProbeRef.current = null;
    setChecking(false);
    setResult(null);
    setProgress({
      phase: "idle",
      percent: null,
      responded: 0,
      total: servers.length > 0 ? servers.length : defaultServers.length,
      unattributedMapping: false,
      label: "已取消检测",
    });
  };

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
    runParamsRef.current = { serversText, timeoutMs };
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

  const stageProps = {
    result,
    checking,
    progress,
    onRun: () => void run(),
    onCancel: cancel,
    serversText,
    onServersTextChange: setServersText,
    timeoutMs,
    onTimeoutChange: setTimeoutMs,
    selfHostedStunServer,
    probeActive: activeProbeConfig != null,
    resultStale,
    onResetServers: () => setServersText(defaultServers.join("\n")),
  };
  const currentLevel = result ? browserNatOutcome(result).level : null;

  if (publicPage) {
    return (
      <PublicPage active="nat-detect">
        <div className="pub-container pub-nat">
          <NatDetectStage {...stageProps} />

          {result && (
            <>
              <NatVerdictSection result={result} />
              <NatTechnicalDetails result={result} />
            </>
          )}

          <NatTypeGuide probeConfig={natProbeConfig} currentLevel={currentLevel} />
          <NatFooterNote probeConfig={natProbeConfig} />
        </div>
      </PublicPage>
    );
  }

  // 控制台内嵌版：同一套卡片，检测球缩小，不带页头和页脚说明。
  return (
    <div className="pub-nat pub-nat--embedded">
      <NatDetectStage embedded {...stageProps} />
      {result && (
        <>
          <NatVerdictSection result={result} />
          <NatTechnicalDetails result={result} />
        </>
      )}
      <NatTypeGuide probeConfig={natProbeConfig} compact currentLevel={currentLevel} />
    </div>
  );
}

interface NatDetectStageProps {
  embedded?: boolean;
  result: BrowserNatResult | null;
  checking: boolean;
  progress: NatCheckProgress;
  onRun: () => void;
  onCancel: () => void;
  serversText: string;
  onServersTextChange: (text: string) => void;
  timeoutMs: string;
  onTimeoutChange: (value: string) => void;
  selfHostedStunServer: string;
  /** 与 run() 相同的判定：当前服务器列表是否走 RFC 5780 四端点 */
  probeActive: boolean;
  /** 检测参数在出结果后被修改，结果可能过期 */
  resultStale: boolean;
  onResetServers: () => void;
}

/**
 * 检测舞台：页面唯一的动作中心。
 *
 * 信息架构是「大按钮 → 一句话结论 → 细节折叠」，所以这里只保留
 * 状态标签、标题、检测球和可折叠的高级设置卡片，结果渲染全部交给 NatVerdictSection。
 */
function NatDetectStage({
  embedded = false,
  result,
  checking,
  progress,
  onRun,
  onCancel,
  serversText,
  onServersTextChange,
  timeoutMs,
  onTimeoutChange,
  selfHostedStunServer,
  probeActive,
  resultStale,
  onResetServers,
}: NatDetectStageProps) {
  const profile = browserNatProfile(checking ? "checking" : result?.kind ?? "idle");
  const outcome = result ? browserNatOutcome(result) : null;
  const fieldId = useId();
  const timeoutValid = timeoutMsInputValid(timeoutMs);
  const serverCount = serversText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).length;
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
      ? "结论与影响见下方报告；修改 STUN 服务或超时后建议重新检测。"
      : profile.description;
  const TitleTag = embedded ? "h2" : "h1";

  return (
    <section className={`pub-nat-stage${embedded ? " pub-nat-stage--embedded" : ""}`} aria-labelledby={`${fieldId}-title`}>
      <span className="jd-sr-only" role="status" aria-live="polite" aria-atomic="true">
        {liveAnnouncement}
      </span>
      <div className="pub-nat-stage-head">
        <div className="bd-row pub-nat-stage-tags">
          <Tag tone={checking ? "info" : result ? "success" : "neutral"}>
            {checking ? "检测进行中" : result ? "检测完成" : "准备就绪"}
          </Tag>
          <Tag plain>{probeActive ? "RFC 5780 四端点" : "WebRTC 多 STUN"}</Tag>
          {resultStale && <Tag tone="warning">参数已变更，结果可能过期</Tag>}
        </div>
        <TitleTag id={`${fieldId}-title`} className="bd-page-title pub-nat-title">{heroTitle}</TitleTag>
        <p className="bd-page-desc pub-nat-desc">{heroDescription}</p>
      </div>

      <div className="pub-nat-orb-row">
        <NatStageChannel
          state={checking ? "checking" : result ? "complete" : "idle"}
          tone={outcome?.tone ?? null}
          embedded={embedded}
        />
        <NatDetectionOrb
          embedded={embedded}
          checking={checking}
          result={result}
          progress={progress}
          onRun={onRun}
          onCancel={onCancel}
        />
      </div>

      <details className="bd-card pub-collapse pub-nat-settings">
        <summary>
          <Icon name="chevron-right" className="pub-collapse-chevron" />
          <span>高级设置（STUN 服务、超时时间）</span>
          <span className="pub-collapse-meta bd-num">{serverCount} 个服务 · 单服务 {timeoutMs.trim() || "—"} ms</span>
        </summary>
        <div className="pub-collapse-body">
          <div className="bd-form-grid pub-nat-settings-grid">
            <div className="bd-field">
              <label className="bd-label" htmlFor={`${fieldId}-servers`}>STUN 服务（每行一个，默认主备节点）</label>
              <textarea
                id={`${fieldId}-servers`}
                className="bd-input pub-mono-input"
                rows={3}
                spellCheck={false}
                value={serversText}
                onChange={(event) => onServersTextChange(event.target.value)}
                aria-describedby={`${fieldId}-servers-help`}
              />
              <p id={`${fieldId}-servers-help`} className="bd-help">
                {probeActive
                  ? "默认使用自建 A1/A2、P1/P2 四端点。页面先逐一验证可达性，再用同一 ICE socket 对比映射；不会使用 TURN relay。"
                  : `默认使用 specus 主备 STUN${selfHostedStunServer ? `，首选 ${selfHostedStunServer}` : ""}。浏览器仅使用标准 STUN Binding，不使用 TURN relay。`}
              </p>
            </div>
            <div className="bd-field">
              <label className="bd-label" htmlFor={`${fieldId}-timeout`}>单服务超时</label>
              <div className="bd-input-group">
                <input
                  id={`${fieldId}-timeout`}
                  className="bd-input bd-num"
                  inputMode="numeric"
                  value={timeoutMs}
                  onChange={(event) => onTimeoutChange(event.target.value)}
                  aria-invalid={timeoutValid ? undefined : true}
                  aria-describedby={`${fieldId}-timeout-help`}
                />
                <span className="bd-addon">ms</span>
              </div>
              <p id={`${fieldId}-timeout-help`} className={`bd-help${timeoutValid ? "" : " bd-help--error"}`}>
                {timeoutValid ? "3000–15000 毫秒，超时后这个服务记为未返回映射" : "超时要填 3000–15000 之间的毫秒数"}
              </p>
            </div>
          </div>
          <div className="pub-nat-settings-actions">
            <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={onResetServers}>
              <Icon name="rotate-ccw" />
              <span>恢复默认</span>
            </button>
          </div>
        </div>
      </details>
    </section>
  );
}

function useSmoothedPercent(target: number | null, active: boolean): number | null {
  const [display, setDisplay] = useState<number | null>(target);
  const displayRef = useRef<number | null>(target);

  useEffect(() => {
    if (!active || target == null) {
      displayRef.current = target;
      setDisplay(target);
      return;
    }
    if (displayRef.current == null) {
      displayRef.current = target;
    }
    let raf = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      const current = displayRef.current ?? target;
      let next = current + (target - current) * Math.min(1, dt * 3.4);
      // 两次上报之间缓慢向前爬升，避免进度环长时间停在一个值上
      const creepCap = Math.min(target + 6, 96);
      if (next < creepCap) {
        next += dt * 1.8;
      }
      next = Math.min(100, Math.max(0, next));
      displayRef.current = next;
      setDisplay(next);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, active]);

  return display;
}

const NAT_CHECK_STEPS: Array<{ phase: NatCheckProgressPhase; label: string }> = [
  { phase: "preparing", label: "准备探针" },
  { phase: "validating", label: "验证端点" },
  { phase: "probing", label: "映射探测" },
  { phase: "analyzing", label: "分析特征" },
];

const NAT_PHASE_ORDER: Record<NatCheckProgressPhase, number> = {
  idle: -1,
  preparing: 0,
  validating: 1,
  probing: 2,
  analyzing: 3,
  complete: NAT_CHECK_STEPS.length,
};

/** The running check as a staged row: done steps get a check, the current one is accent. */
function NatCheckSteps({ phase }: { phase: NatCheckProgressPhase }) {
  const current = NAT_PHASE_ORDER[phase];
  return (
    <ol className="pub-stages pub-stages--row" aria-hidden="true">
      {NAT_CHECK_STEPS.map((step, index) => {
        const state = index < current ? "done" : index === current ? "active" : "pending";
        return (
          <li key={step.phase} className="pub-stage" data-state={state}>
            <span className="pub-stage-dot bd-num">{state === "done" ? <Icon name="check" size={12} /> : index + 1}</span>
            <span className="pub-stage-body"><b>{step.label}</b></span>
          </li>
        );
      })}
    </ol>
  );
}

// 检测各阶段的主色：随阶段推进从蓝过渡到绿，给检测动画一个明确的前进感。
const NAT_PHASE_ACCENTS: Record<NatCheckProgressPhase, string> = {
  idle: "#0a84ff",
  preparing: "#0a84ff",
  validating: "#5e5ce6",
  probing: "#2ea5ff",
  analyzing: "#30d158",
  complete: "#30d158",
};

/** 渠水染成结论色：直连顺畅是 emerald，受阻依次转 amber / rose。 */
const NAT_CHANNEL_TONE_WATER: Record<BrowserNatOutcome["tone"], string> = {
  default: "#94a3b8",
  primary: "var(--specus-accent)",
  success: "#10b981",
  warning: "#f59e0b",
  danger: "#f43f5e",
};

/** 出结果后球内水位：直连越顺畅渠水越满，受阻则退到近涸。 */
const NAT_ORB_WATER_BY_TONE: Record<BrowserNatOutcome["tone"], number> = {
  default: 30,
  primary: 85,
  success: 85,
  warning: 45,
  danger: 16,
};

/** 渠面漂移的光点：节奏错开，读起来像持续的来水。 */
const NAT_CHANNEL_DOTS = [
  { duration: "6.4s", delay: "0s" },
  { duration: "8.2s", delay: "2.1s" },
  { duration: "7.3s", delay: "4.2s" },
] as const;

/**
 * 检测台的意象底座：一条水渠横贯检测球后方——检测球就是渠上的中央拱。
 *
 * 水流即检测：待命时渠水静静流淌；检测中水流加速、染成品牌蓝；
 * 出结果后渠水染成结论色，直连受阻（warning / danger）时流速骤降、
 * 光点隐去，像渠里断了水——能不能打洞，看这条渠就知道。
 *
 * 构图刻意只做「槽沿 + 水面 + 槽底」三道细线：检测球本身已是视觉中心，
 * 再叠拱券会和它打架（落地页主视觉才承担完整渠体）。
 */
function NatStageChannel({
  state,
  tone,
  embedded,
}: {
  state: "idle" | "checking" | "complete";
  tone: BrowserNatOutcome["tone"] | null;
  embedded: boolean;
}) {
  const blocked = state === "complete" && (tone === "warning" || tone === "danger");
  const waterColor = state === "checking"
    ? "var(--specus-accent)"
    : state === "complete" && tone
      ? NAT_CHANNEL_TONE_WATER[tone]
      : "var(--specus-water)";
  const style = {
    top: embedded ? 32 : 56,
    "--nat-channel-water": waterColor,
  } as CSSProperties;

  return (
    <div
      aria-hidden="true"
      className={`nat-stage-channel${state === "checking" ? " nat-stage-channel-checking" : ""}${blocked ? " nat-stage-channel-blocked" : ""}`}
      style={style}
    >
      <svg className="block h-full w-full" viewBox="0 0 1200 48" preserveAspectRatio="xMidYMid slice" fill="none">
        <defs>
          <linearGradient id="nat-channel-fade" x1="0" y1="0" x2="1200" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0" style={{ stopColor: "var(--specus-stroke)" }} stopOpacity="0" />
            <stop offset="0.18" style={{ stopColor: "var(--specus-stroke)" }} stopOpacity="0.4" />
            <stop offset="0.5" style={{ stopColor: "var(--specus-stroke)" }} stopOpacity="0.6" />
            <stop offset="0.82" style={{ stopColor: "var(--specus-stroke)" }} stopOpacity="0.4" />
            <stop offset="1" style={{ stopColor: "var(--specus-stroke)" }} stopOpacity="0" />
          </linearGradient>
          <linearGradient id="nat-channel-water-fade" x1="0" y1="0" x2="1200" y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0" style={{ stopColor: "var(--nat-channel-water, var(--specus-water))" }} stopOpacity="0" />
            <stop offset="0.14" style={{ stopColor: "var(--nat-channel-water, var(--specus-water))" }} stopOpacity="1" />
            <stop offset="0.86" style={{ stopColor: "var(--nat-channel-water, var(--specus-water))" }} stopOpacity="1" />
            <stop offset="1" style={{ stopColor: "var(--nat-channel-water, var(--specus-water))" }} stopOpacity="0" />
          </linearGradient>
        </defs>
        {/* 槽沿与槽底 */}
        <path d="M0 16 H1200" stroke="url(#nat-channel-fade)" strokeWidth="1.75" strokeLinecap="round" />
        <path d="M0 32 H1200" stroke="url(#nat-channel-fade)" strokeWidth="1.25" strokeLinecap="round" opacity="0.7" />
        {/* 槽中水面：dash march 模拟流动 */}
        <path d="M0 24 H1200" stroke="url(#nat-channel-water-fade)" strokeWidth="4" strokeLinecap="round" className="specus-water-march" />
      </svg>
      {NAT_CHANNEL_DOTS.map((dot) => (
        <span
          key={dot.delay}
          className="nat-channel-dot"
          style={{ animationDuration: dot.duration, animationDelay: dot.delay }}
        />
      ))}
    </div>
  );
}


function NatDetectionOrb({
  embedded,
  checking,
  result,
  progress,
  onRun,
  onCancel,
}: {
  embedded: boolean;
  checking: boolean;
  result: BrowserNatResult | null;
  progress: NatCheckProgress;
  onRun: () => void;
  onCancel: () => void;
}) {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const determinate = checking && progress.percent != null;
  const smoothPercent = useSmoothedPercent(progress.percent, checking);
  const ringPercent = determinate ? Math.min(100, Math.max(0, smoothPercent ?? 0)) : 0;
  const progressOffset = circumference * (1 - ringPercent / 100);
  const state = checking ? "checking" : result ? "complete" : "idle";
  const gradientId = useId();
  const outcomeTone = result ? browserNatOutcome(result).tone : null;
  // 球内水位：待命小半渠（停在副标题之下），检测中随进度涨水，出结果后停在结论对应的高度
  const waterLevel = checking
    ? determinate
      ? Math.round(18 + ringPercent * 0.68)
      : 40
    : result && outcomeTone
      ? NAT_ORB_WATER_BY_TONE[outcomeTone]
      : 20;
  const accentStyle = {
    "--nat-orb-accent": checking ? NAT_PHASE_ACCENTS[progress.phase] : "#0a84ff",
    "--nat-orb-water": checking
      ? "var(--specus-accent)"
      : outcomeTone
        ? NAT_CHANNEL_TONE_WATER[outcomeTone]
        : "var(--specus-water)",
    "--nat-orb-level": `${waterLevel}%`,
  } as CSSProperties;
  const centerText = checking
    ? progress.responded > 0 && progress.total > 0
      ? `${progress.responded}/${progress.total}`
      : progress.unattributedMapping
        ? "已映射"
        : "检测中"
    : result
      ? "再测一次"
      : "开始检测";

  return (
    <div className="relative flex min-w-0 flex-col items-center justify-center gap-3">
      {checking && (
        <span
          className="sr-only"
          role="progressbar"
          aria-label="NAT 检测进度"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={determinate ? Math.round(ringPercent) : undefined}
          aria-valuetext={progress.label}
        />
      )}
      <div className="nat-orb-stage" data-state={state}>
        <span className="nat-orb-halo" style={accentStyle} aria-hidden="true" />
        {/* The focus ring replaces the orb's own box-shadow. index.css sets that shadow for the dark
            and checking states with a selector as specific as focus-visible:ring-4 and now wins the
            tie, so those states repeat the ring with a variant that outranks it. */}
        <button
          type="button"
          aria-busy={checking}
          aria-label={checking ? "取消 NAT 检测" : result ? "重新检测 NAT 类型" : "检测 NAT 类型"}
          data-state={state}
          onClick={checking ? onCancel : onRun}
          style={accentStyle}
          className={`nat-detect-orb group relative isolate flex shrink-0 items-center justify-center rounded-full text-center outline-hidden focus-visible:ring-4 dark:focus-visible:ring-4 data-[state=checking]:focus-visible:ring-4 focus-visible:ring-primary-500/30 focus-visible:ring-offset-4 focus-visible:ring-offset-background motion-reduce:transform-none ${
            embedded ? "h-28 w-28" : "h-40 w-40"
          } cursor-pointer`}
        >
          {/* 隧道口沿圈：静态的一圈薄沿，让按钮读作渠首洞口 */}
          <span className="nat-orb-rim" aria-hidden="true" />
          {/* 探测波：三道涟漪自洞口荡出，一去不回 */}
          {checking && (
            <span className="nat-orb-sonar" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
          )}
          {/* 球内渠水：贴着球体弧度的一泓水，水位随状态涨落 */}
          <span className="nat-orb-water-clip" aria-hidden="true">
            <span className="nat-orb-water" />
          </span>
          {/* 落定：出结果时荡开一圈，像水滴刚落进渠里 */}
          {result && !checking && <span className="nat-orb-settle" aria-hidden="true" />}
          {checking && (
            <svg aria-hidden="true" className={`absolute inset-0 h-full w-full -rotate-90 ${determinate ? "" : "nat-detect-progress-indeterminate"}`} viewBox="0 0 100 100">
              <defs>
                <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" style={{ stopColor: "var(--nat-orb-accent, #0a84ff)" }} />
                  <stop offset="100%" style={{ stopColor: "var(--app-apple-blue, #0066cc)" }} />
                </linearGradient>
              </defs>
              <circle cx="50" cy="50" r={radius} fill="none" stroke="currentColor" strokeWidth="3" className="text-primary-500/15 dark:text-primary-300/15" />
              <circle
                cx="50"
                cy="50"
                r={radius}
                fill="none"
                stroke={`url(#${gradientId})`}
                strokeLinecap="round"
                strokeWidth="3"
                strokeDasharray={determinate ? circumference : `72 ${circumference - 72}`}
                strokeDashoffset={determinate ? progressOffset : 0}
              />
              {determinate && (
                <circle
                  cx={50 + radius * Math.cos((ringPercent / 100) * 2 * Math.PI)}
                  cy={50 + radius * Math.sin((ringPercent / 100) * 2 * Math.PI)}
                  r="3.4"
                  fill="currentColor"
                  className="nat-detect-progress-head text-primary-600 dark:text-primary-300"
                />
              )}
            </svg>
          )}
          <span className="relative z-10 flex max-w-[82%] flex-col items-center gap-1">
            {!checking && (
              <svg aria-hidden="true" className="nat-orb-idle-icon mb-0.5 h-7 w-7 text-primary-700 dark:text-primary-200" viewBox="0 0 32 32" fill="none">
                {/* 拱券 + 基石蓝点 + 拱下一脉水：specus 标识的缩影 */}
                <path d="M7 26 V16 A9 9 0 0 1 25 16 V26" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
                <circle cx="16" cy="3.6" r="2.1" fill="var(--specus-accent)" className="nat-orb-keystone" />
                <path d="M5.5 28.5 H26.5" stroke="var(--specus-water)" strokeWidth="1.6" strokeLinecap="round" strokeDasharray="3.5 3" opacity="0.85" />
              </svg>
            )}
            <span className={`pub-orb-value${checking ? " is-number" : embedded ? " is-small" : ""}`}>
              {checking && determinate ? `${Math.round(ringPercent)}%` : centerText}
            </span>
            <span className="pub-orb-hint">
              {checking ? "STUN 探测 · 按下取消" : result ? "更新检测结果" : "浏览器直测"}
            </span>
          </span>
        </button>
      </div>
      <div className="pub-orb-status">
        {checking && (
          <>
            <span className="pub-orb-status-label">{progress.label}</span>
            <span className="bd-num">
              {progress.responded > 0
                ? `${progress.responded}/${progress.total} 个 STUN 已返回映射`
                : progress.unattributedMapping
                  ? "已收到公网映射，来源未归属"
                  : "等待公网映射返回"}
            </span>
          </>
        )}
      </div>
      <div className="pub-orb-steps">
        {checking && <NatCheckSteps phase={progress.phase} />}
      </div>
    </div>
  );
}

type NatTone = BrowserNatOutcome["tone"];

/** The outcome tones in the design's status vocabulary: primary is informational, default neutral. */
function tagTone(tone: NatTone | "default" | "primary" | "success" | "warning" | "danger"): Tone {
  if (tone === "primary") return "info";
  if (tone === "default") return "neutral";
  return tone;
}

const TONE_ICON: Record<NatTone, IconName> = {
  default: "circle-alert",
  primary: "info-circle",
  success: "circle-check",
  warning: "alert",
  danger: "circle-x",
};

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
    <article className="bd-card pub-outcome nat-result-reveal" data-tone={outcome.tone}>
      <div className="pub-outcome-head">
        <span className="pub-outcome-mark" aria-hidden="true">
          <Icon name={TONE_ICON[outcome.tone]} size={22} />
        </span>
        <div className="min-w-0 flex-1">
          <p className="pub-outcome-kicker">检测结果</p>
          <div className="pub-outcome-title-row">
            <h2 className="pub-outcome-title">{outcome.title}</h2>
            <Tag tone={tagTone(outcome.tone)}>{outcome.reachability}</Tag>
          </div>
        </div>
        {outcome.level ? <NatDifficultyMeter level={outcome.level} tone={outcome.tone} /> : null}
      </div>

      <div className="pub-outcome-body">
        <p className="pub-outcome-desc">{outcome.description}</p>

        <dl className="bd-desc pub-outcome-facts">
          <div>
            <dt>映射行为</dt>
            <dd>{mappingBehaviorText(result.mappingBehavior)}</dd>
          </div>
          <div>
            <dt>过滤行为</dt>
            <dd>{result.filteringBehavior === "BROWSER_NOT_OBSERVABLE" ? "需原生 RFC 5780 验证" : "本轮未知"}</dd>
          </div>
          <div>
            <dt>验证方法</dt>
            <dd>{verificationMethodLabel(result.verificationMethod)}</dd>
          </div>
        </dl>

        <div className="pub-impact-grid">
          <NatImpactCard title="游戏联机" icon="users" experience={outcome.game} />
          <NatImpactCard title="P2P / 语音视频" icon="video" experience={outcome.p2p} />
        </div>

        <Alert tone="info" title="建议">{result.recommendation}</Alert>
      </div>

      <div className="pub-outcome-meta">
        <Tooltip
          placement="bottom"
          content={<div className="max-w-64 py-0.5 text-tiny">{technicalSummary}</div>}
        >
          <a href="#/help/peer-mesh#nat-types" className="jd-link pub-outcome-tech">
            技术判断：{technicalLabel}
          </a>
        </Tooltip>
        <span>置信度 {confidenceLabel(result.confidence)}</span>
        <span className="bd-num">耗时 {formatElapsedMs(result.finishedAt - result.startedAt)}</span>
        <span>{result.evidence}</span>
      </div>
    </article>
  );
}

// 直连难度量表：四段刻度，点亮的段数即难度，颜色跟随结论 tone。
function NatDifficultyMeter({ level, tone }: { level: BrowserNatLevel; tone: NatTone }) {
  return (
    <div className="pub-meter" data-tone={tone} role="img" aria-label={`直连难度 ${level}/4`}>
      <div className="pub-meter-head">
        <span>直连难度</span>
        <b className="bd-num">{level}<span>/4</span></b>
      </div>
      <div className="pub-meter-track" aria-hidden="true">
        {[1, 2, 3, 4].map((segment) => (
          <span key={segment} className={segment <= level ? "is-on" : undefined} />
        ))}
      </div>
    </div>
  );
}

function verificationMethodLabel(method: BrowserNatVerificationMethod): string {
  return method === "RFC5780_WEBRTC_MAPPING" ? "四端点 + 共享 ICE" : "多 STUN 共享 ICE";
}

function NatImpactCard({ title, icon, experience }: { title: string; icon: IconName; experience: BrowserNatExperience }) {
  return (
    <section className="pub-impact">
      <div className="pub-impact-head">
        <span className="pub-impact-icon" aria-hidden="true"><Icon name={icon} size={14} /></span>
        <span>{title}</span>
      </div>
      <p className="pub-impact-verdict">{experience.verdict}</p>
      <p className="pub-impact-desc">{experience.description}</p>
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
    return unavailableNatOutcome("本次检测未完成", "检测流程发生异常，这不是 NAT 类型结论。", "重新检测；仍不成功时检查 WebRTC 权限，或在高级设置里更换 STUN 服务。");
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

/** The four numbers of a finished check, with what each means on hover. */
function NatMetrics({ result }: { result: BrowserNatResult }) {
  const knownProbes = result.probes.filter((probe) => probe.sourceKnown);
  const respondedCount = knownProbes.filter((probe) =>
    probe.candidates.some((candidate) => candidate.type === "srflx"),
  ).length;
  const endpointTotal = result.endpointChecks.length;
  const reachableCount = result.endpointChecks.filter((check) => check.reachable).length;
  const items = [
    {
      label: endpointTotal ? "四端点预检" : "STUN 服务",
      value: endpointTotal > 0 ? `${reachableCount}/${endpointTotal}` : `${respondedCount}/${knownProbes.length}`,
      hint: endpointTotal
        ? "先分别验证 A1:P1、A1:P2、A2:P1、A2:P2 可达，防止把服务端点不可达误判成 NAT 行为。"
        : "返回公网映射的 STUN 服务数 / 参与探测的总数。返回数越多，映射结论越可靠。",
    },
    {
      label: "映射行为",
      value: mappingBehaviorShortLabel(result.mappingBehavior),
      hint: "EIM 表示映射不随目标变化；ADM/APDM 表示映射依赖目标地址或端口。映射和过滤是两个独立维度。",
    },
    {
      label: "公网映射端点",
      value: `${result.mappedEndpoints.length} 个`,
      hint: "NAT 分配给本机的公网 IP:Port。同一 UDP 基址因目标变化出现多个端点，表示目标相关映射。",
    },
    {
      label: "总耗时",
      value: formatElapsedMs(Math.max(0, result.finishedAt - result.startedAt)),
      hint: "从发起检测到 ICE 收集结束的总时间，受「单服务超时」设置影响。",
    },
  ];
  return (
    <div className="bd-dash pub-nat-metrics nat-result-reveal" style={{ animationDelay: "90ms" }}>
      {items.map((item) => (
        <Tooltip
          key={item.label}
          placement="bottom"
          content={<div className="max-w-60 py-0.5 text-tiny">{item.hint}</div>}
        >
          <div className="bd-card bd-stat bd-span-3 pub-nat-stat" tabIndex={0} aria-label={`${item.label}：${item.value}。${item.hint}`}>
            <div className="bd-stat-label">
              <span>{item.label}</span>
              <Icon name="info" size={12} />
            </div>
            <div className="bd-stat-value">{item.value}</div>
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

/**
 * 结论区：用户最关心的部分全部平铺——一句话结论、关键指标、自己的公网映射端点。
 */
function NatVerdictSection({ result }: { result: BrowserNatResult }) {
  const outcome = browserNatOutcome(result);
  const profile = browserNatProfile(result.kind);
  const natTypeProfileEntry = result.natType ? natTypeProfile(result.natType) : null;
  return (
    <section className="pub-nat-verdict" aria-label="检测报告">
      <NatOutcomeCard
        result={result}
        outcome={outcome}
        technicalLabel={natTypeProfileEntry?.label ?? profile.title}
        technicalSummary={natTypeProfileEntry?.summary ?? result.summary}
      />
      <NatMetrics result={result} />
      <MappedEndpointsCard result={result} />
    </section>
  );
}

/**
 * 技术细节折叠卡片：RFC 5780 预检、STUN 探测归属、ICE Candidate 明细。
 * 面向的用户只需要结论，这些证据默认收起，排查时一次展开。
 */
function NatTechnicalDetails({ result }: { result: BrowserNatResult }) {
  const candidateCount = result.probes.reduce((count, probe) => count + probe.candidates.length, 0);
  return (
    <details className="bd-card pub-collapse pub-nat-details nat-result-reveal" style={{ animationDelay: "220ms" }}>
      <summary>
        <Icon name="chevron-right" className="pub-collapse-chevron" />
        <span>技术细节</span>
        <span className="pub-collapse-meta bd-num">
          {[
            result.endpointChecks.length > 0 ? "RFC 5780 预检" : null,
            `${result.probes.length} 个 STUN 探测`,
            `${candidateCount} 个 ICE Candidate`,
          ].filter(Boolean).join(" · ")}
        </span>
      </summary>
      <div className="pub-collapse-body pub-nat-details-body">
        {result.endpointChecks.length > 0 && <Rfc5780EndpointCard checks={result.endpointChecks} />}
        <StunProbesCard result={result} />
        <CandidateTableCard result={result} />
      </div>
    </details>
  );
}

function MappedEndpointsCard({ result }: { result: BrowserNatResult }) {
  const groups = [
    { label: "IPv4", endpoints: result.mappedEndpoints.filter((endpoint) => !isIpv6Endpoint(endpoint)) },
    { label: "IPv6", endpoints: result.mappedEndpoints.filter((endpoint) => isIpv6Endpoint(endpoint)) },
  ].filter((group) => group.endpoints.length > 0);

  return (
    <Card className="pub-nat-endpoints nat-result-reveal" style={{ animationDelay: "160ms" }}>
      <CardHeader
        title="公网映射端点"
        description="NAT 分配给本机的公网出口；按端点即可复制"
        actions={<Tag tone={groups.length ? "success" : "warning"} className="bd-num">{result.mappedEndpoints.length} 个</Tag>}
      />
      <div className="bd-card-body">
        {groups.length === 0 ? (
          <Alert tone="warning" title="未发现 server-reflexive 映射端点">
            UDP 出站可能被阻断，或配置的 STUN 服务均不可达。换一个网络，或在高级设置里更换 STUN 服务后重新检测。
          </Alert>
        ) : (
          <div className="pub-endpoint-groups">
            {groups.map((group) => (
              <div key={group.label} className="pub-endpoint-group">
                <span className="pub-endpoint-family">{group.label}</span>
                <div className="bd-row">
                  {group.endpoints.map((endpoint) => (
                    <button
                      key={endpoint}
                      type="button"
                      onClick={() => void copyEndpoint(endpoint)}
                      className="bd-btn bd-btn--secondary bd-btn--sm pub-endpoint"
                    >
                      <span>{endpoint}</span>
                      <Icon name="copy" />
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
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
  const summaryTone: Tone = sharedCandidateDeduplicated
    ? "success"
    : respondedCount === 0
      ? "danger"
      : respondedCount < knownProbes.length
        ? "warning"
        : "success";

  return (
    <section className="pub-subsection">
      <div className="pub-subsection-head">
        <div className="min-w-0">
          <h3>共享 ICE 映射归属</h3>
          <p>浏览器可能合并多个端点返回的相同公网候选</p>
        </div>
        <Tag tone={summaryTone} className="bd-num">{respondedCount}/{knownProbes.length} 已返回映射</Tag>
      </div>
      {sharedCandidateDeduplicated && (
        <Alert tone="success" title="四端点均已通过独立预检">
          共享 ICE 只暴露一个相同公网映射，其余端点标记为候选去重，不代表服务不可达。
        </Alert>
      )}
      <div className="bd-table-wrap">
        <table className="bd-table jd-stack pub-nat-table">
          <thead>
            <tr>
              <th scope="col">STUN 服务</th>
              <th scope="col">状态</th>
              <th scope="col">公网映射</th>
            </tr>
          </thead>
          <tbody>
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
              const showError = Boolean(probe.error) && !candidateDeduplicated;
              return (
                <tr key={probe.server}>
                  <td className="jd-cell-full">
                    <code className="pub-mono">{probe.server}</code>
                    {showError && (
                      <span className={`pub-probe-error${probe.sourceKnown ? " is-danger" : ""}`}>{probe.error}</span>
                    )}
                  </td>
                  <td><Tag tone={tagTone(status.color)}>{status.label}</Tag></td>
                  <td className={endpoints.length ? undefined : "is-empty"}>
                    {endpoints.length ? (
                      <span className="pub-mono-list">
                        {endpoints.map((endpoint) => <code key={endpoint} className="pub-mono">{endpoint}</code>)}
                      </span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
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
    notify("没有复制：当前浏览器不允许自动写入剪贴板，手动选中端点文字复制", "error");
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
    <details className="pub-collapse pub-subcollapse">
      <summary>
        <Icon name="chevron-right" className="pub-collapse-chevron" />
        <span>ICE Candidate 明细</span>
        <span className="pub-collapse-meta bd-num">{candidates.length} 个</span>
      </summary>
      <div className="pub-subcollapse-body">
        {candidates.length === 0 ? (
          <p className="pub-muted-note">未收集到 ICE candidate。</p>
        ) : (
          <div className="bd-table-wrap">
            <table className="bd-table bd-table--compact jd-stack pub-nat-table">
              <thead>
                <tr>
                  <th scope="col">STUN</th>
                  <th scope="col">类型</th>
                  <th scope="col">协议</th>
                  <th scope="col">地址</th>
                  <th scope="col">
                    <Tooltip
                      placement="top"
                      content={
                        <div className="max-w-60 py-0.5 text-tiny">
                          raddr / rport：srflx 候选对应的本机源地址与源端口，用于对照公网端口是否被 NAT 改写。
                        </div>
                      }
                    >
                      <span className="pub-th-hint" tabIndex={0}>
                        关联地址
                        <Icon name="info" size={12} />
                      </span>
                    </Tooltip>
                  </th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((item) => (
                  <tr key={item.id}>
                    <td className="jd-cell-full">
                      <span className="pub-mono pub-wrap">{item.probe.server}</span>
                      {item.probe.error ? <span className="pub-probe-error is-danger">{item.probe.error}</span> : null}
                    </td>
                    <td>
                      <Tooltip
                        placement="top"
                        content={<div className="max-w-60 py-0.5 text-tiny">{candidateTypeHint(item.candidate.type)}</div>}
                      >
                        <span tabIndex={0} className="pub-tag-hint">
                          <Tag tone={tagTone(candidateColor(item.candidate.type))}>{item.candidate.type}</Tag>
                        </span>
                      </Tooltip>
                    </td>
                    <td data-label="协议" className="pub-upper">{item.candidate.protocol}</td>
                    <td data-label="地址"><span className="pub-mono pub-wrap">{endpointOf(item.candidate)}</span></td>
                    <td data-label="关联地址"><span className="pub-mono pub-wrap pub-muted">{relatedEndpointOf(item.candidate)}</span></td>
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

const NAT_LEVEL_GUIDE: Array<{
  level: BrowserNatLevel;
  title: string;
  modern: string;
  signal: string;
  detail: string;
  impact: string;
  tone: NatTone;
}> = [
  {
    level: 1,
    title: "公网直连型",
    modern: "未观察到 NAT 转换",
    signal: "公网候选地址和端口与本地 UDP 基址一致。",
    detail: "这通常表示设备直接持有公网地址，但不代表入站一定开放；本机防火墙、云安全组或运营商策略仍可能拦截数据。",
    impact: "直连条件最好，仍应通过 ICE 连通性检查确认真实路径。",
    tone: "success",
  },
  {
    level: 2,
    title: "端口保持型 NAT",
    modern: "EIM + 端口保持",
    signal: "四端点共享映射稳定，公网端口与本地源端口相同。",
    detail: "端口保持是端口分配特征，不是独立的 cone 类型。它让对端更容易预测候选端口，但过滤策略仍可能很严格。",
    impact: "通常利于 UDP 打洞，遇到严格过滤或目标相关映射对端时仍可能中继。",
    tone: "primary",
  },
  {
    level: 3,
    title: "端点无关映射 NAT",
    modern: "Endpoint-Independent Mapping",
    signal: "访问 A1/A2、P1/P2 时公网映射不变，但端口发生转换。",
    detail: "它可能对应旧称 Full Cone、Restricted Cone 或 Port Restricted Cone；三者的差别在过滤轴，浏览器页面不能用 ICE candidate 完整区分。",
    impact: "映射侧对直连友好，实际成功率取决于双方过滤行为和防火墙。",
    tone: "warning",
  },
  {
    level: 4,
    title: "目标相关映射 NAT",
    modern: "ADM / APDM，旧称 Symmetric NAT",
    signal: "同一 UDP 基址因目标 IP 或端口不同而获得不同公网映射。",
    detail: "ADM 依赖目标地址，APDM 同时依赖目标地址和端口。对端难以通过一次 STUN 结果预测后续目标可用的公网端点。",
    impact: "直连可预测性最低，应并行尝试候选并快速准备 TURN / Relay。",
    tone: "danger",
  },
];

/**
 * 分级徽章里的拱洞：拱顶的数字是基石，拱券立在渠床上，
 * 拱下的开口与穿洞的水就是直连难度——NAT1 开敞通水，
 * NAT2 收窄，NAT3 半掩水弱，NAT4 闸死断流。
 */
function NatLevelArchGlyph({ level }: { level: BrowserNatLevel }) {
  return (
    <svg viewBox="0 0 40 48" fill="none" aria-hidden="true">
      {/* 拱券 */}
      <path d="M9.5 41 V22 A10.5 10.5 0 0 1 30.5 22 V41" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      {/* 渠床两道线 */}
      <path d="M4 43.75 H36" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" opacity="0.45" />
      <path d="M7.5 46.25 H32.5" stroke="currentColor" strokeWidth="1" strokeLinecap="round" opacity="0.28" />
      {/* 穿洞的水：随级别变窄变淡，NAT4 断流 */}
      {level <= 3 && (
        <path
          d={level === 1 ? "M12 38 H28" : level === 2 ? "M14.5 38 H25.5" : "M15.5 38 H24.5"}
          stroke="var(--specus-water)"
          strokeWidth={level === 3 ? 1.3 : 1.8}
          strokeLinecap="round"
          strokeDasharray="3 2.4"
          opacity={level === 3 ? 0.6 : 0.9}
        />
      )}
      {/* 收窄的副拱 / 半掩的闸板 / 封死的闸 */}
      {level === 2 && (
        <path d="M14.5 41 V27 A5.5 5.5 0 0 1 25.5 27 V41" stroke="currentColor" strokeWidth="1.5" opacity="0.7" />
      )}
      {level === 3 && (
        <path d="M12.5 31 H27.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.85" />
      )}
      {level === 4 && (
        <path d="M11.5 41 V31 H28.5 V41 Z" fill="currentColor" opacity="0.85" />
      )}
    </svg>
  );
}

const VERIFICATION_CHAIN = [
  { title: "端点预检", detail: "逐一确认 A1/A2、P1/P2 四个 STUN 端点可达" },
  { title: "同一 ICE socket 比对映射", detail: "浏览器用共享 socket 访问四端点，观察映射是否随目标变化" },
  { title: "原生客户端补全过滤行为", detail: "发送 CHANGE-REQUEST 区分 EIF / ADF / APDF" },
];

function NatTypeGuide({
  probeConfig,
  compact = false,
  currentLevel = null,
}: {
  probeConfig: PublicNatProbeConfig | null;
  compact?: boolean;
  /** 本次检测结果命中的分级，对应条目会高亮标注 */
  currentLevel?: BrowserNatLevel | null;
}) {
  const topologyAvailable = rfc5780ProbeEndpoints(probeConfig).length === 4;
  const capabilities = probeConfig?.capabilities;

  return (
    <section className="jd-section pub-nat-guide" aria-labelledby="nat-type-guide-title">
      <div className="jd-section-head">
        <div className="min-w-0">
          <h2 id="nat-type-guide-title">NAT1-4 直连难度分级</h2>
          <p>
            映射决定端点是否可预测，过滤决定谁能回包。NAT1-4 是本页面为了直观展示而使用的分级，不是 IETF 标准类型；现代诊断应把映射行为和过滤行为分开记录。
          </p>
        </div>
        <Tag tone={topologyAvailable ? "success" : "warning"}>
          {topologyAvailable ? "RFC 5780 拓扑已下发" : "基础 STUN 兼容模式"}
        </Tag>
      </div>

      <div className="pub-axis-grid">
        <Card className="pub-axis">
          <h3 className="bd-card-title">映射行为 Mapping</h3>
          <p>EIM 不随目标变化；ADM 随目标 IP 变化；APDM 同时随目标 IP 和端口变化。本页面用共享 ICE socket 对四端点进行这一轴的观察。</p>
        </Card>
        <Card className="pub-axis">
          <h3 className="bd-card-title">过滤行为 Filtering</h3>
          <p>EIF 接受任意来源；ADF 要求先联系过来源 IP；APDF 要求先联系过来源 IP:Port。完整判断需要原生客户端发送 CHANGE-REQUEST。</p>
        </Card>
      </div>

      <Card className="pub-level-card">
        <ol className="pub-stages pub-level-scale" aria-label="直连难度从易到难">
          {NAT_LEVEL_GUIDE.map((item) => {
            const isCurrent = currentLevel === item.level;
            return (
              <li key={item.level} className="pub-stage pub-level" data-tone={item.tone} data-current={isCurrent || undefined}>
                <span className="pub-level-badge">
                  <NatLevelArchGlyph level={item.level} />
                  <span className="pub-level-badge-num bd-num">{item.level}</span>
                </span>
                <div className="pub-stage-body">
                  <div className="pub-level-title">
                    <h3>{item.title}</h3>
                    <code>{item.modern}</code>
                    {isCurrent && <Tag tone="info">本次结果</Tag>}
                  </div>
                  <dl className="pub-level-facts">
                    <div><dt>判断依据</dt><dd>{item.signal}</dd></div>
                    <div><dt>含义</dt><dd>{item.detail}</dd></div>
                    <div><dt>直连影响</dt><dd>{item.impact}</dd></div>
                  </dl>
                </div>
              </li>
            );
          })}
        </ol>
      </Card>

      {!compact && (
        <Card className="pub-chain">
          <CardHeader
            title="当前验证链路"
            description="端点预检 → 同一 ICE socket 比对映射 → 原生客户端 CHANGE-REQUEST 补全过滤行为"
          />
          <div className="bd-card-body pub-chain-body">
            <ol className="pub-stages pub-chain-steps">
              {VERIFICATION_CHAIN.map((step, index) => (
                <li key={step.title} className="pub-stage">
                  <span className="pub-stage-dot bd-num">{index + 1}</span>
                  <div className="pub-stage-body">
                    <b>{step.title}</b>
                    <span>{step.detail}</span>
                  </div>
                </li>
              ))}
            </ol>
            <div className="pub-chain-caps">
              <p className="pub-chain-caps-label">STUN 服务支持的属性</p>
              <div className="bd-row">
                {[
                  ["Binding", capabilities?.binding],
                  ["CHANGE-REQUEST", capabilities?.changeRequest],
                  ["RESPONSE-ORIGIN", capabilities?.responseOrigin],
                  ["OTHER-ADDRESS", capabilities?.otherAddress],
                  ["RESPONSE-PORT", capabilities?.responsePort],
                  ["PADDING", capabilities?.padding],
                ].map(([label, enabled]) => (
                  <Tag key={String(label)} tone={enabled ? "success" : "neutral"} plain={!enabled}>
                    {label}
                  </Tag>
                ))}
              </div>
            </div>
          </div>
        </Card>
      )}
    </section>
  );
}

/**
 * 页脚说明：三条使用须知 + 标准文档链接。
 */
function NatFooterNote({ probeConfig }: { probeConfig: PublicNatProbeConfig | null }) {
  const tips = [
    { title: "这是即时快照", text: "RFC 5780 描述当前路径和当前端口的可观察行为。网关可能随负载、VPN、网络切换或映射超时改变结果。" },
    { title: "浏览器只验证映射轴", text: "WebRTC 不允许页面构造 CHANGE-REQUEST，因此过滤轴不会用超时猜测；原生客户端可完成 EIF / ADF / APDF 分类。" },
    { title: "类型不等于最终路径", text: "ICE 会交换真实候选并执行连通性检查。即使 NAT4 也应尝试直连，同时准备经过认证的 TURN / Relay。" },
  ];

  return (
    <section className="jd-section" aria-labelledby="nat-notes-title">
      <div className="jd-section-head">
        <div className="min-w-0">
          <h2 id="nat-notes-title">使用须知</h2>
          <p>当前接口：{probeConfig?.protocol ?? "RFC8489"} / {probeConfig?.discoveryMethod ?? "BASIC_STUN"}。标准原文和实践说明可用于核对术语边界。</p>
        </div>
        <div className="bd-row">
          <a className="bd-btn bd-btn--ghost bd-btn--sm" href="https://www.rfc-editor.org/rfc/rfc5780" rel="noreferrer" target="_blank">
            <span>RFC 5780</span>
            <Icon name="external" />
          </a>
          <a className="bd-btn bd-btn--ghost bd-btn--sm" href="https://www.rfc-editor.org/rfc/rfc8489" rel="noreferrer" target="_blank">
            <span>RFC 8489</span>
            <Icon name="external" />
          </a>
          <a className="bd-btn bd-btn--ghost bd-btn--sm" href={NAT_TRAVERSAL_REFERENCE.url} rel="noreferrer" target="_blank">
            <span>NAT traversal</span>
            <Icon name="external" />
          </a>
        </div>
      </div>
      <ul className="pub-tips">
        {tips.map((tip) => (
          <li key={tip.title} className="bd-card">
            <b>{tip.title}</b>
            <p>{tip.text}</p>
          </li>
        ))}
      </ul>
    </section>
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
      pc.createDataChannel("specus-nat-check");
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
  const reachable = checks.filter((check) => check.reachable).length;
  return (
    <section className="pub-subsection">
      <div className="pub-subsection-head">
        <div className="min-w-0">
          <h3>RFC 5780 四端点预检</h3>
          <p>A1/A2 是两个公网地址，P1/P2 是两个 UDP 端口。预检只确认端点可达，不跨不同浏览器 socket 比较映射。</p>
        </div>
        <Tag tone={reachable === checks.length ? "success" : "warning"} className="bd-num">
          {reachable}/{checks.length} 可达
        </Tag>
      </div>
      <div className="pub-endpoint-checks">
        {checks.map((check) => (
          <div key={check.endpoint.id} className="pub-endpoint-check">
            <div className="pub-endpoint-check-head">
              <b className="pub-mono">{check.endpoint.id}</b>
              <Tag tone={check.reachable ? "success" : "danger"}>{check.reachable ? "可达" : "不可达"}</Tag>
            </div>
            <code className="pub-mono pub-wrap">{check.endpoint.url}</code>
            <span className="pub-endpoint-check-meta" title={check.mappedEndpoint ?? check.error ?? ""}>
              {check.mappedEndpoint ?? check.error ?? "未返回映射"} · <span className="bd-num">{check.elapsedMs} ms</span>
            </span>
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
