export type NatReachability = "direct" | "likely" | "conditional" | "relay" | "unknown";

export type NatTone = "default" | "primary" | "success" | "warning" | "danger";

export interface NatTypeProfile {
  key: string;
  label: string;
  shortLabel: string;
  tone: NatTone;
  reachability: NatReachability;
  reachabilityLabel: string;
  summary: string;
  detection: string;
  recommendation: string;
}

const NAT_BEHAVIOR_LABELS: Record<string, string> = {
  ENDPOINT_INDEPENDENT: "端点无关",
  ADDRESS_DEPENDENT: "地址相关",
  ADDRESS_AND_PORT_DEPENDENT: "地址和端口相关",
  TARGET_DEPENDENT: "目标相关",
  UNKNOWN: "未知",
  UNSUPPORTED: "服务不支持",
};

const NAT_MAPPING_BEHAVIOR_LABELS: Record<string, string> = {
  ENDPOINT_INDEPENDENT: "端点无关映射（EIM）",
  ADDRESS_DEPENDENT: "地址相关映射（ADM）",
  ADDRESS_AND_PORT_DEPENDENT: "地址和端口相关映射（APDM）",
  TARGET_DEPENDENT: "目标相关映射",
  UNKNOWN: "映射未知",
  UNSUPPORTED: "映射检测不支持",
};

const NAT_FILTERING_BEHAVIOR_LABELS: Record<string, string> = {
  ENDPOINT_INDEPENDENT: "端点无关过滤（EIF）",
  ADDRESS_DEPENDENT: "地址相关过滤（ADF）",
  ADDRESS_AND_PORT_DEPENDENT: "地址和端口相关过滤（APDF）",
  UNKNOWN: "过滤未知",
  UNSUPPORTED: "过滤检测不支持",
};

const NAT_DISCOVERY_LABELS: Record<string, string> = {
  RFC5780: "RFC 5780",
  BASIC: "基础 STUN",
  BASIC_STUN: "基础 STUN",
};

export const NAT_TRAVERSAL_REFERENCE = {
  title: "How NAT traversal works",
  author: "Tailscale",
  url: "https://tailscale.com/blog/how-nat-traversal-works",
  notes: [
    {
      title: "NAT 不只是防火墙",
      text: "NAT 可以理解为带状态防火墙再加上地址和端口改写。客户端从内网发出的 UDP 包，会被网关改写成一个公网 IP:Port；外部只能看到这个映射端点。",
    },
    {
      title: "STUN 负责发现公网端点",
      text: "客户端用将要承载业务流量的同一个 UDP socket 去问 STUN 服务端：从你那里看，我的公网 IP:Port 是什么。这个结果再通过控制面同步给 peer。",
    },
    {
      title: "关键差异是映射是否依赖目标",
      text: "RFC 5780 将 NAT 拆成映射和过滤两个独立轴。EIM、ADM、APDM 描述公网映射是否随目标变化；EIF、ADF、APDF 描述允许哪些来源回包，比 Full Cone、Restricted Cone 等旧名更精确。",
    },
    {
      title: "ICE 的策略是并行尝试",
      text: "不要提前赌某条路径一定可用。收集 LAN、STUN 公网映射、端口映射和 relay 等候选地址，经由控制面交换后同时探测，选出实际可达且质量最好的路径。",
    },
    {
      title: "Relay 是必要兜底",
      text: "遇到 ADM/APDM、APDF、严格防火墙或 UDP 出站受限时，直连可能不可用。Relay 延迟通常高一点，但它能把“连不上”变成“可用”，再由后台继续寻找更优路径。",
    },
  ],
};

export const NAT_BEHAVIOR_AXES = [
  {
    key: "mapping",
    title: "映射行为",
    subtitle: "目标变化时，公网 IP:Port 是否复用",
    items: [
      {
        behavior: "ENDPOINT_INDEPENDENT",
        code: "EIM",
        label: "端点无关映射",
        detail: "不同目标复用同一公网映射，最利于打洞。",
      },
      {
        behavior: "ADDRESS_DEPENDENT",
        code: "ADM",
        label: "地址相关映射",
        detail: "目标 IP 变化会产生新映射，STUN 端点难直接复用于 peer。",
      },
      {
        behavior: "ADDRESS_AND_PORT_DEPENDENT",
        code: "APDM",
        label: "地址和端口相关映射",
        detail: "目标 IP 或端口变化都会产生新映射，通常优先 Relay。",
      },
    ],
  },
  {
    key: "filtering",
    title: "过滤行为",
    subtitle: "哪些外部来源可以向既有映射回包",
    items: [
      {
        behavior: "ENDPOINT_INDEPENDENT",
        code: "EIF",
        label: "端点无关过滤",
        detail: "任意外部端点均可回包。",
      },
      {
        behavior: "ADDRESS_DEPENDENT",
        code: "ADF",
        label: "地址相关过滤",
        detail: "仅客户端联系过的外部 IP 可以回包。",
      },
      {
        behavior: "ADDRESS_AND_PORT_DEPENDENT",
        code: "APDF",
        label: "地址和端口相关过滤",
        detail: "仅客户端联系过的准确 IP:Port 可以回包。",
      },
    ],
  },
] as const;

export const UNKNOWN_NAT_PROFILE: NatTypeProfile = {
  key: "UNKNOWN",
  label: "NAT 未知",
  shortLabel: "未知",
  tone: "default",
  reachability: "unknown",
  reachabilityLabel: "等待检测",
  summary: "客户端还没有上报完整 NAT 探测结果，或服务端 UDP 探测端口不可达。",
  detection: "没有可用的 mapped endpoint，页面只能展示未知状态。",
  recommendation: "确认客户端在线、已启用私有组网，并放行独立 STUN 的 A1/A2、P1/P2 四端点。",
};

export const NAT_TYPE_PROFILES: Record<string, NatTypeProfile> = {
  NO_NAT: {
    key: "NO_NAT",
    label: "无 NAT",
    shortLabel: "无 NAT",
    tone: "success",
    reachability: "direct",
    reachabilityLabel: "直连友好",
    summary: "客户端公网地址和本机地址一致，通常可以直接被对端 UDP 访问。",
    detection: "服务端看到的 mapped endpoint 与客户端本地 UDP 地址一致。",
    recommendation: "优先走 direct；如果仍失败，重点检查本机防火墙和运营商入站 UDP 策略。",
  },
  PORT_PRESERVED_NAT: {
    key: "PORT_PRESERVED_NAT",
    label: "端口保持（基础判断）",
    shortLabel: "端口保持 / 基础",
    tone: "primary",
    reachability: "likely",
    reachabilityLabel: "直连较友好",
    summary: "NAT 会保留客户端源端口，打洞成功率通常较高。",
    detection: "基础 STUN 看到公网映射端口与客户端本地 UDP 端口一致，但尚未完成 RFC 5780 双轴分类。",
    recommendation: "可以优先尝试 direct，同时继续完成 RFC 5780 探测并保留 relay。",
  },
  FULL_CONE_OR_RESTRICTED_NAT: {
    key: "FULL_CONE_OR_RESTRICTED_NAT",
    label: "EIM + EIF/ADF（兼容）",
    shortLabel: "EIM / EIF-ADF",
    tone: "primary",
    reachability: "likely",
    reachabilityLabel: "直连较友好",
    summary: "兼容标签：映射端点稳定，过滤行为为 EIF 或 ADF；应优先查看独立的 mapping/filtering 字段。",
    detection: "原生客户端完成 RFC 5780 后，为旧版本服务端和界面保留的兼容 natType。",
    recommendation: "优先尝试 direct，并以实际 ICE 连通性决定是否切换 relay。",
  },
  CONE_LIKE_NAT: {
    key: "CONE_LIKE_NAT",
    label: "EIM（浏览器兼容）",
    shortLabel: "EIM / 浏览器",
    tone: "primary",
    reachability: "likely",
    reachabilityLabel: "直连较友好",
    summary: "同一 UDP 基址访问不同 STUN 目标时公网映射保持一致，但端口已被改写；过滤行为仍需单独验证。",
    detection: "浏览器侧观测：同一个 ICE socket 访问 A1/A2、P1/P2 四端点时，server-reflexive 映射不随目标变化。",
    recommendation: "映射侧通常利于 direct 打洞；仍需通过 ICE 连通性检查，并在严格过滤时自动回退 relay。",
  },
  PORT_RESTRICTED_NAT: {
    key: "PORT_RESTRICTED_NAT",
    label: "EIM + APDF（兼容）",
    shortLabel: "EIM / APDF",
    tone: "warning",
    reachability: "conditional",
    reachabilityLabel: "直连受限",
    summary: "兼容标签：映射为 EIM，但过滤为 APDF，只有已经向特定 IP:Port 发包后才允许其回包。",
    detection: "RFC 5780 映射测试稳定，而 CHANGE-REQUEST 的变更地址和变更端口响应均不可达。",
    recommendation: "双方应并行发起打洞；未快速建立 direct 时立即使用 relay。",
  },
  SYMMETRIC_NAT: {
    key: "SYMMETRIC_NAT",
    label: "ADM/APDM（兼容）",
    shortLabel: "ADM/APDM",
    tone: "danger",
    reachability: "relay",
    reachabilityLabel: "建议 Relay",
    summary: "兼容标签：同一 UDP 基址访问不同目标地址或端口时产生不同公网映射，具体应查看 ADM 或 APDM。",
    detection: "A1/A2、P1/P2 四端点看到的 mapped endpoint 随目标 IP 或端口变化。",
    recommendation: "并行尝试 direct candidate，同时快速准备 TURN / Relay；以 ICE 实际连通性结果选择路径。",
  },
  NAT: {
    key: "NAT",
    label: "NAT（基础 STUN）",
    shortLabel: "NAT / 基础",
    tone: "default",
    reachability: "unknown",
    reachabilityLabel: "保守未知",
    summary: "已确认客户端在 NAT 后，但当前观测不足以稳定细分类型。",
    detection: "只有基础 binding 结果，缺少辅助端口或变更端口观测。",
    recommendation: "放行辅助 UDP 端口后重新观察；业务路径保守使用快速 direct + relay fallback。",
  },
};

export function natTypeProfile(natType?: string | null): NatTypeProfile {
  if (!natType) {
    return UNKNOWN_NAT_PROFILE;
  }
  return NAT_TYPE_PROFILES[natType] ?? {
    ...UNKNOWN_NAT_PROFILE,
    key: natType,
    label: natType,
    shortLabel: natType,
    summary: "客户端上报了当前前端尚未内置说明的 NAT 类型。",
  };
}

export function natClassificationProfile(
  natType?: string | null,
  mappingBehavior?: string | null,
  filteringBehavior?: string | null,
): NatTypeProfile {
  const compatibility = natTypeProfile(natType);
  if (compatibility.key === "NO_NAT") {
    return compatibility;
  }

  const mapping = normalizeNatBehavior(mappingBehavior);
  const filtering = normalizeNatBehavior(filteringBehavior);
  if (!["ENDPOINT_INDEPENDENT", "ADDRESS_DEPENDENT", "ADDRESS_AND_PORT_DEPENDENT"].includes(mapping)) {
    return compatibility;
  }

  if (mapping === "ENDPOINT_INDEPENDENT") {
    if (filtering === "ENDPOINT_INDEPENDENT") {
      return behaviorProfile(
        "EIM_EIF",
        "EIM + EIF",
        "EIM / EIF",
        "success",
        "direct",
        "直连友好",
        "公网映射不随目标变化，并允许任意外部端点向该映射回包。",
        "RFC 5780：A1/A2、P1/P2 映射一致，CHANGE-REQUEST 变更地址和端口响应成功。",
        "优先使用 direct；失败时重点检查主机防火墙，并保留 relay 兜底。",
      );
    }
    if (filtering === "ADDRESS_DEPENDENT") {
      return behaviorProfile(
        "EIM_ADF",
        "EIM + ADF",
        "EIM / ADF",
        "primary",
        "likely",
        "直连较友好",
        "公网映射稳定，但只有客户端已联系过的外部 IP 可以回包。",
        "RFC 5780：映射四端点一致；变更 IP+端口超时，单独变更端口响应成功。",
        "双方并行发起 direct 探测；未建立路径时自动切换 relay。",
      );
    }
    if (filtering === "ADDRESS_AND_PORT_DEPENDENT") {
      return behaviorProfile(
        "EIM_APDF",
        "EIM + APDF",
        "EIM / APDF",
        "warning",
        "conditional",
        "直连受限",
        "公网映射稳定，但必须先向特定外部 IP:Port 发包才允许其回包。",
        "RFC 5780：映射四端点一致；两次 CHANGE-REQUEST 均超时，且普通 A2 端点验证成功。",
        "双方必须并行打洞；短时间内未连通就使用 relay。",
      );
    }
    return behaviorProfile(
      "EIM_FILTER_UNKNOWN",
      "EIM + 过滤待定",
      "EIM / 过滤待定",
      "primary",
      "conditional",
      "需要连通性验证",
      "已确认公网映射不依赖目标，但浏览器限制、服务能力或端点异常使过滤行为无法确认。",
      "映射测试完整，过滤字段为 UNKNOWN、UNSUPPORTED 或尚未上报。",
      "先并行尝试 direct，并始终保留 relay。",
    );
  }

  const mappingCode = mapping === "ADDRESS_DEPENDENT" ? "ADM" : "APDM";
  const filteringCode = natFilteringBehaviorCode(filtering);
  return behaviorProfile(
    `${mappingCode}_${filteringCode || "UNKNOWN"}`,
    `${mappingCode}${filteringCode ? ` + ${filteringCode}` : " + 过滤待定"}`,
    `${mappingCode}${filteringCode ? ` / ${filteringCode}` : " / ?"}`,
    "danger",
    "relay",
    "Relay 优先",
    mapping === "ADDRESS_DEPENDENT"
      ? "公网映射随目标 IP 变化，STUN 看到的端点通常不能直接复用于任意 peer。"
      : "公网映射同时随目标 IP 和端口变化，直连端点最难预测。",
    `RFC 5780 四端点映射比较得到 ${mappingCode}；过滤行为独立记录为 ${filteringCode || "未确认"}。`,
    "并行尝试 direct candidate，同时预建 TURN/Relay，避免等待直连超时后才开始回退。",
  );
}

function behaviorProfile(
  key: string,
  label: string,
  shortLabel: string,
  tone: NatTone,
  reachability: NatReachability,
  reachabilityLabel: string,
  summary: string,
  detection: string,
  recommendation: string,
): NatTypeProfile {
  return { key, label, shortLabel, tone, reachability, reachabilityLabel, summary, detection, recommendation };
}

function normalizeNatBehavior(value?: string | null): string {
  return value?.trim().toUpperCase() ?? "";
}

function natFilteringBehaviorCode(value?: string | null): string {
  switch (normalizeNatBehavior(value)) {
    case "ENDPOINT_INDEPENDENT":
      return "EIF";
    case "ADDRESS_DEPENDENT":
      return "ADF";
    case "ADDRESS_AND_PORT_DEPENDENT":
      return "APDF";
    default:
      return "";
  }
}

export function natTypeLabel(natType?: string | null): string {
  return natTypeProfile(natType).label;
}

export function natTypeColor(natType?: string | null): NatTone {
  return natTypeProfile(natType).tone;
}

export function natReachabilityWeight(natType?: string | null): number {
  const reachability = natTypeProfile(natType).reachability;
  switch (reachability) {
    case "direct":
      return 4;
    case "likely":
      return 3;
    case "conditional":
      return 2;
    case "relay":
      return 1;
    default:
      return 0;
  }
}

export function natBehaviorLabel(behavior?: string | null): string {
  if (!behavior) {
    return "未检测";
  }
  return NAT_BEHAVIOR_LABELS[behavior] ?? behavior;
}

export function natMappingBehaviorLabel(behavior?: string | null): string {
  if (!behavior) {
    return "未检测";
  }
  const normalized = normalizeNatBehavior(behavior);
  return NAT_MAPPING_BEHAVIOR_LABELS[normalized] ?? behavior;
}

export function natFilteringBehaviorLabel(behavior?: string | null): string {
  if (!behavior) {
    return "未检测";
  }
  const normalized = normalizeNatBehavior(behavior);
  return NAT_FILTERING_BEHAVIOR_LABELS[normalized] ?? behavior;
}

export function natBehaviorDiscoveryLabel(discovery?: string | null): string {
  if (!discovery) {
    return "未上报";
  }
  return NAT_DISCOVERY_LABELS[discovery] ?? discovery;
}
