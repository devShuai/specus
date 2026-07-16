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
  UNKNOWN: "未知",
  UNSUPPORTED: "服务不支持",
};

const NAT_DISCOVERY_LABELS: Record<string, string> = {
  RFC5780: "RFC 5780",
  BASIC: "基础 STUN",
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
      text: "现代实现里，比起 Full Cone、Restricted Cone 这些旧名，更重要的是 NAT mapping 是否随目标变化。Endpoint-Independent Mapping 较容易打洞；Endpoint-Dependent Mapping 也就是常说的 Symmetric NAT，更容易让直连失败。",
    },
    {
      title: "ICE 的策略是并行尝试",
      text: "不要提前赌某条路径一定可用。收集 LAN、STUN 公网映射、端口映射和 relay 等候选地址，经由控制面交换后同时探测，选出实际可达且质量最好的路径。",
    },
    {
      title: "Relay 是必要兜底",
      text: "遇到 Symmetric NAT、严格防火墙或 UDP 出站受限时，直连可能不可用。Relay 延迟通常高一点，但它能把“连不上”变成“可用”，再由后台继续寻找更优路径。",
    },
  ],
};

export const UNKNOWN_NAT_PROFILE: NatTypeProfile = {
  key: "UNKNOWN",
  label: "NAT 未知",
  shortLabel: "未知",
  tone: "default",
  reachability: "unknown",
  reachabilityLabel: "等待检测",
  summary: "客户端还没有上报完整 NAT 探测结果，或服务端 UDP 探测端口不可达。",
  detection: "没有可用的 mapped endpoint，页面只能展示未知状态。",
  recommendation: "确认客户端在线、已启用私有组网，并放行标准 STUN/TURN 子集 UDP 主端口和辅助探测端口。",
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
    label: "端口保持 NAT",
    shortLabel: "端口保持",
    tone: "primary",
    reachability: "likely",
    reachabilityLabel: "直连较友好",
    summary: "NAT 会保留客户端源端口，打洞成功率通常较高。",
    detection: "服务端看到公网映射端口与客户端本地 UDP 端口一致，但仍处于 NAT 后。",
    recommendation: "优先尝试 direct；如果对端是 Symmetric NAT，仍应自动回退 relay。",
  },
  FULL_CONE_OR_RESTRICTED_NAT: {
    key: "FULL_CONE_OR_RESTRICTED_NAT",
    label: "Full cone / Restricted NAT",
    shortLabel: "Cone/Restricted",
    tone: "success",
    reachability: "direct",
    reachabilityLabel: "直连友好",
    summary: "公网映射稳定，且服务端辅助端口探测表现较好，通常适合 UDP 打洞。",
    detection: "主端口和辅助端口看到的 mapped endpoint 稳定，辅助探测有响应。",
    recommendation: "优先走 direct；只有网络策略阻断时才需要 relay。",
  },
  CONE_LIKE_NAT: {
    key: "CONE_LIKE_NAT",
    label: "锥形 NAT（cone-like）",
    shortLabel: "Cone-like",
    tone: "primary",
    reachability: "likely",
    reachabilityLabel: "直连较友好",
    summary: "多个 STUN 看到的公网端点一致，但端口被改写。可能是 Full Cone / Restricted / Port Restricted，浏览器不能再细分。",
    detection: "浏览器侧观测：同一本机 socket 给多个 STUN，看到相同的 server-reflexive 端点。",
    recommendation: "通常可以 direct 打洞，失败时由 Peer Mesh 自动回退 relay。",
  },
  PORT_RESTRICTED_NAT: {
    key: "PORT_RESTRICTED_NAT",
    label: "Port Restricted NAT",
    shortLabel: "Port Restricted",
    tone: "warning",
    reachability: "conditional",
    reachabilityLabel: "直连受限",
    summary: "公网映射端点相对稳定，但入站 UDP 往往要求先向目标 IP:Port 发过包。",
    detection: "主端口映射稳定，但辅助端口主动回包不可达或不足以确认 Full cone。",
    recommendation: "仍会尝试 direct candidate；若对端映射不可达，应自动回退 relay。",
  },
  SYMMETRIC_NAT: {
    key: "SYMMETRIC_NAT",
    label: "Symmetric NAT",
    shortLabel: "Symmetric",
    tone: "danger",
    reachability: "relay",
    reachabilityLabel: "建议 Relay",
    summary: "不同目标会产生不同公网映射，直连探测容易出现 RTT 假阳性，业务流不稳定。",
    detection: "主端口和辅助端口看到的 mapped endpoint 不一致。",
    recommendation: "默认不要选 direct path，应使用 server relay，避免 HTTP/TCP 访问时断流。",
  },
  NAT: {
    key: "NAT",
    label: "NAT",
    shortLabel: "NAT",
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

export function natBehaviorDiscoveryLabel(discovery?: string | null): string {
  if (!discovery) {
    return "未上报";
  }
  return NAT_DISCOVERY_LABELS[discovery] ?? discovery;
}
