import type {
  PeerEgressDestinationRule,
  PeerEgressPolicy,
  PeerEgressPolicyMutation,
  PeerEgressSwitch,
  PeerMeshDevice,
} from "../../api/types";

// The rules an egress applies, as protocol/spec/peer-egress.md states them. The servers refuse a policy
// whose destination rules the egress could not read (peer-egress-management-v1.json), one problem at a
// time; the page checks first so every problem is listed at once, in words, with the hints a server
// does not give. Policies stored before the servers checked can still hold such rules.

export const MAX_DESTINATION_RULES = 64;
export const MAX_CONSUMERS = 32;
export const MAX_RULES_JSON_BYTES = 4096;
export const MAX_PORT_RANGES = 32;
export const DEFAULT_LIMITS = { maxConcurrentFlows: 256, maxFlowsPerConsumer: 64, idleTimeoutSeconds: 60 };

/** Always refused by the egress, whatever the policy says. */
export const FORCED_DENY: ReadonlyArray<{ cidr: string; label: string }> = [
  { cidr: "0.0.0.0/8", label: "本网络地址" },
  { cidr: "127.0.0.0/8", label: "回环地址" },
  { cidr: "169.254.0.0/16", label: "链路本地地址（含云元数据 169.254.169.254）" },
  { cidr: "224.0.0.0/4", label: "组播地址" },
  { cidr: "240.0.0.0/4", label: "保留地址" },
  { cidr: "255.255.255.255/32", label: "广播地址" },
  { cidr: "100.100.100.200/32", label: "云元数据地址" },
];

/** What scope LAN covers; PUBLIC is every other address the forced-deny list leaves. */
export const LAN_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];

export interface Ipv4Cidr {
  base: number;
  prefix: number;
  text: string;
}

/** A dotted IPv4 address, strictly: four decimal octets, no leading zeros. */
export function parseIpv4(text: string): number | null {
  const parts = text.split(".");
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) {
      return null;
    }
    value = value * 256 + Number(part);
  }
  return value;
}

function formatIpv4(value: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");
}

/** A CIDR as the egress parses it: a bare address is a /32, and host bits must be zero. */
export function parseCidr(input: string): Ipv4Cidr | { error: string } {
  const text = input.trim();
  if (!text) {
    return { error: "请填写目标网段" };
  }
  if (text.includes(":")) {
    return { error: `${text}：目前只支持 IPv4` };
  }
  const [address, prefixText, ...rest] = text.split("/");
  const base = parseIpv4(address);
  if (base == null || rest.length > 0) {
    return { error: `${text}：不是有效的 IPv4 地址或网段` };
  }
  let prefix = 32;
  if (prefixText !== undefined) {
    if (!/^(0|[1-9][0-9]?)$/.test(prefixText) || Number(prefixText) > 32) {
      return { error: `${text}：前缀长度应为 0–32` };
    }
    prefix = Number(prefixText);
  }
  const masked = Math.floor(base / 2 ** (32 - prefix)) * 2 ** (32 - prefix);
  if (masked !== base) {
    return { error: `${text}：主机位不为零，应写作 ${formatIpv4(masked)}/${prefix}` };
  }
  return { base, prefix, text: `${formatIpv4(base)}/${prefix}` };
}

function cidrOf(text: string): Ipv4Cidr {
  const parsed = parseCidr(text);
  if ("error" in parsed) {
    throw new Error(parsed.error);
  }
  return parsed;
}

function span(cidr: Ipv4Cidr): [number, number] {
  return [cidr.base, cidr.base + 2 ** (32 - cidr.prefix) - 1];
}

export function cidrOverlaps(a: Ipv4Cidr, b: Ipv4Cidr): boolean {
  const [aLow, aHigh] = span(a);
  const [bLow, bHigh] = span(b);
  return aLow <= bHigh && bLow <= aHigh;
}

function cidrWithin(inner: Ipv4Cidr, outer: Ipv4Cidr): boolean {
  const [low, high] = span(inner);
  const [outerLow, outerHigh] = span(outer);
  return low >= outerLow && high <= outerHigh;
}

/** Inclusive port ranges from text such as "443, 8000-8100" or "全部". */
export function parsePorts(input: string): number[][] | { error: string } {
  const text = input.trim();
  if (!text) {
    return { error: "请填写端口；所有端口填「全部」" };
  }
  if (["全部", "all", "*", "any"].includes(text.toLowerCase())) {
    return [[1, 65535]];
  }
  const ranges: number[][] = [];
  for (const token of text.split(/[\s,，、]+/).filter(Boolean)) {
    const match = /^([0-9]+)(?:-([0-9]+))?$/.exec(token);
    const low = match ? Number(match[1]) : NaN;
    const high = match ? Number(match[2] ?? match[1]) : NaN;
    if (!match || low < 1 || high > 65535 || low > high) {
      return { error: `端口「${token}」无效：应为 1–65535 的端口或「起-止」范围` };
    }
    ranges.push([low, high]);
  }
  if (ranges.length > MAX_PORT_RANGES) {
    return { error: `端口范围最多 ${MAX_PORT_RANGES} 段` };
  }
  return ranges;
}

export function formatPorts(ranges: number[][] | null | undefined): string {
  const list = ranges ?? [];
  if (list.length === 0) {
    return "无（拒绝所有端口）";
  }
  if (list.some(([low, high]) => low <= 1 && high >= 65535)) {
    return "全部端口";
  }
  return list.map(([low, high]) => (low === high ? String(low) : `${low}-${high}`)).join(", ");
}

/**
 * Why a stored rule never lets anything through, or "" when it can. A policy saved by another tool,
 * or before this page checked, can hold one: the egress compares protocols case-sensitively, reads an
 * empty port list as every port denied, and never matches a CIDR it cannot parse.
 */
export function storedRuleProblem(rule: PeerEgressDestinationRule): string {
  const cidr = parseCidr(rule.cidr ?? "");
  if ("error" in cidr) {
    return "网段无效，不会匹配";
  }
  const protocols = rule.protocols ?? [];
  if (!protocols.some((protocol) => protocol === "tcp" || protocol === "udp")) {
    return "没有可识别的协议（只认小写 tcp/udp），不会匹配";
  }
  if ((rule.portRanges ?? []).length === 0) {
    return "没有端口，所有端口都被拒绝";
  }
  return "";
}

export function scopeLabel(scope: string): string {
  return scope === "LAN" ? "局域网" : scope === "PUBLIC" ? "公网" : scope || "未设置";
}

/**
 * What an admin should know about a destination before saving it: the parts the egress will refuse
 * anyway, and the parts the scope can never let through.
 */
export function destinationNotes(cidrText: string, scope: string, meshCidr: string): string[] {
  const parsed = parseCidr(cidrText);
  if ("error" in parsed) {
    return [];
  }
  const notes: string[] = [];
  const denied = FORCED_DENY.filter((entry) => cidrOverlaps(parsed, cidrOf(entry.cidr))).map((entry) => entry.label);
  const mesh = parseCidr(meshCidr);
  if (!("error" in mesh) && cidrOverlaps(parsed, mesh)) {
    denied.push(`组网网段 ${mesh.text}`);
  }
  if (denied.length > 0) {
    notes.push(`${parsed.text} 包含始终被拒绝的地址：${denied.join("、")}`);
  }
  const lan = LAN_RANGES.map(cidrOf);
  const insideLan = lan.some((range) => cidrWithin(parsed, range));
  const touchesLan = lan.some((range) => cidrOverlaps(parsed, range));
  if (scope === "LAN" && !touchesLan) {
    notes.push(`${parsed.text} 不在局域网范围内，范围为「局域网」时永远不会放行`);
  } else if (scope === "PUBLIC" && insideLan) {
    notes.push(`${parsed.text} 是局域网地址，范围为「公网」时不会放行；访问局域网请把范围设为「局域网」`);
  }
  return notes;
}

export interface EgressRuleDraft {
  cidr: string;
  tcp: boolean;
  udp: boolean;
  ports: string;
}

export interface EgressPolicyDraft {
  egressClientId: string;
  enabled: boolean;
  scope: "PUBLIC" | "LAN";
  consumers: string[];
  rules: EgressRuleDraft[];
  maxConcurrentFlows: string;
  maxFlowsPerConsumer: string;
  idleTimeoutSeconds: string;
}

export function emptyRuleDraft(): EgressRuleDraft {
  return { cidr: "", tcp: true, udp: false, ports: "443" };
}

export function emptyPolicyDraft(): EgressPolicyDraft {
  return {
    egressClientId: "",
    enabled: false,
    scope: "PUBLIC",
    consumers: [],
    rules: [emptyRuleDraft()],
    maxConcurrentFlows: String(DEFAULT_LIMITS.maxConcurrentFlows),
    maxFlowsPerConsumer: String(DEFAULT_LIMITS.maxFlowsPerConsumer),
    idleTimeoutSeconds: String(DEFAULT_LIMITS.idleTimeoutSeconds),
  };
}

export function draftFromPolicy(policy: PeerEgressPolicy): EgressPolicyDraft {
  return {
    egressClientId: String(policy.egressClientId),
    enabled: policy.enabled,
    scope: policy.scope === "LAN" ? "LAN" : "PUBLIC",
    consumers: (policy.allowedConsumerClientIds ?? []).map(String),
    rules: (policy.destinationRules ?? []).map((rule) => ({
      cidr: rule.cidr,
      tcp: (rule.protocols ?? []).includes("tcp"),
      udp: (rule.protocols ?? []).includes("udp"),
      ports: (rule.portRanges ?? []).length === 0 ? "" : formatPorts(rule.portRanges) === "全部端口" ? "全部" : formatPorts(rule.portRanges),
    })),
    maxConcurrentFlows: String(policy.maxConcurrentFlows),
    maxFlowsPerConsumer: String(policy.maxFlowsPerConsumer),
    idleTimeoutSeconds: String(policy.idleTimeoutSeconds),
  };
}

function positive(text: string, label: string, errors: string[]): number {
  const value = Number(text.trim());
  if (!/^[1-9][0-9]*$/.test(text.trim()) || !Number.isSafeInteger(value)) {
    errors.push(`${label}应为正整数`);
    return 0;
  }
  return value;
}

export interface EgressDraftCheck {
  errors: string[];
  warnings: string[];
  mutation: PeerEgressPolicyMutation | null;
}

/**
 * Checks a draft the way the egress will read it and builds the request. Errors keep it from being
 * saved; warnings are saved with the admin's knowledge, because each is a policy that works as
 * written but does less than it looks like it does.
 */
export function checkPolicyDraft(draft: EgressPolicyDraft, meshCidr: string): EgressDraftCheck {
  const errors: string[] = [];
  const warnings: string[] = [];
  const egressClientId = Number(draft.egressClientId);
  if (!draft.egressClientId || !Number.isSafeInteger(egressClientId) || egressClientId <= 0) {
    errors.push("请选择出口设备");
  }
  const consumers = [...new Set(draft.consumers)].map(Number).filter((id) => Number.isSafeInteger(id) && id > 0);
  if (consumers.includes(egressClientId)) {
    errors.push("出口设备不能授权给自己");
  }
  if (consumers.length > MAX_CONSUMERS) {
    errors.push(`授权的消费设备最多 ${MAX_CONSUMERS} 台`);
  }
  if (consumers.length === 0) {
    warnings.push("未授权任何消费设备：出口不会为任何设备转发");
  }
  if (draft.rules.length > MAX_DESTINATION_RULES) {
    errors.push(`目的规则最多 ${MAX_DESTINATION_RULES} 条`);
  }
  const rules: { cidr: string; protocols: string[]; portRanges: number[][] }[] = [];
  draft.rules.forEach((rule, index) => {
    const label = `目的规则 ${index + 1}`;
    const cidr = parseCidr(rule.cidr);
    if ("error" in cidr) {
      errors.push(`${label}：${cidr.error}`);
    }
    const protocols = [rule.tcp ? "tcp" : "", rule.udp ? "udp" : ""].filter(Boolean);
    if (protocols.length === 0) {
      errors.push(`${label}：至少选择一个协议`);
    }
    const ports = parsePorts(rule.ports);
    if ("error" in ports) {
      errors.push(`${label}：${ports.error}`);
    }
    if (!("error" in cidr) && !("error" in ports)) {
      rules.push({ cidr: cidr.text, protocols, portRanges: ports });
      warnings.push(...destinationNotes(cidr.text, draft.scope, meshCidr));
    }
  });
  if (draft.rules.length === 0) {
    warnings.push("没有目的规则：所有目标都会被拒绝");
  }
  if (new TextEncoder().encode(JSON.stringify(rules)).length > MAX_RULES_JSON_BYTES) {
    errors.push(`目的规则合计超过 ${MAX_RULES_JSON_BYTES} 字节，请合并网段或减少端口段`);
  }
  const maxConcurrentFlows = positive(draft.maxConcurrentFlows, "最大并发流", errors);
  const maxFlowsPerConsumer = positive(draft.maxFlowsPerConsumer, "每台消费设备最大流数", errors);
  const idleTimeoutSeconds = positive(draft.idleTimeoutSeconds, "空闲超时", errors);
  if (errors.length > 0) {
    return { errors, warnings, mutation: null };
  }
  return {
    errors,
    warnings,
    mutation: {
      egressClientId,
      enabled: draft.enabled,
      scope: draft.scope,
      allowedConsumerClientIds: consumers,
      destinationRules: rules,
      maxConcurrentFlows,
      maxFlowsPerConsumer,
      idleTimeoutSeconds,
    },
  };
}

export interface EgressPolicyState {
  label: string;
  color: "success" | "warning" | "default" | "danger";
  detail: string;
}

/**
 * Why a listed consumer is not among the effective ones. The server intersects the list with its
 * Peer ACL check, which also needs both devices enabled in the mesh and lets devices of one owner
 * through without a rule; saying "ACL" for a disabled device would send an admin to the wrong page.
 */
export function consumerNote(
  clientId: number,
  policy: PeerEgressPolicy,
  devices: ReadonlyMap<number, Pick<PeerMeshDevice, "enabled">>,
): string {
  if (!policy.enabled || (policy.effectiveConsumerClientIds ?? []).includes(clientId)) {
    return "";
  }
  const device = devices.get(clientId);
  if (!device) {
    return "不在组网设备中";
  }
  if (!device.enabled) {
    return "未启用组网";
  }
  const egress = devices.get(policy.egressClientId);
  if (!egress || !egress.enabled) {
    return "出口设备未启用组网";
  }
  return "Peer ACL 未放行";
}

/** Whether a policy forwards anything now, and if not, the one thing stopping it. */
export function policyState(
  policy: PeerEgressPolicy,
  egressSwitch: PeerEgressSwitch | null,
  devices: ReadonlyMap<number, Pick<PeerMeshDevice, "enabled">> = new Map(),
): EgressPolicyState {
  if (egressSwitch && !egressSwitch.deploymentEnabled) {
    return { label: "部署未启用组网", color: "default", detail: "服务端未启用 Peer Mesh，出口分流不会生效" };
  }
  if (!policy.enabled) {
    return { label: "未启用", color: "default", detail: "策略已保存，启用后才转发" };
  }
  if (egressSwitch && !egressSwitch.configuredEnabled) {
    return { label: "总开关关闭", color: "warning", detail: "策略已启用，但出口分流总开关关闭" };
  }
  const allowed = policy.allowedConsumerClientIds ?? [];
  const effective = policy.effectiveConsumerClientIds ?? [];
  if (allowed.length === 0) {
    return { label: "未授权设备", color: "warning", detail: "没有授权任何消费设备" };
  }
  if (effective.length === 0) {
    const egress = devices.get(policy.egressClientId);
    if (egress && !egress.enabled) {
      return { label: "出口设备未启用组网", color: "warning", detail: "在「设备拓扑」中启用该设备后，授权才会生效" };
    }
    const notes = new Set(allowed.map((id) => consumerNote(id, policy, devices)));
    if (notes.size === 1 && notes.has("未启用组网")) {
      return { label: "消费设备未启用组网", color: "warning", detail: "授权的消费设备都未在「设备拓扑」中启用" };
    }
    return { label: "无设备可用", color: "warning", detail: "授权的消费设备都不能与出口通信：须启用组网，且同属一个用户或有 Peer ACL 放行" };
  }
  if ((policy.destinationRules ?? []).length === 0) {
    return { label: "无目的规则", color: "warning", detail: "没有目的规则，所有目标都会被拒绝" };
  }
  return {
    label: "生效中",
    color: "success",
    detail: effective.length < allowed.length ? `${effective.length}/${allowed.length} 台消费设备经 ACL 放行` : `${effective.length} 台消费设备`,
  };
}

/** The switch's own line: whether it can work at all, and what is on. */
export function switchSummary(egressSwitch: PeerEgressSwitch | null, loading: boolean): string {
  if (loading && !egressSwitch) {
    return "正在读取出口分流状态…";
  }
  if (!egressSwitch) {
    return "出口分流状态未知";
  }
  if (!egressSwitch.deploymentEnabled) {
    return "服务端未启用 Peer Mesh，出口分流不可用";
  }
  if (!egressSwitch.configuredEnabled) {
    return `已关闭：所有出口停止转发${egressSwitch.enabledPolicyCount > 0 ? `（${egressSwitch.enabledPolicyCount} 条已启用策略开启后恢复）` : ""}`;
  }
  return `已开启：${egressSwitch.enabledPolicyCount} 条策略启用中`;
}
