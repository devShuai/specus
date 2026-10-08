import type {
  PeerEgressDestinationRule,
  PeerEgressDomainRule,
  PeerEgressPolicy,
  PeerEgressPolicyMutation,
  PeerEgressSwitch,
  PeerMeshDevice,
} from "../../api/types";

// The rules an egress applies, as protocol/spec/peer-egress.md states them. The servers refuse a policy
// whose destination or domain rules the egress could not read (peer-egress-management-v1.json,
// peer-egress-domain-policy-v1.json), one problem at a time; the page checks first so every problem is
// listed at once, in words, with the hints a server does not give. Policies stored before the servers
// checked can still hold such rules.

export const MAX_DESTINATION_RULES = 64;
export const MAX_DOMAIN_RULES = 64;
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

/** The IPv6 counterparts the egress refuses whatever the policy says (peer-egress-authz-v1.json, ipv6). */
export const FORCED_DENY6: ReadonlyArray<{ cidr: string; label: string }> = [
  { cidr: "::/128", label: "未指定地址" },
  { cidr: "::1/128", label: "回环地址" },
  { cidr: "::ffff:0:0/96", label: "IPv4 映射地址" },
  { cidr: "64:ff9b::/96", label: "NAT64 地址（嵌入 IPv4）" },
  { cidr: "64:ff9b:1::/48", label: "NAT64 本地地址（嵌入 IPv4）" },
  { cidr: "2002::/16", label: "6to4 地址（嵌入 IPv4）" },
  { cidr: "fe80::/10", label: "链路本地地址" },
  { cidr: "fec0::/10", label: "站点本地地址" },
  { cidr: "ff00::/8", label: "组播地址" },
  { cidr: "fd00:ec2::254/128", label: "云元数据地址" },
];

/** What scope LAN covers in IPv6: unique local addresses. */
export const LAN_RANGES6 = ["fc00::/7"];

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

/** An IPv6 prefix as the egress parses it; base is the network as a 128-bit number. */
export interface Ipv6Cidr {
  base: bigint;
  prefix: number;
  text: string;
}

const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;

function hexGroups(part: string): number[] | null {
  if (part === "") {
    return [];
  }
  const groups: number[] = [];
  for (const group of part.split(":")) {
    if (!HEX_GROUP.test(group)) {
      return null;
    }
    groups.push(parseInt(group, 16));
  }
  return groups;
}

/**
 * An IPv6 address the way every implementation reads it (peer-egress.md, IPv6 写法; the ipv6Prefixes
 * section of peer-egress-rules-v1.json): eight groups of one to four hex digits, at most one "::".
 * No dotted IPv4 tail, no zone, no brackets.
 */
export function parseIpv6(text: string): bigint | null {
  if (!text || text.length > 39 || !/^[0-9A-Fa-f:]+$/.test(text)) {
    return null;
  }
  if (text.includes(":::") || text.split("::").length > 2) {
    return null;
  }
  let groups: number[] | null;
  const compressed = text.indexOf("::");
  if (compressed >= 0) {
    const high = hexGroups(text.slice(0, compressed));
    const low = hexGroups(text.slice(compressed + 2));
    if (!high || !low || high.length + low.length > 7) {
      return null;
    }
    groups = [...high, ...new Array<number>(8 - high.length - low.length).fill(0), ...low];
  } else {
    groups = hexGroups(text);
    if (!groups || groups.length !== 8) {
      return null;
    }
  }
  return groups.reduce((value, group) => (value << 16n) | BigInt(group), 0n);
}

/** RFC 5952 form, as the servers store an IPv6 destination: lower case, the longest zero run as "::". */
export function formatIpv6(value: bigint): string {
  const groups = Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(112 - 16 * index)) & 0xffffn));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < 8; ) {
    if (groups[index] !== 0) {
      index++;
      continue;
    }
    let end = index;
    while (end < 8 && groups[end] === 0) {
      end++;
    }
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const hex = (from: number, to: number) => groups.slice(from, to).map((group) => group.toString(16)).join(":");
  return bestLength < 2 ? hex(0, 8) : `${hex(0, bestStart)}::${hex(bestStart + bestLength, 8)}`;
}

/** An IPv6 address or prefix as the egress parses it: a bare address is a /128, host bits must be zero. */
export function parseIpv6Cidr(input: string): Ipv6Cidr | { error: string } {
  const text = input.trim();
  const [address, prefixText, ...rest] = text.split("/");
  const base = parseIpv6(address);
  if (base == null || rest.length > 0) {
    return { error: `${text}：不是有效的 IPv6 地址或网段（只写十六进制，不带区域、方括号或点分 IPv4）` };
  }
  let prefix = 128;
  if (prefixText !== undefined) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(prefixText) || Number(prefixText) > 128) {
      return { error: `${text}：前缀长度应为 0–128` };
    }
    prefix = Number(prefixText);
  }
  const host = (1n << BigInt(128 - prefix)) - 1n;
  if ((base & host) !== 0n) {
    return { error: `${text}：主机位不为零，应写作 ${formatIpv6(base & ~host)}/${prefix}` };
  }
  return { base, prefix, text: `${formatIpv6(base)}/${prefix}` };
}

/** A destination rule's CIDR as the egress parses it: IPv6 when it has a colon, IPv4 otherwise. */
export function parseDestinationCidr(input: string): Ipv4Cidr | Ipv6Cidr | { error: string } {
  const text = input.trim();
  return text.includes(":") ? parseIpv6Cidr(text) : parseCidr(text);
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
  const cidr = parseDestinationCidr(rule.cidr ?? "");
  if ("error" in cidr) {
    return "网段无效，不会匹配";
  }
  return storedGrantProblem(rule);
}

/** The same for a stored domain rule; the egress skips one whose match it cannot read. */
export function storedDomainRuleProblem(rule: PeerEgressDomainRule): string {
  if ("error" in parseDomainMatch(rule.match ?? "")) {
    return "域名写法无效，出口会跳过这条";
  }
  return storedGrantProblem(rule);
}

function storedGrantProblem(rule: Pick<PeerEgressDestinationRule, "protocols" | "portRanges">): string {
  const protocols = rule.protocols ?? [];
  if (!protocols.some((protocol) => protocol === "tcp" || protocol === "udp")) {
    return "没有可识别的协议（只认小写 tcp/udp），不会匹配";
  }
  if ((rule.portRanges ?? []).length === 0) {
    return "没有端口，所有端口都被拒绝";
  }
  return "";
}

const DOMAIN_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * A domain rule's match as the servers store it: trimmed, trailing dots removed, lower case. It is
 * written like the consumer's domain rules (peer-egress-dns.md): "example.com" covers that name only,
 * "*.example.com" covers its subdomains but not the name itself; at least two labels, punycode for an
 * internationalised name. Anything else is refused with the hint a server does not give, an address
 * or CIDR above all, which only a destination rule can grant.
 */
export function parseDomainMatch(input: string): { match: string } | { error: string } {
  const text = input.trim();
  if (!text) {
    return { error: "请填写域名" };
  }
  if (/[^\x00-\x7f]/.test(text)) {
    const ascii = punycodeHint(text);
    return { error: `${text}：含非 ASCII 字符，国际化域名请写成 punycode${ascii ? `，应写作 ${ascii}` : "（xn--…）"}` };
  }
  // The servers read text with neither a leading * nor a letter as an address, never as a name.
  if (!text.startsWith("*") && !/[a-z]/i.test(text)) {
    return { error: `${text}：不是域名，按地址授权请写进目的规则` };
  }
  const match = text.replace(/\.+$/, "").toLowerCase();
  const wildcard = match.startsWith("*.");
  const name = wildcard ? match.slice(2) : match;
  if (match === "*") {
    return { error: "不能单独写 *：通配只能写在两级以上的名字前，如 *.example.com" };
  }
  if (!name || name.includes("*")) {
    return { error: `${text}：* 只能写在开头，形如 *.example.com` };
  }
  if (name.length > 253) {
    return { error: `${text}：域名超过 253 个字符` };
  }
  // Neither character is allowed in a label; these two only make the refusal say why.
  if (name.includes("/")) {
    return { error: `${text}：只填域名，不带协议或路径` };
  }
  if (name.includes(":")) {
    return {
      error: /^[^:]+:[0-9]*$/.test(name) ? `${text}：不能带端口，端口填在右侧` : `${text}：不是域名，按地址授权请写进目的规则`,
    };
  }
  const labels = name.split(".");
  if (labels.length < 2) {
    return {
      error: wildcard
        ? `${text}：只有一级的后缀不能通配，至少写到两级，如 *.example.com`
        : `${text}：单标签名字不能授权，至少写到两级，如 example.com`,
    };
  }
  if (labels.every((label) => /^[0-9]+$/.test(label))) {
    return { error: `${text}：不是域名，按地址授权请写进目的规则` };
  }
  const bad = labels.find((label) => !DOMAIN_LABEL.test(label));
  if (bad !== undefined) {
    return {
      error: bad
        ? `${text}：「${bad}」无效，每一级只能用字母、数字与连字符，不以连字符开头或结尾，最长 63 个字符`
        : `${text}：有空的一级（连续的点）`,
    };
  }
  return { match };
}

/** The punycode spelling of a name typed in Unicode, when the browser can produce a valid one. */
function punycodeHint(text: string): string {
  const wildcard = text.startsWith("*.");
  try {
    const host = new URL(`http://${wildcard ? text.slice(2) : text}/`).hostname;
    const candidate = `${wildcard ? "*." : ""}${host}`;
    return "match" in parseDomainMatch(candidate) ? candidate : "";
  } catch {
    return "";
  }
}

export interface DomainRuleInput {
  match?: unknown;
  protocols?: readonly unknown[] | null;
  portRanges?: readonly unknown[] | null;
}

export type StoredDomainRule = NonNullable<PeerEgressPolicyMutation["domainRules"]>[number];

/**
 * Domain rules as a server stores them, or every reason it answers 400 instead (the management half
 * of peer-egress-domain-policy-v1.json). Protocols are trimmed, lower-cased and de-duplicated in order
 * and port ranges are [low, high] within 0-65535, as for destination rules; an absent list is stored
 * empty. The count and the stored size are limited apart from the destination rules.
 */
export function normalizeDomainRules(rules: ReadonlyArray<DomainRuleInput>): { stored: StoredDomainRule[]; errors: string[] } {
  const errors: string[] = [];
  if (rules.length > MAX_DOMAIN_RULES) {
    errors.push(`域名规则最多 ${MAX_DOMAIN_RULES} 条`);
  }
  const stored: StoredDomainRule[] = [];
  rules.forEach((rule, index) => {
    const label = `域名规则 ${index + 1}`;
    const problems: string[] = [];
    const match = typeof rule.match === "string" ? parseDomainMatch(rule.match) : { error: "请填写域名" };
    if ("error" in match) {
      problems.push(match.error);
    }
    const protocols: string[] = [];
    for (const protocol of rule.protocols ?? []) {
      const value = String(protocol).trim().toLowerCase();
      if (value !== "tcp" && value !== "udp") {
        problems.push(`协议「${String(protocol)}」无效，只能是 tcp 或 udp`);
      } else if (!protocols.includes(value)) {
        protocols.push(value);
      }
    }
    const portRanges: number[][] = [];
    for (const pair of rule.portRanges ?? []) {
      if (!Array.isArray(pair) || pair.length !== 2 || !pair.every((port) => Number.isInteger(port))) {
        problems.push("端口范围应为 [起, 止] 两个整数");
      } else if (pair[0] < 0 || pair[1] > 65535 || pair[0] > pair[1]) {
        problems.push(`端口范围 ${pair[0]}-${pair[1]} 无效：应为 0–65535，起不大于止`);
      } else {
        portRanges.push([pair[0], pair[1]]);
      }
    }
    if ((rule.portRanges ?? []).length > MAX_PORT_RANGES) {
      problems.push(`端口范围最多 ${MAX_PORT_RANGES} 段`);
    }
    errors.push(...problems.map((problem) => `${label}：${problem}`));
    if (problems.length === 0 && "match" in match) {
      stored.push({ match: match.match, protocols, portRanges });
    }
  });
  if (jsonBytes(stored) > MAX_RULES_JSON_BYTES) {
    errors.push(`域名规则合计超过 ${MAX_RULES_JSON_BYTES} 字节，请合并规则或减少端口段`);
  }
  return { stored, errors };
}

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).length;
}

export function scopeLabel(scope: string): string {
  return scope === "LAN" ? "局域网" : scope === "PUBLIC" ? "公网" : scope || "未设置";
}

/**
 * What an admin should know about a destination before saving it: the parts the egress will refuse
 * anyway, and the parts the scope can never let through.
 */
export function destinationNotes(cidrText: string, scope: string, meshCidr: string): string[] {
  if (cidrText.includes(":")) {
    return ipv6DestinationNotes(cidrText, scope);
  }
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

function span6(cidr: Ipv6Cidr): [bigint, bigint] {
  return [cidr.base, cidr.base + (1n << BigInt(128 - cidr.prefix)) - 1n];
}

function cidr6Of(text: string): Ipv6Cidr {
  const parsed = parseIpv6Cidr(text);
  if ("error" in parsed) {
    throw new Error(parsed.error);
  }
  return parsed;
}

/** destinationNotes for an IPv6 destination: the IPv6 forced-deny list and the unique local range. */
function ipv6DestinationNotes(cidrText: string, scope: string): string[] {
  const parsed = parseIpv6Cidr(cidrText);
  if ("error" in parsed) {
    return [];
  }
  const [low, high] = span6(parsed);
  const overlaps = (other: Ipv6Cidr) => {
    const [otherLow, otherHigh] = span6(other);
    return low <= otherHigh && otherLow <= high;
  };
  const notes: string[] = [];
  const denied = FORCED_DENY6.filter((entry) => overlaps(cidr6Of(entry.cidr))).map((entry) => entry.label);
  if (denied.length > 0) {
    notes.push(`${parsed.text} 包含始终被拒绝的地址：${denied.join("、")}`);
  }
  const lan = LAN_RANGES6.map(cidr6Of);
  const insideLan = lan.some((range) => {
    const [rangeLow, rangeHigh] = span6(range);
    return low >= rangeLow && high <= rangeHigh;
  });
  const touchesLan = lan.some(overlaps);
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

export interface EgressDomainRuleDraft {
  match: string;
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
  domainRules: EgressDomainRuleDraft[];
  maxConcurrentFlows: string;
  maxFlowsPerConsumer: string;
  idleTimeoutSeconds: string;
}

export function emptyRuleDraft(): EgressRuleDraft {
  return { cidr: "", tcp: true, udp: false, ports: "443" };
}

export function emptyDomainRuleDraft(): EgressDomainRuleDraft {
  return { match: "", tcp: true, udp: false, ports: "443" };
}

export function emptyPolicyDraft(): EgressPolicyDraft {
  return {
    egressClientId: "",
    enabled: false,
    scope: "PUBLIC",
    consumers: [],
    rules: [emptyRuleDraft()],
    domainRules: [],
    maxConcurrentFlows: String(DEFAULT_LIMITS.maxConcurrentFlows),
    maxFlowsPerConsumer: String(DEFAULT_LIMITS.maxFlowsPerConsumer),
    idleTimeoutSeconds: String(DEFAULT_LIMITS.idleTimeoutSeconds),
  };
}

/** A stored rule's protocols and ports as the editor's checkboxes and port text. */
function grantDraft(rule: Pick<PeerEgressDestinationRule, "protocols" | "portRanges">): Omit<EgressRuleDraft, "cidr"> {
  const ports = formatPorts(rule.portRanges);
  return {
    tcp: (rule.protocols ?? []).includes("tcp"),
    udp: (rule.protocols ?? []).includes("udp"),
    ports: (rule.portRanges ?? []).length === 0 ? "" : ports === "全部端口" ? "全部" : ports,
  };
}

export function draftFromPolicy(policy: PeerEgressPolicy): EgressPolicyDraft {
  return {
    egressClientId: String(policy.egressClientId),
    enabled: policy.enabled,
    scope: policy.scope === "LAN" ? "LAN" : "PUBLIC",
    consumers: (policy.allowedConsumerClientIds ?? []).map(String),
    rules: (policy.destinationRules ?? []).map((rule) => ({ cidr: rule.cidr, ...grantDraft(rule) })),
    domainRules: (policy.domainRules ?? []).map((rule) => ({ match: rule.match, ...grantDraft(rule) })),
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
    const cidr = parseDestinationCidr(rule.cidr);
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
    warnings.push(draft.domainRules.length === 0
      ? "没有目的规则：所有目标都会被拒绝"
      : "没有目的规则：只按地址发出的流都会被拒绝，只有消费端按域名发出的流可能经域名规则放行");
  }
  if (jsonBytes(rules) > MAX_RULES_JSON_BYTES) {
    errors.push(`目的规则合计超过 ${MAX_RULES_JSON_BYTES} 字节，请合并网段或减少端口段`);
  }
  // The editor also refuses a rule without protocols or ports, which a server would store but which
  // grants nothing; the rules it lets through then go through the servers' own normalisation.
  const domainInputs: DomainRuleInput[] = [];
  draft.domainRules.forEach((rule, index) => {
    const label = `域名规则 ${index + 1}`;
    const match = parseDomainMatch(rule.match);
    if ("error" in match) {
      errors.push(`${label}：${match.error}`);
    }
    const protocols = [rule.tcp ? "tcp" : "", rule.udp ? "udp" : ""].filter(Boolean);
    if (protocols.length === 0) {
      errors.push(`${label}：至少选择一个协议`);
    }
    const ports = parsePorts(rule.ports);
    if ("error" in ports) {
      errors.push(`${label}：${ports.error}`);
    }
    if (!("error" in match) && protocols.length > 0 && !("error" in ports)) {
      domainInputs.push({ match: rule.match, protocols, portRanges: ports });
    }
  });
  const domainRules = normalizeDomainRules(domainInputs);
  errors.push(...domainRules.errors);
  if (draft.domainRules.length > 0 && draft.scope === "LAN") {
    warnings.push("范围为「局域网」：域名规则只放行解析到局域网地址的名字，解析到公网地址的仍被拒绝");
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
      domainRules: domainRules.stored,
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
  // Domain rules grant only flows sent by name, so a policy with nothing else still forwards those.
  const domainOnly = (policy.destinationRules ?? []).length === 0;
  if (domainOnly && (policy.domainRules ?? []).length === 0) {
    return { label: "无目的规则", color: "warning", detail: "没有目的规则，所有目标都会被拒绝" };
  }
  const consumers = effective.length < allowed.length ? `${effective.length}/${allowed.length} 台消费设备经 ACL 放行` : `${effective.length} 台消费设备`;
  return {
    label: "生效中",
    color: "success",
    detail: domainOnly ? `${consumers}；只有域名规则，只放行按域名发出的流` : consumers,
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
