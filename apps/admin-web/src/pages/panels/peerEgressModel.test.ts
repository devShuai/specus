import { describe, expect, it } from "vitest";
import vectors from "../../../../../protocol/test-vectors/peer-egress-domain-policy-v1.json";
import rulesVector from "../../../../../protocol/test-vectors/peer-egress-rules-v1.json";
import type { PeerEgressPolicy, PeerEgressSwitch } from "../../api/types";
import {
  checkPolicyDraft,
  consumerNote,
  destinationNotes,
  type DomainRuleInput,
  draftFromPolicy,
  emptyDomainRuleDraft,
  emptyPolicyDraft,
  formatIpv6,
  formatPorts,
  MAX_DOMAIN_RULES,
  MAX_PORT_RANGES,
  MAX_RULES_JSON_BYTES,
  normalizeDomainRules,
  parseCidr,
  parseDestinationCidr,
  parseDomainMatch,
  parseIpv6,
  parseIpv6Cidr,
  parsePorts,
  policyState,
  storedDomainRuleProblem,
  storedRuleProblem,
  switchSummary,
} from "./peerEgressModel";

const mesh = "100.96.0.0/11";

describe("parseCidr", () => {
  it("reads a CIDR the way the egress does", () => {
    expect(parseCidr("203.0.113.0/24")).toMatchObject({ text: "203.0.113.0/24", prefix: 24 });
    expect(parseCidr(" 203.0.113.7 ")).toMatchObject({ text: "203.0.113.7/32" });
    expect(parseCidr("0.0.0.0/0")).toMatchObject({ text: "0.0.0.0/0" });
  });

  it("refuses what the egress would store and never match", () => {
    expect(parseCidr("203.0.113.1/24")).toEqual({ error: "203.0.113.1/24：主机位不为零，应写作 203.0.113.0/24" });
    expect(parseCidr("203.0.113.01")).toHaveProperty("error");
    expect(parseCidr("256.0.0.0/8")).toHaveProperty("error");
    expect(parseCidr("10.0.0.0/33")).toHaveProperty("error");
    expect(parseCidr("2001:db8::/32")).toEqual({ error: "2001:db8::/32：目前只支持 IPv4" });
    expect(parseCidr("example.com")).toHaveProperty("error");
    expect(parseCidr("")).toEqual({ error: "请填写目标网段" });
  });
});

describe("IPv6 destinations", () => {
  // The spelling every implementation reads, from the ipv6Prefixes section of the rules vector.
  it("reads and refuses the spellings the shared vector pins", () => {
    for (const { text, address, prefixLength } of rulesVector.ipv6Prefixes.accept) {
      const parsed = parseDestinationCidr(text);
      expect(parsed, text).toEqual(expect.objectContaining({ prefix: prefixLength, text: `${address}/${prefixLength}` }));
      expect(parseIpv6(address), address).toBe((parsed as { base: bigint }).base);
      expect(formatIpv6(parseIpv6(address) ?? -1n)).toBe(address);
    }
    for (const { text } of rulesVector.ipv6Prefixes.reject) {
      expect(parseIpv6Cidr(text), text).toHaveProperty("error");
    }
  });

  it("says why an IPv6 rule is refused and what it means to save one", () => {
    expect(parseIpv6Cidr("2001:db8::1/32")).toEqual({ error: "2001:db8::1/32：主机位不为零，应写作 2001:db8::/32" });
    expect(parseIpv6Cidr("2001:db8::/129")).toEqual({ error: "2001:db8::/129：前缀长度应为 0–128" });
    expect(parseIpv6Cidr("::ffff:192.0.2.1")).toHaveProperty("error");
    expect(destinationNotes("2001:db8::/32", "PUBLIC", mesh)).toEqual([]);
    expect(destinationNotes("::/0", "PUBLIC", mesh)[0]).toContain("回环地址");
    expect(destinationNotes("::/0", "PUBLIC", mesh)[0]).toContain("NAT64 地址");
    expect(destinationNotes("fd00::/8", "LAN", mesh)).toEqual(["fd00::/8 包含始终被拒绝的地址：云元数据地址"]);
    expect(destinationNotes("fd12:3456::/32", "PUBLIC", mesh)[0]).toContain("局域网地址");
    expect(destinationNotes("2001:db8::/32", "LAN", mesh)[0]).toContain("不在局域网范围内");
    expect(storedRuleProblem({ cidr: "2001:db8::/32", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("");
    expect(storedRuleProblem({ cidr: "2001:db8::1/32", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("网段无效，不会匹配");
  });

  it("sends an IPv6 rule in RFC 5952 form", () => {
    const draft = { ...emptyPolicyDraft(), egressClientId: "2", consumers: ["3"],
      rules: [{ cidr: " 2001:0DB8:0000::/48 ", tcp: true, udp: false, ports: "443" }] };
    const check = checkPolicyDraft(draft, mesh);
    expect(check.errors).toEqual([]);
    expect(check.mutation?.destinationRules).toEqual([{ cidr: "2001:db8::/48", protocols: ["tcp"], portRanges: [[443, 443]] }]);
  });
});

describe("ports", () => {
  it("parses single ports, ranges and all", () => {
    expect(parsePorts("443, 8000-8100")).toEqual([[443, 443], [8000, 8100]]);
    expect(parsePorts("80，443")).toEqual([[80, 80], [443, 443]]);
    expect(parsePorts("全部")).toEqual([[1, 65535]]);
  });

  it("refuses an empty list, which would deny every port", () => {
    expect(parsePorts("")).toHaveProperty("error");
    expect(parsePorts("0")).toHaveProperty("error");
    expect(parsePorts("9000-8000")).toHaveProperty("error");
    expect(parsePorts("65536")).toHaveProperty("error");
  });

  it("formats what the server stored", () => {
    expect(formatPorts([[1, 65535]])).toBe("全部端口");
    expect(formatPorts([[443, 443], [8000, 8100]])).toBe("443, 8000-8100");
    expect(formatPorts([])).toBe("无（拒绝所有端口）");
    expect(formatPorts(null)).toBe("无（拒绝所有端口）");
  });
});

describe("destinationNotes", () => {
  it("names the forced-deny ranges a rule covers, the mesh included", () => {
    expect(destinationNotes("127.0.0.1", "PUBLIC", mesh)[0]).toContain("回环地址");
    expect(destinationNotes("0.0.0.0/0", "PUBLIC", mesh)[0]).toContain("组网网段 100.96.0.0/11");
    expect(destinationNotes("203.0.113.0/24", "PUBLIC", mesh)).toEqual([]);
  });

  it("warns when the scope can never let a rule through", () => {
    expect(destinationNotes("192.168.1.0/24", "PUBLIC", mesh)[0]).toContain("局域网地址");
    expect(destinationNotes("203.0.113.0/24", "LAN", mesh)[0]).toContain("不在局域网范围内");
    expect(destinationNotes("192.168.1.0/24", "LAN", mesh)).toEqual([]);
  });
});

describe("checkPolicyDraft", () => {
  it("builds the request with flat limits and normalised rules", () => {
    const draft = { ...emptyPolicyDraft(), egressClientId: "2", consumers: ["3", "3", "4"],
      rules: [{ cidr: "203.0.113.9", tcp: true, udp: true, ports: "443" }] };
    const check = checkPolicyDraft(draft, mesh);
    expect(check.errors).toEqual([]);
    expect(check.mutation).toEqual({
      egressClientId: 2, enabled: false, scope: "PUBLIC", allowedConsumerClientIds: [3, 4],
      destinationRules: [{ cidr: "203.0.113.9/32", protocols: ["tcp", "udp"], portRanges: [[443, 443]] }],
      domainRules: [],
      maxConcurrentFlows: 256, maxFlowsPerConsumer: 64, idleTimeoutSeconds: 60,
    });
  });

  it("refuses a draft the egress would misread", () => {
    const draft = { ...emptyPolicyDraft(), consumers: [], maxConcurrentFlows: "0",
      rules: [{ cidr: "203.0.113.1/24", tcp: false, udp: false, ports: "" }] };
    const check = checkPolicyDraft(draft, mesh);
    expect(check.mutation).toBeNull();
    expect(check.errors).toEqual([
      "请选择出口设备",
      "目的规则 1：203.0.113.1/24：主机位不为零，应写作 203.0.113.0/24",
      "目的规则 1：至少选择一个协议",
      "目的规则 1：请填写端口；所有端口填「全部」",
      "最大并发流应为正整数",
    ]);
    expect(check.warnings).toContain("未授权任何消费设备：出口不会为任何设备转发");
  });

  it("does not let a device be its own consumer", () => {
    const draft = { ...emptyPolicyDraft(), egressClientId: "2", consumers: ["2"],
      rules: [{ cidr: "203.0.113.0/24", tcp: true, udp: false, ports: "443" }] };
    expect(checkPolicyDraft(draft, mesh).errors).toEqual(["出口设备不能授权给自己"]);
  });
});

function policy(overrides: Partial<PeerEgressPolicy> = {}): PeerEgressPolicy {
  return {
    id: 1, egressClientId: 2, egressClientName: "home", enabled: true, scope: "PUBLIC",
    allowedConsumerClientIds: [3, 4], effectiveConsumerClientIds: [3, 4],
    destinationRules: [{ cidr: "203.0.113.0/24", protocols: ["tcp"], portRanges: [[443, 443]] }],
    maxConcurrentFlows: 256, maxFlowsPerConsumer: 64, idleTimeoutSeconds: 60,
    createdAt: "2026-09-29T00:00:00Z", updatedAt: "2026-09-29T00:00:00Z", ...overrides,
  };
}

const switchOn: PeerEgressSwitch = {
  deploymentEnabled: true, configuredEnabled: true, effectiveEnabled: true, protocolVersion: 1,
  enabledPolicyCount: 1, updatedAt: null, updatedBy: null,
};

describe("policyState", () => {
  it("names the one thing stopping a policy", () => {
    expect(policyState(policy(), switchOn)).toMatchObject({ label: "生效中", color: "success" });
    expect(policyState(policy({ effectiveConsumerClientIds: [3] }), switchOn).detail).toBe("1/2 台消费设备经 ACL 放行");
    expect(policyState(policy({ enabled: false }), switchOn).label).toBe("未启用");
    expect(policyState(policy(), { ...switchOn, configuredEnabled: false }).label).toBe("总开关关闭");
    expect(policyState(policy(), { ...switchOn, deploymentEnabled: false }).label).toBe("部署未启用组网");
    expect(policyState(policy({ allowedConsumerClientIds: [], effectiveConsumerClientIds: [] }), switchOn).label).toBe("未授权设备");
    expect(policyState(policy({ effectiveConsumerClientIds: null }), switchOn).label).toBe("无设备可用");
    expect(policyState(policy({ destinationRules: null }), switchOn).label).toBe("无目的规则");
    expect(policyState(policy({ destinationRules: [], domainRules: null }), switchOn).label).toBe("无目的规则");
    expect(policyState(policy({ destinationRules: [],
      domainRules: [{ match: "*.example.com", protocols: ["tcp"], portRanges: [[443, 443]] }] }), switchOn))
      .toEqual({ label: "生效中", color: "success", detail: "2 台消费设备；只有域名规则，只放行按域名发出的流" });
  });

  it("tells a disabled device apart from a missing ACL", () => {
    const enabled = new Map([[2, { enabled: true }], [3, { enabled: true }], [4, { enabled: true }]]);
    const idle = policy({ effectiveConsumerClientIds: [] });
    expect(policyState(idle, switchOn, new Map([...enabled, [2, { enabled: false }]])).label).toBe("出口设备未启用组网");
    expect(policyState(idle, switchOn, new Map([...enabled, [3, { enabled: false }], [4, { enabled: false }]])).label).toBe("消费设备未启用组网");
    expect(policyState(idle, switchOn, enabled).label).toBe("无设备可用");
    expect(consumerNote(3, policy({ effectiveConsumerClientIds: [4] }), enabled)).toBe("Peer ACL 未放行");
    expect(consumerNote(3, policy({ effectiveConsumerClientIds: [4] }), new Map([...enabled, [3, { enabled: false }]]))).toBe("未启用组网");
    expect(consumerNote(9, policy({ allowedConsumerClientIds: [9], effectiveConsumerClientIds: [] }), enabled)).toBe("不在组网设备中");
    expect(consumerNote(4, policy(), enabled)).toBe("");
    expect(consumerNote(3, policy({ enabled: false, effectiveConsumerClientIds: [] }), enabled)).toBe("");
  });

  it("describes the switch", () => {
    expect(switchSummary(null, true)).toBe("正在读取出口分流状态…");
    expect(switchSummary({ ...switchOn, configuredEnabled: false }, false)).toBe("已关闭：所有出口停止转发（1 条已启用策略开启后恢复）");
    expect(switchSummary(switchOn, false)).toBe("已开启：1 条策略启用中");
  });
});

it("flags a stored rule the egress would never match", () => {
  expect(storedRuleProblem({ cidr: "203.0.113.0/24", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("");
  expect(storedRuleProblem({ cidr: "203.0.113.1/24", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("网段无效，不会匹配");
  expect(storedRuleProblem({ cidr: "203.0.113.0/24", protocols: ["TCP"], portRanges: [[443, 443]] })).toContain("只认小写");
  expect(storedRuleProblem({ cidr: "203.0.113.0/24", protocols: ["udp"], portRanges: null })).toBe("没有端口，所有端口都被拒绝");
});

it("round-trips a stored policy into an editable draft", () => {
  const draft = draftFromPolicy(policy({ destinationRules: [
    { cidr: "203.0.113.0/24", protocols: ["tcp", "udp"], portRanges: [[1, 65535]] },
    { cidr: "198.51.100.0/24", protocols: null, portRanges: null },
  ] }));
  expect(draft.rules).toEqual([
    { cidr: "203.0.113.0/24", tcp: true, udp: true, ports: "全部" },
    { cidr: "198.51.100.0/24", tcp: false, udp: false, ports: "" },
  ]);
  expect(draft.consumers).toEqual(["3", "4"]);
  expect(draft.domainRules).toEqual([]);
  expect(draftFromPolicy(policy({ domainRules: [
    { match: "*.example.com", protocols: ["udp"], portRanges: [[443, 443], [8000, 8100]] },
    { match: "example.org", protocols: null, portRanges: null },
  ] })).domainRules).toEqual([
    { match: "*.example.com", tcp: false, udp: true, ports: "443, 8000-8100" },
    { match: "example.org", tcp: false, udp: false, ports: "" },
  ]);
});

describe("domain rules", () => {
  // The management half of the shared vector: what a server stores, and what it answers 400 to.
  const { accept, reject } = vectors.management;
  const rulesOf = (rules: unknown) => rules as DomainRuleInput[];

  it("uses the vector's limits", () => {
    expect(vectors.limits).toEqual({ rules: MAX_DOMAIN_RULES, portRangesPerRule: MAX_PORT_RANGES, storedJsonBytes: MAX_RULES_JSON_BYTES });
  });

  it.each(accept.map((item) => [item.name, item] as const))("stores %s as the servers do", (_, item) => {
    expect(normalizeDomainRules(rulesOf(item.domainRules))).toEqual({ stored: item.stored, errors: [] });
  });

  it.each(reject.map((item) => [item.name, item] as const))("refuses %s as the servers do", (_, item) => {
    expect(normalizeDomainRules(rulesOf(item.domainRules)).errors).not.toEqual([]);
  });

  // The editor's own path to the same request: checkboxes and port text instead of lists.
  function draftWith(rules: DomainRuleInput[]) {
    const domainRules = rules.map((rule) => {
      const protocols = (rule.protocols ?? []).map((protocol) => String(protocol).trim().toLowerCase());
      return {
        match: typeof rule.match === "string" ? rule.match : "",
        tcp: protocols.includes("tcp"),
        udp: protocols.includes("udp"),
        ports: ((rule.portRanges ?? []) as number[][]).map(([low, high]) => `${low}-${high}`).join(", "),
      };
    });
    return { ...emptyPolicyDraft(), egressClientId: "2", consumers: ["3"], rules: [], domainRules };
  }
  const grantsNothing = (rules: DomainRuleInput[]) =>
    rules.some((rule) => (rule.protocols ?? []).length === 0 || (rule.portRanges ?? []).length === 0);
  const sorted = (rules: { protocols: string[] }[]) => rules.map((rule) => ({ ...rule, protocols: [...rule.protocols].sort() }));

  it.each(accept.map((item) => [item.name, item] as const))("the editor saves %s as stored, unless it grants nothing", (_, item) => {
    const rules = rulesOf(item.domainRules);
    const check = checkPolicyDraft(draftWith(rules), mesh);
    if (grantsNothing(rules)) {
      // A server stores a rule without protocols or ports; the editor asks for both.
      expect(check.errors.some((error) => error.startsWith("域名规则"))).toBe(true);
      return;
    }
    expect(check.errors).toEqual([]);
    expect(sorted(check.mutation?.domainRules ?? [])).toEqual(sorted(item.stored));
  });

  it.each(reject.map((item) => [item.name, item] as const))("the editor refuses %s", (_, item) => {
    const check = checkPolicyDraft(draftWith(rulesOf(item.domainRules)), mesh);
    expect(check.mutation).toBeNull();
    expect(check.errors.some((error) => error.startsWith("域名规则"))).toBe(true);
  });

  it("says why a match is refused", () => {
    expect(parseDomainMatch(" *.CDN.Example. ")).toEqual({ match: "*.cdn.example" });
    expect(parseDomainMatch("203.0.113.5")).toEqual({ error: "203.0.113.5：不是域名，按地址授权请写进目的规则" });
    expect(parseDomainMatch("203.0.113.0/24")).toEqual({ error: "203.0.113.0/24：不是域名，按地址授权请写进目的规则" });
    expect(parseDomainMatch("*.1.2")).toEqual({ error: "*.1.2：不是域名，按地址授权请写进目的规则" });
    expect(parseDomainMatch("2001:db8::1")).toEqual({ error: "2001:db8::1：不是域名，按地址授权请写进目的规则" });
    expect(parseDomainMatch("中国.example")).toEqual({ error: "中国.example：含非 ASCII 字符，国际化域名请写成 punycode，应写作 xn--fiqs8s.example" });
    expect(parseDomainMatch("*.中国.example")).toEqual({ error: "*.中国.example：含非 ASCII 字符，国际化域名请写成 punycode，应写作 *.xn--fiqs8s.example" });
    expect(parseDomainMatch("*")).toEqual({ error: "不能单独写 *：通配只能写在两级以上的名字前，如 *.example.com" });
    expect(parseDomainMatch("*.com")).toEqual({ error: "*.com：只有一级的后缀不能通配，至少写到两级，如 *.example.com" });
    expect(parseDomainMatch("localhost")).toEqual({ error: "localhost：单标签名字不能授权，至少写到两级，如 example.com" });
    expect(parseDomainMatch("a.*.example.com")).toEqual({ error: "a.*.example.com：* 只能写在开头，形如 *.example.com" });
    expect(parseDomainMatch("example.com:443")).toEqual({ error: "example.com:443：不能带端口，端口填在右侧" });
    expect(parseDomainMatch("https://example.com")).toEqual({ error: "https://example.com：只填域名，不带协议或路径" });
    expect(parseDomainMatch("_srv.example.com")).toHaveProperty("error", expect.stringContaining("「_srv」无效"));
    expect(parseDomainMatch("a..example")).toEqual({ error: "a..example：有空的一级（连续的点）" });
    expect(parseDomainMatch("")).toEqual({ error: "请填写域名" });
  });

  it("checks domain rules in the draft beside the destination rules", () => {
    const draft = { ...emptyPolicyDraft(), egressClientId: "2", consumers: ["3"], rules: [],
      domainRules: [{ ...emptyDomainRuleDraft(), match: "Example.COM." }, { match: "10.0.0.0/8", tcp: false, udp: false, ports: "" }] };
    expect(checkPolicyDraft(draft, mesh).errors).toEqual([
      "域名规则 2：10.0.0.0/8：不是域名，按地址授权请写进目的规则",
      "域名规则 2：至少选择一个协议",
      "域名规则 2：请填写端口；所有端口填「全部」",
    ]);
    const fixed = { ...draft, domainRules: draft.domainRules.slice(0, 1) };
    const check = checkPolicyDraft(fixed, mesh);
    expect(check.mutation?.domainRules).toEqual([{ match: "example.com", protocols: ["tcp"], portRanges: [[443, 443]] }]);
    expect(check.warnings).toContain("没有目的规则：只按地址发出的流都会被拒绝，只有消费端按域名发出的流可能经域名规则放行");
    expect(checkPolicyDraft({ ...fixed, scope: "LAN" }, mesh).warnings)
      .toContain("范围为「局域网」：域名规则只放行解析到局域网地址的名字，解析到公网地址的仍被拒绝");
    const many = (count: number, match: (index: number) => string) =>
      ({ ...fixed, domainRules: Array.from({ length: count }, (_, index) => ({ ...emptyDomainRuleDraft(), match: match(index) })) });
    expect(checkPolicyDraft(many(MAX_DOMAIN_RULES + 1, (index) => `h${index}.io`), mesh).errors).toContain(`域名规则最多 ${MAX_DOMAIN_RULES} 条`);
    expect(checkPolicyDraft(many(MAX_DOMAIN_RULES, () => "a.io"), mesh).errors).toEqual([]);
    // With longer names the stored size runs out before the count does.
    expect(checkPolicyDraft(many(MAX_DOMAIN_RULES, (index) => `host-${index}.example.com`), mesh).errors)
      .toEqual([`域名规则合计超过 ${MAX_RULES_JSON_BYTES} 字节，请合并规则或减少端口段`]);
  });

  it("flags a stored domain rule the egress would skip or never match", () => {
    expect(storedDomainRuleProblem({ match: "*.example.com", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("");
    expect(storedDomainRuleProblem({ match: "*", protocols: ["tcp"], portRanges: [[443, 443]] })).toBe("域名写法无效，出口会跳过这条");
    expect(storedDomainRuleProblem({ match: "example.com", protocols: ["TCP"], portRanges: [[443, 443]] })).toContain("只认小写");
    expect(storedDomainRuleProblem({ match: "example.com", protocols: ["udp"], portRanges: [] })).toBe("没有端口，所有端口都被拒绝");
  });
});
