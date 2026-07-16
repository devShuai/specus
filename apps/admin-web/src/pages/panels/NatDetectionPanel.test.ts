import { describe, expect, it } from "vitest";
import {
  browserNatOutcome,
  classifyBrowserNatResult,
  type BrowserNatResult,
} from "./NatDetectionPanel";

function result(overrides: Partial<BrowserNatResult>): BrowserNatResult {
  return {
    kind: "mapping-stable",
    natType: "NO_NAT",
    startedAt: 1,
    finishedAt: 2,
    probes: [],
    mappedEndpoints: [],
    hostCandidates: [],
    confidence: "high",
    evidence: "test evidence",
    summary: "test summary",
    recommendation: "test recommendation",
    ...overrides,
  };
}

function srflx(address: string, port: number, relatedAddress: string, relatedPort: number) {
  return {
    raw: `candidate:1 1 udp 1 ${address} ${port} typ srflx raddr ${relatedAddress} rport ${relatedPort}`,
    foundation: "1",
    component: "1",
    protocol: "udp",
    priority: "1",
    address,
    port,
    type: "srflx",
    relatedAddress,
    relatedPort,
  };
}

function probe(server: string, candidates: ReturnType<typeof srflx>[]) {
  return {
    server,
    candidates,
    error: null,
    elapsedMs: 50,
    sourceKnown: true,
  };
}

describe("browser NAT result presentation", () => {
  it.each([
    ["NO_NAT", "公网直连型", 1, "联机条件优秀"],
    ["PORT_PRESERVED_NAT", "端口保持型 NAT", 2, "多数联机场景友好"],
    ["CONE_LIKE_NAT", "稳定映射型 NAT", 3, "联机可用但受对端影响"],
    ["SYMMETRIC_NAT", "对称映射型 NAT", 4, "直连联机更易受限"],
  ] as const)("maps %s to its user-facing impact", (natType, title, level, gameVerdict) => {
    const outcome = browserNatOutcome(result({ natType }));

    expect(outcome.title).toBe(title);
    expect(outcome.level).toBe(level);
    expect(outcome.game.verdict).toBe(gameVerdict);
    expect(outcome.p2p.description.length).toBeGreaterThan(0);
  });

  it("does not overstate a low-evidence generic NAT result", () => {
    const outcome = browserNatOutcome(result({ natType: "NAT", confidence: "low" }));

    expect(outcome.title).toBe("类型暂未细分");
    expect(outcome.level).toBeNull();
    expect(outcome.reachability).toBe("暂时无法判断");
  });

  it("explains when no public UDP mapping was obtained", () => {
    const outcome = browserNatOutcome(result({ kind: "udp-blocked", natType: null }));

    expect(outcome.title).toBe("未获得公网 UDP 映射");
    expect(outcome.game.verdict).toContain("UDP");
    expect(outcome.p2p.verdict).toContain("P2P");
  });

  it.each([
    ["not-supported", "当前浏览器无法检测"],
    ["failed", "本次检测未完成"],
  ] as const)("marks %s as inconclusive", (kind, title) => {
    const outcome = browserNatOutcome(result({ kind, natType: null }));

    expect(outcome.title).toBe(title);
    expect(outcome.reachability).toBe("暂时无法判断");
    expect(outcome.game.verdict).toBe("暂时无法判断");
  });
});

describe("browser NAT evidence thresholds", () => {
  it("keeps a single attributable STUN mapping inconclusive", () => {
    const classified = classifyBrowserNatResult(1, [
      probe("stun:example.test:3478", [srflx("203.0.113.10", 50000, "192.168.1.10", 40000)]),
    ]);

    expect(classified.natType).toBe("NAT");
    expect(classified.confidence).toBe("low");
    expect(classified.summary).toContain("暂时无法判断");
  });

  it("does not confuse mappings from Wi-Fi and VPN sockets with symmetric NAT", () => {
    const classified = classifyBrowserNatResult(1, [
      probe("stun:a.example:3478", [srflx("198.51.100.10", 50000, "192.168.1.10", 40000)]),
      probe("stun:b.example:3478", [srflx("203.0.113.20", 55000, "10.8.0.2", 45000)]),
    ]);

    expect(classified.natType).toBe("NAT");
    expect(classified.confidence).toBe("low");
  });

  it("detects target-dependent mappings only for the same local UDP base", () => {
    const classified = classifyBrowserNatResult(1, [
      probe("stun:a.example:3478", [srflx("198.51.100.10", 50000, "192.168.1.10", 40000)]),
      probe("stun:b.example:3478", [srflx("198.51.100.10", 50001, "192.168.1.10", 40000)]),
    ]);

    expect(classified.natType).toBe("SYMMETRIC_NAT");
    expect(classified.kind).toBe("mapping-changing");
  });

  it("derives confidence from the group that produced the final worst result", () => {
    const classified = classifyBrowserNatResult(1, [
      probe("stun:a.example:3478", [
        srflx("198.51.100.10", 50000, "192.168.1.10", 40000),
        srflx("203.0.113.20", 55000, "10.8.0.2", 45000),
      ]),
      probe("stun:b.example:3478", [
        srflx("198.51.100.10", 50000, "192.168.1.10", 40000),
        srflx("203.0.113.20", 55001, "10.8.0.2", 45000),
      ]),
      probe("stun:c.example:3478", [
        srflx("198.51.100.10", 50000, "192.168.1.10", 40000),
      ]),
    ]);

    expect(classified.natType).toBe("SYMMETRIC_NAT");
    expect(classified.confidence).toBe("medium");
  });
});
