import { describe, expect, it } from "vitest";
import vector from "../../../../protocol/test-vectors/service-workbench-v1.json";
import type { Client, HttpRoute, PeerMeshServiceSharing, PeerMeshSharedService, Specus } from "../api/types";
import {
  ATTENTION_NOTE,
  NO_KNOWN_PROBLEM,
  NO_KNOWN_PROBLEM_CAVEAT,
  PROBLEM_CODES,
  derivePendingProblems,
  problemInputFromReads,
  problemNextStep,
  problemTitle,
  sourceStateOfError,
  type PendingProblem,
  type ProblemInput,
  type WorkbenchReads,
} from "./workbenchProblems";
import { ApiError } from "../api/client";

describe("pending problems from the shared vector", () => {
  it("uses the vector's codes, severities and order", () => {
    expect(PROBLEM_CODES).toEqual(vector.problems.codes);
  });

  for (const testCase of vector.problems.cases) {
    it(testCase.name, () => {
      expect(derivePendingProblems(testCase.input as ProblemInput)).toEqual(testCase.expect);
    });
  }

  it("covers every problem code", () => {
    const used = new Set(vector.problems.cases.flatMap((testCase) => testCase.expect.problems.map((p) => p.code)));
    expect([...used].sort()).toEqual(PROBLEM_CODES.map((entry) => entry.code).sort());
  });
});

const NOW = Date.parse("2026-10-06T00:00:00Z");

function client(id: number, online = true, enabled = true): Client {
  return { id, clientName: `device-${id}`, enabled, online } as Client;
}

function route(id: number, clientId: number, enabled = true): HttpRoute {
  return { id, clientId, clientName: `device-${clientId}`, route: `r${id}`, targetBaseUrl: "http://127.0.0.1", enabled } as HttpRoute;
}

function mapping(id: number, clientId: number): Specus {
  return { id, clientId, clientName: `device-${clientId}`, listenPort: 20000 + id, targetAddress: "127.0.0.1", targetPort: 22, enabled: true } as Specus;
}

function peer(id: number, clientId: number, instances: PeerMeshSharedService["instances"], publishedAddress: string | null = "100.96.0.2:8080"): PeerMeshSharedService {
  return { id, clientId, clientName: `device-${clientId}`, serviceId: `s${id}`, name: `s${id}`, enabled: true,
    application: "http", path: "", publishedAddress, instances } as PeerMeshSharedService;
}

const sharingOn = { deploymentEnabled: true, configuredEnabled: true } as PeerMeshServiceSharing;
const live = { publisherSessionId: 1, online: true, advertised: true, revision: 1, expiresAt: "2026-10-06T00:05:00Z" };

function reads(overrides: Partial<WorkbenchReads> = {}): WorkbenchReads {
  return {
    clients: { state: "ok", data: [client(1), client(2, false)] },
    httpRoutes: { state: "ok", data: [route(10, 1), route(11, 2), route(12, 2, false)] },
    tcpMappings: { state: "ok", data: [mapping(20, 2)] },
    peerSharing: { state: "ok", data: sharingOn },
    peerServices: { state: "ok", data: [peer(30, 1, [live])] },
    ...overrides,
  };
}

describe("problem input from the list endpoints", () => {
  it("abstracts what the five lists answered", () => {
    const result = derivePendingProblems(problemInputFromReads(reads(), NOW));
    expect(result).toEqual({
      complete: true,
      unreadSources: [],
      problems: [{ code: "DEVICE_OFFLINE", severity: "blocking", clientId: 2,
        services: [{ kind: "http-route", id: 11 }, { kind: "tcp-mapping", id: 20 }] }],
    });
  });

  it("reads a Peer instance's expiry and address the way the Peer tab does", () => {
    const expired = { ...live, expiresAt: "2026-10-05T23:59:59Z" };
    const input = problemInputFromReads(reads({
      peerServices: { state: "ok", data: [
        peer(30, 1, [expired]),
        peer(31, 1, [{ ...live, online: false }, live]), // the instance closest to listing it decides
        peer(32, 1, [live], null),
        peer(33, 1, []),
      ] },
    }), NOW);
    expect(input.peerServices?.map((service) => service.instance)).toEqual([
      { online: true, expired: true, advertised: true, hasAddress: true },
      { online: true, expired: false, advertised: true, hasAddress: true },
      { online: true, expired: false, advertised: true, hasAddress: false },
      null,
    ]);
    const codes = derivePendingProblems(input).problems.map((problem) => [problem.code, problem.services.map((ref) => ref.id)]);
    expect(codes).toEqual([["DEVICE_OFFLINE", [11, 20]], ["PEER_NOT_REPORTED", [33]],
      ["PEER_DIRECTORY_EXPIRED", [30]], ["PEER_NOT_ADVERTISED", [32]]]);
  });

  it("never turns a failed read into no problems", () => {
    const result = derivePendingProblems(problemInputFromReads(reads({
      clients: { state: "failed" },
      tcpMappings: { state: "failed" },
    }), NOW));
    expect(result.complete).toBe(false);
    expect(result.unreadSources).toEqual(["clients", "tcpMappings"]);
    expect(result.problems).toEqual([]);
  });

  it("decides no Peer rule without the sharing switch", () => {
    const failed = problemInputFromReads(reads({ peerSharing: { state: "failed" } }), NOW);
    expect(failed.sources.peerServices).toBe("failed");
    expect(failed.peerServices).toBeUndefined();
    const unsupported = problemInputFromReads(reads({ peerSharing: { state: "unsupported" }, peerServices: { state: "unsupported" } }), NOW);
    expect(unsupported.sources.peerServices).toBe("unsupported");
    expect(derivePendingProblems(unsupported).complete).toBe(true);
  });

  it("classifies 404/405 as unsupported and everything else as failed", () => {
    expect(sourceStateOfError(new ApiError("not found", 404))).toBe("unsupported");
    expect(sourceStateOfError(new ApiError("method", 405))).toBe("unsupported");
    expect(sourceStateOfError(new ApiError("down", 503))).toBe("failed");
    expect(sourceStateOfError(new TypeError("Failed to fetch"))).toBe("failed");
    expect(sourceStateOfError(new SyntaxError("Unexpected token"))).toBe("failed");
  });
});

describe("problem wording", () => {
  const forbidden = ["正常", "健康", "可用", "可访问", "已连通"];
  const all: PendingProblem[] = PROBLEM_CODES.map(({ code, severity }) => ({
    code, severity, clientId: 1, services: [{ kind: "http-route", id: 1 }, { kind: "http-route", id: 2 }],
  }));

  it("never claims a service works", () => {
    const texts = [
      ...all.flatMap((problem) => [problemTitle(problem), problemNextStep(problem, true), problemNextStep(problem, false)]),
      ATTENTION_NOTE,
      NO_KNOWN_PROBLEM,
    ];
    for (const text of texts) {
      for (const word of forbidden) expect(text, text).not.toContain(word);
    }
  });

  it("says no known problem is not reachability", () => {
    expect(NO_KNOWN_PROBLEM).toBe("未发现已知问题");
    expect(NO_KNOWN_PROBLEM_CAVEAT).toContain("这不代表服务可以访问");
    expect(NO_KNOWN_PROBLEM_CAVEAT).toContain("连接检查");
  });

  it("counts the services in the titles that carry a number", () => {
    expect(problemTitle(all[0])).toBe("设备已停用，其上 2 个已启用的服务不会对外提供");
    expect(problemTitle(all[1])).toBe("设备离线，其上 2 个已启用的服务现在无法经 specus 访问");
    expect(problemNextStep(all[0], false)).toContain("普通用户请联系租户管理员");
  });
});
