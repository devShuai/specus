import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import vector from "../../../../../protocol/test-vectors/service-connectivity-check-v1.json";
import {
  AUTH_REQUIRED_LABEL,
  describeConnectivityCheck,
  describeConnectivityRefusal,
  RESULT_LABELS,
  STAGE_LABELS,
  UNSUPPORTED_MESSAGE,
  UPGRADE_HINT,
  type ConnectivityCheckResult,
  type ConnectivityStageName,
} from "../../lib/connectivityCheck";
import { ConnectivityCheckResultView } from "./ConnectivityCheckResult";

// Every outcome of the shared vector, rendered as the page shows it: the body the server returns
// plus the runtime routeId and checkedAt the vector leaves out.

interface VectorCase {
  name: string;
  expect: { httpStatus: number; code?: string; retryAfterSeconds?: number; body?: Omit<ConnectivityCheckResult, "routeId" | "checkedAt"> };
}

const cases = (vector.cases as unknown as VectorCase[]);
const ran = cases.filter((testCase) => testCase.expect.httpStatus === 200);
const refused = cases.filter((testCase) => testCase.expect.httpStatus !== 200);

function resultOf(testCase: VectorCase): ConnectivityCheckResult {
  return { ...testCase.expect.body!, routeId: 42, checkedAt: "2026-10-06T08:00:00Z" };
}

function stageItems(html: string): Map<string, string> {
  const items = new Map<string, string>();
  for (const match of html.matchAll(/<li[^>]*data-stage="([^"]+)"[^>]*>([\s\S]*?)<\/li>/g)) {
    items.set(match[1], match[0]);
  }
  return items;
}

describe("connectivity check result rendering", () => {
  it("covers every check outcome of the vector", () => {
    expect(ran.length).toBeGreaterThan(30);
    expect(new Set(ran.map((testCase) => testCase.expect.body!.outcome))).toEqual(new Set(["succeeded", "failed", "unverified"]));
  });

  it.each(ran.map((testCase) => [testCase.name, testCase] as const))("%s", (_name, testCase) => {
    const result = resultOf(testCase);
    const html = renderToStaticMarkup(<ConnectivityCheckResultView result={result} />);
    const view = describeConnectivityCheck(result);
    const items = stageItems(html);

    // Four stages, in order, each with its Chinese label and result; decided stages show their code.
    expect([...items.keys()]).toEqual(["configured", "device-online", "target-reachable", "access-succeeded"]);
    for (const stage of result.stages) {
      const item = items.get(stage.stage)!;
      expect(item).toContain(STAGE_LABELS[stage.stage as ConnectivityStageName]);
      expect(item).toContain(`data-result="${stage.result}"`);
      expect(item).toContain(RESULT_LABELS[stage.result]);
      if (stage.code) {
        expect(item).toContain(stage.code);
        expect(item).toContain(`${stage.atMs} ms`);
      } else {
        expect(stage.result).toBe("skipped");
      }
    }

    // Exactly the stage the check stopped at is highlighted, with a next step; none when it passed.
    const decisive = [...items.entries()].filter(([, item]) => item.includes('data-decisive="true"')).map(([name]) => name);
    expect(decisive).toEqual(result.stoppedAt ? [result.stoppedAt] : []);
    if (result.stoppedAt) {
      expect(items.get(result.stoppedAt)).toContain("下一步：");
    }

    // The outcome is named as the server decided it; "无法判定" is never a pass or a failure.
    expect(html).toContain(`data-outcome="${result.outcome}"`);
    if (result.outcome === "succeeded") {
      expect(html).toContain("检查通过");
      expect(html).not.toContain("无法判定");
    } else if (result.outcome === "unverified") {
      expect(html).toContain("无法判定");
      expect(html).not.toContain("检查通过");
      expect(html).not.toContain("检查未通过");
    } else {
      expect(html).toContain("检查未通过");
    }
    if (result.code === "TARGET_UNVERIFIED") expect(html).toContain(UPGRADE_HINT);
    if (result.code === "ACCESS_AUTH_REQUIRED") expect(html).toContain(AUTH_REQUIRED_LABEL);

    // The time of the check is labelled; the target address is never part of the result.
    expect(html).toContain(view.checkedAtText);
    expect(view.checkedAtText).toMatch(/^检查于 \d{2}:\d{2}:\d{2}$/);
    expect(html).toContain(`${result.totalMs} ms`);
    if (result.statusClass) expect(html).toContain(result.statusClass);
    // Hints name schemes ("http://"), but no address with a host ever appears.
    expect(html).not.toMatch(/https?:\/\/[\w.-]/);
  });
});

describe("connectivity check refusals", () => {
  it.each(refused.filter((testCase) => testCase.expect.code).map((testCase) => [testCase.name, testCase] as const))(
    "%s is explained without blaming the route",
    (_name, testCase) => {
      const answer = describeConnectivityRefusal({
        status: testCase.expect.httpStatus,
        code: testCase.expect.code ?? null,
        retryAfterSeconds: testCase.expect.retryAfterSeconds ?? null,
      });
      expect(answer.unsupported).toBe(false);
      expect(answer.message).not.toMatch(/HTTP \d{3}/);
      expect(answer.message.length).toBeGreaterThan(5);
    },
  );

  it("counts down a rate limit by Retry-After", () => {
    for (const event of vector.rate.events.filter((item) => !item.admitted)) {
      const answer = describeConnectivityRefusal({ status: 429, code: "CHECK_RATE_LIMITED", retryAfterSeconds: event.retryAfterSeconds! });
      expect(answer.message).toContain(`${event.retryAfterSeconds} 秒后再试`);
    }
  });

  it("reads an old server's 404 or 405 as no support, not as a route problem", () => {
    for (const refusal of [{ status: 404, code: null }, { status: 405, code: null }, { status: 404, code: "NOT_FOUND" }]) {
      const answer = describeConnectivityRefusal({ ...refusal, retryAfterSeconds: null });
      expect(answer.unsupported).toBe(true);
      expect(answer.message).toContain(UNSUPPORTED_MESSAGE);
    }
    expect(describeConnectivityRefusal({ status: 404, code: "CHECK_TARGET_NOT_FOUND", retryAfterSeconds: null }).unsupported).toBe(false);
  });

  it("answers 409 and 503 politely", () => {
    expect(describeConnectivityRefusal({ status: 409, code: null, retryAfterSeconds: 3 }).message).toBe("请在 3 秒后再试。");
    expect(describeConnectivityRefusal({ status: 503, code: "CHECK_BUSY", retryAfterSeconds: 1 }).message).toContain("稍后再试");
    expect(describeConnectivityRefusal({ status: 503, code: "CHECK_UNAVAILABLE", retryAfterSeconds: 1 }).message).toContain("不代表路由配置有误");
  });
});
