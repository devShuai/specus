import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import vector from "../../../../../protocol/test-vectors/product-metrics-v1.json";
import type { ProductMetricsSummary } from "../../api/types";
import { ProductMetricsDisclosure, ProductMetricsMemberNotice } from "../../components/ProductMetricsDisclosure";
import { PRODUCT_METRICS_MEMBER_NOTICE } from "../../lib/productMetrics";
import { ProductMetricsSummaryView } from "./ProductMetricsPanel";

// The summaries the shared vector expects, rendered as the admin page shows them.

interface VectorOp {
  op: string;
  expect: { status?: number; body?: unknown };
}

function summaries(scenario: string): ProductMetricsSummary[] {
  const ops = (vector.scenarios.find((item) => item.name === scenario)!.ops as unknown as VectorOp[]);
  return ops.filter((op) => op.op === "summary" && op.expect.status === 200).map((op) => op.expect.body as ProductMetricsSummary);
}

describe("product metrics summary view", () => {
  it("shows the onboarding funnel, the median bucket and that a recent cohort is not final", () => {
    const [full] = summaries("onboarding-funnel");
    const html = renderToStaticMarkup(<ProductMetricsSummaryView summary={full} />);
    for (const text of ["创建账号", "发布服务", "85.7%", "完成 4 / 7", "57.1%", "10–30 分钟", "还有 1 个账号在窗口内，完成率仍会变化"]) {
      expect(html).toContain(text);
    }
  });

  it("shows transfer success by path and size, by mode and the retry-after-failure rate", () => {
    const [full] = summaries("transfer-outcomes");
    const html = renderToStaticMarkup(<ProductMetricsSummaryView summary={full} />);
    for (const text of ["直连 · &lt; 1 MiB", "临时存储 · &gt; 512 MiB", "未建立 · &lt; 1 MiB", "发给设备", "文件链接", "失败后重试的成功率 50.0%", "总成功率 64.3%"]) {
      expect(html).toContain(text);
    }
    expect(html).not.toContain("完成率仍会变化");
  });

  it("states when the tenant no longer collects and an empty range has no cells", () => {
    const purged = summaries("transfer-outcomes").find((summary) => !summary.enabled)!;
    const html = renderToStaticMarkup(<ProductMetricsSummaryView summary={purged} />);
    expect(html).toContain("当前未开启");
    expect(html).toContain("区间内没有上报");
  });
});

describe("disclosure", () => {
  it("lists every required item and the member notice links the full text", () => {
    const disclosure = renderToStaticMarkup(<ProductMetricsDisclosure />);
    for (const title of ["统计什么", "不统计什么", "怎么保存", "谁能看", "怎么停"]) expect(disclosure).toContain(title);
    const notice = renderToStaticMarkup(<ProductMetricsMemberNotice />);
    expect(notice).toContain(PRODUCT_METRICS_MEMBER_NOTICE);
    expect(notice).toContain("/#/help/metrics");
  });
});
