import { Button } from "@heroui/react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ActionTooltip } from "./ActionTooltip";

describe("action tooltip focus ownership", () => {
  it("leaves an enabled action as the sole focusable trigger", () => {
    const html = renderToStaticMarkup(<ActionTooltip label="刷新目录状态"><Button>检查目录状态</Button></ActionTooltip>);
    expect(html.match(/<button\b/g)).toHaveLength(1);
    expect(html).not.toContain('data-slot="tooltip-trigger"');
    expect(html).not.toContain('role="group"');
  });

  it("gives a disabled action a labelled, focusable explanation without enabling it", () => {
    const html = renderToStaticMarkup(<ActionTooltip disabled label="全局服务共享已关闭"><Button isDisabled>复制地址</Button></ActionTooltip>);
    expect(html).toContain('role="group"');
    expect(html).toContain('tabindex="0"');
    expect(html).toContain('aria-label="全局服务共享已关闭"');
    expect(html).toMatch(/<button[^>]*disabled=""/);
    expect(html.match(/<button\b/g)).toHaveLength(1);
  });
});
