import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ProgressMeter } from "./ProgressMeter";

describe("native progress meter structure", () => {
  it("paints one real track and fill while exposing determinate progress", () => {
    const html = renderToStaticMarkup(<ProgressMeter aria-label="文件发送进度" value={37} size="sm" />);
    expect(html.match(/data-slot="progress-bar-track"/g)).toHaveLength(1);
    expect(html.match(/data-slot="progress-bar-fill"/g)).toHaveLength(1);
    expect(html).toContain('role="progressbar"');
    expect(html).toContain('aria-label="文件发送进度"');
    expect(html).toContain('aria-valuenow="37"');
    expect(html).toContain('width:37%');
  });

  it("keeps an indeterminate track without inventing a numeric completion value", () => {
    const html = renderToStaticMarkup(<ProgressMeter aria-label="等待对方确认" isIndeterminate />);
    expect(html).toContain('data-slot="progress-bar-track"');
    expect(html).toContain('data-slot="progress-bar-fill"');
    expect(html).toContain('aria-label="等待对方确认"');
    expect(html).not.toContain("aria-valuenow");
  });
});
