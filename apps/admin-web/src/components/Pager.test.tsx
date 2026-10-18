import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Pager } from "./Pager";

const control = (html: string, slot: "previous" | "next") => html.match(new RegExp(`<button[^>]*data-slot="pagination-${slot}"[^>]*>`))?.[0] ?? "";

describe("native page controls", () => {
  it("hides a single page instead of exposing unusable navigation", () => {
    expect(renderToStaticMarkup(<Pager page={1} total={1} onChange={() => {}} />)).toBe("");
  });

  it("labels navigation and disables only the relevant endpoint", () => {
    const first = renderToStaticMarkup(<Pager page={1} total={2} onChange={() => {}} />);
    expect(first).toContain('aria-label="分页"');
    expect(control(first, "previous")).toContain('disabled=""');
    expect(control(first, "next")).not.toContain('disabled=""');
    const last = renderToStaticMarkup(<Pager page={2} total={2} onChange={() => {}} />);
    expect(control(last, "previous")).not.toContain('disabled=""');
    expect(control(last, "next")).toContain('disabled=""');
  });

  it("keeps first and last pages reachable across gaps and freezes both directions while pending", () => {
    const html = renderToStaticMarkup(<Pager page={9} total={20} isDisabled onChange={() => {}} />);
    expect(html).toContain('aria-current="page"');
    expect(html).toContain('>1</button>');
    expect(html).toContain('>20</button>');
    expect(html).toContain('data-slot="pagination-ellipsis"');
    expect(control(html, "previous")).toContain('disabled=""');
    expect(control(html, "next")).toContain('disabled=""');
  });
});
