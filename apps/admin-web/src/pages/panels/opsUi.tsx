// Small pieces of the design shared by the workbench, overview, traffic and connection pages:
// design pagination, the number-card icon block, a type tag keyed by a chart color and the
// loading / empty rows of a design table. Styles are in src/styles/area-ops.css.
import type { CSSProperties, ReactNode } from "react";
import { Icon, type IconName } from "../../components/ui";

/** One of the design's categorical chart colors (chart-1 … chart-6). */
export type ChartColor = 1 | 2 | 3 | 4 | 5 | 6;

export const chartVar = (slot: ChartColor) => `var(--chart-${slot})`;

/** The 30px tinted icon block in front of a Stat label (jd-kpi-icon). */
export function KpiLabel({ icon, color, children }: { icon: IconName; color: ChartColor; children: ReactNode }) {
  return (
    <>
      <span className="jd-kpi-icon" style={{ "--k": chartVar(color) } as CSSProperties} aria-hidden="true">
        <Icon name={icon} />
      </span>
      {children}
    </>
  );
}

/**
 * A type label: a Tag whose dot carries a chart color (types, not status, may use the chart
 * colors). Without a color it is the plain neutral Tag.
 */
export function TypeTag({ color, children, title }: { color?: ChartColor; children: ReactNode; title?: string }) {
  return (
    <span
      className={color ? "bd-tag ops-type-tag" : "bd-tag"}
      style={color ? ({ "--k": chartVar(color) } as CSSProperties) : undefined}
      title={title}
    >
      {children}
    </span>
  );
}

/** Pages to show around the current one: first, last, current ± 1, gaps as null. */
export function pageWindow(current: number, total: number): Array<number | null> {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index);
  const pages = new Set([0, total - 1, current - 1, current, current + 1].filter((page) => page >= 0 && page < total));
  if (current <= 2) [1, 2, 3].forEach((page) => pages.add(page));
  if (current >= total - 3) [total - 4, total - 3, total - 2].forEach((page) => pages.add(page));
  const sorted = [...pages].sort((left, right) => left - right);
  const out: Array<number | null> = [];
  sorted.forEach((page, index) => {
    if (index > 0 && page - sorted[index - 1] > 1) out.push(null);
    out.push(page);
  });
  return out;
}

/**
 * Pagination of the design (bd-pagination): the total on the left, page numbers on the right.
 * Pages are 0-based here, shown 1-based.
 */
export function Pagination({ page, totalPages, total, onChange, disabled = false, label = "分页" }: {
  page: number;
  totalPages: number;
  total: ReactNode;
  onChange: (page: number) => void;
  disabled?: boolean;
  label?: string;
}) {
  const pages = Math.max(1, totalPages);
  const go = (next: number) => {
    if (disabled || next < 0 || next >= pages || next === page) return;
    onChange(next);
  };
  return (
    <nav className="bd-pagination jd-pagination ops-pagination" aria-label={label}>
      <span className="bd-page-total bd-num">{total}</span>
      {pages > 1 ? (
        <>
          <button type="button" className="bd-page" aria-label="上一页" disabled={disabled || page === 0}
            aria-disabled={disabled || page === 0} onClick={() => go(page - 1)}>
            <Icon name="chevron-left" />
          </button>
          {pageWindow(page, pages).map((item, index) => item == null ? (
            <span key={`gap-${index}`} className="jd-page-gap" aria-hidden="true">…</span>
          ) : (
            <button
              key={item}
              type="button"
              className="bd-page"
              aria-label={`第 ${item + 1} 页`}
              aria-current={item === page ? "page" : undefined}
              disabled={disabled}
              onClick={() => go(item)}
            >
              {item + 1}
            </button>
          ))}
          <button type="button" className="bd-page" aria-label="下一页" disabled={disabled || page >= pages - 1}
            aria-disabled={disabled || page >= pages - 1} onClick={() => go(page + 1)}>
            <Icon name="chevron-right" />
          </button>
        </>
      ) : null}
    </nav>
  );
}

/** "第 1-20 条，共 146 条" as the pages already wrote it. */
export function rangeText(page: number, pageSize: number, total: number): string {
  if (total === 0) return "共 0 条";
  const start = page * pageSize + 1;
  const end = Math.min(total, (page + 1) * pageSize);
  return `第 ${start}-${end} 条，共 ${total} 条`;
}

/** A full-width row of a design table that says the rows are loading. */
export function TableLoadingRow({ colSpan, label = "加载中…" }: { colSpan: number; label?: string }) {
  return (
    <tr className="ops-table-state">
      <td colSpan={colSpan} className="jd-cell-full">
        <span className="ops-loading" role="status"><Icon name="loader" />{label}</span>
      </td>
    </tr>
  );
}

/** A full-width row of a design table holding an empty state. */
export function TableEmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr className="ops-table-state">
      <td colSpan={colSpan} className="jd-cell-full">{children}</td>
    </tr>
  );
}
