import { Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, PaginationNext, PaginationPrevious } from "@heroui/react";

/**
 * Page numbers to show around the current page, with ellipses standing in for
 * the gaps. Always keeps the first and last page reachable.
 */
function pageWindow(page: number, total: number): (number | "gap")[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  const around = [page - 1, page, page + 1].filter((p) => p > 1 && p < total);
  const slots = new Set<number>([1, ...around, total]);
  const sorted = [...slots].sort((a, b) => a - b);

  const out: (number | "gap")[] = [];
  let previous = 0;
  for (const p of sorted) {
    if (previous && p - previous > 1) {
      out.push("gap");
    }
    out.push(p);
    previous = p;
  }
  return out;
}

export interface PagerProps {
  /** 1-based current page. */
  page: number;
  total: number;
  onChange: (page: number) => void;
  className?: string;
  /** Freezes every control, e.g. while the page behind it is still loading. */
  isDisabled?: boolean;
}

/**
 * HeroUI 3 ships Pagination as presentation only — the page maths and the
 * button wiring belong to the app. This is that wiring, in one place, so the
 * panels keep passing `page`/`total`/`onChange` and nothing has to repeat it.
 */
export function Pager({ page, total, onChange, className, isDisabled = false }: PagerProps) {
  if (total <= 1) {
    return null;
  }
  const current = Math.min(Math.max(page, 1), total);

  return (
    <Pagination className={className}>
      <PaginationPrevious
        isDisabled={isDisabled || current <= 1}
        onPress={() => onChange(current - 1)}
      >
        上一页
      </PaginationPrevious>
      <PaginationContent>
        {pageWindow(current, total).map((slot, index) =>
          slot === "gap" ? (
            <PaginationItem key={`gap-${index}`}>
              <PaginationEllipsis />
            </PaginationItem>
          ) : (
            <PaginationItem key={slot}>
              <PaginationLink
                isActive={slot === current}
                isDisabled={isDisabled}
                onPress={() => onChange(slot)}
              >
                {slot}
              </PaginationLink>
            </PaginationItem>
          ),
        )}
      </PaginationContent>
      <PaginationNext
        isDisabled={isDisabled || current >= total}
        onPress={() => onChange(current + 1)}
      >
        下一页
      </PaginationNext>
    </Pagination>
  );
}
