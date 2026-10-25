// React wrappers around the Liquid Glass Base component classes (src/styles/liquid-glass.css).
// They render the design's own markup (bd-* / jd-* class names), so a page written with them looks
// like the design system's component cards. HeroUI stays in use for overlays, selects and fields
// that need its behaviour; its theme follows the same tokens.
import { useEffect, useRef, useState, type HTMLAttributes, type KeyboardEvent, type ReactNode } from "react";
import { formatAbsoluteTime, formatRelativeTime } from "../../lib/format";
import { Icon, type IconName } from "./Icon";

export { Icon, type IconName } from "./Icon";

const cx = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(" ");

/* ---------------------------------------------------------------- containers */

export function Card({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cx("bd-card", className)} {...rest}>{children}</div>;
}

export function CardHeader({ title, description, actions, className }: {
  title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string;
}) {
  return (
    <div className={cx("bd-card-header", className)}>
      <div className="min-w-0">
        <h3 className="bd-card-title">{title}</h3>
        {description ? <p className="app-card-desc">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-none flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function CardBody({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cx("bd-card-body", className)} {...rest}>{children}</div>;
}

export function CardFooter({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cx("bd-card-footer", className)} {...rest}>{children}</div>;
}

/** A content block with a 20px section title (jd-section-head); adjacent sections are 32px apart. */
export function Section({ title, description, actions, children, className, id }: {
  title?: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; id?: string;
}) {
  return (
    <section className={cx("jd-section", className)} id={id}>
      {title ? <SectionHead title={title} description={description} actions={actions} /> : null}
      {children}
    </section>
  );
}

export function SectionHead({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="jd-section-head">
      <div className="min-w-0">
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-none flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A row of 3–4 number cards, only where the numbers are the point of the page. */
export function StatGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("bd-dash", className)}>{children}</div>;
}

export function Stat({ label, value, meta, span = 3, tone }: {
  label: ReactNode; value: ReactNode; meta?: ReactNode; span?: 3 | 4 | 6 | 12;
  /** Colors the value for a status number; leave unset for plain counts. */
  tone?: "success" | "warning" | "danger" | "info";
}) {
  return (
    <div className={cx("bd-card bd-stat", `bd-span-${span}`)}>
      <div className="bd-stat-label">{label}</div>
      <div className={cx("bd-stat-value", tone && `app-tone-${tone}`)}>{value}</div>
      {meta ? <div className="bd-stat-meta">{meta}</div> : null}
    </div>
  );
}

export function TableWrap({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("bd-table-wrap", className)}>{children}</div>;
}

/** The glass filter bar above a list: search, selects and the result count. */
export function FilterBar({ children, end, className }: { children: ReactNode; end?: ReactNode; className?: string }) {
  return (
    <div className={cx("bd-filterbar", className)}>
      {children}
      {end ? <div className="bd-filterbar-end">{end}</div> : null}
    </div>
  );
}

/* ---------------------------------------------------------------- status */

export type Tone = "success" | "warning" | "danger" | "info" | "neutral";

/** Tag component: a pill with a dot. Status tones are a tint plus colored text; always has text. */
export function Tag({ tone = "neutral", plain, children, className, title }: {
  tone?: Tone; plain?: boolean; children: ReactNode; className?: string; title?: string;
}) {
  return (
    <span className={cx("bd-tag", tone !== "neutral" && `bd-tag--${tone}`, plain && "bd-tag--plain", className)} title={title}>
      {children}
    </span>
  );
}

const ALERT_ICON: Record<Exclude<Tone, "neutral">, IconName> = {
  success: "circle-check", warning: "alert", danger: "circle-alert", info: "info-circle",
};

/** Alert component: what happened and what to do next. */
export function Alert({ tone = "info", title, children, actions, className, role }: {
  tone?: Exclude<Tone, "neutral">; title?: ReactNode; children?: ReactNode; actions?: ReactNode; className?: string;
  role?: "alert" | "status";
}) {
  return (
    <div className={cx("bd-alert", `bd-alert--${tone}`, className)} role={role}>
      <Icon name={ALERT_ICON[tone]} />
      <div className="min-w-0 flex-1">
        {title ? <div className="bd-alert-title">{title}</div> : null}
        {children ? <div className="bd-alert-body">{children}</div> : null}
      </div>
      {actions ? <div className="app-alert-actions flex flex-none flex-wrap items-center gap-2 self-center">{actions}</div> : null}
    </div>
  );
}

export function Progress({ value, label }: { value: number; label?: string }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className="bd-progress" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(clamped)}>
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}

/** EmptyState component: a round icon, what is missing and the next step. */
export function Empty({ icon = "layers", title, description, actions, className }: {
  icon?: IconName; title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string;
}) {
  return (
    <div className={cx("bd-empty", className)}>
      <div className="bd-empty-icon"><Icon name={icon} size={24} /></div>
      <div className="bd-empty-title">{title}</div>
      {description ? <div className="bd-empty-desc">{description}</div> : null}
      {actions ? <div className="bd-row">{actions}</div> : null}
    </div>
  );
}

/* ---------------------------------------------------------------- navigation */

export interface TabItem<K extends string> {
  key: K;
  label: ReactNode;
  icon?: IconName;
  count?: number;
  /** For hub tabs that navigate (an href) instead of switching a view. */
  href?: string;
}

/**
 * Tabs component: pills, the selected one a raised surface chip. `hub` is the row of sibling pages
 * above the page header, `section` the view switch below it. Arrow keys move between tabs.
 */
export function Tabs<K extends string>({ items, value, onChange, variant = "section", label, className }: {
  items: Array<TabItem<K>>; value: K; onChange?: (key: K) => void; variant?: "hub" | "section" | "plain";
  label: string; className?: string;
}) {
  const refs = useRef<Array<HTMLElement | null>>([]);
  const onKeyDown = (event: KeyboardEvent, index: number) => {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (index + delta + items.length) % items.length;
    refs.current[next]?.focus();
    if (!items[next].href) onChange?.(items[next].key);
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      className={cx("bd-tabs", variant === "hub" && "jd-hub-tabs", variant === "section" && "jd-section-tabs", className)}
    >
      {items.map((item, index) => {
        const selected = item.key === value;
        const content = (
          <>
            {item.icon ? <Icon name={item.icon} /> : null}
            <span>{item.label}</span>
            {item.count !== undefined ? <span className="bd-tab-count">{item.count}</span> : null}
          </>
        );
        const common = {
          role: "tab",
          "aria-selected": selected,
          tabIndex: selected ? 0 : -1,
          className: "bd-tab",
          onKeyDown: (event: KeyboardEvent) => onKeyDown(event, index),
        } as const;
        return item.href ? (
          <a key={item.key} href={item.href} ref={(el) => { refs.current[index] = el; }} {...common}>{content}</a>
        ) : (
          <button key={item.key} type="button" ref={(el) => { refs.current[index] = el; }} {...common} onClick={() => onChange?.(item.key)}>
            {content}
          </button>
        );
      })}
    </div>
  );
}

export interface SegmentOption<K extends string> {
  key: K;
  label: ReactNode;
  icon?: IconName;
  disabled?: boolean;
}

/** Segmented component: a muted track; the chosen option is a raised chip (aria-pressed). */
export function Segmented<K extends string>({ options, value, onChange, label, size = "md", className }: {
  options: Array<SegmentOption<K>>; value: K; onChange: (key: K) => void; label: string; size?: "sm" | "md"; className?: string;
}) {
  return (
    <div role="group" aria-label={label} className={cx("bd-seg", size === "md" && "bd-seg--md", className)}>
      {options.map((option) => (
        <button
          key={option.key}
          type="button"
          aria-pressed={option.key === value}
          disabled={option.disabled}
          onClick={() => onChange(option.key)}
        >
          {option.icon ? <Icon name={option.icon} /> : null}
          {option.label}
        </button>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------- time */

/**
 * A time written the design's way: relative within 24 hours ("3 分钟前"), the full time otherwise,
 * with the full time on hover. Re-renders every 30 seconds so relative times stay true.
 */
export function RelativeTime({ value, className }: { value: string | number | Date | null | undefined; className?: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);
  const text = formatRelativeTime(value, now);
  if (!text) return null;
  const full = formatAbsoluteTime(value);
  const iso = value instanceof Date ? value.toISOString() : typeof value === "number" ? new Date(value).toISOString() : value ?? undefined;
  return <time className={cx("bd-num", className)} dateTime={iso} title={full}>{text}</time>;
}
