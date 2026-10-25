// Small pieces in the design's own markup (Choice, Input, Table, code card) shared by the private-mesh,
// system, product-metrics and help pages. Styles: src/styles/area-mesh-system.css and liquid-glass.css.
import { useId, useState, type ReactNode } from "react";
import { Icon, Tag, type Tone } from "../../components/ui";
import { copyTextWithFeedback } from "../../lib/clipboard";

const cx = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(" ");

/** HeroUI color names used by the page models, mapped onto the Tag tones. */
export type ModelColor = "default" | "primary" | "secondary" | "success" | "warning" | "danger";

export function toneOf(color: ModelColor | string | null | undefined): Tone {
  switch (color) {
    case "success":
    case "warning":
    case "danger":
      return color;
    case "primary":
      return "info";
    default:
      return "neutral";
  }
}

/** A Tag colored by a model's HeroUI color name. */
export function ModelTag({ color, children, title, className }: { color: ModelColor | string; children: ReactNode; title?: string; className?: string }) {
  return <Tag tone={toneOf(color)} title={title} className={className}>{children}</Tag>;
}

/** Choice: a switch (bd-switch) over a native checkbox with role="switch". Takes effect at once. */
export function Toggle({ checked, onChange, disabled, label, describedBy, busy, children, className }: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Accessible name when the switch has no visible text. */
  label?: string;
  describedBy?: string;
  busy?: boolean;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <label className={cx("bd-switch ms-switch", disabled && "is-disabled", className)}>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        aria-label={label}
        aria-describedby={describedBy}
        aria-busy={busy || undefined}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="bd-switch-track" aria-hidden="true" />
      {children ? <span className="ms-switch-text">{children}</span> : null}
    </label>
  );
}

/** Choice: a checkbox (bd-check) for options saved together with a form. */
export function Check({ checked, onChange, disabled, children, label }: {
  checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; children?: ReactNode; label?: string;
}) {
  return (
    <label className={cx("bd-check ms-check", disabled && "is-disabled")}>
      <input type="checkbox" checked={checked} disabled={disabled} aria-label={label} onChange={(event) => onChange(event.target.checked)} />
      <span className="bd-check-box" aria-hidden="true" />
      {children}
    </label>
  );
}

export interface RadioCardOption<V extends string> {
  value: V;
  title: ReactNode;
  description: ReactNode;
  disabled?: boolean;
}

/** Choice: radio cards, two or more options that each need a sentence of explanation. */
export function RadioCards<V extends string>({ legend, value, onChange, options, disabled, help, columns }: {
  legend: ReactNode; value: V; onChange: (value: V) => void; options: Array<RadioCardOption<V>>;
  disabled?: boolean; help?: ReactNode; columns?: number;
}) {
  const name = useId();
  return (
    <fieldset className="jd-fieldset ms-fieldset" disabled={disabled}>
      <legend className="bd-label">{legend}</legend>
      <div className="bd-radio-cards" style={columns ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` } : undefined}>
        {options.map((option) => (
          <label key={option.value} className={cx("bd-radio-card", option.disabled && "is-disabled")}>
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={value === option.value}
              disabled={option.disabled}
              onChange={() => onChange(option.value)}
            />
            <b>{option.title}</b>
            <span>{option.description}</span>
          </label>
        ))}
      </div>
      {help ? <div className="bd-help">{help}</div> : null}
    </fieldset>
  );
}

/** A set of checkboxes standing in for a multiple select (devices allowed, consumers). */
export function CheckGroup({ legend, options, values, onChange, help, empty, disabled }: {
  legend: ReactNode;
  options: Array<{ value: string; label: ReactNode }>;
  values: string[];
  onChange: (values: string[]) => void;
  help?: ReactNode;
  empty?: ReactNode;
  disabled?: boolean;
}) {
  const toggle = (value: string, checked: boolean) => {
    const next = checked ? [...values.filter((item) => item !== value), value] : values.filter((item) => item !== value);
    onChange(next);
  };
  return (
    <fieldset className="jd-fieldset ms-fieldset" disabled={disabled}>
      <legend className="bd-label">{legend}</legend>
      {options.length === 0 ? (
        <div className="bd-help">{empty ?? "没有可选的设备"}</div>
      ) : (
        <div className="ms-check-grid">
          {options.map((option) => (
            <Check key={option.value} checked={values.includes(option.value)} onChange={(checked) => toggle(option.value, checked)}>
              <span className="jd-ellipsis">{option.label}</span>
            </Check>
          ))}
        </div>
      )}
      {help ? <div className="bd-help">{help}</div> : null}
    </fieldset>
  );
}

/** Input: label, control and one line of help or the error. */
export function Field({ label, help, error, required, optional, children, htmlFor, className }: {
  label: ReactNode; help?: ReactNode; error?: ReactNode; required?: boolean; optional?: boolean;
  children: ReactNode; htmlFor: string; className?: string;
}) {
  return (
    <div className={cx("bd-field", className)}>
      <label className="bd-label" htmlFor={htmlFor}>
        {label}
        {required ? <span className="bd-req" aria-hidden="true">*</span> : null}
        {optional ? <span className="bd-form-opt">可选</span> : null}
      </label>
      {children}
      {error ? <div className="bd-help bd-help--error">{error}</div> : help ? <div className="bd-help">{help}</div> : null}
    </div>
  );
}

/** A text input in the design's markup. */
export function TextField({ label, value, onChange, help, error, required, optional, type = "text", placeholder, disabled, autoComplete, inputMode, maxLength, min, className, unit, ariaLabel }: {
  label: ReactNode; value: string; onChange: (value: string) => void; help?: ReactNode; error?: ReactNode;
  required?: boolean; optional?: boolean; type?: string; placeholder?: string; disabled?: boolean; autoComplete?: string;
  inputMode?: "numeric" | "text" | "url"; maxLength?: number; min?: number; className?: string; unit?: string; ariaLabel?: string;
}) {
  const id = useId();
  const input = (
    <input
      id={id}
      className="bd-input"
      type={type}
      value={value}
      placeholder={placeholder}
      disabled={disabled}
      required={required}
      autoComplete={autoComplete}
      inputMode={inputMode}
      maxLength={maxLength}
      min={min}
      aria-label={ariaLabel}
      aria-invalid={error ? true : undefined}
      onChange={(event) => onChange(event.target.value)}
    />
  );
  return (
    <Field label={label} help={help} error={error} required={required} optional={optional} htmlFor={id} className={className}>
      {unit ? <div className="bd-input-group">{input}<span className="bd-addon">{unit}</span></div> : input}
    </Field>
  );
}

/** A native select in the design's markup. */
export function SelectField<V extends string>({ label, value, onChange, options, help, disabled, placeholder, className }: {
  label: ReactNode; value: V | ""; onChange: (value: V) => void;
  options: Array<{ value: V; label: string; disabled?: boolean }>;
  help?: ReactNode; disabled?: boolean; placeholder?: string; className?: string;
}) {
  const id = useId();
  return (
    <Field label={label} help={help} htmlFor={id} className={className}>
      <select id={id} className="bd-select" value={value} disabled={disabled} onChange={(event) => onChange(event.target.value as V)}>
        {placeholder !== undefined ? <option value="" disabled>{placeholder}</option> : null}
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>{option.label}</option>
        ))}
      </select>
    </Field>
  );
}

/** A row inside a settings card: what the setting does on the left, the switch on the right. */
export function SettingRow({ title, description, descriptionId, control, children }: {
  title: ReactNode; description?: ReactNode; descriptionId?: string; control: ReactNode; children?: ReactNode;
}) {
  return (
    <div className="ms-setting">
      <div className="ms-setting-text">
        <div className="ms-setting-title">{title}</div>
        {description ? <p className="ms-setting-desc" id={descriptionId}>{description}</p> : null}
        {children}
      </div>
      <div className="ms-setting-control">{control}</div>
    </div>
  );
}

/** A table row standing for a loading or empty table (spans every column). */
export function TableStateRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr className="ms-table-state">
      <td colSpan={colSpan}>{children}</td>
    </tr>
  );
}

export function TableLoadingRow({ colSpan, label = "正在加载…" }: { colSpan: number; label?: string }) {
  return (
    <TableStateRow colSpan={colSpan}>
      <span className="ms-loading" role="status"><span className="ms-spinner" aria-hidden="true" />{label}</span>
    </TableStateRow>
  );
}

/** A code card: language, the code and a copy button. */
export function CodeCard({ language, code, title }: { language: string; code: string; title?: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    const ok = await copyTextWithFeedback(code, "已复制到剪贴板");
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  };
  return (
    <figure className="ms-code">
      <figcaption className="ms-code-head">
        <span className="ms-code-lang">{title ?? language}</span>
        <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm ms-code-copy" aria-label={copied ? "已复制" : `复制${title ?? ` ${language} `}代码`} onClick={() => void onCopy()}>
          <Icon name={copied ? "check" : "copy"} size={14} />
          <span>{copied ? "已复制" : "复制"}</span>
        </button>
      </figcaption>
      <pre className="ms-code-body"><code className={`language-${language}`}>{code}</code></pre>
    </figure>
  );
}

/** Inline code in running text. */
export function InlineCode({ children }: { children: ReactNode }) {
  return <code className="ms-inline-code">{children}</code>;
}

/** A collapsible row (details/summary) in the design's fold style. */
export function Fold({ title, icon, children, defaultOpen, meta }: {
  title: ReactNode; icon?: Parameters<typeof Icon>[0]["name"]; children: ReactNode; defaultOpen?: boolean; meta?: ReactNode;
}) {
  return (
    <details className="ms-fold" open={defaultOpen}>
      <summary className="ms-fold-head">
        {icon ? <Icon name={icon} size={18} /> : null}
        <span className="ms-fold-title">{title}</span>
        {meta ? <span className="ms-fold-meta">{meta}</span> : null}
        <Icon name="chevron-down" size={18} className="ms-fold-chevron" />
      </summary>
      <div className="ms-fold-body">{children}</div>
    </details>
  );
}

/** A description list (bd-desc) that leaves out the items without data. */
export function DescList({ items, cols = 3, className }: {
  items: Array<{ label: ReactNode; value: ReactNode; key?: string } | null | false | undefined>;
  cols?: number; className?: string;
}) {
  const shown = items.filter((item): item is { label: ReactNode; value: ReactNode; key?: string } =>
    Boolean(item) && (item as { value: ReactNode }).value !== null && (item as { value: ReactNode }).value !== undefined && (item as { value: ReactNode }).value !== "");
  return (
    <dl className={cx("bd-desc ms-desc", className)} style={{ ["--cols" as string]: cols }}>
      {shown.map((item, index) => (
        <div key={item.key ?? index}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
