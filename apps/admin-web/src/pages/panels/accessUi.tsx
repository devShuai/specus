// Form controls and list states of the access pages (clients, messages, port mappings, HTTP routes,
// downloads), written with the design's Choice and EmptyState markup (bd-switch, bd-radio-cards,
// bd-check, bd-skeleton). The native inputs keep their roles: a switch is role="switch", a radio card
// is named by its bold title only and described by its one-line explanation.
import { useId, type ReactNode } from "react";
import { RelativeTime } from "../../components/ui";

const cx = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(" ");

/** Switch of the design: takes effect at once. Without a visible label pass ariaLabel. */
export function DesignSwitch({ checked, onChange, disabled, label, ariaLabel, className }: {
  checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean; label?: ReactNode; ariaLabel?: string; className?: string;
}) {
  return (
    <label className={cx("bd-switch acc-switch", disabled && "is-disabled", className)}>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="bd-switch-track" aria-hidden="true" />
      {label ? <span className="acc-switch-label">{label}</span> : null}
    </label>
  );
}

export interface RadioCardOption<K extends string> {
  key: K;
  title: string;
  description: ReactNode;
}

/** Radio cards of the design: a choice where each option needs one line of explanation. */
export function RadioCards<K extends string>({ legend, value, options, onChange, className }: {
  legend: string; value: K; options: Array<RadioCardOption<K>>; onChange: (key: K) => void; className?: string;
}) {
  const base = useId();
  return (
    <fieldset className={cx("jd-fieldset acc-radio-fieldset", className)}>
      <legend className="bd-label">{legend}</legend>
      <div className="bd-radio-cards acc-radio-cards">
        {options.map((option) => {
          const titleId = `${base}-${option.key}-title`;
          const descriptionId = `${base}-${option.key}-desc`;
          return (
            <label key={option.key} className="bd-radio-card">
              <input
                type="radio"
                name={base}
                value={option.key}
                checked={value === option.key}
                aria-labelledby={titleId}
                aria-describedby={descriptionId}
                onChange={() => onChange(option.key)}
              />
              <b id={titleId}>{option.title}</b>
              <span id={descriptionId}>{option.description}</span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

/** Checkbox of the design: a setting saved together with the rest of the form. */
export function DesignCheck({ checked, onChange, children, className }: {
  checked: boolean; onChange: (checked: boolean) => void; children: ReactNode; className?: string;
}) {
  return (
    <label className={cx("bd-check acc-check", className)}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span className="bd-check-box" aria-hidden="true" />
      <span>{children}</span>
    </label>
  );
}

/** A row of plain radios of the design (bd-check--radio) for short options. */
export function DesignRadioRow<K extends string>({ legend, value, options, onChange }: {
  legend: string; value: K | ""; options: Array<{ key: K; label: string }>; onChange: (key: K) => void;
}) {
  const name = useId();
  return (
    <fieldset className="jd-fieldset acc-radio-fieldset">
      <legend className="bd-label">{legend}</legend>
      <div className="acc-radio-row">
        {options.map((option) => (
          <label key={option.key} className="bd-check bd-check--radio acc-check">
            <input type="radio" name={name} value={option.key} checked={value === option.key} onChange={() => onChange(option.key)} />
            <span className="bd-check-box" aria-hidden="true" />
            <span>{option.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** Loading placeholder of a list: skeleton lines (not blinking) and what is being read. */
export function ListLoading({ label, rows = 3 }: { label: string; rows?: number }) {
  return (
    <div className="acc-loading" role="status">
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="bd-skeleton" style={{ ["--w" as string]: `${90 - index * 18}%`, ["--h" as string]: "14px" }} />
      ))}
      <span className="bd-skeleton-note">{label}</span>
    </div>
  );
}

/** A time the design's way (relative within 24 hours, full time on hover); "—" when there is none. */
export function TimeText({ value }: { value: string | null | undefined }) {
  return value ? <RelativeTime value={value} /> : <span className="jd-subtle">—</span>;
}

/** The muted "—" of an empty table cell. */
export function EmptyCell() {
  return <span className="jd-subtle">—</span>;
}
