import { Button } from "@heroui/react";

export type EmptyStateIcon = "clients" | "traffic" | "peer" | "connections" | "generic";

export interface EmptyStateProps {
  icon?: EmptyStateIcon; title: string; description?: string;
  actionLabel?: string; onAction?: () => void; className?: string;
}

export function EmptyState({ icon = "generic", title, description, actionLabel, onAction, className = "" }: EmptyStateProps) {
  return (
    <div className={`bd-empty ${className}`}>
      <div className="bd-empty-icon">{Ill(icon)}</div>
      <h3 className="bd-empty-title">{title}</h3>
      {description && <p className="bd-empty-desc">{description}</p>}
      {actionLabel && onAction && <div className="bd-row"><Button color="primary" size="sm" onPress={onAction}>{actionLabel}</Button></div>}
    </div>
  );
}

// Line icons of the design (24 canvas, 1.75 stroke) inside the empty state's round badge.
const S = { fill:"none",stroke:"currentColor",strokeWidth:"1.75",strokeLinecap:"round" as const,strokeLinejoin:"round" as const };
function Ill(k: EmptyStateIcon) {
  const c = "h-6 w-6";
  switch(k){
    case "clients": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 24 24"><rect height="13" rx="2" width="18" x="3" y="3"/><path d="M12 16v4M8 20h8"/></svg>;
    case "traffic": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 24 24"><path d="M4 20V8M10 20V4M16 20v-8M20 20H3"/></svg>;
    case "peer": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 24 24"><circle cx="7" cy="7" r="3"/><circle cx="17" cy="17" r="3"/><path d="M9.5 9.5l5 5"/></svg>;
    case "connections": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 24 24"><path d="M4 8h13M13 4l4 4-4 4M20 16H7M11 12l-4 4 4 4"/></svg>;
    default: return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 24 24"><path d="M3 7.5 12 3l9 4.5v9L12 21l-9-4.5z"/><path d="M3 7.5 12 12l9-4.5M12 12v9"/></svg>;
  }
}
