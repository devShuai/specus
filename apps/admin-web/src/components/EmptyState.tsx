import { Button } from "@heroui/react";

export type EmptyStateIcon = "clients" | "traffic" | "peer" | "connections" | "generic";

export interface EmptyStateProps {
  icon?: EmptyStateIcon; title: string; description?: string;
  actionLabel?: string; onAction?: () => void; className?: string;
}

export function EmptyState({ icon = "generic", title, description, actionLabel, onAction, className = "" }: EmptyStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center py-12 text-center ${className}`}>
      <div className="mb-4 text-default-300">{Ill(icon)}</div>
      <h3 className="text-small font-semibold text-default-600">{title}</h3>
      {description && <p className="mt-1.5 max-w-xs text-tiny text-default-400">{description}</p>}
      {actionLabel && onAction && <Button className="mt-4" color="primary" size="sm" variant="flat" onPress={onAction}>{actionLabel}</Button>}
    </div>
  );
}

const S = { fill:"none",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round" as const,strokeLinejoin:"round" as const };
function Ill(k: EmptyStateIcon) {
  const c = "h-20 w-20";
  switch(k){
    case "clients": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 80 80"><rect height="38" rx="4" width="52" x="14" y="16"/><line x1="40" x2="40" y1="54" y2="62"/><line x1="28" x2="52" y1="62" y2="62"/><circle cx="58" cy="14" fill="currentColor" r="12" stroke="none"/><line stroke="white" x1="58" x2="58" y1="8" y2="20"/><line stroke="white" x1="52" x2="64" y1="14" y2="14"/></svg>;
    case "traffic": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 80 80"><line x1="16" x2="16" y1="12" y2="68"/><line x1="16" x2="72" y1="68" y2="68"/><rect height="0" rx="2" width="12" x="22" y="68"/><rect height="0" rx="2" width="12" x="38" y="68"/><rect height="0" rx="2" width="12" x="54" y="68"/><line strokeDasharray="3 3" x1="28" x2="28" y1="28" y2="64"/><line strokeDasharray="3 3" x1="44" x2="44" y1="28" y2="64"/><line strokeDasharray="3 3" x1="60" x2="60" y1="28" y2="64"/></svg>;
    case "peer": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 80 80"><circle cx="26" cy="26" r="14"/><circle cx="54" cy="54" r="14"/><line x1="38" x2="44" y1="34" y2="46"/><circle cx="26" cy="26" fill="currentColor" r="3" stroke="none"/><circle cx="54" cy="54" fill="currentColor" r="3" stroke="none"/><text dominantBaseline="central" fill="currentColor" fontSize="14" fontWeight="600" stroke="none" textAnchor="middle" x="54" y="54">?</text></svg>;
    case "connections": return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 80 80"><rect height="20" rx="4" width="20" x="10" y="30"/><rect height="20" rx="4" width="20" x="50" y="30"/><line x1="30" x2="50" y1="36" y2="36"/><polyline points="44,30 50,36 44,42"/><line strokeDasharray="4 3" x1="30" x2="50" y1="46" y2="46"/><polyline points="36,40 30,46 36,52"/></svg>;
    default: return <svg aria-hidden="true" className={c} {...S} viewBox="0 0 80 80"><path d="M16 24 L16 66 L64 66 L64 24 Z"/><path d="M16 24 L38 14 L64 24"/><line x1="40" x2="40" y1="38" y2="52"/><line x1="32" x2="48" y1="45" y2="45"/></svg>;
  }
}
