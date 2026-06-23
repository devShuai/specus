// Formatting helpers ported from the original vanilla SPA, preserving exact output.

export function formatBytes(bytes: number | null | undefined): string {
  const value = Number(bytes ?? 0);
  if (!Number.isFinite(value) || value <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = 0;
  let scaled = value;
  while (scaled >= 1024 && index < units.length - 1) {
    scaled /= 1024;
    index += 1;
  }
  const text = index === 0 ? String(Math.round(scaled)) : scaled.toFixed(2);
  return `${text} ${units[index]}`;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

// formatDuration renders the gap between two timestamps. When `to` is null the connection is
// still active, so the result is prefixed with "~" and computed against now.
export function formatDuration(
  from: string | null | undefined,
  to: string | null | undefined,
  nowMillis = Date.now(),
): string {
  if (!from) {
    return "-";
  }
  const start = new Date(from).getTime();
  if (Number.isNaN(start)) {
    return "-";
  }
  const active = !to;
  const end = active ? nowMillis : new Date(to as string).getTime();
  if (Number.isNaN(end)) {
    return "-";
  }
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  const text = humanizeSeconds(seconds);
  return active ? `~${text}` : text;
}

function humanizeSeconds(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m`;
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h`;
  }
  return `${Math.floor(seconds / 86400)}d`;
}

// formatSince renders an online client's elapsed time from its login epoch-ms.
export function formatSince(loginTimeMs: number | null | undefined, nowMillis = Date.now()): string {
  if (!loginTimeMs || loginTimeMs <= 0) {
    return "";
  }
  const seconds = Math.max(0, Math.floor((nowMillis - loginTimeMs) / 1000));
  return humanizeSeconds(seconds);
}
