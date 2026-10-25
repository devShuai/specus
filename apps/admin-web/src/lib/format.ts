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

const pad2 = (value: number) => String(value).padStart(2, "0");

// formatAbsoluteTime renders the design's full timestamp, "2026-10-23 16:02".
export function formatAbsoluteTime(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined || value === "") {
    return "";
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return typeof value === "string" ? value : "";
  }
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
}

// formatRelativeTime follows the design's copy rule: within 24 hours a relative time ("3 分钟前",
// "40 分钟后", "刚刚", "马上"), otherwise the full timestamp.
export function formatRelativeTime(value: string | number | Date | null | undefined, nowMillis = Date.now()): string {
  if (value === null || value === undefined || value === "") {
    return "";
  }
  const date = value instanceof Date ? value : new Date(value);
  const time = date.getTime();
  if (Number.isNaN(time)) {
    return typeof value === "string" ? value : "";
  }
  const delta = time - nowMillis;
  const seconds = Math.round(Math.abs(delta) / 1000);
  if (seconds >= 86400) {
    return formatAbsoluteTime(date);
  }
  const future = delta > 0;
  if (seconds < 60) {
    return future ? "马上" : "刚刚";
  }
  const amount = seconds < 3600 ? `${Math.floor(seconds / 60)} 分钟` : `${Math.floor(seconds / 3600)} 小时`;
  return future ? `${amount}后` : `${amount}前`;
}

// formatElapsed renders a span of time the way the design writes durations: "2 秒", "3 分 20 秒",
// "1 小时 5 分", "2 天 3 小时".
export function formatElapsed(totalSeconds: number | null | undefined): string {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds) || totalSeconds < 0) {
    return "";
  }
  const seconds = Math.floor(totalSeconds);
  if (seconds < 60) {
    return `${seconds} 秒`;
  }
  if (seconds < 3600) {
    const rest = seconds % 60;
    return rest ? `${Math.floor(seconds / 60)} 分 ${rest} 秒` : `${Math.floor(seconds / 60)} 分`;
  }
  if (seconds < 86400) {
    const minutes = Math.floor((seconds % 3600) / 60);
    return minutes ? `${Math.floor(seconds / 3600)} 小时 ${minutes} 分` : `${Math.floor(seconds / 3600)} 小时`;
  }
  const hours = Math.floor((seconds % 86400) / 3600);
  return hours ? `${Math.floor(seconds / 86400)} 天 ${hours} 小时` : `${Math.floor(seconds / 86400)} 天`;
}
