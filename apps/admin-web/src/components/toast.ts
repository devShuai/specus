import { toast } from "@heroui/react";

type ToastKind = "success" | "error" | "info";
const DEDUPE_WINDOW_MS = 5000;
const recentToasts = new Map<string, number>();

// HeroUI 3 exposes one entry point per severity instead of a color prop.
const EMIT: Record<ToastKind, (message: string, options?: { timeout?: number }) => string> = {
  success: toast.success,
  error: toast.danger,
  info: toast.info,
};

// notify shows a HeroUI toast. Errors linger longer than success/info messages.
export function notify(message: string, kind: ToastKind = "success"): void {
  if (isDuplicateToast(message, kind)) {
    return;
  }
  EMIT[kind](message, { timeout: kind === "error" ? 8000 : 4000 });
}

// notifyError extracts a message from an unknown thrown value.
export function notifyError(error: unknown, fallback = "操作失败"): void {
  notify(error instanceof Error ? error.message : fallback, "error");
}

function isDuplicateToast(message: string, kind: ToastKind): boolean {
  const key = `${kind}:${message}`;
  const now = Date.now();
  const last = recentToasts.get(key);
  cleanupRecentToasts(now);
  if (last && now - last < DEDUPE_WINDOW_MS) {
    return true;
  }
  recentToasts.set(key, now);
  return false;
}

function cleanupRecentToasts(now: number): void {
  for (const [key, timestamp] of recentToasts) {
    if (now - timestamp > DEDUPE_WINDOW_MS) {
      recentToasts.delete(key);
    }
  }
}
