import { addToast } from "@heroui/react";

type ToastKind = "success" | "error" | "info";

const COLOR: Record<ToastKind, "success" | "danger" | "primary"> = {
  success: "success",
  error: "danger",
  info: "primary",
};

// notify shows a HeroUI toast. Errors linger longer than success/info messages.
export function notify(message: string, kind: ToastKind = "success"): void {
  addToast({
    title: message,
    color: COLOR[kind],
    timeout: kind === "error" ? 8000 : 4000,
  });
}

// notifyError extracts a message from an unknown thrown value.
export function notifyError(error: unknown, fallback = "操作失败"): void {
  notify(error instanceof Error ? error.message : fallback, "error");
}
