// The part of RTCDataChannel the resumable transfer uses, so tests can run over a fake pair.

export interface BulkChannel {
  readonly readyState: string;
  bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  send(data: string | ArrayBuffer): void;
  addEventListener(type: "bufferedamountlow" | "close", listener: () => void): void;
  removeEventListener(type: "bufferedamountlow" | "close", listener: () => void): void;
}

export function sendJson(channel: BulkChannel, message: Record<string, unknown>): boolean {
  if (channel.readyState !== "open") {
    return false;
  }
  try {
    channel.send(JSON.stringify(message));
    return true;
  } catch {
    return false;
  }
}

export const BUFFER_HIGH_WATER_BYTES = 4 * 1024 * 1024;
export const BUFFER_LOW_THRESHOLD_BYTES = 1024 * 1024;

/** Resolves once bufferedAmount drops to the low threshold; rejects on close, abort or timeout. */
export function waitForBufferLow(channel: BulkChannel, timeoutMs: number, signal?: AbortSignal): Promise<void> {
  if (channel.bufferedAmount <= channel.bufferedAmountLowThreshold) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("DataChannel 发送缓冲区等待超时"));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      channel.removeEventListener("bufferedamountlow", onLow);
      channel.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const onLow = () => {
      cleanup();
      resolve();
    };
    const onClose = () => {
      cleanup();
      reject(new Error("DataChannel 已关闭"));
    };
    const onAbort = () => {
      cleanup();
      reject(new Error("文件发送已取消"));
    };
    channel.addEventListener("bufferedamountlow", onLow);
    channel.addEventListener("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
    } else if (channel.bufferedAmount <= channel.bufferedAmountLowThreshold) {
      onLow();
    }
  });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Control messages of §5 that belong to the resumable protocol (file-meta is routed by its `resume` field). */
export const RECEIVER_BOUND_KINDS = new Set(["resume-offer", "file-cancel", "transfer-error"]);
export const SENDER_BOUND_KINDS = new Set([
  "file-accept",
  "file-reject",
  "file-ready",
  "file-ack",
  "resume-state",
  "resume-reject",
  "resume-request",
  "chunk-ack",
  "chunk-nack",
  "transfer-complete",
  "transfer-error",
  "file-cancel",
]);
