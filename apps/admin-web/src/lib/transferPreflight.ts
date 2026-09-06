export const MAX_QUEUED_FILE_TRANSFERS = 40;
export type FileDeliveryMode = "device" | "link";

export interface FilePreflightInput {
  files: readonly { name: string; size: number }[];
  mode: FileDeliveryMode;
  memoryLimitBytes: number;
  queuedCount: number;
  signedIn: boolean;
  rtcSupported: boolean;
  recipientOnline: boolean;
  discoveryOnline: boolean;
  writable: boolean;
  scopeCurrent: boolean;
}

/** Metadata-only check: never hash, read file bytes, reserve quota or start a transfer here. */
export function checkFilePreflight(input: FilePreflightInput) {
  const totalBytes = input.files.reduce((sum, file) => sum + file.size, 0);
  const oversized = input.files.filter((file) => file.size > input.memoryLimitBytes);
  const errors: string[] = [];
  if (!input.scopeCurrent) errors.push("房间已变化，请取消后重新选择文件。");
  if (!input.writable) errors.push("当前为只读访客，不能发送文件。");
  if (input.files.length === 0) errors.push("请选择文件。");
  if (input.files.some((file) => !Number.isSafeInteger(file.size) || file.size <= 0) || !Number.isSafeInteger(totalBytes)) {
    errors.push("包含空文件或无法识别大小的文件，请移除后重试。");
  }
  if (input.files.length + input.queuedCount > MAX_QUEUED_FILE_TRANSFERS) {
    errors.push(`最多保留 ${MAX_QUEUED_FILE_TRANSFERS} 个进行中的发送任务，请减少文件或等待任务完成。`);
  }
  if (input.mode === "device") {
    if (!input.recipientOnline) errors.push("原接收设备已离线或未选择；不会自动换成其他设备，请取消后重新选择。");
    if (!input.discoveryOnline) errors.push("房间连接尚未恢复，请等待连接恢复后再确认。");
    if (!input.rtcSupported) errors.push("当前浏览器不支持设备文件传输，请使用支持 WebRTC 的浏览器，或明确改为生成文件链接。");
    if (oversized.length > 0) errors.push(`${oversized.length} 个文件超过设备传输的单文件内存上限，请移除，或明确改为生成文件链接。`);
  } else if (!input.signedIn) {
    errors.push("生成文件链接需要登录；登录后仍需重新确认上传。");
  }
  return { totalBytes, oversized, errors, canSend: errors.length === 0 };
}

/** A retry must not gain cloud permission just because the user has since signed in. */
export function cloudFallbackPermitted(consented: boolean, signedIn: boolean, sameLan: boolean): boolean {
  return consented && signedIn && !sameLan;
}

export function hasVolatileFileWork(input: {
  draftCount: number; outgoingCount: number; receivingCount: number; pendingCount: number; unsavedIncomingCount: number;
}): boolean {
  return Object.values(input).some((count) => count > 0);
}

/** Retain every in-flight task even when recent completed history fills the list. */
export function retainVisibleFileActivities<T extends { status: string }>(items: readonly T[], limit: number): T[] {
  const active = (item: T) => ["queued", "connecting", "sending"].includes(item.status);
  let historySlots = Math.max(0, limit - items.filter(active).length);
  return items.filter((item) => active(item) || historySlots-- > 0);
}
