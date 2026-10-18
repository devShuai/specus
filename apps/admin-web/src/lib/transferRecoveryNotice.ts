import type { FileDeliveryMode } from "./transferPreflight";

/** Describe recovery without promising persistence for drafts, cloud uploads or memory receives. */
export function transferRecoveryNotice(mode: FileDeliveryMode, resumable: boolean): string {
  if (mode === "device" && resumable) {
    return "文件草稿不会在刷新后恢复。设备传输中，对方确认写入本机浏览器存储的接收，可在同意后 24 小时内续传；若发送方刷新，需要重新选择同一文件。自动接收或仅保存在内存中的接收，刷新后要重新发送。";
  }
  return "文件草稿不会在刷新后恢复。刷新或关闭页面会中断当前传输，不能恢复本次进度。";
}
