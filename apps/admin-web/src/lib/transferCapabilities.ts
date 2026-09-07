export interface TransferCapabilities {
  schemaVersion: 1;
  checkedAt: string;
  storageEnabled: boolean;
  maxAttachmentBytes: number;
  retentionHours: number;
  storageQuotaBytes: number;
  storageUsedBytes: number;
  storageRemainingBytes: number;
  monthlyDownloadQuotaBytes: number;
  monthlyDownloadUsedBytes: number;
  monthlyDownloadRemainingBytes: number;
  downloadUsageMonth: string;
  downloadResetsAt: string;
  downloadGrantSingleUse: true;
}

/** Old servers may return HTML/partial data. Unknown must never mean unlimited or zero usage. */
export function parseTransferCapabilities(value: unknown): TransferCapabilities {
  if (!value || typeof value !== "object") throw new Error("服务端尚未提供可识别的额度信息");
  const v = value as Record<string, unknown>;
  const bytes = ["maxAttachmentBytes", "storageQuotaBytes", "storageUsedBytes", "storageRemainingBytes",
    "monthlyDownloadQuotaBytes", "monthlyDownloadUsedBytes", "monthlyDownloadRemainingBytes", "retentionHours"];
  if (v.schemaVersion !== 1 || typeof v.storageEnabled !== "boolean" || v.downloadGrantSingleUse !== true
    || bytes.some((key) => !Number.isSafeInteger(v[key]) || (v[key] as number) < 0)
    || (v.retentionHours as number) < 1 || (v.storageQuotaBytes as number) < 1 || (v.monthlyDownloadQuotaBytes as number) < 1
    || typeof v.checkedAt !== "string" || !Number.isFinite(Date.parse(v.checkedAt))
    || typeof v.downloadResetsAt !== "string" || !Number.isFinite(Date.parse(v.downloadResetsAt))
    || typeof v.downloadUsageMonth !== "string" || !/^\d{4}-(0[1-9]|1[0-2])$/.test(v.downloadUsageMonth)
    || v.storageRemainingBytes !== Math.max(0, (v.storageQuotaBytes as number) - (v.storageUsedBytes as number))
    || v.monthlyDownloadRemainingBytes !== Math.max(0, (v.monthlyDownloadQuotaBytes as number) - (v.monthlyDownloadUsedBytes as number))) {
    throw new Error("服务端额度信息不完整，暂时无法核验");
  }
  const checked = new Date(v.checkedAt as string);
  const reset = Date.UTC(checked.getUTCFullYear(), checked.getUTCMonth() + 1, 1);
  if (v.downloadUsageMonth !== checked.toISOString().slice(0, 7) || Date.parse(v.downloadResetsAt as string) !== reset) {
    throw new Error("服务端额度周期信息不一致，暂时无法核验");
  }
  return v as unknown as TransferCapabilities;
}

export function cloudPreflightErrors(files: readonly { size: number }[], snapshot?: TransferCapabilities | null): string[] {
  if (!snapshot) return [];
  if (!snapshot.storageEnabled) return ["此服务端未启用临时存储，请改用设备传输。"];
  const errors: string[] = [];
  if (files.some((file) => file.size > snapshot.maxAttachmentBytes)) errors.push("有文件超过服务端单文件上传上限，请移除或改用其他方式。");
  if (files.reduce((sum, file) => sum + file.size, 0) > snapshot.storageRemainingBytes) errors.push("本批文件超过账号剩余存储额度，请减少文件或等待旧文件过期后刷新额度。");
  return errors;
}
