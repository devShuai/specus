// What survives a cleanup pass (§10, vector section `cleanup`). Runs on page load, when the
// page returns to the foreground and before every new consent; nothing runs while closed.

export interface CleanupRecord {
  transferId: string;
  state: string;
  /** Local-clock instant in milliseconds. */
  expiresAt: number;
  saved: boolean;
}

export interface CleanupPlan {
  keepRecords: string[];
  deleteRecords: string[];
  /** Transfers whose chunks have no live record (deleted now, or orphans). */
  deleteChunksOf: string[];
}

export function isRecordDead(record: CleanupRecord, now: number): boolean {
  return now >= record.expiresAt
    || record.state === "FAILED"
    || record.state === "CANCELLED"
    || (record.state === "COMPLETE" && record.saved);
}

export function planCleanup(input: {
  now: number;
  records: readonly CleanupRecord[];
  chunkTransferIds: readonly string[];
}): CleanupPlan {
  const keep: string[] = [];
  const remove: string[] = [];
  for (const record of input.records) {
    (isRecordDead(record, input.now) ? remove : keep).push(record.transferId);
  }
  const kept = new Set(keep);
  const orphans = [...new Set(input.chunkTransferIds.filter((transferId) => !kept.has(transferId)))];
  return {
    keepRecords: keep.sort(),
    deleteRecords: remove.sort(),
    deleteChunksOf: orphans.sort(),
  };
}
