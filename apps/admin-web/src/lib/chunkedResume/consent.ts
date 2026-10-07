import {
  MAX_PARTIAL_BYTES_TOTAL,
  MAX_STORED_PARTIALS,
  MEMORY_LIMIT_BYTES,
  STORAGE_MARGIN_BYTES,
} from "./constants";

// Receiver consent for a new resumable offer (§6, vector section `consent`).

export type MemoryReason =
  | "PERSISTENCE_UNAVAILABLE"
  | "TOO_MANY_PARTIALS"
  | "PARTIAL_BYTES_LIMIT"
  | "INSUFFICIENT_STORAGE";

export type ConsentDecision =
  | { decision: "REJECT"; code: "NOT_ALLOWED" | "TRANSFER_ID_IN_USE" | MemoryReason }
  | { decision: "AUTO_ACCEPT_MEMORY" }
  | { decision: "PROMPT_PERSISTENT" }
  | { decision: "PROMPT_MEMORY"; memoryReason: MemoryReason };

export interface ConsentInput {
  policy: {
    autoAccept: boolean;
    /** Secure context, IndexedDB opens and navigator.storage.estimate() answers. */
    persistentAvailable: boolean;
    quotaBytes: number;
    usageBytes: number;
  };
  sizeBytes: number;
  /** Records still counted against the partial-data quota (not expired, failed, cancelled or saved). */
  livePartials: readonly { sizeBytes: number; receivedBytes: number }[];
  /**
   * Unfinished memory-mode receives of this page (RECEIVING or INTERRUPTED). Counted on their own:
   * they hold chunks in the tab, not on disk, and completed ones have dropped theirs.
   */
  memoryPartials: number;
  senderAllowed: boolean;
  transferIdInUse: boolean;
}

export function decideConsent(input: ConsentInput): ConsentDecision {
  const { policy, sizeBytes, livePartials } = input;
  if (!input.senderAllowed) {
    return { decision: "REJECT", code: "NOT_ALLOWED" };
  }
  if (input.transferIdInUse) {
    return { decision: "REJECT", code: "TRANSFER_ID_IN_USE" };
  }
  // Memory mode keeps an interrupted transfer's chunks for in-session retry, so it has a cap too.
  const memoryFull = input.memoryPartials >= MAX_STORED_PARTIALS;
  // Auto-accept never writes to disk: only memory mode is allowed without a click.
  if (policy.autoAccept && sizeBytes <= MEMORY_LIMIT_BYTES) {
    if (memoryFull) {
      return { decision: "REJECT", code: "TOO_MANY_PARTIALS" };
    }
    return { decision: "AUTO_ACCEPT_MEMORY" };
  }
  let reason: MemoryReason;
  const declared = livePartials.reduce((sum, item) => sum + item.sizeBytes, 0);
  const outstanding = livePartials.reduce((sum, item) => sum + Math.max(0, item.sizeBytes - item.receivedBytes), 0);
  if (!policy.persistentAvailable) {
    reason = "PERSISTENCE_UNAVAILABLE";
  } else if (livePartials.length >= MAX_STORED_PARTIALS) {
    reason = "TOO_MANY_PARTIALS";
  } else if (declared + sizeBytes > MAX_PARTIAL_BYTES_TOTAL) {
    reason = "PARTIAL_BYTES_LIMIT";
  } else if (sizeBytes + outstanding + STORAGE_MARGIN_BYTES > policy.quotaBytes - policy.usageBytes) {
    reason = "INSUFFICIENT_STORAGE";
  } else {
    return { decision: "PROMPT_PERSISTENT" };
  }
  if (sizeBytes <= MEMORY_LIMIT_BYTES) {
    if (memoryFull) {
      return { decision: "REJECT", code: "TOO_MANY_PARTIALS" };
    }
    return { decision: "PROMPT_MEMORY", memoryReason: reason };
  }
  return { decision: "REJECT", code: reason };
}
