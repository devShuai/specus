import { MAX_ACTIVE_RECEIVES } from "./constants";
import { ChunkBitmap, resumeProgress } from "./bitmap";

// Receiver's answer to a resume-offer (§8, vector section `resume`).

export type ResumeRejectCode = "UNKNOWN_TRANSFER" | "EXPIRED" | "MANIFEST_CHANGED" | "NOT_ALLOWED" | "BUSY";

export interface ResumeRecordView {
  transferId: string;
  resumeToken: string;
  manifestDigest: string;
  /** Local-clock instant in milliseconds. */
  expiresAt: number;
  state: string;
  have: ChunkBitmap;
  hashesComplete: boolean;
  sizeBytes: number;
  chunkSize: number;
  chunkCount: number;
}

export interface ResumeOfferInput {
  transferId: unknown;
  resumeToken: unknown;
  manifestDigest: unknown;
}

export type ResumeDecision =
  | { result: "REJECT"; code: ResumeRejectCode }
  | {
    result: "RESUME";
    have: string;
    needHashes: boolean;
    complete: boolean;
    ttlSeconds: number;
    firstMissing: number | null;
    resumeOffset: number;
    receivedBytes: number;
    missing: number[];
  };

export function decideResume(input: {
  record: ResumeRecordView | null;
  offer: ResumeOfferInput;
  now: number;
  senderAllowed: boolean;
  /** Active receive sessions of other transfers. */
  otherActiveSessions: number;
}): ResumeDecision {
  const { record, offer, now } = input;
  // A wrong token is indistinguishable from an unknown transfer and is checked before
  // anything that would reveal expiry or a manifest change.
  if (!record || record.state === "FAILED" || record.state === "CANCELLED"
    || record.transferId !== offer.transferId || record.resumeToken !== offer.resumeToken) {
    return { result: "REJECT", code: "UNKNOWN_TRANSFER" };
  }
  if (now >= record.expiresAt) {
    return { result: "REJECT", code: "EXPIRED" };
  }
  if (record.manifestDigest !== offer.manifestDigest) {
    return { result: "REJECT", code: "MANIFEST_CHANGED" };
  }
  if (!input.senderAllowed) {
    return { result: "REJECT", code: "NOT_ALLOWED" };
  }
  const complete = record.state === "COMPLETE";
  if (!complete && input.otherActiveSessions >= MAX_ACTIVE_RECEIVES) {
    return { result: "REJECT", code: "BUSY" };
  }
  const progress = resumeProgress(record, record.have);
  return {
    result: "RESUME",
    have: record.have.encode(),
    needHashes: !record.hashesComplete,
    complete,
    ttlSeconds: Math.max(0, Math.floor((record.expiresAt - now) / 1000)),
    firstMissing: progress.firstMissing,
    resumeOffset: progress.resumeOffset,
    receivedBytes: progress.receivedBytes,
    missing: progress.missing,
  };
}
