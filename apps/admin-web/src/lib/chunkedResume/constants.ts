// Constants of the chunked resume contract (protocol/spec/chunked-resume.md §2 and §14).
// Both pages must agree on every value here; the vector test compares them with
// protocol/test-vectors/chunked-resume-v1.json.

export const KIB = 1024;
export const MIB = 1024 * KIB;
export const GIB = 1024 * MIB;

export const CHUNK_SIZE_MIN = 64 * KIB;
export const CHUNK_SIZE_MAX = 4 * MIB;
/** v1 always sends 1 MiB chunks; the receiver accepts any power of two in [64 KiB, 4 MiB]. */
export const CHUNK_SIZE_DEFAULT = 1 * MIB;
export const MAX_CHUNK_COUNT = 4096;
export const MAX_RESUMABLE_BYTES = 2 * GIB;
export const MEMORY_LIMIT_BYTES = 128 * MIB;
export const MAX_STORED_PARTIALS = 4;
export const MAX_PARTIAL_BYTES_TOTAL = 4 * GIB;
export const STORAGE_MARGIN_BYTES = 64 * MIB;
export const MAX_ACTIVE_RECEIVES = 2;
export const MAX_CHUNK_MISMATCHES_PER_SESSION = 3;
export const MAX_INTEGRITY_FAILURES = 16;
export const RESUME_TTL_SECONDS = 24 * 3600;
export const FRAME_HEADER_BYTES = 36;
export const FRAME_MAX_BYTES = 64 * KIB;
export const UNACKED_WINDOW_CHUNKS = 8;

/** In-session reconnects per transfer; the counter resets whenever a new chunk-ack arrives. */
export const MAX_SESSION_RECONNECTS = 5;
/** Backoff before reconnect attempt n (1-based): 1, 2, 4, 8, 16 s. */
export function reconnectBackoffMs(attempt: number): number {
  return Math.min(16, 2 ** Math.max(0, attempt - 1)) * 1000;
}
/** A resume-offer without an answer counts as UNKNOWN_TRANSFER (old page or wrong device). */
export const RESUME_OFFER_TIMEOUT_MS = 10_000;
