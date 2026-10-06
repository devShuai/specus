import { MAX_SESSION_RECONNECTS, reconnectBackoffMs } from "./constants";
import { ChunkBitmap } from "./bitmap";
import { randomHex128, type Digest } from "./bytes";
import type { BulkChannel } from "./channel";
import type { Manifest } from "./manifest";
import {
  createOutgoing,
  runSenderSession,
  SenderError,
  type OutgoingTransfer,
  type SenderRouter,
} from "./senderController";

// One sendDirect call: open a channel, run sessions, and reconnect inside the page (§9) up to
// MAX_SESSION_RECONNECTS times with 1-16 s backoff; any newly acknowledged chunk resets the count.

export interface OpenedChannel {
  channel: BulkChannel;
  peerId: string;
  frameBytes: number;
  ensureCurrent(): void;
}

export interface ResumableSendOptions {
  source: Blob;
  lastModified: number;
  targetPeerId: string;
  targetName: string;
  /** A transfer this page already started for the same file (or restored after a reload). */
  existing: OutgoingTransfer | null;
  router: SenderRouter;
  digest: Digest;
  signal?: AbortSignal;
  now(): number;
  openChannel(): Promise<OpenedChannel>;
  buildManifest(): Promise<Manifest>;
  /** Reconnect after an open failure too (false for direct mode: the caller then tries relay). */
  retryOpenFailures: boolean;
  /** Resolves after `ms`, or early when the receiver asks for a resume. */
  sleep(ms: number): Promise<void>;
  onTransfer(transfer: OutgoingTransfer): void;
  onPhase(phase: "waiting" | "sending"): void;
  onProgress(transfer: OutgoingTransfer): void;
  onAccepted(transfer: OutgoingTransfer): Promise<void>;
  /** The transfer is over for good (complete or dropped): forget it and its persisted record. */
  onFinished(transfer: OutgoingTransfer, outcome: "complete" | "dropped"): void;
  onReconnect?(attempt: number, error: SenderError | Error): void;
}

export type ResumableSendResult =
  | { kind: "complete"; transfer: OutgoingTransfer }
  | { kind: "legacy"; transfer: OutgoingTransfer; channel: OpenedChannel };

/** Same manifest, fresh identity: used when the receiver no longer knows the transfer. */
export function renewOutgoing(transfer: OutgoingTransfer): OutgoingTransfer {
  return {
    ...transfer,
    transferId: randomHex128(),
    resumeToken: null,
    storage: null,
    expiresAt: null,
    acked: new ChunkBitmap(transfer.manifest.chunkCount),
    confirmedPeers: new Set(),
    offered: false,
  };
}

export async function sendResumable(options: ResumableSendOptions): Promise<ResumableSendResult> {
  let transfer = options.existing;
  let attempts = 0;
  let restarted = false;
  let sessions = 0;

  const backoff = async (error: SenderError | Error): Promise<boolean> => {
    attempts += 1;
    if (attempts > MAX_SESSION_RECONNECTS) return false;
    options.onReconnect?.(attempts, error);
    await options.sleep(reconnectBackoffMs(attempts));
    if (options.signal?.aborted) throw options.signal.reason instanceof Error ? options.signal.reason : new Error("文件发送已取消");
    return true;
  };

  for (;;) {
    if (options.signal?.aborted) {
      throw options.signal.reason instanceof Error ? options.signal.reason : new Error("文件发送已取消");
    }
    let opened: OpenedChannel;
    try {
      opened = await options.openChannel();
    } catch (error) {
      const failure = error instanceof Error ? error : new Error("DataChannel 打开失败");
      if (sessions === 0 || !transfer?.resumeToken || !options.retryOpenFailures || !(await backoff(failure))) {
        throw failure;
      }
      continue;
    }
    sessions += 1;
    if (!transfer) {
      // Hash after the channel opens so an unreachable peer fails fast.
      transfer = createOutgoing(await options.buildManifest(), options.source, {
        peerId: opened.peerId,
        name: options.targetName,
        lastModified: options.lastModified,
      });
      opened.ensureCurrent();
      options.onTransfer(transfer);
    } else if (!transfer.resumeToken && transfer.offered) {
      // An offer whose file-accept never arrived: offer again under a fresh transferId so a
      // record the receiver may have created for the lost answer cannot collide.
      const previous = transfer;
      transfer = renewOutgoing(previous);
      transfer.source = options.source;
      options.onFinished(previous, "dropped");
      options.onTransfer(transfer);
    } else {
      transfer.source = options.source;
    }
    const current = transfer;
    const ackedBefore = current.acked.count();
    try {
      const outcome = await runSenderSession(current, {
        router: options.router,
        channel: opened.channel,
        peerId: opened.peerId,
        frameBytes: opened.frameBytes,
        digest: options.digest,
        now: options.now,
        signal: options.signal,
        ensureCurrent: opened.ensureCurrent,
        onPhase: options.onPhase,
        onProgress: options.onProgress,
        onAccepted: options.onAccepted,
      });
      if (outcome.kind === "legacy") {
        options.onFinished(current, "dropped");
        return { kind: "legacy", transfer: current, channel: opened };
      }
      options.onFinished(current, "complete");
      return { kind: "complete", transfer: current };
    } catch (error) {
      if (!(error instanceof SenderError)) {
        throw error;
      }
      if (error.failure === "drop") {
        options.onFinished(current, "dropped");
        throw error;
      }
      if (error.failure === "stop") {
        throw error;
      }
      if (error.failure === "restart") {
        if (restarted) throw error;
        restarted = true;
        attempts = 0;
        options.onFinished(current, "dropped");
        transfer = renewOutgoing(current);
        options.onTransfer(transfer);
        continue;
      }
      if (current.acked.count() > ackedBefore) {
        attempts = 0; // progress resets the reconnect budget
      }
      if (!(await backoff(error))) {
        throw error;
      }
    }
  }
}
