// Opt-in product metrics (protocol/spec/product-metrics.md): the closed transfer-outcome event, the
// disclosure the page must show, the per-device opt-out, the outcome derivation from the transfer
// page's send records and the at-most-once reporter. Nothing here ever carries a file name, a size
// in bytes, a room, a device, an address or any identifier; the five closed fields are all.

export const PRODUCT_METRICS_DISCLOSURE_VERSION = 1;
export const PRODUCT_METRICS_MAX_EVENTS_PER_REQUEST = 20;
export const PRODUCT_METRICS_MAX_WAIT_MS = 5_000;
export const PRODUCT_METRICS_MAX_QUEUE = 40;

export type TransferMetricsMode = "device" | "link";
export type TransferMetricsPath = "direct" | "turn" | "cloud" | "unestablished";
export type TransferMetricsAttempt = "first" | "retry_after_failure" | "retry_after_cancel";
export type TransferMetricsOutcome = "success" | "failure" | "cancelled";
export type TransferMetricsSizeBucket = "lt1m" | "1m-16m" | "16m-128m" | "128m-512m" | "gt512m";

/** One finished attempt, exactly the five closed fields of section 4.2. */
export interface TransferOutcomeEvent {
  mode: TransferMetricsMode;
  path: TransferMetricsPath;
  sizeBucket: TransferMetricsSizeBucket;
  attempt: TransferMetricsAttempt;
  outcome: TransferMetricsOutcome;
}

export const TRANSFER_METRICS_PATHS: readonly TransferMetricsPath[] = ["direct", "turn", "cloud", "unestablished"];
export const TRANSFER_METRICS_SIZE_BUCKETS: readonly TransferMetricsSizeBucket[] =
  ["lt1m", "1m-16m", "16m-128m", "128m-512m", "gt512m"];
export const TRANSFER_METRICS_MODES: readonly TransferMetricsMode[] = ["device", "link"];
export const TRANSFER_METRICS_ATTEMPTS: readonly TransferMetricsAttempt[] =
  ["first", "retry_after_failure", "retry_after_cancel"];

const MIB = 1024 * 1024;

/** The size range of a file; empty files never produce an event. The exact size stays here. */
export function transferSizeBucket(bytes: number): TransferMetricsSizeBucket | null {
  if (!Number.isFinite(bytes) || bytes < 1) return null;
  if (bytes < MIB) return "lt1m";
  if (bytes < 16 * MIB) return "1m-16m";
  if (bytes <= 128 * MIB) return "16m-128m";
  if (bytes <= 512 * MIB) return "128m-512m";
  return "gt512m";
}

/** The combination rules of section 4.2: a link is never direct or relayed, a success has a path. */
export function isValidTransferOutcomeEvent(event: TransferOutcomeEvent): boolean {
  if (event.mode === "link" && event.path !== "cloud" && event.path !== "unestablished") return false;
  return !(event.outcome === "success" && event.path === "unestablished");
}

// ---- disclosure (section 3.1) ------------------------------------------------------------------

export interface DisclosureItem {
  title: string;
  detail: string;
}

/** The disclosure an admin confirms before switching on (version PRODUCT_METRICS_DISCLOSURE_VERSION). */
export const PRODUCT_METRICS_DISCLOSURE: readonly DisclosureItem[] = [
  {
    title: "统计什么",
    detail: "新账号在 14 天内是否完成「登录 → 创建接入凭证 → 客户端上线 → 发布服务」以及完成耗时区间；"
      + "已登录成员在互传中每次发送的方式（设备/链接）、实际路径（直连/中继/临时存储/未建立）、文件大小区间、第几次尝试和结果（成功/失败/取消）。",
  },
  {
    title: "不统计什么",
    detail: "凭证、文件名、文件类型、精确大小、文本或剪贴板内容、房间与设备标识、IP 或内网地址、目标地址、浏览器信息、失败原因文本。匿名访客的互传不统计。",
  },
  {
    title: "怎么保存",
    detail: "只存按天汇总的计数；接入进度只在 14 天窗口内按账号暂存，结束即汇总并删除。计数保存 180 天。"
      + "清除是硬删除，无法恢复；数据库备份里的副本按部署自身的备份保留策略过期。",
  },
  {
    title: "谁能看",
    detail: "只有本租户管理员能看汇总，看不到任何个人或单次记录。",
  },
  {
    title: "怎么停",
    detail: "随时关闭；关闭时可以一并清除全部已收集数据。成员可以在互传页选择「本设备不参与」。",
  },
];

/** The one-line notice members see while their organisation has metrics switched on. */
export const PRODUCT_METRICS_MEMBER_NOTICE =
  "你所在组织已开启产品指标：只统计传输方式、文件大小区间与成败次数，不含文件名、内容或地址";

/** Where the full disclosure is shown to members. */
export const PRODUCT_METRICS_DISCLOSURE_HREF = "/#/help/metrics";

// ---- per-device opt-out (section 3.1) ------------------------------------------------------------

export const PRODUCT_METRICS_OPT_OUT_KEY = "specus.productMetrics.deviceOptOut";

type KeyValueStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function defaultStorage(): KeyValueStorage | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

/** Whether this browser chose not to take part; any storage failure counts as not taking part. */
export function readDeviceOptOut(storage: KeyValueStorage | null = defaultStorage()): boolean {
  if (!storage) return true;
  try {
    return storage.getItem(PRODUCT_METRICS_OPT_OUT_KEY) === "1";
  } catch {
    return true;
  }
}

export function writeDeviceOptOut(optOut: boolean, storage: KeyValueStorage | null = defaultStorage()): void {
  if (!storage) return;
  try {
    if (optOut) storage.setItem(PRODUCT_METRICS_OPT_OUT_KEY, "1");
    else storage.removeItem(PRODUCT_METRICS_OPT_OUT_KEY);
  } catch {
    // A browser that cannot store the choice simply keeps not reporting.
  }
}

// ---- outcome derivation from send records ------------------------------------------------------

export type OutgoingSendStatus = "queued" | "connecting" | "sending" | "completed" | "failed" | "cancelled";

/** What the derivation reads of one send record of the transfer page. */
export interface OutgoingSendView {
  id: string;
  status: OutgoingSendStatus;
  sizeBytes: number;
  /** Empty for a file link. */
  targetPeerId: string;
  /** Set on completion: peer = direct, relay = TURN, cloud = temporary storage. */
  transport?: "peer" | "relay" | "cloud";
  completedAt?: number;
}

export interface SendAttemptTrack {
  status: OutgoingSendStatus;
  attempt: TransferMetricsAttempt;
  completedAt?: number;
}

/** What the page knows about the path of an attempt that did not complete. */
export interface SendPathHints {
  /** The temporary-storage upload of this record started in the current attempt. */
  cloudStarted(id: string): boolean;
  /** A peer connection carried this record's bytes in the current attempt. */
  established(id: string): boolean;
  /** The established peer path to a device, when there is one. */
  peerPath(peerId: string): "direct" | "turn" | undefined;
}

const TERMINAL = new Set<OutgoingSendStatus>(["completed", "failed", "cancelled"]);

function outcomeOf(status: OutgoingSendStatus): TransferMetricsOutcome {
  return status === "completed" ? "success" : status === "failed" ? "failure" : "cancelled";
}

function nextAttempt(previous: OutgoingSendStatus): TransferMetricsAttempt {
  if (previous === "failed") return "retry_after_failure";
  if (previous === "cancelled") return "retry_after_cancel";
  return "first";
}

function pathOf(send: OutgoingSendView, hints: SendPathHints): TransferMetricsPath {
  const mode: TransferMetricsMode = send.targetPeerId ? "device" : "link";
  if (send.status === "completed") {
    if (send.transport === "cloud" || mode === "link") return "cloud";
    return send.transport === "relay" ? "turn" : "direct";
  }
  if (hints.cloudStarted(send.id)) return "cloud";
  if (mode === "link" || !hints.established(send.id)) return "unestablished";
  return hints.peerPath(send.targetPeerId) ?? "direct";
}

function eventOf(send: OutgoingSendView, track: SendAttemptTrack, hints: SendPathHints): TransferOutcomeEvent | null {
  const sizeBucket = transferSizeBucket(send.sizeBytes);
  if (!sizeBucket) return null;
  const event: TransferOutcomeEvent = {
    mode: send.targetPeerId ? "device" : "link",
    path: pathOf(send, hints),
    sizeBucket,
    attempt: track.attempt,
    outcome: outcomeOf(send.status),
  };
  return isValidTransferOutcomeEvent(event) ? event : null;
}

/**
 * Turns the transitions between two snapshots of the send records into finished-attempt events:
 * one event when an attempt enters completed/failed/cancelled, a retry after a failure or a
 * cancellation starts the next attempt. Attempts still running when the page closes never appear.
 */
export function trackSendOutcomes(
  previous: ReadonlyMap<string, SendAttemptTrack>,
  sends: readonly OutgoingSendView[],
  hints: SendPathHints,
): { next: Map<string, SendAttemptTrack>; events: TransferOutcomeEvent[] } {
  const next = new Map<string, SendAttemptTrack>();
  const events: TransferOutcomeEvent[] = [];
  for (const send of sends) {
    const before = previous.get(send.id);
    let track: SendAttemptTrack;
    if (!before) {
      track = { status: send.status, attempt: "first" };
      if (TERMINAL.has(send.status)) {
        const event = eventOf(send, track, hints);
        if (event) events.push(event);
      }
    } else if (!TERMINAL.has(before.status)) {
      track = { ...before, status: send.status };
      if (TERMINAL.has(send.status)) {
        const event = eventOf(send, track, hints);
        if (event) events.push(event);
      }
    } else if (!TERMINAL.has(send.status)) {
      // A retry: the next attempt of the same record, on the same receiver.
      track = { status: send.status, attempt: nextAttempt(before.status) };
    } else if (send.completedAt !== before.completedAt) {
      // A whole retry ended between two snapshots.
      track = { status: send.status, attempt: nextAttempt(before.status) };
      const event = eventOf(send, track, hints);
      if (event) events.push(event);
    } else {
      track = before;
    }
    next.set(send.id, { ...track, completedAt: send.completedAt });
  }
  return { next, events };
}

// ---- reporter (section 4.2) ----------------------------------------------------------------------

export interface ReportAnswer {
  status: number;
  collecting?: boolean;
}

export interface TransferOutcomeReporterOptions {
  /** Sends one batch; keepalive is set on pagehide. Any rejection counts as a failed request. */
  send: (events: TransferOutcomeEvent[], keepalive: boolean) => Promise<ReportAnswer>;
  /** Called when the server answers that the tenant does not collect: re-read the settings. */
  onStopped?: () => void;
  setTimer?: (callback: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

/**
 * Batches finished attempts and sends them at most once: at 20 queued events, 5 seconds after the
 * first queued event, and on pagehide with keepalive. A failed request, a 429 or a 400 drops its
 * batch without retrying, so the counts are a lower bound. While inactive (not signed in, the
 * tenant not collecting, or this device opted out) nothing is queued and nothing is sent.
 */
export class TransferOutcomeReporter {
  private readonly options: TransferOutcomeReporterOptions;
  private readonly setTimer: (callback: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private queue: TransferOutcomeEvent[] = [];
  private timer: unknown = null;
  private active = false;

  constructor(options: TransferOutcomeReporterOptions) {
    this.options = options;
    this.setTimer = options.setTimer ?? ((callback, ms) => globalThis.setTimeout(callback, ms));
    this.clearTimer = options.clearTimer ?? ((handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>));
  }

  isActive(): boolean {
    return this.active;
  }

  /** Becoming inactive drops whatever is queued: nothing is sent once the member may not report. */
  setActive(active: boolean): void {
    this.active = active;
    if (!active) this.reset();
  }

  pending(): number {
    return this.queue.length;
  }

  enqueue(event: TransferOutcomeEvent): void {
    if (!this.active || !isValidTransferOutcomeEvent(event)) return;
    if (this.queue.length >= PRODUCT_METRICS_MAX_QUEUE) return;
    this.queue.push({ mode: event.mode, path: event.path, sizeBucket: event.sizeBucket, attempt: event.attempt,
      outcome: event.outcome });
    if (this.queue.length >= PRODUCT_METRICS_MAX_EVENTS_PER_REQUEST) {
      void this.flush(false);
    } else if (this.timer === null) {
      this.timer = this.setTimer(() => {
        this.timer = null;
        void this.flush(false);
      }, PRODUCT_METRICS_MAX_WAIT_MS);
    }
  }

  /** Sends everything queued, in batches of at most 20; on pagehide with keepalive. */
  async flush(keepalive: boolean): Promise<void> {
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
    const batches: TransferOutcomeEvent[][] = [];
    while (this.queue.length > 0) {
      batches.push(this.queue.splice(0, PRODUCT_METRICS_MAX_EVENTS_PER_REQUEST));
    }
    for (const batch of batches) {
      if (!this.active) return;
      let answer: ReportAnswer;
      try {
        answer = await this.options.send(batch, keepalive);
      } catch {
        continue; // dropped: at most once
      }
      if (answer.status === 200 && answer.collecting === false) {
        this.setActive(false);
        this.options.onStopped?.();
        return;
      }
    }
  }

  private reset(): void {
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
    this.queue = [];
  }
}

// ---- summary presentation ----------------------------------------------------------------------

/** A basis-point rate as a percentage with one decimal, or a dash without a denominator. */
export function formatRateBp(rateBp: number | null | undefined): string {
  if (rateBp === null || rateBp === undefined) return "—";
  return `${(rateBp / 100).toFixed(1)}%`;
}

export const ONBOARDING_STEP_LABELS: Record<string, string> = {
  account_created: "创建账号",
  signed_in: "登录",
  credential_created: "创建接入凭证",
  client_online: "客户端上线",
  service_published: "发布服务",
};

export const DURATION_BUCKET_LABELS: Record<string, string> = {
  "lt10m": "10 分钟内",
  "10m-30m": "10–30 分钟",
  "30m-2h": "30 分钟–2 小时",
  "2h-24h": "2–24 小时",
  "1d-3d": "1–3 天",
  "3d-14d": "3–14 天",
};

export const TRANSFER_PATH_LABELS: Record<TransferMetricsPath, string> = {
  direct: "直连",
  turn: "中继",
  cloud: "临时存储",
  unestablished: "未建立",
};

export const TRANSFER_SIZE_LABELS: Record<TransferMetricsSizeBucket, string> = {
  "lt1m": "< 1 MiB",
  "1m-16m": "1–16 MiB",
  "16m-128m": "16–128 MiB",
  "128m-512m": "128–512 MiB",
  "gt512m": "> 512 MiB",
};

export const TRANSFER_MODE_LABELS: Record<TransferMetricsMode, string> = {
  device: "发给设备",
  link: "文件链接",
};

export const TRANSFER_ATTEMPT_LABELS: Record<TransferMetricsAttempt, string> = {
  first: "首次尝试",
  retry_after_failure: "失败后重试",
  retry_after_cancel: "取消后重试",
};

/** UTC day "YYYY-MM-DD" of a date, the unit of every summary range. */
export function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** The default summary range: today and the 29 days before it, in UTC. */
export function defaultSummaryRange(now: Date = new Date()): { from: string; to: string } {
  const to = utcDay(now);
  const from = utcDay(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 29)));
  return { from, to };
}
