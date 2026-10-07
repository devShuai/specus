import { describe, expect, it, vi } from "vitest";
import vector from "../../../../protocol/test-vectors/product-metrics-v1.json";
import {
  PRODUCT_METRICS_DISCLOSURE,
  PRODUCT_METRICS_MAX_QUEUE,
  PRODUCT_METRICS_OPT_OUT_KEY,
  TransferOutcomeReporter,
  defaultSummaryRange,
  formatRateBp,
  isValidTransferOutcomeEvent,
  readDeviceOptOut,
  trackSendOutcomes,
  transferSizeBucket,
  writeDeviceOptOut,
  type OutgoingSendView,
  type SendAttemptTrack,
  type SendPathHints,
  type TransferOutcomeEvent,
} from "./productMetrics";

const SAMPLE: TransferOutcomeEvent = { mode: "device", path: "direct", sizeBucket: "lt1m", attempt: "first", outcome: "success" };

describe("closed fields", () => {
  it("buckets sizes exactly like the shared vector", () => {
    for (const item of vector.sizeBuckets) {
      expect(transferSizeBucket(item.sizeBytes), String(item.sizeBytes)).toBe(item.bucket);
    }
  });

  it("accepts every event the vector accepts and refuses its combination violations", () => {
    for (const item of vector.ingestValidation.cases) {
      if (item.expect.status !== 200) continue;
      const events = (JSON.parse(item.bodyText) as { events: TransferOutcomeEvent[] }).events;
      for (const event of events) expect(isValidTransferOutcomeEvent(event), item.name).toBe(true);
    }
    expect(isValidTransferOutcomeEvent({ ...SAMPLE, mode: "link", path: "direct" })).toBe(false);
    expect(isValidTransferOutcomeEvent({ ...SAMPLE, mode: "link", path: "turn", outcome: "failure" })).toBe(false);
    expect(isValidTransferOutcomeEvent({ ...SAMPLE, path: "unestablished" })).toBe(false);
    expect(isValidTransferOutcomeEvent({ ...SAMPLE, path: "unestablished", outcome: "cancelled" })).toBe(true);
  });

  it("formats basis points like the summary rates", () => {
    expect(formatRateBp(6667)).toBe("66.7%");
    expect(formatRateBp(10000)).toBe("100.0%");
    expect(formatRateBp(null)).toBe("—");
  });

  it("defaults the summary to the last 30 UTC days", () => {
    expect(defaultSummaryRange(new Date("2026-09-21T23:30:00Z"))).toEqual({ from: "2026-08-23", to: "2026-09-21" });
  });

  it("discloses every required item of section 3.1", () => {
    expect(PRODUCT_METRICS_DISCLOSURE.map((item) => item.title)).toEqual(["统计什么", "不统计什么", "怎么保存", "谁能看", "怎么停"]);
    const text = PRODUCT_METRICS_DISCLOSURE.map((item) => item.detail).join("");
    for (const term of ["14 天", "文件名", "IP 或内网地址", "匿名访客", "180 天", "管理员", "清除"]) {
      expect(text).toContain(term);
    }
  });
});

describe("per-device opt-out", () => {
  it("is remembered in local storage and fails closed", () => {
    const values = new Map<string, string>();
    const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => void values.set(key, value),
      removeItem: (key: string) => void values.delete(key) };
    expect(readDeviceOptOut(storage)).toBe(false);
    writeDeviceOptOut(true, storage);
    expect(values.get(PRODUCT_METRICS_OPT_OUT_KEY)).toBe("1");
    expect(readDeviceOptOut(storage)).toBe(true);
    writeDeviceOptOut(false, storage);
    expect(readDeviceOptOut(storage)).toBe(false);
    expect(readDeviceOptOut(null)).toBe(true);
    expect(readDeviceOptOut({ ...storage, getItem: () => { throw new Error("blocked"); } })).toBe(true);
  });
});

function hints(overrides: Partial<{ cloud: string[]; established: string[]; paths: Record<string, "direct" | "turn"> }> = {}): SendPathHints {
  return {
    cloudStarted: (id) => (overrides.cloud ?? []).includes(id),
    established: (id) => (overrides.established ?? []).includes(id),
    peerPath: (peerId) => overrides.paths?.[peerId],
  };
}

function send(patch: Partial<OutgoingSendView>): OutgoingSendView {
  return { id: "a", status: "queued", sizeBytes: 2 * 1024 * 1024, targetPeerId: "peer-1", ...patch };
}

function run(states: OutgoingSendView[][], pathHints: SendPathHints = hints()): TransferOutcomeEvent[] {
  let tracks = new Map<string, SendAttemptTrack>();
  const events: TransferOutcomeEvent[] = [];
  for (const snapshot of states) {
    const result = trackSendOutcomes(tracks, snapshot, pathHints);
    tracks = result.next;
    events.push(...result.events);
  }
  return events;
}

describe("send outcomes", () => {
  it("reports one event per finished attempt and nothing for a running one", () => {
    expect(run([[send({})], [send({ status: "connecting" })], [send({ status: "sending" })]])).toEqual([]);
    expect(run([[send({})], [send({ status: "completed", transport: "relay", completedAt: 1 })],
      [send({ status: "completed", transport: "relay", completedAt: 1 })]])).toEqual([
      { mode: "device", path: "turn", sizeBucket: "1m-16m", attempt: "first", outcome: "success" }]);
  });

  it("numbers retries after a failure and after a cancellation", () => {
    const events = run([
      [send({})],
      [send({ status: "failed", completedAt: 1 })],
      [send({ status: "queued" })],
      [send({ status: "cancelled", completedAt: 2 })],
      [send({ status: "queued" })],
      [send({ status: "completed", transport: "peer", completedAt: 3 })],
    ]);
    expect(events.map((event) => [event.attempt, event.outcome, event.path])).toEqual([
      ["first", "failure", "unestablished"],
      ["retry_after_failure", "cancelled", "unestablished"],
      ["retry_after_cancel", "success", "direct"],
    ]);
  });

  it("sees a whole retry that ended between two snapshots", () => {
    const events = run([[send({})], [send({ status: "failed", completedAt: 1 })], [send({ status: "failed", completedAt: 2 })]]);
    expect(events.map((event) => event.attempt)).toEqual(["first", "retry_after_failure"]);
  });

  it("derives the path of an attempt that did not complete", () => {
    expect(run([[send({})], [send({ status: "failed", completedAt: 1 })]], hints({ established: ["a"], paths: { "peer-1": "turn" } })))
      .toEqual([{ mode: "device", path: "turn", sizeBucket: "1m-16m", attempt: "first", outcome: "failure" }]);
    expect(run([[send({})], [send({ status: "failed", completedAt: 1 })]], hints({ established: ["a"] }))[0].path).toBe("direct");
    expect(run([[send({})], [send({ status: "failed", completedAt: 1 })]], hints({ cloud: ["a"], established: ["a"] }))[0].path).toBe("cloud");
    expect(run([[send({ targetPeerId: "" })], [send({ targetPeerId: "", status: "failed", completedAt: 1 })]], hints({ established: ["a"] })))
      .toEqual([{ mode: "link", path: "unestablished", sizeBucket: "1m-16m", attempt: "first", outcome: "failure" }]);
    expect(run([[send({ targetPeerId: "" })], [send({ targetPeerId: "", status: "completed", transport: "cloud", completedAt: 1 })]]))
      .toEqual([{ mode: "link", path: "cloud", sizeBucket: "1m-16m", attempt: "first", outcome: "success" }]);
    expect(run([[send({})], [send({ status: "completed", transport: "cloud", completedAt: 1 })]])[0])
      .toMatchObject({ mode: "device", path: "cloud" });
  });

  it("reports a record that failed before the first snapshot and never an empty file", () => {
    expect(run([[send({ status: "failed", completedAt: 1 })]])).toHaveLength(1);
    expect(run([[send({ sizeBytes: 0 })], [send({ sizeBytes: 0, status: "completed", transport: "peer", completedAt: 1 })]])).toEqual([]);
  });

  it("carries nothing but the five closed fields", () => {
    const [event] = run([[send({})], [send({ status: "completed", transport: "peer", completedAt: 1 })]]);
    expect(Object.keys(event).sort()).toEqual(["attempt", "mode", "outcome", "path", "sizeBucket"]);
  });
});

describe("reporter", () => {
  function reporter(answer: () => Promise<{ status: number; collecting?: boolean }>) {
    const send = vi.fn((events: TransferOutcomeEvent[], keepalive: boolean) => { void events; void keepalive; return answer(); });
    const timers: { callback: () => void; ms: number }[] = [];
    const onStopped = vi.fn();
    const instance = new TransferOutcomeReporter({
      send, onStopped,
      setTimer: (callback, ms) => { timers.push({ callback, ms }); return timers.length; },
      clearTimer: () => undefined,
    });
    return { instance, send, timers, onStopped };
  }

  it("sends nothing while inactive", async () => {
    const { instance, send } = reporter(async () => ({ status: 200, collecting: true }));
    instance.enqueue(SAMPLE);
    await instance.flush(true);
    expect(send).not.toHaveBeenCalled();
    expect(instance.pending()).toBe(0);
  });

  it("sends at 20 events, or 5 seconds after the first queued one", async () => {
    const { instance, send, timers } = reporter(async () => ({ status: 200, collecting: true }));
    instance.setActive(true);
    instance.enqueue(SAMPLE);
    expect(timers).toHaveLength(1);
    expect(timers[0].ms).toBe(5000);
    timers[0].callback();
    await Promise.resolve();
    expect(send).toHaveBeenCalledWith([SAMPLE], false);
    for (let i = 0; i < 20; i += 1) instance.enqueue(SAMPLE);
    await Promise.resolve();
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][0]).toHaveLength(20);
  });

  it("drops a failed or refused batch without retrying", async () => {
    let calls = 0;
    const { instance, send } = reporter(async () => {
      calls += 1;
      if (calls === 1) throw new Error("offline");
      return { status: 429 };
    });
    instance.setActive(true);
    instance.enqueue(SAMPLE);
    await instance.flush(false);
    instance.enqueue(SAMPLE);
    await instance.flush(false);
    await instance.flush(false);
    expect(send).toHaveBeenCalledTimes(2);
    expect(instance.pending()).toBe(0);
  });

  it("stops and asks to re-read the settings when the tenant no longer collects", async () => {
    const { instance, send, onStopped } = reporter(async () => ({ status: 200, collecting: false }));
    instance.setActive(true);
    instance.enqueue(SAMPLE);
    await instance.flush(false);
    expect(onStopped).toHaveBeenCalledTimes(1);
    expect(instance.isActive()).toBe(false);
    instance.enqueue(SAMPLE);
    await instance.flush(false);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("drops the queue when it becomes inactive and sends the rest on pagehide with keepalive", async () => {
    const { instance, send } = reporter(async () => ({ status: 200, collecting: true }));
    instance.setActive(true);
    for (let i = 0; i < 19; i += 1) instance.enqueue(SAMPLE);
    instance.setActive(false);
    expect(instance.pending()).toBe(0);
    instance.setActive(true);
    for (let i = 0; i < 15; i += 1) instance.enqueue({ ...SAMPLE, outcome: i % 2 === 0 ? "failure" : "success" });
    await instance.flush(true);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0][0]).toHaveLength(15);
    expect(send.mock.calls[0][1]).toBe(true);
    expect(PRODUCT_METRICS_MAX_QUEUE).toBe(40);
  });

  it("strips anything but the closed fields before queueing", async () => {
    const { instance, send } = reporter(async () => ({ status: 200, collecting: true }));
    instance.setActive(true);
    instance.enqueue({ ...SAMPLE, fileName: "secret.pdf" } as TransferOutcomeEvent);
    await instance.flush(false);
    expect(send.mock.calls[0][0]).toEqual([SAMPLE]);
  });
});
