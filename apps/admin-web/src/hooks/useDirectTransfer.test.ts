import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { waitForDataChannelDrain } from "./useDirectTransfer";

class FakeDataChannel extends EventTarget {
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 1024 * 1024;
  readyState = "open";

  drain() {
    this.bufferedAmount = 0;
    this.dispatchEvent(new Event("bufferedamountlow"));
  }

  close() {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

beforeAll(() => {
  // 被测代码与浏览器实现一致地使用 window.setTimeout；node 环境下挂到 globalThis。
  (globalThis as { window?: unknown }).window = globalThis;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("waitForDataChannelDrain", () => {
  it("resolves immediately when the buffer is already empty", async () => {
    const channel = new FakeDataChannel();
    await waitForDataChannelDrain(channel as unknown as RTCDataChannel);
    expect(channel.bufferedAmountLowThreshold).toBe(0);
  });

  it("waits for the buffer to fully drain over a slow relay", async () => {
    const channel = new FakeDataChannel();
    channel.bufferedAmount = 4 * 1024 * 1024;
    const pending = waitForDataChannelDrain(channel as unknown as RTCDataChannel);
    // 未到 0 的 bufferedamountlow 不算排空（阈值以下仍有积压）。
    channel.bufferedAmount = 512 * 1024;
    channel.dispatchEvent(new Event("bufferedamountlow"));
    channel.drain();
    await pending;
  });

  it("rejects when the channel closes before draining", async () => {
    const channel = new FakeDataChannel();
    channel.bufferedAmount = 1024;
    const pending = waitForDataChannelDrain(channel as unknown as RTCDataChannel);
    const assertion = expect(pending).rejects.toThrow("DataChannel 已关闭");
    channel.close();
    await assertion;
  });

  it("rejects on timeout when the buffer never drains", async () => {
    vi.useFakeTimers();
    const channel = new FakeDataChannel();
    channel.bufferedAmount = 1024;
    const pending = waitForDataChannelDrain(channel as unknown as RTCDataChannel, 5000);
    const assertion = expect(pending).rejects.toThrow("DataChannel 发送缓冲排空超时");
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;
  });
});
