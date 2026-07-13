import { describe, expect, it, vi } from "vitest";
import { sendWhiteboardWithFallback, WHITEBOARD_TRANSPORT_ORDER } from "./whiteboardTransport";

describe("sendWhiteboardWithFallback", () => {
  it("uses Direct first and stops after a successful send", async () => {
    const direct = vi.fn().mockResolvedValue(true);
    const turn = vi.fn().mockResolvedValue(true);
    const websocket = vi.fn().mockReturnValue(true);

    await expect(sendWhiteboardWithFallback({ direct, turn, websocket })).resolves.toBe("direct");
    expect(direct).toHaveBeenCalledOnce();
    expect(turn).not.toHaveBeenCalled();
    expect(websocket).not.toHaveBeenCalled();
  });

  it("falls back from Direct to TURN before WebSocket", async () => {
    const calls: string[] = [];

    await expect(sendWhiteboardWithFallback({
      direct: async () => {
        calls.push("direct");
        return false;
      },
      turn: async () => {
        calls.push("turn");
        return true;
      },
      websocket: () => {
        calls.push("websocket");
        return true;
      },
    })).resolves.toBe("turn");
    expect(calls).toEqual(["direct", "turn"]);
  });

  it("uses WebSocket only after Direct and TURN both fail", async () => {
    const calls: string[] = [];

    await expect(sendWhiteboardWithFallback({
      direct: async () => {
        calls.push("direct");
        throw new Error("direct failed");
      },
      turn: () => {
        calls.push("turn");
        return false;
      },
      websocket: () => {
        calls.push("websocket");
        return true;
      },
    })).resolves.toBe("websocket");
    expect(calls).toEqual(WHITEBOARD_TRANSPORT_ORDER);
  });

  it("returns null when every path is unavailable", async () => {
    await expect(sendWhiteboardWithFallback({
      direct: () => false,
      turn: () => false,
      websocket: () => false,
    })).resolves.toBeNull();
  });
});
