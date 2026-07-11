import { describe, expect, it } from "vitest";
import type { WhiteboardPayload } from "../components/SyncedWhiteboard";
import { shouldPreferWhiteboardRelay } from "./whiteboardTransport";

describe("shouldPreferWhiteboardRelay", () => {
  it("uses the reliable relay for durable object mutations", () => {
    const payloads: WhiteboardPayload[] = [
      {
        type: "STWB1",
        kind: "object-upsert",
        object: {
          objectId: "text-1",
          sourcePeerId: "peer-a",
          kind: "text",
          x: 0.1,
          y: 0.1,
          width: 0.3,
          height: 0.2,
          color: "#172033",
          strokeWidth: 2,
          text: "同步文本",
          fontSize: 22,
          updatedAt: 100,
        },
        createdAt: 100,
      },
      { type: "STWB1", kind: "remove-object", objectId: "text-1", createdAt: 101 },
      { type: "STWB1", kind: "clear", clearId: "clear-1", createdAt: 102 },
    ];

    for (const payload of payloads) {
      expect(shouldPreferWhiteboardRelay(payload)).toBe(true);
    }
  });

  it("keeps high-frequency stroke traffic on the direct channel", () => {
    const payloads: WhiteboardPayload[] = [
      {
        type: "STWB1",
        kind: "stroke-start",
        strokeId: "stroke-1",
        color: "#172033",
        width: 6,
        point: { x: 0.1, y: 0.1 },
        createdAt: 100,
      },
      {
        type: "STWB1",
        kind: "stroke-points",
        strokeId: "stroke-1",
        points: [{ x: 0.2, y: 0.2 }],
        createdAt: 101,
      },
      {
        type: "STWB1",
        kind: "stroke-end",
        strokeId: "stroke-1",
        points: [],
        createdAt: 102,
      },
    ];

    for (const payload of payloads) {
      expect(shouldPreferWhiteboardRelay(payload)).toBe(false);
    }
  });
});
