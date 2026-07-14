import { describe, expect, it } from "vitest";
import {
  CLIPBOARD_TEXT_BLOCK_LIMIT,
  createInboundClipboardTextBlocks,
  createLocalClipboardTextBlock,
  prependClipboardTextBlocks,
  updateClipboardTextBlock,
} from "./clipboardBlocks";
import type { ClipboardInboundEvent, ClipboardSyncPayload } from "./clipboardSync";

describe("clipboard text blocks", () => {
  it("keeps every local paste as an independent editable block", () => {
    const first = createLocalClipboardTextBlock("first", 1, "local:first");
    const second = createLocalClipboardTextBlock("second", 2, "local:second");
    const blocks = prependClipboardTextBlocks(
      prependClipboardTextBlocks([], [first]),
      [second],
    );

    const edited = updateClipboardTextBlock(blocks, second.id, "second edited");

    expect(edited.map((block) => block.text)).toEqual(["second edited", "first"]);
    expect(blocks.map((block) => block.text)).toEqual(["second", "first"]);
  });

  it("materializes every inbound event as a newest-first block", () => {
    const blocks = createInboundClipboardTextBlocks([
      inboundEvent("event-1", "peer-a", "first", 1),
      inboundEvent("event-2", "peer-b", "second", 2),
    ]);

    expect(blocks).toMatchObject([
      { id: "remote:event-2", text: "second", origin: "remote", sourcePeerId: "peer-b" },
      { id: "remote:event-1", text: "first", origin: "remote", sourcePeerId: "peer-a" },
    ]);
  });

  it("deduplicates repeated blocks and enforces the memory limit", () => {
    const first = createLocalClipboardTextBlock("first", 1, "local:first");
    const second = createLocalClipboardTextBlock("second", 2, "local:second");
    const replacement = { ...first, text: "first updated" };

    expect(prependClipboardTextBlocks([first, second], [replacement], 2)).toEqual([
      replacement,
      second,
    ]);
  });

  it("preserves rich clipboard content and readable source names", () => {
    const event = inboundEvent("event-rich", "peer-a", "Hello", 3);
    event.sourceDisplayName = "会议室电脑";
    event.payload = {
      ...event.payload,
      type: "STCLIP2",
      kind: "html",
      html: "<strong>Hello</strong>",
    };

    expect(createInboundClipboardTextBlocks([event])).toMatchObject([{
      kind: "html",
      html: "<strong>Hello</strong>",
      sourceDisplayName: "会议室电脑",
    }]);
  });

  it("keeps an expanded clipboard history", () => {
    const blocks = Array.from({ length: CLIPBOARD_TEXT_BLOCK_LIMIT + 1 }, (_, index) => (
      createLocalClipboardTextBlock(String(index), index, `local:${index}`)
    ));

    expect(prependClipboardTextBlocks([], blocks)).toHaveLength(CLIPBOARD_TEXT_BLOCK_LIMIT);
    expect(CLIPBOARD_TEXT_BLOCK_LIMIT).toBe(80);
  });
});

function inboundEvent(
  eventId: string,
  sourcePeerId: string,
  text: string,
  receivedAt: number,
): ClipboardInboundEvent {
  const payload: ClipboardSyncPayload = {
    type: "STCLIP1",
    kind: "text",
    id: eventId,
    sessionId: "session-a",
    sequence: receivedAt,
    text,
    createdAt: receivedAt,
  };
  return { eventId, sourcePeerId, payload, receivedAt };
}
