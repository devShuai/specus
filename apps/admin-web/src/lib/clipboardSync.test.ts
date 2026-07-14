import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CLIPBOARD_TEXT_MAX_CHARS,
  CLIPBOARD_TEXT_MAX_UTF8_BYTES,
  clipboardPayloadHtml,
  clipboardSyncEventKey,
  createClipboardSessionId,
  createClipboardSyncPayload,
  isClipboardSyncPayload,
  serializeClipboardRelayEnvelope,
  type ClipboardInboundEvent,
  type ClipboardSyncPayload,
} from "./clipboardSync";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("clipboard sync payload", () => {
  it("creates a valid STCLIP1 text payload", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-11T01:02:03.000Z"));

    const sessionId = createClipboardSessionId();
    const payload = createClipboardSyncPayload("hello\n剪贴板", sessionId, 7);

    expect(sessionId).toMatch(UUID_PATTERN);
    expect(payload).toMatchObject({
      type: "STCLIP1",
      kind: "text",
      sessionId,
      sequence: 7,
      text: "hello\n剪贴板",
      createdAt: Date.parse("2026-07-11T01:02:03.000Z"),
    });
    expect(payload.id).toMatch(UUID_PATTERN);
    expect(isClipboardSyncPayload(payload)).toBe(true);
  });

  it("creates rich-text and link payloads with STCLIP2", () => {
    const sessionId = createClipboardSessionId();
    const rich = createClipboardSyncPayload("Hello", sessionId, 1, {
      kind: "html",
      html: "<p><strong>Hello</strong></p>",
    });
    const link = createClipboardSyncPayload("https://example.com/docs", sessionId, 2, { kind: "link" });

    expect(rich).toMatchObject({ type: "STCLIP2", kind: "html", text: "Hello" });
    expect(clipboardPayloadHtml(rich)).toBe("<p><strong>Hello</strong></p>");
    expect(isClipboardSyncPayload(rich)).toBe(true);
    expect(link).toMatchObject({ type: "STCLIP2", kind: "link", html: null });
    expect(isClipboardSyncPayload(link)).toBe(true);
  });

  it("rejects unsafe links and oversized combined rich content", () => {
    const sessionId = createClipboardSessionId();
    expect(() => createClipboardSyncPayload(
      "javascript:alert(1)",
      sessionId,
      1,
      { kind: "link" },
    )).toThrow(RangeError);
    expect(() => createClipboardSyncPayload(
      "a".repeat(CLIPBOARD_TEXT_MAX_UTF8_BYTES / 2),
      sessionId,
      2,
      { kind: "html", html: "b".repeat(CLIPBOARD_TEXT_MAX_UTF8_BYTES / 2 + 1) },
    )).toThrow(RangeError);
  });

  it("falls back to getRandomValues when randomUUID is unavailable", () => {
    vi.stubGlobal("crypto", {
      getRandomValues<T extends ArrayBufferView>(array: T) {
        const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
        bytes.forEach((_, index) => {
          bytes[index] = index;
        });
        return array;
      },
    });

    expect(createClipboardSessionId()).toBe("00010203-0405-4607-8809-0a0b0c0d0e0f");
  });

  it("accepts values exactly at both text limits", () => {
    const asciiBoundary = validPayload("a".repeat(CLIPBOARD_TEXT_MAX_CHARS));
    const emojiBoundary = validPayload("😀".repeat(CLIPBOARD_TEXT_MAX_UTF8_BYTES / 4));

    expect(new TextEncoder().encode(emojiBoundary.text)).toHaveLength(CLIPBOARD_TEXT_MAX_UTF8_BYTES);
    expect(emojiBoundary.text.length).toBeLessThanOrEqual(CLIPBOARD_TEXT_MAX_CHARS);
    expect(isClipboardSyncPayload(asciiBoundary)).toBe(true);
    expect(isClipboardSyncPayload(emojiBoundary)).toBe(true);
  });

  it("rejects UTF-16 and UTF-8 overflow independently", () => {
    const tooManyCodeUnits = validPayload("a".repeat(CLIPBOARD_TEXT_MAX_CHARS + 1));
    const utf8Boundary = "汉".repeat(Math.floor(CLIPBOARD_TEXT_MAX_UTF8_BYTES / 3));
    const tooManyUtf8Bytes = validPayload(`${utf8Boundary}汉`);

    expect(utf8Boundary.length).toBeLessThan(CLIPBOARD_TEXT_MAX_CHARS);
    expect(new TextEncoder().encode(utf8Boundary).byteLength).toBeLessThanOrEqual(CLIPBOARD_TEXT_MAX_UTF8_BYTES);
    expect(new TextEncoder().encode(tooManyUtf8Bytes.text).byteLength).toBeGreaterThan(CLIPBOARD_TEXT_MAX_UTF8_BYTES);
    expect(isClipboardSyncPayload(validPayload(utf8Boundary))).toBe(true);
    expect(isClipboardSyncPayload(tooManyCodeUnits)).toBe(false);
    expect(isClipboardSyncPayload(tooManyUtf8Bytes)).toBe(false);
  });

  it("throws when the factory receives invalid or oversized input", () => {
    const sessionId = createClipboardSessionId();

    expect(() => createClipboardSyncPayload("x".repeat(CLIPBOARD_TEXT_MAX_CHARS + 1), sessionId, 1)).toThrow(RangeError);
    expect(() => createClipboardSyncPayload("ok", "", 1)).toThrow(RangeError);
    expect(() => createClipboardSyncPayload("ok", sessionId, -1)).toThrow(RangeError);
  });

  it.each([
    null,
    [],
    {},
    { ...validPayload("ok"), type: "STCLIP2" },
    { ...validPayload("ok"), kind: "html" },
    { ...validPayload("ok"), id: "" },
    { ...validPayload("ok"), sessionId: " padded " },
    { ...validPayload("ok"), sequence: -1 },
    { ...validPayload("ok"), sequence: 1.5 },
    { ...validPayload("ok"), sequence: Number.MAX_SAFE_INTEGER + 1 },
    { ...validPayload("ok"), text: 42 },
    { ...validPayload("ok"), text: "" },
    { ...validPayload("ok"), createdAt: -1 },
    { ...validPayload("ok"), createdAt: 1.5 },
    { ...validPayload("ok"), extra: true },
  ])("rejects malformed payload %#", (value) => {
    expect(isClipboardSyncPayload(value)).toBe(false);
  });
});

describe("clipboardSyncEventKey", () => {
  it("combines the authoritative source, sender session, and message id", () => {
    const payload = validPayload("hello");
    const event: ClipboardInboundEvent = {
      eventId: clipboardSyncEventKey("peer-a", payload),
      sourcePeerId: "peer-a",
      payload,
      receivedAt: 123,
    };

    expect(event.eventId).toBe('["peer-a","clipboard","session-a","message-a"]');
    expect(clipboardSyncEventKey("peer-b", payload)).not.toBe(event.eventId);
    expect(clipboardSyncEventKey("peer-a", { ...payload, id: "message-b" })).not.toBe(event.eventId);
  });

  it("does not collide when tuple values contain separators", () => {
    const left = validPayload("hello");
    const right = { ...left, sessionId: "b", id: "c:d" };

    expect(clipboardSyncEventKey("a", { ...left, sessionId: "b:c", id: "d" }))
      .not.toBe(clipboardSyncEventKey("a", right));
  });
});

describe("serializeClipboardRelayEnvelope", () => {
  it("creates the targeted discovery WebSocket envelope", () => {
    const payload = validPayload("hello");
    expect(JSON.parse(serializeClipboardRelayEnvelope("peer-b", payload))).toEqual({
      type: "clipboard",
      targetPeerId: "peer-b",
      payload,
    });
  });

  it("rejects JSON escape expansion beyond the discovery message limit", () => {
    const payload = validPayload("\0".repeat(11_000));
    expect(isClipboardSyncPayload(payload)).toBe(true);
    expect(() => serializeClipboardRelayEnvelope("peer-b", payload)).toThrow(RangeError);
  });
});

function validPayload(text: string): ClipboardSyncPayload {
  return {
    type: "STCLIP1",
    kind: "text",
    id: "message-a",
    sessionId: "session-a",
    sequence: 1,
    text,
    createdAt: 1_752_195_723_000,
  };
}
