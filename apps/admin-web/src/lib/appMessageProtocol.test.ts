import { describe, expect, it } from "vitest";
import vectors from "../../../../protocol/test-vectors/application-protocol-v2.json";
import {
  AppMessageReassembler,
  decodeRelayAppFrame,
  encodeAppAcknowledgement,
  encodeAppMessage,
  encodeRelayAppFrame,
} from "./appMessageProtocol";
import { isClipboardSyncPayload } from "./clipboardSync";

describe("app message protocol v2", () => {
  it("matches the central STAP2, STWR2, and STCLIP2 vectors", async () => {
    const canonicalFrame = fromHex(vectors.appFrame.frameHex);
    const decoded = await new AppMessageReassembler().push(canonicalFrame);
    expect(decoded).toEqual({
      kind: "message",
      messageId: vectors.appFrame.messageIdHex,
      acknowledgementRequired: true,
      message: { messageType: "clipboard", payload: vectors.clipboard.payload },
    });
    expect(isClipboardSyncPayload(vectors.clipboard.payload)).toBe(true);
    expect(canonicalFrame.slice(72)).toEqual(fromHex(vectors.clipboard.bodyHex));

    const encoded = await encodeAppMessage({
      messageType: "clipboard",
      payload: vectors.clipboard.payload,
    });
    const encodedFrame = new Uint8Array(encoded.frames[0]);
    expect(encodedFrame.slice(0, 8)).toEqual(canonicalFrame.slice(0, 8));
    expect(encodedFrame.slice(24)).toEqual(canonicalFrame.slice(24));

    const acknowledgement = encodeAppAcknowledgement(vectors.appFrame.messageIdHex);
    expect(new Uint8Array(acknowledgement)).toEqual(fromHex(vectors.appFrame.ackHex));

    const routed = decodeRelayAppFrame(fromHex(vectors.relay.frameHex));
    expect(routed.targetPeerId).toBe(vectors.relay.targetPeerId);
    expect(routed.sourcePeerId).toBe(vectors.relay.sourcePeerId);
    expect(new Uint8Array(routed.appFrame)).toEqual(canonicalFrame);

    const tampered = canonicalFrame.slice();
    tampered[tampered.length - vectors.appFrame.tamper.offsetFromEnd] ^= vectors.appFrame.tamper.value;
    await expect(new AppMessageReassembler().push(tampered)).rejects.toThrow(
      vectors.appFrame.tamper.expectedRejection,
    );
  });

  it("chunks and reassembles rich clipboard payloads", async () => {
    const encoded = await encodeAppMessage({
      messageType: "clipboard",
      payload: { type: "STCLIP2", kind: "html", text: "hello", html: "<b>" + "x".repeat(90_000) + "</b>" },
    }, 4096);
    expect(encoded.frames.length).toBeGreaterThan(20);
    const reassembler = new AppMessageReassembler();
    let decoded = null;
    for (const frame of [...encoded.frames].reverse()) {
      decoded = await reassembler.push(frame) ?? decoded;
    }
    expect(decoded).toMatchObject({
      kind: "message",
      messageId: encoded.messageId,
      acknowledgementRequired: true,
      message: { messageType: "clipboard" },
    });
  });

  it("keeps Yjs bytes binary in STDG2", async () => {
    const update = Uint8Array.from({ length: 32_000 }, (_, index) => index % 251);
    const encoded = await encodeAppMessage({
      messageType: "whiteboard",
      payload: { type: "STDG2", kind: "diagram-update", update, createdAt: 1 },
    }, 2048);
    const reassembler = new AppMessageReassembler();
    let decoded: Awaited<ReturnType<typeof reassembler.push>> = null;
    for (const frame of encoded.frames) decoded = await reassembler.push(frame) ?? decoded;
    expect(decoded?.kind).toBe("message");
    if (decoded?.kind !== "message") return;
    const payload = decoded.message.payload as { update: Uint8Array };
    expect(payload.update).toBeInstanceOf(Uint8Array);
    expect(Array.from(payload.update)).toEqual(Array.from(update));
  });

  it("rejects tampered chunks and decodes acknowledgements", async () => {
    const encoded = await encodeAppMessage({
      messageType: "whiteboard",
      payload: { type: "STWB1", kind: "clear", clearId: "c", createdAt: 1 },
    });
    const tampered = new Uint8Array(encoded.frames[0].slice(0));
    tampered[tampered.length - 1] ^= 1;
    await expect(new AppMessageReassembler().push(tampered)).rejects.toThrow("digest");
    await expect(new AppMessageReassembler().push(encodeAppAcknowledgement(encoded.messageId)))
      .resolves.toEqual({ kind: "ack", messageId: encoded.messageId });
  });

  it("uses the same app frame inside the WS relay envelope", async () => {
    const encoded = await encodeAppMessage({
      messageType: "whiteboard",
      payload: { type: "STWB1", kind: "clear", clearId: "c", createdAt: 1 },
    });
    const routed = encodeRelayAppFrame("peer-b", "peer-a", encoded.frames[0]);
    const decoded = decodeRelayAppFrame(routed);
    expect(decoded.targetPeerId).toBe("peer-b");
    expect(decoded.sourcePeerId).toBe("peer-a");
    expect(new Uint8Array(decoded.appFrame)).toEqual(new Uint8Array(encoded.frames[0]));
  });
});

function fromHex(value: string) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new Error("invalid hex fixture");
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
