import {
  clipboardPayloadHtml,
  createClipboardSessionId,
  type ClipboardContentKind,
  type ClipboardInboundEvent,
} from "./clipboardSync";

export const CLIPBOARD_TEXT_BLOCK_LIMIT = 80;

export interface ClipboardTextBlock {
  id: string;
  text: string;
  kind: ClipboardContentKind;
  html?: string;
  origin: "local" | "remote";
  createdAt: number;
  sourcePeerId?: string;
  sourceDisplayName?: string;
  sourceEventId?: string;
}

export function createLocalClipboardTextBlock(
  text: string,
  createdAt = Date.now(),
  id = `local:${createClipboardSessionId()}`,
  content: { kind?: ClipboardContentKind; html?: string } = {},
): ClipboardTextBlock {
  return {
    id,
    text,
    kind: content.kind ?? "text",
    html: content.html,
    origin: "local",
    createdAt,
  };
}

export function createInboundClipboardTextBlocks(events: ClipboardInboundEvent[]): ClipboardTextBlock[] {
  return events.slice().reverse().map((event) => ({
    id: inboundClipboardBlockId(event.eventId),
    text: event.payload.text,
    kind: event.payload.kind,
    html: clipboardPayloadHtml(event.payload) || undefined,
    origin: "remote",
    createdAt: event.receivedAt,
    sourcePeerId: event.sourcePeerId,
    sourceDisplayName: event.sourceDisplayName,
    sourceEventId: event.eventId,
  }));
}

export function prependClipboardTextBlocks(
  current: ClipboardTextBlock[],
  incoming: ClipboardTextBlock[],
  limit = CLIPBOARD_TEXT_BLOCK_LIMIT,
): ClipboardTextBlock[] {
  const incomingIds = new Set(incoming.map((block) => block.id));
  return [
    ...incoming,
    ...current.filter((block) => !incomingIds.has(block.id)),
  ].slice(0, Math.max(0, limit));
}

export function updateClipboardTextBlock(
  blocks: ClipboardTextBlock[],
  blockId: string,
  text: string,
  content?: { kind?: ClipboardContentKind; html?: string },
): ClipboardTextBlock[] {
  return blocks.map((block) => block.id === blockId
    ? {
        ...block,
        text,
        kind: content?.kind ?? block.kind,
        html: content ? content.html : block.html,
      }
    : block);
}

function inboundClipboardBlockId(eventId: string) {
  return `remote:${eventId}`;
}
