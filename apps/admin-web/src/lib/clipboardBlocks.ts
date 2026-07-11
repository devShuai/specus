import { createClipboardSessionId, type ClipboardInboundEvent } from "./clipboardSync";

export const CLIPBOARD_TEXT_BLOCK_LIMIT = 40;

export interface ClipboardTextBlock {
  id: string;
  text: string;
  origin: "local" | "remote";
  createdAt: number;
  sourcePeerId?: string;
  sourceEventId?: string;
}

export function createLocalClipboardTextBlock(
  text: string,
  createdAt = Date.now(),
  id = `local:${createClipboardSessionId()}`,
): ClipboardTextBlock {
  return { id, text, origin: "local", createdAt };
}

export function createInboundClipboardTextBlocks(events: ClipboardInboundEvent[]): ClipboardTextBlock[] {
  return events.slice().reverse().map((event) => ({
    id: inboundClipboardBlockId(event.eventId),
    text: event.payload.text,
    origin: "remote",
    createdAt: event.receivedAt,
    sourcePeerId: event.sourcePeerId,
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
): ClipboardTextBlock[] {
  return blocks.map((block) => block.id === blockId ? { ...block, text } : block);
}

function inboundClipboardBlockId(eventId: string) {
  return `remote:${eventId}`;
}
