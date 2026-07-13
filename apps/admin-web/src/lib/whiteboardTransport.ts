export type WhiteboardTransportPath = "direct" | "turn" | "websocket";

export interface WhiteboardTransportSenders {
  direct: () => boolean | Promise<boolean>;
  turn: () => boolean | Promise<boolean>;
  websocket: () => boolean | Promise<boolean>;
}

export const WHITEBOARD_TRANSPORT_ORDER: readonly WhiteboardTransportPath[] = [
  "direct",
  "turn",
  "websocket",
];

export async function sendWhiteboardWithFallback(
  senders: WhiteboardTransportSenders,
): Promise<WhiteboardTransportPath | null> {
  for (const path of WHITEBOARD_TRANSPORT_ORDER) {
    try {
      if (await senders[path]()) {
        return path;
      }
    } catch {
      // A failed transport must not block the next fallback path.
    }
  }
  return null;
}
