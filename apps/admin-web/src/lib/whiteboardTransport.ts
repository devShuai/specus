import type { WhiteboardPayload } from "../components/SyncedWhiteboard";

export function shouldPreferWhiteboardRelay(payload: WhiteboardPayload) {
  return payload.kind === "object-upsert"
    || payload.kind === "remove-object"
    || payload.kind === "clear";
}
