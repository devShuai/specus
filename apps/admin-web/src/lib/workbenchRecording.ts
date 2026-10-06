import type { WorkbenchDocument, WorkbenchKind, WorkbenchRef } from "../api/types";
import { WORKBENCH_KINDS } from "../api/types";

// "Recently opened" records what the person explicitly did with a service in this console. It is
// not an access log and says nothing about whether the service answered. Only the actions below
// record (a closed list); loading, refreshing, polling, rendering, switching tabs, expanding,
// hovering, focusing, creating, editing, toggling, deleting, favouriting, checking a directory and
// copying through the browser's context menu never do. See service-workbench.md section 9.

export type WorkbenchOpenAction =
  | "http-route.open-link"      // left or middle click on the access link
  | "http-route.copy-link"      // 复制访问链接
  | "tcp-mapping.copy-port"     // 复制公网端口
  | "peer-service.copy-address" // 复制地址
  | "peer-service.open-link";   // 打开 (HTTP/HTTPS services only)

export const WORKBENCH_OPEN_ACTIONS: ReadonlyArray<WorkbenchOpenAction> = [
  "http-route.open-link",
  "http-route.copy-link",
  "tcp-mapping.copy-port",
  "peer-service.copy-address",
  "peer-service.open-link",
];

export function recordsOpen(action: string): action is WorkbenchOpenAction {
  return (WORKBENCH_OPEN_ACTIONS as ReadonlyArray<string>).includes(action);
}

/** The kind an open action belongs to; recording another kind's reference is refused. */
export function actionKind(action: WorkbenchOpenAction): WorkbenchKind {
  return action.slice(0, action.indexOf(".")) as WorkbenchKind;
}

/**
 * A pointer click on a native link opens it with the main button (0) or, for a new tab, the
 * middle one (1). The secondary button only opens the context menu, which the page cannot follow.
 */
export function isLinkOpeningClick(event: { button: number }): boolean {
  return event.button === 0 || event.button === 1;
}

export function validWorkbenchRef(ref: { kind: string; id: number }): ref is WorkbenchRef {
  return (WORKBENCH_KINDS as ReadonlyArray<string>).includes(ref.kind)
    && Number.isSafeInteger(ref.id) && ref.id >= 1;
}

export interface RecordOpenOptions {
  token: string | null;
  fetchImpl?: typeof fetch;
}

/**
 * Records one open after the action has already happened: the link stays a native link and the copy
 * is done before this is called; nothing waits for the answer. The request is a keepalive fetch so
 * it survives the tab navigating away, and carries the bearer token (sendBeacon cannot). Every
 * failure -- 429, 503, an older server's 404/405, a network error -- resolves to null silently:
 * no message, no retry. A success resolves to the server's document.
 */
export async function recordWorkbenchOpen(
  action: WorkbenchOpenAction,
  ref: WorkbenchRef,
  options: RecordOpenOptions,
): Promise<WorkbenchDocument | null> {
  if (!recordsOpen(action) || !validWorkbenchRef(ref) || actionKind(action) !== ref.kind || !options.token) {
    return null;
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  try {
    const response = await fetchImpl(`/api/admin/workbench/recents/${ref.kind}/${ref.id}`, {
      method: "POST",
      keepalive: true,
      headers: { Authorization: `Bearer ${options.token}` },
    });
    if (!response.ok) return null;
    const document = (await response.json()) as WorkbenchDocument;
    return document && Array.isArray(document.recents) && Array.isArray(document.favorites) ? document : null;
  } catch {
    return null;
  }
}

/**
 * Copies first and records only when the copy happened: a failed copy did not give the person the
 * address, so nothing was opened.
 */
export async function copyThenRecord(
  copy: () => Promise<boolean>,
  record: () => Promise<unknown>,
): Promise<boolean> {
  const copied = await copy();
  if (copied) void record();
  return copied;
}
