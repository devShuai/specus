import { MAX_TRANSFER_ROOM_NAME_LENGTH } from "./transferRoom";

export type TransferInviteRoomRole = "OWNER" | "EDITOR" | "VIEWER";
export type ShareableTransferInviteRole = Exclude<TransferInviteRoomRole, "OWNER">;

export interface TransferNavigationUrlOptions {
  origin: string;
  workspacePath: string;
  roomId: string;
}

export interface TransferInviteUrlOptions extends TransferNavigationUrlOptions {
  token?: string | null;
}

export interface TransferPairingUrlOptions {
  origin: string;
  workspacePath: string;
  code: string;
}

export interface ExplicitTransferInviteToken {
  role: ShareableTransferInviteRole;
  token: string;
}

export interface SafeTransferInviteTokenOptions {
  sharedRoom: boolean;
  currentRole: TransferInviteRoomRole | null;
  currentRoomToken?: string | null;
  explicitInvite?: ExplicitTransferInviteToken | null;
  allowCurrentRoleForwarding?: boolean;
}

const CREDENTIAL_QUERY_KEYS = ["token", "roomToken", "pair", "pairCode"] as const;
const ROOM_QUERY_KEYS = ["mode", "networkMode", "room", "roomId"] as const;

/**
 * Builds the URL that is safe to keep in browser history. Room identity is not
 * secret, while every room credential is removed from both query and fragment.
 */
export function buildTransferNavigationUrl(options: TransferNavigationUrlOptions): string {
  const url = sameOriginWorkspaceUrl(options.origin, options.workspacePath);

  [...CREDENTIAL_QUERY_KEYS, ...ROOM_QUERY_KEYS].forEach((key) => url.searchParams.delete(key));
  url.searchParams.set("room", normalizeRoomId(options.roomId));
  url.hash = "";
  return url.toString();
}

/** Builds a short-code entry URL while keeping the code out of the HTTP query string. */
export function buildTransferPairingUrl(options: TransferPairingUrlOptions): string | null {
  const code = normalizeTransferPairingCode(options.code);
  if (!code) {
    return null;
  }

  const url = sameOriginWorkspaceUrl(options.origin, options.workspacePath);
  CREDENTIAL_QUERY_KEYS.forEach((key) => url.searchParams.delete(key));
  url.hash = `?${new URLSearchParams({ pair: code }).toString()}`;
  return url.toString();
}

/**
 * Builds a shareable invitation URL without putting the credential in the HTTP
 * query string. A shared-room invitation carries the role token in the fragment;
 * without a token the link is a plain credential-free entry to the page.
 */
export function buildTransferInviteUrl(options: TransferInviteUrlOptions): string {
  const navigationUrl = buildTransferNavigationUrl(options);
  const token = options.token?.trim();
  if (!token) {
    return navigationUrl;
  }

  const url = new URL(navigationUrl);
  url.hash = new URLSearchParams({ token }).toString();
  return url.toString();
}

/**
 * Chooses only credentials that are safe to share. An owner's current room
 * token is never a candidate. EDITOR and VIEWER tokens require an explicit
 * forwarding opt-in so opening an invite surface cannot redistribute them by
 * accident. Nearby (non-shared) rooms never produce shareable credentials.
 */
export function selectSafeTransferInviteToken(
  options: SafeTransferInviteTokenOptions,
): string | null {
  if (!options.sharedRoom) {
    return null;
  }

  const explicitToken = options.explicitInvite?.token.trim();
  const explicitRole = options.explicitInvite?.role;
  if (explicitToken && (explicitRole === "EDITOR" || explicitRole === "VIEWER")) {
    return explicitToken;
  }

  if (options.currentRole === "OWNER" || options.currentRole === null) {
    return null;
  }
  if (!options.allowCurrentRoleForwarding) {
    return null;
  }

  return options.currentRoomToken?.trim() || null;
}

/** Returns a canonical eight-digit code, or null when the input is incomplete or invalid. */
export function normalizeTransferPairingCode(value: string): string | null {
  const normalized = value.trim().replace(/[ -]/g, "");
  return /^\d{8}$/.test(normalized) ? normalized : null;
}

function normalizeRoomId(value: string): string {
  const roomId = value.trim() || "nearby";
  return roomId.length > MAX_TRANSFER_ROOM_NAME_LENGTH
    ? roomId.slice(0, MAX_TRANSFER_ROOM_NAME_LENGTH)
    : roomId;
}

function sameOriginWorkspaceUrl(origin: string, workspacePath: string): URL {
  const baseUrl = new URL(origin);
  const url = new URL(workspacePath, baseUrl.origin);
  if (url.origin !== baseUrl.origin) {
    throw new Error("workspacePath 必须与当前页面同源");
  }
  return url;
}
