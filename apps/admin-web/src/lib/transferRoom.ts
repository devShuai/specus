export const MAX_TRANSFER_ROOM_NAME_LENGTH = 120;
export const MAX_TRANSFER_ROOM_TOKEN_LENGTH = 512;
export type TransferNetworkMode = "lan" | "internet";

export interface TransferRoomValidationOptions {
  roomTokenRequired?: boolean;
}

export interface TransferRoomSettingsErrors {
  roomId?: string;
  roomToken?: string;
}

export interface TransferRoomSettingsValidation {
  roomId: string;
  roomToken: string;
  errors: TransferRoomSettingsErrors;
}

export function validateTransferRoomSettings(
  roomIdInput: string,
  roomTokenInput: string,
  options: TransferRoomValidationOptions = {},
): TransferRoomSettingsValidation {
  const roomId = roomIdInput.trim();
  const roomToken = roomTokenInput.trim();
  const roomTokenRequired = options.roomTokenRequired ?? true;
  const errors: TransferRoomSettingsErrors = {};

  if (!roomId) {
    errors.roomId = "房间名不能为空";
  } else if (/[\r\n]/.test(roomId)) {
    errors.roomId = "房间名不能包含换行";
  } else if (roomId.length > MAX_TRANSFER_ROOM_NAME_LENGTH) {
    errors.roomId = `房间名不能超过 ${MAX_TRANSFER_ROOM_NAME_LENGTH} 个字符`;
  }

  if (!roomToken && roomTokenRequired) {
    errors.roomToken = "Token 不能为空";
  } else if (roomToken && /[\r\n]/.test(roomToken)) {
    errors.roomToken = "Token 不能包含换行";
  } else if (roomToken && roomToken.length > MAX_TRANSFER_ROOM_TOKEN_LENGTH) {
    errors.roomToken = `Token 不能超过 ${MAX_TRANSFER_ROOM_TOKEN_LENGTH} 个字符`;
  }

  return { roomId, roomToken, errors };
}

export function resolveTransferNetworkMode(
  value: string | null | undefined,
  roomToken: string | null | undefined,
): TransferNetworkMode {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "lan" || normalized === "local" || normalized === "intranet") {
    return "lan";
  }
  if (normalized === "internet" || normalized === "external" || normalized === "wan") {
    return "internet";
  }
  return roomToken?.trim() ? "internet" : "lan";
}

export function retainExplicitTransferPeerSelection(
  currentPeerId: string,
  visiblePeerIds: readonly string[],
): string {
  if (!currentPeerId) return "";
  return visiblePeerIds.includes(currentPeerId) ? currentPeerId : "";
}

export function localizeTransferDiscoveryError(message: string): string {
  const normalized = message.trim();
  const lower = normalized.toLowerCase();
  if (!normalized) {
    return "房间连接暂时失败，正在自动重试";
  }
  if (lower.includes("internal server error") || /\b5\d\d\b/.test(lower)) {
    return "房间服务暂时不可用，正在自动重试";
  }
  if (lower.includes("failed to fetch") || lower.includes("network error") || lower.includes("connection refused")) {
    return "暂时无法连接房间服务，请检查网络后重试";
  }
  if (lower.includes("rate limit")) {
    return "请求过于频繁，请稍后再试";
  }
  if (lower.includes("room token") || lower.includes("invalid token") || lower.includes("unauthorized")) {
    return "房间口令无效或已过期，请检查邀请链接";
  }
  if (lower.includes("room not found") || lower.includes("unknown room")) {
    return "房间不存在或已关闭";
  }
  if (lower.includes("ticket")) {
    return "连接凭证无效，请刷新页面重试";
  }
  if (lower.includes("timeout") || lower.includes("timed out")) {
    return "连接超时，请检查网络后重试";
  }
  if (/^[\x00-\x7f]+$/.test(normalized) && /[a-z]/i.test(normalized)) {
    return "房间连接暂时失败，正在自动重试";
  }
  return normalized;
}
