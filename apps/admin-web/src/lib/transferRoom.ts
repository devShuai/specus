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
