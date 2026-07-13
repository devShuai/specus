import { describe, expect, it } from "vitest";
import {
  MAX_TRANSFER_ROOM_NAME_LENGTH,
  MAX_TRANSFER_ROOM_TOKEN_LENGTH,
  resolveTransferNetworkMode,
  validateTransferRoomSettings,
} from "./transferRoom";

describe("transfer room settings", () => {
  it("trims and accepts custom room names and tokens", () => {
    expect(validateTransferRoomSettings("  项目联调房间  ", "  team token / 2026  ")).toEqual({
      roomId: "项目联调房间",
      roomToken: "team token / 2026",
      errors: {},
    });
  });

  it("rejects blank values and line breaks", () => {
    expect(validateTransferRoomSettings("  ", "token\nnext").errors).toEqual({
      roomId: "房间名不能为空",
      roomToken: "Token 不能包含换行",
    });
  });

  it("uses the same length limits as the server", () => {
    expect(validateTransferRoomSettings(
      "a".repeat(MAX_TRANSFER_ROOM_NAME_LENGTH + 1),
      "b".repeat(MAX_TRANSFER_ROOM_TOKEN_LENGTH + 1),
    ).errors).toEqual({
      roomId: `房间名不能超过 ${MAX_TRANSFER_ROOM_NAME_LENGTH} 个字符`,
      roomToken: `Token 不能超过 ${MAX_TRANSFER_ROOM_TOKEN_LENGTH} 个字符`,
    });
  });

  it("allows an empty token for LAN rooms", () => {
    expect(validateTransferRoomSettings("附近设备", "", { roomTokenRequired: false })).toEqual({
      roomId: "附近设备",
      roomToken: "",
      errors: {},
    });
  });

  it("defaults to LAN while keeping old token links on internet mode", () => {
    expect(resolveTransferNetworkMode(null, null)).toBe("lan");
    expect(resolveTransferNetworkMode(null, "legacy-token")).toBe("internet");
    expect(resolveTransferNetworkMode("lan", "ignored-in-lan")).toBe("lan");
    expect(resolveTransferNetworkMode("external", null)).toBe("internet");
  });
});
