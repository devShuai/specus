import { describe, expect, it } from "vitest";
import {
  buildTransferInviteUrl,
  buildTransferNavigationUrl,
  buildTransferPairingUrl,
  normalizeTransferPairingCode,
  selectSafeTransferInviteToken,
} from "./transferInvite";

const ORIGIN = "https://specus.devshuai.com";

describe("transfer invitation URLs", () => {
  it("builds a credential-free navigation URL for the selected workspace", () => {
    const result = buildTransferNavigationUrl({
      origin: ORIGIN,
      workspacePath: "/diagram?campaign=room&token=owner-secret&pair=87654321&mode=internet#token=fragment-secret",
      roomId: "  设计评审  ",
    });
    const url = new URL(result);

    expect(url.origin).toBe(ORIGIN);
    expect(url.pathname).toBe("/diagram");
    expect(url.searchParams.get("campaign")).toBe("room");
    expect(url.searchParams.has("mode")).toBe(false);
    expect(url.searchParams.get("room")).toBe("设计评审");
    expect(url.searchParams.has("token")).toBe(false);
    expect(url.searchParams.has("roomToken")).toBe(false);
    expect(url.searchParams.has("pair")).toBe(false);
    expect(url.hash).toBe("");
  });

  it("rejects a cross-origin workspace path", () => {
    expect(() => buildTransferNavigationUrl({
      origin: ORIGIN,
      workspacePath: "https://attacker.example/transfer",
      roomId: "nearby",
    })).toThrow("workspacePath 必须与当前页面同源");
  });

  it("keeps the invitation token only in fragment parameters", () => {
    const result = buildTransferInviteUrl({
      origin: ORIGIN,
      workspacePath: "/transfer",
      roomId: "nearby",
      token: " role token / 2026 ",
    });
    expect(result).not.toBeNull();

    const url = new URL(result!);
    const fragment = new URLSearchParams(url.hash.slice(1));
    expect(url.pathname).toBe("/transfer");
    expect(url.searchParams.has("mode")).toBe(false);
    expect(url.searchParams.get("room")).toBe("nearby");
    expect(url.searchParams.has("token")).toBe(false);
    expect(url.searchParams.has("roomToken")).toBe(false);
    expect(fragment.get("token")).toBe("role token / 2026");
  });

  it("returns a credential-free entry URL when no token is supplied", () => {
    const result = buildTransferInviteUrl({
      origin: ORIGIN,
      workspacePath: "/transfer",
      roomId: "附近设备",
    });
    const url = new URL(result);

    expect(url.searchParams.has("token")).toBe(false);
    expect(url.searchParams.has("roomToken")).toBe(false);
    expect(url.hash).toBe("");
  });
});

describe("safe transfer invitation token selection", () => {
  it("never falls back to the owner's current token", () => {
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "OWNER",
      currentRoomToken: "owner-secret",
    })).toBeNull();
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "OWNER",
      currentRoomToken: "owner-secret",
      allowCurrentRoleForwarding: true,
    })).toBeNull();
  });

  it("accepts an explicit EDITOR or VIEWER invitation token", () => {
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "OWNER",
      currentRoomToken: "owner-secret",
      explicitInvite: { role: "EDITOR", token: " editor-invite " },
    })).toBe("editor-invite");
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "OWNER",
      currentRoomToken: "owner-secret",
      explicitInvite: { role: "VIEWER", token: "viewer-invite" },
    })).toBe("viewer-invite");
  });

  it("does not forward EDITOR or VIEWER credentials by default", () => {
    for (const currentRole of ["EDITOR", "VIEWER"] as const) {
      expect(selectSafeTransferInviteToken({
        sharedRoom: true,
        currentRole,
        currentRoomToken: `${currentRole.toLowerCase()}-secret`,
      })).toBeNull();
    }
  });

  it("forwards a non-owner credential only after explicit opt-in", () => {
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "EDITOR",
      currentRoomToken: " editor-secret ",
      allowCurrentRoleForwarding: true,
    })).toBe("editor-secret");
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: "VIEWER",
      currentRoomToken: "viewer-secret",
      allowCurrentRoleForwarding: true,
    })).toBe("viewer-secret");
  });

  it("does not select any token before the server confirms a role", () => {
    expect(selectSafeTransferInviteToken({
      sharedRoom: true,
      currentRole: null,
      currentRoomToken: "unconfirmed-secret",
      allowCurrentRoleForwarding: true,
    })).toBeNull();
  });

  it("never selects a token outside a shared room", () => {
    expect(selectSafeTransferInviteToken({
      sharedRoom: false,
      currentRole: "OWNER",
      currentRoomToken: "owner-secret",
      explicitInvite: { role: "EDITOR", token: "editor-invite" },
      allowCurrentRoleForwarding: true,
    })).toBeNull();
  });
});

describe("transfer pairing codes", () => {
  it("normalizes eight digits separated by spaces or hyphens", () => {
    expect(normalizeTransferPairingCode("12345678")).toBe("12345678");
    expect(normalizeTransferPairingCode("1234 5678")).toBe("12345678");
    expect(normalizeTransferPairingCode(" 12-34 56-78 ")).toBe("12345678");
  });

  it("rejects incomplete, overlong, or non-numeric codes", () => {
    expect(normalizeTransferPairingCode("")).toBeNull();
    expect(normalizeTransferPairingCode("1234567")).toBeNull();
    expect(normalizeTransferPairingCode("123456789")).toBeNull();
    expect(normalizeTransferPairingCode("1234-ABCD")).toBeNull();
    expect(normalizeTransferPairingCode("１２３４５６７８")).toBeNull();
    expect(normalizeTransferPairingCode("1234\t5678")).toBeNull();
  });

  it("builds a pairing URL with an eight-digit code only in the fragment", () => {
    const result = buildTransferPairingUrl({
      origin: ORIGIN,
      workspacePath: "/transfer?campaign=pair&token=must-not-leak&pairCode=87654321",
      code: "1234-5678",
    });
    expect(result).not.toBeNull();

    const url = new URL(result!);
    expect(url.pathname).toBe("/transfer");
    expect(url.searchParams.get("campaign")).toBe("pair");
    expect(url.searchParams.has("token")).toBe(false);
    expect(url.searchParams.has("pairCode")).toBe(false);
    expect(url.hash).toBe("#?pair=12345678");
  });

  it("does not build a pairing URL for an invalid code", () => {
    expect(buildTransferPairingUrl({
      origin: ORIGIN,
      workspacePath: "/diagram",
      code: "1234567",
    })).toBeNull();
  });
});
