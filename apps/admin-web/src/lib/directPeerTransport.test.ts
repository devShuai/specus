import { describe, expect, it } from "vitest";
import type { PublicTransferIceConfig } from "../api/types";
import {
  buildPeerRtcConfiguration,
  hasTurnIceServer,
  normalizePeerTransportMode,
} from "./directPeerTransport";

const config: PublicTransferIceConfig = {
  peerMeshEnabled: true,
  iceServers: [
    { urls: "stun:tunnel.example.com:3478", username: "", credential: "" },
    { urls: "turn:tunnel.example.com:3478?transport=udp", username: "user", credential: "secret" },
    { urls: "turns:tunnel.example.com:5349", username: "user", credential: "secret" },
  ],
  turnAuthRequired: true,
  stunTurnPort: 3478,
};

describe("direct peer transport configuration", () => {
  it("keeps TURN candidates out of the Direct connection", () => {
    const rtc = buildPeerRtcConfiguration(config, "direct");

    expect(rtc.iceTransportPolicy).toBe("all");
    expect(rtc.iceServers).toEqual([
      { urls: "stun:tunnel.example.com:3478", username: undefined, credential: undefined },
    ]);
  });

  it("forces relay-only ICE for the TURN fallback", () => {
    const rtc = buildPeerRtcConfiguration(config, "relay");

    expect(rtc.iceTransportPolicy).toBe("relay");
    expect(rtc.iceServers).toHaveLength(2);
    expect(rtc.iceServers?.every((server) => String(server.urls).startsWith("turn"))).toBe(true);
    expect(hasTurnIceServer(config)).toBe(true);
  });

  it("keeps legacy signals on auto mode", () => {
    expect(normalizePeerTransportMode(undefined)).toBe("auto");
    expect(normalizePeerTransportMode("unexpected")).toBe("auto");
    expect(normalizePeerTransportMode("direct")).toBe("direct");
    expect(normalizePeerTransportMode("relay")).toBe("relay");
  });
});
