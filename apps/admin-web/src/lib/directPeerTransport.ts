import type { PublicTransferIceConfig } from "../api/types";

export type PeerTransportMode = "auto" | "direct" | "relay";

export function normalizePeerTransportMode(value: unknown): PeerTransportMode {
  return value === "direct" || value === "relay" ? value : "auto";
}

export function buildPeerRtcConfiguration(
  config: PublicTransferIceConfig | null,
  mode: PeerTransportMode,
): RTCConfiguration {
  const iceServers = (config?.iceServers ?? [])
    .filter((server) => shouldUseIceServer(server.urls, mode))
    .map((server) => ({
      urls: server.urls,
      username: server.username || undefined,
      credential: server.credential || undefined,
    }));

  return {
    iceServers,
    iceTransportPolicy: mode === "relay" ? "relay" : "all",
  };
}

export function hasTurnIceServer(config: PublicTransferIceConfig | null) {
  return (config?.iceServers ?? []).some((server) => isTurnUrl(server.urls));
}

function shouldUseIceServer(url: string, mode: PeerTransportMode) {
  if (mode === "auto") {
    return true;
  }
  return mode === "relay" ? isTurnUrl(url) : isStunUrl(url);
}

function isTurnUrl(url: string) {
  return /^turns?:/i.test(url.trim());
}

function isStunUrl(url: string) {
  return /^stuns?:/i.test(url.trim());
}
