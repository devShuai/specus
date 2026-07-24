import type { PublicTransferIceConfig } from "../api/types";

export type PeerTransportMode = "auto" | "direct" | "relay";

const TURN_CREDENTIAL_REFRESH_DEFAULT_MS = 30 * 60 * 1000;
const TURN_CREDENTIAL_REFRESH_MAX_MS = 12 * 60 * 60 * 1000;
const TURN_CREDENTIAL_REFRESH_RETRY_MS = 30 * 1000;
const TURN_CREDENTIAL_REFRESH_SAFETY_MS = 5 * 60 * 1000;

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

export function turnCredentialRefreshDelayMs(
  config: PublicTransferIceConfig | null,
  nowMs = Date.now(),
) {
  if (!config) {
    return TURN_CREDENTIAL_REFRESH_RETRY_MS;
  }
  const expirations = config.iceServers
    .filter((server) => isTurnUrl(server.urls))
    .map((server) => turnCredentialExpirationMs(server.username))
    .filter((value): value is number => value !== null);
  if (expirations.length === 0) {
    return TURN_CREDENTIAL_REFRESH_DEFAULT_MS;
  }
  const refreshAt = Math.min(...expirations) - TURN_CREDENTIAL_REFRESH_SAFETY_MS;
  return Math.max(TURN_CREDENTIAL_REFRESH_RETRY_MS,
    Math.min(TURN_CREDENTIAL_REFRESH_MAX_MS, refreshAt - nowMs));
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

function turnCredentialExpirationMs(username: string) {
  const separator = username.indexOf(":");
  const value = Number(separator >= 0 ? username.slice(0, separator) : username);
  if (!Number.isSafeInteger(value) || value <= 0) {
    return null;
  }
  const expirationMs = value * 1000;
  return Number.isSafeInteger(expirationMs) ? expirationMs : null;
}
