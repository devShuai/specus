const PERCENT_ENCODED_OCTET = /%[0-9a-f]{2}/i;

export function decodeLegacyPeerDisplayName(value: string) {
  const displayName = value.trim();
  if (!PERCENT_ENCODED_OCTET.test(displayName)) {
    return displayName;
  }

  try {
    return decodeURIComponent(displayName.replace(/\+/g, " ")).trim();
  } catch {
    return displayName;
  }
}
