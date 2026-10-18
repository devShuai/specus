const CHANGE_KEY = "specus:ownership-changed";

/** Invalidation only: never broadcast account names, resource IDs, tokens or credentials. */
export function publishOwnershipChange() {
  window.dispatchEvent(new Event(CHANGE_KEY));
  try { localStorage.setItem(CHANGE_KEY, crypto.randomUUID()); } catch { /* Local refresh still works in private/storage-disabled contexts. */ }
}
export function watchOwnershipChanges(refresh: () => void, includeLocal = true) {
  const storage = (event: StorageEvent) => { if (event.key === CHANGE_KEY) refresh(); };
  const visible = () => { if (document.visibilityState === "visible") refresh(); };
  if (includeLocal) window.addEventListener(CHANGE_KEY, refresh);
  window.addEventListener("storage", storage);
  window.addEventListener("focus", refresh);
  document.addEventListener("visibilitychange", visible);
  return () => {
    if (includeLocal) window.removeEventListener(CHANGE_KEY, refresh);
    window.removeEventListener("storage", storage); window.removeEventListener("focus", refresh);
    document.removeEventListener("visibilitychange", visible);
  };
}
