import { useEffect, useState } from "react";

// useNowTick returns the current browser time and updates it on an interval, used to
// render live durations without asking the server for fresh values.
export function useNowTick(intervalMs: number, enabled = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) {
      return;
    }
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, enabled]);
  return now;
}
