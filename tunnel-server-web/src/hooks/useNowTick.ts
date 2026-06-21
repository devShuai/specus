import { useEffect, useState } from "react";

// useNowTick returns a counter that increments every `intervalMs`, used to re-render live
// duration cells once per second without storing per-row timers.
export function useNowTick(intervalMs: number, enabled = true): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!enabled) {
      return;
    }
    const timer = window.setInterval(() => setTick((value) => value + 1), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, enabled]);
  return tick;
}
