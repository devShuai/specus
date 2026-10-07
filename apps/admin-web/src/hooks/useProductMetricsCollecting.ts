import { useEffect, useState } from "react";
import { fetchProductMetricsCollecting } from "../api/client";

/**
 * Whether the signed-in member's organisation collects product metrics, for the standing member
 * notice (protocol/spec/product-metrics.md section 3.1). Read once per sign-in; silent on failure.
 */
export function useProductMetricsCollecting(signedIn: boolean): boolean {
  const [collecting, setCollecting] = useState(false);
  useEffect(() => {
    if (!signedIn) {
      setCollecting(false);
      return undefined;
    }
    let alive = true;
    void fetchProductMetricsCollecting().then((value) => {
      if (alive) setCollecting(value);
    });
    return () => {
      alive = false;
    };
  }, [signedIn]);
  return signedIn && collecting;
}
