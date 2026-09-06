import { useEffect } from "react";

/** Browsers control the wording and may suppress this prompt, especially on mobile. */
export function useFileLeaveWarning(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [enabled]);
}
