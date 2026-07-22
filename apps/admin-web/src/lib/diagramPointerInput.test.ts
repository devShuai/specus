import { describe, expect, it, vi } from "vitest";
import { isTouchGesture, preserveTouchTap } from "./diagramPointerInput";
import type { DiagramGestureEvent } from "./diagramPointerInput";

describe("diagram palette pointer input", () => {
  it("recognizes touch and pointer-based touch gestures", () => {
    expect(isTouchGesture({ type: "touchstart" })).toBe(true);
    expect(isTouchGesture({ type: "pointerdown", pointerType: "touch" })).toBe(true);
    expect(isTouchGesture({ type: "pointerdown", pointerType: "mouse" })).toBe(false);
    expect(isTouchGesture({ type: "mousedown" })).toBe(false);
  });

  it("leaves touch taps for the button click handler while retaining mouse drag", () => {
    const dragStart = vi.fn<(event: DiagramGestureEvent) => void>();
    const handleGesture = preserveTouchTap(dragStart);

    handleGesture({ type: "touchstart" });
    handleGesture({ type: "pointerdown", pointerType: "touch" });
    expect(dragStart).not.toHaveBeenCalled();

    handleGesture({ type: "pointerdown", pointerType: "mouse" });
    handleGesture({ type: "mousedown" });
    expect(dragStart).toHaveBeenCalledTimes(2);
  });
});
