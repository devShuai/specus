import { describe, expect, it } from "vitest";
import { signedRotationDelta } from "./diagramRotation";

describe("diagram rotation", () => {
  it("keeps clockwise rotation continuous across the angle boundary", () => {
    expect(signedRotationDelta(179, -179)).toBe(2);
  });

  it("keeps counter-clockwise rotation continuous across the angle boundary", () => {
    expect(signedRotationDelta(-179, 179)).toBe(-2);
  });

  it("accumulates more than one complete turn", () => {
    const pointerAngles = [-90, 0, 90, 180, -90, 0, 90, 180, -90, 0];
    const rotation = pointerAngles.slice(1).reduce(
      (total, angle, index) => total + signedRotationDelta(pointerAngles[index], angle),
      0,
    );

    expect(rotation).toBe(810);
  });
});
