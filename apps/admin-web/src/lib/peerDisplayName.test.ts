import { describe, expect, it } from "vitest";
import { decodeLegacyPeerDisplayName } from "./peerDisplayName";

describe("decodeLegacyPeerDisplayName", () => {
  it("decodes UTF-8 form encoded names returned by legacy servers", () => {
    expect(decodeLegacyPeerDisplayName("%E7%BD%91%E9%A1%B5%E8%AE%BE%E5%A4%87+%C2%B7+6"))
      .toBe("网页设备 · 6");
  });

  it("keeps literal plus signs in already decoded names", () => {
    expect(decodeLegacyPeerDisplayName("C++ Builder")).toBe("C++ Builder");
  });

  it("keeps malformed encoded names unchanged", () => {
    expect(decodeLegacyPeerDisplayName("device-%E0%A4%A")).toBe("device-%E0%A4%A");
  });
});
