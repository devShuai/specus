import { describe, expect, it } from "vitest";
import {
  natClassificationProfile,
  natFilteringBehaviorLabel,
  natMappingBehaviorLabel,
} from "./nat";

describe("NAT behavior classification", () => {
  it("treats EIM plus EIF as direct friendly", () => {
    const profile = natClassificationProfile(
      "FULL_CONE_OR_RESTRICTED_NAT",
      "ENDPOINT_INDEPENDENT",
      "ENDPOINT_INDEPENDENT",
    );

    expect(profile.key).toBe("EIM_EIF");
    expect(profile.label).toBe("EIM + EIF");
    expect(profile.reachability).toBe("direct");
  });

  it("treats EIM plus APDF as constrained rather than target-dependent", () => {
    const profile = natClassificationProfile(
      "PORT_RESTRICTED_NAT",
      "ENDPOINT_INDEPENDENT",
      "ADDRESS_AND_PORT_DEPENDENT",
    );

    expect(profile.key).toBe("EIM_APDF");
    expect(profile.reachability).toBe("conditional");
  });

  it.each([
    ["ADDRESS_DEPENDENT", "ADM_ADF", "ADM + ADF"],
    ["ADDRESS_AND_PORT_DEPENDENT", "APDM_ADF", "APDM + ADF"],
  ])("prioritizes %s mapping for relay guidance", (mapping, key, label) => {
    const profile = natClassificationProfile(
      "SYMMETRIC_NAT",
      mapping,
      "ADDRESS_DEPENDENT",
    );

    expect(profile.key).toBe(key);
    expect(profile.label).toBe(label);
    expect(profile.reachability).toBe("relay");
  });

  it("keeps the compatibility profile when behavior discovery is unavailable", () => {
    const profile = natClassificationProfile("PORT_PRESERVED_NAT", null, null);

    expect(profile.key).toBe("PORT_PRESERVED_NAT");
    expect(profile.label).toContain("基础判断");
  });

  it("uses axis-specific RFC 5780 labels", () => {
    expect(natMappingBehaviorLabel("ADDRESS_AND_PORT_DEPENDENT")).toBe("地址和端口相关映射（APDM）");
    expect(natFilteringBehaviorLabel("ADDRESS_AND_PORT_DEPENDENT")).toBe("地址和端口相关过滤（APDF）");
  });
});
