import { describe, expect, it } from "vitest";
import { buildClientStartupConfig, CLIENT_ONBOARDING_STEPS, clientOnboardingStatus } from "./clientOnboarding";

describe("client onboarding", () => {
  it("requires an online instance before guiding users to publish", () => {
    expect(CLIENT_ONBOARDING_STEPS.map((step) => step.title)).toEqual([
      "下载客户端", "创建接入凭证并保存配置", "启动客户端，确认设备上线", "发布服务并验证访问",
    ]);
  });
  it("generates the shared startup format without exposing credentials in the URL", () => {
    const value = JSON.parse(buildClientStartupConfig("https://server.example/base/", " key ", "s\"e\\cret\nvalue"));
    expect(value).toEqual({ serverBaseUrl: "https://server.example/base", apiKey: "key", secret: "s\"e\\cret\nvalue" });
  });
  it.each(["javascript:alert(1)", "https://user:secret@example.com", "https://example.com?token=x", "https://example.com#token=x", "not a url"])("rejects an unsafe base URL: %s", (url) => {
    expect(() => buildClientStartupConfig(url, "key", "secret")).toThrow();
  });
  it("does not mistake a failed load for an empty account", () => {
    expect(clientOnboardingStatus({ loading: false, error: true, online: 0, registered: 0, credentials: 0 })).toContain("状态未知");
    expect(clientOnboardingStatus({ loading: false, error: false, online: 0, registered: 0, credentials: 1 })).toContain("先启动客户端");
    expect(clientOnboardingStatus({ loading: false, error: false, online: 1, registered: 1, credentials: 1 })).toContain("仍需实际验证");
  });
});
