import { describe, expect, it } from "vitest";
import {
  MACOS_CLIENT_START_COMMAND,
  MACOS_HOMEBREW_INSTALL_COMMAND,
  MACOS_HOMEBREW_UPGRADE_COMMAND,
  SPECUS_HOMEBREW_TAP_URL,
} from "./macosInstall";

describe("macOS Homebrew instructions", () => {
  it("uses the renamed public tap and the published cask token", () => {
    expect(SPECUS_HOMEBREW_TAP_URL).toBe("https://github.com/devShuai/homebrew-specus");
    expect(MACOS_HOMEBREW_INSTALL_COMMAND).toBe(
      "brew install --cask devshuai/specus/specus-client",
    );
  });

  it("documents the installed binary and upgrade command", () => {
    expect(MACOS_CLIENT_START_COMMAND).toBe("specus-client -config /path/to/client.jsonc");
    expect(MACOS_HOMEBREW_UPGRADE_COMMAND).toBe(
      "brew update && brew upgrade --cask specus-client",
    );
  });
});
