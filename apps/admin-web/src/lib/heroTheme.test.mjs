import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

// Inspect the authored tokens, not Vite's processed (or test-stubbed) CSS module.
const css = readFileSync(new URL("../hero-theme.css", import.meta.url), "utf8");
const entry = readFileSync(new URL("../tailwind.css", import.meta.url), "utf8");

const declarations = (pattern) => new Map(
  [...css.match(pattern)[1].matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((match) => [match[1], match[2].trim()]),
);
const light = declarations(/\[data-theme="light"\]\s*\{([^}]+)\}/);
const dark = declarations(/\[data-theme="dark"\]\s*\{([^}]+)\}/);
const utilities = declarations(/@theme inline\s*\{([^}]+)\}/);

function luminance(hex) {
  const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255)
    .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}
const contrast = (a, b) => (Math.max(luminance(a), luminance(b)) + 0.05) / (Math.min(luminance(a), luminance(b)) + 0.05);

describe("native HeroUI theme migration", () => {
  it("keeps semantic neutral utilities theme-dependent instead of hard-wiring light zinc", () => {
    for (const step of [50, 100, 200, 300, 400, 500, 600, 700, 800, 900]) {
      expect(utilities.get(`--color-default-${step}`)).toBe(`var(--app-default-${step})`);
      expect(dark.get(`--app-default-${step}`)).not.toBe(light.get(`--app-default-${step}`));
    }
    expect(light.get("--app-default-600")).toBe("#52525b");
    expect(dark.get("--app-default-600")).toBe("#d0d6e0");
  });

  it("retains readable core neutral text and accent button token pairs in both themes", () => {
    for (const theme of [light, dark]) {
      expect(contrast(theme.get("--app-default-600"), theme.get("--surface"))).toBeGreaterThanOrEqual(4.5);
      expect(contrast(theme.get("--accent-foreground"), theme.get("--accent"))).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("loads one native stylesheet entry without the obsolete v2 plugin", () => {
    expect(entry.match(/@import "tailwindcss"/g)).toHaveLength(1);
    expect(entry).toContain('@import "@heroui/react/styles"');
    expect(entry).not.toContain("@plugin");
  });
});
