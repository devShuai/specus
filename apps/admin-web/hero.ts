// HeroUI's Tailwind plugin, loaded by src/tailwind.css through @plugin.
import { heroui } from "@heroui/react";

// The site-wide semantic colors share the diagram editor's Apple-style palette, so HeroUI
// components and the public tool pages match. Every scale carries 50–900: HeroUI's flat/subtle
// variants (Chip, Badge) rely on -100/-200 backgrounds and -600/-700 text.
// The palette is passed to heroui() (the same shape extendTheme takes), which emits the CSS
// variables and semantic utilities. Light and dark switch on the .dark/.light class of <html>
// (see ThemeContext.tsx), which the `dark` custom variant in src/tailwind.css follows.

// src/tailwind.css maps the legacy cyan-* utilities onto these same values; keep the two in sync.
const appleBlueScale = {
  50: "#f0f7ff",
  100: "#e1efff",
  200: "#bfddff",
  300: "#8ec4ff",
  400: "#5aa8ff",
  500: "#2997ff",
  600: "#0077ed",
  700: "#0066cc",
  800: "#0055aa",
  900: "#00447f",
};

// The primary color keeps enough contrast; status colors keep their own hues so the UI does not
// collapse into a single color.
const semanticColors = {
  // primary = Apple blue
  primary: {
    ...appleBlueScale,
    DEFAULT: "#0066cc",
    foreground: "#ffffff",
  },
  // secondary = Apple neutral (secondary actions; no separate cool hue)
  secondary: {
    50: "#f5f5f7",
    100: "#e8e8ed",
    200: "#d2d2d7",
    300: "#b8b8bd",
    400: "#8e8e93",
    500: "#6e6e73",
    600: "#515154",
    700: "#3a3a3c",
    800: "#2c2c2e",
    900: "#1d1d1f",
    DEFAULT: "#6e6e73",
    foreground: "#ffffff",
  },
  // success = emerald
  success: {
    50: "#ecfdf5",
    100: "#d1fae5",
    200: "#a7f3d0",
    300: "#6ee7b7",
    400: "#34d399",
    500: "#10b981",
    600: "#059669",
    700: "#047857",
    800: "#065f46",
    900: "#064e3b",
    DEFAULT: "#10b981",
    foreground: "#ffffff",
  },
  // warning = amber (a solid amber fill needs dark text to reach the contrast ratio)
  warning: {
    50: "#fffbeb",
    100: "#fef3c7",
    200: "#fde68a",
    300: "#fcd34d",
    400: "#fbbf24",
    500: "#f59e0b",
    600: "#d97706",
    700: "#b45309",
    800: "#92400e",
    900: "#78350f",
    DEFAULT: "#f59e0b",
    foreground: "#1a1205",
  },
  // danger = rose
  danger: {
    50: "#fff1f2",
    100: "#ffe4e6",
    200: "#fecdd3",
    300: "#fda4af",
    400: "#fb7185",
    500: "#f43f5e",
    600: "#e11d48",
    700: "#be123c",
    800: "#9f1239",
    900: "#881337",
    DEFAULT: "#f43f5e",
    foreground: "#ffffff",
  },
};

// default = the zinc scale (neutral borders and fills). The light theme uses stock zinc.
const zincScale = {
  50: "#fafafa",
  100: "#f4f4f5",
  200: "#e4e4e7",
  300: "#d4d4d8",
  400: "#a1a1aa",
  500: "#71717a",
  600: "#52525b",
  700: "#3f3f46",
  800: "#27272a",
  900: "#18181b",
};

// Apple-style dark layers: dark surfaces first, readable text last. HeroUI's dark semantic scale
// must run opposite to the light one, or text-default-600 lands on dark gray and
// bg/border-default-* invert as well.
const appleDarkScale = {
  50: "#0f1011",
  100: "#141516",
  200: "#23252a",
  300: "#34343a",
  400: "#8a8f98",
  500: "#a8adb6",
  600: "#d0d6e0",
  700: "#e0e4ea",
  800: "#eef0f3",
  900: "#f7f8f8",
};

export default heroui({
  themes: {
    light: {
      colors: {
        ...semanticColors,
        default: { ...zincScale, DEFAULT: "#e8e8ed", foreground: "#1d1d1f" },
        background: "#f5f5f7",
        foreground: "#1d1d1f",
        content1: "#ffffff",
        content2: "#fbfbfd",
        content3: "#f5f5f7",
        divider: "#e5e5e7",
        focus: "#0066cc",
      },
    },
    dark: {
      colors: {
        ...semanticColors,
        default: { ...appleDarkScale, DEFAULT: "#34343a", foreground: "#f7f8f8" },
        background: "#1d1d1f",
        foreground: { ...appleDarkScale, DEFAULT: "#f5f5f7" },
        content1: { DEFAULT: "#2c2c2e", foreground: "#f5f5f7" },
        content2: { DEFAULT: "#242426", foreground: "#d1d1d6" },
        content3: { DEFAULT: "#323234", foreground: "#d1d1d6" },
        content4: { DEFAULT: "#3a3a3c", foreground: "#d1d1d6" },
        divider: "#3a3a3c",
        focus: "#2997ff",
      },
    },
  },
});
