/** @type {import('tailwindcss').Config} */
import { heroui } from "@heroui/react";

// shuai-tunnel 品牌语义色：直接复用项目已有的 Tailwind 调色板 hex，保证 HeroUI 语义令牌
// (color="primary" / bg-primary / border-default-200 …) 与散落的 bg-cyan-500 等工具类同色。
// 色阶 50–900 同时给出，HeroUI 的 flat/subtle 变体（Chip、Badge）依赖 -100/-200 底与 -600/-700 文字。
// 配置写在 heroui() 插件里（extendTheme 的同形配置），由插件生成 CSS 变量与语义工具类；
// 深浅主题靠 <html> 上的 .dark/.light 切换（见 ThemeContext.tsx），与 darkMode: "class" 一致。

// 饱和语义色：light/dark 共用同一套色阶（HeroUI 组件自带深浅感知变体），仅 DEFAULT/foreground 固定。
const semanticColors = {
  // primary = cyan（主色，对应现有 cyan-500 系）
  primary: {
    50: "#ecfeff",
    100: "#cffafe",
    200: "#a5f3fc",
    300: "#67e8f9",
    400: "#22d3ee",
    500: "#06b6d4",
    600: "#0891b2",
    700: "#0e7490",
    800: "#155e75",
    900: "#164e63",
    DEFAULT: "#06b6d4",
    foreground: "#ffffff",
  },
  // secondary = slate（低调中性灰，带轻微冷调，不抢 cyan 主色；与 zinc 中性可区分）
  secondary: {
    50: "#f8fafc",
    100: "#f1f5f9",
    200: "#e2e8f0",
    300: "#cbd5e1",
    400: "#94a3b8",
    500: "#64748b",
    600: "#475569",
    700: "#334155",
    800: "#1e293b",
    900: "#0f172a",
    DEFAULT: "#64748b",
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
  // warning = amber（amber 实底需深色文字才达标对比度）
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

// default = zinc 色阶（中性边框/底纹用）。DEFAULT/foreground 按深浅反转：浅色实底按钮=深、暗色实底按钮=浅，
// 与 HeroUI 默认中性按钮语义一致。色阶共用，DEFAULT/foreground 分主题给。
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

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
    // npm can keep HeroUI's theme package nested under @heroui/react.
    "./node_modules/@heroui/react/node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  darkMode: "class",
  plugins: [
    heroui({
      themes: {
        light: {
          colors: {
            ...semanticColors,
            default: { ...zincScale, DEFAULT: "#18181b", foreground: "#fafafa" },
            background: "#ffffff",
            foreground: "#18181b",
            content1: "#ffffff",
            content2: "#fafafa",
            content3: "#f4f4f5",
            divider: "#e4e4e7",
            focus: "#06b6d4",
          },
        },
        dark: {
          colors: {
            ...semanticColors,
            default: { ...zincScale, DEFAULT: "#fafafa", foreground: "#18181b" },
            background: "#09090b",
            foreground: "#f4f4f5",
            content1: "#18181b",
            content2: "#27272a",
            content3: "#3f3f46",
            divider: "#27272a",
            focus: "#22d3ee",
          },
        },
      },
    }),
  ],
};
