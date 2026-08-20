/** @type {import('tailwindcss').Config} */
import { heroui } from "@heroui/react";

// 全站语义色与专业流程图编辑器共用 Apple 风格色板，保证 HeroUI 组件和公开工具页一致。
// 色阶 50–900 同时给出，HeroUI 的 flat/subtle 变体（Chip、Badge）依赖 -100/-200 底与 -600/-700 文字。
// 配置写在 heroui() 插件里（extendTheme 的同形配置），由插件生成 CSS 变量与语义工具类；
// 深浅主题靠 <html> 上的 .dark/.light 切换（见 ThemeContext.tsx），与 darkMode: "class" 一致。

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

// 主色保持足够对比度，状态色继续使用各自语义色，避免界面退化成单色。
const semanticColors = {
  // primary = Apple blue
  primary: {
    ...appleBlueScale,
    DEFAULT: "#0066cc",
    foreground: "#ffffff",
  },
  // secondary = Apple neutral（用于次级操作，不引入独立冷色系）
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

// default = zinc 色阶（中性边框/底纹用）。浅色主题沿用标准 zinc。
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

// Apple 风格的暗色层级：深色表面在前、可读文字在后。HeroUI 的暗色语义色阶必须
// 与浅色相反，否则 text-default-600 会落成深灰，bg/border-default-* 也会反向失真。
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

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
    "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
    // npm can keep HeroUI's theme package nested under @heroui/react.
    "./node_modules/@heroui/react/node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      // 历史页面仍使用 cyan-* 工具类，在主题层映射为编辑器蓝以保留原有状态选择器。
      colors: {
        cyan: appleBlueScale,
      },
      // Inter 变体字体 + CJK 系统回退（中文走系统字体，不内嵌巨型 CJK 字体）。
      fontFamily: {
        sans: [
          "Inter Variable",
          "Inter",
          "PingFang SC",
          "Hiragino Sans GB",
          "Microsoft YaHei",
          "Noto Sans CJK SC",
          "Noto Sans SC",
          "system-ui",
          "sans-serif",
        ],
      },
      // 与专业编辑器一致，所有显示字号保持自然字距。
      fontSize: {
        "display-xl": ["3rem", { lineHeight: "1.05", letterSpacing: "0" }],
        "display-lg": ["2rem", { lineHeight: "1.1", letterSpacing: "0" }],
        "display-md": ["1.5rem", { lineHeight: "1.15", letterSpacing: "0" }],
        "display-sm": ["1.25rem", { lineHeight: "1.2", letterSpacing: "0" }],
      },
    },
  },
  darkMode: "class",
  plugins: [
    heroui({
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
    }),
  ],
};
