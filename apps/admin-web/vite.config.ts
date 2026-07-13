import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies the backend admin/control HTTP surface so `npm run dev` works against a
// locally running tunnel-server (Go/C#/Java). Override the target with VITE_API_TARGET.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_API_TARGET || "http://127.0.0.1:8088";
  const proxy = (paths: string[], ws = false) =>
    Object.fromEntries(paths.map((path) => [path, { target, changeOrigin: true, ws }]));

  return {
    plugins: [react()],
    base: "/",
    server: {
      port: 5173,
      proxy: {
        ...proxy(["/api", "/auth", "/oidc-config", "/oidc", "/http", "/health"]),
        ...proxy(["/ws"], true),
      },
    },
    build: {
      outDir: "dist",
      // Keep asset paths stable under /assets so any static file server can serve the SPA.
      assetsDir: "assets",
      modulePreload: {
        resolveDependencies(_filename, deps) {
          return deps.filter((dep) => dep.includes("react-vendor"));
        },
      },
      rollupOptions: {
        output: {
          manualChunks(id) {
            const normalized = id.replace(/\\/g, "/");
            if (normalized.includes("vite/preload-helper")) {
              return "vite-runtime";
            }
            if (!normalized.includes("/node_modules/")) {
              return undefined;
            }

            if (normalized.includes("/node_modules/@maxgraph/core/")) {
              return "diagram-engine";
            }
            if (
              normalized.includes("/node_modules/yjs/")
              || normalized.includes("/node_modules/lib0/")
              || normalized.includes("/node_modules/isomorphic.js/")
            ) {
              return "diagram-collaboration";
            }
            if (normalized.includes("/node_modules/pako/")) {
              return "diagram-compression";
            }
            if (
              normalized.includes("/node_modules/jspdf/")
              || normalized.includes("/node_modules/fflate/")
              || normalized.includes("/node_modules/fast-png/")
              || normalized.includes("/node_modules/canvg/")
              || normalized.includes("/node_modules/html2canvas/")
              || normalized.includes("/node_modules/dompurify/")
              || normalized.includes("/node_modules/core-js/")
              || normalized.includes("/node_modules/regenerator-runtime/")
              || normalized.includes("/node_modules/raf/")
              || normalized.includes("/node_modules/rgbcolor/")
              || normalized.includes("/node_modules/stackblur-canvas/")
              || normalized.includes("/node_modules/svg-pathdata/")
              || normalized.includes("/node_modules/css-line-break/")
              || normalized.includes("/node_modules/text-segmentation/")
            ) {
              return "diagram-pdf";
            }

            if (
              normalized.includes("/node_modules/react/") ||
              normalized.includes("/node_modules/react-dom/") ||
              normalized.includes("/node_modules/scheduler/") ||
              normalized.includes("/node_modules/use-sync-external-store/")
            ) {
              return "react-vendor";
            }
            if (normalized.includes("/node_modules/framer-motion/")) {
              return "motion-vendor";
            }
            if (normalized.includes("/node_modules/@heroui/")) {
              return "heroui-vendor";
            }
            if (normalized.includes("/node_modules/@react-aria/")) {
              return "react-aria";
            }
            if (normalized.includes("/node_modules/@react-stately/")) {
              return "react-stately";
            }
            if (normalized.includes("/node_modules/@react-types/")) {
              return "react-types";
            }
            if (normalized.includes("/node_modules/@internationalized/")) {
              return "intl-vendor";
            }
            if (normalized.includes("/node_modules/@floating-ui/")) {
              return "floating-ui";
            }
            return "vendor";
          },
        },
      },
    },
  };
});
