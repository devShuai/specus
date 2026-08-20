import { Buffer } from "node:buffer";
import type { OutputChunk } from "rollup";
import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const DEFAULT_CHUNK_BUDGET_KIB = 500;
const CHUNK_BUDGETS_KIB = new Map([
  // These packages publish their browser player as one pre-bundled ESM module. They are
  // loaded only after the user starts the matching media type, so splitting them further
  // would only add artificial request boundaries without reducing transferred code.
  //
  // media-hls was 550 while hls.js sat on 1.6.x and built to 512.7 KiB. 1.7.1 builds to
  // 580.3 KiB, a 13% jump that no local change caused, so the budget follows upstream rather
  // than pinning the library. 620 keeps roughly the same 7% headroom the old pair had, which
  // is the point of the number: enough room for a patch release, not so much that the next
  // real regression slips through unnoticed.
  ["media-dash", 900],
  ["media-hls", 620],
]);
// Guard the static transitive graph too: several medium chunks can regress a route even when
// every individual file remains below the default limit.
const STATIC_ROUTE_BUDGETS = [
  { facadeSuffix: "/src/pages/PublicDownloadPage.tsx", budgetKib: 300 },
];

function staticChunkGraphBytes(entry: OutputChunk, chunks: Map<string, OutputChunk>): number {
  const pending = [entry.fileName];
  const visited = new Set<string>();
  let bytes = 0;
  while (pending.length > 0) {
    const fileName = pending.pop();
    if (!fileName || visited.has(fileName)) {
      continue;
    }
    visited.add(fileName);
    const chunk = chunks.get(fileName);
    if (!chunk) {
      continue;
    }
    bytes += Buffer.byteLength(chunk.code, "utf8");
    pending.push(...chunk.imports);
  }
  return bytes;
}

function enforceChunkBudgets(): Plugin {
  return {
    name: "specus-chunk-budgets",
    apply: "build",
    generateBundle(_options, bundle) {
      const chunks = Object.values(bundle).filter((output): output is OutputChunk => output.type === "chunk");
      for (const output of chunks) {
        const budgetKib = CHUNK_BUDGETS_KIB.get(output.name) ?? DEFAULT_CHUNK_BUDGET_KIB;
        const bytes = Buffer.byteLength(output.code, "utf8");
        if (bytes > budgetKib * 1024) {
          this.error(
            `${output.fileName} is ${(bytes / 1024).toFixed(2)} KiB; `
              + `the budget for ${output.name} is ${budgetKib} KiB.`,
          );
        }
      }
      const chunksByFileName = new Map(chunks.map((chunk) => [chunk.fileName, chunk]));
      const isApplicationBundle = chunks.some((chunk) =>
        chunk.isEntry && chunk.facadeModuleId?.replace(/\\/g, "/").endsWith("/index.html"),
      );
      for (const { facadeSuffix, budgetKib } of STATIC_ROUTE_BUDGETS) {
        const entry = chunks.find((chunk) =>
          chunk.facadeModuleId?.replace(/\\/g, "/").endsWith(facadeSuffix),
        );
        if (!entry) {
          if (isApplicationBundle) {
            this.error(`Cannot enforce the static route budget: ${facadeSuffix} was not emitted.`);
          }
          continue;
        }
        const bytes = staticChunkGraphBytes(entry, chunksByFileName);
        if (bytes > budgetKib * 1024) {
          this.error(
            `${facadeSuffix} has ${(bytes / 1024).toFixed(2)} KiB of static JavaScript; `
              + `the route budget is ${budgetKib} KiB.`,
          );
        }
      }
    },
  };
}

// Dev server proxies the backend admin/control HTTP surface so `npm run dev` works against a
// locally running specus-server (Go/C#/Java). Override the target with VITE_API_TARGET.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const target = env.VITE_API_TARGET || "http://127.0.0.1:8088";
  const proxy = (paths: string[], ws = false) =>
    Object.fromEntries(paths.map((path) => [path, { target, changeOrigin: true, ws }]));

  return {
    plugins: [react(), enforceChunkBudgets()],
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
      // Vite has one global warning threshold. The stricter per-chunk policy above still
      // enforces 500 KiB by default while allowing audited, lazy, atomic dependencies.
      chunkSizeWarningLimit: 900,
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
            if (normalized.includes("/node_modules/fflate/")) {
              return "diagram-archive";
            }
            if (normalized.includes("/node_modules/hls.js/")) {
              return "media-hls";
            }
            if (normalized.includes("/node_modules/dashjs/")) {
              return "media-dash";
            }
            if (normalized.includes("/node_modules/mp4box/")) {
              return "media-mp4";
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
            // Let Rollup keep remaining dependencies with their actual route or dynamic
            // importer. A generic vendor bucket couples unrelated, rarely used features.
            return undefined;
          },
        },
      },
    },
  };
});
