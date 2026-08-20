import { Buffer } from "node:buffer";
import type { OutputChunk } from "rollup";
import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
// Tailwind 4 的官方 Vite 插件。走 PostCSS 时 Vite 没有应用 postcss.config.js，
// @source 指令原样落进产物、工具类一条都没生成；这个插件是官方推荐的接法。
import tailwindcss from "@tailwindcss/vite";

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

/** Matches a package directory under node_modules, on either path separator. */
function NM(pkg: string): RegExp {
  return new RegExp(`[\\/]node_modules[\\/]${pkg}[\\/]`);
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
    plugins: [tailwindcss(),react(), enforceChunkBudgets()],
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
          // rolldown replaced manualChunks with codeSplitting. The difference that
          // matters here: a group is a hard assignment, so React's small entry
          // shims (jsx-runtime, react-dom) stay in react-vendor instead of being
          // copied into whichever vendor chunk imports them. With manualChunks the
          // public download route ended up importing two of those copies out of
          // heroui-vendor, which put the whole 438 KiB component library in its
          // static graph even though the page renders no HeroUI component.
          //
          // Groups are matched in order, so the list reads like the old if-chain.
          // Anything unmatched stays with its actual route or dynamic importer —
          // a generic vendor bucket would couple unrelated, rarely used features.
          codeSplitting: {
            groups: [
              { name: "vite-runtime", test: /vite[\/]preload-helper/ },

              { name: "react-vendor", test: NM("(react|react-dom|scheduler|use-sync-external-store)") },

              { name: "diagram-engine", test: NM("@maxgraph[\/]core") },
              { name: "diagram-collaboration", test: NM("(yjs|lib0|isomorphic\.js)") },
              { name: "diagram-compression", test: NM("pako") },
              { name: "diagram-archive", test: NM("fflate") },
              { name: "media-hls", test: NM("hls\.js") },
              { name: "media-dash", test: NM("dashjs") },
              { name: "media-mp4", test: NM("mp4box") },

              { name: "motion-vendor", test: NM("framer-motion") },
              // tailwind-variants and tailwind-merge ship CJS; keeping them out of
              // heroui-vendor stops their interop helpers from anchoring the whole
              // component library into a route that only needed a helper.
              { name: "style-utils", test: NM("(tailwind-variants|tailwind-merge)") },
              { name: "heroui-vendor", test: NM("(@heroui|@radix-ui|input-otp)") },
              // HeroUI 3 builds on react-aria-components, a top-level package that
              // the scoped @react-aria/* pattern does not cover.
              { name: "react-aria", test: NM("(react-aria-components|react-aria|@react-aria)") },
              { name: "react-stately", test: NM("@react-stately") },
              { name: "react-types", test: NM("@react-types") },
              { name: "intl-vendor", test: NM("@internationalized") },
              { name: "floating-ui", test: NM("@floating-ui") },
            ],
          },
        },
      },
    },
  };
});
