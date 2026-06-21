// Copies the built SPA (dist/) into each server's static-asset directory so Go/C#/Java all
// ship the same React admin UI. Run via `npm run deploy` (which builds first).
import { cp, rm, readdir, access } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(moduleDir, "..");
const repoRoot = resolve(webRoot, "..");
const dist = join(webRoot, "dist");

const targets = [
  join(repoRoot, "tunnel-server-go", "web", "static"),
  join(repoRoot, "tunnel-server-csharp", "src", "ShuaiTunnel.Server", "wwwroot"),
  join(repoRoot, "tunnel-server", "src", "main", "resources", "static"),
];

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function emptyDir(path) {
  if (!(await exists(path))) {
    return;
  }
  for (const entry of await readdir(path)) {
    await rm(join(path, entry), { recursive: true, force: true });
  }
}

async function main() {
  if (!(await exists(dist))) {
    console.error("dist/ not found — run `npm run build` first.");
    process.exit(1);
  }
  for (const target of targets) {
    if (!(await exists(resolve(target, "..")))) {
      console.warn(`skip (parent missing): ${target}`);
      continue;
    }
    await emptyDir(target);
    await cp(dist, target, { recursive: true });
    console.log(`deployed -> ${target}`);
  }
  console.log("done. Rebuild Go (go build) to re-embed; C#/Java pick up files on next build/run.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
