// Copies the built SPA (dist/) into selected server static-asset directories.
// Run via `npm run deploy:<target>` so each server build only touches its own assets.
import { cp, rm, readdir, access, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(moduleDir, "..");
const repoRoot = resolve(webRoot, "..", "..");
const dist = join(webRoot, "dist");

const targets = {
  go: join(repoRoot, "implementations", "go", "server", "web", "static"),
  csharp: join(repoRoot, "implementations", "csharp", "server", "src", "Specus.Server", "wwwroot"),
  java: join(repoRoot, "implementations", "java", "server", "src", "main", "resources", "static"),
};

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

async function normalizeIndexHtml(path) {
  const index = join(path, "index.html");
  if (!(await exists(index))) {
    return;
  }
  const html = await readFile(index, "utf8");
  await writeFile(index, html.replace(/\r\n/g, "\n"), "utf8");
}

function requestedTargets() {
  const args = process.argv.slice(2);
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--target" || arg === "-t") {
      values.push(args[index + 1] ?? "");
      index += 1;
      continue;
    }
    if (arg.startsWith("--target=")) {
      values.push(arg.slice("--target=".length));
      continue;
    }
    if (!arg.startsWith("-")) {
      values.push(arg);
    }
  }
  const names = values.flatMap((value) => value.split(",")).map((value) => value.trim()).filter(Boolean);
  if (names.length === 0 || names.includes("all")) {
    return Object.keys(targets);
  }
  const unknown = names.filter((name) => !targets[name]);
  if (unknown.length > 0) {
    console.error(`unknown target(s): ${unknown.join(", ")}`);
    console.error(`valid targets: ${Object.keys(targets).join(", ")}, all`);
    process.exit(1);
  }
  return [...new Set(names)];
}

async function main() {
  if (!(await exists(dist))) {
    console.error("dist/ not found — run `npm run build` first.");
    process.exit(1);
  }
  const names = requestedTargets();
  for (const name of names) {
    const target = targets[name];
    if (!(await exists(resolve(target, "..")))) {
      console.warn(`skip (parent missing): ${target}`);
      continue;
    }
    await emptyDir(target);
    await cp(dist, target, { recursive: true });
    await normalizeIndexHtml(target);
    console.log(`deployed ${name} -> ${target}`);
  }
  console.log(`done. target(s): ${names.join(", ")}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
