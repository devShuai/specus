import { copyFile, mkdir, readdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const appRoot = resolve(moduleDir, "..");
const repoRoot = resolve(appRoot, "..", "..");
const sourceDir = resolve(repoRoot, "protocol", "schemas");
const targetDir = resolve(appRoot, "public", "schemas");

await rm(targetDir, { recursive: true, force: true });
await mkdir(targetDir, { recursive: true });

const entries = await readdir(sourceDir, { withFileTypes: true });
const schemas = entries
  .filter((entry) => entry.isFile() && entry.name.endsWith(".schema.json"))
  .map((entry) => entry.name)
  .sort();

for (const schema of schemas) {
  await copyFile(resolve(sourceDir, schema), resolve(targetDir, schema));
}

console.log(`synced ${schemas.length} schemas to ${targetDir}`);
