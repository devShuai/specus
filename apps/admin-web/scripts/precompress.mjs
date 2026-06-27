// Pre-compress Vite static assets for OpenResty/nginx gzip_static and optional brotli_static.
import { constants, createReadStream, createWriteStream } from "node:fs";
import { access, readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createBrotliCompress, createGzip, constants as zlibConstants } from "node:zlib";
import { pipeline } from "node:stream/promises";

const distDir = fileURLToPath(new URL("../dist/", import.meta.url));
const MIN_BYTES = 1024;
const COMPRESSIBLE_EXTENSIONS = new Set([
  ".css",
  ".html",
  ".js",
  ".json",
  ".map",
  ".mjs",
  ".svg",
  ".txt",
  ".webmanifest",
  ".xml",
]);

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function extension(name) {
  const index = name.lastIndexOf(".");
  return index === -1 ? "" : name.slice(index).toLowerCase();
}

async function collectFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await collectFiles(path));
      continue;
    }
    if (!entry.isFile() || entry.name.endsWith(".gz") || entry.name.endsWith(".br")) {
      continue;
    }
    if (COMPRESSIBLE_EXTENSIONS.has(extension(entry.name))) {
      files.push(path);
    }
  }
  return files;
}

async function compressFile(source, target, streamFactory) {
  const temp = `${target}.tmp`;
  await pipeline(createReadStream(source), streamFactory(), createWriteStream(temp));
  const [sourceInfo, targetInfo] = await Promise.all([stat(source), stat(temp)]);
  if (targetInfo.size >= sourceInfo.size) {
    await unlink(temp);
    return false;
  }
  await unlink(target).catch(() => {});
  await import("node:fs/promises").then(({ rename }) => rename(temp, target));
  return true;
}

async function main() {
  if (!(await exists(distDir))) {
    console.error("dist/ not found. Run `npm run build` first.");
    process.exit(1);
  }

  const files = await collectFiles(distDir);
  let gzipCount = 0;
  let brotliCount = 0;
  for (const file of files) {
    const info = await stat(file);
    if (info.size < MIN_BYTES) {
      continue;
    }
    if (await compressFile(file, `${file}.gz`, () => createGzip({ level: 9 }))) {
      gzipCount += 1;
    }
    if (
      await compressFile(file, `${file}.br`, () =>
        createBrotliCompress({
          params: {
            [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
            [zlibConstants.BROTLI_PARAM_SIZE_HINT]: info.size,
          },
        }))
    ) {
      brotliCount += 1;
    }
  }
  console.log(`precompressed ${gzipCount} gzip file(s), ${brotliCount} brotli file(s)`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
