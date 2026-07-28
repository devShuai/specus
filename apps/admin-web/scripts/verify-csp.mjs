import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(moduleDir, "..");
const repoRoot = resolve(webRoot, "..", "..");
const indexFlagIndex = process.argv.indexOf("--index");
const indexArgument = process.argv.find((argument) => argument.startsWith("--index="))
  ?.slice("--index=".length)
  ?? (indexFlagIndex >= 0 ? process.argv[indexFlagIndex + 1] : undefined);
const indexPath = resolve(webRoot, indexArgument || "index.html");
const policySources = [
  {
    label: "Java",
    path: join(
      repoRoot,
      "implementations",
      "java",
      "server",
      "src",
      "main",
      "java",
      "com",
      "theshuai",
      "specusserver",
      "config",
      "SecurityConfig.java",
    ),
  },
  {
    label: "Go",
    path: join(
      repoRoot,
      "implementations",
      "go",
      "server",
      "internal",
      "server",
      "app.go",
    ),
  },
  {
    label: ".NET",
    path: join(
      repoRoot,
      "implementations",
      "csharp",
      "server",
      "src",
      "Specus.Server",
      "Management",
      "ManagementPageSecurityHeaders.cs",
    ),
  },
  {
    label: "OpenResty",
    path: join(repoRoot, "deploy", "openresty", "specus.conf"),
  },
];

const executableTypes = new Set([
  "",
  "application/javascript",
  "module",
  "text/javascript",
]);
const hashPattern = /'(?<hash>sha256-[A-Za-z0-9+/]+={0,2})'/g;

function inlineScriptHashes(html) {
  const hashes = new Set();
  const scripts = html.matchAll(/<script\b(?<attrs>[^>]*)>(?<body>[\s\S]*?)<\/script>/gi);
  for (const match of scripts) {
    const attrs = match.groups?.attrs ?? "";
    if (/\bsrc\s*=/i.test(attrs)) {
      continue;
    }
    const type = attrs.match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1]
      ?.trim()
      .toLowerCase() ?? "";
    if (!executableTypes.has(type)) {
      continue;
    }
    const body = match.groups?.body ?? "";
    hashes.add(`sha256-${createHash("sha256").update(body, "utf8").digest("base64")}`);
  }
  return hashes;
}

function configuredHashes(source) {
  return new Set(
    [...source.matchAll(hashPattern)]
      .map((match) => match.groups?.hash)
      .filter(Boolean),
  );
}

function difference(left, right) {
  return [...left].filter((value) => !right.has(value));
}

async function main() {
  const expected = inlineScriptHashes(await readFile(indexPath, "utf8"));
  if (expected.size === 0) {
    throw new Error("index.html 中没有找到可执行内联脚本");
  }

  const failures = [];
  for (const target of policySources) {
    const actual = configuredHashes(await readFile(target.path, "utf8"));
    const missing = difference(expected, actual);
    const obsolete = difference(actual, expected);
    if (missing.length > 0 || obsolete.length > 0) {
      failures.push(
        `${target.label}: missing=[${missing.join(", ")}], obsolete=[${obsolete.join(", ")}]`,
      );
    }
  }
  if (failures.length > 0) {
    throw new Error(`CSP 内联脚本哈希未同步:\n${failures.join("\n")}`);
  }
  console.log(`verified ${expected.size} inline script hash(es) across ${policySources.length} CSP targets`);
}

await main();
