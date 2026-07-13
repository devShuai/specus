import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { DOMParser } from "@xmldom/xmldom";

const sourceRoot = path.resolve(process.argv[2] ?? "../../../../drawio/src/main/webapp/stencils");
const targetRoot = path.resolve(process.argv[3] ?? "public/drawio-stencils");

const GROUPS = [
  { id: "general", name: "通用与流程" },
  { id: "software", name: "软件与业务建模" },
  { id: "cloud", name: "云平台与容器" },
  { id: "network", name: "网络与基础设施" },
  { id: "engineering", name: "工程与制造" },
  { id: "ui", name: "界面与移动端" },
  { id: "symbols", name: "标识与图标" },
  { id: "other", name: "行业与其他" },
];

const DISPLAY_NAMES = new Map(Object.entries({
  basic: "基础图形",
  arrows: "箭头",
  flowchart: "流程图",
  bpmn: "BPMN",
  eip: "企业集成模式",
  lean_mapping: "精益价值流",
  sitemap: "站点地图",
  floorplan: "平面图",
  fluid_power: "流体动力",
  networks: "网络图",
  networks2: "网络图 2",
  kubernetes: "Kubernetes",
  kubernetes2: "Kubernetes 2",
  openstack: "OpenStack",
  alibaba_cloud: "阿里云",
  ibm_cloud: "IBM Cloud",
  gmdl: "Material Design",
  webicons: "Web 图标",
  weblogos: "Web Logo",
  cabinets: "机柜",
  cisco19: "Cisco 2019",
  citrix: "Citrix",
  citrix2: "Citrix 2",
  salesforce: "Salesforce",
  atlassian: "Atlassian",
  bootstrap: "Bootstrap",
  vvd: "VMware Validated Design",
}));

const GROUP_PREFIXES = [
  ["cloud", /^(aws|aws2|aws3|aws3d|aws4|azure|gcp|gcp2|gcp3|alibaba_cloud|ibm_cloud|openstack|kubernetes)/],
  ["network", /^(networks|cisco|cisco19|cisco_safe|citrix|citrix2|office|rack|cabinets|veeam|vvd|mscae|ibm(?:\/|$))/],
  ["engineering", /^(electrical|pid|fluid_power|floorplan)/],
  ["ui", /^(mockup|android|ios7|bootstrap|gmdl)/],
  ["symbols", /^(signs|webicons|weblogos|arrows)/],
  ["software", /^(bpmn|eip|lean_mapping|sitemap|atlassian|salesforce)/],
  ["general", /^(basic|flowchart)/],
];

function groupFor(filePath) {
  const withoutExtension = filePath.replace(/\.xml$/i, "");
  return GROUP_PREFIXES.find(([, pattern]) => pattern.test(withoutExtension))?.[0] ?? "other";
}

function titleCase(value) {
  return value
    .split(/[\/_-]+/)
    .filter(Boolean)
    .map((part) => part.length <= 4 ? part.toUpperCase() : `${part[0].toUpperCase()}${part.slice(1)}`)
    .join(" · ");
}

function libraryName(filePath) {
  const withoutExtension = filePath.replace(/\.xml$/i, "");
  return DISPLAY_NAMES.get(withoutExtension)
    ?? DISPLAY_NAMES.get(path.basename(withoutExtension))
    ?? titleCase(withoutExtension);
}

async function walkXmlFiles(directory, relative = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relativePath = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) {
      files.push(...await walkXmlFiles(path.join(directory, entry.name), relativePath));
    } else if (entry.isFile() && entry.name.endsWith(".xml")) {
      files.push(relativePath);
    }
  }
  return files;
}

function shapeKey(namespace, name) {
  return `${namespace}.${name.replace(/ /g, "_")}`.toLowerCase();
}

async function parseLibrary(filePath) {
  const xml = await readFile(path.join(sourceRoot, filePath), "utf8");
  const document = new DOMParser().parseFromString(xml, "application/xml");
  const root = document.documentElement;
  if (!root || root.nodeName !== "shapes") {
    throw new Error(`Unsupported stencil root in ${filePath}`);
  }
  const namespace = root.getAttribute("name")?.trim();
  if (!namespace) {
    throw new Error(`Missing stencil namespace in ${filePath}`);
  }
  const shapes = Array.from(root.childNodes)
    .filter((node) => node.nodeType === 1 && node.nodeName === "shape")
    .map((node, index) => {
      const name = node.getAttribute("name")?.trim();
      if (!name) {
        throw new Error(`Missing shape name in ${filePath} at index ${index}`);
      }
      return {
        id: `${filePath}#${index}`,
        name,
        shape: shapeKey(namespace, name),
        width: Number(node.getAttribute("w")) || 100,
        height: Number(node.getAttribute("h")) || 100,
        aspect: node.getAttribute("aspect") || "variable",
      };
    });
  return {
    id: filePath.replace(/\.xml$/i, ""),
    name: libraryName(filePath),
    group: groupFor(filePath),
    path: filePath,
    namespace: namespace.toLowerCase(),
    shapeCount: shapes.length,
    shapes,
  };
}

const files = await walkXmlFiles(sourceRoot);
const libraries = [];
for (const file of files) {
  libraries.push(await parseLibrary(file));
}

await rm(targetRoot, { recursive: true, force: true });
await mkdir(path.dirname(targetRoot), { recursive: true });
await cp(sourceRoot, targetRoot, { recursive: true });
const catalog = {
  format: "shuai-drawio-stencil-catalog",
  version: 1,
  generatedAt: new Date().toISOString(),
  source: "https://github.com/jgraph/drawio/tree/dev/src/main/webapp/stencils",
  groups: GROUPS,
  libraryCount: libraries.length,
  shapeCount: libraries.reduce((sum, library) => sum + library.shapeCount, 0),
  libraries,
};
await writeFile(path.join(targetRoot, "catalog.json"), `${JSON.stringify(catalog)}\n`, "utf8");
console.log(`Synced ${catalog.libraryCount} draw.io libraries with ${catalog.shapeCount} shapes.`);
