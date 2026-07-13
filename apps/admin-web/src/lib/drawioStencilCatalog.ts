import { Shape, StencilShape, StencilShapeRegistry, SvgCanvas2D } from "@maxgraph/core";

export const DRAWIO_STENCIL_BASE_URL = "/drawio-stencils";

export interface DrawioStencilGroup {
  id: string;
  name: string;
}

export interface DrawioStencilShape {
  id: string;
  name: string;
  shape: string;
  width: number;
  height: number;
  aspect: string;
}

export interface DrawioStencilLibrary {
  id: string;
  name: string;
  group: string;
  path: string;
  namespace: string;
  shapeCount: number;
  shapes: DrawioStencilShape[];
}

export interface DrawioStencilCatalog {
  format: "shuai-drawio-stencil-catalog";
  version: 1;
  generatedAt: string;
  source: string;
  groups: DrawioStencilGroup[];
  libraryCount: number;
  shapeCount: number;
  libraries: DrawioStencilLibrary[];
}

let catalogPromise: Promise<DrawioStencilCatalog> | undefined;
const libraryPromises = new Map<string, Promise<number>>();

export function loadDrawioStencilCatalog(): Promise<DrawioStencilCatalog> {
  catalogPromise ??= fetch(`${DRAWIO_STENCIL_BASE_URL}/catalog.json`)
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`图形库清单加载失败 (${response.status})`);
      }
      const value: unknown = await response.json();
      if (!isDrawioStencilCatalog(value)) {
        throw new Error("draw.io 图形库清单格式无效");
      }
      return value;
    })
    .catch((error) => {
      catalogPromise = undefined;
      throw error;
    });
  return catalogPromise;
}

export function loadDrawioStencilLibrary(library: DrawioStencilLibrary): Promise<number> {
  const existing = libraryPromises.get(library.path);
  if (existing) {
    return existing;
  }
  const pending = fetch(`${DRAWIO_STENCIL_BASE_URL}/${library.path}`)
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`${library.name} 加载失败 (${response.status})`);
      }
      return registerDrawioStencilXml(await response.text());
    })
    .catch((error) => {
      libraryPromises.delete(library.path);
      throw error;
    });
  libraryPromises.set(library.path, pending);
  return pending;
}

export function registerDrawioStencilXml(xml: string): number {
  const document = new DOMParser().parseFromString(xml, "application/xml");
  if (document.querySelector("parsererror")) {
    throw new Error("draw.io 图形库 XML 无效");
  }
  const roots = document.documentElement.nodeName === "stencils"
    ? Array.from(document.documentElement.children).filter((element) => element.nodeName === "shapes")
    : [document.documentElement];
  let count = 0;
  for (const root of roots) {
    if (root.nodeName !== "shapes") {
      continue;
    }
    const namespace = root.getAttribute("name")?.trim().toLowerCase();
    if (!namespace) {
      continue;
    }
    for (const element of Array.from(root.children)) {
      if (element.nodeName !== "shape") {
        continue;
      }
      const name = element.getAttribute("name")?.trim();
      if (!name) {
        continue;
      }
      StencilShapeRegistry.add(drawioStencilShapeName(namespace, name), new StencilShape(element));
      count += 1;
    }
  }
  return count;
}

export function drawioStencilShapeName(namespace: string, shapeName: string): string {
  return `${namespace}.${shapeName.replace(/ /g, "_")}`.toLowerCase();
}

export function createDrawioStencilPreviewShape(stencilName: string): Shape | undefined {
  const stencil = StencilShapeRegistry.get(stencilName);
  if (!stencil) {
    return undefined;
  }
  const shape = new Shape(stencil);
  shape.fill = "#f8fafc";
  shape.stroke = "#334155";
  shape.strokeWidth = 1.4;
  shape.opacity = 100;
  shape.fillOpacity = 100;
  shape.strokeOpacity = 100;
  shape.style = { shape: stencilName, strokeWidth: 1.4 };
  return shape;
}

export function renderDrawioStencilPreview(
  svg: SVGSVGElement,
  stencilName: string,
  width = 64,
  height = 42,
): boolean {
  const stencil = StencilShapeRegistry.get(stencilName);
  const shape = createDrawioStencilPreviewShape(stencilName);
  if (!stencil || !shape) {
    return false;
  }
  svg.replaceChildren();
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const canvas = new SvgCanvas2D(svg, false);
  canvas.setFillColor(shape.fill);
  canvas.setStrokeColor(shape.stroke);
  canvas.setStrokeWidth(shape.strokeWidth);
  canvas.setFillAlpha(shape.fillOpacity / 100);
  canvas.setStrokeAlpha(shape.strokeOpacity / 100);
  stencil.drawShape(canvas, shape, 3, 3, width - 6, height - 6);
  return true;
}

function isDrawioStencilCatalog(value: unknown): value is DrawioStencilCatalog {
  if (!isRecord(value)
    || value.format !== "shuai-drawio-stencil-catalog"
    || value.version !== 1
    || !Array.isArray(value.groups)
    || !Array.isArray(value.libraries)
    || typeof value.libraryCount !== "number"
    || typeof value.shapeCount !== "number") {
    return false;
  }
  return value.groups.every((group) => isRecord(group)
      && typeof group.id === "string"
      && typeof group.name === "string")
    && value.libraries.every((library) => isRecord(library)
      && typeof library.id === "string"
      && typeof library.name === "string"
      && typeof library.group === "string"
      && typeof library.path === "string"
      && typeof library.namespace === "string"
      && typeof library.shapeCount === "number"
      && Array.isArray(library.shapes)
      && library.shapes.every((shape) => isRecord(shape)
        && typeof shape.id === "string"
        && typeof shape.name === "string"
        && typeof shape.shape === "string"
        && typeof shape.width === "number"
        && typeof shape.height === "number"
        && typeof shape.aspect === "string"));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
