import type { Cell, CellStyle } from "@maxgraph/core";
import type {
  DiagramEdge,
  DiagramEdgeStyle,
  DiagramEdgeType,
  DiagramNode,
  DiagramNodeKind,
  DiagramNodeStyle,
  DiagramArrowType,
  DiagramFontFamily,
  DiagramLinePattern,
  DiagramVerticalAlign,
} from "../../lib/diagramDocument";
import type {
  DrawioStencilCatalog,
  DrawioStencilLibrary,
  DrawioStencilShape,
} from "../../lib/drawioStencilCatalog";
import { semanticShapeName } from "../../lib/diagramSemanticShapes";
import { CUBIC_CONTROL_DEFAULTS, DIAGRAM_CUBIC_EDGE_SHAPE } from "./graphShapes";
import { cubicControlStyleForEdge, portCoordinates } from "./graphGeometry";
import { STENCIL_COLLECTION_RULES } from "./paletteCatalog";
import type { StencilCollection, StencilPaletteItem } from "./paletteCatalog";
import type { DiagramCellStyle } from "./types";

/**
 * 图形样式与默认值：把业务模型（DiagramNode / DiagramEdge）翻译成 maxGraph 的 CellStyle，
 * 以及各图形种类的默认尺寸、标签与拖拽预览。
 *
 * 新增一种图形时，通常只需要在这里补 nodeDefaults 与 nodeShape 两处。
 */

export function isDiamondLikeKind(kind: DiagramNodeKind): boolean {
  return kind === "diamond"
    || kind === "decision"
    || kind === "bpmnGateway"
    || kind === "erRelationship";
}

export function nodeCellStyle(node: DiagramNode, optimizeLargeGraph = false): DiagramCellStyle {
  const isContainer = node.kind === "container" || node.kind === "swimlane" || node.kind === "lane";
  const isDiamondLike = isDiamondLikeKind(node.kind);
  const defaultFontFamily: DiagramFontFamily = node.kind === "umlClass" || node.kind === "entity" ? "mono" : "system";
  const usesRoundedCorners = node.kind === "process"
    || node.kind === "roundedRectangle"
    || node.kind === "subprocess"
    || node.kind === "bpmnTask"
    || node.kind === "umlClass"
    || node.kind === "umlPackage"
    || node.kind === "umlComponent"
    || node.kind === "entity"
    || node.kind === "client"
    || node.kind === "firewall"
    || node.kind === "server"
    || node.kind === "queue";
  const base: DiagramCellStyle = {
    diagramKind: node.kind,
    ...(node.stencilName ? { diagramStencilName: node.stencilName } : {}),
    ...(node.stencilLibrary ? { diagramStencilLibrary: node.stencilLibrary } : {}),
    shape: node.stencilName ?? nodeShape(node.kind),
    absoluteArcSize: true,
    arcSize: 16,
    whiteSpace: "wrap",
    overflow: "hidden",
    align: node.style.align ?? "center",
    verticalAlign: node.style.verticalAlign ?? "middle",
    spacing: node.style.spacing ?? (isDiamondLike ? 22 : 10),
    fontFamily: diagramFontFamilyCss(node.style.fontFamily ?? defaultFontFamily),
    fontSize: node.style.fontSize ?? 13,
    fontStyle: (node.style.bold === true ? 1 : 0) + (node.style.italic ? 2 : 0) + (node.style.underline ? 4 : 0),
    fillColor: node.style.fillColor,
    gradientColor: "none",
    gradientDirection: "north",
    strokeColor: node.style.strokeColor,
    fontColor: node.style.fontColor,
    labelBackgroundColor: node.style.labelBackgroundColor ?? "none",
    strokeWidth: node.style.strokeWidth,
    dashed: node.style.linePattern ? node.style.linePattern !== "solid" : Boolean(node.style.dashed),
    dashPattern: dashPatternForLinePattern(node.style.linePattern),
    shadow: !isContainer && !node.stencilName && !optimizeLargeGraph && Boolean(node.style.shadow),
    opacity: node.style.opacity ?? 100,
    rounded: node.style.rounded ?? usesRoundedCorners,
    rotation: node.rotation ?? 0,
    flipH: Boolean(node.style.flipH),
    flipV: Boolean(node.style.flipV),
    diagramLocked: Boolean(node.locked),
  };
  if (node.kind === "note") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    if (node.style.bold === undefined && node.style.italic === undefined) base.fontStyle = 0;
  }
  if (node.kind === "text") {
    base.align = node.style.align ?? "left";
    base.fontStyle = (node.style.bold ? 1 : 0) + (node.style.italic ? 2 : 0) + (node.style.underline ? 4 : 0);
    base.shadow = false;
  }
  if (isDiamondLike) {
    base.spacingLeft = 28;
    base.spacingRight = 28;
    base.spacingTop = 14;
    base.spacingBottom = 14;
  }
  if (node.kind === "umlClass" || node.kind === "entity") {
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    base.spacingTop = 10;
  }
  if (node.kind === "umlPackage") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    base.spacingTop = 28;
    base.spacingLeft = 12;
  }
  if (node.kind === "umlComponent") {
    base.spacingLeft = 36;
  }
  if (node.kind === "container" || node.kind === "swimlane" || node.kind === "lane") {
    if (node.style.align === undefined) base.align = "left";
    if (node.style.verticalAlign === undefined) base.verticalAlign = "top";
    base.spacingTop = node.kind === "swimlane" || node.kind === "lane" ? 8 : 12;
    base.spacingLeft = 10;
    base.connectable = false;
    base.collapsible = true;
    base.recursiveResize = false;
  }
  if (node.kind === "swimlane") {
    base.horizontal = node.swimlaneDirection !== "vertical";
    base.startSize = 32;
    base.swimlaneFillColor = node.style.fillColor;
  }
  if (node.kind === "lane") {
    base.horizontal = true;
    base.startSize = 28;
    base.swimlaneFillColor = node.style.fillColor;
    base.collapsible = false;
  }
  return base;
}

export function edgeCellStyle(edge: DiagramEdge, sourceCell?: Cell, targetCell?: Cell): CellStyle {
  const sourcePort = portCoordinates(edge.sourcePort);
  const targetPort = portCoordinates(edge.targetPort);
  return {
    ...edgeRoutingStyle(edge.style.edgeType ?? "orthogonal"),
    ...(edge.style.edgeType === "curved"
      ? cubicControlStyleForEdge(edge, sourceCell, targetCell)
      : {}),
    rounded: true,
    orthogonalLoop: true,
    jettySize: "auto",
    startArrow: edge.style.startArrow ?? "none",
    startFill: edge.style.startArrow !== "open" && edge.style.startArrow !== "none",
    startSize: edge.style.startSize ?? 8,
    endArrow: edge.style.endArrow ?? "block",
    endFill: edge.style.endArrow !== "open" && edge.style.endArrow !== "none",
    endSize: edge.style.endSize ?? 8,
    strokeColor: edge.style.strokeColor,
    fontColor: edge.style.fontColor,
    fontFamily: diagramFontFamilyCss(edge.style.fontFamily ?? "system"),
    fontSize: edge.style.fontSize ?? 12,
    fontStyle: (edge.style.bold ? 1 : 0) + (edge.style.italic ? 2 : 0) + (edge.style.underline ? 4 : 0),
    align: edge.style.align ?? "center",
    strokeWidth: edge.style.strokeWidth,
    dashed: edge.style.linePattern ? edge.style.linePattern !== "solid" : Boolean(edge.style.dashed),
    dashPattern: dashPatternForLinePattern(edge.style.linePattern),
    opacity: edge.style.opacity ?? 100,
    labelBackgroundColor: edge.style.labelBackgroundColor ?? "#ffffff",
    exitX: sourcePort?.x,
    exitY: sourcePort?.y,
    exitPerimeter: true,
    entryX: targetPort?.x,
    entryY: targetPort?.y,
    entryPerimeter: true,
  };
}

export function buildStencilCollections(catalog: DrawioStencilCatalog): StencilCollection[] {
  const collections = new Map<string, StencilCollection>();
  for (const library of catalog.libraries) {
    const rule = STENCIL_COLLECTION_RULES.find((candidate) => candidate.pattern.test(library.id));
    const collectionId = rule?.id ?? library.id;
    const key = `${library.group}:${collectionId}`;
    const existing = collections.get(key);
    if (existing) {
      existing.libraryCount += 1;
      existing.shapeCount += library.shapeCount;
      existing.items.push(...library.shapes.map((shape) => ({ library, shape })));
      continue;
    }
    collections.set(key, {
      id: key,
      name: rule?.name ?? library.name,
      group: library.group,
      libraryCount: 1,
      shapeCount: library.shapeCount,
      items: library.shapes.map((shape) => ({ library, shape })),
    });
  }
  return Array.from(collections.values());
}

export function stencilPaletteItem(library: DrawioStencilLibrary, shape: DrawioStencilShape): StencilPaletteItem {
  return {
    id: shape.id,
    kind: "rectangle",
    label: shape.name,
    detail: library.name,
    stencilName: shape.shape,
    stencilLibrary: library.path,
    width: shape.width,
    height: shape.height,
  };
}

export function stencilNodeDefaults(item: StencilPaletteItem): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const sourceWidth = Math.max(1, item.width);
  const sourceHeight = Math.max(1, item.height);
  const scale = Math.min(156 / sourceWidth, 108 / sourceHeight);
  return {
    label: "",
    width: Math.max(52, Math.round(sourceWidth * scale)),
    height: Math.max(44, Math.round(sourceHeight * scale)),
    style: {
      fillColor: "#ffffff",
      strokeColor: "#d2d2d7",
      fontColor: "#1d1d1f",
      strokeWidth: 1.2,
      fontSize: 12,
      bold: false,
      shadow: false,
    },
  };
}

export function nodeDefaults(kind: DiagramNodeKind): { label: string; width: number; height: number; style: DiagramNodeStyle } {
  const base: DiagramNodeStyle = {
    fillColor: "#ffffff",
    strokeColor: "#d2d2d7",
    fontColor: "#1d1d1f",
    strokeWidth: 1.2,
    fontSize: 14,
    bold: false,
    shadow: false,
  };
  const style = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => ({ ...base, ...overrides });
  const blue = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style({
    fillColor: "#e8f2ff",
    strokeColor: "#0066cc",
    bold: true,
    ...overrides,
  });
  const neutral = (overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style(overrides);
  const system = (fillColor: string, strokeColor: string, overrides: Partial<DiagramNodeStyle> = {}): DiagramNodeStyle => style({
    fillColor,
    strokeColor,
    ...overrides,
  });
  if (kind === "rectangle") {
    return { label: "矩形", width: 168, height: 76, style: neutral() };
  }
  if (kind === "roundedRectangle") {
    return { label: "圆角矩形", width: 168, height: 76, style: neutral({ fillColor: "#fbfbfd", rounded: true }) };
  }
  if (kind === "ellipse") {
    return { label: "椭圆", width: 164, height: 92, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "circle") {
    return { label: "圆形", width: 96, height: 96, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "diamond") {
    return { label: "菱形", width: 128, height: 128, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "triangle") {
    return { label: "三角形", width: 120, height: 104, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "hexagon") {
    return { label: "六边形", width: 164, height: 88, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "text") {
    return { label: "双击编辑文本", width: 180, height: 52, style: neutral({ fillColor: "none", strokeColor: "none", strokeWidth: 0, align: "left" }) };
  }
  if (kind === "start") {
    return { label: "开始", width: 128, height: 48, style: blue() };
  }
  if (kind === "end") {
    return { label: "结束", width: 128, height: 48, style: blue() };
  }
  if (kind === "decision") {
    return { label: "判断条件", width: 176, height: 112, style: system("#fff7e6", "#ff9f0a", { bold: true }) };
  }
  if (kind === "database") {
    return { label: "数据库", width: 148, height: 92, style: neutral({ fillColor: "#fbfbfd", strokeColor: "#86868b" }) };
  }
  if (kind === "document") {
    return { label: "文档", width: 156, height: 86, style: blue({ bold: false }) };
  }
  if (kind === "actor") {
    return { label: "参与者", width: 116, height: 98, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "note") {
    return { label: "补充说明", width: 176, height: 100, style: system("#fff7e6", "#d2d2d7", { align: "left" }) };
  }
  if (kind === "subprocess") {
    return { label: "子流程", width: 184, height: 76, style: blue() };
  }
  if (kind === "data") {
    return { label: "数据", width: 164, height: 76, style: blue({ bold: false }) };
  }
  if (kind === "delay") {
    return { label: "等待", width: 156, height: 76, style: system("#fff7e6", "#ff9f0a") };
  }
  if (kind === "manualInput") {
    return { label: "手动输入", width: 168, height: 76, style: system("#fff7e6", "#ff9f0a") };
  }
  if (kind === "connector") {
    return { label: "A", width: 56, height: 56, style: blue({ fontSize: 12 }) };
  }
  if (kind === "bpmnTask") {
    return { label: "业务任务", width: 172, height: 72, style: blue({ rounded: true }) };
  }
  if (kind === "cloud") {
    return { label: "云服务", width: 176, height: 96, style: blue({ bold: false }) };
  }
  if (kind === "container") {
    return { label: "分组容器", width: 480, height: 320, style: neutral({ fillColor: "#f5f5f7", strokeColor: "#86868b", dashed: true }) };
  }
  if (kind === "swimlane") {
    return { label: "职责泳道", width: 560, height: 300, style: neutral({ fillColor: "#f5f5f7", strokeColor: "#0066cc" }) };
  }
  if (kind === "lane") {
    return { label: "泳道", width: 560, height: 120, style: neutral({ fillColor: "#fbfbfd", strokeColor: "#d2d2d7" }) };
  }
  if (kind === "bpmnEvent") {
    return { label: "中间事件", width: 76, height: 76, style: blue() };
  }
  if (kind === "bpmnGateway") {
    return { label: "网关", width: 112, height: 112, style: system("#fff7e6", "#ff9f0a", { bold: true }) };
  }
  if (kind === "bpmnDataObject") {
    return { label: "数据对象", width: 124, height: 92, style: blue({ bold: false }) };
  }
  if (kind === "umlUseCase") {
    return { label: "用户用例", width: 172, height: 84, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "umlClass") {
    return { label: "ClassName\n────────\n+ field: Type\n────────\n+ method()", width: 216, height: 154, style: neutral({ fillColor: "#fbfbfd", align: "left" }) };
  }
  if (kind === "umlInterface") {
    return { label: "Interface", width: 104, height: 104, style: neutral({ fillColor: "#fbfbfd", fontSize: 11 }) };
  }
  if (kind === "umlPackage") {
    return { label: "Package", width: 190, height: 112, style: neutral({ fillColor: "#f5f5f7", align: "left" }) };
  }
  if (kind === "umlComponent") {
    return { label: "Component", width: 190, height: 100, style: blue({ bold: false }) };
  }
  if (kind === "entity") {
    return { label: "Entity\n────────\nid: UUID\nname: VARCHAR", width: 204, height: 134, style: neutral({ fillColor: "#fbfbfd", align: "left" }) };
  }
  if (kind === "erRelationship") {
    return { label: "关系", width: 152, height: 104, style: blue({ bold: false }) };
  }
  if (kind === "erAttribute") {
    return { label: "属性", width: 152, height: 72, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "server") {
    return { label: "应用服务器", width: 156, height: 104, style: blue({ bold: false }) };
  }
  if (kind === "client") {
    return { label: "客户端", width: 156, height: 88, style: blue({ bold: false }) };
  }
  if (kind === "router") {
    return { label: "路由器", width: 128, height: 72, style: blue({ bold: false }) };
  }
  if (kind === "firewall") {
    return { label: "防火墙", width: 160, height: 76, style: system("#fff1f2", "#ff3b30", { bold: true }) };
  }
  if (kind === "queue") {
    return { label: "消息队列", width: 164, height: 86, style: neutral({ fillColor: "#fbfbfd" }) };
  }
  if (kind === "service") {
    return { label: "应用服务", width: 168, height: 84, style: system("#ecfdf5", "#34c759", { bold: true }) };
  }
  return { label: "处理步骤", width: 168, height: 68, style: blue() };
}

export function defaultEdgeStyle(): DiagramEdgeStyle {
  return {
    strokeColor: "#0066cc",
    fontColor: "#1d1d1f",
    strokeWidth: 1.8,
    edgeType: "orthogonal",
    startArrow: "none",
    endArrow: "block",
  };
}

export function nodeShape(kind: DiagramNodeKind) {
  const semanticShape = semanticShapeName(kind);
  if (semanticShape) return semanticShape;
  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "umlUseCase" || kind === "erAttribute" || kind === "router") return "ellipse";
  if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") return "rhombus";
  if (kind === "bpmnEvent" || kind === "umlInterface") return "doubleEllipse";
  if (kind === "triangle") return "triangle";
  if (kind === "hexagon" || kind === "service") return "hexagon";
  if (kind === "database") return "cylinder";
  if (kind === "actor") return "actor";
  if (kind === "cloud") return "cloud";
  if (kind === "swimlane" || kind === "lane") return "swimlane";
  return "rectangle";
}

export function mixHexColor(color: string, target: string, amount: number) {
  const parse = (value: string) => {
    const match = /^#([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(value);
    return match ? [Number.parseInt(match[1], 16), Number.parseInt(match[2], 16), Number.parseInt(match[3], 16)] : null;
  };
  const sourceRgb = parse(color);
  const targetRgb = parse(target);
  if (!sourceRgb || !targetRgb) return target;
  const mixed = sourceRgb.map((channel, index) => Math.round(channel + (targetRgb[index] - channel) * amount));
  return `#${mixed.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

export function createNodeDragPreview(
  kind: DiagramNodeKind,
  defaults: { label: string; width: number; height: number; style: DiagramNodeStyle },
) {
  const scale = Math.min(1, 220 / defaults.width, 150 / defaults.height);
  const width = Math.max(64, Math.round(defaults.width * scale));
  const height = Math.max(48, Math.round(defaults.height * scale));
  const isContainer = kind === "container" || kind === "swimlane" || kind === "lane";
  const element = window.document.createElement("div");
  element.style.width = `${width}px`;
  element.style.height = `${height}px`;
  element.style.boxSizing = "border-box";
  element.style.position = "relative";
  element.style.pointerEvents = "none";
  element.style.opacity = "0.98";
  // Soft, layered elevation so the shape reads as a card being lifted onto the canvas.
  // drop-shadow (not box-shadow) follows the clip-path silhouette of non-rectangular kinds.
  element.style.filter = "drop-shadow(0 14px 30px rgba(15, 23, 42, 0.26)) drop-shadow(0 3px 8px rgba(15, 23, 42, 0.14))";

  const shape = window.document.createElement("div");
  shape.style.position = "absolute";
  shape.style.inset = isContainer ? "2px" : "1px";
  shape.style.boxSizing = "border-box";
  shape.style.background = isContainer
    ? "#f5f5f7"
    : defaults.style.fillColor;
  shape.style.border = `${Math.max(1, defaults.style.strokeWidth)}px ${defaults.style.dashed ? "dashed" : "solid"} ${defaults.style.strokeColor}`;
  shape.style.borderRadius = "14px";
  // Faint top highlight for a soft, dimensional finish (clipped to the shape for non-rect kinds).
  shape.style.boxShadow = "inset 0 1px 0 rgba(255, 255, 255, 0.5)";

  if (kind === "ellipse" || kind === "circle" || kind === "start" || kind === "end" || kind === "connector" || kind === "bpmnEvent" || kind === "umlUseCase" || kind === "umlInterface" || kind === "erAttribute" || kind === "router") {
    shape.style.borderRadius = "999px";
  } else if (kind === "diamond" || kind === "decision" || kind === "bpmnGateway" || kind === "erRelationship") {
    shape.style.inset = "18%";
    shape.style.borderRadius = "8px";
    shape.style.transform = "rotate(45deg)";
  } else if (kind === "database") {
    shape.style.borderRadius = "50% / 18%";
  } else if (kind === "hexagon" || kind === "service") {
    shape.style.clipPath = "polygon(14% 0, 86% 0, 100% 50%, 86% 100%, 14% 100%, 0 50%)";
  } else if (kind === "triangle") {
    shape.style.clipPath = "polygon(50% 0, 100% 100%, 0 100%)";
  } else if (kind === "data") {
    shape.style.clipPath = "polygon(14% 0, 100% 0, 86% 100%, 0 100%)";
  } else if (kind === "manualInput") {
    shape.style.clipPath = "polygon(0 20%, 100% 0, 100% 100%, 0 100%)";
  } else if (kind === "note" || kind === "bpmnDataObject") {
    shape.style.clipPath = "polygon(0 0, 82% 0, 100% 22%, 100% 100%, 0 100%)";
  } else if (kind === "delay") {
    shape.style.borderRadius = "0 999px 999px 0";
  } else if (kind === "umlPackage") {
    shape.style.clipPath = "polygon(0 0, 42% 0, 42% 18%, 100% 18%, 100% 100%, 0 100%)";
  } else if (kind === "cloud") {
    shape.style.borderRadius = "48% 52% 46% 54% / 58% 48% 52% 42%";
  }
  if (kind === "text") {
    shape.style.display = "none";
    element.style.filter = "none";
  }
  element.appendChild(shape);

  if (kind === "subprocess" || kind === "server" || kind === "firewall" || kind === "umlClass" || kind === "entity") {
    const overlay = window.document.createElement("div");
    overlay.style.position = "absolute";
    overlay.style.inset = "1px";
    overlay.style.pointerEvents = "none";
    if (kind === "subprocess") {
      overlay.style.borderLeft = `2px solid ${defaults.style.strokeColor}`;
      overlay.style.borderRight = `2px solid ${defaults.style.strokeColor}`;
      overlay.style.marginInline = "10px";
    } else {
      overlay.style.background = `linear-gradient(to bottom, transparent 31%, ${defaults.style.strokeColor} 31%, ${defaults.style.strokeColor} 33%, transparent 33%, transparent 67%, ${defaults.style.strokeColor} 67%, ${defaults.style.strokeColor} 69%, transparent 69%)`;
    }
    element.appendChild(overlay);
  }

  if (kind === "swimlane" || kind === "lane") {
    const header = window.document.createElement("div");
    header.style.position = "absolute";
    header.style.inset = "3px 3px auto";
    header.style.height = `${Math.max(22, Math.round(30 * scale))}px`;
    header.style.borderRadius = "11px 11px 4px 4px";
    header.style.background = mixHexColor(defaults.style.strokeColor, "#ffffff", 0.82);
    header.style.borderBottom = `1px solid ${mixHexColor(defaults.style.strokeColor, "#ffffff", 0.45)}`;
    element.appendChild(header);
  }

  const label = window.document.createElement("div");
  label.textContent = defaults.label.split("\n")[0];
  label.style.position = "absolute";
  label.style.inset = isContainer ? "12px auto auto 14px" : "8px";
  label.style.display = "flex";
  label.style.alignItems = "center";
  label.style.justifyContent = isContainer ? "flex-start" : "center";
  label.style.color = defaults.style.fontColor;
  label.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
  label.style.fontSize = `${Math.max(10, Math.min(13, Math.round(13 * scale)))}px`;
  label.style.fontWeight = "650";
  label.style.lineHeight = "1.2";
  label.style.textAlign = isContainer ? "left" : "center";
  label.style.whiteSpace = "nowrap";
  element.appendChild(label);

  // "Add" affordance in the diagram accent blue with a white ring — reads as an intentional badge
  // rather than the previous stray cyan dot, and matches the editor's blue accent language.
  const addBadge = window.document.createElement("div");
  addBadge.style.position = "absolute";
  addBadge.style.top = "-7px";
  addBadge.style.right = "-7px";
  addBadge.style.display = "flex";
  addBadge.style.alignItems = "center";
  addBadge.style.justifyContent = "center";
  addBadge.style.width = "18px";
  addBadge.style.height = "18px";
  addBadge.style.borderRadius = "999px";
  addBadge.style.background = "#0066cc";
  addBadge.style.color = "#ffffff";
  addBadge.style.fontFamily = "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
  addBadge.style.fontSize = "13px";
  addBadge.style.fontWeight = "700";
  addBadge.style.lineHeight = "1";
  addBadge.style.boxShadow = "0 0 0 2px #ffffff, 0 4px 10px rgba(0, 102, 204, 0.42)";
  addBadge.textContent = "+";
  element.appendChild(addBadge);

  return { element, width, height };
}

export function edgeRoutingStyle(type: DiagramEdgeType): CellStyle {
  if (type === "straight") return { edgeStyle: "none", curved: false };
  if (type === "elbow") return { edgeStyle: "elbowEdgeStyle", elbow: "horizontal", curved: false };
  if (type === "curved") return {
    edgeStyle: "none",
    curved: true,
    shape: DIAGRAM_CUBIC_EDGE_SHAPE,
    diagramCubicControl1T: CUBIC_CONTROL_DEFAULTS.control1T,
    diagramCubicControl1N: CUBIC_CONTROL_DEFAULTS.control1N,
    diagramCubicControl2T: CUBIC_CONTROL_DEFAULTS.control2T,
    diagramCubicControl2N: CUBIC_CONTROL_DEFAULTS.control2N,
  } as DiagramCellStyle;
  return { edgeStyle: "orthogonalEdgeStyle", orthogonalLoop: true, jettySize: "auto", curved: false };
}

export function edgeTypeFromCellStyle(style: CellStyle): DiagramEdgeType {
  if (style.curved) return "curved";
  if (!style.edgeStyle || style.edgeStyle === "none") return "straight";
  if (String(style.edgeStyle).toLowerCase().includes("elbow")) return "elbow";
  return "orthogonal";
}

export function arrowTypeFromStyle(value: unknown, fallback: DiagramArrowType): DiagramArrowType {
  return value === "none" || value === "classic" || value === "block" || value === "open" || value === "oval" || value === "diamond"
    ? value
    : fallback;
}



export function textAlignFromStyle(value: unknown): "left" | "center" | "right" {
  return value === "left" || value === "right" ? value : "center";
}



export function linePatternFromStyle(style: CellStyle): DiagramLinePattern {
  if (!style.dashed) return "solid";
  return typeof style.dashPattern === "string" && /^\s*1(?:\s|$)/.test(style.dashPattern) ? "dotted" : "dashed";
}

export function dashPatternForLinePattern(pattern?: DiagramLinePattern) {
  if (pattern === "dotted") return "1 4";
  if (pattern === "dashed") return "8 4";
  return undefined;
}

export function diagramFontFamilyCss(fontFamily: DiagramFontFamily) {
  if (fontFamily === "rounded") return "ui-rounded, SF Pro Rounded, system-ui, sans-serif";
  if (fontFamily === "serif") return "Georgia, Times New Roman, serif";
  if (fontFamily === "mono") return "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
  return "system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
}

export function diagramFontFamilyFromStyle(value: unknown): DiagramFontFamily {
  if (typeof value !== "string") return "system";
  const normalized = value.toLowerCase();
  if (normalized.includes("mono") || normalized.includes("menlo") || normalized.includes("consolas")) return "mono";
  if (normalized.includes("rounded")) return "rounded";
  if ((normalized.includes("georgia") || normalized.includes("times") || normalized.endsWith("serif"))
    && !normalized.includes("sans-serif")) return "serif";
  return "system";
}

export function verticalAlignFromStyle(value: unknown): DiagramVerticalAlign {
  return value === "top" || value === "bottom" ? value : "middle";
}
