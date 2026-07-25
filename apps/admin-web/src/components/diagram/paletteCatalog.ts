import { ConnectionConstraint, Point } from "@maxgraph/core";
import type {
  DiagramArrowType,
  DiagramEdgeStyle,
  DiagramFontFamily,
  DiagramNodeKind,
  DiagramNodeStyle,
  DiagramPort,
} from "../../lib/diagramDocument";
import type { DrawioStencilLibrary, DrawioStencilShape } from "../../lib/drawioStencilCatalog";

/**
 * 图形库目录：内置图形分类、drawio stencil 分组规则、字体/箭头选项与流程模板定义。
 *
 * 这些是纯数据，与编辑器运行时状态无关，独立成模块便于新增图形分类时只改这里。
 */

export const PORT_CONSTRAINTS = [
  new ConnectionConstraint(new Point(0.5, 0), true, "north"),
  new ConnectionConstraint(new Point(1, 0.5), true, "east"),
  new ConnectionConstraint(new Point(0.5, 1), true, "south"),
  new ConnectionConstraint(new Point(0, 0.5), true, "west"),
];

export const PALETTE_CATEGORIES = ["通用图形", "流程图", "BPMN", "UML", "ER 图", "网络与架构", "容器与泳道"] as const;
export type PaletteCategory = typeof PALETTE_CATEGORIES[number];

export const NODE_PALETTE: Array<{ kind: DiagramNodeKind; label: string; detail: string; category: PaletteCategory }> = [
  { kind: "rectangle", label: "矩形", detail: "通用容器", category: "通用图形" },
  { kind: "roundedRectangle", label: "圆角矩形", detail: "通用卡片", category: "通用图形" },
  { kind: "ellipse", label: "椭圆", detail: "通用图形", category: "通用图形" },
  { kind: "circle", label: "圆形", detail: "通用图形", category: "通用图形" },
  { kind: "diamond", label: "菱形", detail: "关系判断", category: "通用图形" },
  { kind: "triangle", label: "三角形", detail: "方向标识", category: "通用图形" },
  { kind: "hexagon", label: "六边形", detail: "准备步骤", category: "通用图形" },
  { kind: "text", label: "文本", detail: "无边框文字", category: "通用图形" },
  { kind: "note", label: "便签", detail: "补充说明", category: "通用图形" },

  { kind: "start", label: "开始", detail: "流程起点", category: "流程图" },
  { kind: "process", label: "处理", detail: "业务步骤", category: "流程图" },
  { kind: "decision", label: "判断", detail: "条件分支", category: "流程图" },
  { kind: "end", label: "结束", detail: "流程终点", category: "流程图" },
  { kind: "document", label: "文档", detail: "文档输出", category: "流程图" },
  { kind: "database", label: "数据存储", detail: "数据库", category: "流程图" },
  { kind: "data", label: "输入输出", detail: "数据输入", category: "流程图" },
  { kind: "subprocess", label: "子流程", detail: "预定义过程", category: "流程图" },
  { kind: "delay", label: "延迟", detail: "等待节点", category: "流程图" },
  { kind: "manualInput", label: "手动输入", detail: "人工录入", category: "流程图" },
  { kind: "connector", label: "连接符", detail: "页内连接", category: "流程图" },

  { kind: "bpmnTask", label: "任务", detail: "BPMN Task", category: "BPMN" },
  { kind: "bpmnEvent", label: "事件", detail: "中间事件", category: "BPMN" },
  { kind: "bpmnGateway", label: "网关", detail: "并行或排他", category: "BPMN" },
  { kind: "bpmnDataObject", label: "数据对象", detail: "业务数据", category: "BPMN" },

  { kind: "actor", label: "参与者", detail: "角色或用户", category: "UML" },
  { kind: "umlUseCase", label: "用例", detail: "Use Case", category: "UML" },
  { kind: "umlClass", label: "类", detail: "属性与方法", category: "UML" },
  { kind: "umlInterface", label: "接口", detail: "Interface", category: "UML" },
  { kind: "umlPackage", label: "包", detail: "Package", category: "UML" },
  { kind: "umlComponent", label: "组件", detail: "Component", category: "UML" },

  { kind: "entity", label: "实体", detail: "数据实体", category: "ER 图" },
  { kind: "erRelationship", label: "关系", detail: "实体关系", category: "ER 图" },
  { kind: "erAttribute", label: "属性", detail: "实体属性", category: "ER 图" },

  { kind: "server", label: "服务器", detail: "计算节点", category: "网络与架构" },
  { kind: "client", label: "客户端", detail: "终端设备", category: "网络与架构" },
  { kind: "router", label: "路由器", detail: "网络路由", category: "网络与架构" },
  { kind: "firewall", label: "防火墙", detail: "安全边界", category: "网络与架构" },
  { kind: "cloud", label: "云服务", detail: "外部系统", category: "网络与架构" },
  { kind: "queue", label: "消息队列", detail: "异步通道", category: "网络与架构" },
  { kind: "service", label: "服务", detail: "应用服务", category: "网络与架构" },

  { kind: "container", label: "容器", detail: "分组区域", category: "容器与泳道" },
  { kind: "swimlane", label: "泳池", detail: "职责分区", category: "容器与泳道" },
];

export interface StencilPaletteItem {
  id: string;
  kind: "rectangle";
  label: string;
  detail: string;
  stencilName: string;
  stencilLibrary: string;
  width: number;
  height: number;
}

export type DraggablePaletteItem = (typeof NODE_PALETTE)[number] | StencilPaletteItem;

export interface StencilCollectionItem {
  library: DrawioStencilLibrary;
  shape: DrawioStencilShape;
}

export interface StencilCollection {
  id: string;
  name: string;
  group: string;
  libraryCount: number;
  shapeCount: number;
  items: StencilCollectionItem[];
}

export const STENCIL_COLLECTION_RULES: Array<{ id: string; name: string; pattern: RegExp }> = [
  { id: "aws", name: "AWS", pattern: /^aws(?:\/|2\/|3$|3d$|4$)/ },
  { id: "gcp", name: "Google Cloud", pattern: /^gcp(?:\/|2$|3$)/ },
  { id: "kubernetes", name: "Kubernetes", pattern: /^kubernetes2?$/ },
  { id: "cisco", name: "Cisco", pattern: /^cisco(?:\/|19$|_safe\/)/ },
  { id: "citrix", name: "Citrix", pattern: /^citrix2?$/ },
  { id: "networks", name: "网络设备", pattern: /^networks2?$/ },
  { id: "rack", name: "机架设备", pattern: /^rack\// },
  { id: "office", name: "Microsoft Office", pattern: /^office\// },
  { id: "mscae", name: "Microsoft Cloud Architecture", pattern: /^mscae\// },
  { id: "veeam", name: "Veeam", pattern: /^veeam\// },
  { id: "electrical", name: "电气工程", pattern: /^electrical\// },
  { id: "pid", name: "P&ID", pattern: /^pid\// },
  { id: "mockup", name: "界面原型", pattern: /^mockup\// },
  { id: "ios", name: "iOS", pattern: /^ios7\// },
  { id: "android", name: "Android", pattern: /^android\// },
  { id: "signs", name: "标志与符号", pattern: /^signs\// },
  { id: "web", name: "Web 图标与 Logo", pattern: /^web(?:icons|logos)$/ },
];

export const DIAGRAM_FONT_OPTIONS: Array<{ value: DiagramFontFamily; label: string }> = [
  { value: "system", label: "系统字体" },
  { value: "rounded", label: "圆体" },
  { value: "serif", label: "衬线字体" },
  { value: "mono", label: "等宽字体" },
];
export const DIAGRAM_ARROW_OPTIONS: Array<{ value: DiagramArrowType; label: string }> = [
  { value: "none", label: "无" },
  { value: "classic", label: "经典" },
  { value: "block", label: "实心" },
  { value: "open", label: "开放" },
  { value: "oval", label: "圆点" },
  { value: "diamond", label: "菱形" },
];

export type DiagramTemplateId = "approval" | "architecture" | "er";

export interface DiagramTemplateNodeDefinition {
  id: string;
  kind: DiagramNodeKind;
  label: string;
  dx: number;
  dy: number;
  width: number;
  height: number;
  style?: Partial<DiagramNodeStyle>;
}

export interface DiagramTemplateEdgeDefinition {
  sourceId: string;
  targetId: string;
  label?: string;
  sourcePort: DiagramPort;
  targetPort: DiagramPort;
  style?: Partial<DiagramEdgeStyle>;
}

export interface DiagramTemplateDefinition {
  name: string;
  shortName: string;
  detail: string;
  nodes: DiagramTemplateNodeDefinition[];
  edges: DiagramTemplateEdgeDefinition[];
}

export const DIAGRAM_TEMPLATES: Record<DiagramTemplateId, DiagramTemplateDefinition> = {
  approval: {
    name: "发布审批",
    shortName: "流程",
    detail: "发布审批",
    nodes: [
      { id: "start", kind: "start", label: "开始", dx: 38, dy: 0, width: 88, height: 32, style: { fontSize: 11 } },
      { id: "submit", kind: "process", label: "提交发布版本", dx: 20, dy: 58, width: 124, height: 46, style: { fontSize: 11, rounded: true } },
      { id: "review", kind: "decision", label: "审核通过？", dx: 26, dy: 132, width: 112, height: 72, style: { fontSize: 11 } },
      { id: "published", kind: "end", label: "发布完成", dx: 38, dy: 236, width: 88, height: 32, style: { fillColor: "#ecfdf3", strokeColor: "#34c759", fontSize: 11 } },
      { id: "rejected", kind: "end", label: "退回修改", dx: 190, dy: 151, width: 100, height: 34, style: { fillColor: "#fff1f2", strokeColor: "#ff3b30", fontSize: 11, bold: false } },
    ],
    edges: [
      { sourceId: "start", targetId: "submit", sourcePort: "south", targetPort: "north" },
      { sourceId: "submit", targetId: "review", sourcePort: "south", targetPort: "north" },
      { sourceId: "review", targetId: "published", label: "通过", sourcePort: "south", targetPort: "north" },
      { sourceId: "review", targetId: "rejected", label: "退回", sourcePort: "east", targetPort: "west", style: { strokeColor: "#ff3b30" } },
    ],
  },
  architecture: {
    name: "直传架构",
    shortName: "架构",
    detail: "直连与兜底",
    nodes: [
      { id: "sender", kind: "client", label: "发送端", dx: 0, dy: 66, width: 112, height: 52, style: { fontSize: 11, rounded: true } },
      { id: "coordinator", kind: "service", label: "协调服务", dx: 150, dy: 0, width: 124, height: 52, style: { fillColor: "#f5f5f7", strokeColor: "#86868b", fontSize: 11 } },
      { id: "receiver", kind: "client", label: "接收端", dx: 312, dy: 66, width: 112, height: 52, style: { fontSize: 11, rounded: true } },
      { id: "storage", kind: "cloud", label: "对象存储\n失败兜底", dx: 150, dy: 150, width: 124, height: 58, style: { fillColor: "#ecfdf3", strokeColor: "#34c759", fontSize: 10 } },
    ],
    edges: [
      { sourceId: "sender", targetId: "receiver", label: "WebRTC 直传", sourcePort: "east", targetPort: "west", style: { edgeType: "straight" } },
      { sourceId: "sender", targetId: "coordinator", label: "信令", sourcePort: "north", targetPort: "west" },
      { sourceId: "coordinator", targetId: "receiver", label: "协商", sourcePort: "east", targetPort: "north" },
      { sourceId: "sender", targetId: "storage", label: "预签名上传", sourcePort: "south", targetPort: "west", style: { strokeColor: "#34c759" } },
      { sourceId: "storage", targetId: "receiver", label: "临时下载", sourcePort: "east", targetPort: "south", style: { strokeColor: "#34c759" } },
    ],
  },
  er: {
    name: "房间 ER",
    shortName: "ER",
    detail: "房间数据",
    nodes: [
      { id: "room", kind: "entity", label: "Room 房间\n────────\nid: UUID\nname: VARCHAR", dx: 145, dy: 0, width: 142, height: 92, style: { fontSize: 10, spacing: 8 } },
      { id: "member", kind: "entity", label: "Member 成员\n────────\nid: UUID\nroom_id: UUID", dx: 0, dy: 138, width: 142, height: 104, style: { strokeColor: "#34c759", fontSize: 10, spacing: 8 } },
      { id: "transfer", kind: "entity", label: "Transfer 传输\n────────\nid: UUID\nroom_id: UUID", dx: 290, dy: 138, width: 142, height: 104, style: { strokeColor: "#ff9f0a", fontSize: 10, spacing: 8 } },
    ],
    edges: [
      { sourceId: "room", targetId: "member", label: "1 : N", sourcePort: "south", targetPort: "north", style: { strokeColor: "#34c759" } },
      { sourceId: "room", targetId: "transfer", label: "1 : N", sourcePort: "south", targetPort: "north", style: { strokeColor: "#ff9f0a" } },
    ],
  },
};

/** 判断任意值是否为受支持的内置图形种类（泳道为容器类，单列）。 */
export function isDiagramNodeKind(value: unknown): value is DiagramNodeKind {
  return value === "lane" || NODE_PALETTE.some((item) => item.kind === value);
}
