import { Point } from "@maxgraph/core";
import type { Cell, CellState, CellStyle, Graph } from "@maxgraph/core";
import type { DiagramEdge, DiagramPort } from "../../lib/diagramDocument";
import type { DiagramCellStyle } from "./types";
import { edgeRoutingStyle } from "./graphStyles";
import { CUBIC_CONTROL_DEFAULTS } from "./graphShapes";
import { PORT_CONSTRAINTS } from "./paletteCatalog";

/**
 * 画布几何与样式取值工具。
 *
 * 包含旋转角度归一化、单元绝对坐标、三次贝塞尔连线控制点换算，以及从 CellStyle
 * 安全读取颜色/数值的取值器。全部为纯函数，不依赖编辑器状态。
 */

export function normalizeRotation(value: number) {
  return ((Math.round(value) % 360) + 360) % 360;
}

export function pointerAngleDegrees(state: CellState, x: number, y: number) {
  return (Math.atan2(y - state.getCenterY(), x - state.getCenterX()) * 180) / Math.PI;
}

export function portCoordinates(port?: DiagramPort) {
  if (port === "north") return { x: 0.5, y: 0 };
  if (port === "east") return { x: 1, y: 0.5 };
  if (port === "south") return { x: 0.5, y: 1 };
  if (port === "west") return { x: 0, y: 0.5 };
  return undefined;
}

export function absoluteCellOrigin(cell: Cell) {
  let x = 0;
  let y = 0;
  let current: Cell | null = cell;
  while (current) {
    const geometry = current.getGeometry();
    if (geometry && !geometry.relative) {
      x += geometry.x;
      y += geometry.y;
    }
    current = current.getParent();
  }
  return { x, y };
}

export function absoluteCellCenter(cell: Cell) {
  const origin = absoluteCellOrigin(cell);
  const geometry = cell.getGeometry();
  return {
    x: origin.x + (geometry?.width ?? 0) / 2,
    y: origin.y + (geometry?.height ?? 0) / 2,
  };
}

export function cubicControlPointsFromStyle(
  start: Point,
  end: Point,
  style?: CellStyle | null,
) {
  const cubicStyle = style as DiagramCellStyle | undefined;
  const deltaX = end.x - start.x;
  const deltaY = end.y - start.y;
  const point = (t: number, n: number) => new Point(
    start.x + deltaX * t - deltaY * n,
    start.y + deltaY * t + deltaX * n,
  );
  return [
    point(
      styleNumber(cubicStyle?.diagramCubicControl1T, CUBIC_CONTROL_DEFAULTS.control1T),
      styleNumber(cubicStyle?.diagramCubicControl1N, CUBIC_CONTROL_DEFAULTS.control1N),
    ),
    point(
      styleNumber(cubicStyle?.diagramCubicControl2T, CUBIC_CONTROL_DEFAULTS.control2T),
      styleNumber(cubicStyle?.diagramCubicControl2N, CUBIC_CONTROL_DEFAULTS.control2N),
    ),
  ];
}

export function cubicFactorsForPoint(start: Point, end: Point, point: Point) {
  const deltaX = end.x - start.x;
  const deltaY = end.y - start.y;
  const lengthSquared = Math.max(1, deltaX * deltaX + deltaY * deltaY);
  const relativeX = point.x - start.x;
  const relativeY = point.y - start.y;
  return {
    t: clampNumber((relativeX * deltaX + relativeY * deltaY) / lengthSquared, -4, 4),
    n: clampNumber((-relativeX * deltaY + relativeY * deltaX) / lengthSquared, -4, 4),
  };
}

export function cubicControlStyleFromPoints(start: { x: number; y: number }, end: { x: number; y: number }, points: Point[]) {
  const first = cubicFactorsForPoint(new Point(start.x, start.y), new Point(end.x, end.y), points[0]);
  const second = cubicFactorsForPoint(new Point(start.x, start.y), new Point(end.x, end.y), points[1]);
  return {
    diagramCubicControl1T: first.t,
    diagramCubicControl1N: first.n,
    diagramCubicControl2T: second.t,
    diagramCubicControl2N: second.n,
  } satisfies Partial<DiagramCellStyle>;
}

export function cubicControlStyleForEdge(edge: DiagramEdge, source?: Cell, target?: Cell) {
  if (source && target && edge.waypoints && edge.waypoints.length >= 2) {
    return cubicControlStyleFromPoints(
      absoluteCellCenter(source),
      absoluteCellCenter(target),
      [
        new Point(edge.waypoints[0].x, edge.waypoints[0].y),
        new Point(edge.waypoints[edge.waypoints.length - 1].x, edge.waypoints[edge.waypoints.length - 1].y),
      ],
    );
  }
  return {
    diagramCubicControl1T: CUBIC_CONTROL_DEFAULTS.control1T,
    diagramCubicControl1N: CUBIC_CONTROL_DEFAULTS.control1N,
    diagramCubicControl2T: CUBIC_CONTROL_DEFAULTS.control2T,
    diagramCubicControl2N: CUBIC_CONTROL_DEFAULTS.control2N,
  } satisfies Partial<DiagramCellStyle>;
}

export function cubicEdgeModelEndpoints(state: CellState): [Point, Point] {
  const scale = Math.max(0.0001, state.view.scale);
  const translate = state.view.translate;
  const first = state.absolutePoints[0] ?? new Point(state.x, state.y);
  const last = state.absolutePoints[state.absolutePoints.length - 1] ?? new Point(state.x + state.width, state.y + state.height);
  return [
    new Point(first.x / scale - translate.x, first.y / scale - translate.y),
    new Point(last.x / scale - translate.x, last.y / scale - translate.y),
  ];
}

export function edgeWaypointsForGraph(edge: DiagramEdge) {
  if (edge.style.edgeType === "curved") return undefined;
  return edge.waypoints?.map((point) => new Point(point.x, point.y));
}

export function defaultCubicControlPoints(graph: Graph, source: Cell, target: Cell) {
  const sourceCenter = absoluteCellCenter(source);
  const targetCenter = absoluteCellCenter(target);
  return cubicControlPointsFromStyle(
    new Point(sourceCenter.x, sourceCenter.y),
    new Point(targetCenter.x, targetCenter.y),
    edgeRoutingStyle("curved"),
  ).map((point) => new Point(graph.snap(point.x), graph.snap(point.y)));
}

export function constraintForPort(port?: DiagramPort) {
  return PORT_CONSTRAINTS.find((constraint) => constraint.name === port) ?? null;
}

export function portFromStyle(style: CellStyle, source: boolean): DiagramPort | undefined {
  const x = styleNumber(source ? style.exitX : style.entryX, Number.NaN);
  const y = styleNumber(source ? style.exitY : style.entryY, Number.NaN);
  if (!Number.isFinite(x) || !Number.isFinite(y)) {
    return undefined;
  }
  if (y <= 0.05) return "north";
  if (x >= 0.95) return "east";
  if (y >= 0.95) return "south";
  if (x <= 0.05) return "west";
  return undefined;
}

export function styleColor(value: unknown, fallback: string) {
  return value === "none" || (typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value)) ? value : fallback;
}

export function styleNumber(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function clampNumber(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, Number.isFinite(value) ? value : min));
}
