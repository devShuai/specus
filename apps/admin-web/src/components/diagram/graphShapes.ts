import {
  ConnectorShape,
  PolylineShape,
  ShapeRegistry,
  StyleDefaultsConfig,
  EdgeHandler,
  EdgeHandlerConfig,
  EllipseShape,
  HandleConfig,
  InternalEvent,
  Point,
  Rectangle,
  VertexHandle,
  VertexHandler,
  VertexHandlerConfig,
  mathUtils,
} from "@maxgraph/core";

import type { AbstractCanvas2D, CellState, EventSource, InternalMouseEvent } from "@maxgraph/core";
import { registerDiagramSemanticShapes } from "../../lib/diagramSemanticShapes";
import type { DiagramCellStyle } from "./types";
import { signedRotationDelta } from "../../lib/diagramRotation";
import {
  cubicControlPointsFromStyle,
  cubicEdgeModelEndpoints,
  cubicFactorsForPoint,
  pointerAngleDegrees,
  styleNumber,
} from "./graphGeometry";

/**
 * maxGraph 自定义图元：三次贝塞尔连线形状与其控制点手柄、旋转手柄，
 * 以及承载它们的 VertexHandler / EdgeHandler 子类。
 *
 * 这些类直接继承 maxGraph 的渲染与交互基类，属于引擎适配层，与业务状态无关。
 */

export const DIAGRAM_CUBIC_EDGE_SHAPE = "diagramCubicConnector";
export const CUBIC_CONTROL_DEFAULTS = {
  control1T: 1 / 3,
  control1N: 0.18,
  control2T: 2 / 3,
  control2N: 0.18,
};
export const DIAGRAM_ROTATION_HANDLE_SIZE = 18;
export const DIAGRAM_ROTATION_HANDLE_FILL = "transparent";
export const DIAGRAM_ROTATION_HANDLE_ACCENT = "var(--diagram-apple-blue)";

export class DiagramCubicConnectorShape extends ConnectorShape {
  override paintEdgeShape(canvas: AbstractCanvas2D, points: Point[]) {
    const start = points[0];
    const end = points[points.length - 1];
    if (!start || !end) return;
    const [control1, control2] = cubicControlPointsFromStyle(start, end, this.style);
    super.paintEdgeShape(canvas, [start, control1, control2, end]);
  }

  override paintCurvedLine(canvas: AbstractCanvas2D, points: Point[]) {
    const start = points[0];
    const control1 = points[1];
    const control2 = points[points.length - 2];
    const end = points[points.length - 1];
    if (!start || !control1 || !control2 || !end) return;
    canvas.begin();
    canvas.moveTo(start.x, start.y);
    canvas.curveTo(control1.x, control1.y, control2.x, control2.y, end.x, end.y);
    canvas.stroke();
  }
}

export class DiagramCubicControlHandle extends VertexHandle {
  controlIndex: 0 | 1;

  constructor(state: CellState, controlIndex: 0 | 1) {
    super(
      state,
      "move",
      null,
      new EllipseShape(new Rectangle(0, 0, 11, 11), "#0066cc", "#ffffff", 2),
    );
    this.controlIndex = controlIndex;
    this.shape?.node.classList.add("diagram-cubic-control-handle");
    this.shape?.node.setAttribute("data-control-index", String(controlIndex + 1));
  }

  override getPosition(_bounds: Rectangle | null) {
    const [start, end] = cubicEdgeModelEndpoints(this.state);
    return cubicControlPointsFromStyle(start, end, this.state.style)[this.controlIndex];
  }

  override setPosition(_bounds: Rectangle | null, point: Point, _event: InternalMouseEvent) {
    const [start, end] = cubicEdgeModelEndpoints(this.state);
    const { t, n } = cubicFactorsForPoint(start, end, point);
    const style = this.state.style as DiagramCellStyle;
    if (this.controlIndex === 0) {
      style.diagramCubicControl1T = t;
      style.diagramCubicControl1N = n;
    } else {
      style.diagramCubicControl2T = t;
      style.diagramCubicControl2N = n;
    }
  }

  override execute(_event: InternalMouseEvent) {
    const transientStyle = this.state.style as DiagramCellStyle;
    const style = this.state.cell.getClonedStyle() as DiagramCellStyle;
    if (this.controlIndex === 0) {
      style.diagramCubicControl1T = transientStyle.diagramCubicControl1T;
      style.diagramCubicControl1N = transientStyle.diagramCubicControl1N;
    } else {
      style.diagramCubicControl2T = transientStyle.diagramCubicControl2T;
      style.diagramCubicControl2N = transientStyle.diagramCubicControl2N;
    }
    this.graph.getDataModel().setStyle(this.state.cell, style);
  }
}

export class DiagramRotationHandleShape extends EllipseShape {
  override init(container: HTMLElement | SVGElement) {
    super.init(container);
    this.node.classList.add("diagram-rotation-handle");
    this.node.setAttribute("data-diagram-handle", "rotation");
  }

  override paintVertexShape(canvas: AbstractCanvas2D, x: number, y: number, width: number, height: number) {
    const centerX = x + width / 2;
    const centerY = y + height / 2;

    // Keep a generous drag target while showing only the familiar rotate glyph.
    canvas.setFillColor("transparent");
    canvas.setStrokeColor("transparent");
    canvas.ellipse(x, y, width, height);
    canvas.fillAndStroke();

    const radius = Math.min(width, height) * 0.27;
    canvas.setStrokeColor(DIAGRAM_ROTATION_HANDLE_ACCENT);
    canvas.setStrokeWidth(1.7);
    canvas.setLineCap("round");
    canvas.setLineJoin("round");
    canvas.begin();
    canvas.moveTo(centerX + radius * 0.62, centerY - radius * 0.68);
    canvas.curveTo(
      centerX + radius * 0.2,
      centerY - radius,
      centerX - radius * 0.38,
      centerY - radius,
      centerX - radius * 0.76,
      centerY - radius * 0.62,
    );
    canvas.curveTo(
      centerX - radius * 1.22,
      centerY - radius * 0.16,
      centerX - radius * 1.08,
      centerY + radius * 0.62,
      centerX - radius * 0.5,
      centerY + radius * 0.92,
    );
    canvas.curveTo(
      centerX + radius * 0.08,
      centerY + radius * 1.22,
      centerX + radius * 0.82,
      centerY + radius * 0.9,
      centerX + radius,
      centerY + radius * 0.28,
    );
    canvas.stroke();
    canvas.begin();
    canvas.moveTo(centerX + radius * 0.72, centerY - radius);
    canvas.lineTo(centerX + radius * 0.72, centerY - radius * 0.48);
    canvas.lineTo(centerX + radius * 0.2, centerY - radius * 0.48);
    canvas.stroke();
  }
}

export class DiagramVertexHandler extends VertexHandler {
  rotateSingleSizer = false;
  private previousRotationPointerAngle: number | null = null;
  private accumulatedRotation = 0;

  override isRotationEnabled() {
    return true;
  }

  override start(x: number, y: number, index: number) {
    super.start(x, y, index);
    if (index === InternalEvent.ROTATION_HANDLE) {
      this.previousRotationPointerAngle = pointerAngleDegrees(this.state, x, y);
      this.accumulatedRotation = styleNumber(this.state.style.rotation, 0);
    } else {
      this.previousRotationPointerAngle = null;
    }
  }

  override rotateVertex(event: InternalMouseEvent) {
    const point = new Point(event.getGraphX(), event.getGraphY());
    const pointerAngle = pointerAngleDegrees(this.state, point.x, point.y);
    if (this.previousRotationPointerAngle === null) {
      this.previousRotationPointerAngle = pointerAngle;
      this.accumulatedRotation = styleNumber(this.state.style.rotation, 0);
    } else {
      this.accumulatedRotation += signedRotationDelta(this.previousRotationPointerAngle, pointerAngle);
      this.previousRotationPointerAngle = pointerAngle;
    }

    let rotation = this.accumulatedRotation;
    if (this.rotationRaster && this.graph.isGridEnabledEvent(event.getEvent())) {
      const dx = point.x - this.state.getCenterX();
      const dy = point.y - this.state.getCenterY();
      const distance = Math.sqrt(dx * dx + dy * dy);
      const raster = distance - this.startDist < 2 ? 15 : distance - this.startDist < 25 ? 5 : 1;
      rotation = Math.round(rotation / raster) * raster;
    } else {
      rotation = this.roundAngle(rotation);
    }

    this.currentAlpha = rotation;
    this.selectionBorder.rotation = rotation;
    this.selectionBorder.redraw();
    if (this.livePreviewActive) this.redrawHandles();
  }

  override redrawHandles() {
    super.redrawHandles();
    const resizeHandle = this.sizers[0];
    if (!this.rotateSingleSizer || !this.singleSizer || !resizeHandle) return;

    const bounds = this.getSizerBounds();
    const radians = mathUtils.toRadians(this.currentAlpha ?? this.state.style.rotation ?? 0);
    const center = new Point(bounds.getCenterX(), bounds.getCenterY());
    const position = mathUtils.getRotatedPoint(
      new Point(bounds.x + bounds.width, bounds.y + bounds.height),
      Math.cos(radians),
      Math.sin(radians),
      center,
    );
    this.moveSizerTo(resizeHandle, position.x, position.y);

    const cursors = [
      "nw-resize",
      "n-resize",
      "ne-resize",
      "e-resize",
      "se-resize",
      "s-resize",
      "sw-resize",
      "w-resize",
    ];
    const cursorOffset = Math.round((radians * 4) / Math.PI);
    resizeHandle.setCursor(cursors[mathUtils.mod(4 + cursorOffset, cursors.length)]);
  }

  ensureRotationHandle() {
    if (this.rotationShape) return;
    this.rotationShape = this.createSizer(
      this.rotationCursor,
      InternalEvent.ROTATION_HANDLE,
      DIAGRAM_ROTATION_HANDLE_SIZE,
      DIAGRAM_ROTATION_HANDLE_FILL,
    );
    this.sizers.push(this.rotationShape);
  }

  override createSizerShape(bounds: Rectangle, index: number, fillColor = HandleConfig.fillColor) {
    if (index === InternalEvent.ROTATION_HANDLE) {
      return new DiagramRotationHandleShape(
        new Rectangle(bounds.x, bounds.y, DIAGRAM_ROTATION_HANDLE_SIZE, DIAGRAM_ROTATION_HANDLE_SIZE),
        DIAGRAM_ROTATION_HANDLE_FILL,
        DIAGRAM_ROTATION_HANDLE_ACCENT,
        1.5,
      );
    }
    return super.createSizerShape(bounds, index, fillColor);
  }
}

export class DiagramCubicEdgeHandler extends EdgeHandler {
  private controlGuides?: [PolylineShape, PolylineShape];

  constructor(state: CellState) {
    super(state);
    const overlayPane = this.graph.getView().getOverlayPane();
    const createGuide = () => {
      const guide = new PolylineShape([], "#2997ff", 1);
      guide.dialect = "svg";
      guide.isDashed = true;
      guide.opacity = 68;
      guide.pointerEvents = false;
      guide.init(overlayPane);
      guide.node.classList.add("diagram-cubic-control-guide");
      guide.node.setAttribute("aria-hidden", "true");
      guide.node.style.pointerEvents = "none";
      if (this.shape.node.parentNode === overlayPane) {
        overlayPane.insertBefore(guide.node, this.shape.node);
      }
      return guide;
    };
    this.controlGuides = [createGuide(), createGuide()];
    this.redrawControlGuides();
  }

  override isVirtualBendsEnabled() {
    return false;
  }

  override isHandleVisible(index: number) {
    return index === 0 || index === this.abspoints.length - 1;
  }

  override isAddPointEvent(_event: MouseEvent) {
    return false;
  }

  override isRemovePointEvent(_event: MouseEvent) {
    return false;
  }

  override createCustomHandles() {
    return [
      new DiagramCubicControlHandle(this.state, 0),
      new DiagramCubicControlHandle(this.state, 1),
    ];
  }

  override mouseMove(sender: EventSource, event: InternalMouseEvent) {
    super.mouseMove(sender, event);
    this.redrawControlGuides();
  }

  override redraw(ignoreHandles?: boolean) {
    super.redraw(ignoreHandles);
    this.redrawControlGuides();
  }

  override setHandlesVisible(visible: boolean) {
    super.setHandlesVisible(visible);
    this.controlGuides?.forEach((guide) => {
      guide.node.style.display = visible ? "" : "none";
    });
  }

  override onDestroy() {
    this.controlGuides?.forEach((guide) => guide.destroy());
    this.controlGuides = undefined;
    super.onDestroy();
  }

  private redrawControlGuides() {
    if (!this.controlGuides || this.isDestroyed()) return;
    const [start, end] = cubicEdgeModelEndpoints(this.state);
    const [control1, control2] = cubicControlPointsFromStyle(start, end, this.state.style);
    const { scale, translate } = this.state.view;
    const toViewPoint = (point: Point) => new Point(
      (point.x + translate.x) * scale,
      (point.y + translate.y) * scale,
    );
    const startPoint = this.state.absolutePoints[0] ?? toViewPoint(start);
    const endPoint = this.state.absolutePoints[this.state.absolutePoints.length - 1] ?? toViewPoint(end);
    const visible = !this.graph.isEditing() && this.graph.getSelectionCount() === 1;
    this.controlGuides[0].points = [startPoint, toViewPoint(control1)];
    this.controlGuides[1].points = [endPoint, toViewPoint(control2)];
    this.controlGuides.forEach((guide) => {
      guide.node.style.visibility = visible ? "" : "hidden";
      guide.redraw();
    });
  }
}

ShapeRegistry.add(DIAGRAM_CUBIC_EDGE_SHAPE, DiagramCubicConnectorShape);

VertexHandlerConfig.selectionColor = "#0066cc";
VertexHandlerConfig.selectionDashed = false;
VertexHandlerConfig.selectionStrokeWidth = 1.5;
VertexHandlerConfig.cursorMovable = "grab";
VertexHandlerConfig.rotationEnabled = true;
EdgeHandlerConfig.selectionColor = "#0066cc";
EdgeHandlerConfig.selectionDashed = false;
EdgeHandlerConfig.selectionStrokeWidth = 2;
EdgeHandlerConfig.addBendOnShiftClickEnabled = true;
EdgeHandlerConfig.removeBendOnShiftClickEnabled = true;
EdgeHandlerConfig.virtualBendsEnabled = true;
EdgeHandlerConfig.virtualBendOpacity = 36;
EdgeHandlerConfig.handleShape = "circle";
HandleConfig.size = 8;
HandleConfig.fillColor = "#ffffff";
HandleConfig.strokeColor = "#0066cc";
HandleConfig.labelFillColor = "#2997ff";
StyleDefaultsConfig.shadowColor = "#0f172a";
StyleDefaultsConfig.shadowOpacity = 0.16;
StyleDefaultsConfig.shadowOffsetX = 0;
StyleDefaultsConfig.shadowOffsetY = 4;
registerDiagramSemanticShapes();

