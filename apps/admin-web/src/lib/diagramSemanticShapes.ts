import { Shape, ShapeRegistry } from "@maxgraph/core";
import type { AbstractCanvas2D } from "@maxgraph/core";

const SHAPE_NAMES = {
  document: "specusDocument",
  data: "specusData",
  subprocess: "specusSubprocess",
  delay: "specusDelay",
  manualInput: "specusManualInput",
  note: "specusNote",
  dataObject: "specusDataObject",
  package: "specusPackage",
  component: "specusComponent",
  server: "specusServer",
  client: "specusClient",
  firewall: "specusFirewall",
  queue: "specusQueue",
} as const;

class DocumentShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    c.begin();
    c.moveTo(x, y);
    c.lineTo(x + w, y);
    c.lineTo(x + w, y + h * 0.82);
    c.curveTo(x + w * 0.78, y + h * 0.7, x + w * 0.58, y + h * 1.02, x + w * 0.32, y + h * 0.86);
    c.curveTo(x + w * 0.18, y + h * 0.78, x + w * 0.08, y + h * 0.82, x, y + h * 0.9);
    c.close();
    c.fillAndStroke();
  }
}

class DataShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const inset = Math.min(w * 0.16, h * 0.42);
    c.begin();
    c.moveTo(x + inset, y);
    c.lineTo(x + w, y);
    c.lineTo(x + w - inset, y + h);
    c.lineTo(x, y + h);
    c.close();
    c.fillAndStroke();
  }
}

class SubprocessShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const radius = Math.min(12, h * 0.16);
    c.roundrect(x, y, w, h, radius, radius);
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x + Math.min(14, w * 0.1), y);
    c.lineTo(x + Math.min(14, w * 0.1), y + h);
    c.moveTo(x + w - Math.min(14, w * 0.1), y);
    c.lineTo(x + w - Math.min(14, w * 0.1), y + h);
    c.stroke();
  }
}

class DelayShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    c.begin();
    c.moveTo(x, y);
    c.lineTo(x + w * 0.55, y);
    c.curveTo(x + w * 0.84, y, x + w, y + h * 0.22, x + w, y + h * 0.5);
    c.curveTo(x + w, y + h * 0.78, x + w * 0.84, y + h, x + w * 0.55, y + h);
    c.lineTo(x, y + h);
    c.close();
    c.fillAndStroke();
  }
}

class ManualInputShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    c.begin();
    c.moveTo(x, y + h * 0.2);
    c.lineTo(x + w, y);
    c.lineTo(x + w, y + h);
    c.lineTo(x, y + h);
    c.close();
    c.fillAndStroke();
  }
}

class FoldedDocumentShape extends Shape {
  protected foldSize(w: number, h: number) {
    return Math.min(w * 0.24, h * 0.3, 24);
  }

  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const fold = this.foldSize(w, h);
    c.begin();
    c.moveTo(x, y);
    c.lineTo(x + w - fold, y);
    c.lineTo(x + w, y + fold);
    c.lineTo(x + w, y + h);
    c.lineTo(x, y + h);
    c.close();
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x + w - fold, y);
    c.lineTo(x + w - fold, y + fold);
    c.lineTo(x + w, y + fold);
    c.stroke();
  }
}

class NoteShape extends FoldedDocumentShape {}

class DataObjectShape extends FoldedDocumentShape {}

class PackageShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const tabWidth = Math.min(w * 0.42, 72);
    const tabHeight = Math.min(h * 0.2, 22);
    c.begin();
    c.moveTo(x, y);
    c.lineTo(x + tabWidth, y);
    c.lineTo(x + tabWidth, y + tabHeight);
    c.lineTo(x + w, y + tabHeight);
    c.lineTo(x + w, y + h);
    c.lineTo(x, y + h);
    c.close();
    c.fillAndStroke();
  }
}

class ComponentShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const radius = Math.min(10, h * 0.12);
    c.roundrect(x, y, w, h, radius, radius);
    c.fillAndStroke();
    c.setShadow(false);
    const markerWidth = Math.min(22, w * 0.18);
    const markerHeight = Math.min(14, h * 0.18);
    const markerX = x + Math.min(14, w * 0.1);
    for (const markerY of [y + h * 0.27, y + h * 0.59]) {
      c.rect(markerX, markerY, markerWidth, markerHeight);
      c.fillAndStroke();
    }
  }
}

class ServerShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const radius = Math.min(10, h * 0.1);
    c.roundrect(x, y, w, h, radius, radius);
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x, y + h * 0.32);
    c.lineTo(x + w, y + h * 0.32);
    c.moveTo(x, y + h * 0.68);
    c.lineTo(x + w, y + h * 0.68);
    c.stroke();
    const dot = Math.max(2, Math.min(5, h * 0.05));
    for (const centerY of [y + h * 0.16, y + h * 0.84]) {
      c.ellipse(x + w - dot * 3, centerY - dot, dot * 2, dot * 2);
      c.fillAndStroke();
    }
  }
}

class ClientShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const screenHeight = h * 0.72;
    const radius = Math.min(10, screenHeight * 0.12);
    c.roundrect(x, y, w, screenHeight, radius, radius);
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x + w * 0.5, y + screenHeight);
    c.lineTo(x + w * 0.5, y + h * 0.88);
    c.moveTo(x + w * 0.34, y + h * 0.88);
    c.lineTo(x + w * 0.66, y + h * 0.88);
    c.stroke();
  }
}

class FirewallShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    c.rect(x, y, w, h);
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x, y + h * 0.27);
    c.lineTo(x + w, y + h * 0.27);
    c.moveTo(x, y + h * 0.73);
    c.lineTo(x + w, y + h * 0.73);
    for (const ratio of [0.22, 0.68]) {
      c.moveTo(x + w * ratio, y);
      c.lineTo(x + w * ratio, y + h * 0.27);
    }
    for (const ratio of [0.36, 0.8]) {
      c.moveTo(x + w * ratio, y + h * 0.73);
      c.lineTo(x + w * ratio, y + h);
    }
    c.stroke();
  }
}

class QueueShape extends Shape {
  override paintVertexShape(c: AbstractCanvas2D, x: number, y: number, w: number, h: number) {
    const cap = Math.min(w * 0.14, h * 0.34);
    c.begin();
    c.moveTo(x + cap, y);
    c.lineTo(x + w - cap, y);
    c.curveTo(x + w, y, x + w, y + h, x + w - cap, y + h);
    c.lineTo(x + cap, y + h);
    c.curveTo(x, y + h, x, y, x + cap, y);
    c.close();
    c.fillAndStroke();
    c.setShadow(false);
    c.begin();
    c.moveTo(x + cap, y);
    c.curveTo(x + cap * 2, y, x + cap * 2, y + h, x + cap, y + h);
    c.stroke();
  }
}

let registered = false;

export function registerDiagramSemanticShapes() {
  if (registered) return;
  registered = true;
  ShapeRegistry.add(SHAPE_NAMES.document, DocumentShape);
  ShapeRegistry.add(SHAPE_NAMES.data, DataShape);
  ShapeRegistry.add(SHAPE_NAMES.subprocess, SubprocessShape);
  ShapeRegistry.add(SHAPE_NAMES.delay, DelayShape);
  ShapeRegistry.add(SHAPE_NAMES.manualInput, ManualInputShape);
  ShapeRegistry.add(SHAPE_NAMES.note, NoteShape);
  ShapeRegistry.add(SHAPE_NAMES.dataObject, DataObjectShape);
  ShapeRegistry.add(SHAPE_NAMES.package, PackageShape);
  ShapeRegistry.add(SHAPE_NAMES.component, ComponentShape);
  ShapeRegistry.add(SHAPE_NAMES.server, ServerShape);
  ShapeRegistry.add(SHAPE_NAMES.client, ClientShape);
  ShapeRegistry.add(SHAPE_NAMES.firewall, FirewallShape);
  ShapeRegistry.add(SHAPE_NAMES.queue, QueueShape);
}

export function semanticShapeName(kind: string): string | undefined {
  if (kind === "document") return SHAPE_NAMES.document;
  if (kind === "data") return SHAPE_NAMES.data;
  if (kind === "subprocess") return SHAPE_NAMES.subprocess;
  if (kind === "delay") return SHAPE_NAMES.delay;
  if (kind === "manualInput") return SHAPE_NAMES.manualInput;
  if (kind === "note") return SHAPE_NAMES.note;
  if (kind === "bpmnDataObject") return SHAPE_NAMES.dataObject;
  if (kind === "umlPackage") return SHAPE_NAMES.package;
  if (kind === "umlComponent") return SHAPE_NAMES.component;
  if (kind === "server") return SHAPE_NAMES.server;
  if (kind === "client") return SHAPE_NAMES.client;
  if (kind === "firewall") return SHAPE_NAMES.firewall;
  if (kind === "queue") return SHAPE_NAMES.queue;
  return undefined;
}
