import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import type { DiagramEdge, DiagramNode, DiagramPage } from "./diagramDocument";
import { DiagramRemoteUpdateValidator } from "./diagramYjsValidation";

function createSourceDocument() {
  const document = new Y.Doc();
  document.getMap<DiagramPage>("pages").set("page-1", { id: "page-1", name: "页面 1", order: 0 });
  document.getMap<DiagramNode>("nodes").set("node-1", {
    id: "node-1",
    kind: "rectangle",
    label: "节点",
    x: 10,
    y: 20,
    width: 120,
    height: 64,
    zIndex: 0,
    pageId: "page-1",
    style: {
      fillColor: "#ffffff",
      strokeColor: "#475569",
      fontColor: "#172033",
      strokeWidth: 1,
    },
  });
  return document;
}

function updateFrom(source: Y.Doc, mutate: (document: Y.Doc) => void) {
  const remote = new Y.Doc();
  Y.applyUpdate(remote, Y.encodeStateAsUpdate(source));
  const stateVector = Y.encodeStateVector(source);
  mutate(remote);
  return Y.encodeStateAsUpdate(remote, stateVector);
}

describe("DiagramRemoteUpdateValidator", () => {
  it("accepts a valid incremental node update", () => {
    const source = createSourceDocument();
    const validator = new DiagramRemoteUpdateValidator(source);
    const update = updateFrom(source, (remote) => {
      const nodes = remote.getMap<DiagramNode>("nodes");
      nodes.set("node-1", { ...nodes.get("node-1")!, x: 80 });
    });

    expect(validator.validate(update, source)).toBe(true);
    validator.destroy();
    source.destroy();
  });

  it("rejects malformed values without poisoning later validation", () => {
    const source = createSourceDocument();
    const validator = new DiagramRemoteUpdateValidator(source);
    const invalid = updateFrom(source, (remote) => {
      remote.getMap<unknown>("nodes").set("node-1", { id: "node-1", label: "broken" });
    });
    const valid = updateFrom(source, (remote) => {
      const nodes = remote.getMap<DiagramNode>("nodes");
      nodes.set("node-1", { ...nodes.get("node-1")!, y: 90 });
    });

    expect(validator.validate(invalid, source)).toBe(false);
    expect(validator.validate(valid, source)).toBe(true);
    validator.destroy();
    source.destroy();
  });

  it("rejects deleting a page that still owns nodes", () => {
    const source = createSourceDocument();
    const validator = new DiagramRemoteUpdateValidator(source);
    const update = updateFrom(source, (remote) => {
      remote.getMap<DiagramPage>("pages").delete("page-1");
    });

    expect(validator.validate(update, source)).toBe(false);
    validator.destroy();
    source.destroy();
  });

  it("rejects a parent mutation that invalidates an unchanged child", () => {
    const source = createSourceDocument();
    const nodes = source.getMap<DiagramNode>("nodes");
    nodes.set("container-1", {
      ...nodes.get("node-1")!,
      id: "container-1",
      kind: "container",
      label: "容器",
    });
    nodes.set("node-1", { ...nodes.get("node-1")!, parentId: "container-1" });
    const validator = new DiagramRemoteUpdateValidator(source);
    const update = updateFrom(source, (remote) => {
      const remoteNodes = remote.getMap<DiagramNode>("nodes");
      remoteNodes.set("container-1", { ...remoteNodes.get("container-1")!, kind: "rectangle" });
    });

    expect(validator.validate(update, source)).toBe(false);
    validator.destroy();
    source.destroy();
  });

  it("rejects a node page mutation that invalidates an unchanged edge", () => {
    const source = createSourceDocument();
    const pages = source.getMap<DiagramPage>("pages");
    pages.set("page-2", { id: "page-2", name: "页面 2", order: 1 });
    const nodes = source.getMap<DiagramNode>("nodes");
    nodes.set("node-2", { ...nodes.get("node-1")!, id: "node-2", x: 220 });
    source.getMap<DiagramEdge>("edges").set("edge-1", {
      id: "edge-1",
      label: "",
      sourceId: "node-1",
      targetId: "node-2",
      pageId: "page-1",
      zIndex: 0,
      style: {
        strokeColor: "#475569",
        fontColor: "#172033",
        strokeWidth: 1,
      },
    });
    const validator = new DiagramRemoteUpdateValidator(source);
    const update = updateFrom(source, (remote) => {
      const remoteNodes = remote.getMap<DiagramNode>("nodes");
      remoteNodes.set("node-2", { ...remoteNodes.get("node-2")!, pageId: "page-2" });
    });

    expect(validator.validate(update, source)).toBe(false);
    validator.destroy();
    source.destroy();
  });
});
