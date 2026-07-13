import { describe, expect, it } from "vitest";
import {
  exportMermaidDocument,
  exportPlantUmlDocument,
  parseMermaidDocument,
  parsePlantUmlDocument,
} from "./diagramTextFormats";

describe("diagram text format compatibility", () => {
  it("imports Mermaid pages, shapes, labels, and edges", () => {
    const document = parseMermaidDocument(`## Approval

\`\`\`mermaid
flowchart TD
  start(["Start"])
  review["Review"]
  accepted{"Accepted?"}
  db[("Audit DB")]
  start --> review
  review -->|"check"| accepted
  accepted -.-> db
\`\`\`
`);
    expect(document.pages).toHaveLength(1);
    expect(document.nodes.map((node) => node.kind)).toEqual(["start", "process", "decision", "database"]);
    expect(document.edges).toHaveLength(3);
    expect(document.edges[1].label).toBe("check");
    expect(document.edges[2].style.dashed).toBe(true);
    expect(exportMermaidDocument(document)).toContain("flowchart TD");
  });

  it("round-trips the supported PlantUML graph subset", () => {
    const imported = parsePlantUmlDocument(`@startuml
title Architecture
left to right direction
cloud "Internet" as web
node "API" as api
database "Store" as db
web --> api : HTTPS
api ..> db : SQL
@enduml`);
    expect(imported.nodes.map((node) => node.kind)).toEqual(["cloud", "server", "database"]);
    expect(imported.edges.map((edge) => edge.label)).toEqual(["HTTPS", "SQL"]);
    const exported = exportPlantUmlDocument(imported);
    expect(exported).toContain("@startuml");
    expect(exported).toContain("left to right direction");
    expect(parsePlantUmlDocument(exported).nodes).toHaveLength(3);
  });

  it("rejects text documents without recognizable graphs", () => {
    expect(() => parseMermaidDocument("hello")).toThrow(/Mermaid/);
    expect(() => parsePlantUmlDocument("@startuml\ntitle Empty\n@enduml")).toThrow(/PlantUML/);
  });
});
