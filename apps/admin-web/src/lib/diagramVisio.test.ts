import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { strToU8, zipSync } from "fflate";
import { beforeAll, describe, expect, it } from "vitest";
import { exportVisioVdx, parseVisioVdx, parseVisioVsdx } from "./diagramVisio";

beforeAll(() => {
  Object.assign(globalThis, { XMLSerializer });
});

const parser = new DOMParser() as unknown as globalThis.DOMParser;

describe("Visio diagram compatibility", () => {
  it("imports VSDX page shapes and dynamic connectors", () => {
    const pages = `<?xml version="1.0"?><Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main"><Page ID="0" Name="Network"/></Pages>`;
    const page = `<?xml version="1.0"?><PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main">
      <PageSheet><Cell N="PageHeight" V="11"/></PageSheet>
      <Shapes>
        <Shape ID="1" NameU="Start"><Cell N="PinX" V="2"/><Cell N="PinY" V="9"/><Cell N="Width" V="1.5"/><Cell N="Height" V="0.75"/><Text>Start</Text></Shape>
        <Shape ID="2" NameU="Database"><Cell N="PinX" V="5"/><Cell N="PinY" V="7"/><Cell N="Width" V="2"/><Cell N="Height" V="1"/><Text>Store</Text></Shape>
        <Shape ID="3" NameU="Dynamic connector" OneD="1"><Text>write</Text></Shape>
      </Shapes>
      <Connects><Connect FromSheet="3" FromCell="BeginX" ToSheet="1"/><Connect FromSheet="3" FromCell="EndX" ToSheet="2"/></Connects>
    </PageContents>`;
    const archive = zipSync({
      "visio/pages/pages.xml": strToU8(pages),
      "visio/pages/page1.xml": strToU8(page),
    });
    const document = parseVisioVsdx(archive, parser);
    expect(document.pages?.[0].name).toBe("Network");
    expect(document.nodes.map((node) => node.kind)).toEqual(["start", "database"]);
    expect(document.edges).toHaveLength(1);
    expect(document.edges[0].label).toBe("write");
  });

  it("exports and reimports Visio XML VDX", () => {
    const source = `<?xml version="1.0"?><VisioDocument xmlns="urn:schemas-microsoft-com:office:visio"><Pages><Page ID="1" Name="Flow"><PageSheet><PageProps><PageHeight>11</PageHeight></PageProps></PageSheet><Shapes><Shape ID="1" NameU="Process"><XForm><PinX>2</PinX><PinY>8</PinY><Width>2</Width><Height>1</Height></XForm><Text>Task</Text></Shape></Shapes><Connects/></Page></Pages></VisioDocument>`;
    const imported = parseVisioVdx(source, parser);
    expect(imported.nodes).toHaveLength(1);
    const exported = exportVisioVdx(imported);
    expect(exported).toContain("VisioDocument");
    expect(parseVisioVdx(exported, parser).nodes[0].label).toBe("Task");
  });

  it("rejects damaged VSDX archives", () => {
    expect(() => parseVisioVsdx(new Uint8Array([1, 2, 3]), parser)).toThrow(/VSDX/);
  });
});
