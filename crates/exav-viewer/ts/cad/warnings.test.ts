import { describe, expect, it } from "vitest";

import type { Warnings } from "./types";
import { cadWarnings } from "./warnings";

const none: Warnings = {
  unknownEntities: 0,
  missingBlocks: 0,
  textRuns: 0,
  strokeGlyphs: 0,
  hatchPatternsMissing: 0,
  hatchPatternsTruncated: 0,
  externalReferences: 0,
  depthExceeded: 0,
  sceneTruncated: 0,
  proxyWithoutGraphics: 0,
  notDrawn: {},
  externalFiles: [],
};

describe("cadWarnings", () => {
  it("is empty for a drawing drawn whole", () => {
    expect(cadWarnings(none, false)).toEqual([]);
  });

  it("names the types left out and the files referenced", () => {
    const w = { ...none, unknownEntities: 3, notDrawn: { "3DSOLID": 2, REGION: 1 }, externalReferences: 2, externalFiles: ["walls.dwg"] };
    expect(cadWarnings(w, false)).toEqual([
      { key: "unknown_entities", count: 3, names: ["3DSOLID (2)", "REGION"] },
      { key: "external_references", count: 2, names: ["walls.dwg"] },
    ]);
  });

  it("says first that the thumbnail stands in for the drawing", () => {
    const w = { ...none, unknownEntities: 1, notDrawn: { "3DSOLID": 1 } };
    expect(cadWarnings(w, true).map((x) => x.key)).toEqual(["preview_shown", "unknown_entities"]);
  });

  it("leaves names out when there are none, as an OLE object's", () => {
    expect(cadWarnings({ ...none, externalReferences: 1 }, false)).toEqual([{ key: "external_references", count: 1 }]);
  });
});
