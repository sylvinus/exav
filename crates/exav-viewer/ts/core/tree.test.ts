import { describe, expect, it } from "vitest";

import { resolveInTree } from "./tree.js";

const tree = (path: string, paths: string[]) => ({ path, paths: [path, ...paths] });

describe("the file a reference names", () => {
  const site = tree("Site/Plans/ground.dwg", ["Site/Plans/Xref/title block.dwg", "Site/Plans/Xref/Notes.dwg", "Site/survey.dwg", "Other/survey.dwg", "Site/Plans/readme.txt"]);

  it("is found as a path from the file's folder, either slash", () => {
    expect(resolveInTree(site, ".\\Xref\\title block.dwg")).toBe("Site/Plans/Xref/title block.dwg");
    expect(resolveInTree(site, "Xref/Notes.dwg")).toBe("Site/Plans/Xref/Notes.dwg");
    expect(resolveInTree(site, "..\\survey.dwg")).toBe("Site/survey.dwg");
  });

  it("is found by the end of a path written for another machine", () => {
    expect(resolveInTree(site, "C:\\Projects\\site\\Plans\\Xref\\title block.dwg")).toBe("Site/Plans/Xref/title block.dwg");
    expect(resolveInTree(site, "D:\\x\\y\\title block.dwg")).toBe("Site/Plans/Xref/title block.dwg");
  });

  it("does not tell case or the form of an accent apart", () => {
    const accents = tree("a.dwg", ["Plans/la Colline\u0300re.dwg", "Plans/Caf\u00e9.dwg"]);
    expect(resolveInTree(accents, "PLANS\\LA COLLIN\u00c8RE.DWG")).toBe("Plans/la Colline\u0300re.dwg");
    expect(resolveInTree(accents, "plans/cafe\u0301.dwg")).toBe("Plans/Caf\u00e9.dwg");
  });

  it("takes the nearest of several with the same name", () => {
    expect(resolveInTree(tree("Site/Plans/ground.dwg", ["Site/survey.dwg", "Other/survey.dwg"]), "E:\\survey.dwg")).toBe("Site/survey.dwg");
    expect(resolveInTree(tree("Other/ground.dwg", ["Site/survey.dwg", "Other/survey.dwg"]), "E:\\survey.dwg")).toBe("Other/survey.dwg");
  });

  it("is tried with an extension when the reference has none", () => {
    expect(resolveInTree(site, "Notes", [".dwg"])).toBe("Site/Plans/Xref/Notes.dwg");
    expect(resolveInTree(site, "Notes")).toBeNull();
    expect(resolveInTree(site, "readme", [".dwg"])).toBeNull();
  });

  it("is not the file itself, and is null when nothing has the name", () => {
    expect(resolveInTree(site, "ground.dwg")).toBeNull();
    expect(resolveInTree(site, "missing.dwg")).toBeNull();
    expect(resolveInTree(site, "")).toBeNull();
    expect(resolveInTree(site, "..\\..\\..\\..\\..\\missing.dwg")).toBeNull();
  });

  it("does not leave the tree for a reference that climbs out of it", () => {
    const flat = tree("a.dwg", ["b.dwg"]);
    // Past the root, it is still looked for by its name.
    expect(resolveInTree(flat, "..\\..\\b.dwg")).toBe("b.dwg");
  });
});
