// Writes the browser tests' sample files into e2e/.out/samples. Every one is
// generated here (the drawings, plan.dxf and plan.dwg, by make-plan.py, and
// kept beside this script, which copies them), so the tests carry nobody's
// work and nobody's data. The Playwright setup runs it.
//
//     node e2e/fixtures/make-samples.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "..", ".out", "samples");
fs.mkdirSync(out, { recursive: true });
const write = (name, data) => fs.writeFileSync(path.join(out, name), data);

// ── zip (stored) ────────────────────────────────────────────────────────────
const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
function zip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of files) {
    const data = Buffer.from(content);
    const fname = Buffer.from(name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(fname.length, 26);
    parts.push(local, fname, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(fname.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, fname);
    offset += 30 + fname.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cdBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cdBuf, end]);
}

// ── PDF, with an outline (ISO 32000-1, 12.3.3) and links (12.5.6.5) ──────────
function pdf() {
  const objects = [];
  const add = (body) => objects.push(body) && objects.length;
  const esc = (s) => s.replace(/[\\()]/g, (c) => `\\${c}`);
  const font = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const bold = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  // Each page is written after its content stream.
  const third = objects.length + 2 * 3;
  const link = (y, action) => `<< /Type /Annot /Subtype /Link /Rect [56 ${y - 4} 300 ${y + 12}] /Border [0 0 0] ${action} >>`;
  const pages = [
    [
      "Inspection report",
      ["1. Scope", "The north facade, the roof and the stairwell were inspected.", "", "2. Findings", "Render cracked above the second-floor windows.", "", "See 3. Actions for what follows.", "Guide: https://example.com/guide"],
      // Over the last two lines: to the third page's heading, and to an address.
      [link(610, `/Dest [${third} 0 R /XYZ 0 790 0]`), link(590, "/A << /S /URI /URI (https://example.com/guide) >>")],
    ],
    ["2. Findings (continued)", ["Gutter joint leaking at the north-east corner.", "Handrail loose on the third flight."], []],
    ["3. Actions", ["Repoint the render before winter.", "Replace the gutter joint.", "Refix the handrail."], []],
  ];
  const pagesId = objects.length + 1 + pages.length * 2 + 4;
  const pageIds = [];
  for (const [title, lines, annots] of pages) {
    const ops = [`BT /F2 22 Tf 56 770 Td (${esc(title)}) Tj ET`];
    lines.forEach((l, i) => ops.push(`BT /F1 12 Tf 56 ${730 - i * 20} Td (${esc(l)}) Tj ET`));
    ops.push("0.2 0.4 0.8 RG 2 w 56 750 m 539 750 l S");
    const stream = ops.join("\n");
    const content = add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const links = annots.length ? ` /Annots [${annots.join(" ")}]` : "";
    pageIds.push(add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 595 842] /Contents ${content} 0 R /Resources << /Font << /F1 ${font} 0 R /F2 ${bold} 0 R >> >>${links} >>`));
  }
  if (pageIds[2] !== third) throw new Error("the third page is not where its link says");
  // Outline: three entries, each landing on its heading (XYZ with a top).
  const outlineId = objects.length + 4;
  const e1 = objects.length + 1;
  add(`<< /Title (Scope) /Parent ${outlineId} 0 R /Next ${e1 + 1} 0 R /Dest [${pageIds[0]} 0 R /XYZ 0 790 0] >>`);
  add(`<< /Title (Findings) /Parent ${outlineId} 0 R /Prev ${e1} 0 R /Next ${e1 + 2} 0 R /Dest [${pageIds[1]} 0 R /XYZ 0 790 0] >>`);
  add(`<< /Title (Actions) /Parent ${outlineId} 0 R /Prev ${e1 + 1} 0 R /Dest [${pageIds[2]} 0 R /XYZ 0 790 0] >>`);
  add(`<< /Type /Outlines /First ${e1} 0 R /Last ${e1 + 2} 0 R /Count 3 >>`);
  add(`<< /Type /Pages /Kids [${pageIds.map((p) => `${p} 0 R`).join(" ")}] /Count ${pageIds.length} >>`);
  const catalog = add(`<< /Type /Catalog /Pages ${pagesId} 0 R /Outlines ${outlineId} 0 R /PageMode /UseOutlines >>`);
  let body = "%PDF-1.7\n";
  const xref = [];
  objects.forEach((o, i) => {
    xref.push(body.length);
    body += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const start = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${xref.map((x) => `${String(x).padStart(10, "0")} 00000 n \n`).join("")}`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root ${catalog} 0 R >>\nstartxref\n${start}\n%%EOF\n`;
  return Buffer.from(body, "latin1");
}

// ── images ──────────────────────────────────────────────────────────────────
const W = 640;
const H = 420;
function pixels() {
  const px = Buffer.alloc(W * H * 3);
  for (let y = 0; y < H; y++)
    for (let x = 0; x < W; x++) {
      const i = (y * W + x) * 3;
      const sky = y < H * 0.6;
      const sun = (x - 480) ** 2 + (y - 110) ** 2 < 55 ** 2;
      const hill = y > H * 0.55 + 40 * Math.sin(x / 70);
      const [r, g, b] = sun ? [250, 200, 80] : hill ? [70, 120 + (x % 40), 60] : sky ? [120 + y / 4, 170 + y / 6, 235] : [90, 140, 70];
      px[i] = r;
      px[i + 1] = g;
      px[i + 2] = b;
    }
  return px;
}
function png(px) {
  const raw = Buffer.alloc((W * 3 + 1) * H);
  for (let y = 0; y < H; y++) px.copy(raw, y * (W * 3 + 1) + 1, y * W * 3, (y + 1) * W * 3);
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}
/** TIFF, Deflate-compressed RGB in one strip: what most browsers do not draw. */
function tiff(px) {
  const strip = zlib.deflateSync(px);
  const entries = [
    [256, 3, 1, W],
    [257, 3, 1, H],
    [258, 3, 3, 0], // BitsPerSample: three shorts, at an offset filled below
    [259, 3, 1, 8],
    [262, 3, 1, 2],
    [273, 4, 1, 0], // StripOffsets, filled below
    [277, 3, 1, 3],
    [278, 3, 1, H],
    [279, 4, 1, strip.length],
    [284, 3, 1, 1],
    [339, 3, 1, 1],
  ];
  const ifdAt = 8;
  const bpsAt = ifdAt + 2 + entries.length * 12 + 4;
  const dataAt = bpsAt + 6;
  const head = Buffer.alloc(dataAt);
  head.write("II", 0);
  head.writeUInt16LE(42, 2);
  head.writeUInt32LE(ifdAt, 4);
  head.writeUInt16LE(entries.length, ifdAt);
  entries.forEach(([tag, type, count, value], i) => {
    const at = ifdAt + 2 + i * 12;
    head.writeUInt16LE(tag, at);
    head.writeUInt16LE(type, at + 2);
    head.writeUInt32LE(count, at + 4);
    const v = tag === 258 ? bpsAt : tag === 273 ? dataAt : value;
    if (type === 3 && count === 1) head.writeUInt16LE(v, at + 8);
    else head.writeUInt32LE(v, at + 8);
  });
  head.writeUInt32LE(0, ifdAt + 2 + entries.length * 12);
  head.writeUInt16LE(8, bpsAt);
  head.writeUInt16LE(8, bpsAt + 2);
  head.writeUInt16LE(8, bpsAt + 4);
  return Buffer.concat([head, strip]);
}

// ── Office ──────────────────────────────────────────────────────────────────
const rels = (target, type) =>
  `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${type}" Target="${target}"/></Relationships>`;
function docx() {
  const run = (text, bold = false) => `<w:r>${bold ? "<w:rPr><w:b/><w:sz w:val=\"32\"/></w:rPr>" : ""}<w:t xml:space="preserve">${text}</w:t></w:r>`;
  const para = (text, bold = false) => `<w:p>${run(text, bold)}</w:p>`;
  const body = [
    para("Meeting notes", true),
    para("Present: the client, the contractor, the engineer."),
    para("1. The schedule is confirmed for the spring."),
    para("2. Samples of the facade render are expected next week."),
    para("3. Next meeting in two weeks."),
    // Links: to the heading of the second page, and to an address.
    `<w:p><w:hyperlink w:anchor="actions">${run("See the actions on the next page.")}</w:hyperlink></w:p>`,
    `<w:p><w:hyperlink r:id="rIdMinutes">${run("Minutes: https://example.com/minutes")}</w:hyperlink></w:p>`,
    `<w:p><w:r><w:br w:type="page"/></w:r></w:p>`,
    `<w:p><w:bookmarkStart w:id="0" w:name="actions"/>${run("Actions", true)}<w:bookmarkEnd w:id="0"/></w:p>`,
    para("The contractor sends the render samples."),
  ].join("");
  const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
  return zip([
    ["[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`],
    ["_rels/.rels", rels("word/document.xml", "officeDocument")],
    ["word/_rels/document.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdMinutes" Type="${REL}/hyperlink" Target="https://example.com/minutes" TargetMode="External"/></Relationships>`],
    ["word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="${REL}"><w:body>${body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>`],
  ]);
}
// Two slides (ECMA-376 Part 1, 19), on the least a PresentationML package
// needs: a master, a layout and a theme.
function pptx() {
  const R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
  const NS = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="${R}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"`;
  const XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const relsOf = (list) =>
    `${XML}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${list
      .map(([id, type, target, external]) => `<Relationship Id="${id}" Type="${R}/${type}" Target="${target}"${external ? ' TargetMode="External"' : ""}/>`)
      .join("")}</Relationships>`;
  const tree = (shapes) =>
    `<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>${shapes}</p:spTree></p:cSld>`;
  // A text box at (x, y) cm, w by h cm, one paragraph per entry, each a list of [text, size in pt, link rel id?].
  const EMU = 360000;
  const box = (id, x, y, w, h, paragraphs) =>
    `<p:sp><p:nvSpPr><p:cNvPr id="${id}" name="Text ${id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="${x * EMU}" y="${y * EMU}"/><a:ext cx="${w * EMU}" cy="${h * EMU}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr wrap="square"/><a:lstStyle/>${paragraphs
      .map(
        (runs) =>
          `<a:p>${runs
            .map(([text, size, link, jump]) => `<a:r><a:rPr lang="en-GB" sz="${size * 100}">${link ? `<a:hlinkClick r:id="${link}"${jump ? ' action="ppaction://hlinksldjump"' : ""}/>` : ""}</a:rPr><a:t>${text}</a:t></a:r>`)
            .join("")}</a:p>`,
      )
      .join("")}</p:txBody></p:sp>`;
  const slide = (shapes) => `${XML}<p:sld ${NS}>${tree(shapes)}<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>`;
  const scheme = ["dk1", "lt1", "dk2", "lt2", "accent1", "accent2", "accent3", "accent4", "accent5", "accent6", "hlink", "folHlink"];
  const colours = ["000000", "FFFFFF", "1F2937", "F3F4F6", "0F766E", "B45309", "1D4ED8", "BE123C", "4D7C0F", "7C3AED", "0563C1", "954F72"];
  const solid = '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>';
  const line = `<a:ln w="9525">${solid}</a:ln>`;
  const theme = `${XML}<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Plain"><a:themeElements><a:clrScheme name="Plain">${scheme
    .map((s, i) => `<a:${s}><a:srgbClr val="${colours[i]}"/></a:${s}>`)
    .join("")}</a:clrScheme><a:fontScheme name="Plain"><a:majorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Plain"><a:fillStyleLst>${solid.repeat(3)}</a:fillStyleLst><a:lnStyleLst>${line.repeat(3)}</a:lnStyleLst><a:effectStyleLst>${"<a:effectStyle><a:effectLst/></a:effectStyle>".repeat(3)}</a:effectStyleLst><a:bgFillStyleLst>${solid.repeat(3)}</a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>`;
  const master = `${XML}<p:sldMaster ${NS}>${tree("")}<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>`;
  const layout = `${XML}<p:sldLayout ${NS}>${tree("")}<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>`;
  const presentation = `${XML}<p:presentation ${NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId2"/><p:sldId id="257" r:id="rId3"/></p:sldIdLst><p:sldSz cx="${32 * EMU}" cy="${18 * EMU}"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>`;
  const types = `${XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${[
    ["/ppt/presentation.xml", "presentationml.presentation.main"],
    ["/ppt/slides/slide1.xml", "presentationml.slide"],
    ["/ppt/slides/slide2.xml", "presentationml.slide"],
    ["/ppt/slideMasters/slideMaster1.xml", "presentationml.slideMaster"],
    ["/ppt/slideLayouts/slideLayout1.xml", "presentationml.slideLayout"],
    ["/ppt/theme/theme1.xml", "theme"],
  ]
    .map(([part, type]) => `<Override PartName="${part}" ContentType="application/vnd.openxmlformats-officedocument.${type}+xml"/>`)
    .join("")}</Types>`;
  return zip([
    ["[Content_Types].xml", types],
    ["_rels/.rels", rels("ppt/presentation.xml", "officeDocument")],
    ["ppt/presentation.xml", presentation],
    ["ppt/_rels/presentation.xml.rels", relsOf([["rId1", "slideMaster", "slideMasters/slideMaster1.xml"], ["rId2", "slide", "slides/slide1.xml"], ["rId3", "slide", "slides/slide2.xml"], ["rId4", "theme", "theme/theme1.xml"]])],
    ["ppt/slideMasters/slideMaster1.xml", master],
    ["ppt/slideMasters/_rels/slideMaster1.xml.rels", relsOf([["rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"], ["rId2", "theme", "../theme/theme1.xml"]])],
    ["ppt/slideLayouts/slideLayout1.xml", layout],
    ["ppt/slideLayouts/_rels/slideLayout1.xml.rels", relsOf([["rId1", "slideMaster", "../slideMasters/slideMaster1.xml"]])],
    ["ppt/theme/theme1.xml", theme],
    [
      "ppt/slides/slide1.xml",
      slide(
        box(2, 2, 1.5, 28, 2.5, [[["Site visit", 36]]]) +
          box(3, 2, 5, 28, 6, [[["Roof inspected.", 24]], [["Gutter replaced.", 24]]]) +
          // Links: to the second slide, and to an address.
          box(4, 2, 12, 28, 4, [[["See the actions", 20, "rId3", true]], [["Photos: https://example.com/photos", 20, "rId2"]]]),
      ),
    ],
    ["ppt/slides/_rels/slide1.xml.rels", relsOf([["rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"], ["rId2", "hyperlink", "https://example.com/photos", true], ["rId3", "slide", "slide2.xml"]])],
    ["ppt/slides/slide2.xml", slide(box(2, 2, 1.5, 28, 2.5, [[["Actions", 36]]]) + box(3, 2, 5, 28, 6, [[["Book the roofer for spring.", 24]]]))],
    ["ppt/slides/_rels/slide2.xml.rels", relsOf([["rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"]])],
  ]);
}
function xlsx() {
  const rows = [
    ["Item", "Quantity", "Unit price", "Total"],
    ["Render", 120, 18.5, 2220],
    ["Gutter joint", 1, 95, 95],
    ["Handrail fixings", 12, 4.2, 50.4],
  ];
  const cell = (v, r, c) => {
    const ref = `${"ABCD"[c]}${r + 1}`;
    return typeof v === "number" ? `<c r="${ref}"><v>${v}</v></c>` : `<c r="${ref}" t="inlineStr"><is><t>${v}</t></is></c>`;
  };
  const sheet = rows.map((row, r) => `<row r="${r + 1}">${row.map((v, c) => cell(v, r, c)).join("")}</row>`).join("");
  const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
  return zip([
    ["[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`],
    ["_rels/.rels", rels("xl/workbook.xml", "officeDocument")],
    ["xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="${REL}"><sheets><sheet name="Quote" sheetId="1" r:id="rId1"/></sheets></workbook>`],
    ["xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="${REL}/styles" Target="styles.xml"/></Relationships>`],
    ["xl/worksheets/sheet1.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="22" customWidth="1"/><col min="2" max="4" width="12" customWidth="1"/></cols><sheetData>${sheet}</sheetData></worksheet>`],
    ["xl/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="1"><font><sz val="11"/><name val="Arial"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs></styleSheet>`],
  ]);
}

// ── STL: a small house, two boxes and a gable ───────────────────────────────
function stl() {
  const facets = [];
  const quad = (a, b, c, d) => facets.push([a, b, c], [a, c, d]);
  const box = (x0, y0, z0, x1, y1, z1) => {
    const p = (x, y, z) => [x, y, z];
    const v = [p(x0, y0, z0), p(x1, y0, z0), p(x1, y1, z0), p(x0, y1, z0), p(x0, y0, z1), p(x1, y0, z1), p(x1, y1, z1), p(x0, y1, z1)];
    quad(v[0], v[3], v[2], v[1]);
    quad(v[4], v[5], v[6], v[7]);
    quad(v[0], v[1], v[5], v[4]);
    quad(v[1], v[2], v[6], v[5]);
    quad(v[2], v[3], v[7], v[6]);
    quad(v[3], v[0], v[4], v[7]);
  };
  box(0, 0, 0, 40, 30, 25);
  box(40, 5, 0, 60, 25, 15);
  const r = (x, y, z) => [x, y, z];
  facets.push([r(0, 0, 25), r(40, 0, 25), r(20, 0, 40)], [r(0, 30, 25), r(20, 30, 40), r(40, 30, 25)]);
  quad(r(0, 0, 25), r(20, 0, 40), r(20, 30, 40), r(0, 30, 25));
  quad(r(40, 0, 25), r(40, 30, 25), r(20, 30, 40), r(20, 0, 40));
  const f = (n) => n.toFixed(4);
  return `solid house\n${facets.map((t) => `facet normal 0 0 0\n outer loop\n${t.map((v) => `  vertex ${v.map(f).join(" ")}`).join("\n")}\n endloop\nendfacet`).join("\n")}\nendsolid house\n`;
}

// ── WAV: a two-second chime ─────────────────────────────────────────────────
function wav() {
  const rate = 22050;
  const n = rate * 2;
  const data = Buffer.alloc(n * 2);
  for (let i = 0; i < n; i++) {
    const t = i / rate;
    const s = Math.exp(-2 * t) * (Math.sin(2 * Math.PI * 660 * t) + 0.5 * Math.sin(2 * Math.PI * 990 * t));
    data.writeInt16LE(Math.round(s * 12000), i * 2);
  }
  const h = Buffer.alloc(44);
  h.write("RIFF", 0);
  h.writeUInt32LE(36 + data.length, 4);
  h.write("WAVEfmt ", 8);
  h.writeUInt32LE(16, 16);
  h.writeUInt16LE(1, 20);
  h.writeUInt16LE(1, 22);
  h.writeUInt32LE(rate, 24);
  h.writeUInt32LE(rate * 2, 28);
  h.writeUInt16LE(2, 32);
  h.writeUInt16LE(16, 34);
  h.write("data", 36);
  h.writeUInt32LE(data.length, 40);
  return Buffer.concat([h, data]);
}

// ── IFC4: a storey with four walls and a slab ───────────────────────────────
// `stray`: four posts at the corners too, and a beam left 1.2 km away, as
// exports sometimes leave one.
function ifc({ stray = false } = {}) {
  let id = 0;
  const lines = [];
  const e = (s) => {
    lines.push(`#${++id}=${s};`);
    return `#${id}`;
  };
  const guid = () => {
    const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$";
    let s = "";
    for (let i = 0; i < 22; i++) s += chars[(id * 7 + i * 13 + s.length * 3) % 64];
    return `'${s}'`;
  };
  const owner = e(`IFCOWNERHISTORY(${e(`IFCPERSONANDORGANIZATION(${e("IFCPERSON($,'Demo',$,$,$,$,$,$)")},${e("IFCORGANIZATION($,'exav',$,$,$)")},$)`)},${e(`IFCAPPLICATION(#3,'1.0','exav demo','exav')`)},$,.ADDED.,$,$,$,0)`);
  const origin = e("IFCCARTESIANPOINT((0.,0.,0.))");
  const z = e("IFCDIRECTION((0.,0.,1.))");
  const x = e("IFCDIRECTION((1.,0.,0.))");
  const world = e(`IFCAXIS2PLACEMENT3D(${origin},${z},${x})`);
  const context = e(`IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,1.E-05,${world},$)`);
  const body = e(`IFCGEOMETRICREPRESENTATIONSUBCONTEXT('Body','Model',*,*,*,*,${context},$,.MODEL_VIEW.,$)`);
  const units = e(`IFCUNITASSIGNMENT((${e("IFCSIUNIT(*,.LENGTHUNIT.,$,.METRE.)")},${e("IFCSIUNIT(*,.AREAUNIT.,$,.SQUARE_METRE.)")},${e("IFCSIUNIT(*,.VOLUMEUNIT.,$,.CUBIC_METRE.)")}))`);
  const project = e(`IFCPROJECT(${guid()},${owner},'Demo house',$,$,$,$,(${context}),${units})`);
  const place = (rel, px, py, pz) => e(`IFCLOCALPLACEMENT(${rel},${e(`IFCAXIS2PLACEMENT3D(${e(`IFCCARTESIANPOINT((${px},${py},${pz}))`)},${z},${x})`)})`);
  const sitePl = place("$", "0.", "0.", "0.");
  const site = e(`IFCSITE(${guid()},${owner},'Site',$,$,${sitePl},$,$,.ELEMENT.,$,$,$,$,$)`);
  const bldgPl = place(sitePl, "0.", "0.", "0.");
  const building = e(`IFCBUILDING(${guid()},${owner},'House',$,$,${bldgPl},$,$,.ELEMENT.,$,$,$)`);
  const storeyPl = place(bldgPl, "0.", "0.", "0.");
  const storey = e(`IFCBUILDINGSTOREY(${guid()},${owner},'Ground floor',$,$,${storeyPl},$,$,.ELEMENT.,0.)`);
  e(`IFCRELAGGREGATES(${guid()},${owner},$,$,${project},(${site}))`);
  e(`IFCRELAGGREGATES(${guid()},${owner},$,$,${site},(${building}))`);
  e(`IFCRELAGGREGATES(${guid()},${owner},$,$,${building},(${storey}))`);
  const solid = (dx, dy, dz) => {
    const profile = e(`IFCRECTANGLEPROFILEDEF(.AREA.,$,${e(`IFCAXIS2PLACEMENT2D(${e(`IFCCARTESIANPOINT((${dx / 2},${dy / 2}))`)},$)`)},${dx},${dy})`);
    const extruded = e(`IFCEXTRUDEDAREASOLID(${profile},${e(`IFCAXIS2PLACEMENT3D(${origin},$,$)`)},${z},${dz})`);
    return e(`IFCPRODUCTDEFINITIONSHAPE($,$,(${e(`IFCSHAPEREPRESENTATION(${body},'Body','SweptSolid',(${extruded}))`)}))`);
  };
  const elements = [];
  const wall = (name, px, py, dx, dy) => elements.push(e(`IFCWALL(${guid()},${owner},'${name}',$,$,${place(storeyPl, px, py, "0.")},${solid(dx, dy, 3)},$,.STANDARD.)`));
  wall("North wall", "0.", "7.8", 12, 0.2);
  wall("South wall", "0.", "0.", 12, 0.2);
  wall("East wall", "11.8", "0.2", 0.2, 7.6);
  wall("West wall", "0.", "0.2", 0.2, 7.6);
  elements.push(e(`IFCSLAB(${guid()},${owner},'Ground slab',$,$,${place(storeyPl, "0.", "0.", "-0.3")},${solid(12, 8, 0.3)},$,.FLOOR.)`));
  if (stray) {
    for (const [px, py] of [["0.", "0."], ["11.8", "0."], ["0.", "7.8"], ["11.8", "7.8"]]) {
      elements.push(e(`IFCCOLUMN(${guid()},${owner},'Post',$,$,${place(storeyPl, px, py, "3.")},${solid(0.2, 0.2, 0.5)},$,.COLUMN.)`));
    }
    elements.push(e(`IFCBEAM(${guid()},${owner},'Stray beam',$,$,${place(storeyPl, "1200.", "150.", "0.")},${solid(2, 0.3, 0.3)},$,.BEAM.)`));
  }
  e(`IFCRELCONTAINEDINSPATIALSTRUCTURE(${guid()},${owner},$,$,(${elements.join(",")}),${storey})`);
  return `ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('ViewDefinition [ReferenceView]'),'2;1');\nFILE_NAME('house.ifc','2026-01-01T00:00:00',(''),(''),'exav','exav demo','');\nFILE_SCHEMA(('IFC4'));\nENDSEC;\nDATA;\n${lines.join("\n")}\nENDSEC;\nEND-ISO-10303-21;\n`;
}

const px = pixels();
const report = pdf();
write("report.pdf", report);
write("landscape.png", png(px));
write("landscape.tif", tiff(px));
write("quote.csv", "Item;Quantity;Unit price;Total\nRender;120;18,50;2220,00\nGutter joint;1;95,00;95,00\nHandrail fixings;12;4,20;50,40\n");
write("notes.docx", docx());
write("visit.pptx", pptx());
write("quote.xlsx", xlsx());
write("house.stl", stl());
write("chime.wav", wav());
write("house.ifc", ifc());
write("stray.ifc", ifc({ stray: true }));
const plan = fs.readFileSync(path.join(here, "plan.dwg"));
write("plan.dxf", fs.readFileSync(path.join(here, "plan.dxf")));
write("plan.dwg", plan);
const inner = zip([["photos/landscape.tif", tiff(px)]]);
write(
  "delivery.zip",
  zip([
    ["documents/report.pdf", report],
    ["documents/quote.csv", fs.readFileSync(path.join(out, "quote.csv"))],
    ["drawings/plan.dwg", plan],
    ["photos.zip", inner],
  ]),
);
console.log(`samples written to ${out}`);
