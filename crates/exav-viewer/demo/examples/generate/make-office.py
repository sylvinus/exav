#!/usr/bin/env python3
"""Writes the demo's Office and OpenDocument examples into ../files/office/,
../files/converted/ and ../files/pdf/.

    python3 -I make-office.py [OUT_DIR]      # OUT_DIR holds office/, converted/ and pdf/

Output: CC0-1.0, a public domain dedication by the exav project. The four
documents (a handbook, a workbook, a deck and a diagram) are written here as
flat OpenDocument XML, by hand, with their text, their numbers and their
pictures made up for the demo. LibreOffice (soffice) is then used as a black
box that only converts those four documents into the other formats; it adds
nothing of its own to them.

Needs: Python 3, Pillow, numpy, and LibreOffice 7.5 or later (soffice).

- handbook: .fodt (flat), .odt, .docx, .doc, .rtf, and a tagged PDF with
  bookmarks and links. Styles, outline numbering, a table of contents, lists,
  tables with merged cells and a repeated header, pictures, footnotes,
  hyperlinks, bookmarks, fields, comments, tracked changes, columns, a
  landscape section, headers and footers with page numbers.
- workbook: .fods (flat), .ods, .xlsx, .xls. Three sheets with formulas,
  number formats, merged cells, a frozen header, conditional formatting, a
  validation list, named ranges, comments, hyperlinks, and bar, line and pie
  charts.
- deck: .fodp (flat), .odp, .pptx, .ppt. Slides with a master (footer, slide
  number), pictures, a table, a native chart, shapes with gradients and
  arrows, bulleted text of several levels, speaker notes (not shown by the
  viewer) and transitions.
- diagram: .fodg (flat) and .odg. A flowchart on two pages with layers,
  connectors that follow their shapes, groups, gradients, curves, text.
"""
import base64
import io
import math
import os
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape, quoteattr

import numpy as np
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files")
for d in ("office", "converted", "pdf"):
    os.makedirs(os.path.join(OUT, d), exist_ok=True)

NS = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" '
    'xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
    'xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" '
    'xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" '
    'xmlns:smil="urn:oasis:names:tc:opendocument:xmlns:smil-compatible:1.0" xmlns:anim="urn:oasis:names:tc:opendocument:xmlns:animation:1.0" '
    'xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2" '
    'xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0" xmlns:loext="urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0" '
    'xmlns:ooo="http://openoffice.org/2004/office"'
)


def aileron(size):
    return ImageFont.load_default(size)


def png_b64(im):
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode()


def picture(w=640, h=360, seed=1, label="exav example picture"):
    """A made-up picture: a lake at dusk, drawn with numpy and Pillow."""
    y = np.linspace(0, 1, h)[:, None]
    x = np.linspace(0, 1, w)[None, :]
    px = np.zeros((h, w, 3), float)
    px[..., 0] = 30 + 200 * y ** 1.5
    px[..., 1] = 40 + 90 * y
    px[..., 2] = 110 + 40 * y - 60 * y ** 2
    sun = np.hypot((x - 0.7) * w / h, y - 0.55) < 0.07
    px[sun] = (255, 245, 215)
    im = Image.fromarray(np.clip(px, 0, 255).astype(np.uint8), "RGB")
    d = ImageDraw.Draw(im)
    rng = np.random.default_rng(seed)
    pts = [(0, int(h * 0.64))] + [(i * w // 16, int(h * (0.5 + 0.1 * rng.random()))) for i in range(1, 16)] + [(w, int(h * 0.64)), (w, h), (0, h)]
    d.polygon(pts, fill=(34, 40, 66))
    d.rectangle((0, int(h * 0.64), w, h), fill=(28, 56, 92))
    d.text((12, h - 30), label, font=aileron(18), fill=(245, 235, 215))
    return im


# ======================================================================
# The handbook (text document)
# ======================================================================

LOREM = [
    "The east quay was built in three stages. The first stage, a timber jetty of twenty berths, dates from the start of the register; the second doubled it in stone, and the third, the long breakwater, shelters both from the south-west swell.",
    "Every berth has a number, a length in metres and a holder. The register is kept on paper and in a table; the two are compared each spring, and the differences are explained in the notes of the harbour master.",
    "Visitors are asked to call the harbour office on channel 9 before they come in, to give the length of their boat and its draught, and to say how many nights they plan to stay.",
]


def t(text):
    return escape(text)


def span(style, text):
    return f'<text:span text:style-name="{style}">{t(text)}</text:span>'


def para(style, *content):
    return f'<text:p text:style-name="{style}">{"".join(c if c.startswith("<") else t(c) for c in content)}</text:p>'


def heading(level, text, bookmark=None):
    b = f'<text:bookmark text:name="{bookmark}"/>' if bookmark else ""
    return f'<text:h text:style-name="Heading_20_{level}" text:outline-level="{level}">{b}{t(text)}</text:h>'


def list_(style, items, level=1):
    out = [f'<text:list text:style-name="{style}">']
    for it in items:
        if isinstance(it, list):
            out.append("<text:list-item>" + list_(style, it, level + 1) + "</text:list-item>")
        else:
            out.append(f'<text:list-item><text:p text:style-name="List_20_Contents">{it if it.startswith("<") else t(it)}</text:p></text:list-item>')
    out.append("</text:list>")
    return "".join(out)


def table(name, style, widths, rows, header_rows=1):
    cols = "".join(f'<table:table-column table:style-name="{w}"/>' for w in widths)
    head, body = rows[:header_rows], rows[header_rows:]
    out = [f'<table:table table:name="{name}" table:style-name="{style}">', cols]
    if header_rows:
        out.append("<table:table-header-rows>" + "".join(row for row in head) + "</table:table-header-rows>")
    out.append("".join(body))
    out.append("</table:table>")
    return "".join(out)


def cell(text, style="Tc", pstyle="Table_20_Contents", span_=1, rowspan=1, value=None):
    attrs = f' table:style-name="{style}" office:value-type="string"'
    if span_ > 1:
        attrs += f' table:number-columns-spanned="{span_}"'
    if rowspan > 1:
        attrs += f' table:number-rows-spanned="{rowspan}"'
    if value is not None:
        attrs = attrs.replace('office:value-type="string"', f'office:value-type="float" office:value="{value}"')
    return f'<table:table-cell{attrs}><text:p text:style-name="{pstyle}">{text if text.startswith("<") else t(text)}</text:p></table:table-cell>'


def covered(n=1):
    return "<table:covered-table-cell/>" * n


def row(*cells):
    return "<table:table-row>" + "".join(cells) + "</table:table-row>"


def handbook_fodt():
    pic = picture(640, 360)
    pic2 = picture(480, 270, 4, "Second picture")
    cites = " ".join([f"[{i}]" for i in range(1, 3)])
    headings = [("Introduction", 1, "intro"), ("Text and styles", 1, "text"), ("Lists", 1, "lists"), ("Tables", 1, "tables"), ("Pictures and shapes", 1, "pictures"), ("Links, fields and notes", 1, "links"), ("Wide table (landscape)", 1, "wide")]
    toc_entries = "".join(
        f'<text:p text:style-name="Contents_20_1"><text:a xlink:type="simple" xlink:href="#{b}" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">{i}. {t(h)}</text:a></text:p>'
        for i, (h, _, b) in enumerate(headings, 1)
    )
    body = []
    # Title page.
    body.append(para("Title", "Harbour handbook"))
    body.append(para("Subtitle", "The east quay: rules, figures and notes"))
    body.append(para("Author", "exav project, written for the demo (CC0-1.0)"))
    body.append(para("Author", "1 January 2000"))
    body.append(
        '<text:table-of-content text:style-name="Sect1" text:protected="true" text:name="Table of Contents1"><text:table-of-content-source text:outline-level="2">'
        '<text:index-title-template text:style-name="Contents_20_Heading">Contents</text:index-title-template></text:table-of-content-source>'
        f'<text:index-body><text:index-title text:style-name="Sect1" text:name="Table of Contents1_Head"><text:p text:style-name="Contents_20_Heading">Contents</text:p></text:index-title>{toc_entries}</text:index-body></text:table-of-content>'
    )
    # 1 Introduction.
    body.append(heading(1, "Introduction", "intro"))
    body.append(para("Text_20_body", LOREM[0]))
    body.append(para("Text_20_body", LOREM[1] + " ", f'<text:note text:id="ftn1" text:note-class="footnote"><text:note-citation>1</text:note-citation><text:note-body><text:p text:style-name="Footnote">The register of 2000 lists sixty berths.</text:p></text:note-body></text:note>'))
    body.append(para("Quotations", "“A harbour is a promise that the sea will wait.” "))
    body.append(para("Text_20_body", LOREM[2]))
    # 2 Text and styles.
    body.append(heading(1, "Text and styles", "text"))
    body.append(heading(2, "Character formatting"))
    body.append(
        para(
            "Text_20_body",
            span("Strong", "Bold"), ", ", span("Emphasis", "italic"), ", ", span("Underline", "underlined"), ", ", span("Strike", "struck through"), ", ", span("Red", "red"), ", ", span("Highlight", "highlighted"),
            ", ", span("SmallCaps", "small capitals"), ", ", span("Big", "large"), " and ", span("Mono", "monospaced"), " text; H", span("Sub", "2"), "O and 10", span("Super", "3"), "; a ", span("Emphasis", "mixed"), " style.",
        )
    )
    body.append(heading(2, "Paragraph formatting"))
    body.append(para("Justified", LOREM[0] + " " + LOREM[1]))
    body.append(para("Centered", "A centred line"))
    body.append(para("Right", "A line aligned to the right"))
    body.append(para("Indented", "An indented paragraph with a left border: " + LOREM[2]))
    body.append(para("Code", "moor --boat Aurora --length 6.5"))
    body.append(para("Code", "berth 14 free until 06:00"))
    body.append(heading(2, "A section in two columns"))
    body.append(
        '<text:section text:style-name="Sect2" text:name="Columns">'
        + para("Text_20_body", LOREM[0] + " " + LOREM[1] + " " + LOREM[2] + " " + LOREM[0])
        + "</text:section>"
    )
    # 3 Lists.
    body.append(heading(1, "Lists", "lists"))
    body.append(list_("L1", ["Water at every berth", ["cold, from the quay", "hot, in the shower block"], "Electricity", ["16 A at berths 1 to 40", ["with a meter", "without a meter"], "32 A at the east pontoon"], "Wi-Fi on the quay"]))
    body.append(para("Text_20_body", "Numbered, with other numbering styles at each level:"))
    body.append(list_("L2", ["Call the office on channel 9", "Give the length and the draught", ["length over all, in metres", "draught, in metres"], "Take the berth you are given", ["tie up bow first", "tie up stern first"], "Pay at the office"]))
    # 4 Tables.
    body.append(heading(1, "Tables", "tables"))
    body.append(para("Caption", "Table ", '<text:sequence text:ref-name="refTable0" text:name="Table" text:formula="ooow:Table+1" style:num-format="1">1</text:sequence>', ": berths by length, with merged cells and a repeated header row"))
    rows = [row(cell("Length", "Th", "Table_20_Heading"), cell("Berths", "Th", "Table_20_Heading"), cell("Let by", "Th", "Table_20_Heading"), cell("Fee (EUR)", "Th", "Table_20_Heading"))]
    for a, b, c, d in [("up to 6 m", 12, "week", 18.0), ("6 to 8 m", 18, "season", 24.5), ("8 to 10 m", 14, "season", 31.0), ("10 to 12 m", 9, "year", 42.0), ("over 12 m", 7, "year", 58.5)]:
        rows.append(row(cell(a), cell(str(b), "TcR", "Table_20_Right", value=b), cell(c), cell(f"{d:.2f}", "TcR", "Table_20_Right", value=d)))
    rows.append(row(cell("<text:span text:style-name=\"Strong\">Total</text:span>", "TcTotal", span_=1), cell("60", "TcTotalR", "Table_20_Right", value=60), cell("", "TcTotal", span_=2), covered()))
    body.append(table("Table1", "Tbl1", ["TcolA", "TcolB", "TcolC", "TcolD"], rows))
    body.append(para("Text_20_body", ""))
    rows = [
        row(cell("Merged across two columns", "Th", "Table_20_Heading", span_=2), covered(), cell("Merged down two rows", "Tc", rowspan=2), ),
        row(cell("a"), cell("b"), covered()),
        row(cell("c"), cell("d"), cell("e")),
    ]
    body.append(table("Table2", "Tbl1", ["TcolA", "TcolB", "TcolC"], rows, header_rows=0))
    # 5 Pictures and shapes.
    body.append(heading(1, "Pictures and shapes", "pictures"))
    body.append(
        '<text:p text:style-name="Text_20_body"><draw:frame draw:style-name="fr1" draw:name="Picture 1" text:anchor-type="paragraph" svg:width="8cm" svg:height="4.5cm">'
        f'<draw:image><office:binary-data>{png_b64(pic)}</office:binary-data></draw:image><svg:title>A lake at dusk</svg:title><svg:desc>A made-up picture of a lake and a hill at dusk.</svg:desc></draw:frame>'
        + t(LOREM[0] + " " + LOREM[1] + " " + LOREM[2] + " ")
        + t(LOREM[0] + " ")
        + "</text:p>"
    )
    body.append(para("Caption", "Figure ", '<text:sequence text:ref-name="refFigure0" text:name="Figure" text:formula="ooow:Figure+1" style:num-format="1">1</text:sequence>', ": a picture that text flows around"))
    body.append(
        '<text:p text:style-name="Centered"><draw:frame draw:style-name="fr2" draw:name="Picture 2" text:anchor-type="as-char" svg:width="6cm" svg:height="3.375cm">'
        f'<draw:image><office:binary-data>{png_b64(pic2)}</office:binary-data></draw:image><svg:title>The second picture</svg:title></draw:frame></text:p>'
    )
    body.append(
        '<text:p text:style-name="Text_20_body"><draw:custom-shape draw:style-name="gr1" draw:name="Callout" text:anchor-type="paragraph" svg:width="6cm" svg:height="2cm" svg:x="2cm" svg:y="0.2cm">'
        '<text:p text:style-name="Centered">A shape with text in it</text:p><draw:enhanced-geometry svg:viewBox="0 0 21600 21600" draw:type="round-rectangle" draw:enhanced-path="M 3600 0 X 0 3600 L 0 18000 Y 3600 21600 L 18000 21600 X 21600 18000 L 21600 3600 Y 18000 0 Z N"/></draw:custom-shape>'
        "A line of text beside a shape.</text:p>"
    )
    # 6 Links, fields and notes.
    body.append(heading(1, "Links, fields and notes", "links"))
    body.append(
        para(
            "Text_20_body",
            "An external link: ", '<text:a xlink:type="simple" xlink:href="https://exav.org/" text:style-name="Internet_20_link" text:visited-style-name="Visited_20_Internet_20_Link">exav.org</text:a>',
            ". An internal link: ", '<text:a xlink:type="simple" xlink:href="#intro" text:style-name="Internet_20_link" text:visited-style-name="Visited_20_Internet_20_Link">back to the introduction</text:a>',
            ". A reference to a bookmark: ", '<text:bookmark-ref text:reference-format="text" text:ref-name="tables">Tables</text:bookmark-ref>', ".",
        )
    )
    body.append(
        para(
            "Text_20_body", "Fields: this document is titled “", '<text:title>Harbour handbook</text:title>', "”, and this line is on page ",
            '<text:page-number text:select-page="current">1</text:page-number>', ". A fixed date: ", '<text:date style:data-style-name="N10" text:date-value="2000-01-01" text:fixed="true">01/01/2000</text:date>', ".",
        )
    )
    body.append(
        para(
            "Text_20_body", "A comment is attached to this word", '<office:annotation><dc:creator>exav</dc:creator><dc:date>2000-01-01T00:00:00</dc:date><text:p>A comment: the viewer shows or ignores it.</text:p></office:annotation>',
            ". A change that was tracked: ", '<text:change-start text:change-id="ct1"/>this text was inserted<text:change-end text:change-id="ct1"/>', ", ", '<text:change text:change-id="ct2"/>', "and some text was deleted before this one.",
        )
    )
    body.append(para("Text_20_body", f"Citations {cites}. ", '<text:note text:id="ftn2" text:note-class="footnote"><text:note-citation>2</text:note-citation><text:note-body><text:p text:style-name="Footnote">A second footnote, with <text:span text:style-name="Emphasis">emphasis</text:span>.</text:p></text:note-body></text:note>'))
    # 7 A wide table in landscape.
    body.append('<text:h text:style-name="Heading_20_1_20_Landscape" text:outline-level="1"><text:bookmark text:name="wide"/>Wide table (landscape)</text:h>')
    heads = ["Month"] + [f"Berth {i}" for i in range(1, 11)] + ["Total"]
    rows = [row(*[cell(h, "Th", "Table_20_Heading") for h in heads])]
    for m, name in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]):
        vals = [(m * 7 + i * 5) % 9 + 1 for i in range(10)]
        rows.append(row(cell(name), *[cell(str(v), "TcR", "Table_20_Right", value=v) for v in vals], cell(str(sum(vals)), "TcTotalR", "Table_20_Right", value=sum(vals))))
    body.append(table("Table3", "TblWide", ["TcolW"] * 12, rows))
    body.append(para("Text_20_body", "Nights let at each berth, by month."))

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document {NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text">
<office:meta><meta:initial-creator>exav project</meta:initial-creator><dc:title>Harbour handbook</dc:title><dc:subject>A document made for the exav demo (CC0-1.0)</dc:subject><meta:keyword>demo</meta:keyword><dc:language>en-US</dc:language><meta:creation-date>2000-01-01T00:00:00</meta:creation-date></office:meta>
<office:font-face-decls>
<style:font-face style:name="Liberation Serif" svg:font-family="'Liberation Serif'" style:font-family-generic="roman" style:font-pitch="variable"/>
<style:font-face style:name="Liberation Sans" svg:font-family="'Liberation Sans'" style:font-family-generic="swiss" style:font-pitch="variable"/>
<style:font-face style:name="Liberation Mono" svg:font-family="'Liberation Mono'" style:font-family-generic="modern" style:font-pitch="fixed"/>
</office:font-face-decls>
<office:styles>
<style:default-style style:family="paragraph"><style:paragraph-properties fo:orphans="2" fo:widows="2" style:tab-stop-distance="1.25cm"/><style:text-properties style:font-name="Liberation Serif" fo:font-size="11pt" fo:language="en" fo:country="US"/></style:default-style>
<style:style style:name="Standard" style:family="paragraph" style:class="text"/>
<style:style style:name="Text_20_body" style:display-name="Text body" style:family="paragraph" style:parent-style-name="Standard" style:class="text"><style:paragraph-properties fo:margin-top="0cm" fo:margin-bottom="0.22cm" fo:line-height="125%"/></style:style>
<style:style style:name="Title" style:family="paragraph" style:parent-style-name="Standard" style:next-style-name="Subtitle" style:class="chapter"><style:paragraph-properties fo:margin-top="3cm" fo:margin-bottom="0.3cm" fo:text-align="start"/><style:text-properties style:font-name="Liberation Sans" fo:font-size="30pt" fo:font-weight="bold" fo:color="#0b4f6c"/></style:style>
<style:style style:name="Subtitle" style:family="paragraph" style:parent-style-name="Standard" style:class="chapter"><style:paragraph-properties fo:margin-bottom="0.6cm"/><style:text-properties style:font-name="Liberation Sans" fo:font-size="16pt" fo:color="#555555"/></style:style>
<style:style style:name="Author" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-bottom="0.1cm"/><style:text-properties fo:font-size="10pt" fo:color="#666666"/></style:style>
<style:style style:name="Heading" style:family="paragraph" style:parent-style-name="Standard" style:next-style-name="Text_20_body" style:class="text"><style:paragraph-properties fo:margin-top="0.45cm" fo:margin-bottom="0.2cm" fo:keep-with-next="always"/><style:text-properties style:font-name="Liberation Sans" fo:font-weight="bold"/></style:style>
<style:style style:name="Heading_20_1" style:display-name="Heading 1" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:default-outline-level="1" style:list-style-name="Outline" style:class="text"><style:text-properties fo:font-size="17pt" fo:color="#0b4f6c"/></style:style>
<style:style style:name="Heading_20_2" style:display-name="Heading 2" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:default-outline-level="2" style:list-style-name="Outline" style:class="text"><style:text-properties fo:font-size="13pt" fo:color="#146c94"/></style:style>
<style:style style:name="Heading_20_1_20_Landscape" style:display-name="Heading 1 Landscape" style:family="paragraph" style:parent-style-name="Heading_20_1"><style:paragraph-properties style:page-number="auto" style:master-page-name="Landscape" fo:break-before="page"/></style:style>
<style:style style:name="Contents_20_Heading" style:display-name="Contents Heading" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-top="1.5cm" fo:margin-bottom="0.3cm"/><style:text-properties style:font-name="Liberation Sans" fo:font-size="15pt" fo:font-weight="bold"/></style:style>
<style:style style:name="Contents_20_1" style:display-name="Contents 1" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-bottom="0.1cm"/></style:style>
<style:style style:name="Quotations" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-left="1cm" fo:margin-right="1cm" fo:margin-top="0.2cm" fo:margin-bottom="0.3cm" fo:padding="0.15cm" fo:border-left="2.25pt solid #146c94" fo:border-top="none" fo:border-bottom="none" fo:border-right="none"/><style:text-properties fo:font-style="italic" fo:color="#333333"/></style:style>
<style:style style:name="Justified" style:family="paragraph" style:parent-style-name="Text_20_body"><style:paragraph-properties fo:text-align="justify"/></style:style>
<style:style style:name="Centered" style:family="paragraph" style:parent-style-name="Text_20_body"><style:paragraph-properties fo:text-align="center"/></style:style>
<style:style style:name="Right" style:family="paragraph" style:parent-style-name="Text_20_body"><style:paragraph-properties fo:text-align="end"/></style:style>
<style:style style:name="Indented" style:family="paragraph" style:parent-style-name="Text_20_body"><style:paragraph-properties fo:margin-left="1.5cm" fo:border-left="1pt solid #999999" fo:padding-left="0.2cm"/></style:style>
<style:style style:name="Code" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-left="0.5cm" fo:margin-bottom="0cm" fo:background-color="#f0f0f0" fo:padding="0.08cm"/><style:text-properties style:font-name="Liberation Mono" fo:font-size="9.5pt"/></style:style>
<style:style style:name="Caption" style:family="paragraph" style:parent-style-name="Standard" style:class="extra"><style:paragraph-properties fo:margin-top="0.1cm" fo:margin-bottom="0.2cm"/><style:text-properties fo:font-size="9pt" fo:font-style="italic" fo:color="#444444"/></style:style>
<style:style style:name="Footnote" style:family="paragraph" style:parent-style-name="Standard" style:class="extra"><style:paragraph-properties fo:margin-left="0.5cm" fo:text-indent="-0.5cm"/><style:text-properties fo:font-size="9pt"/></style:style>
<style:style style:name="Header" style:family="paragraph" style:parent-style-name="Standard" style:class="extra"><style:text-properties fo:font-size="9pt" fo:color="#666666"/></style:style>
<style:style style:name="Footer" style:family="paragraph" style:parent-style-name="Standard" style:class="extra"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="9pt" fo:color="#666666"/></style:style>
<style:style style:name="List_20_Contents" style:display-name="List Contents" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-bottom="0.08cm"/></style:style>
<style:style style:name="Table_20_Contents" style:display-name="Table Contents" style:family="paragraph" style:parent-style-name="Standard"/>
<style:style style:name="Table_20_Heading" style:display-name="Table Heading" style:family="paragraph" style:parent-style-name="Table_20_Contents"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="Table_20_Right" style:display-name="Table Right" style:family="paragraph" style:parent-style-name="Table_20_Contents"><style:paragraph-properties fo:text-align="end"/></style:style>
<style:style style:name="Strong" style:family="text"><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="Emphasis" style:family="text"><style:text-properties fo:font-style="italic"/></style:style>
<style:style style:name="Underline" style:family="text"><style:text-properties style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color"/></style:style>
<style:style style:name="Strike" style:family="text"><style:text-properties style:text-line-through-style="solid"/></style:style>
<style:style style:name="Red" style:family="text"><style:text-properties fo:color="#c0392b"/></style:style>
<style:style style:name="Highlight" style:family="text"><style:text-properties fo:background-color="#ffeb3b"/></style:style>
<style:style style:name="SmallCaps" style:family="text"><style:text-properties fo:font-variant="small-caps"/></style:style>
<style:style style:name="Big" style:family="text"><style:text-properties fo:font-size="15pt"/></style:style>
<style:style style:name="Mono" style:family="text"><style:text-properties style:font-name="Liberation Mono" fo:font-size="10pt"/></style:style>
<style:style style:name="Sub" style:family="text"><style:text-properties style:text-position="sub 58%"/></style:style>
<style:style style:name="Super" style:family="text"><style:text-properties style:text-position="super 58%"/></style:style>
<style:style style:name="Internet_20_link" style:display-name="Internet link" style:family="text"><style:text-properties fo:color="#0645ad" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color"/></style:style>
<style:style style:name="Visited_20_Internet_20_Link" style:display-name="Visited Internet Link" style:family="text"><style:text-properties fo:color="#6a1b9a" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color"/></style:style>
<style:style style:name="Index_20_Link" style:display-name="Index Link" style:family="text"/>
<text:outline-style style:name="Outline">
<text:outline-level-style text:level="1" style:num-format="1" style:num-suffix=". "><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.9cm" fo:text-indent="-0.9cm" fo:margin-left="0.9cm"/></style:list-level-properties></text:outline-level-style>
<text:outline-level-style text:level="2" style:num-format="1" text:display-levels="2" style:num-suffix=" "><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.2cm" fo:text-indent="-1.2cm" fo:margin-left="1.2cm"/></style:list-level-properties></text:outline-level-style>
</text:outline-style>
<text:list-style style:name="L1">
<text:list-level-style-bullet text:level="1" text:bullet-char="•"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.9cm" fo:text-indent="-0.5cm" fo:margin-left="0.9cm"/></style:list-level-properties></text:list-level-style-bullet>
<text:list-level-style-bullet text:level="2" text:bullet-char="◦"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.7cm" fo:text-indent="-0.5cm" fo:margin-left="1.7cm"/></style:list-level-properties></text:list-level-style-bullet>
<text:list-level-style-bullet text:level="3" text:bullet-char="▪"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.5cm" fo:text-indent="-0.5cm" fo:margin-left="2.5cm"/></style:list-level-properties></text:list-level-style-bullet>
</text:list-style>
<text:list-style style:name="L2">
<text:list-level-style-number text:level="1" style:num-suffix="." style:num-format="1"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.9cm" fo:text-indent="-0.6cm" fo:margin-left="0.9cm"/></style:list-level-properties></text:list-level-style-number>
<text:list-level-style-number text:level="2" style:num-suffix=")" style:num-format="a"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.8cm" fo:text-indent="-0.6cm" fo:margin-left="1.8cm"/></style:list-level-properties></text:list-level-style-number>
</text:list-style>
<text:notes-configuration text:note-class="footnote" style:num-format="1" text:start-value="0" text:footnotes-position="page" text:start-numbering-at="document"/>
<text:linenumbering-configuration text:number-lines="false"/>
<style:style style:name="fr1" style:family="graphic"><style:graphic-properties style:wrap="parallel" style:number-wrapped-paragraphs="no-limit" style:wrap-contour="false" style:vertical-pos="top" style:vertical-rel="paragraph" style:horizontal-pos="right" style:horizontal-rel="paragraph" fo:margin-left="0.3cm" fo:margin-bottom="0.2cm" fo:border="0.5pt solid #999999"/></style:style>
<style:style style:name="fr2" style:family="graphic"><style:graphic-properties style:vertical-pos="top" style:vertical-rel="baseline" fo:border="0.5pt solid #999999"/></style:style>
<style:style style:name="gr1" style:family="graphic"><style:graphic-properties draw:fill="solid" draw:fill-color="#dbe9f4" draw:stroke="solid" svg:stroke-color="#146c94" svg:stroke-width="0.06cm" style:wrap="none" style:vertical-pos="top" style:vertical-rel="paragraph" style:horizontal-pos="from-left" style:horizontal-rel="paragraph"/></style:style>
</office:styles>
<office:automatic-styles>
<number:date-style style:name="N10"><number:day number:style="long"/><number:text>/</number:text><number:month number:style="long"/><number:text>/</number:text><number:year number:style="long"/></number:date-style>
<style:page-layout style:name="pm1"><style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm" style:print-orientation="portrait" fo:margin-top="1.5cm" fo:margin-bottom="1.2cm" fo:margin-left="2.2cm" fo:margin-right="2.2cm"/><style:header-style><style:header-footer-properties fo:min-height="0.5cm" fo:margin-bottom="0.4cm"/></style:header-style><style:footer-style><style:header-footer-properties fo:min-height="0.5cm" fo:margin-top="0.4cm"/></style:footer-style></style:page-layout>
<style:page-layout style:name="pm2"><style:page-layout-properties fo:page-width="29.7cm" fo:page-height="21cm" style:print-orientation="landscape" fo:margin-top="1.5cm" fo:margin-bottom="1.2cm" fo:margin-left="2.2cm" fo:margin-right="2.2cm"/><style:header-style><style:header-footer-properties fo:min-height="0.5cm" fo:margin-bottom="0.4cm"/></style:header-style><style:footer-style><style:header-footer-properties fo:min-height="0.5cm" fo:margin-top="0.4cm"/></style:footer-style></style:page-layout>
<style:style style:name="Sect1" style:family="section"><style:section-properties text:dont-balance-text-columns="false" style:editable="false"><style:columns fo:column-count="0" fo:column-gap="0cm"/></style:section-properties></style:style>
<style:style style:name="Sect2" style:family="section"><style:section-properties text:dont-balance-text-columns="false" style:editable="false"><style:columns fo:column-count="2" fo:column-gap="0.8cm"><style:column-sep style:width="0.5pt" style:color="#999999" style:height="100%"/><style:column style:rel-width="1*" fo:start-indent="0cm" fo:end-indent="0.4cm"/><style:column style:rel-width="1*" fo:start-indent="0.4cm" fo:end-indent="0cm"/></style:columns></style:section-properties></style:style>
<style:style style:name="Tbl1" style:family="table"><style:table-properties style:width="14cm" table:align="left" fo:margin-top="0.2cm" fo:margin-bottom="0.3cm"/></style:style>
<style:style style:name="TblWide" style:family="table"><style:table-properties style:width="24.5cm" table:align="left"/></style:style>
<style:style style:name="TcolA" style:family="table-column"><style:table-column-properties style:column-width="4.5cm"/></style:style>
<style:style style:name="TcolB" style:family="table-column"><style:table-column-properties style:column-width="3cm"/></style:style>
<style:style style:name="TcolC" style:family="table-column"><style:table-column-properties style:column-width="3.5cm"/></style:style>
<style:style style:name="TcolD" style:family="table-column"><style:table-column-properties style:column-width="3cm"/></style:style>
<style:style style:name="TcolW" style:family="table-column"><style:table-column-properties style:column-width="2.04cm"/></style:style>
<style:style style:name="Tc" style:family="table-cell"><style:table-cell-properties fo:padding="0.1cm" fo:border="0.5pt solid #8aa6b4"/></style:style>
<style:style style:name="TcR" style:family="table-cell"><style:table-cell-properties fo:padding="0.1cm" fo:border="0.5pt solid #8aa6b4"/></style:style>
<style:style style:name="Th" style:family="table-cell"><style:table-cell-properties fo:padding="0.1cm" fo:background-color="#0b4f6c" fo:border="0.5pt solid #8aa6b4"/></style:style>
<style:style style:name="TcTotal" style:family="table-cell"><style:table-cell-properties fo:padding="0.1cm" fo:background-color="#e8f1f5" fo:border="0.5pt solid #8aa6b4" fo:border-top="1.5pt solid #000000"/></style:style>
<style:style style:name="TcTotalR" style:family="table-cell"><style:table-cell-properties fo:padding="0.1cm" fo:background-color="#e8f1f5" fo:border="0.5pt solid #8aa6b4" fo:border-top="1.5pt solid #000000"/></style:style>
</office:automatic-styles>
<office:master-styles>
<style:master-page style:name="Standard" style:page-layout-name="pm1"><style:header><text:p text:style-name="Header">Harbour handbook<text:tab/><text:tab/>exav demo</text:p></style:header><style:footer><text:p text:style-name="Footer">Page <text:page-number text:select-page="current">1</text:page-number> of <text:page-count>1</text:page-count></text:p></style:footer></style:master-page>
<style:master-page style:name="Landscape" style:page-layout-name="pm2"><style:header><text:p text:style-name="Header">Harbour handbook (landscape section)</text:p></style:header><style:footer><text:p text:style-name="Footer">Page <text:page-number text:select-page="current">1</text:page-number></text:p></style:footer></style:master-page>
</office:master-styles>
<office:body><office:text>
<text:tracked-changes text:track-changes="false">
<text:changed-region text:id="ct1"><text:insertion><office:change-info><dc:creator>exav</dc:creator><dc:date>2000-01-01T00:00:00</dc:date></office:change-info></text:insertion></text:changed-region>
<text:changed-region text:id="ct2"><text:deletion><office:change-info><dc:creator>exav</dc:creator><dc:date>2000-01-01T00:00:00</dc:date></office:change-info><text:p text:style-name="Text_20_body">some deleted words </text:p></text:deletion></text:changed-region>
</text:tracked-changes>
{"".join(body)}
</office:text></office:body>
</office:document>
"""


# ======================================================================
# The workbook (spreadsheet)
# ======================================================================


def chart(kind, title, ranges, cats, series, width="15cm", height="8.5cm", legend=True):
    """An embedded chart object. series: [(name cell, values range)]; ranges: the whole data range."""
    ser = "".join(
        f'<chart:series chart:values-cell-range-address="{v}" chart:label-cell-address="{n}" chart:class="chart:{kind}" chart:style-name="chs{i}"><chart:data-point chart:repeated="1"/></chart:series>'
        for i, (n, v) in enumerate(series)
    )
    styles = "".join(
        f'<style:style style:name="chs{i}" style:family="chart"><style:graphic-properties draw:stroke="{"solid" if kind == "line" else "none"}" svg:stroke-color="{c}" draw:fill-color="{c}"/></style:style>'
        for i, c in enumerate(["#146c94", "#f6a01a", "#2c7a4b", "#c0392b"])
    )
    pie_styles = ""
    if kind == "circle":
        pie_styles = "".join(f'<style:style style:name="pt{i}" style:family="chart"><style:graphic-properties draw:fill-color="{c}"/></style:style>' for i, c in enumerate(["#146c94", "#f6a01a", "#2c7a4b", "#c0392b", "#8e44ad"]))
        ser = ser.replace('<chart:data-point chart:repeated="1"/>', "".join(f'<chart:data-point chart:style-name="pt{i}"/>' for i in range(5)))
    axes = (
        f'<chart:axis chart:dimension="x" chart:name="primary-x"><chart:categories table:cell-range-address="{cats}"/></chart:axis><chart:axis chart:dimension="y" chart:name="primary-y"><chart:grid chart:class="major"/></chart:axis>'
        if kind != "circle"
        else ""
    )
    return f"""<draw:object><office:document office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.chart"><office:automatic-styles>{styles}{pie_styles}</office:automatic-styles><office:body><office:chart>
<chart:chart chart:class="chart:{kind}" svg:width="{width}" svg:height="{height}"><chart:title><text:p>{t(title)}</text:p></chart:title>{'<chart:legend chart:legend-position="end"/>' if legend else ""}
<chart:plot-area table:cell-range-address="{ranges}" chart:data-source-has-labels="both">{axes}{ser}</chart:plot-area></chart:chart></office:chart></office:body></office:document></draw:object>"""


def workbook_fods():
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
    cats = ["Berths let", "Visitors", "Shop", "Fuel", "Repairs"]
    values = [[11200, 11800, 12100, 15400, 21800, 24900], [3100, 3300, 4800, 8200, 15600, 19200], [1200, 1100, 1500, 2600, 4100, 5200], [900, 800, 1100, 1900, 3300, 4400], [-2100, -900, -3300, -1500, -800, -1200]]

    def fcell(v, style=None):
        return f'<table:table-cell{f" table:style-name={quoteattr(style)}" if style else ""} office:value-type="float" office:value="{v}"><text:p>{v}</text:p></table:table-cell>'

    def scell(s, style=None, extra=""):
        return f'<table:table-cell{f" table:style-name={quoteattr(style)}" if style else ""}{extra} office:value-type="string"><text:p>{t(s)}</text:p></table:table-cell>'

    def fm(formula, style=None, value=None, vtype="float"):
        key = "office:string-value" if vtype == "string" else "office:value"
        v = f' office:value-type="{vtype}"' + (f' {key}="{value}"' if value is not None else "")
        return f'<table:table-cell{f" table:style-name={quoteattr(style)}" if style else ""} table:formula={quoteattr(formula)}{v}><text:p>{value if value is not None else ""}</text:p></table:table-cell>'

    # Sheet 1: Budget (rows 1 title, 2 note, 3 header, 4-8 data, 9 total, then a lookup block).
    rows = []
    rows.append('<table:table-row table:style-name="ro-title">' + scell("Harbour budget, first half", "title", ' table:number-columns-spanned="9" table:number-rows-spanned="1"') + "<table:covered-table-cell/>" * 8 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Amounts in euros; the totals are formulas.", "note") + "<table:table-cell/>" * 8 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Category", "head") + "".join(scell(m, "head") for m in months) + scell("Total", "head") + scell("Share", "head") + "</table:table-row>")
    # Every formula carries the value it gives, as a spreadsheet saves it.
    grand = sum(sum(v) for v in values)
    nets = [sum(v[i] for v in values) for i in range(6)]
    for i, (name, vals) in enumerate(zip(cats, values)):
        r = 4 + i
        total = sum(vals)
        rows.append(
            "<table:table-row>" + scell(name, "label") + "".join(fcell(v, "eur") for v in vals)
            + fm(f"of:=SUM([.B{r}:.G{r}])", "eurb", total) + fm(f"of:=[.H{r}]/[.H$9]", "pct", total / grand) + "</table:table-row>"
        )
    rows.append(
        "<table:table-row>" + scell("Net", "labelb") + "".join(fm(f"of:=SUM([.{c}4:.{c}8])", "eurtot", nets[i]) for i, c in enumerate("BCDEFG")) + fm("of:=SUM([.H4:.H8])", "eurtot", grand) + fm("of:=SUM([.I4:.I8])", "pcttot", 1) + "</table:table-row>"
    )
    rows.append("<table:table-row>" + "<table:table-cell/>" * 9 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Averages and checks", "labelb") + "<table:table-cell/>" * 8 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Average a month", "label") + fm("of:=AVERAGE([.B9:.G9])", "eur", grand / 6) + scell("Best month", "label") + fm("of:=INDEX([.B3:.G3];MATCH(MAX([.B9:.G9]);[.B9:.G9];0))", None, months[nets.index(max(nets))], "string") + scell("Months in credit", "label") + fm("of:=COUNTIF([.B9:.G9];\">0\")", None, sum(1 for n in nets if n > 0)) + "<table:table-cell/>" * 3 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Largest item", "label") + fm("of:=MAX([.B4:.G8])", "eur", max(max(v) for v in values)) + scell("Rounded share of fuel", "label") + fm("of:=ROUND([.I7];3)", "pct", round(sum(values[3]) / grand, 3)) + scell("Status", "label") + fm('of:=IF([.H9]>0;"surplus";"deficit")', None, "surplus" if grand > 0 else "deficit", "string") + "<table:table-cell/>" * 3 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Lookup: category", "label") + scell("Shop", "input") + scell("its total", "label") + fm("of:=VLOOKUP([.B14];[.A4:.H8];8;0)", "eur", sum(values[2])) + "<table:table-cell/>" * 5 + "</table:table-row>")
    rows.append("<table:table-row>" + scell("Link", "label") + '<table:table-cell office:value-type="string"><text:p><text:a xlink:href="https://exav.org/viewer/" xlink:type="simple">exav.org/viewer</text:a></text:p></table:table-cell>' + scell("Note on a cell", "label") + '<table:table-cell office:value-type="string"><office:annotation><dc:creator>exav</dc:creator><text:p>This cell has a comment.</text:p></office:annotation><text:p>hover me</text:p></table:table-cell>' + "<table:table-cell/>" * 5 + "</table:table-row>")
    budget_cols = '<table:table-column table:style-name="co-a"/><table:table-column table:style-name="co-n" table:number-columns-repeated="6"/><table:table-column table:style-name="co-t"/><table:table-column table:style-name="co-p"/>'
    budget = '<table:table table:name="Budget" table:style-name="ta1">' + budget_cols + "".join(rows) + "</table:table>"

    # Sheet 2: Data, 120 rows, with an autofilter.
    rng = np.random.default_rng(3)
    regions, products = ["West", "East", "North", "South"], ["Mooring", "Fuel", "Water", "Power", "Shop"]
    drows = ["<table:table-row>" + "".join(scell(h, "head") for h in ["Date", "Region", "Product", "Units", "Unit price", "Amount"]) + "</table:table-row>"]
    units_sum, amount_sum = 0, 0.0
    for i in range(120):
        day = 1 + i * 150 // 120
        month, dd = 1 + (day - 1) // 28, 1 + (day - 1) % 28
        units = int(rng.integers(1, 40))
        price = round(float(rng.uniform(2, 60)), 2)
        units_sum += units
        amount_sum += round(units * price, 2)
        r = i + 2
        drows.append(
            "<table:table-row>"
            f'<table:table-cell table:style-name="date" office:value-type="date" office:date-value="2000-{month:02d}-{dd:02d}"><text:p>{dd:02d}/{month:02d}/2000</text:p></table:table-cell>'
            + scell(regions[i % 4]) + scell(products[(i * 3) % 5]) + fcell(units) + fcell(price, "eur2") + fm(f"of:=[.D{r}]*[.E{r}]", "eur2", round(units * price, 2)) + "</table:table-row>"
        )
    drows.append("<table:table-row>" + scell("Total", "labelb") + "<table:table-cell/>" * 2 + fm("of:=SUM([.D2:.D121])", "eurtot", units_sum) + "<table:table-cell/>" + fm("of:=SUBTOTAL(9;[.F2:.F121])", "eurtot", round(amount_sum, 2)) + "</table:table-row>")
    data = (
        '<table:table table:name="Data" table:style-name="ta1"><table:table-column table:style-name="co-d"/><table:table-column table:style-name="co-n" table:number-columns-repeated="5"/>'
        + "".join(drows) + "</table:table>"
    )

    # Sheet 3: Charts.
    c1 = chart("bar", "Spending by category", "Budget.$A$3:.$G$7", "Budget.$A$4:.$A$7", [("Budget.$B$3", "Budget.$B$4:.$B$7"), ("Budget.$G$3", "Budget.$G$4:.$G$7")])
    c2 = chart("line", "Net income by month", "Budget.$A$3:.$G$3", "Budget.$B$3:.$G$3", [("Budget.$A$9", "Budget.$B$9:.$G$9")])
    c3 = chart("circle", "Share of the total", "Budget.$A$4:.$A$8", "Budget.$A$4:.$A$8", [("Budget.$I$3", "Budget.$I$4:.$I$8")])
    charts = (
        '<table:table table:name="Charts" table:style-name="ta1"><table:shapes>'
        f'<draw:frame draw:style-name="gr1" draw:name="Bar chart" table:end-cell-address="Charts.H19" table:end-x="0.3cm" table:end-y="0.3cm" svg:width="14cm" svg:height="8cm" svg:x="0.5cm" svg:y="0.5cm">{c1}</draw:frame>'
        f'<draw:frame draw:style-name="gr1" draw:name="Line chart" table:end-cell-address="Charts.P19" table:end-x="0.3cm" table:end-y="0.3cm" svg:width="14cm" svg:height="8cm" svg:x="15cm" svg:y="0.5cm">{c2}</draw:frame>'
        f'<draw:frame draw:style-name="gr1" draw:name="Pie chart" table:end-cell-address="Charts.H38" table:end-x="0.3cm" table:end-y="0.3cm" svg:width="14cm" svg:height="8cm" svg:x="0.5cm" svg:y="9cm">{c3}</draw:frame>'
        '</table:shapes><table:table-column/><table:table-row><table:table-cell office:value-type="string"><text:p/></table:table-cell></table:table-row></table:table>'
    )

    settings = """<office:settings><config:config-item-set config:name="ooo:view-settings"><config:config-item-map-indexed config:name="Views"><config:config-item-map-entry>
<config:config-item config:name="ViewId" config:type="string">view1</config:config-item>
<config:config-item-map-named config:name="Tables"><config:config-item-map-entry config:name="Budget">
<config:config-item config:name="HorizontalSplitMode" config:type="short">0</config:config-item><config:config-item config:name="VerticalSplitMode" config:type="short">2</config:config-item>
<config:config-item config:name="VerticalSplitPosition" config:type="int">3</config:config-item><config:config-item config:name="PositionBottom" config:type="int">3</config:config-item>
</config:config-item-map-entry><config:config-item-map-entry config:name="Data">
<config:config-item config:name="HorizontalSplitMode" config:type="short">0</config:config-item><config:config-item config:name="VerticalSplitMode" config:type="short">2</config:config-item>
<config:config-item config:name="VerticalSplitPosition" config:type="int">1</config:config-item><config:config-item config:name="PositionBottom" config:type="int">1</config:config-item>
</config:config-item-map-entry></config:config-item-map-named></config:config-item-map-entry></config:config-item-map-indexed></config:config-item-set></office:settings>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document {NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.spreadsheet">
<office:meta><meta:initial-creator>exav project</meta:initial-creator><dc:title>Harbour workbook</dc:title><dc:subject>A workbook made for the exav demo (CC0-1.0)</dc:subject><meta:creation-date>2000-01-01T00:00:00</meta:creation-date></office:meta>
{settings}
<office:font-face-decls><style:font-face style:name="Liberation Sans" svg:font-family="'Liberation Sans'" style:font-family-generic="swiss"/></office:font-face-decls>
<office:styles>
<style:default-style style:family="table-cell"><style:text-properties style:font-name="Liberation Sans" fo:font-size="10pt"/></style:default-style>
<number:currency-style style:name="NEUR"><number:currency-symbol number:language="en" number:country="IE">€</number:currency-symbol><number:number number:decimal-places="0" number:min-integer-digits="1" number:grouping="true"/></number:currency-style>
<number:currency-style style:name="NEUR2"><number:currency-symbol number:language="en" number:country="IE">€</number:currency-symbol><number:number number:decimal-places="2" number:min-integer-digits="1" number:grouping="true"/></number:currency-style>
<number:percentage-style style:name="NPCT"><number:number number:decimal-places="1" number:min-integer-digits="1"/><number:text>%</number:text></number:percentage-style>
<number:date-style style:name="NDATE"><number:day number:style="long"/><number:text>/</number:text><number:month number:style="long"/><number:text>/</number:text><number:year number:style="long"/></number:date-style>
<style:style style:name="Default" style:family="table-cell"/>
<style:style style:name="title" style:family="table-cell"><style:table-cell-properties fo:background-color="#0b4f6c" style:vertical-align="middle"/><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="16pt" fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="note" style:family="table-cell"><style:text-properties fo:font-style="italic" fo:color="#666666"/></style:style>
<style:style style:name="head" style:family="table-cell"><style:table-cell-properties fo:background-color="#146c94" fo:border-bottom="1.5pt solid #000000"/><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="label" style:family="table-cell"><style:table-cell-properties fo:border-bottom="0.5pt solid #cccccc"/></style:style>
<style:style style:name="labelb" style:family="table-cell"><style:table-cell-properties fo:border-top="1.5pt solid #000000"/><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="input" style:family="table-cell"><style:table-cell-properties fo:background-color="#fff6cc" fo:border="0.5pt solid #d6b656"/></style:style>
<style:style style:name="eur" style:family="table-cell" style:data-style-name="NEUR"><style:table-cell-properties fo:border-bottom="0.5pt solid #cccccc"/></style:style>
<style:style style:name="eurb" style:family="table-cell" style:data-style-name="NEUR"><style:table-cell-properties fo:background-color="#e8f1f5" fo:border-bottom="0.5pt solid #cccccc"/><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="eurtot" style:family="table-cell" style:data-style-name="NEUR"><style:table-cell-properties fo:background-color="#e8f1f5" fo:border-top="1.5pt solid #000000"/><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="eur2" style:family="table-cell" style:data-style-name="NEUR2"/>
<style:style style:name="pct" style:family="table-cell" style:data-style-name="NPCT"><style:table-cell-properties fo:border-bottom="0.5pt solid #cccccc"/></style:style>
<style:style style:name="pcttot" style:family="table-cell" style:data-style-name="NPCT"><style:table-cell-properties fo:background-color="#e8f1f5" fo:border-top="1.5pt solid #000000"/><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="date" style:family="table-cell" style:data-style-name="NDATE"/>
<style:style style:name="bad" style:family="table-cell"><style:table-cell-properties fo:background-color="#f8d7da"/><style:text-properties fo:color="#842029"/></style:style>
<style:style style:name="good" style:family="table-cell"><style:table-cell-properties fo:background-color="#d1e7dd"/><style:text-properties fo:color="#0f5132"/></style:style>
</office:styles>
<office:automatic-styles>
<style:style style:name="co-a" style:family="table-column"><style:table-column-properties style:column-width="4.2cm"/></style:style>
<style:style style:name="co-n" style:family="table-column"><style:table-column-properties style:column-width="2.4cm"/></style:style>
<style:style style:name="co-t" style:family="table-column"><style:table-column-properties style:column-width="2.8cm"/></style:style>
<style:style style:name="co-p" style:family="table-column"><style:table-column-properties style:column-width="2cm"/></style:style>
<style:style style:name="co-d" style:family="table-column"><style:table-column-properties style:column-width="2.6cm"/></style:style>
<style:style style:name="ro-title" style:family="table-row"><style:table-row-properties style:row-height="1.1cm"/></style:style>
<style:style style:name="ta1" style:family="table" style:master-page-name="Default"><style:table-properties table:display="true" style:writing-mode="lr-tb"/></style:style>
<style:style style:name="gr1" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="none"/></style:style>
</office:automatic-styles>
<office:master-styles><style:master-page style:name="Default" style:page-layout-name="pm1"/></office:master-styles>
<office:body><office:spreadsheet>
<table:content-validations><table:content-validation table:name="val1" table:condition="of:cell-content-is-in-list(&quot;Berths let&quot;;&quot;Visitors&quot;;&quot;Shop&quot;;&quot;Fuel&quot;;&quot;Repairs&quot;)" table:allow-empty-cell="true" table:display-list="unsorted" table:base-cell-address="Budget.B14"><table:error-message table:display="true" table:message-type="stop" table:title="Not a category">Choose one of the five categories.</table:error-message></table:content-validation></table:content-validations>
{budget.replace('<table:table-cell table:style-name="input" office:value-type="string"><text:p>Shop</text:p>', '<table:table-cell table:style-name="input" table:content-validation-name="val1" office:value-type="string"><text:p>Shop</text:p>')}
{data}
{charts}
<table:named-expressions><table:named-range table:name="Spending" table:base-cell-address="$Budget.$B$4" table:cell-range-address="$Budget.$B$4:.$G$8"/><table:named-range table:name="NetByMonth" table:base-cell-address="$Budget.$B$9" table:cell-range-address="$Budget.$B$9:.$G$9"/></table:named-expressions>
<table:database-ranges><table:database-range table:name="SalesData" table:target-range-address="Data.A1:.F121" table:display-filter-buttons="true" table:contains-header="true"/></table:database-ranges>
</office:spreadsheet></office:body>
</office:document>
"""


# ======================================================================
# The deck (presentation)
# ======================================================================


def deck_fodp():
    pic = picture(800, 450, 2, "Slide picture")
    c = chart("bar", "Berths let by month", "local-table.$A$1:.$C$7", "local-table.$A$2:.$A$7", [("local-table.$B$1", "local-table.$B$2:.$B$7"), ("local-table.$C$1", "local-table.$C$2:.$C$7")])
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]
    local = '<table:table table:name="local-table"><table:table-header-columns><table:table-column/></table:table-header-columns><table:table-columns><table:table-column table:number-columns-repeated="2"/></table:table-columns><table:table-header-rows><table:table-row><table:table-cell><text:p/></table:table-cell><table:table-cell office:value-type="string"><text:p>This year</text:p></table:table-cell><table:table-cell office:value-type="string"><text:p>Last year</text:p></table:table-cell></table:table-row></table:table-header-rows><table:table-rows>'
    for i, m in enumerate(months):
        local += f'<table:table-row><table:table-cell office:value-type="string"><text:p>{m}</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="{20 + i * 6}"><text:p>{20 + i * 6}</text:p></table:table-cell><table:table-cell office:value-type="float" office:value="{18 + i * 5}"><text:p>{18 + i * 5}</text:p></table:table-cell></table:table-row>'
    local += "</table:table-rows></table:table>"
    c = c.replace("</chart:chart>", local + "</chart:chart>")

    def title(text, y="0.8cm"):
        return f'<draw:frame presentation:style-name="pr-title" draw:layer="layout" svg:width="24cm" svg:height="2.4cm" svg:x="2cm" svg:y="{y}" presentation:class="title" presentation:user-transformed="true"><draw:text-box><text:p text:style-name="P-title">{t(text)}</text:p></draw:text-box></draw:frame>'

    def bullets(items, y="3.8cm", w="24cm", h="10cm", x="2cm"):
        def li(it, lv=1):
            if isinstance(it, list):
                return "<text:list-item><text:list>" + "".join(li(i, lv + 1) for i in it) + "</text:list></text:list-item>"
            return f'<text:list-item><text:p text:style-name="P-body">{t(it)}</text:p></text:list-item>'

        return f'<draw:frame presentation:style-name="pr-body" draw:layer="layout" svg:width="{w}" svg:height="{h}" svg:x="{x}" svg:y="{y}" presentation:class="outline"><draw:text-box><text:list text:style-name="L-bul">' + "".join(li(i) for i in items) + "</text:list></draw:text-box></draw:frame>"

    def notes(text):
        return f'<presentation:notes><draw:page-thumbnail presentation:class="page" draw:layer="layout" svg:width="14.8cm" svg:height="8.3cm" svg:x="3.2cm" svg:y="2cm"/><draw:frame presentation:class="notes" draw:layer="layout" svg:width="17cm" svg:height="12cm" svg:x="2cm" svg:y="11cm"><draw:text-box><text:p>{t(text)}</text:p></draw:text-box></draw:frame></presentation:notes>'

    slides = []
    slides.append(
        f'<draw:page draw:name="Title" draw:style-name="dp-title" draw:master-page-name="Master" presentation:presentation-page-layout-name="AL1">'
        f'<draw:frame presentation:style-name="pr-title" draw:layer="layout" svg:width="24cm" svg:height="3cm" svg:x="2cm" svg:y="4.5cm" presentation:class="title" presentation:user-transformed="true"><draw:text-box><text:p text:style-name="P-big">Harbour review</text:p></draw:text-box></draw:frame>'
        f'<draw:frame presentation:style-name="pr-body" draw:layer="layout" svg:width="24cm" svg:height="2cm" svg:x="2cm" svg:y="8cm" presentation:class="subtitle"><draw:text-box><text:p text:style-name="P-sub">The east quay, first half of the year</text:p></draw:text-box></draw:frame>'
        f'<draw:ellipse draw:style-name="gr-grad" draw:layer="layout" svg:width="5.5cm" svg:height="5.5cm" svg:x="20cm" svg:y="8.2cm"><text:p text:style-name="P-white">exav</text:p></draw:ellipse>'
        f'{notes("Welcome. These notes are speaker notes: the viewer does not show them.")}</draw:page>'
    )
    slides.append(
        f'<draw:page draw:name="Agenda" draw:style-name="dp-plain" draw:master-page-name="Master" presentation:presentation-page-layout-name="AL2">{title("Agenda")}'
        + bullets(["Where we are", ["berths let", ["by length", "by season"], "visitors"], "What the figures say", "What we do next", ["order the new chain", "paint the numbers"]])
        + notes("Four items.") + "</draw:page>"
    )
    slides.append(
        f'<draw:page draw:name="Chart" draw:style-name="dp-plain" draw:master-page-name="Master" presentation:presentation-page-layout-name="AL2">{title("Berths let, month by month")}'
        f'<draw:frame draw:style-name="gr-none" draw:layer="layout" svg:width="19cm" svg:height="11cm" svg:x="2cm" svg:y="3.6cm">{c}</draw:frame>'
        '<draw:custom-shape draw:style-name="gr-callout" draw:layer="layout" svg:width="5.5cm" svg:height="3cm" svg:x="21.5cm" svg:y="5cm"><text:p text:style-name="P-center">Up 40% on last year</text:p>'
        '<draw:enhanced-geometry svg:viewBox="0 0 21600 21600" draw:type="round-rectangular-callout" draw:enhanced-path="M 3590 0 X 0 3590 L 0 14370 Y 3590 17960 L 7200 17960 L 5400 21600 L 10800 17960 L 18010 17960 X 21600 14370 L 21600 3590 Y 18010 0 Z N"/></draw:custom-shape>'
        + notes("The chart is a native chart, with its data inside the slide.") + "</draw:page>"
    )
    rows = ""
    for r in [("Length", "Berths", "Fee"), ("up to 6 m", "12", "18.00"), ("6 to 8 m", "18", "24.50"), ("8 to 10 m", "14", "31.00"), ("over 10 m", "16", "48.00")]:
        head = r[0] == "Length"
        rows += "<table:table-row>" + "".join(f'<table:table-cell table:style-name="{"tc-head" if head else "tc"}" office:value-type="string"><text:p text:style-name="{"P-th" if head else "P-td"}">{t(v)}</text:p></table:table-cell>' for v in r) + "</table:table-row>"
    slides.append(
        f'<draw:page draw:name="Table" draw:style-name="dp-plain" draw:master-page-name="Master" presentation:presentation-page-layout-name="AL2">{title("Fees")}'
        '<draw:frame draw:layer="layout" svg:width="16cm" svg:height="8cm" svg:x="2cm" svg:y="4cm"><table:table table:style-name="tb1"><table:table-column table:style-name="tcol1"/><table:table-column table:style-name="tcol2"/><table:table-column table:style-name="tcol2"/>'
        f"{rows}</table:table></draw:frame>"
        + bullets(["Season fee includes water", "Power is metered", "Visitors pay by the night"], y="4cm", w="8cm", h="8cm", x="19cm") + "</draw:page>"
    )
    slides.append(
        f'<draw:page draw:name="Picture" draw:style-name="dp-plain" draw:master-page-name="Master" presentation:presentation-page-layout-name="AL2">{title("A picture and shapes")}'
        f'<draw:frame draw:layer="layout" svg:width="12.8cm" svg:height="7.2cm" svg:x="2cm" svg:y="4cm"><draw:image><office:binary-data>{png_b64(pic)}</office:binary-data></draw:image><svg:title>A lake at dusk</svg:title></draw:frame>'
        '<draw:rect draw:style-name="gr-grad" draw:layer="layout" svg:width="4cm" svg:height="2.4cm" svg:x="16cm" svg:y="4cm"><text:p text:style-name="P-center">Start</text:p></draw:rect>'
        '<draw:line draw:style-name="gr-arrow" draw:layer="layout" svg:x1="20cm" svg:y1="5.2cm" svg:x2="22.5cm" svg:y2="5.2cm"/>'
        '<draw:ellipse draw:style-name="gr-fill2" draw:layer="layout" svg:width="3.4cm" svg:height="2.4cm" svg:x="22.8cm" svg:y="4cm"><text:p text:style-name="P-center">Moor</text:p></draw:ellipse>'
        '<draw:line draw:style-name="gr-arrow" draw:layer="layout" svg:x1="24.5cm" svg:y1="6.4cm" svg:x2="24.5cm" svg:y2="8.4cm"/>'
        '<draw:polygon draw:style-name="gr-fill3" draw:layer="layout" svg:width="4cm" svg:height="3cm" svg:x="22.5cm" svg:y="8.5cm" svg:viewBox="0 0 4000 3000" draw:points="2000,0 4000,1500 2000,3000 0,1500"><text:p text:style-name="P-center">Pay?</text:p></draw:polygon>'
        '<draw:custom-shape draw:style-name="gr-fill4" draw:layer="layout" svg:width="4cm" svg:height="3cm" svg:x="16.5cm" svg:y="8.5cm"><text:p text:style-name="P-center">Star</text:p><draw:enhanced-geometry svg:viewBox="0 0 21600 21600" draw:type="star5" draw:enhanced-path="M 10800 0 L 8270 8260 0 8260 6720 13360 4200 21600 10800 16500 17400 21600 14880 13360 21600 8260 13330 8260 Z N"/></draw:custom-shape>'
        + notes("Shapes with gradients, arrows and text.") + "</draw:page>"
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document {NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.presentation">
<office:meta><meta:initial-creator>exav project</meta:initial-creator><dc:title>Harbour review</dc:title><dc:subject>A deck made for the exav demo (CC0-1.0)</dc:subject><meta:creation-date>2000-01-01T00:00:00</meta:creation-date></office:meta>
<office:font-face-decls><style:font-face style:name="Liberation Sans" svg:font-family="'Liberation Sans'" style:font-family-generic="swiss"/></office:font-face-decls>
<office:styles>
<draw:gradient draw:name="Sea" draw:style="linear" draw:start-color="#0b4f6c" draw:end-color="#3fa7d6" draw:start-intensity="100%" draw:end-intensity="100%" draw:angle="30deg" draw:border="0%"/>
<draw:gradient draw:name="Sun" draw:style="radial" draw:cx="50%" draw:cy="50%" draw:start-color="#f6a01a" draw:end-color="#c0392b" draw:start-intensity="100%" draw:end-intensity="100%" draw:border="0%"/>
<draw:marker draw:name="Arrow" svg:viewBox="0 0 20 30" svg:d="m10 0-10 30h20z"/>
<style:style style:name="standard" style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-color="#3465a4" draw:fill="solid" draw:fill-color="#729fcf"/><style:text-properties style:font-name="Liberation Sans" fo:font-size="18pt"/></style:style>
<style:style style:name="pr-title" style:family="presentation"><style:graphic-properties draw:stroke="none" draw:fill="none" draw:auto-grow-height="false" draw:auto-grow-width="false" draw:textarea-vertical-align="middle"/></style:style>
<style:style style:name="pr-body" style:family="presentation"><style:graphic-properties draw:stroke="none" draw:fill="none" draw:auto-grow-height="false" draw:auto-grow-width="false"/></style:style>
</office:styles>
<office:automatic-styles>
<style:page-layout style:name="pm1"><style:page-layout-properties fo:margin-top="0cm" fo:margin-bottom="0cm" fo:margin-left="0cm" fo:margin-right="0cm" fo:page-width="28cm" fo:page-height="15.75cm" style:print-orientation="landscape"/></style:page-layout>
<style:style style:name="dp-title" style:family="drawing-page"><style:drawing-page-properties presentation:background-visible="true" presentation:background-objects-visible="true" draw:fill="gradient" draw:fill-gradient-name="Sea" presentation:transition-type="automatic" presentation:transition-style="fade-from-center" presentation:duration="PT00H00M01S" smil:type="fade"/></style:style>
<style:style style:name="dp-plain" style:family="drawing-page"><style:drawing-page-properties presentation:background-visible="true" presentation:background-objects-visible="true" draw:fill="solid" draw:fill-color="#fbfaf7" smil:type="slideWipe" smil:subtype="fromLeft"/></style:style>
<style:style style:name="gr-none" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="none"/></style:style>
<style:style style:name="gr-grad" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="gradient" draw:fill-gradient-name="Sea" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/><style:text-properties fo:color="#ffffff"/></style:style>
<style:style style:name="gr-fill2" style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-color="#1c6e3e" svg:stroke-width="0.08cm" draw:fill="solid" draw:fill-color="#7bc67e" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="gr-fill3" style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-color="#7a5c00" draw:stroke-dash="dash" draw:fill="solid" draw:fill-color="#ffe08a" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="gr-fill4" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="gradient" draw:fill-gradient-name="Sun" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/><style:text-properties fo:color="#ffffff"/></style:style>
<style:style style:name="gr-arrow" style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-width="0.1cm" svg:stroke-color="#333333" draw:marker-end="Arrow" draw:marker-end-width="0.3cm"/></style:style>
<style:style style:name="gr-callout" style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-color="#c0392b" draw:fill="solid" draw:fill-color="#fdecea" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="P-title" style:family="paragraph"><style:paragraph-properties fo:text-align="start"/><style:text-properties fo:font-size="30pt" fo:font-weight="bold" fo:color="#0b4f6c"/></style:style>
<style:style style:name="P-big" style:family="paragraph"><style:text-properties fo:font-size="48pt" fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="P-sub" style:family="paragraph"><style:text-properties fo:font-size="24pt" fo:color="#dbe9f4"/></style:style>
<style:style style:name="P-body" style:family="paragraph"><style:text-properties fo:font-size="22pt"/></style:style>
<style:style style:name="P-center" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="16pt"/></style:style>
<style:style style:name="P-white" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="20pt" fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="P-th" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="16pt" fo:font-weight="bold" fo:color="#ffffff"/></style:style>
<style:style style:name="P-td" style:family="paragraph"><style:text-properties fo:font-size="16pt"/></style:style>
<text:list-style style:name="L-bul"><text:list-level-style-bullet text:level="1" text:bullet-char="●"><style:list-level-properties text:min-label-width="0.6cm"/><style:text-properties fo:color="#146c94"/></text:list-level-style-bullet><text:list-level-style-bullet text:level="2" text:bullet-char="–"><style:list-level-properties text:space-before="0.8cm" text:min-label-width="0.6cm"/></text:list-level-style-bullet><text:list-level-style-bullet text:level="3" text:bullet-char="•"><style:list-level-properties text:space-before="1.6cm" text:min-label-width="0.6cm"/></text:list-level-style-bullet></text:list-style>
<style:style style:name="tb1" style:family="table"><style:table-properties style:width="16cm" table:align="left"/></style:style>
<style:style style:name="tcol1" style:family="table-column"><style:table-column-properties style:column-width="6cm"/></style:style>
<style:style style:name="tcol2" style:family="table-column"><style:table-column-properties style:column-width="5cm"/></style:style>
<style:style style:name="tc" style:family="table-cell"><style:table-cell-properties fo:padding="0.15cm" fo:border="0.5pt solid #8aa6b4" fo:background-color="#ffffff"/></style:style>
<style:style style:name="tc-head" style:family="table-cell"><style:table-cell-properties fo:padding="0.15cm" fo:border="0.5pt solid #8aa6b4" fo:background-color="#0b4f6c"/></style:style>
<presentation:presentation-page-layout style:name="AL1"/>
<presentation:presentation-page-layout style:name="AL2"/>
</office:automatic-styles>
<office:master-styles>
<draw:layer-set><draw:layer draw:name="layout"/><draw:layer draw:name="background"/><draw:layer draw:name="backgroundobjects"/></draw:layer-set>
<style:master-page style:name="Master" style:page-layout-name="pm1" draw:style-name="dp-plain">
<draw:rect draw:style-name="gr-grad" draw:layer="backgroundobjects" svg:width="28cm" svg:height="0.5cm" svg:x="0cm" svg:y="15.25cm"/>
<draw:frame presentation:style-name="pr-body" draw:layer="backgroundobjects" svg:width="12cm" svg:height="0.9cm" svg:x="1cm" svg:y="14.2cm" presentation:class="footer"><draw:text-box><text:p><presentation:footer/></text:p></draw:text-box></draw:frame>
<draw:frame presentation:style-name="pr-body" draw:layer="backgroundobjects" svg:width="3cm" svg:height="0.9cm" svg:x="24cm" svg:y="14.2cm" presentation:class="page-number"><draw:text-box><text:p><text:page-number>1</text:page-number></text:p></draw:text-box></draw:frame>
</style:master-page>
</office:master-styles>
<office:body><office:presentation>
{"".join(slides)}
<presentation:settings presentation:full-screen="false"/>
</office:presentation></office:body>
</office:document>
"""


# ======================================================================
# The diagram (drawing)
# ======================================================================


def diagram_fodg():
    def node(i, x, y, w, h, text, style="st-box", shape="rect"):
        tag = "draw:rect" if shape == "rect" else "draw:ellipse"
        return f'<{tag} draw:id="n{i}" draw:style-name="{style}" draw:layer="Boxes" svg:width="{w}cm" svg:height="{h}cm" svg:x="{x}cm" svg:y="{y}cm" draw:corner-radius="0.2cm"><text:p text:style-name="P-c">{t(text)}</text:p></{tag}>' if shape == "rect" else f'<{tag} draw:id="n{i}" draw:style-name="{style}" draw:layer="Boxes" svg:width="{w}cm" svg:height="{h}cm" svg:x="{x}cm" svg:y="{y}cm"><text:p text:style-name="P-c">{t(text)}</text:p></{tag}>'

    def conn(a, b, sa=2, sb=0, kind="standard", style="st-line", label=None):
        return f'<draw:connector draw:style-name="{style}" draw:layer="Lines" draw:type="{kind}" draw:start-shape="n{a}" draw:start-glue-point="{sa}" draw:end-shape="n{b}" draw:end-glue-point="{sb}" svg:x1="0cm" svg:y1="0cm" svg:x2="1cm" svg:y2="1cm"/>'

    p1 = [
        node(1, 9, 1, 6, 1.6, "Boat calls the office", "st-start", "ell"),
        node(2, 9, 4, 6, 1.6, "Is a berth free?", "st-decision"),
        node(3, 2, 7.5, 6, 1.6, "Give berth number"),
        node(4, 16, 7.5, 6, 1.6, "Offer the waiting list"),
        node(5, 2, 11, 6, 1.6, "Boat moors"),
        node(6, 9, 14.5, 6, 1.6, "Pay at the office", "st-end", "ell"),
        node(7, 16, 11, 6, 1.6, "Boat waits at anchor"),
    ]
    links = [conn(1, 2), conn(2, 3, 3, 0, "standard"), conn(2, 4, 3, 0), conn(3, 5), conn(4, 7), conn(5, 6, 2, 1), conn(7, 2, 1, 3, "curve")]
    labels = '<draw:custom-shape draw:style-name="st-note" draw:layer="Notes" svg:width="1.6cm" svg:height="0.9cm" svg:x="5.2cm" svg:y="5.2cm"><text:p text:style-name="P-c">yes</text:p><draw:enhanced-geometry svg:viewBox="0 0 21600 21600" draw:type="rectangle" draw:enhanced-path="M 0 0 L 21600 0 21600 21600 0 21600 Z N"/></draw:custom-shape>' + '<draw:custom-shape draw:style-name="st-note" draw:layer="Notes" svg:width="1.6cm" svg:height="0.9cm" svg:x="16.2cm" svg:y="5.2cm"><text:p text:style-name="P-c">no</text:p><draw:enhanced-geometry svg:viewBox="0 0 21600 21600" draw:type="rectangle" draw:enhanced-path="M 0 0 L 21600 0 21600 21600 0 21600 Z N"/></draw:custom-shape>'
    legend = (
        '<draw:g draw:layer="Notes"><draw:rect draw:style-name="st-legend" svg:width="5.5cm" svg:height="3.4cm" svg:x="0.8cm" svg:y="0.6cm"/>'
        '<draw:rect draw:style-name="st-start" svg:width="0.7cm" svg:height="0.5cm" svg:x="1.1cm" svg:y="1.1cm"/><draw:frame draw:style-name="st-text" svg:width="3.8cm" svg:height="0.6cm" svg:x="2cm" svg:y="1.05cm"><draw:text-box><text:p text:style-name="P-s">start or end</text:p></draw:text-box></draw:frame>'
        '<draw:rect draw:style-name="st-box" svg:width="0.7cm" svg:height="0.5cm" svg:x="1.1cm" svg:y="2cm"/><draw:frame draw:style-name="st-text" svg:width="3.8cm" svg:height="0.6cm" svg:x="2cm" svg:y="1.95cm"><draw:text-box><text:p text:style-name="P-s">step</text:p></draw:text-box></draw:frame>'
        '<draw:rect draw:style-name="st-decision" svg:width="0.7cm" svg:height="0.5cm" svg:x="1.1cm" svg:y="2.9cm"/><draw:frame draw:style-name="st-text" svg:width="3.8cm" svg:height="0.6cm" svg:x="2cm" svg:y="2.85cm"><draw:text-box><text:p text:style-name="P-s">decision</text:p></draw:text-box></draw:frame></draw:g>'
    )
    curve = '<draw:path draw:style-name="st-curve" draw:layer="Notes" svg:width="6cm" svg:height="2.5cm" svg:x="17cm" svg:y="15cm" svg:viewBox="0 0 6000 2500" svg:d="M 0 2000 C 1500 -500 3000 4500 6000 500"/>'
    page1 = f'<draw:page draw:name="Mooring" draw:style-name="dp1" draw:master-page-name="Default">{"".join(p1)}{"".join(links)}{labels}{legend}{curve}<draw:frame draw:style-name="st-text" draw:layer="Notes" svg:width="14cm" svg:height="1cm" svg:x="0.8cm" svg:y="17.4cm"><draw:text-box><text:p text:style-name="P-s">Flowchart for the exav demo (CC0-1.0). Connectors follow their shapes.</text:p></draw:text-box></draw:frame></draw:page>'
    # Page 2: a block diagram with groups and a hidden layer.
    blocks = ""
    for i, (x, label) in enumerate([(1.5, "Harbour office"), (9.5, "Berth register"), (17.5, "Billing")]):
        blocks += f'<draw:g draw:layer="Boxes"><draw:rect draw:id="b{i}" draw:style-name="st-box" svg:width="6cm" svg:height="3cm" svg:x="{x}cm" svg:y="2cm"><text:p text:style-name="P-c">{label}</text:p></draw:rect><draw:ellipse draw:style-name="st-start" svg:width="0.8cm" svg:height="0.8cm" svg:x="{x + 5.4}cm" svg:y="2.2cm"><text:p text:style-name="P-s">{i + 1}</text:p></draw:ellipse></draw:g>'
    blocks += '<draw:connector draw:style-name="st-line" draw:layer="Lines" draw:type="line" draw:start-shape="b0" draw:start-glue-point="3" draw:end-shape="b1" draw:end-glue-point="1" svg:x1="7.5cm" svg:y1="3.5cm" svg:x2="9.5cm" svg:y2="3.5cm"/><draw:connector draw:style-name="st-line" draw:layer="Lines" draw:type="line" draw:start-shape="b1" draw:start-glue-point="3" draw:end-shape="b2" draw:end-glue-point="1" svg:x1="15.5cm" svg:y1="3.5cm" svg:x2="17.5cm" svg:y2="3.5cm"/>'
    stack = "".join(f'<draw:rect draw:style-name="st-grad" draw:layer="Boxes" svg:width="{14 - i * 2}cm" svg:height="1.4cm" svg:x="{5 + i}cm" svg:y="{7 + i * 1.6}cm"><text:p text:style-name="P-c">Layer {i + 1}</text:p></draw:rect>' for i in range(4))
    hidden = '<draw:rect draw:style-name="st-box" draw:layer="Hidden" svg:width="8cm" svg:height="1.4cm" svg:x="2cm" svg:y="15cm"><text:p text:style-name="P-c">On a hidden layer</text:p></draw:rect>'
    page2 = f'<draw:page draw:name="Blocks" draw:style-name="dp1" draw:master-page-name="Default">{blocks}{stack}{hidden}<draw:polyline draw:style-name="st-curve" draw:layer="Notes" svg:width="8cm" svg:height="3cm" svg:x="14cm" svg:y="14cm" svg:viewBox="0 0 8000 3000" draw:points="0,3000 2000,500 4000,2500 6000,0 8000,2000"/></draw:page>'
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document {NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.graphics">
<office:meta><meta:initial-creator>exav project</meta:initial-creator><dc:title>Flowchart</dc:title><dc:subject>A drawing made for the exav demo (CC0-1.0)</dc:subject><meta:creation-date>2000-01-01T00:00:00</meta:creation-date></office:meta>
<office:font-face-decls><style:font-face style:name="Liberation Sans" svg:font-family="'Liberation Sans'" style:font-family-generic="swiss"/></office:font-face-decls>
<office:styles>
<draw:gradient draw:name="Steel" draw:style="linear" draw:start-color="#c7d9e6" draw:end-color="#6f93ad" draw:start-intensity="100%" draw:end-intensity="100%" draw:angle="0deg" draw:border="0%"/>
<draw:marker draw:name="Arrow" svg:viewBox="0 0 20 30" svg:d="m10 0-10 30h20z"/>
<style:default-style style:family="graphic"><style:graphic-properties draw:stroke="solid" svg:stroke-color="#3465a4" draw:fill="solid" draw:fill-color="#729fcf"/><style:text-properties style:font-name="Liberation Sans" fo:font-size="14pt"/></style:default-style>
<style:style style:name="st-box" style:family="graphic"><style:graphic-properties svg:stroke-width="0.06cm" svg:stroke-color="#0b4f6c" draw:fill="solid" draw:fill-color="#dbe9f4" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center" draw:shadow="visible" draw:shadow-offset-x="0.1cm" draw:shadow-offset-y="0.1cm" draw:shadow-color="#999999"/></style:style>
<style:style style:name="st-start" style:family="graphic"><style:graphic-properties svg:stroke-width="0.06cm" svg:stroke-color="#1c6e3e" draw:fill="solid" draw:fill-color="#bfe8c4" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="st-end" style:family="graphic"><style:graphic-properties svg:stroke-width="0.06cm" svg:stroke-color="#8a1c1c" draw:fill="solid" draw:fill-color="#f5c2c0" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="st-decision" style:family="graphic"><style:graphic-properties svg:stroke-width="0.06cm" svg:stroke-color="#7a5c00" draw:stroke-dash="dash" draw:fill="solid" draw:fill-color="#ffe9a8" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="st-grad" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="gradient" draw:fill-gradient-name="Steel" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/></style:style>
<style:style style:name="st-line" style:family="graphic"><style:graphic-properties draw:fill="none" svg:stroke-width="0.08cm" svg:stroke-color="#333333" draw:marker-end="Arrow" draw:marker-end-width="0.35cm"/></style:style>
<style:style style:name="st-curve" style:family="graphic"><style:graphic-properties draw:fill="none" svg:stroke-width="0.1cm" svg:stroke-color="#c0392b"/></style:style>
<style:style style:name="st-note" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="none" draw:textarea-vertical-align="middle" draw:textarea-horizontal-align="center"/><style:text-properties fo:font-style="italic" fo:color="#555555"/></style:style>
<style:style style:name="st-legend" style:family="graphic"><style:graphic-properties svg:stroke-width="0.03cm" svg:stroke-color="#999999" draw:fill="solid" draw:fill-color="#ffffff"/></style:style>
<style:style style:name="st-text" style:family="graphic"><style:graphic-properties draw:stroke="none" draw:fill="none" draw:auto-grow-height="false"/></style:style>
</office:styles>
<office:automatic-styles>
<style:page-layout style:name="pm1"><style:page-layout-properties fo:margin-top="0cm" fo:margin-bottom="0cm" fo:margin-left="0cm" fo:margin-right="0cm" fo:page-width="24cm" fo:page-height="19cm" style:print-orientation="portrait"/></style:page-layout>
<style:style style:name="dp1" style:family="drawing-page"><style:drawing-page-properties draw:background-size="border" draw:fill="solid" draw:fill-color="#fbfaf7"/></style:style>
<style:style style:name="P-c" style:family="paragraph"><style:paragraph-properties fo:text-align="center"/><style:text-properties fo:font-size="13pt"/></style:style>
<style:style style:name="P-s" style:family="paragraph"><style:text-properties fo:font-size="10pt"/></style:style>
</office:automatic-styles>
<office:master-styles><draw:layer-set><draw:layer draw:name="Boxes"/><draw:layer draw:name="Lines"/><draw:layer draw:name="Notes"/><draw:layer draw:name="Hidden" draw:display="none"/></draw:layer-set><style:master-page style:name="Default" style:page-layout-name="pm1" draw:style-name="dp1"/></office:master-styles>
<office:body><office:drawing>{page1}{page2}</office:drawing></office:body>
</office:document>
"""


# ======================================================================
# Conversion
# ======================================================================

TARGETS = {
    "handbook": [("fodt", "converted", None), ("odt", "converted", "odt:writer8"), ("docx", "office", 'docx:MS Word 2007 XML'), ("doc", "converted", "doc:MS Word 97"), ("rtf", "converted", "rtf:Rich Text Format")],
    "workbook": [("fods", "converted", None), ("ods", "converted", "ods:calc8"), ("xlsx", "office", "xlsx:Calc MS Excel 2007 XML"), ("xls", "converted", "xls:MS Excel 97")],
    "deck": [("fodp", "converted", None), ("odp", "converted", "odp:impress8"), ("pptx", "office", "pptx:Impress MS PowerPoint 2007 XML"), ("ppt", "converted", "ppt:MS PowerPoint 97")],
    "diagram": [("fodg", "converted", None), ("odg", "converted", "odg:draw8")],
}


def convert(src, filt, outdir, profile):
    ext, name = filt.split(":", 1)
    subprocess.run(
        ["soffice", f"-env:UserInstallation=file://{profile}", "--headless", "--norestore", "--convert-to", f"{ext}:{name}", "--outdir", outdir, src],
        check=True, capture_output=True, timeout=300,
    )


def main():
    docs = {"handbook": ("fodt", handbook_fodt()), "workbook": ("fods", workbook_fods()), "deck": ("fodp", deck_fodp()), "diagram": ("fodg", diagram_fodg())}
    if not shutil.which("soffice"):
        print("soffice is missing: only the flat files are written", file=sys.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        profile = os.path.join(tmp, "profile")
        for base, (ext, xml) in docs.items():
            src_dir = os.path.join(tmp, base)
            os.makedirs(src_dir)
            src = os.path.join(src_dir, f"{base}.{ext}")
            with open(src, "w", encoding="utf-8") as f:
                f.write(xml)
            for target, folder, filt in TARGETS[base]:
                dest = os.path.join(OUT, folder, f"{base}.{target}")
                if filt is None:
                    shutil.copy(src, dest)
                elif shutil.which("soffice"):
                    out_dir = os.path.join(tmp, f"out-{base}-{target}")
                    os.makedirs(out_dir)
                    convert(src, filt, out_dir, profile)
                    shutil.copy(os.path.join(out_dir, f"{base}.{target}"), dest)
            if base == "handbook" and shutil.which("soffice"):
                out_dir = os.path.join(tmp, "out-pdf")
                os.makedirs(out_dir)
                opts = '{"UseTaggedPDF":{"type":"boolean","value":"true"},"ExportBookmarks":{"type":"boolean","value":"true"},"ExportNotes":{"type":"boolean","value":"false"},"SelectPdfVersion":{"type":"long","value":"2"}}'
                subprocess.run(["soffice", f"-env:UserInstallation=file://{profile}", "--headless", "--norestore", "--convert-to", f"pdf:writer_pdf_Export:{opts}", "--outdir", out_dir, src], check=True, capture_output=True, timeout=300)
                shutil.copy(os.path.join(out_dir, "handbook.pdf"), os.path.join(OUT, "pdf", "handbook-tagged.pdf"))


main()
