#!/usr/bin/env python3
"""Writes the demo's PDF examples into ../files/pdf/.

    python3 -I make-pdf.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. Every file
is made here from scratch.

Needs: Python 3, reportlab 4 (BSD licence), Pillow, numpy; the programs
opj_compress (libopenjp2-tools) and jbig2 (jbig2enc) and tiffcp (libtiff-tools)
for the scan; the Liberation fonts (SIL OFL 1.1, which lets documents embed
them) for the embedded-font page. The pictures' text is set in Pillow's
bundled Aileron font (CC0). A part whose program is missing is skipped.

- field-report.pdf: six pages of a report written for the demo: a table of
  contents whose entries are links, an outline of two levels, roman and
  arabic page labels, internal and external links, tables, bar, line and pie
  charts drawn as vectors, a raster picture, text in the 14 standard fonts
  and in embedded Liberation fonts (Latin, Greek, Cyrillic), footnote
  references, running heads, document information.
- application-form.pdf: an AcroForm with text fields (one multiline, one
  with a maximum length), check boxes, radio buttons, a drop-down list, a
  list box and a push button, some filled in.
- annotations.pdf: link annotations (URI, page, named destination) and
  markup annotations (note, highlight, underline, strike-out, squiggly, free
  text, square, circle, line, polygon, ink, stamp) without appearance
  streams, an outline and a named destination: written by the small PDF
  writer below.
- scan-mixed.pdf: a four-page scanned letter, one page for each image filter
  a scanner's PDF uses: DCTDecode (JPEG), CCITTFaxDecode (Group 4),
  JBIG2Decode and JPXDecode (JPEG 2000), each with an invisible text layer
  (an OCR result).
- vector-art.pdf: gradients (axial and radial shadings), transparency,
  clipping, dashes, caps and joins, Bezier curves, rotated and scaled text.
"""
import io
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from reportlab import rl_config

rl_config.invariant = 1

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import BaseDocTemplate, Frame, Image as RLImage, KeepTogether, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "pdf")
os.makedirs(OUT, exist_ok=True)
FONTS = "/usr/share/fonts/truetype/liberation"
EMBED = os.path.exists(os.path.join(FONTS, "LiberationSans-Regular.ttf"))
if EMBED:
    for name, f in [("LibSans", "LiberationSans-Regular"), ("LibSerif", "LiberationSerif-Regular"), ("LibSerif-Italic", "LiberationSerif-Italic"), ("LibMono", "LiberationMono-Regular")]:
        pdfmetrics.registerFont(TTFont(name, os.path.join(FONTS, f + ".ttf")))
        # Names the font by itself so that <b> and <i> stay in the family.
    pdfmetrics.registerFontFamily("LibSerif", normal="LibSerif", italic="LibSerif-Italic", bold="LibSerif", boldItalic="LibSerif-Italic")


def aileron(size):
    return ImageFont.load_default(size)


# ------------------------------------------------------------ field report


def diagram_image():
    """A small raster picture: a gradient with circles, for the report."""
    w, h = 480, 260
    y = np.linspace(0, 1, h)[:, None]
    x = np.linspace(0, 1, w)[None, :]
    px = np.zeros((h, w, 3), np.uint8)
    px[..., 0] = 40 + 160 * x
    px[..., 1] = 80 + 100 * y
    px[..., 2] = 200 - 120 * x
    im = Image.fromarray(px, "RGB")
    d = ImageDraw.Draw(im)
    for i in range(7):
        r = 14 + i * 7
        d.ellipse((60 + i * 60 - r, 130 - r, 60 + i * 60 + r, 130 + r), outline=(255, 255, 255), width=3)
    d.text((16, 14), "A raster picture in the report", font=aileron(22), fill=(255, 255, 255))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=88)
    buf.seek(0)
    return buf


class Report(BaseDocTemplate):
    def __init__(self, path):
        super().__init__(path, pagesize=A4, leftMargin=2.2 * cm, rightMargin=2.2 * cm, topMargin=2.5 * cm, bottomMargin=2.2 * cm,
                         title="Field report: the east quay", author="exav project", subject="A report written for the exav demo (CC0-1.0)",
                         keywords="demo, report, links, outline, charts", creator="exav make-pdf.py", pageCompression=1)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=self.decorate)])

    def decorate(self, c, doc):
        c.saveState()
        if doc.page == 1:
            # The cover and the contents are i and ii; the body starts again at 1.
            c.addPageLabel(0, "ROMAN_LOWER", 1)
            c.addPageLabel(2, "ARABIC", 1)
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#555555"))
        if doc.page > 1:
            c.drawString(self.leftMargin, A4[1] - 1.5 * cm, "Field report: the east quay")
            c.drawRightString(A4[0] - self.rightMargin, A4[1] - 1.5 * cm, "exav demo, CC0-1.0")
            c.setStrokeColor(colors.HexColor("#999999"))
            c.line(self.leftMargin, A4[1] - 1.7 * cm, A4[0] - self.rightMargin, A4[1] - 1.7 * cm)
            c.drawCentredString(A4[0] / 2, 1.2 * cm, f"page {doc.page}")
            c.linkURL("https://exav.org/viewer/", (A4[0] - self.rightMargin - 3 * cm, A4[1] - 1.6 * cm, A4[0] - self.rightMargin, A4[1] - 1.3 * cm), relative=0)
        c.restoreState()

    def afterFlowable(self, fl):
        if isinstance(fl, Paragraph) and fl.style.name in ("H1", "H2"):
            level = 0 if fl.style.name == "H1" else 1
            text = fl.getPlainText()
            key = "h" + "".join(c if c.isalnum() else "-" for c in text)
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level, closed=False)
            self.notify("TOCEntry", (level, text, self.page, key))


def field_report(path):
    ss = getSampleStyleSheet()
    body_font, serif_font = ("LibSans", "LibSerif") if EMBED else ("Helvetica", "Times-Roman")
    body = ParagraphStyle("Body", parent=ss["BodyText"], fontName=serif_font, fontSize=10.5, leading=14.5, alignment=TA_JUSTIFY, spaceAfter=6)
    h1 = ParagraphStyle("H1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=18, spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#0b4f6c"))
    h2 = ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13, spaceBefore=10, spaceAfter=5, textColor=colors.HexColor("#146c94"))
    small = ParagraphStyle("Small", parent=body, fontSize=8.5, leading=11, alignment=0)
    mono = ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=9, leading=11.5, alignment=0, backColor=colors.HexColor("#f2f2f2"), borderPadding=4, spaceBefore=4, spaceAfter=8)

    lorem = [
        "The east quay was built in three stages. The first stage, a timber jetty of twenty berths, dates from the start of the register; the second doubled it in stone, and the third, the long breakwater, shelters both from the south-west swell.",
        "Every berth has a number, a length in metres and a holder. The register is kept on paper and in a table; the two are compared each spring, and the differences are explained in the notes of the harbour master.",
        "Visitors are asked to call the harbour office on channel 9 before they come in, to give the length of their boat and the draught, and to say how many nights they plan to stay. The office will give a berth number and, when the tide is low, the best line of approach.",
        "A note on the figures. Lengths are over all, in metres, to one decimal. Fees are in euros and include the tax. Where a table gives a total, it is the sum of the rows above it, rounded once, at the end.",
    ]

    def paras(n, start=0):
        return [Paragraph(lorem[(start + i) % len(lorem)], body) for i in range(n)]

    story = []
    # The cover page.
    story += [Spacer(1, 5 * cm), Paragraph("Field report", ParagraphStyle("Title", parent=h1, fontSize=34, leading=40, textColor=colors.HexColor("#0b4f6c"))),
              Paragraph("The east quay: berths, tides and visitors", ParagraphStyle("Sub", parent=body, fontName="Helvetica", fontSize=16, leading=20, alignment=0)), Spacer(1, 1.2 * cm),
              Paragraph("A document made for the exav demo. It has a table of contents whose lines are links, an outline in the side panel, page labels, charts drawn as vectors, tables, a picture, and text in embedded fonts. It is in the public domain (CC0-1.0).", body),
              Spacer(1, 1 * cm), Paragraph('Project page: <a href="https://exav.org/viewer/" color="blue">https://exav.org/viewer/</a>', body), PageBreak()]
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("t0", fontName="Helvetica-Bold", fontSize=11, leading=16, leftIndent=0, firstLineIndent=0), ParagraphStyle("t1", fontName="Helvetica", fontSize=10, leading=14, leftIndent=18, firstLineIndent=0)]
    story += [Paragraph("Contents", ParagraphStyle("TocTitle", parent=h1)), toc, PageBreak()]

    story += [Paragraph("1. The quay", h1), Paragraph("1.1 History", h2)] + paras(3)
    story += [Paragraph("1.2 Today", h2)] + paras(2, 1)
    story += [Paragraph("Notes: see <a href=\"#fig1\" color=\"blue\">the picture</a> and <a href=\"#tab1\" color=\"blue\">the first table</a> in section 2.<super>1</super>", small)]
    story += [Paragraph("2. Figures", h1), Paragraph("2.1 Berths by length", h2)]
    data = [["Length (m)", "Berths", "Let by", "Fee (EUR)", "Income (EUR)"]]
    rows = [("up to 6", 12, "week", 18.0), ("6 to 8", 18, "season", 24.5), ("8 to 10", 14, "season", 31.0), ("10 to 12", 9, "year", 42.0), ("over 12", 7, "year", 58.5)]
    for a, b, c, d in rows:
        data.append([a, b, c, f"{d:.2f}", f"{b * d:.2f}"])
    data.append(["Total", sum(r[1] for r in rows), "", "", f"{sum(r[1] * r[3] for r in rows):.2f}"])
    t = Table(data, colWidths=[3.2 * cm, 2.4 * cm, 2.6 * cm, 3 * cm, 3.4 * cm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b4f6c")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                           ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"), ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#e8f1f5")]),
                           ("ALIGN", (1, 0), (-1, -1), "RIGHT"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#8aa6b4")), ("LINEABOVE", (0, -1), (-1, -1), 1.2, colors.black)]))
    story += [Paragraph('<a name="tab1"/>Table 1. Berths by length, with the season\'s fee.', small), t, Spacer(1, 0.4 * cm)]
    story += [Paragraph("2.2 Charts", h2)]
    bar = Drawing(420, 200)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 40, 30, 360, 150
    chart.data = [[12, 18, 14, 9, 7], [10, 17, 15, 8, 5]]
    chart.categoryAxis.categoryNames = [r[0] for r in rows]
    chart.valueAxis.valueMin, chart.valueAxis.valueMax, chart.valueAxis.valueStep = 0, 20, 5
    chart.bars[0].fillColor = colors.HexColor("#146c94")
    chart.bars[1].fillColor = colors.HexColor("#f6a01a")
    chart.barLabelFormat = "%d"
    chart.barLabels.nudge = 7
    bar.add(chart)
    bar.add(String(40, 188, "Berths let, this year and last", fontName="Helvetica-Bold", fontSize=10))
    story += [bar]
    line = Drawing(420, 190)
    lp = LinePlot()
    lp.x, lp.y, lp.width, lp.height = 40, 25, 360, 140
    months = list(range(1, 13))
    lp.data = [[(m, 40 + 35 * math.sin((m - 3) / 12 * 2 * math.pi) + 5 * m / 12) for m in months], [(m, 28 + 22 * math.sin((m - 3) / 12 * 2 * math.pi)) for m in months]]
    lp.lines[0].strokeColor, lp.lines[1].strokeColor = colors.HexColor("#c0392b"), colors.HexColor("#2c7a4b")
    lp.lines[0].strokeWidth = lp.lines[1].strokeWidth = 2
    lp.lines[0].symbol = lp.lines[1].symbol = None
    lp.xValueAxis.valueMin, lp.xValueAxis.valueMax, lp.xValueAxis.valueStep = 1, 12, 1
    line.add(lp)
    line.add(String(40, 175, "Boats a day, by month (visitors and holders)", fontName="Helvetica-Bold", fontSize=10))
    story += [line]
    pie = Drawing(420, 180)
    p = Pie()
    p.x, p.y, p.width, p.height = 40, 15, 140, 140
    p.data = [41, 27, 18, 9, 5]
    p.labels = ["sail", "motor", "fishing", "rowing", "other"]
    for i, c in enumerate(["#146c94", "#f6a01a", "#2c7a4b", "#c0392b", "#8e44ad"]):
        p.slices[i].fillColor = colors.HexColor(c)
    p.slices[0].popout = 8
    pie.add(p)
    leg = Legend()
    leg.x, leg.y, leg.alignment = 230, 120, "right"
    leg.colorNamePairs = [(colors.HexColor(c), f"{n} ({v}%)") for c, n, v in zip(["#146c94", "#f6a01a", "#2c7a4b", "#c0392b", "#8e44ad"], p.labels, p.data)]
    pie.add(leg)
    story += [pie]
    story += [Paragraph("2.3 A picture", h2), Paragraph('<a name="fig1"/>Figure 1. A raster picture, embedded as a JPEG.', small), RLImage(diagram_image(), width=12 * cm, height=6.5 * cm)]
    story += [Paragraph("3. Fonts and text", h1), Paragraph("3.1 The standard fonts", h2)]
    for fam, label in [("Helvetica", "Helvetica"), ("Times-Roman", "Times Roman"), ("Courier", "Courier"), ("Helvetica-Oblique", "Helvetica Oblique"), ("Times-BoldItalic", "Times Bold Italic"), ("Symbol", "Symbol: abgd"), ("ZapfDingbats", "abcdef")]:
        story.append(Paragraph(f"{label}: The quick brown fox jumps over the lazy dog 0123456789", ParagraphStyle("f", parent=body, fontName=fam, fontSize=10.5, alignment=0, spaceAfter=2)))
    if EMBED:
        story += [Paragraph("3.2 Embedded fonts (Liberation, SIL OFL 1.1)", h2),
                  Paragraph("Latin: café, naïve, Zürich, Łódź, ångström, €12,50. Greek: Αθήνα, π ≈ 3,14159. Cyrillic: Москва, живой язык.", ParagraphStyle("u", parent=body, fontName="LibSerif", alignment=0)),
                  Paragraph("Sans: Portez ce vieux whisky au juge blond qui fume. 0123456789", ParagraphStyle("u2", parent=body, fontName="LibSans", alignment=0)),
                  Paragraph("def moor(boat): return berth_for(boat.length)", ParagraphStyle("u3", parent=body, fontName="LibMono", fontSize=9.5, alignment=0))]
    story += [Paragraph("3.3 Preformatted text and a list", h2), Paragraph("moor --boat Aurora --length 6.5\nberth 14 free until 06:00\n    (tide table on page 6)", mono)]
    bullets = [Paragraph(f"• {t}", ParagraphStyle("b", parent=body, leftIndent=14, firstLineIndent=-10, spaceAfter=2, alignment=0)) for t in ["Call the office on channel 9.", "Give the length, the draught and the number of nights.", "Take the berth you are given."]]
    story += bullets
    story += [Paragraph("4. Links", h1), Paragraph("4.1 Where they go", h2),
              Paragraph('An external link: <a href="https://exav.org/" color="blue">exav.org</a>. A link to another page of this file: <a href="#h1--The-quay" color="blue">back to section 1</a>. A link on a picture, and one around a long phrase that wraps at the end of a line to the next, so that its box is two rectangles: <a href="https://github.com/sylvinus/exav" color="blue">the source of the demo is on GitHub, and this phrase is long enough to wrap</a>.', body)] + paras(2, 2)
    story += [Paragraph("Footnote 1: the table's totals are exact; the charts are rounded.", small)]
    doc = Report(path)
    doc.multiBuild(story)


# ------------------------------------------------------------------- forms


def application_form(path):
    c = canvas.Canvas(path, pagesize=A4, pageCompression=1)
    c.setTitle("Berth application form")
    c.setAuthor("exav project")
    form = c.acroForm
    w, h = A4
    c.setFont("Helvetica-Bold", 20)
    c.drawString(2 * cm, h - 2.5 * cm, "Berth application")
    c.setFont("Helvetica", 9)
    c.drawString(2 * cm, h - 3.1 * cm, "A form for the exav demo (CC0-1.0). Some fields are filled in.")
    y = h - 4.5 * cm

    def label(text, yy):
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.black)
        c.drawString(2 * cm, yy + 3, text)

    label("Full name", y)
    form.textfield(name="name", tooltip="Full name", value="Anne Le Gall", x=6 * cm, y=y - 3, width=9 * cm, height=0.7 * cm, borderStyle="inset", fillColor=colors.HexColor("#fffbe6"), fontSize=11)
    y -= 1.2 * cm
    label("Boat's name", y)
    form.textfield(name="boat", tooltip="Boat's name", value="Hirondelle", x=6 * cm, y=y - 3, width=9 * cm, height=0.7 * cm, borderStyle="inset", fontSize=11)
    y -= 1.2 * cm
    label("Length (m), 5 characters", y)
    form.textfield(name="length", tooltip="Length", value="9.4", maxlen=5, x=6.5 * cm, y=y - 3, width=2.2 * cm, height=0.7 * cm, borderStyle="inset", fontSize=11)
    y -= 1.2 * cm
    label("Type of boat", y)
    form.choice(name="kind", tooltip="Type of boat", value="sloop", options=["sloop", "ketch", "trawler", "motor yacht", "catamaran"], x=6 * cm, y=y - 3, width=5 * cm, height=0.7 * cm, fieldFlags="combo", borderStyle="inset", fontSize=11)
    y -= 1.2 * cm
    label("Services", y)
    for i, (n, t) in enumerate([("water", "Water"), ("power", "Shore power"), ("wifi", "Wi-Fi")]):
        form.checkbox(name=n, tooltip=t, checked=(i != 2), x=6 * cm + i * 4 * cm, y=y - 2, size=14, buttonStyle="check", borderColor=colors.black, fillColor=colors.white, textColor=colors.black)
        c.drawString(6 * cm + i * 4 * cm + 20, y + 1, t)
    y -= 1.2 * cm
    label("Stay", y)
    for i, (v, t) in enumerate([("night", "One night"), ("week", "A week"), ("season", "The season")]):
        form.radio(name="stay", tooltip=t, value=v, selected=(v == "week"), x=6 * cm + i * 4 * cm, y=y - 2, size=14, buttonStyle="circle", borderColor=colors.black, fillColor=colors.white, textColor=colors.black)
        c.drawString(6 * cm + i * 4 * cm + 20, y + 1, t)
    y -= 1.2 * cm
    label("Arrival month", y)
    form.listbox(name="month", tooltip="Arrival month", value="June", options=["April", "May", "June", "July", "August", "September"], x=6 * cm, y=y - 2.4 * cm, width=4 * cm, height=2.4 * cm + 0.5 * cm, borderStyle="inset", fontSize=10)
    y -= 3.6 * cm
    label("Remarks", y)
    form.textfield(name="remarks", tooltip="Remarks", value="Arriving after sunset.\nDraught 1.4 m.", x=6 * cm, y=y - 2 * cm, width=10 * cm, height=2.4 * cm, borderStyle="inset", fieldFlags="multiline", fontSize=10)
    y -= 3.4 * cm
    label("Password (hidden)", y)
    form.textfield(name="secret", tooltip="A password field shows dots", value="berth", x=6 * cm, y=y - 3, width=5 * cm, height=0.7 * cm, borderStyle="inset", fieldFlags="password", fontSize=11)
    y -= 1.6 * cm
    form.textfield(name="readonly", tooltip="Read only", value="Application no. 2000-0001 (read only)", x=2 * cm, y=y - 3, width=9 * cm, height=0.7 * cm, borderStyle="solid", fieldFlags="readOnly", fontSize=10, fillColor=colors.HexColor("#eeeeee"))
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(2 * cm, 2 * cm, "Fill the fields in the viewer; nothing is sent anywhere.")
    c.showPage()
    c.save()


# --------------------------------------------------------- a tiny PDF writer


class Pdf:
    def __init__(self):
        self.objs = []

    def reserve(self):
        self.objs.append(None)
        return len(self.objs)

    def set(self, n, body):
        self.objs[n - 1] = body if isinstance(body, bytes) else body.encode("latin-1")

    def add(self, body):
        n = self.reserve()
        self.set(n, body)
        return n

    def stream(self, entries, data, compress=False):
        if compress:
            data = zlib.compress(data, 9)
            entries += " /Filter /FlateDecode"
        return self.add(f"<< {entries} /Length {len(data)} >>\nstream\n".encode("latin-1") + data + b"\nendstream")

    def write(self, path, root, info=None):
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(self.objs, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(self.objs) + 1}\n0000000000 65535 f \n".encode()
        for o in offsets:
            out += f"{o:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(self.objs) + 1} /Root {root} 0 R {f'/Info {info} 0 R' if info else ''} /ID [<6578617620657861> <6578617620657861>] >>\nstartxref\n{xref}\n%%EOF\n".encode()
        with open(path, "wb") as f:
            f.write(out)


def pdf_str(s):
    return "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")"


def annotations(path):
    p = Pdf()
    catalog, pages = p.reserve(), p.reserve()
    page1, page2 = p.reserve(), p.reserve()
    font = p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    bold = p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    attach = p.stream("/Type /EmbeddedFile /Subtype /text#2Fplain /Params << /Size 38 >>", b"An attached file, inside the annotation.\n", False)
    spec = p.add(f"<< /Type /Filespec /F (note.txt) /UF (note.txt) /EF << /F {attach} 0 R >> /Desc (A file attached to the page) >>")

    lines = []
    annots = []

    def text(x, y, s, f="F1", size=11):
        lines.append(f"BT /{f} {size} Tf {x} {y} Td {pdf_str(s)} Tj ET")

    def annot(body):
        annots.append(p.add(body))

    text(50, 790, "Annotations", "F2", 22)
    text(50, 770, "Every mark below is an annotation of the page, drawn from its own entry.", "F1", 10)
    rows = [
        ("Link to a web address", "<< /Type /Annot /Subtype /Link /Rect [200 722 330 740] /Border [0 0 1] /C [0 0 1] /A << /S /URI /URI (https://exav.org/viewer/) >> >>"),
        ("Link to page 2", f"<< /Type /Annot /Subtype /Link /Rect [200 692 330 710] /Border [0 0 1] /C [0 0.5 0] /Dest [{page2} 0 R /XYZ 50 760 0] >>"),
        ("Link to a named place", "<< /Type /Annot /Subtype /Link /Rect [200 662 330 680] /Border [0 0 1] /C [0.6 0 0.6] /Dest (target) >>"),
    ]
    y = 730
    for label, body in rows:
        text(50, y, label)
        text(205, y, "click here")
        annot(body)
        y -= 30
    y = 630
    marks = [
        ("Highlight", "Highlight", "/C [1 1 0]"),
        ("Underline", "Underline", "/C [0 0.6 0]"),
        ("Strike-out", "StrikeOut", "/C [1 0 0]"),
        ("Squiggly", "Squiggly", "/C [0.6 0 0.8]"),
    ]
    for label, sub, extra in marks:
        text(50, y, f"{label}: marked text in a line")
        x0, x1 = 50, 50 + 7.0 * len(f"{label}: marked text in a line") * 0.82
        annot(f"<< /Type /Annot /Subtype /{sub} /Rect [{x0} {y - 3} {x1} {y + 11}] /QuadPoints [{x0} {y + 11} {x1} {y + 11} {x0} {y - 3} {x1} {y - 3}] {extra} /T (exav) /Contents ({label} annotation) /F 4 >>")
        y -= 24
    text(50, 520, "Text note (sticky note), free text, shapes:")
    annot("<< /Type /Annot /Subtype /Text /Rect [60 470 80 490] /Name /Comment /Contents (A note. Its text is in the annotation.) /T (exav) /C [1 0.8 0] /Open false /F 28 >>")
    annot("<< /Type /Annot /Subtype /FreeText /Rect [100 450 300 495] /Contents (Free text in a box) /DA (/Helv 12 Tf 0 0 1 rg) /DS (font: Helvetica 12pt) /C [1 1 0.8] /IC [1 1 0.8] /BS << /W 1 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Square /Rect [320 450 400 495] /C [1 0 0] /IC [1 0.9 0.9] /BS << /W 2 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Circle /Rect [420 450 500 495] /C [0 0 1] /IC [0.9 0.9 1] /BS << /W 2 /S /D /D [4 2] >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Line /Rect [50 390 250 430] /L [60 400 240 420] /LE [/OpenArrow /ClosedArrow] /C [0 0.5 0] /BS << /W 2 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Polygon /Rect [280 380 380 430] /Vertices [290 390 370 390 380 420 300 425] /C [0.5 0 0.5] /IC [0.95 0.85 0.95] /BS << /W 1.5 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /PolyLine /Rect [400 380 500 430] /Vertices [410 390 440 425 470 392 495 420] /C [0 0.4 0.4] /BS << /W 2 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Ink /Rect [50 310 250 370] /InkList [[60 320 90 360 120 320 150 360 180 320 210 360 240 330]] /C [0.8 0.3 0] /BS << /W 2.5 >> /F 4 >>")
    annot("<< /Type /Annot /Subtype /Stamp /Rect [280 310 400 370] /Name /Approved /Contents (A stamp) /C [0 0.6 0] /F 4 >>")
    annot(f"<< /Type /Annot /Subtype /FileAttachment /Rect [430 330 450 350] /FS {spec} 0 R /Name /Paperclip /Contents (An attached file) /C [0.3 0.3 0.3] /F 28 >>")
    text(50, 280, "The page also holds a link under a rotated line of text, below.", "F1", 10)
    lines.append("q 0.866 0.5 -0.5 0.866 80 150 cm BT /F1 12 Tf 0 0 Td (A rotated line with a link over it) Tj ET Q")
    annot("<< /Type /Annot /Subtype /Link /Rect [80 150 330 230] /Border [0 0 0] /QuadPoints [80 150 80 150 80 150 80 150] /A << /S /URI /URI (https://exav.org/) >> >>")
    content1 = p.stream("", "\n".join(lines).encode("latin-1"), True)

    lines2 = []
    lines2.append("BT /F2 22 Tf 50 790 Td (Page 2: the target) Tj ET")
    lines2.append("BT /F1 11 Tf 50 760 Td (The named destination \"target\" points here, and so does the second line of the outline.) Tj ET")
    lines2.append("0.9 0.95 1 rg 50 600 300 120 re f 0 0 0.6 RG 50 600 300 120 re S")
    lines2.append("BT /F1 11 Tf 60 700 Td (A framed box.) Tj ET")
    content2 = p.stream("", "\n".join(lines2).encode("latin-1"), True)

    res = f"<< /Font << /F1 {font} 0 R /F2 {bold} 0 R /Helv {font} 0 R >> >>"
    p.set(page1, f"<< /Type /Page /Parent {pages} 0 R /MediaBox [0 0 595 842] /Resources {res} /Contents {content1} 0 R /Annots [{' '.join(f'{a} 0 R' for a in annots)}] >>")
    p.set(page2, f"<< /Type /Page /Parent {pages} 0 R /MediaBox [0 0 595 842] /Resources {res} /Contents {content2} 0 R >>")
    p.set(pages, f"<< /Type /Pages /Kids [{page1} 0 R {page2} 0 R] /Count 2 >>")
    outlines, o1, o2, o3 = p.reserve(), p.reserve(), p.reserve(), p.reserve()
    p.set(outlines, f"<< /Type /Outlines /First {o1} 0 R /Last {o2} 0 R /Count 3 >>")
    p.set(o1, f"<< /Title (Annotations) /Parent {outlines} 0 R /Next {o2} 0 R /Dest [{page1} 0 R /Fit] >>")
    p.set(o2, f"<< /Title (The target) /Parent {outlines} 0 R /Prev {o1} 0 R /First {o3} 0 R /Last {o3} 0 R /Count 1 /Dest [{page2} 0 R /XYZ 50 760 0] >>")
    p.set(o3, f"<< /Title (A box on that page) /Parent {o2} 0 R /A << /S /GoTo /D [{page2} 0 R /FitR 50 600 350 720] >> >>")
    info = p.add("<< /Title (Annotations) /Author (exav project) /Subject (CC0-1.0) /Creator (exav make-pdf.py) >>")
    p.set(catalog, f"<< /Type /Catalog /Pages {pages} 0 R /Outlines {outlines} 0 R /Names << /Dests << /Names [(target) [{page2} 0 R /XYZ 50 760 0]] >> >> /PageMode /UseOutlines /ViewerPreferences << /DisplayDocTitle true >> /Lang (en) >>")
    p.write(path, catalog, info)


# ------------------------------------------------------------------- scan

LETTER = [
    ["Harbour office, East quay", "", "Report of the harbour master", "for the month of March", "", "Berths let this month: 41 of 60.", "Visitors: 63 boats, of which 18 stayed more than two nights.", "",
     "The breakwater light was out for three nights; it is repaired.", "The pontoon at berth 24 needs a new chain; quote attached.", "", "Weather: four days of gale from the south-west, no damage."],
    ["Tide notes", "", "High water at the quay was at 06:12 and 18:34 on the first.", "The spring tides of the 14th and 15th reached 7.4 metres.", "Boats drawing more than 1.8 metres should wait for the", "top of the tide before they come in.", "", "The fairway buoy has been moved 50 metres to the east."],
    ["Visitors' book (extract)", "", "Aurora, sloop 9.4 m, two nights.", "Brise, ketch 12.1 m, one night.", "Calypso, trawler 14.0 m, a week.", "Dorade, sloop 8.2 m, one night.", "", "Thanks to the office for the loan of the bicycle."],
    ["Notes for the next month", "", "Order a new chain for berth 24.", "Paint the numbers on the east pontoon.", "Check the shore power at berths 30 to 40.", "", "Signed, the harbour master"],
]


def letter_page(n, w=1240, h=1754):
    """A scanned-looking letter: paper tone, text a little off the straight, noise, a shadow."""
    rng = np.random.default_rng(n)
    page = Image.new("L", (w, h), 255)
    d = ImageDraw.Draw(page)
    words = []
    y = 160
    for i, line in enumerate(LETTER[n]):
        size = 54 if i == 0 else 38
        d.text((130, y), line, font=aileron(size), fill=25)
        if line:
            words.append((130, y, line, size))
        y += 88 if i == 0 else 62
    d.line((130, 140, w - 130, 140), fill=40, width=3)
    d.rectangle((w - 420, h - 420, w - 140, h - 170), outline=60, width=4)
    d.text((w - 400, h - 330), "STAMP", font=aileron(48), fill=60)
    page = page.rotate(0.5 + 0.25 * n, resample=Image.BICUBIC, fillcolor=255, expand=False)
    return page, words


def scan_variants(n):
    page, words = letter_page(n)
    arr = np.array(page).astype(float)
    yy, xx = np.mgrid[0 : arr.shape[0], 0 : arr.shape[1]]
    paper = 232 - 18 * (xx / arr.shape[1]) ** 3 - 14 * (yy / arr.shape[0]) ** 2
    grey = arr / 255 * paper + np.random.default_rng(100 + n).normal(0, 3.0, arr.shape)
    scan_grey = Image.fromarray(np.clip(grey, 0, 255).astype(np.uint8), "L").filter(ImageFilter.GaussianBlur(0.6))
    bilevel = page.point(lambda v: 255 if v > 150 else 0).convert("1")
    return scan_grey, bilevel, words


def scan_pdf(path):
    if not (shutil.which("opj_compress") and shutil.which("jbig2") and shutil.which("tiffcp")):
        print("scan-mixed.pdf skipped: opj_compress, jbig2 or tiffcp is missing", file=sys.stderr)
        return
    p = Pdf()
    catalog, pages = p.reserve(), p.reserve()
    font = p.add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    kids = []
    W, H = 1240, 1754
    with tempfile.TemporaryDirectory() as tmp:
        for n in range(4):
            grey, bilevel, words = scan_variants(n)
            if n == 0:
                buf = io.BytesIO()
                grey.save(buf, "JPEG", quality=70, dpi=(150, 150))
                img = p.stream(f"/Type /XObject /Subtype /Image /Width {W} /Height {H} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode", buf.getvalue())
            elif n == 1:
                src = os.path.join(tmp, "p.tif")
                inv = bilevel.convert("L").point(lambda v: 255 - v).convert("1")
                inv.save(src)
                dst = os.path.join(tmp, "g4.tif")
                subprocess.run(["tiffcp", "-c", "g4", "-r", str(H), src, dst], check=True, capture_output=True)
                raw = open(dst, "rb").read()
                e = "<" if raw[:2] == b"II" else ">"
                ifd = struct.unpack(e + "I", raw[4:8])[0]
                tags = {}
                for i in range(struct.unpack(e + "H", raw[ifd : ifd + 2])[0]):
                    tag, kind, count, value = struct.unpack(e + "HHII", raw[ifd + 2 + 12 * i : ifd + 14 + 12 * i])
                    if kind == 3 and count == 1:
                        value = value & 0xFFFF if e == "<" else value >> 16
                    tags[tag] = value
                strip = raw[tags[273] : tags[273] + tags[279]]
                img = p.stream(f"/Type /XObject /Subtype /Image /Width {W} /Height {H} /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter /CCITTFaxDecode /DecodeParms << /K -1 /Columns {W} /Rows {H} >>", strip)
            elif n == 2:
                src = os.path.join(tmp, "p.png")
                bilevel.save(src)
                data = subprocess.run(["jbig2", "-p", src], check=True, capture_output=True).stdout
                img = p.stream(f"/Type /XObject /Subtype /Image /Width {W} /Height {H} /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter /JBIG2Decode", data)
            else:
                src = os.path.join(tmp, "p.png")
                grey.save(src)
                dst = os.path.join(tmp, "p.jp2")
                subprocess.run(["opj_compress", "-i", src, "-o", dst, "-r", "30", "-n", "5"], check=True, capture_output=True)
                img = p.stream(f"/Type /XObject /Subtype /Image /Width {W} /Height {H} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /JPXDecode", open(dst, "rb").read())
            # The page is A4 at 150 dpi: 595 by 842 points. The invisible text sits over each line.
            sx = 595.0 / W
            ops = [f"q {595} 0 0 {842} 0 0 cm /Im0 Do Q", "BT 3 Tr"]
            for x, y, line, size in words:
                ops.append(f"/F1 {size * sx * 0.95:.1f} Tf 1 0 0 1 {x * sx:.1f} {842 - (y + size) * sx:.1f} Tm {pdf_str(line)} Tj")
            ops.append("ET")
            content = p.stream("", "\n".join(ops).encode("latin-1"), True)
            kids.append(p.add(f"<< /Type /Page /Parent {pages} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font} 0 R >> /XObject << /Im0 {img} 0 R >> >> /Contents {content} 0 R >>"))
    p.set(pages, f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>")
    p.set(catalog, f"<< /Type /Catalog /Pages {pages} 0 R /Lang (en) >>")
    info = p.add("<< /Title (Scanned letters) /Author (exav project) /Subject (CC0-1.0) /Creator (exav make-pdf.py) >>")
    p.write(path, catalog, info)


# ------------------------------------------------------------ vector art


def vector_art(path):
    c = canvas.Canvas(path, pagesize=A4, pageCompression=1)
    c.setTitle("Vector art")
    c.setAuthor("exav project")
    w, h = A4
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, h - 50, "Vector art")
    c.setFont("Helvetica", 9)
    c.drawString(40, h - 64, "Gradients, transparency, clipping, dashes, joins, curves and transformed text (CC0-1.0).")
    # Axial and radial shadings.
    # A shading paints everywhere inside the clip, so each is clipped to its box.
    c.saveState()
    box = c.beginPath()
    box.roundRect(40, h - 200, 200, 110, 14)
    c.clipPath(box, stroke=0, fill=0)
    c.linearGradient(40, h - 200, 240, h - 90, (colors.HexColor("#0b4f6c"), colors.HexColor("#f6a01a"), colors.HexColor("#c0392b")), (0, 0.5, 1))
    c.restoreState()
    c.saveState()
    disc = c.beginPath()
    disc.circle(400, h - 145, 70)
    c.clipPath(disc, stroke=0, fill=0)
    c.radialGradient(400, h - 145, 70, (colors.white, colors.HexColor("#146c94"), colors.black), (0, 0.6, 1))
    c.restoreState()
    # Transparency: three overlapping discs.
    for i, (cx, col) in enumerate([(80, "#c0392b"), (130, "#2c7a4b"), (105, "#146c94")]):
        c.saveState()
        c.setFillAlpha(0.55)
        c.setFillColor(colors.HexColor(col))
        c.circle(cx, h - 290 + (i == 2) * 40, 45, stroke=0, fill=1)
        c.restoreState()
    # Clipping: a star clips a striped rectangle.
    c.saveState()
    p = c.beginPath()
    cx, cy, r1, r2 = 330, h - 280, 60, 25
    for i in range(10):
        a = math.pi / 5 * i - math.pi / 2
        r = r1 if i % 2 == 0 else r2
        (p.moveTo if i == 0 else p.lineTo)(cx + r * math.cos(a), cy + r * math.sin(a))
    p.close()
    c.clipPath(p, stroke=0, fill=0)
    for i in range(14):
        c.setFillColor(colors.HexColor("#f6a01a") if i % 2 else colors.HexColor("#0b4f6c"))
        c.rect(cx - 70 + i * 10, cy - 70, 10, 140, stroke=0, fill=1)
    c.restoreState()
    # Dashes, caps and joins.
    y = h - 380
    for i, (dash, cap, join) in enumerate([((), 0, 0), ((6, 3), 1, 1), ((12, 4, 2, 4), 2, 2), ((1, 5), 1, 0)]):
        c.saveState()
        c.setLineWidth(10 if i != 3 else 3)
        c.setDash(list(dash), 0)
        c.setLineCap(cap)
        c.setLineJoin(join)
        c.setStrokeColor(colors.HexColor("#146c94"))
        pth = c.beginPath()
        pth.moveTo(50 + i * 130, y)
        pth.lineTo(90 + i * 130, y - 50)
        pth.lineTo(130 + i * 130, y)
        c.drawPath(pth, stroke=1, fill=0)
        c.restoreState()
    # Bezier curves.
    c.saveState()
    c.setStrokeColor(colors.HexColor("#c0392b"))
    c.setLineWidth(2)
    pth = c.beginPath()
    pth.moveTo(40, h - 500)
    pth.curveTo(120, h - 400, 200, h - 600, 280, h - 500)
    pth.curveTo(340, h - 440, 400, h - 560, 480, h - 480)
    c.drawPath(pth, stroke=1, fill=0)
    c.setFillColor(colors.HexColor("#8e44ad"))
    c.setFillAlpha(0.4)
    pth = c.beginPath()
    pth.moveTo(60, h - 600)
    pth.curveTo(60, h - 540, 160, h - 540, 160, h - 600)
    pth.curveTo(160, h - 660, 60, h - 660, 60, h - 600)
    c.drawPath(pth, stroke=1, fill=1)
    c.restoreState()
    # Even-odd fill: a ring.
    c.saveState()
    c.setFillColor(colors.HexColor("#2c7a4b"))
    pth = c.beginPath()
    pth.circle(260, h - 600, 50)
    pth.circle(260, h - 600, 28)
    c.drawPath(pth, stroke=0, fill=1, fillMode=0)
    c.restoreState()
    # Text: rotated, scaled, with a stroke and a fill (render modes).
    c.saveState()
    c.translate(420, h - 640)
    c.rotate(25)
    c.setFont("Times-BoldItalic", 34)
    t = c.beginText(0, 0)
    t.setTextRenderMode(2)
    t.setFillColor(colors.HexColor("#f6a01a"))
    t.setStrokeColor(colors.HexColor("#0b4f6c"))
    t.textOut("exav")
    c.drawText(t)
    c.restoreState()
    c.saveState()
    c.setFont("Helvetica", 14)
    for i, s in enumerate([1.0, 0.8, 0.6]):
        c.saveState()
        c.translate(40, h - 720 - i * 22)
        c.scale(s * 1.5, s)
        c.drawString(0, 0, "Scaled text: the horizontal scale and the size change.")
        c.restoreState()
    c.restoreState()
    c.showPage()
    c.save()


field_report(os.path.join(OUT, "field-report.pdf"))
application_form(os.path.join(OUT, "application-form.pdf"))
annotations(os.path.join(OUT, "annotations.pdf"))
scan_pdf(os.path.join(OUT, "scan-mixed.pdf"))
vector_art(os.path.join(OUT, "vector-art.pdf"))
