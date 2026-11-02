#!/usr/bin/env python3
"""Writes sample.vsdx and themed.vsdx, the Visio drawings the tests read.

usage: python3 make_vsdx.py <output directory>

The text and the shapes are written for this crate (CC0). The part layout
follows the Visio file format reference and [MS-VSDX]; no other file is used.
"""
import struct
import sys
import zlib
import zipfile

NS = (
    "xmlns='http://schemas.microsoft.com/office/visio/2012/main' "
    "xmlns:r='http://schemas.openxmlformats.org/officeDocument/2006/relationships'"
)
REL = "http://schemas.microsoft.com/visio/2010/relationships"
OPC = "http://schemas.openxmlformats.org/package/2006/relationships"


def rels(items):
    body = "".join(
        f'<Relationship Id="{i}" Type="{t}" Target="{g}"/>' for i, t, g in items
    )
    return f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{OPC}">{body}</Relationships>'


def cell(n, v, f=None):
    return f"<Cell N='{n}' V='{v}'" + (f" F='{f}'" if f else "") + "/>"


def row(i, t, **c):
    cells = "".join(cell(k, v) for k, v in c.items())
    return f"<Row T='{t}' IX='{i}'>{cells}</Row>"


def rowf(i, t, cells):
    """A row whose cells are (name, value, formula)."""
    body = "".join(cell(n, v, f) for n, v, f in cells)
    return f"<Row T='{t}' IX='{i}'>{body}</Row>"


def rect(w, h, rel=False):
    t = ("RelMoveTo", "RelLineTo") if rel else ("MoveTo", "LineTo")
    return (
        row(1, t[0], X=0, Y=0)
        + row(2, t[1], X=w, Y=0)
        + row(3, t[1], X=w, Y=h)
        + row(4, t[1], X=0, Y=h)
        + row(5, t[1], X=0, Y=0)
    )


def geometry(rows, flags=""):
    return f"<Section N='Geometry' IX='0'>{flags}{rows}</Section>"


def png(w, h, rgb):
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def package(path, parts):
    z = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)
    z.writestr(
        "[Content_Types].xml",
        '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>'
        "</Types>",
    )
    z.writestr("_rels/.rels", rels([("rId1", REL + "/document", "visio/document.xml")]))
    for name, data in parts.items():
        z.writestr(name, data)
    z.close()


STYLES = """
<StyleSheets>
 <StyleSheet ID='0' NameU='No Style'>
  <Cell N='LineWeight' V='0.01'/><Cell N='LineColor' V='0'/><Cell N='LinePattern' V='1'/>
  <Cell N='FillForegnd' V='1'/><Cell N='FillBkgnd' V='0'/><Cell N='FillPattern' V='1'/>
  <Cell N='LeftMargin' V='0.05'/><Cell N='RightMargin' V='0.05'/><Cell N='TopMargin' V='0.05'/><Cell N='BottomMargin' V='0.05'/>
  <Cell N='VerticalAlign' V='1'/>
  <Section N='Character'><Row IX='0'><Cell N='Size' V='0.1666666667'/><Cell N='Font' V='0'/><Cell N='Color' V='0'/></Row></Section>
  <Section N='Paragraph'><Row IX='0'><Cell N='HorzAlign' V='1'/></Row></Section>
 </StyleSheet>
 <StyleSheet ID='1' NameU='Blue' LineStyle='0' FillStyle='0' TextStyle='0'>
  <Cell N='FillForegnd' V='24'/><Cell N='LineColor' V='25'/><Cell N='LineWeight' V='0.02'/>
 </StyleSheet>
</StyleSheets>"""

LAYERS = """<Section N='Layer'>
 <Row IX='0'><Cell N='Name' V='Shown'/><Cell N='Visible' V='1'/></Row>
 <Row IX='1'><Cell N='Name' V='Hidden'/><Cell N='Visible' V='0'/></Row></Section>"""


def sample(path):
    document = (
        f"<VisioDocument {NS}><Colors><ColorEntry IX='24' RGB='#336699'/><ColorEntry IX='25' RGB='#CC6600'/></Colors>"
        f"<FaceNames><FaceName NameU='Calibri'/><FaceName NameU='Arial'/></FaceNames>{STYLES}</VisioDocument>"
    )
    box = (
        "<Shape ID='1' Type='Shape' LineStyle='1' FillStyle='1' TextStyle='0'>"
        + cell("PinX", 1)
        + cell("PinY", 0.5)
        + cell("Width", 2, "User.Wide")
        + cell("Height", 1)
        + cell("LocPinX", 1, "Width*0.5")
        + cell("LocPinY", 0.5, "Height*0.5")
        + cell("TxtPinX", 1, "Width*0.5")
        + cell("TxtPinY", 0.5, "Height*0.5")
        + cell("TxtWidth", 2, "Width*1")
        + cell("TxtHeight", 1, "Height*1")
        + cell("TxtLocPinX", 1, "TxtWidth*0.5")
        + cell("TxtLocPinY", 0.5, "TxtHeight*0.5")
        + "<Section N='User'><Row N='Wide'>"
        + cell("Value", 2)
        + "</Row></Section>"
        + geometry(
            rowf(1, "MoveTo", [("X", 0, "Width*0"), ("Y", 0, "Height*0")])
            + rowf(2, "LineTo", [("X", 2, "Width*1"), ("Y", 0, "Height*0")])
            + rowf(3, "LineTo", [("X", 2, "Width*1"), ("Y", 1, "Height*1")])
            + rowf(4, "LineTo", [("X", 0, "Width*0"), ("Y", 1, "Height*1")])
            + rowf(5, "LineTo", [("X", 0, "Geometry1.X1"), ("Y", 0, "Geometry1.Y1")])
        )
        + "</Shape>"
    )
    masters = (
        f"<Masters {NS}><Master ID='5' NameU='Box' Name='Box'><Rel r:id='rId1'/></Master></Masters>"
    )
    pages = (
        f"<Pages {NS}>"
        f"<Page ID='0' Name='Plan' NameU='Plan' BackPage='2'><PageSheet>{cell('PageWidth', 11)}{cell('PageHeight', 8.5)}{LAYERS}</PageSheet><Rel r:id='rId1'/></Page>"
        f"<Page ID='1' Name='Detail' NameU='Detail'><PageSheet>{cell('PageWidth', 5.8)}{cell('PageHeight', 8.2)}</PageSheet><Rel r:id='rId2'/></Page>"
        f"<Page ID='2' Name='Back' NameU='Back' Background='1'><PageSheet>{cell('PageWidth', 11)}{cell('PageHeight', 8.5)}</PageSheet><Rel r:id='rId3'/></Page>"
        "</Pages>"
    )

    def sh(id, extra, body="", attrs="Type='Shape'"):
        return f"<Shape ID='{id}' {attrs}>{extra}{body}</Shape>"

    plan = [
        # An instance of the master, wider than it, with text and a link.
        sh(
            1,
            cell("PinX", 3)
            + cell("PinY", 7)
            + cell("Width", 4)
            + "<Section N='Hyperlink'><Row N='Link'>"
            + cell("Address", "https://example.org/")
            + cell("Description", "Example")
            + "</Row></Section>"
            + "<Section N='Character'><Row IX='0'>"
            + cell("Style", 1)
            + cell("Size", 0.25)
            + "</Row></Section>"
            + "<Section N='Geometry' IX='0'><Row T='LineTo' IX='3'>"
            + cell("X", 4)
            + "</Row></Section>",
            "<Text><cp IX='0'/>Wide box</Text>",
            "Type='Shape' Master='5'",
        ),
        # Another one, turned and mirrored, with its own colour.
        sh(
            2,
            cell("PinX", 8)
            + cell("PinY", 7)
            + cell("Angle", 0.5235987756)
            + cell("FlipX", 1)
            + cell("FillForegnd", "#00FF00"),
            "",
            "Type='Shape' Master='5'",
        ),
        # A dashed connector with an arrow, drawn from its begin to its end.
        sh(
            3,
            cell("PinX", 2)
            + cell("PinY", 5)
            + cell("Width", 3)
            + cell("Height", 0)
            + cell("LocPinX", 0)
            + cell("LocPinY", 0)
            + cell("LinePattern", 2)
            + cell("LineWeight", 0.02)
            + cell("LineColor", "#FF0000")
            + cell("EndArrow", 4)
            + cell("EndArrowSize", 3),
            geometry(
                row(1, "MoveTo", X=0, Y=0) + row(2, "LineTo", X=3, Y=0),
                cell("NoFill", 1),
            ),
        ),
        # On a layer that does not show.
        sh(
            4,
            cell("PinX", 5)
            + cell("PinY", 4)
            + cell("Width", 1)
            + cell("Height", 1)
            + cell("LayerMember", "1")
            + cell("FillPattern", 1)
            + cell("FillForegnd", "#123456"),
            geometry(rect(1, 1)) + "<Text>Hidden note</Text>",
        ),
        # A group with two members, in the group's own coordinates.
        "<Shape ID='5' Type='Group'>"
        + cell("PinX", 3)
        + cell("PinY", 2)
        + cell("Width", 2)
        + cell("Height", 1)
        + cell("LocPinX", 1)
        + cell("LocPinY", 0.5)
        + "<Shapes>"
        + sh(
            6,
            cell("PinX", 0.5)
            + cell("PinY", 0.5)
            + cell("Width", 1)
            + cell("Height", 1)
            + cell("LocPinX", 0.5)
            + cell("LocPinY", 0.5)
            + cell("LinePattern", 1)
            + cell("LineColor", "#000000")
            + cell("FillPattern", 1)
            + cell("FillForegnd", "#FF0000"),
            geometry(rect(1, 1)),
        )
        + sh(
            7,
            cell("PinX", 1.5)
            + cell("PinY", 0.5)
            + cell("Width", 1)
            + cell("Height", 1)
            + cell("LocPinX", 0.5)
            + cell("LocPinY", 0.5)
            + cell("FillPattern", 1)
            + cell("FillForegnd", "#0000FF"),
            geometry(
                row(1, "Ellipse", X=0.5, Y=0.5, A=1, B=0.5, C=0.5, D=1)
            ),
        )
        + "</Shapes></Shape>",
        # Text with no geometry, in a text block off to one side.
        sh(
            8,
            cell("PinX", 8)
            + cell("PinY", 3)
            + cell("Width", 2)
            + cell("Height", 1)
            + cell("LocPinX", 1)
            + cell("LocPinY", 0.5)
            + cell("TxtPinX", 1.5)
            + cell("TxtPinY", 0.5)
            + cell("TxtWidth", 1)
            + cell("TxtHeight", 1)
            + cell("TxtLocPinX", 0.5)
            + cell("TxtLocPinY", 0.5)
            + "<Section N='Paragraph'><Row IX='0'>"
            + cell("HorzAlign", 2)
            + "</Row></Section>",
            "<Text><cp IX='0'/>First line\nSecond line</Text>",
        ),
    ]
    detail = [
        # A picture of the package.
        sh(
            1,
            cell("PinX", 2)
            + cell("PinY", 5)
            + cell("Width", 2)
            + cell("Height", 1.5)
            + cell("LocPinX", 1)
            + cell("LocPinY", 0.75)
            + cell("ImgWidth", 2)
            + cell("ImgHeight", 1.5),
            "<ForeignData ForeignType='Bitmap'><Rel r:id='rId1'/></ForeignData>",
            "Type='Foreign'",
        ),
        # A link to the first page.
        sh(
            2,
            cell("PinX", 2)
            + cell("PinY", 2)
            + cell("Width", 1.5)
            + cell("Height", 0.5)
            + cell("LocPinX", 0.75)
            + cell("LocPinY", 0.25)
            + cell("FillPattern", 0)
            + cell("LinePattern", 1)
            + "<Section N='Hyperlink'><Row N='Back'>"
            + cell("SubAddress", "Plan")
            + "</Row></Section>",
            geometry(rect(1.5, 0.5)),
        ),
    ]
    back = [
        sh(
            1,
            cell("PinX", 5.5)
            + cell("PinY", 0.25)
            + cell("Width", 11)
            + cell("Height", 0.5)
            + cell("LocPinX", 5.5)
            + cell("LocPinY", 0.25)
            + cell("FillPattern", 1)
            + cell("FillForegnd", "#CCCCCC"),
            geometry(rect(11, 0.5)),
        )
    ]
    contents = lambda shapes: f"<PageContents {NS}><Shapes>{''.join(shapes)}</Shapes></PageContents>"
    package(
        path,
        {
            "visio/document.xml": document,
            "visio/_rels/document.xml.rels": rels(
                [
                    ("rId1", REL + "/masters", "masters/masters.xml"),
                    ("rId2", REL + "/pages", "pages/pages.xml"),
                ]
            ),
            "visio/masters/masters.xml": masters,
            "visio/masters/_rels/masters.xml.rels": rels(
                [("rId1", REL + "/master", "master1.xml")]
            ),
            "visio/masters/master1.xml": f"<MasterContents {NS}><Shapes>{box}</Shapes></MasterContents>",
            "visio/pages/pages.xml": pages,
            "visio/pages/_rels/pages.xml.rels": rels(
                [
                    ("rId1", REL + "/page", "page1.xml"),
                    ("rId2", REL + "/page", "page2.xml"),
                    ("rId3", REL + "/page", "page3.xml"),
                ]
            ),
            "visio/pages/page1.xml": contents(plan),
            "visio/pages/page2.xml": contents(detail),
            "visio/pages/_rels/page2.xml.rels": rels(
                [
                    (
                        "rId1",
                        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                        "../media/image1.png",
                    )
                ]
            ),
            "visio/media/image1.png": png(4, 3, (200, 40, 40)),
            "visio/pages/page3.xml": contents(back),
        },
    )


THEME = """<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office"><a:themeElements>
<a:clrScheme name="Office"><a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>
<a:dk2><a:srgbClr val="44546A"/></a:dk2><a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>
<a:accent1><a:srgbClr val="4472C4"/></a:accent1><a:accent2><a:srgbClr val="ED7D31"/></a:accent2>
<a:accent3><a:srgbClr val="A5A5A5"/></a:accent3><a:accent4><a:srgbClr val="FFC000"/></a:accent4>
<a:accent5><a:srgbClr val="5B9BD5"/></a:accent5><a:accent6><a:srgbClr val="70AD47"/></a:accent6>
<a:hlink><a:srgbClr val="0563C1"/></a:hlink><a:folHlink><a:srgbClr val="954F72"/></a:folHlink>
<a:extLst><a:ext uri="{093E89EA-6996-430E-BFF9-83A9FAAAAB73}"><vt:bkgnd xmlns:vt="http://schemas.microsoft.com/office/visio/2012/theme"><a:srgbClr val="F0F0F0"/></vt:bkgnd></a:ext>
<a:ext uri="{DDD2D869-C2EF-471E-B8FA-914AFA308C9F}"><vt:variationClrSchemeLst xmlns:vt="http://schemas.microsoft.com/office/visio/2012/theme">
<vt:variationClrScheme><vt:varColor1><a:srgbClr val="111111"/></vt:varColor1><vt:varColor2><a:srgbClr val="222222"/></vt:varColor2></vt:variationClrScheme>
<vt:variationClrScheme><vt:varColor1><a:srgbClr val="AA0000"/></vt:varColor1><vt:varColor2><a:srgbClr val="00AA00"/></vt:varColor2></vt:variationClrScheme>
</vt:variationClrSchemeLst></a:ext></a:extLst></a:clrScheme>
<a:fontScheme name="Office"><a:majorFont><a:latin typeface="Georgia"/></a:majorFont><a:minorFont><a:latin typeface="Verdana"/></a:minorFont></a:fontScheme>
</a:themeElements></a:theme>"""


def themed(path):
    themed_cells = "".join(
        f"<Cell N='{n}' V='Themed' F='THEMEVAL()'/>"
        for n in ("LineColor", "FillForegnd", "FillPattern", "LinePattern")
    )
    document = (
        f"<VisioDocument {NS}><StyleSheets>"
        "<StyleSheet ID='0' NameU='No Style'><Cell N='LineWeight' V='0.01'/><Cell N='LineColor' V='0'/><Cell N='LinePattern' V='1'/>"
        "<Cell N='FillForegnd' V='1'/><Cell N='FillPattern' V='1'/>"
        "<Section N='Character'><Row IX='0'><Cell N='Size' V='0.1666666667'/><Cell N='Color' V='0'/></Row></Section></StyleSheet>"
        f"<StyleSheet ID='6' NameU='Theme' LineStyle='0' FillStyle='0' TextStyle='0'>{themed_cells}"
        "<Cell N='QuickStyleFillColor' V='100'/><Cell N='QuickStyleLineColor' V='100'/>"
        "<Section N='Character'><Row IX='0'><Cell N='Font' V='Themed' F='THEMEVAL()'/><Cell N='Color' V='Themed' F='THEMEVAL()'/></Row></Section></StyleSheet>"
        "<StyleSheet ID='7' NameU='Flow' LineStyle='6' FillStyle='6' TextStyle='6'/>"
        "</StyleSheets></VisioDocument>"
    )

    def box(id, x, quick):
        return (
            f"<Shape ID='{id}' Type='Shape' LineStyle='7' FillStyle='7' TextStyle='7'>"
            + cell("PinX", x)
            + cell("PinY", 1)
            + cell("Width", 1)
            + cell("Height", 1)
            + cell("LocPinX", 0.5)
            + cell("LocPinY", 0.5)
            + quick
            + geometry(rect(1, 1))
            + "<Text>Themed</Text></Shape>"
        )

    shapes = [
        # No quick style of its own: the root style sheet's colours.
        box(1, 1, ""),
        # Accent 1 of the theme.
        box(2, 3, cell("QuickStyleFillColor", 2) + cell("QuickStyleLineColor", 3)),
        # The second colour of the second variation.
        box(3, 5, cell("QuickStyleFillColor", 101) + cell("VariationColorIndex", 1)),
        # A variation that is not there: the first, and the background colour.
        box(4, 7, cell("QuickStyleFillColor", 201) + cell("VariationColorIndex", 65534)),
        box(5, 9, cell("QuickStyleFillColor", 8)),
    ]
    package(
        path,
        {
            "visio/document.xml": document,
            "visio/_rels/document.xml.rels": rels(
                [
                    ("rId2", REL + "/pages", "pages/pages.xml"),
                    (
                        "rId4",
                        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme",
                        "theme/theme1.xml",
                    ),
                ]
            ),
            "visio/theme/theme1.xml": THEME,
            "visio/pages/pages.xml": (
                f"<Pages {NS}><Page ID='0' Name='Themed' NameU='Themed'><PageSheet>{cell('PageWidth', 11)}{cell('PageHeight', 4)}</PageSheet><Rel r:id='rId1'/></Page></Pages>"
            ),
            "visio/pages/_rels/pages.xml.rels": rels([("rId1", REL + "/page", "page1.xml")]),
            "visio/pages/page1.xml": f"<PageContents {NS}><Shapes>{''.join(shapes)}</Shapes></PageContents>",
        },
    )


if __name__ == "__main__":
    out = sys.argv[1]
    sample(out + "/sample.vsdx")
    themed(out + "/themed.vsdx")
