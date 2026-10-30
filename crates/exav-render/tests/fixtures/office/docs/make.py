#!/usr/bin/env python3
"""Writes sample.odt, sample.fodt and sample.rtf: a heading, a paragraph with
bold and italic words, a bulleted list and a table. The text is ours (CC0).
sample.doc is the ODT converted to DOC by an office application, as a black
box; see README.md.
"""
import zipfile, pathlib

HERE = pathlib.Path(__file__).parent

NS = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" '
    'xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"'
)

STYLES = """<office:font-face-decls><style:font-face style:name="Liberation Serif" svg:font-family="'Liberation Serif'"/></office:font-face-decls>
<office:styles>
<style:default-style style:family="paragraph"><style:text-properties style:font-name="Liberation Serif" fo:font-size="12pt"/></style:default-style>
<style:style style:name="Standard" style:family="paragraph"/>
<style:style style:name="Heading_20_1" style:display-name="Heading 1" style:family="paragraph" style:parent-style-name="Standard" style:default-outline-level="1"><style:paragraph-properties fo:margin-top="0.4cm" fo:margin-bottom="0.2cm"/><style:text-properties fo:font-size="18pt" fo:font-weight="bold"/></style:style>
<text:list-style style:name="Bullets"><text:list-level-style-bullet text:level="1" text:bullet-char="&#8226;"><style:list-level-properties text:list-level-position-and-space-mode="label-alignment"><style:list-level-label-alignment text:label-followed-by="listtab" fo:text-indent="-0.5cm" fo:margin-left="1cm"/></style:list-level-properties></text:list-level-style-bullet></text:list-style>
</office:styles>
<office:automatic-styles>
<style:page-layout style:name="pm1"><style:page-layout-properties fo:page-width="21cm" fo:page-height="29.7cm" fo:margin-top="2cm" fo:margin-bottom="2cm" fo:margin-left="2cm" fo:margin-right="2cm"/></style:page-layout>
</office:automatic-styles>
<office:master-styles><style:master-page style:name="Standard" style:page-layout-name="pm1"/></office:master-styles>"""

BODY = """<office:body><office:text>
<text:h text:style-name="Heading_20_1" text:outline-level="1">Quarterly summary</text:h>
<text:p text:style-name="Standard">Revenue grew by <text:span text:style-name="B">twelve percent</text:span> over the quarter, while costs stayed <text:span text:style-name="I">flat</text:span>.</text:p>
<text:list text:style-name="Bullets"><text:list-item><text:p text:style-name="Standard">First item</text:p></text:list-item><text:list-item><text:p text:style-name="Standard">Second item</text:p></text:list-item></text:list>
<table:table table:name="T1" table:style-name="T1"><table:table-column table:style-name="C1" table:number-columns-repeated="2"/>
<table:table-row><table:table-cell table:style-name="Cell"><text:p text:style-name="Standard">Region</text:p></table:table-cell><table:table-cell table:style-name="Cell"><text:p text:style-name="Standard">Sales</text:p></table:table-cell></table:table-row>
<table:table-row><table:table-cell table:style-name="Cell"><text:p text:style-name="Standard">North</text:p></table:table-cell><table:table-cell table:style-name="Cell"><text:p text:style-name="Standard">120</text:p></table:table-cell></table:table-row>
</table:table>
<text:p text:style-name="Standard">End of the summary.</text:p>
</office:text></office:body>"""

AUTO = """<office:automatic-styles>
<style:style style:name="B" style:family="text"><style:text-properties fo:font-weight="bold"/></style:style>
<style:style style:name="I" style:family="text"><style:text-properties fo:font-style="italic"/></style:style>
<style:style style:name="T1" style:family="table"><style:table-properties style:width="12cm"/></style:style>
<style:style style:name="C1" style:family="table-column"><style:table-column-properties style:column-width="6cm"/></style:style>
<style:style style:name="Cell" style:family="table-cell"><style:table-cell-properties fo:border="0.5pt solid #000000" fo:padding="0.1cm"/></style:style>
</office:automatic-styles>"""

MIME = "application/vnd.oasis.opendocument.text"


def odt():
    content = f'<?xml version="1.0" encoding="UTF-8"?><office:document-content {NS} office:version="1.2">{AUTO}{BODY}</office:document-content>'
    styles = f'<?xml version="1.0" encoding="UTF-8"?><office:document-styles {NS} office:version="1.2">{STYLES}</office:document-styles>'
    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">'
        f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{MIME}"/>'
        '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
        '<manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>'
        "</manifest:manifest>"
    )
    with zipfile.ZipFile(HERE / "sample.odt", "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype", (2020, 1, 1, 0, 0, 0)), MIME)
        for name, data in (("content.xml", content), ("styles.xml", styles), ("META-INF/manifest.xml", manifest)):
            z.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)


def fodt():
    styles = STYLES.replace("<office:automatic-styles>", "<office:automatic-styles>", 1)
    # One tree: styles, then the content's automatic styles with the body.
    auto = AUTO.replace("<office:automatic-styles>", "").replace("</office:automatic-styles>", "")
    styles = styles.replace("</office:automatic-styles>", auto + "</office:automatic-styles>")
    doc = f'<?xml version="1.0" encoding="UTF-8"?><office:document {NS} office:version="1.2" office:mimetype="{MIME}">{styles}{BODY}</office:document>'
    (HERE / "sample.fodt").write_text(doc, encoding="utf-8")


RTF = r"""{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0\froman\fcharset0 Liberation Serif;}}
{\colortbl;\red0\green0\blue0;\red192\green0\blue0;}
\paperw11906\paperh16838\margl1134\margr1134\margt1134\margb1134
\pard\sa120\b\fs36 Quarterly summary\par
\pard\plain\f0\fs24 Revenue grew by \b twelve percent\b0  over the quarter, while costs stayed \i flat\i0 .\par
\pard\fi-283\li567 \bullet\tab First item\par
\pard\fi-283\li567 \bullet\tab Second item\par
\pard\trowd\trgaph108\cellx3000\cellx6000
\intbl Region\cell Sales\cell\row
\trowd\trgaph108\cellx3000\cellx6000
\intbl North\cell 120\cell\row
\pard End of the summary.\par
}
"""


odt()
fodt()
(HERE / "sample.rtf").write_text(RTF, encoding="ascii")
