//! A sheet's drawing part: pictures, charts and shapes, anchored to cells.

use super::xml::{esc, esc_into, rgb};
use super::{Numbers, Package, Rels, XML_HEAD};
use crate::formats::office::sheets::error::Result;
use crate::formats::office::sheets::model::*;
use std::fmt::Write as _;

const NS_XDR: &str = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing";
const NS_A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
const NS_C: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";
const NS_R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
use crate::formats::office::sheets::geom::{EMU_PER_PX, Grid, col_px, row_px};

fn off(frac: i64, px: f64) -> i64 {
    (frac.clamp(0, 1_000_000) as f64 / 1e6 * px * EMU_PER_PX).round() as i64
}

fn anchor_xml(d: &mut String, sh: &Sheet, a: &Anchor, edit_as: &str) {
    let (fc, fr, fdx, fdy) = a.from;
    let (tc, tr, tdx, tdy) = a.to;
    let (fc, fr, tc, tr) = (
        fc.min(MAX_COL),
        fr.min(MAX_ROW),
        tc.min(MAX_COL),
        tr.min(MAX_ROW),
    );
    let _ = write!(
        d,
        "<xdr:twoCellAnchor editAs=\"{edit_as}\"><xdr:from><xdr:col>{fc}</xdr:col><xdr:colOff>{}</xdr:colOff><xdr:row>{fr}</xdr:row><xdr:rowOff>{}</xdr:rowOff></xdr:from><xdr:to><xdr:col>{tc}</xdr:col><xdr:colOff>{}</xdr:colOff><xdr:row>{tr}</xdr:row><xdr:rowOff>{}</xdr:rowOff></xdr:to>",
        off(fdx, col_px(sh, fc)),
        off(fdy, row_px(sh, fr)),
        off(tdx, col_px(sh, tc)),
        off(tdy, row_px(sh, tr))
    );
}

fn mime(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "emf" => "image/x-emf",
        "wmf" => "image/x-wmf",
        "bmp" => "image/bmp",
        "tiff" => "image/tiff",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pict" => "image/pict",
        _ => "application/octet-stream",
    }
}

fn chart_frame(d: &mut String, id: usize, name: &str, rid: &str) {
    let _ = write!(
        d,
        "<xdr:graphicFrame macro=\"\"><xdr:nvGraphicFramePr><xdr:cNvPr id=\"{id}\" name=\"{}\"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr><xdr:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/></xdr:xfrm><a:graphic><a:graphicData uri=\"{NS_C}\"><c:chart xmlns:c=\"{NS_C}\" r:id=\"{rid}\"/></a:graphicData></a:graphic></xdr:graphicFrame>",
        esc(name)
    );
}

fn shape_xml(d: &mut String, sh: &Sheet, grid: &Grid, shp: &Shape, id: usize) {
    anchor_xml(d, sh, &shp.anchor, "absolute");
    let a = &shp.anchor;
    let emu = |px: f64| (px * EMU_PER_PX) as i64;
    let (x0, y0) = (
        emu(grid.x(sh, a.from.0, a.from.2)),
        emu(grid.y(sh, a.from.1, a.from.3)),
    );
    let (x1, y1) = (
        emu(grid.x(sh, a.to.0, a.to.2)),
        emu(grid.y(sh, a.to.1, a.to.3)),
    );
    // Lines are shapes too (not connection shapes), which readers draw.
    let line = shp.geom == "line" || shp.geom == "straightConnector1";
    let tag = "sp";
    let _ = write!(
        d,
        "<xdr:sp macro=\"\" textlink=\"\"><xdr:nvSpPr><xdr:cNvPr id=\"{id}\" name=\""
    );
    esc_into(d, &shp.name);
    d.push_str("\"/><xdr:cNvSpPr/></xdr:nvSpPr><xdr:spPr><a:xfrm");
    if shp.rotation != 0.0 {
        let _ = write!(
            d,
            " rot=\"{}\"",
            (shp.rotation.rem_euclid(360.0) * 60000.0).round() as i64
        );
    }
    if shp.flip_h {
        d.push_str(" flipH=\"1\"");
    }
    if shp.flip_v {
        d.push_str(" flipV=\"1\"");
    }
    let _ = write!(
        d,
        "><a:off x=\"{}\" y=\"{}\"/><a:ext cx=\"{}\" cy=\"{}\"/></a:xfrm>",
        x0.min(x1),
        y0.min(y1),
        (x1 - x0).abs(),
        (y1 - y0).abs()
    );
    let _ = write!(
        d,
        "<a:prstGeom prst=\"{}\"><a:avLst/></a:prstGeom>",
        shp.geom
    );
    if !line {
        match shp.fill {
            Some(c) => {
                let _ = write!(
                    d,
                    "<a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>",
                    rgb(c)
                );
            }
            None => d.push_str("<a:noFill/>"),
        }
    }
    match shp.line {
        Some(c) => {
            d.push_str("<a:ln");
            if let Some(w) = shp.line_width {
                let _ = write!(d, " w=\"{}\"", w.clamp(0, 20_116_800));
            }
            let _ = write!(
                d,
                "><a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>",
                rgb(c)
            );
            if let Some(dash) = shp.line_dash {
                let _ = write!(d, "<a:prstDash val=\"{dash}\"/>");
            }
            if shp.head_arrow {
                d.push_str("<a:headEnd type=\"triangle\"/>");
            }
            if shp.tail_arrow {
                d.push_str("<a:tailEnd type=\"triangle\"/>");
            }
            d.push_str("</a:ln>");
        }
        None => d.push_str("<a:ln><a:noFill/></a:ln>"),
    }
    d.push_str("</xdr:spPr>");
    if !line && !shp.text.text.is_empty() {
        let t = &shp.text;
        d.push_str("<xdr:txBody><a:bodyPr");
        if let Some(an) = t.anchor {
            let _ = write!(d, " anchor=\"{an}\"");
        }
        d.push_str("/><a:lstStyle/>");
        for p in t.text.split('\n') {
            d.push_str("<a:p>");
            if let Some(al) = t.align {
                let _ = write!(d, "<a:pPr algn=\"{al}\"/>");
            }
            if !p.is_empty() {
                d.push_str("<a:r>");
                if let Some(f) = &t.font {
                    let _ = write!(
                        d,
                        "<a:rPr lang=\"en-US\" sz=\"{}\" b=\"{}\" i=\"{}\"",
                        (f.size_centipt).clamp(100, 400_000),
                        u8::from(f.bold),
                        u8::from(f.italic)
                    );
                    if f.underline.is_some() {
                        d.push_str(" u=\"sng\"");
                    }
                    d.push('>');
                    if let Some(c) = f.color {
                        let _ = write!(
                            d,
                            "<a:solidFill><a:srgbClr val=\"{}\"/></a:solidFill>",
                            rgb(c)
                        );
                    }
                    let _ = write!(
                        d,
                        "<a:latin typeface=\"{}\"/></a:rPr>",
                        esc(super::ms_font_name(&f.name))
                    );
                }
                d.push_str("<a:t>");
                esc_into(d, p);
                d.push_str("</a:t></a:r>");
            }
            d.push_str("</a:p>");
        }
        d.push_str("</xdr:txBody>");
    }
    let _ = write!(d, "</xdr:{tag}><xdr:clientData/></xdr:twoCellAnchor>");
}

/// Writes the sheet's drawing, its pictures and charts; returns the
/// relationship id the worksheet names it by.
pub(crate) fn drawing(
    pkg: &mut Package,
    sh: &Sheet,
    rels: &mut Rels,
    n: &mut Numbers,
) -> Result<Option<String>> {
    if sh.images.is_empty() && sh.charts.is_empty() && sh.shapes.is_empty() {
        return Ok(None);
    }
    n.drawing += 1;
    let k = n.drawing;
    let mut d = format!(
        "{XML_HEAD}<xdr:wsDr xmlns:xdr=\"{NS_XDR}\" xmlns:a=\"{NS_A}\" xmlns:r=\"{NS_R}\">"
    );
    let mut drels = Rels::default();
    let mut id = 1usize;
    for img in &sh.images {
        n.image += 1;
        let ext = img.ext;
        pkg.put(&format!("xl/media/image{}.{ext}", n.image), &img.data)?;
        pkg.default_type(ext, mime(ext));
        let rid = drels.add("image", format!("../media/image{}.{ext}", n.image), false);
        anchor_xml(&mut d, sh, &img.anchor, "oneCell");
        id += 1;
        let _ = write!(
            d,
            "<xdr:pic><xdr:nvPicPr><xdr:cNvPr id=\"{id}\" name=\"{}\"/><xdr:cNvPicPr/></xdr:nvPicPr><xdr:blipFill><a:blip r:embed=\"{rid}\"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill><xdr:spPr><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:twoCellAnchor>",
            esc(&img.name)
        );
    }
    for (i, ch) in sh.charts.iter().enumerate() {
        n.chart += 1;
        pkg.part(
            &format!("xl/charts/chart{}.xml", n.chart),
            super::chart::chart_xml(ch).as_bytes(),
            "application/vnd.openxmlformats-officedocument.drawingml.chart+xml",
        )?;
        let rid = drels.add("chart", format!("../charts/chart{}.xml", n.chart), false);
        anchor_xml(&mut d, sh, &ch.anchor, "oneCell");
        id += 1;
        chart_frame(&mut d, id, &format!("Chart {}", i + 1), &rid);
        d.push_str("<xdr:clientData/></xdr:twoCellAnchor>");
    }
    if !sh.shapes.is_empty() {
        let grid = Grid::for_anchors(sh, sh.shapes.iter().map(|s| s.anchor));
        for shp in &sh.shapes {
            id += 1;
            shape_xml(&mut d, sh, &grid, shp, id);
        }
    }
    d.push_str("</xdr:wsDr>");
    pkg.part(
        &format!("xl/drawings/drawing{k}.xml"),
        d.as_bytes(),
        "application/vnd.openxmlformats-officedocument.drawing+xml",
    )?;
    pkg.put(
        &format!("xl/drawings/_rels/drawing{k}.xml.rels"),
        drels.xml().as_bytes(),
    )?;
    Ok(Some(rels.add(
        "drawing",
        format!("../drawings/drawing{k}.xml"),
        false,
    )))
}

/// A chart sheet: its first chart over the whole sheet.
pub(crate) fn chartsheet(
    pkg: &mut Package,
    wb: &Workbook,
    si: usize,
    n: &mut Numbers,
) -> Result<Rels> {
    let sh = &wb.sheets[si];
    let mut rels = Rels::default();
    n.drawing += 1;
    n.chart += 1;
    let k = n.drawing;
    pkg.part(
        &format!("xl/charts/chart{}.xml", n.chart),
        super::chart::chart_xml(&sh.charts[0]).as_bytes(),
        "application/vnd.openxmlformats-officedocument.drawingml.chart+xml",
    )?;
    let mut drels = Rels::default();
    let rid = drels.add("chart", format!("../charts/chart{}.xml", n.chart), false);
    let mut d = format!(
        "{XML_HEAD}<xdr:wsDr xmlns:xdr=\"{NS_XDR}\" xmlns:a=\"{NS_A}\" xmlns:r=\"{NS_R}\"><xdr:absoluteAnchor><xdr:pos x=\"0\" y=\"0\"/><xdr:ext cx=\"9293679\" cy=\"6068786\"/>"
    );
    chart_frame(&mut d, 2, "Chart 1", &rid);
    d.push_str("<xdr:clientData/></xdr:absoluteAnchor></xdr:wsDr>");
    pkg.part(
        &format!("xl/drawings/drawing{k}.xml"),
        d.as_bytes(),
        "application/vnd.openxmlformats-officedocument.drawing+xml",
    )?;
    pkg.put(
        &format!("xl/drawings/_rels/drawing{k}.xml.rels"),
        drels.xml().as_bytes(),
    )?;
    let drid = rels.add("drawing", format!("../drawings/drawing{k}.xml"), false);
    let x = format!(
        "{XML_HEAD}<chartsheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"{NS_R}\"><sheetPr/><sheetViews><sheetView{} workbookViewId=\"0\"/></sheetViews><pageMargins left=\"0.75\" right=\"0.75\" top=\"1\" bottom=\"1\" header=\"0.5\" footer=\"0.5\"/><drawing r:id=\"{drid}\"/></chartsheet>",
        if si == wb.active {
            " tabSelected=\"1\""
        } else {
            ""
        }
    );
    pkg.part(
        &format!("xl/chartsheets/sheet{}.xml", si + 1),
        x.as_bytes(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml",
    )?;
    Ok(rels)
}
