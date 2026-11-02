//! The presentation model to a PPTX package (ECMA-376 PresentationML).
//! Parts are written in reading order: the package's own parts, the
//! presentation, themes, masters and layouts, then each slide followed by
//! the pictures it is the first to use, so that a reader of the ZIP from its
//! start meets the first slide early.

mod draw;
mod text;
pub(crate) mod xml;

use crate::formats::office::common::package::{Lift, Out};
use crate::formats::office::slides::error::{Error, Result};
use crate::formats::office::slides::model::*;
use draw::{Ctx, Rels};
use std::fmt::Write as _;
use std::io::Write;
use xml::{XML_HEAD, esc, hex, ns_decl};

fn zip_err(e: impl std::fmt::Display) -> Error {
    let s = e.to_string();
    if s.contains("too large") {
        Error::TooLarge("output")
    } else {
        Error::Malformed(format!("writing the package: {s}"))
    }
}

struct Package {
    // Dropped first: see `Lift`.
    _lift: Lift,
    z: zip::ZipWriter<Out>,
}

impl Package {
    fn put(&mut self, name: &str, data: &[u8], compress: bool) -> Result<()> {
        let method = if compress {
            zip::CompressionMethod::Deflated
        } else {
            zip::CompressionMethod::Stored
        };
        let opt = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .compression_level(compress.then_some(6))
            .last_modified_time(zip::DateTime::default());
        self.z.start_file(name, opt).map_err(zip_err)?;
        self.z.write_all(data).map_err(zip_err)
    }
}

const CT_MAIN: &str = "application/vnd.openxmlformats-officedocument.presentationml";

fn mime(ext: &str) -> &'static str {
    match ext {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "tiff" => "image/tiff",
        "emf" => "image/x-emf",
        "wmf" => "image/x-wmf",
        "svg" => "image/svg+xml",
        "pict" => "image/pict",
        _ => "application/octet-stream",
    }
}

/// Writes `p` as a PPTX, failing past `limit` bytes of output.
/// The pictures' bytes are moved out of `p` and dropped once written.
pub(crate) fn write(p: &mut Presentation, limit: u64) -> Result<Vec<u8>> {
    let scales: Vec<(u32, u32)> = p.media.iter().map(tile_scale).collect();
    let mut data: Vec<Option<Vec<u8>>> = p
        .media
        .iter_mut()
        .map(|m| Some(std::mem::take(&mut m.data)))
        .collect();
    let p = &*p;
    // Sized for the pictures, which are most of a large deck, so that the
    // buffer is not grown to twice its size on the way.
    let media: u64 = data.iter().flatten().map(|d| d.len() as u64).sum();
    let guess = media + (64 << 10) + p.slides.len() as u64 * (8 << 10);
    let (out, lift) = Out::new(guess.min(limit) as usize, limit);
    let mut pkg = Package {
        _lift: lift,
        z: zip::ZipWriter::new(out),
    };
    let width = p.width.clamp(914_400, 51_206_400);
    let height = p.height.clamp(914_400, 51_206_400);

    // Masters, each with at least one layout.
    let mut layouts: Vec<(usize, usize)> = vec![];
    for (mi, m) in p.masters.iter().enumerate() {
        for li in 0..m.layouts.len().max(1) {
            layouts.push((mi, li));
        }
    }
    let masters = p.masters.len().max(1);
    let media_names: Vec<String> = p
        .media
        .iter()
        .enumerate()
        .map(|(i, m)| format!("image{}.{}", i + 1, m.ext))
        .collect();
    let slide_names: Vec<String> = (1..=p.slides.len())
        .map(|i| format!("slide{i}.xml"))
        .collect();

    // [Content_Types].xml
    let mut ct = format!(
        "{XML_HEAD}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/>"
    );
    let mut exts: Vec<&str> = p.media.iter().map(|m| m.ext).collect();
    exts.sort_unstable();
    exts.dedup();
    for e in exts {
        let _ = write!(
            ct,
            "<Default Extension=\"{e}\" ContentType=\"{}\"/>",
            mime(e)
        );
    }
    let mut over = |name: &str, t: &str| {
        let _ = write!(ct, "<Override PartName=\"/{name}\" ContentType=\"{t}\"/>");
    };
    over(
        "ppt/presentation.xml",
        &format!("{CT_MAIN}.presentation.main+xml"),
    );
    over("ppt/presProps.xml", &format!("{CT_MAIN}.presProps+xml"));
    over("ppt/viewProps.xml", &format!("{CT_MAIN}.viewProps+xml"));
    over("ppt/tableStyles.xml", &format!("{CT_MAIN}.tableStyles+xml"));
    over(
        "docProps/core.xml",
        "application/vnd.openxmlformats-package.core-properties+xml",
    );
    over(
        "docProps/app.xml",
        "application/vnd.openxmlformats-officedocument.extended-properties+xml",
    );
    for i in 1..=masters {
        over(
            &format!("ppt/theme/theme{i}.xml"),
            "application/vnd.openxmlformats-officedocument.theme+xml",
        );
        over(
            &format!("ppt/slideMasters/slideMaster{i}.xml"),
            &format!("{CT_MAIN}.slideMaster+xml"),
        );
    }
    for i in 1..=layouts.len().max(1) {
        over(
            &format!("ppt/slideLayouts/slideLayout{i}.xml"),
            &format!("{CT_MAIN}.slideLayout+xml"),
        );
    }
    for n in &slide_names {
        over(&format!("ppt/slides/{n}"), &format!("{CT_MAIN}.slide+xml"));
    }
    let charts: usize = p
        .masters
        .iter()
        .map(|m| {
            draw::count_charts(&m.shapes)
                + m.layouts
                    .iter()
                    .map(|l| draw::count_charts(&l.shapes))
                    .sum::<usize>()
        })
        .sum::<usize>()
        + p.slides
            .iter()
            .map(|s| draw::count_charts(&s.shapes))
            .sum::<usize>();
    for i in 1..=charts {
        over(
            &format!("ppt/charts/chart{i}.xml"),
            "application/vnd.openxmlformats-officedocument.drawingml.chart+xml",
        );
    }
    ct.push_str("</Types>");
    pkg.put("[Content_Types].xml", ct.as_bytes(), true)?;

    let mut root = Rels::default();
    root.add("officeDocument", "ppt/presentation.xml".into(), false);
    root.add(
        "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
        "docProps/core.xml".into(),
        false,
    );
    root.add("extended-properties", "docProps/app.xml".into(), false);
    pkg.put("_rels/.rels", root.xml().as_bytes(), true)?;
    pkg.put("docProps/core.xml", format!("{XML_HEAD}<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/>").as_bytes(), true)?;
    pkg.put("docProps/app.xml", format!("{XML_HEAD}<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"><Application>exav-render</Application><Slides>{}</Slides></Properties>", p.slides.len()).as_bytes(), true)?;

    // The presentation.
    let mut prels = Rels::default();
    let mut pres = format!(
        "{XML_HEAD}<p:presentation {} saveSubsetFonts=\"1\"><p:sldMasterIdLst>",
        ns_decl()
    );
    for i in 1..=masters {
        let id = prels.add(
            "slideMaster",
            format!("slideMasters/slideMaster{i}.xml"),
            false,
        );
        let _ = write!(
            pres,
            "<p:sldMasterId id=\"{}\" r:id=\"{id}\"/>",
            2_147_483_647 + i * 100
        );
    }
    pres.push_str("</p:sldMasterIdLst>");
    if !slide_names.is_empty() {
        pres.push_str("<p:sldIdLst>");
        for (i, n) in slide_names.iter().enumerate() {
            let id = prels.add("slide", format!("slides/{n}"), false);
            let _ = write!(pres, "<p:sldId id=\"{}\" r:id=\"{id}\"/>", 256 + i);
        }
        pres.push_str("</p:sldIdLst>");
    }
    let _ = write!(
        pres,
        "<p:sldSz cx=\"{width}\" cy=\"{height}\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/>"
    );
    pres.push_str("<p:defaultTextStyle><a:defPPr><a:defRPr lang=\"en-US\"/></a:defPPr></p:defaultTextStyle></p:presentation>");
    for i in 1..=masters {
        prels.add("theme", format!("theme/theme{i}.xml"), false);
    }
    prels.add("presProps", "presProps.xml".into(), false);
    prels.add("viewProps", "viewProps.xml".into(), false);
    prels.add("tableStyles", "tableStyles.xml".into(), false);
    pkg.put("ppt/presentation.xml", pres.as_bytes(), true)?;
    pkg.put(
        "ppt/_rels/presentation.xml.rels",
        prels.xml().as_bytes(),
        true,
    )?;
    let ns = ns_decl();
    pkg.put(
        "ppt/presProps.xml",
        format!("{XML_HEAD}<p:presentationPr {ns}/>").as_bytes(),
        true,
    )?;
    pkg.put("ppt/viewProps.xml", format!("{XML_HEAD}<p:viewPr {ns}><p:normalViewPr><p:restoredLeft sz=\"15620\"/><p:restoredTop sz=\"94660\"/></p:normalViewPr><p:gridSpacing cx=\"76200\" cy=\"76200\"/></p:viewPr>").as_bytes(), true)?;
    pkg.put("ppt/tableStyles.xml", format!("{XML_HEAD}<a:tblStyleLst xmlns:a=\"{}\" def=\"{{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}}\"/>", xml::NS_A).as_bytes(), true)?;

    let mut charts_done = 0usize;
    let fallback = Master::default();
    // Themes and masters.
    let mut layout_no = 0usize;
    for mi in 0..masters {
        let m = p.masters.get(mi).unwrap_or(&fallback);
        pkg.put(
            &format!("ppt/theme/theme{}.xml", mi + 1),
            theme(&m.theme).as_bytes(),
            true,
        )?;
        let mut ctx = Ctx::new(&media_names, &scales, &slide_names, charts_done);
        let mut x = format!("{XML_HEAD}<p:sldMaster {ns}><p:cSld>");
        let bg = m
            .background
            .clone()
            .or(Some(Fill::Solid(Color::rgb(0xFFFFFF))));
        draw::background(&mut x, &bg, &mut ctx);
        draw::tree(&mut x, &m.shapes, &mut ctx);
        x.push_str("</p:cSld><p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/><p:sldLayoutIdLst>");
        let n_layouts = m.layouts.len().max(1);
        let mut lrels = vec![];
        for k in 0..n_layouts {
            let id = ctx.rels.add(
                "slideLayout",
                format!("../slideLayouts/slideLayout{}.xml", layout_no + k + 1),
                false,
            );
            let _ = write!(
                x,
                "<p:sldLayoutId id=\"{}\" r:id=\"{id}\"/>",
                2_147_483_648 + mi * 100 + k + 1
            );
            lrels.push(id);
        }
        x.push_str("</p:sldLayoutIdLst><p:txStyles>");
        text::list_style(&mut x, "p:titleStyle", &m.title_style, &mut ctx);
        text::list_style(&mut x, "p:bodyStyle", &m.body_style, &mut ctx);
        text::list_style(&mut x, "p:otherStyle", &m.other_style, &mut ctx);
        x.push_str("</p:txStyles></p:sldMaster>");
        ctx.rels
            .add("theme", format!("../theme/theme{}.xml", mi + 1), false);
        pkg.put(
            &format!("ppt/slideMasters/slideMaster{}.xml", mi + 1),
            x.as_bytes(),
            true,
        )?;
        pkg.put(
            &format!("ppt/slideMasters/_rels/slideMaster{}.xml.rels", mi + 1),
            ctx.rels.xml().as_bytes(),
            true,
        )?;
        put_media(&mut pkg, p, &media_names, &ctx.used, &mut data)?;
        charts_done = put_charts(&mut pkg, &ctx)?;

        let blank = Layout {
            name: "Blank".into(),
            kind: "blank",
            show_master_shapes: true,
            ..Layout::default()
        };
        for k in 0..n_layouts {
            layout_no += 1;
            let l = m.layouts.get(k).unwrap_or(&blank);
            let mut ctx = Ctx::new(&media_names, &scales, &slide_names, charts_done);
            let kind = if l.kind.is_empty() { "blank" } else { l.kind };
            let mut x = format!("{XML_HEAD}<p:sldLayout {ns} type=\"{kind}\" preserve=\"1\"");
            if !l.show_master_shapes {
                x.push_str(" showMasterSp=\"0\"");
            }
            let name = if l.name.is_empty() { "Layout" } else { &l.name };
            let _ = write!(x, "><p:cSld name=\"{}\">", esc(name));
            draw::background(&mut x, &l.background, &mut ctx);
            draw::tree(&mut x, &l.shapes, &mut ctx);
            x.push_str("</p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>");
            ctx.rels.add(
                "slideMaster",
                format!("../slideMasters/slideMaster{}.xml", mi + 1),
                false,
            );
            pkg.put(
                &format!("ppt/slideLayouts/slideLayout{layout_no}.xml"),
                x.as_bytes(),
                true,
            )?;
            pkg.put(
                &format!("ppt/slideLayouts/_rels/slideLayout{layout_no}.xml.rels"),
                ctx.rels.xml().as_bytes(),
                true,
            )?;
            put_media(&mut pkg, p, &media_names, &ctx.used, &mut data)?;
            charts_done = put_charts(&mut pkg, &ctx)?;
        }
    }

    // Slides.
    for (i, s) in p.slides.iter().enumerate() {
        let mut ctx = Ctx::new(&media_names, &scales, &slide_names, charts_done);
        // The layout first: rId1, as PowerPoint writes it.
        let li = layouts
            .iter()
            .position(|&(m, l)| m == s.master.min(masters - 1) && l == s.layout)
            .or_else(|| {
                layouts
                    .iter()
                    .position(|&(m, _)| m == s.master.min(masters - 1))
            })
            .unwrap_or(0);
        ctx.rels.add(
            "slideLayout",
            format!("../slideLayouts/slideLayout{}.xml", li + 1),
            false,
        );
        let mut x = format!("{XML_HEAD}<p:sld {ns}");
        if s.hidden {
            x.push_str(" show=\"0\"");
        }
        if !s.show_master_shapes {
            x.push_str(" showMasterSp=\"0\"");
        }
        match &s.name {
            Some(name) => {
                let _ = write!(x, "><p:cSld name=\"{}\">", esc(name));
            }
            None => x.push_str("><p:cSld>"),
        }
        draw::background(&mut x, &s.background, &mut ctx);
        // A slide's XML is held whole: it is bound by what the conversion
        // has left, as its output is.
        ctx.limit = usize::try_from(limit).unwrap_or(usize::MAX);
        draw::tree(&mut x, &s.shapes, &mut ctx);
        if ctx.over {
            return Err(Error::TooLarge("memory"));
        }
        x.push_str("</p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>");
        pkg.put(
            &format!("ppt/slides/{}", slide_names[i]),
            x.as_bytes(),
            true,
        )?;
        pkg.put(
            &format!("ppt/slides/_rels/{}.rels", slide_names[i]),
            ctx.rels.xml().as_bytes(),
            true,
        )?;
        put_media(&mut pkg, p, &media_names, &ctx.used, &mut data)?;
        charts_done = put_charts(&mut pkg, &ctx)?;
    }

    pkg._lift.lift();
    let out = pkg.z.finish().map_err(zip_err)?;
    Ok(out.into_inner())
}

/// Writes the pictures of `used` not yet written, dropping their bytes.
/// A picture's tile scale: 100% unless its resolution is not 96 dpi.
fn tile_scale(m: &Media) -> (u32, u32) {
    use crate::formats::office::common::image::{natural_emu, pixel_size};
    let scale = |natural: i64, pixels: u32| {
        if pixels == 0 {
            return 100_000;
        }
        (natural as f64 / (f64::from(pixels) * 9525.0) * 100_000.0).clamp(100.0, 10_000_000.0)
            as u32
    };
    match (natural_emu(&m.data), pixel_size(&m.data)) {
        (Some((w, h)), Some((pw, ph))) if matches!(m.ext, "png" | "jpeg") => {
            (scale(w, pw), scale(h, ph))
        }
        _ => (100_000, 100_000),
    }
}

fn put_media(
    pkg: &mut Package,
    p: &Presentation,
    names: &[String],
    used: &[usize],
    data: &mut [Option<Vec<u8>>],
) -> Result<()> {
    for &m in used {
        if let Some(d) = data[m].take() {
            let compress = matches!(
                p.media[m].ext,
                "emf" | "wmf" | "bmp" | "tiff" | "svg" | "pict"
            );
            pkg.put(&format!("ppt/media/{}", names[m]), &d, compress)?;
        }
    }
    Ok(())
}

/// The chart parts a part added; the number of the last one.
fn put_charts(pkg: &mut Package, ctx: &Ctx) -> Result<usize> {
    for (n, xml) in &ctx.charts {
        pkg.put(&format!("ppt/charts/chart{n}.xml"), xml.as_bytes(), true)?;
    }
    Ok(ctx.chart_no)
}

fn theme(t: &Theme) -> String {
    let names = [
        "dk1", "lt1", "dk2", "lt2", "accent1", "accent2", "accent3", "accent4", "accent5",
        "accent6", "hlink", "folHlink",
    ];
    let mut x = format!(
        "{XML_HEAD}<a:theme xmlns:a=\"{}\" name=\"{}\"><a:themeElements><a:clrScheme name=\"{}\">",
        xml::NS_A,
        esc(&t.name),
        esc(&t.name)
    );
    for (n, c) in names.iter().zip(t.colors.iter()) {
        let _ = write!(x, "<a:{n}><a:srgbClr val=\"{}\"/></a:{n}>", hex(*c));
    }
    let _ = write!(
        x,
        "</a:clrScheme><a:fontScheme name=\"{}\"><a:majorFont><a:latin typeface=\"{}\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:majorFont><a:minorFont><a:latin typeface=\"{}\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:minorFont></a:fontScheme>",
        esc(&t.name),
        esc(&t.major_font),
        esc(&t.minor_font)
    );
    x.push_str("<a:fmtScheme name=\"Office\"><a:fillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w=\"6350\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"12700\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"19050\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>");
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG's header with a resolution in dots per metre.
    fn png(w: u32, h: u32, dpm: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 2, 0, 0, 0, 0, 0, 0, 0]);
        v.extend_from_slice(&9u32.to_be_bytes());
        v.extend_from_slice(b"pHYs");
        v.extend_from_slice(&dpm.to_be_bytes());
        v.extend_from_slice(&dpm.to_be_bytes());
        v.push(1);
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"IDAT");
        v
    }

    #[test]
    fn tiles_are_scaled_to_the_pictures_resolution() {
        // 96 dpi is 3780 dots per metre: no scaling.
        let m = Media {
            ext: "png",
            data: png(100, 50, 3780),
        };
        let (sx, sy) = tile_scale(&m);
        assert!((99_900..=100_100).contains(&sx) && sx == sy, "{sx} {sy}");
        // Twice the resolution: half the size.
        let m = Media {
            ext: "png",
            data: png(100, 50, 7559),
        };
        let (sx, _) = tile_scale(&m);
        assert!((49_900..=50_100).contains(&sx), "{sx}");
        // Not a picture of a known resolution.
        let m = Media {
            ext: "svg",
            data: b"<svg/>".to_vec(),
        };
        assert_eq!(tile_scale(&m), (100_000, 100_000));
    }
}
