//! The HEADER section: `9 $NAME` followed by the variable's value groups.

use exav_unpack::dxf::{Decoder, Tag};

use super::{Ctx, Raw};
use crate::formats::cad::model::{Handle, Vec3, Version, WarningKind};

fn point(values: &[Tag<'_>]) -> Vec3 {
    let mut p = Vec3::default();
    for t in values {
        match t.code {
            10 => p.x = t.f64(),
            20 => p.y = t.f64(),
            30 => p.z = t.f64(),
            _ => {}
        }
    }
    p
}

fn first<'t, 'a>(values: &'t [Tag<'a>]) -> Option<&'t Tag<'a>> {
    values.first()
}

pub(crate) fn read(tags: &[Tag<'_>], raw: &mut Raw, ctx: &mut Ctx<'_>) {
    // Split into variables. Groups before the first 9 (the section's own 2)
    // belong to none.
    let mut vars: Vec<(String, &[Tag<'_>])> = Vec::new();
    let mut i = 0;
    while let Some(t) = tags.get(i) {
        if t.code != 9 {
            i += 1;
            continue;
        }
        let rest = tags.get(i + 1..).unwrap_or(&[]);
        let len = rest.iter().position(|t| t.code == 9).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(t.bytes())
            .trim()
            .to_ascii_uppercase();
        vars.push((name, rest.get(..len).unwrap_or(&[])));
        i += 1 + len;
    }

    let get = |name: &str| -> Option<&[Tag<'_>]> {
        vars.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
    };

    let h = &mut raw.header;
    raw.has_header = true;
    if let Some(v) = get("$ACADVER").and_then(first) {
        h.acadver = String::from_utf8_lossy(v.bytes()).trim().to_string();
        h.version = Version::from_acadver(&h.acadver);
    }
    if let Some(v) = get("$DWGCODEPAGE").and_then(first) {
        h.code_page = String::from_utf8_lossy(v.bytes()).trim().to_string();
    }
    ctx.version = h.version;
    let (decoder, known) = Decoder::for_drawing(&h.acadver, &h.code_page);
    ctx.decoder = decoder;
    ctx.code_page = Decoder::for_drawing("AC1018", &h.code_page).0;
    if !known {
        let message = format!(
            "code page {} is not supported; read as Windows-1252",
            h.code_page
        );
        ctx.warn(WarningKind::UnsupportedCodePage, message);
    }

    for (name, values) in &vars {
        let Some(v) = values.first() else {
            continue;
        };
        let h = &mut raw.header;
        match name.as_str() {
            "$HANDSEED" => h.handle_seed = Handle(v.handle()),
            "$INSBASE" => h.insbase = point(values),
            "$EXTMIN" => h.extmin = point(values),
            "$EXTMAX" => h.extmax = point(values),
            "$LIMMIN" => h.limmin = point(values).xy(),
            "$LIMMAX" => h.limmax = point(values).xy(),
            "$PINSBASE" => h.pinsbase = point(values),
            "$PEXTMIN" => h.pextmin = point(values),
            "$PEXTMAX" => h.pextmax = point(values),
            "$PLIMMIN" => h.plimmin = point(values).xy(),
            "$PLIMMAX" => h.plimmax = point(values).xy(),
            "$LTSCALE" => h.ltscale = v.f64(),
            "$CELTSCALE" => h.celtscale = v.f64(),
            "$PSLTSCALE" => h.psltscale = v.bool(),
            "$INSUNITS" => h.insunits = v.i16(),
            "$MEASUREMENT" => h.measurement = v.i16(),
            "$LUNITS" => h.lunits = v.i16(),
            "$LUPREC" => h.luprec = v.i16(),
            "$TEXTSIZE" => h.textsize = v.f64(),
            "$TEXTSTYLE" => h.textstyle = ctx.text(v),
            "$CLAYER" => h.clayer = ctx.text(v),
            "$DIMSTYLE" => h.dimstyle = ctx.text(v),
            "$DIMSCALE" => h.dimscale = v.f64(),
            "$DIMASZ" => h.dimasz = v.f64(),
            "$DIMTXT" => h.dimtxt = v.f64(),
            "$DIMGAP" => h.dimgap = v.f64(),
            "$PDMODE" => h.pdmode = v.i16(),
            "$PDSIZE" => h.pdsize = v.f64(),
            "$ANGBASE" => h.angbase = v.f64().to_radians(),
            "$ANGDIR" => h.angdir = v.i16(),
            "$TILEMODE" => h.tilemode = v.bool(),
            "$LWDISPLAY" => h.lwdisplay = v.bool(),
            "$FILLMODE" => h.fillmode = v.bool(),
            "$MIRRTEXT" => h.mirrtext = v.bool(),
            _ => {}
        }
    }
}
