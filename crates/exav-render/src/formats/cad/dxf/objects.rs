//! OBJECTS section: the object types a drawing depends on. Others are
//! skipped.

use exav_unpack::dxf::{Parts, Record, Tag};

use super::entities::{p2, p3};
use super::{Ctx, Raw};
use crate::formats::cad::model::*;

/// The groups of subclass `name`, or all but the head when the record has
/// no markers.
fn class<'p, 'a>(parts: &'p Parts<'a>, name: &str) -> &'p [Tag<'a>] {
    if !parts.has_markers() {
        return &parts.tags;
    }
    parts.subclass(name).unwrap_or(&[])
}

pub(crate) fn object(rec: &Record<'_>, raw: &mut Raw, ctx: &mut Ctx<'_>) {
    let name = rec.type_name().to_ascii_uppercase();
    let parts = Parts::new(&rec.tags, false);
    let handle = Handle(parts.handle());
    match name.as_str() {
        "DICTIONARY" | "ACDBDICTIONARYWDFLT" => {
            let mut d = Dictionary {
                handle,
                owner: Handle(parts.owner()),
                ..Dictionary::default()
            };
            let mut pending: Option<String> = None;
            for t in class(&parts, "AcDbDictionary") {
                match t.code {
                    280 => d.hard_owner = t.bool(),
                    281 => d.cloning = t.i16(),
                    3 => pending = Some(ctx.text(t)),
                    350 | 360 => {
                        if let Some(n) = pending.take() {
                            if ctx.room(d.entries.len()) {
                                d.entries.push((n, Handle(t.handle())));
                            }
                        }
                    }
                    _ => {}
                }
            }
            raw.dictionaries.push(d);
        }
        "LAYOUT" => raw.layouts.push(layout(&parts, handle, ctx)),
        "SORTENTSTABLE" => {
            let mut s = SortEntsTable {
                handle,
                ..SortEntsTable::default()
            };
            let mut entity: Option<Handle> = None;
            for t in class(&parts, "AcDbSortentsTable") {
                match t.code {
                    330 => s.block_record = Handle(t.handle()),
                    331 => entity = Some(Handle(t.handle())),
                    5 => {
                        if let Some(e) = entity.take() {
                            if ctx.room(s.entries.len()) {
                                s.entries.push((e, Handle(t.handle())));
                            }
                        }
                    }
                    _ => {}
                }
            }
            raw.sort_tables.push(s);
        }
        "IMAGEDEF" => {
            let mut d = ImageDef {
                handle,
                ..ImageDef::default()
            };
            for t in class(&parts, "AcDbRasterImageDef") {
                if p2(&mut d.size, t, 10) {
                    continue;
                }
                match t.code {
                    1 => d.file_name = ctx.text(t),
                    11 => d.pixel_size.x = t.f64(),
                    // Files carry the V size in 21; the 2012 reference says
                    // 12.
                    21 | 12 => d.pixel_size.y = t.f64(),
                    280 => d.loaded = t.bool(),
                    281 => d.resolution_units = t.i16(),
                    _ => {}
                }
            }
            raw.image_defs.push(d);
        }
        "PDFDEFINITION" | "DWFDEFINITION" | "DGNDEFINITION" => {
            let kind = match name.as_str() {
                "PDFDEFINITION" => UnderlayKind::Pdf,
                "DWFDEFINITION" => UnderlayKind::Dwf,
                _ => UnderlayKind::Dgn,
            };
            let mut d = UnderlayDef {
                handle,
                kind,
                ..UnderlayDef::default()
            };
            for t in class(&parts, "AcDbUnderlayDefinition") {
                match t.code {
                    1 => d.file_name = ctx.text(t),
                    2 => d.name = ctx.text(t),
                    _ => {}
                }
            }
            raw.underlay_defs.push(d);
        }
        "MLINESTYLE" => raw.mline_styles.push(mline_style(&parts, handle, ctx)),
        "MLEADERSTYLE" => raw.mleader_styles.push(mleader_style(&parts, handle)),
        _ => {}
    }
}

fn layout(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> Layout {
    let mut l = Layout {
        handle,
        ..Layout::default()
    };
    let p = &mut l.plot;
    for t in class(parts, "AcDbPlotSettings") {
        match t.code {
            1 => p.page_setup_name = ctx.text(t),
            2 => p.plot_device = ctx.text(t),
            4 => p.paper_size = ctx.text(t),
            6 => p.plot_view = ctx.text(t),
            7 => p.style_sheet = ctx.text(t),
            40..=43 => {
                if let Some(m) = p.margins.get_mut((t.code - 40) as usize) {
                    *m = t.f64();
                }
            }
            44 => p.paper_width = t.f64(),
            45 => p.paper_height = t.f64(),
            46 => p.origin.x = t.f64(),
            47 => p.origin.y = t.f64(),
            48 => p.window_min.x = t.f64(),
            49 => p.window_min.y = t.f64(),
            140 => p.window_max.x = t.f64(),
            141 => p.window_max.y = t.f64(),
            142 => p.scale_numerator = t.f64(),
            143 => p.scale_denominator = t.f64(),
            70 => p.flags = t.i32(),
            72 => p.paper_units = t.i16(),
            73 => p.rotation = t.i16(),
            74 => p.plot_type = t.i16(),
            75 => p.standard_scale_type = t.i16(),
            147 => p.standard_scale = t.f64(),
            148 => p.image_origin.x = t.f64(),
            149 => p.image_origin.y = t.f64(),
            _ => {}
        }
    }
    for t in class(parts, "AcDbLayout") {
        if p2(&mut l.limits_min, t, 10)
            || p2(&mut l.limits_max, t, 11)
            || p3(&mut l.insertion_base, t, 12)
            || p3(&mut l.extents_min, t, 14)
            || p3(&mut l.extents_max, t, 15)
            || p3(&mut l.ucs_origin, t, 13)
            || p3(&mut l.ucs_x_axis, t, 16)
            || p3(&mut l.ucs_y_axis, t, 17)
        {
            continue;
        }
        match t.code {
            1 => l.name = ctx.text(t),
            70 => l.flags = t.i16(),
            71 => l.tab_order = t.i16(),
            146 => l.elevation = t.f64(),
            330 => l.block_record = Handle(t.handle()),
            331 => l.last_viewport = Handle(t.handle()),
            _ => {}
        }
    }
    l
}

fn mline_style(parts: &Parts<'_>, handle: Handle, ctx: &mut Ctx<'_>) -> MLineStyle {
    let mut s = MLineStyle {
        handle,
        ..MLineStyle::default()
    };
    for t in class(parts, "AcDbMlineStyle") {
        if t.code == 49 {
            if ctx.room(s.elements.len()) {
                s.elements.push(MLineStyleElement {
                    offset: t.f64(),
                    color: Color::ByLayer,
                    linetype: "BYLAYER".to_string(),
                });
            }
            continue;
        }
        if let Some(e) = s.elements.last_mut() {
            match t.code {
                62 => e.color = Color::from_aci(t.int()),
                420 => e.color = Color::from_rgb24(t.int()),
                6 => e.linetype = ctx.text(t),
                _ => {}
            }
            continue;
        }
        match t.code {
            2 => s.name = ctx.text(t),
            70 => s.flags = t.i16(),
            3 => s.description = ctx.text(t),
            62 => {
                if !matches!(s.fill_color, Color::Rgb(..)) {
                    s.fill_color = Color::from_aci(t.int());
                }
            }
            420 => s.fill_color = Color::from_rgb24(t.int()),
            51 => s.start_angle = t.f64().to_radians(),
            52 => s.end_angle = t.f64().to_radians(),
            _ => {}
        }
    }
    s
}

fn mleader_style(parts: &Parts<'_>, handle: Handle) -> MLeaderStyle {
    let mut s = MLeaderStyle {
        handle,
        ..MLeaderStyle::default()
    };
    for t in class(parts, "AcDbMLeaderStyle") {
        match t.code {
            170 => s.content_type = t.i16(),
            173 => s.leader_line_type = t.i16(),
            91 => s.leader_line_color = Color::from_raw(t.int()),
            340 => s.leader_linetype = Handle(t.handle()),
            92 => s.leader_lineweight = LineWeight::from_code(t.int()),
            290 => s.landing = t.bool(),
            42 => s.landing_gap = t.f64(),
            291 => s.dogleg = t.bool(),
            43 => s.dogleg_length = t.f64(),
            341 => s.arrowhead = Handle(t.handle()),
            44 => s.arrowhead_size = t.f64(),
            342 => s.text_style = Handle(t.handle()),
            174 => s.text_left_attachment = t.i16(),
            178 => s.text_right_attachment = t.i16(),
            175 => s.text_angle_type = t.i16(),
            176 => s.text_alignment_type = t.i16(),
            93 => s.text_color = Color::from_raw(t.int()),
            45 => s.text_height = t.f64(),
            292 => s.text_frame = t.bool(),
            343 => s.block = Handle(t.handle()),
            94 => s.block_color = Color::from_raw(t.int()),
            47 => s.block_scale.x = t.f64(),
            49 => s.block_scale.y = t.f64(),
            140 => s.block_scale.z = t.f64(),
            141 => s.block_rotation = t.f64(),
            177 => s.block_connection = t.i16(),
            142 => s.scale = t.f64(),
            _ => {}
        }
    }
    s
}
