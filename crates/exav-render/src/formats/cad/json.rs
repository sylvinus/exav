//! A stable JSON dump of a [`Drawing`], for tests and inspection.
//!
//! Keys follow the model's field names, in declaration order. Handles are
//! upper-case hexadecimal strings ("0" for none), points are arrays, angles
//! are radians, colours are `"bylayer"`, `"byblock"`, an index or
//! `"#rrggbb"`, lineweights and transparencies `"bylayer"`, `"byblock"`,
//! `"default"` or a number, and a non-finite number is `null`.

use std::fmt::Write as _;

use super::model::*;

/// The drawing as one JSON object.
pub fn to_json(d: &Drawing) -> String {
    let mut s = String::new();
    obj(&mut s, |o| drawing(o, d));
    s
}

struct Obj<'a> {
    s: &'a mut String,
    first: bool,
}

fn obj(s: &mut String, f: impl FnOnce(&mut Obj<'_>)) {
    s.push('{');
    let mut o = Obj { s, first: true };
    f(&mut o);
    o.s.push('}');
}

fn string(s: &mut String, v: &str) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, "\\u{:04x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

fn number(s: &mut String, v: f64) {
    if v.is_finite() {
        let _ = write!(s, "{v:?}");
    } else {
        s.push_str("null");
    }
}

fn handle_str(h: Handle) -> String {
    format!("{:X}", h.0)
}

fn color_json(s: &mut String, c: Color) {
    match c {
        Color::ByLayer => s.push_str("\"bylayer\""),
        Color::ByBlock => s.push_str("\"byblock\""),
        Color::Index(i) => {
            let _ = write!(s, "{i}");
        }
        Color::Rgb(r, g, b) => {
            let _ = write!(s, "\"#{r:02x}{g:02x}{b:02x}\"");
        }
    }
}

impl Obj<'_> {
    fn key(&mut self, k: &str) {
        if !self.first {
            self.s.push(',');
        }
        self.first = false;
        string(self.s, k);
        self.s.push(':');
    }

    fn f(&mut self, k: &str, v: f64) {
        self.key(k);
        number(self.s, v);
    }

    fn i(&mut self, k: &str, v: impl Into<i64>) {
        self.key(k);
        let _ = write!(self.s, "{}", v.into());
    }

    fn b(&mut self, k: &str, v: bool) {
        self.key(k);
        self.s.push_str(if v { "true" } else { "false" });
    }

    fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        string(self.s, v);
    }

    fn h(&mut self, k: &str, v: Handle) {
        self.str(k, &handle_str(v));
    }

    fn v2(&mut self, k: &str, v: Vec2) {
        self.key(k);
        self.s.push('[');
        number(self.s, v.x);
        self.s.push(',');
        number(self.s, v.y);
        self.s.push(']');
    }

    fn v3(&mut self, k: &str, v: Vec3) {
        self.key(k);
        vec3(self.s, v);
    }

    fn color(&mut self, k: &str, c: Color) {
        self.key(k);
        color_json(self.s, c);
    }

    fn lw(&mut self, k: &str, v: LineWeight) {
        self.key(k);
        match v {
            LineWeight::ByLayer => self.s.push_str("\"bylayer\""),
            LineWeight::ByBlock => self.s.push_str("\"byblock\""),
            LineWeight::Default => self.s.push_str("\"default\""),
            LineWeight::Value(n) => {
                let _ = write!(self.s, "{n}");
            }
        }
    }

    fn null(&mut self, k: &str) {
        self.key(k);
        self.s.push_str("null");
    }

    fn opt_v3(&mut self, k: &str, v: Option<Vec3>) {
        match v {
            Some(v) => self.v3(k, v),
            None => self.null(k),
        }
    }

    fn opt_v2(&mut self, k: &str, v: Option<Vec2>) {
        match v {
            Some(v) => self.v2(k, v),
            None => self.null(k),
        }
    }

    fn floats(&mut self, k: &str, v: &[f64]) {
        self.list(k, v, |s, x| number(s, *x));
    }

    fn v3s(&mut self, k: &str, v: &[Vec3]) {
        self.list(k, v, |s, p| vec3(s, *p));
    }

    fn v2s(&mut self, k: &str, v: &[Vec2]) {
        self.list(k, v, |s, p| vec2(s, *p));
    }

    fn handles(&mut self, k: &str, v: &[Handle]) {
        self.list(k, v, |s, h| string(s, &handle_str(*h)));
    }

    fn list<T>(&mut self, k: &str, items: &[T], mut f: impl FnMut(&mut String, &T)) {
        self.key(k);
        self.s.push('[');
        for (n, item) in items.iter().enumerate() {
            if n > 0 {
                self.s.push(',');
            }
            f(self.s, item);
        }
        self.s.push(']');
    }

    fn objects<T>(&mut self, k: &str, items: &[T], mut f: impl FnMut(&mut Obj<'_>, &T)) {
        self.list(k, items, |s, item| obj(s, |o| f(o, item)));
    }

    fn object(&mut self, k: &str, f: impl FnOnce(&mut Obj<'_>)) {
        self.key(k);
        obj(self.s, f);
    }
}

fn vec2(s: &mut String, v: Vec2) {
    s.push('[');
    number(s, v.x);
    s.push(',');
    number(s, v.y);
    s.push(']');
}

fn vec3(s: &mut String, v: Vec3) {
    s.push('[');
    number(s, v.x);
    s.push(',');
    number(s, v.y);
    s.push(',');
    number(s, v.z);
    s.push(']');
}

fn version_name(v: Version) -> &'static str {
    match v {
        Version::R12 => "R12",
        Version::R13 => "R13",
        Version::R14 => "R14",
        Version::R2000 => "R2000",
        Version::R2004 => "R2004",
        Version::R2007 => "R2007",
        Version::R2010 => "R2010",
        Version::R2013 => "R2013",
        Version::R2018 => "R2018",
    }
}

fn drawing(o: &mut Obj<'_>, d: &Drawing) {
    o.object("header", |o| header(o, &d.header));
    o.objects("layers", &d.layers, layer);
    o.objects("linetypes", &d.linetypes, linetype);
    o.objects("text_styles", &d.text_styles, text_style);
    o.objects("dim_styles", &d.dim_styles, dim_style);
    o.objects("vports", &d.vports, vport);
    o.objects("blocks", &d.blocks, block);
    o.objects("layouts", &d.layouts, layout);
    o.objects("dictionaries", &d.dictionaries, |o, x| {
        o.h("handle", x.handle);
        o.h("owner", x.owner);
        o.b("hard_owner", x.hard_owner);
        o.i("cloning", x.cloning);
        o.list("entries", &x.entries, |s, (n, h)| {
            s.push('[');
            string(s, n);
            s.push(',');
            string(s, &handle_str(*h));
            s.push(']');
        });
    });
    o.objects("sort_tables", &d.sort_tables, |o, x| {
        o.h("handle", x.handle);
        o.h("block_record", x.block_record);
        o.list("entries", &x.entries, |s, (e, k)| {
            s.push('[');
            string(s, &handle_str(*e));
            s.push(',');
            string(s, &handle_str(*k));
            s.push(']');
        });
    });
    o.objects("image_defs", &d.image_defs, |o, x| {
        o.h("handle", x.handle);
        o.str("file_name", &x.file_name);
        o.v2("size", x.size);
        o.v2("pixel_size", x.pixel_size);
        o.b("loaded", x.loaded);
        o.i("resolution_units", x.resolution_units);
    });
    o.objects("underlay_defs", &d.underlay_defs, |o, x| {
        o.h("handle", x.handle);
        o.str("kind", underlay_kind(x.kind));
        o.str("file_name", &x.file_name);
        o.str("name", &x.name);
    });
    o.objects("mline_styles", &d.mline_styles, |o, x| {
        o.h("handle", x.handle);
        o.str("name", &x.name);
        o.i("flags", x.flags);
        o.str("description", &x.description);
        o.color("fill_color", x.fill_color);
        o.f("start_angle", x.start_angle);
        o.f("end_angle", x.end_angle);
        o.objects("elements", &x.elements, |o, e| {
            o.f("offset", e.offset);
            o.color("color", e.color);
            o.str("linetype", &e.linetype);
        });
    });
    o.objects("mleader_styles", &d.mleader_styles, mleader_style);
    match &d.preview {
        Some(p) => o.object("preview", |o| {
            o.str("format", p.format.mime());
            o.i("bytes", p.data.len() as i64);
        }),
        None => o.null("preview"),
    }
    o.objects("warnings", &d.warnings, |o, w| {
        o.str("kind", &format!("{:?}", w.kind));
        o.str("message", &w.message);
    });
    o.i("warnings_dropped", d.warnings_dropped as i64);
}

fn header(o: &mut Obj<'_>, h: &Header) {
    o.str("version", version_name(h.version));
    o.str("acadver", &h.acadver);
    o.str("code_page", &h.code_page);
    o.h("handle_seed", h.handle_seed);
    o.v3("insbase", h.insbase);
    o.v3("extmin", h.extmin);
    o.v3("extmax", h.extmax);
    o.v2("limmin", h.limmin);
    o.v2("limmax", h.limmax);
    o.v3("pinsbase", h.pinsbase);
    o.v3("pextmin", h.pextmin);
    o.v3("pextmax", h.pextmax);
    o.v2("plimmin", h.plimmin);
    o.v2("plimmax", h.plimmax);
    o.f("ltscale", h.ltscale);
    o.f("celtscale", h.celtscale);
    o.b("psltscale", h.psltscale);
    o.i("insunits", h.insunits);
    o.i("measurement", h.measurement);
    o.i("lunits", h.lunits);
    o.i("luprec", h.luprec);
    o.f("textsize", h.textsize);
    o.str("textstyle", &h.textstyle);
    o.str("clayer", &h.clayer);
    o.str("dimstyle", &h.dimstyle);
    o.f("dimscale", h.dimscale);
    o.f("dimasz", h.dimasz);
    o.f("dimtxt", h.dimtxt);
    o.f("dimgap", h.dimgap);
    o.i("pdmode", h.pdmode);
    o.f("pdsize", h.pdsize);
    o.f("angbase", h.angbase);
    o.i("angdir", h.angdir);
    o.b("tilemode", h.tilemode);
    o.b("lwdisplay", h.lwdisplay);
    o.b("fillmode", h.fillmode);
    o.b("mirrtext", h.mirrtext);
}

fn layer(o: &mut Obj<'_>, l: &Layer) {
    o.h("handle", l.handle);
    o.str("name", &l.name);
    o.i("flags", l.flags);
    o.color("color", l.color);
    o.b("off", l.off);
    o.str("linetype", &l.linetype);
    o.b("plot", l.plot);
    o.lw("lineweight", l.lineweight);
    o.h("plot_style", l.plot_style);
    o.h("material", l.material);
    o.i("alpha", l.alpha);
}

fn linetype(o: &mut Obj<'_>, l: &Linetype) {
    o.h("handle", l.handle);
    o.str("name", &l.name);
    o.i("flags", l.flags);
    o.str("description", &l.description);
    o.f("pattern_length", l.pattern_length);
    o.objects("elements", &l.elements, |o, e| {
        o.f("length", e.length);
        o.i("flags", e.flags);
        o.i("shape_number", e.shape_number);
        o.h("style", e.style);
        o.f("scale", e.scale);
        o.f("rotation", e.rotation);
        o.v2("offset", e.offset);
        o.str("text", &e.text);
    });
}

fn text_style(o: &mut Obj<'_>, s: &TextStyle) {
    o.h("handle", s.handle);
    o.str("name", &s.name);
    o.i("flags", s.flags);
    o.f("height", s.height);
    o.f("width_factor", s.width_factor);
    o.f("oblique", s.oblique);
    o.i("generation", s.generation);
    o.f("last_height", s.last_height);
    o.str("font_file", &s.font_file);
    o.str("bigfont_file", &s.bigfont_file);
    o.str("font_family", &s.font_family);
    o.i("font_flags", s.font_flags);
}

fn dim_style(o: &mut Obj<'_>, d: &DimStyle) {
    o.h("handle", d.handle);
    o.str("name", &d.name);
    o.i("flags", d.flags);
    o.f("dimscale", d.dimscale);
    o.f("dimasz", d.dimasz);
    o.f("dimexo", d.dimexo);
    o.f("dimexe", d.dimexe);
    o.f("dimdle", d.dimdle);
    o.f("dimtsz", d.dimtsz);
    o.f("dimtxt", d.dimtxt);
    o.f("dimgap", d.dimgap);
    o.color("dimclrd", d.dimclrd);
    o.color("dimclre", d.dimclre);
    o.color("dimclrt", d.dimclrt);
    o.lw("dimlwd", d.dimlwd);
    o.lw("dimlwe", d.dimlwe);
    o.h("dimtxsty", d.dimtxsty);
    o.h("dimldrblk", d.dimldrblk);
    o.h("dimblk", d.dimblk);
    o.h("dimblk1", d.dimblk1);
    o.h("dimblk2", d.dimblk2);
}

fn vport(o: &mut Obj<'_>, v: &VPort) {
    o.h("handle", v.handle);
    o.str("name", &v.name);
    o.i("flags", v.flags);
    o.v2("lower_left", v.lower_left);
    o.v2("upper_right", v.upper_right);
    o.v2("center", v.center);
    o.v3("view_direction", v.view_direction);
    o.v3("target", v.target);
    o.f("height", v.height);
    o.f("aspect_ratio", v.aspect_ratio);
    o.f("twist", v.twist);
}

fn block(o: &mut Obj<'_>, b: &Block) {
    o.str("name", &b.name);
    o.h("record", b.record);
    o.h("handle", b.handle);
    o.h("end_handle", b.end_handle);
    o.i("flags", b.flags);
    o.v3("base_point", b.base_point);
    o.str("xref_path", &b.xref_path);
    o.str("description", &b.description);
    o.str("layer", &b.layer);
    o.h("layout", b.layout);
    o.i("insert_units", b.insert_units);
    o.b("explodable", b.explodable);
    o.b("scalable", b.scalable);
    o.objects("entities", &b.entities, entity);
}

fn plot(o: &mut Obj<'_>, p: &PlotSettings) {
    o.str("page_setup_name", &p.page_setup_name);
    o.str("plot_device", &p.plot_device);
    o.str("paper_size", &p.paper_size);
    o.str("plot_view", &p.plot_view);
    o.str("style_sheet", &p.style_sheet);
    o.floats("margins", &p.margins);
    o.f("paper_width", p.paper_width);
    o.f("paper_height", p.paper_height);
    o.v2("origin", p.origin);
    o.v2("window_min", p.window_min);
    o.v2("window_max", p.window_max);
    o.f("scale_numerator", p.scale_numerator);
    o.f("scale_denominator", p.scale_denominator);
    o.i("flags", p.flags);
    o.i("paper_units", p.paper_units);
    o.i("rotation", p.rotation);
    o.i("plot_type", p.plot_type);
    o.i("standard_scale_type", p.standard_scale_type);
    o.f("standard_scale", p.standard_scale);
    o.v2("image_origin", p.image_origin);
}

fn layout(o: &mut Obj<'_>, l: &Layout) {
    o.h("handle", l.handle);
    o.str("name", &l.name);
    o.i("flags", l.flags);
    o.i("tab_order", l.tab_order);
    o.v2("limits_min", l.limits_min);
    o.v2("limits_max", l.limits_max);
    o.v3("insertion_base", l.insertion_base);
    o.v3("extents_min", l.extents_min);
    o.v3("extents_max", l.extents_max);
    o.f("elevation", l.elevation);
    o.v3("ucs_origin", l.ucs_origin);
    o.v3("ucs_x_axis", l.ucs_x_axis);
    o.v3("ucs_y_axis", l.ucs_y_axis);
    o.h("block_record", l.block_record);
    o.h("last_viewport", l.last_viewport);
    o.object("plot", |o| plot(o, &l.plot));
}

fn mleader_style(o: &mut Obj<'_>, s: &MLeaderStyle) {
    o.h("handle", s.handle);
    o.str("name", &s.name);
    o.i("content_type", s.content_type);
    o.i("leader_line_type", s.leader_line_type);
    o.color("leader_line_color", s.leader_line_color);
    o.h("leader_linetype", s.leader_linetype);
    o.lw("leader_lineweight", s.leader_lineweight);
    o.b("landing", s.landing);
    o.f("landing_gap", s.landing_gap);
    o.b("dogleg", s.dogleg);
    o.f("dogleg_length", s.dogleg_length);
    o.h("arrowhead", s.arrowhead);
    o.f("arrowhead_size", s.arrowhead_size);
    o.h("text_style", s.text_style);
    o.i("text_left_attachment", s.text_left_attachment);
    o.i("text_right_attachment", s.text_right_attachment);
    o.i("text_angle_type", s.text_angle_type);
    o.i("text_alignment_type", s.text_alignment_type);
    o.color("text_color", s.text_color);
    o.f("text_height", s.text_height);
    o.b("text_frame", s.text_frame);
    o.h("block", s.block);
    o.color("block_color", s.block_color);
    o.v3("block_scale", s.block_scale);
    o.f("block_rotation", s.block_rotation);
    o.i("block_connection", s.block_connection);
    o.f("scale", s.scale);
}

fn underlay_kind(k: UnderlayKind) -> &'static str {
    match k {
        UnderlayKind::Pdf => "pdf",
        UnderlayKind::Dwf => "dwf",
        UnderlayKind::Dgn => "dgn",
    }
}

fn plane(o: &mut Obj<'_>, p: &Plane) {
    o.f("thickness", p.thickness);
    o.v3("extrusion", p.extrusion);
}

fn h_align(a: HAlign) -> &'static str {
    match a {
        HAlign::Left => "left",
        HAlign::Center => "center",
        HAlign::Right => "right",
        HAlign::Aligned => "aligned",
        HAlign::Middle => "middle",
        HAlign::Fit => "fit",
    }
}

fn v_align(a: VAlign) -> &'static str {
    match a {
        VAlign::Baseline => "baseline",
        VAlign::Bottom => "bottom",
        VAlign::Middle => "middle",
        VAlign::Top => "top",
    }
}

fn text(o: &mut Obj<'_>, t: &Text) {
    o.v3("insertion", t.insertion);
    o.opt_v3("alignment_point", t.alignment_point);
    o.f("height", t.height);
    o.str("value", &t.value);
    o.f("rotation", t.rotation);
    o.f("width_factor", t.width_factor);
    o.f("oblique", t.oblique);
    o.str("style", &t.style);
    o.i("generation", t.generation);
    o.str("h_align", h_align(t.h_align));
    o.str("v_align", v_align(t.v_align));
    plane(o, &t.plane);
}

fn mtext(o: &mut Obj<'_>, m: &MText) {
    o.v3("insertion", m.insertion);
    o.f("height", m.height);
    o.f("reference_width", m.reference_width);
    o.f("defined_height", m.defined_height);
    o.i("attachment", m.attachment);
    o.i("drawing_direction", m.drawing_direction);
    o.str("style", &m.style);
    o.v3("extrusion", m.extrusion);
    o.opt_v3("x_direction", m.x_direction);
    o.f("rotation", m.rotation);
    o.i("line_spacing_style", m.line_spacing_style);
    o.f("line_spacing_factor", m.line_spacing_factor);
    o.str("text", &m.text);
    o.i("background_fill", m.background_fill);
    o.color("background_color", m.background_color);
    o.f("background_scale", m.background_scale);
    match &m.columns {
        None => o.null("columns"),
        Some(c) => o.object("columns", |o| {
            o.i("kind", c.kind);
            o.i("count", c.count);
            o.b("flow_reversed", c.flow_reversed);
            o.b("auto_height", c.auto_height);
            o.f("width", c.width);
            o.f("gutter", c.gutter);
            o.floats("heights", &c.heights);
        }),
    }
}

fn attribute(o: &mut Obj<'_>, a: &Attribute) {
    o.object("text", |o| text(o, &a.text));
    o.str("tag", &a.tag);
    o.str("prompt", &a.prompt);
    o.i("flags", a.flags);
    o.i("field_length", a.field_length);
    o.b("lock_position", a.lock_position);
    match &a.mtext {
        None => o.null("mtext"),
        Some(m) => o.object("mtext", |o| mtext(o, m)),
    }
}

fn spline(o: &mut Obj<'_>, s: &Spline) {
    o.v3("extrusion", s.extrusion);
    o.i("flags", s.flags);
    o.i("degree", s.degree);
    o.floats("knots", &s.knots);
    o.v3s("control_points", &s.control_points);
    o.floats("weights", &s.weights);
    o.v3s("fit_points", &s.fit_points);
    o.opt_v3("start_tangent", s.start_tangent);
    o.opt_v3("end_tangent", s.end_tangent);
    o.f("knot_tolerance", s.knot_tolerance);
    o.f("control_point_tolerance", s.control_point_tolerance);
    o.f("fit_tolerance", s.fit_tolerance);
}

fn dimension_kind(k: DimensionKind) -> &'static str {
    match k {
        DimensionKind::Linear => "linear",
        DimensionKind::Aligned => "aligned",
        DimensionKind::Angular => "angular",
        DimensionKind::Diameter => "diameter",
        DimensionKind::Radius => "radius",
        DimensionKind::Angular3Point => "angular_3_point",
        DimensionKind::Ordinate => "ordinate",
    }
}

fn edge(s: &mut String, e: &Edge) {
    obj(s, |o| match e {
        Edge::Line { start, end } => {
            o.str("type", "line");
            o.v2("start", *start);
            o.v2("end", *end);
        }
        Edge::Arc {
            center,
            radius,
            start_angle,
            end_angle,
            counter_clockwise,
        } => {
            o.str("type", "arc");
            o.v2("center", *center);
            o.f("radius", *radius);
            o.f("start_angle", *start_angle);
            o.f("end_angle", *end_angle);
            o.b("counter_clockwise", *counter_clockwise);
        }
        Edge::Ellipse {
            center,
            major_axis,
            ratio,
            start_angle,
            end_angle,
            counter_clockwise,
        } => {
            o.str("type", "ellipse");
            o.v2("center", *center);
            o.v2("major_axis", *major_axis);
            o.f("ratio", *ratio);
            o.f("start_angle", *start_angle);
            o.f("end_angle", *end_angle);
            o.b("counter_clockwise", *counter_clockwise);
        }
        Edge::Spline {
            degree,
            rational,
            periodic,
            knots,
            control_points,
            weights,
            fit_points,
            start_tangent,
            end_tangent,
        } => {
            o.str("type", "spline");
            o.i("degree", *degree);
            o.b("rational", *rational);
            o.b("periodic", *periodic);
            o.floats("knots", knots);
            o.v2s("control_points", control_points);
            o.floats("weights", weights);
            o.v2s("fit_points", fit_points);
            o.opt_v2("start_tangent", *start_tangent);
            o.opt_v2("end_tangent", *end_tangent);
        }
    });
}

fn hatch(o: &mut Obj<'_>, h: &Hatch) {
    o.f("elevation", h.elevation);
    o.v3("extrusion", h.extrusion);
    o.str("pattern_name", &h.pattern_name);
    o.b("solid", h.solid);
    o.b("associative", h.associative);
    o.objects("paths", &h.paths, |o, p| {
        o.i("flags", p.flags);
        match &p.data {
            BoundaryData::Polyline { closed, vertices } => {
                o.str("type", "polyline");
                o.b("closed", *closed);
                o.list("vertices", vertices, |s, (p, b)| {
                    s.push('[');
                    number(s, p.x);
                    s.push(',');
                    number(s, p.y);
                    s.push(',');
                    number(s, *b);
                    s.push(']');
                });
            }
            BoundaryData::Edges(edges) => {
                o.str("type", "edges");
                o.list("edges", edges, edge);
            }
        }
        o.handles("sources", &p.sources);
    });
    o.i("style", h.style);
    o.i("pattern_type", h.pattern_type);
    o.f("pattern_angle", h.pattern_angle);
    o.f("pattern_scale", h.pattern_scale);
    o.b("pattern_double", h.pattern_double);
    o.objects("pattern_lines", &h.pattern_lines, |o, l| {
        o.f("angle", l.angle);
        o.v2("base", l.base);
        o.v2("offset", l.offset);
        o.floats("dashes", &l.dashes);
    });
    o.f("pixel_size", h.pixel_size);
    o.v2s("seeds", &h.seeds);
    match &h.gradient {
        None => o.null("gradient"),
        Some(g) => o.object("gradient", |o| {
            o.i("kind", g.kind);
            o.str("name", &g.name);
            o.f("angle", g.angle);
            o.f("shift", g.shift);
            o.b("single_color", g.single_color);
            o.f("tint", g.tint);
            o.list("colors", &g.colors, |s, (v, c)| {
                s.push('[');
                number(s, *v);
                s.push(',');
                color_json(s, *c);
                s.push(']');
            });
        }),
    }
}

fn multileader(o: &mut Obj<'_>, m: &MultiLeader) {
    o.h("style", m.style);
    o.i("property_overrides", m.property_overrides);
    o.i("leader_line_type", m.leader_line_type);
    o.color("leader_line_color", m.leader_line_color);
    o.h("leader_linetype", m.leader_linetype);
    o.lw("leader_lineweight", m.leader_lineweight);
    o.b("landing", m.landing);
    o.b("dogleg", m.dogleg);
    o.f("dogleg_length", m.dogleg_length);
    o.h("arrowhead", m.arrowhead);
    o.f("arrowhead_size", m.arrowhead_size);
    o.i("content_type", m.content_type);
    o.h("text_style", m.text_style);
    o.i("text_left_attachment", m.text_left_attachment);
    o.i("text_right_attachment", m.text_right_attachment);
    o.i("text_angle_type", m.text_angle_type);
    o.i("text_alignment_type", m.text_alignment_type);
    o.color("text_color", m.text_color);
    o.b("text_frame", m.text_frame);
    o.h("block", m.block);
    o.color("block_color", m.block_color);
    o.v3("block_scale", m.block_scale);
    o.f("block_rotation", m.block_rotation);
    o.i("block_connection", m.block_connection);
    o.objects("block_attributes", &m.block_attributes, |o, a| {
        o.h("definition", a.definition);
        o.i("index", a.index);
        o.f("width", a.width);
        o.str("text", &a.text);
    });
    o.i("text_attachment_point", m.text_attachment_point);
    let c = &m.context;
    o.object("context", |o| {
        o.f("scale", c.scale);
        o.v3("content_base", c.content_base);
        o.f("text_height", c.text_height);
        o.f("arrowhead_size", c.arrowhead_size);
        o.f("landing_gap", c.landing_gap);
        o.b("has_text", c.has_text);
        o.str("text", &c.text);
        o.v3("text_normal", c.text_normal);
        o.h("text_style", c.text_style);
        o.v3("text_location", c.text_location);
        o.v3("text_direction", c.text_direction);
        o.f("text_rotation", c.text_rotation);
        o.f("text_width", c.text_width);
        o.f("text_boundary_height", c.text_boundary_height);
        o.f("line_spacing_factor", c.line_spacing_factor);
        o.i("line_spacing_style", c.line_spacing_style);
        o.color("text_color", c.text_color);
        o.i("text_attachment", c.text_attachment);
        o.i("text_flow_direction", c.text_flow_direction);
        o.b("has_block", c.has_block);
        o.h("block", c.block);
        o.v3("block_normal", c.block_normal);
        o.v3("block_position", c.block_position);
        o.v3("block_scale", c.block_scale);
        o.f("block_rotation", c.block_rotation);
        o.color("block_color", c.block_color);
        o.floats("block_transform", &c.block_transform);
        o.v3("plane_origin", c.plane_origin);
        o.v3("plane_x_axis", c.plane_x_axis);
        o.v3("plane_y_axis", c.plane_y_axis);
        o.b("plane_normal_reversed", c.plane_normal_reversed);
        o.objects("leaders", &c.leaders, |o, r| {
            o.v3("connection_point", r.connection_point);
            o.v3("direction", r.direction);
            o.b("has_connection_point", r.has_connection_point);
            o.b("has_direction", r.has_direction);
            o.i("branch_index", r.branch_index);
            o.f("dogleg_length", r.dogleg_length);
            o.objects("lines", &r.lines, |o, l| {
                o.v3s("vertices", &l.vertices);
                o.i("index", l.index);
            });
            o.i("attachment_direction", r.attachment_direction);
        });
    });
}

fn image(o: &mut Obj<'_>, i: &Image) {
    o.i("class_version", i.class_version);
    o.v3("insertion", i.insertion);
    o.v3("u_vector", i.u_vector);
    o.v3("v_vector", i.v_vector);
    o.v2("size", i.size);
    o.h("image_def", i.image_def);
    o.i("display", i.display);
    o.b("clipping", i.clipping);
    o.i("brightness", i.brightness);
    o.i("contrast", i.contrast);
    o.i("fade", i.fade);
    o.h("reactor", i.reactor);
    o.i("clip_type", i.clip_type);
    o.v2s("clip_vertices", &i.clip_vertices);
    o.b("clip_inside", i.clip_inside);
}

fn entity(o: &mut Obj<'_>, e: &Entity) {
    o.str("type", e.type_name());
    o.h("handle", e.handle);
    o.h("owner", e.owner);
    o.str("layer", &e.layer);
    o.str("linetype", &e.linetype);
    o.color("color", e.color);
    o.str("color_name", &e.color_name);
    o.lw("lineweight", e.lineweight);
    o.key("transparency");
    match e.transparency {
        Transparency::ByLayer => o.s.push_str("\"bylayer\""),
        Transparency::ByBlock => o.s.push_str("\"byblock\""),
        Transparency::Alpha(a) => {
            let _ = write!(o.s, "{a}");
        }
    }
    o.f("linetype_scale", e.linetype_scale);
    o.b("invisible", e.invisible);
    o.b("paper_space", e.paper_space);
    kind(o, &e.kind);
}

fn kind(o: &mut Obj<'_>, k: &EntityKind) {
    match k {
        EntityKind::Line(l) => {
            o.v3("start", l.start);
            o.v3("end", l.end);
            plane(o, &l.plane);
        }
        EntityKind::Point(p) => {
            o.v3("location", p.location);
            o.f("x_axis_angle", p.x_axis_angle);
            plane(o, &p.plane);
        }
        EntityKind::Circle(c) => {
            o.v3("center", c.center);
            o.f("radius", c.radius);
            plane(o, &c.plane);
        }
        EntityKind::Arc(a) => {
            o.v3("center", a.center);
            o.f("radius", a.radius);
            o.f("start_angle", a.start_angle);
            o.f("end_angle", a.end_angle);
            plane(o, &a.plane);
        }
        EntityKind::Ellipse(e) => {
            o.v3("center", e.center);
            o.v3("major_axis", e.major_axis);
            o.v3("extrusion", e.extrusion);
            o.f("ratio", e.ratio);
            o.f("start_param", e.start_param);
            o.f("end_param", e.end_param);
        }
        EntityKind::Spline(s) => spline(o, s),
        EntityKind::LwPolyline(p) => lwpolyline(o, p),
        EntityKind::Polyline(p) => {
            o.i("flags", p.flags);
            o.f("elevation", p.elevation);
            o.f("default_start_width", p.default_start_width);
            o.f("default_end_width", p.default_end_width);
            o.i("m_count", p.m_count);
            o.i("n_count", p.n_count);
            o.i("m_density", p.m_density);
            o.i("n_density", p.n_density);
            o.i("curve_type", p.curve_type);
            plane(o, &p.plane);
            o.objects("vertices", &p.vertices, |o, v| {
                o.h("handle", v.handle);
                o.v3("location", v.location);
                o.f("start_width", v.start_width);
                o.f("end_width", v.end_width);
                o.f("bulge", v.bulge);
                o.i("flags", v.flags);
                o.f("tangent", v.tangent);
                o.list("indices", &v.indices, |s, i| {
                    let _ = write!(s, "{i}");
                });
            });
        }
        EntityKind::Solid(q) | EntityKind::Trace(q) => {
            o.v3s("corners", &q.corners);
            plane(o, &q.plane);
        }
        EntityKind::Face3D(f) => {
            o.v3s("corners", &f.corners);
            o.i("invisible_edges", f.invisible_edges);
        }
        EntityKind::Text(t) => text(o, t),
        EntityKind::Attribute(a) | EntityKind::AttributeDefinition(a) => attribute(o, a),
        EntityKind::Insert(i) => {
            o.str("block_name", &i.block_name);
            o.v3("insertion", i.insertion);
            o.v3("scale", i.scale);
            o.f("rotation", i.rotation);
            o.i("columns", i.columns);
            o.i("rows", i.rows);
            o.f("column_spacing", i.column_spacing);
            o.f("row_spacing", i.row_spacing);
            o.v3("extrusion", i.extrusion);
            o.objects("attributes", &i.attributes, entity);
        }
        EntityKind::MText(m) => mtext(o, m),
        EntityKind::Dimension(d) => {
            o.str("kind", dimension_kind(d.kind));
            o.i("flags", d.flags);
            o.str("block_name", &d.block_name);
            o.str("style", &d.style);
            o.v3("definition_point", d.definition_point);
            o.v3("text_midpoint", d.text_midpoint);
            o.v3("insertion_point", d.insertion_point);
            o.v3("point13", d.point13);
            o.v3("point14", d.point14);
            o.v3("point15", d.point15);
            o.v3("point16", d.point16);
            o.i("attachment", d.attachment);
            o.i("line_spacing_style", d.line_spacing_style);
            o.f("line_spacing_factor", d.line_spacing_factor);
            o.f("measurement", d.measurement);
            o.str("text", &d.text);
            o.f("text_rotation", d.text_rotation);
            o.f("horizontal_direction", d.horizontal_direction);
            o.f("angle", d.angle);
            o.f("oblique", d.oblique);
            o.f("leader_length", d.leader_length);
            o.v3("extrusion", d.extrusion);
            o.v3("insertion_scale", d.insertion_scale);
            o.f("insertion_rotation", d.insertion_rotation);
        }
        EntityKind::Leader(l) => {
            o.str("style", &l.style);
            o.b("arrowhead", l.arrowhead);
            o.i("path_type", l.path_type);
            o.i("creation", l.creation);
            o.i("hookline_direction", l.hookline_direction);
            o.b("hookline", l.hookline);
            o.f("text_height", l.text_height);
            o.f("text_width", l.text_width);
            o.v3s("vertices", &l.vertices);
            o.color("leader_color", l.color);
            o.h("annotation", l.annotation);
            o.v3("extrusion", l.extrusion);
            o.v3("horizontal_direction", l.horizontal_direction);
            o.v3("block_offset", l.block_offset);
            o.v3("annotation_offset", l.annotation_offset);
        }
        EntityKind::MultiLeader(m) => multileader(o, m),
        EntityKind::MLine(m) => {
            o.str("style_name", &m.style_name);
            o.h("style", m.style);
            o.f("scale", m.scale);
            o.i("justification", m.justification);
            o.i("flags", m.flags);
            o.i("style_element_count", m.style_element_count);
            o.v3("start", m.start);
            o.v3("extrusion", m.extrusion);
            o.objects("vertices", &m.vertices, |o, v| {
                o.v3("position", v.position);
                o.v3("direction", v.direction);
                o.v3("miter", v.miter);
                o.objects("elements", &v.elements, |o, e| {
                    o.floats("parameters", &e.parameters);
                    o.floats("fill_parameters", &e.fill_parameters);
                });
            });
        }
        EntityKind::Hatch(h) => hatch(o, h),
        EntityKind::Helix(h) => {
            o.object("spline", |o| spline(o, &h.spline));
            o.v3("axis_base", h.axis_base);
            o.v3("start_point", h.start_point);
            o.v3("axis_vector", h.axis_vector);
            o.f("radius", h.radius);
            o.f("turns", h.turns);
            o.f("turn_height", h.turn_height);
            o.b("right_handed", h.right_handed);
            o.i("constraint", h.constraint);
        }
        EntityKind::Ray(r) | EntityKind::XLine(r) => {
            o.v3("base", r.base);
            o.v3("direction", r.direction);
        }
        EntityKind::Viewport(v) => {
            o.v3("center", v.center);
            o.f("width", v.width);
            o.f("height", v.height);
            o.i("status", v.status);
            o.i("id", v.id);
            o.v2("view_center", v.view_center);
            o.v2("snap_base", v.snap_base);
            o.v2("snap_spacing", v.snap_spacing);
            o.v2("grid_spacing", v.grid_spacing);
            o.v3("view_direction", v.view_direction);
            o.v3("view_target", v.view_target);
            o.f("lens_length", v.lens_length);
            o.f("front_clip", v.front_clip);
            o.f("back_clip", v.back_clip);
            o.f("view_height", v.view_height);
            o.f("snap_angle", v.snap_angle);
            o.f("twist", v.twist);
            o.i("circle_zoom", v.circle_zoom);
            o.handles("frozen_layers", &v.frozen_layers);
            o.i("flags", v.flags);
            o.h("clip_boundary", v.clip_boundary);
            o.str("plot_style_sheet", &v.plot_style_sheet);
            o.i("render_mode", v.render_mode);
            o.f("elevation", v.elevation);
            o.i("shade_plot_mode", v.shade_plot_mode);
        }
        EntityKind::Image(i) | EntityKind::Wipeout(i) => image(o, i),
        EntityKind::Underlay(u) => {
            o.str("kind", underlay_kind(u.kind));
            o.h("definition", u.definition);
            o.v3("insertion", u.insertion);
            o.v3("scale", u.scale);
            o.f("rotation", u.rotation);
            o.v3("extrusion", u.extrusion);
            o.i("flags", u.flags);
            o.i("contrast", u.contrast);
            o.i("fade", u.fade);
            o.v2s("clip_vertices", &u.clip_vertices);
        }
        EntityKind::Ole2Frame(f) => {
            o.i("version", f.version);
            o.str("description", &f.description);
            o.v3("upper_left", f.upper_left);
            o.v3("lower_right", f.lower_right);
            o.i("ole_type", f.ole_type);
            o.i("tile_mode", f.tile_mode);
            o.i("data_length", f.data_length);
        }
        EntityKind::Table(t) => {
            o.str("block_name", &t.block_name);
            o.v3("insertion", t.insertion);
            o.v3("horizontal_direction", t.horizontal_direction);
            o.h("style", t.style);
            o.h("block_record", t.block_record);
            o.i("rows", t.rows);
            o.i("columns", t.columns);
            o.floats("row_heights", &t.row_heights);
            o.floats("column_widths", &t.column_widths);
        }
        EntityKind::Shape(s) => {
            o.v3("insertion", s.insertion);
            o.f("size", s.size);
            o.str("name", &s.name);
            o.f("rotation", s.rotation);
            o.f("width_factor", s.width_factor);
            o.f("oblique", s.oblique);
            plane(o, &s.plane);
        }
        EntityKind::Unknown(u) => match &u.graphics {
            Some(g) => o.objects("graphics", &g.items, proxy_item),
            None => o.null("graphics"),
        },
    }
}

fn lwpolyline(o: &mut Obj<'_>, p: &LwPolyline) {
    o.i("flags", p.flags);
    o.f("constant_width", p.constant_width);
    o.f("elevation", p.elevation);
    plane(o, &p.plane);
    o.list("vertices", &p.vertices, |s, v| {
        s.push('[');
        for (n, x) in [v.point.x, v.point.y, v.start_width, v.end_width, v.bulge]
            .into_iter()
            .enumerate()
        {
            if n > 0 {
                s.push(',');
            }
            number(s, x);
        }
        s.push(']');
    });
}

/// One proxy graphics item: `"item"` names it, then its fields.
fn proxy_item(o: &mut Obj<'_>, i: &ProxyItem) {
    let kind = |k: ArcKind| match k {
        ArcKind::Simple => "simple",
        ArcKind::Sector => "sector",
        ArcKind::Chord => "chord",
    };
    match i {
        ProxyItem::Circle {
            center,
            radius,
            normal,
        } => {
            o.str("item", "circle");
            o.v3("center", *center);
            o.f("radius", *radius);
            o.v3("normal", *normal);
        }
        ProxyItem::Circle3P(p) => {
            o.str("item", "circle3p");
            o.v3s("points", p);
        }
        ProxyItem::Arc {
            center,
            radius,
            normal,
            start,
            sweep,
            kind: k,
        } => {
            o.str("item", "arc");
            o.v3("center", *center);
            o.f("radius", *radius);
            o.v3("normal", *normal);
            o.v3("start", *start);
            o.f("sweep", *sweep);
            o.str("kind", kind(*k));
        }
        ProxyItem::Arc3P { points, kind: k } => {
            o.str("item", "arc3p");
            o.v3s("points", points);
            o.str("kind", kind(*k));
        }
        ProxyItem::EllipticalArc(e) => {
            o.str("item", "elliptical_arc");
            o.v3("center", e.center);
            o.v3("normal", e.normal);
            o.f("major_radius", e.major_radius);
            o.f("minor_radius", e.minor_radius);
            o.f("start", e.start);
            o.f("end", e.end);
            o.f("rotation", e.rotation);
            o.str("kind", kind(e.kind));
        }
        ProxyItem::Polyline { points, normal } => {
            o.str("item", "polyline");
            o.v3s("points", points);
            o.opt_v3("normal", *normal);
        }
        ProxyItem::Polygon(p) => {
            o.str("item", "polygon");
            o.v3s("points", p);
        }
        ProxyItem::Mesh(m) => {
            o.str("item", "mesh");
            o.i("rows", m.rows);
            o.i("columns", m.columns);
            o.v3s("vertices", &m.vertices);
            o.list("edge_visible", &m.edge_visible, |s, v| {
                s.push_str(if *v { "true" } else { "false" })
            });
        }
        ProxyItem::Shell(m) => {
            o.str("item", "shell");
            o.v3s("vertices", &m.vertices);
            o.list("faces", &m.faces, |s, v| {
                let _ = write!(s, "{v}");
            });
            o.list("edge_visible", &m.edge_visible, |s, v| {
                s.push_str(if *v { "true" } else { "false" })
            });
        }
        ProxyItem::Text(t) => {
            o.str("item", "text");
            o.v3("position", t.position);
            o.v3("normal", t.normal);
            o.v3("direction", t.direction);
            o.f("height", t.height);
            o.f("width_factor", t.width_factor);
            o.f("oblique", t.oblique);
            o.str("value", &t.value);
            o.b("raw", t.raw);
            o.str("font", &t.font);
            o.str("big_font", &t.big_font);
            o.str("typeface", &t.typeface);
            o.b("bold", t.bold);
            o.b("italic", t.italic);
            o.b("backwards", t.backwards);
            o.b("upside_down", t.upside_down);
        }
        ProxyItem::XLine { base, through, ray } => {
            o.str("item", if *ray { "ray" } else { "xline" });
            o.v3("base", *base);
            o.v3("through", *through);
        }
        ProxyItem::LwPolyline(p) => {
            o.str("item", "lwpolyline");
            lwpolyline(o, p);
        }
        ProxyItem::Color(c) => {
            o.str("item", "color");
            o.color("color", *c);
        }
        ProxyItem::Layer(n) => {
            o.str("item", "layer");
            o.i("index", *n);
        }
        ProxyItem::Linetype(n) => {
            o.str("item", "linetype");
            o.i("index", *n);
        }
        ProxyItem::Fill(on) => {
            o.str("item", "fill");
            o.b("on", *on);
        }
        ProxyItem::LineWeight(w) => {
            o.str("item", "lineweight");
            o.lw("lineweight", *w);
        }
        ProxyItem::LinetypeScale(v) => {
            o.str("item", "linetype_scale");
            o.f("scale", *v);
        }
        ProxyItem::Thickness(v) => {
            o.str("item", "thickness");
            o.f("thickness", *v);
        }
        ProxyItem::PushTransform(m) => {
            o.str("item", "push_transform");
            o.floats("matrix", &m[..]);
        }
        ProxyItem::PopTransform => o.str("item", "pop_transform"),
    }
}
