//! A DWG reading against the DXF reading of the converter's DXF of it, as
//! JSON dumps: where they differ, with a note when the difference is one
//! the converter makes (each note's evidence is in tests/cad_dwg_oracle.rs).

use std::collections::BTreeMap;

use serde_json::Value;

pub fn same_number(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1e-3)
}

/// A layer the converter made up for a dangling reference.
pub fn repair_name(s: &str) -> bool {
    s.contains(" @ ") || s.contains("_@_")
}

/// Two names of an anonymous block of the same kind, `*D20` and `*D12`.
pub fn renumbered(a: &str, b: &str) -> bool {
    let split = |s: &str| {
        let digits = s.trim_end_matches(|c: char| c.is_ascii_digit());
        (digits.to_string(), s.len() > digits.len())
    };
    let ((pa, na), (pb, nb)) = (split(a), split(b));
    a.starts_with('*') && na && nb && pa.eq_ignore_ascii_case(&pb)
}

/// Field paths where `a` (DWG) and `b` (DXF) differ.
pub fn compare(a: &Value, b: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (
                x.as_f64().unwrap_or(f64::NAN),
                y.as_f64().unwrap_or(f64::NAN),
            );
            if !same_number(x, y) {
                // A linetype element's undocumented 8 bit, which the
                // converter's DXF leaves out.
                let note = if path.ends_with("elements[].flags") && (x as i64) & !8 == y as i64 {
                    " (bit 8)"
                } else {
                    ""
                };
                out.push((format!("{path}{note}"), format!("{x} vs {y}")));
            }
        }
        (Value::Object(x), Value::Object(y)) => {
            for (k, va) in x {
                let p = format!("{path}.{k}");
                match y.get(k) {
                    Some(vb) => compare(va, vb, &p, out),
                    None => out.push((p, "only in DWG".into())),
                }
            }
            for k in y.keys().filter(|k| !x.contains_key(*k)) {
                out.push((format!("{path}.{k}"), "only in DXF".into()));
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                out.push((
                    format!("{path} (length)"),
                    format!("{} vs {}", x.len(), y.len()),
                ));
                return;
            }
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                let mut sub = Vec::new();
                compare(va, vb, &format!("{path}[{i}]"), &mut sub);
                // One pattern for any index.
                out.extend(sub.into_iter().map(|(p, e)| {
                    (
                        p.replacen(&format!("{path}[{i}]"), &format!("{path}[]"), 1),
                        format!("[{i}] {e}"),
                    )
                }));
            }
        }
        _ if a == b => {}
        (Value::String(x), Value::String(y)) => {
            let note = if x.eq_ignore_ascii_case(y) {
                " (case)"
            } else if (x.starts_with("$TEMP_REC") || path == "text_styles.name") && y.is_empty() {
                " ($TEMP_REC)"
            } else if (repair_name(x) || repair_name(y))
                && !path.ends_with(".text")
                && !path.ends_with(".value")
            {
                " (repair)"
            } else if y.starts_with("$TD_AUDIT_GENERATED") {
                " (audit)"
            } else if path.ends_with(".type") && y == "ACAD_PROXY_ENTITY" {
                " (proxy)"
            } else if path.ends_with(".type") && x == "INSERT" && y == "HATCH" {
                " (R13 hatch)"
            } else if renumbered(x, y) {
                " (renumbered)"
            } else {
                ""
            };
            out.push((format!("{path}{note}"), format!("{a} vs {b}")));
        }
        _ => {
            let show = |v: &Value| {
                let s = v.to_string();
                match s.char_indices().nth(80) {
                    Some((i, _)) => format!("{}...", &s[..i]),
                    None => s,
                }
            };
            out.push((path.to_string(), format!("{} vs {}", show(a), show(b))));
        }
    }
}

fn number(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn len(v: &Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

/// A spline only fit points define, as a DWG stores one (spec 20.4.40,
/// scenario 2): no knots or control points.
fn fit_only(s: &Value) -> bool {
    len(&s["knots"]) == 0 && len(&s["fit_points"]) > 0
}

/// The closed (1), periodic (2) and rational (4) bits of a SPLINE's flags
/// agree but for periodic, which the converter's DXF sets for any closed
/// spline.
fn spline_bits_agree(e: i64, t: i64) -> bool {
    e & 5 == t & 5 && (t & 2 == e & 2 || e & 1 != 0)
}

/// A spline only fit points define has no closed bit in a DWG; the
/// converter's DXF sets closed and periodic when its first and last fit
/// points are the same, and rational never.
fn fit_spline_bits_agree(s: &Value, t: i64) -> bool {
    let points = s["fit_points"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let closed = match (points.first(), points.last()) {
        (Some(a), Some(b)) if points.len() > 1 => {
            let mut d = Vec::new();
            compare(a, b, "", &mut d);
            d.is_empty()
        }
        _ => false,
    };
    fit_only(s)
        && number(&s["flags"]) == 0.0
        && t & 4 == 0
        && (t & 3 == 3) == closed
        && (t & 1 == 0) == !closed
}

/// The converter's DXF gives an LWPOLYLINE whose vertices all have the
/// same width as start and end that width as its constant width (43) and
/// no vertex widths.
fn constant_width(e: &Value, t: &Value) -> bool {
    let w = number(&t["constant_width"]);
    let all = |v: &Value, f: &dyn Fn(f64) -> bool| {
        v["vertices"].as_array().is_some_and(|l| {
            !l.is_empty() && l.iter().all(|p| f(number(&p[2])) && f(number(&p[3])))
        })
    };
    number(&e["constant_width"]) == 0.0
        && w != 0.0
        && all(e, &|x| same_number(x, w))
        && all(t, &|x| x == 0.0)
}

/// An MTEXT's text the converter wrote again: the same once spaces,
/// braces, paragraph breaks and formatting codes (`\p...;`, `\F...;`,
/// `\H...;`, `\L`...) are left out.
fn same_mtext(a: &str, b: &str) -> bool {
    let plain = |s: &str| {
        let mut out = String::new();
        let mut it = s.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.peek().copied() {
                    Some('p' | 'F' | 'f' | 'H' | 'W' | 'Q' | 'T' | 'A' | 'C' | 'c') => {
                        for d in it.by_ref() {
                            if d == ';' {
                                break;
                            }
                        }
                    }
                    Some('P' | 'L' | 'l' | 'O' | 'o' | 'K' | 'k') => {
                        it.next();
                    }
                    _ => out.push(c),
                }
            } else if !c.is_whitespace() && c != '{' && c != '}' {
                out.push(c);
            }
        }
        out
    };
    plain(a) == plain(b)
}

/// A HATCH's boundary paths in one form for what draws the same: without
/// the paths around texts (flag 8, which the converter computes again from
/// the text) and the undocumented 32 flag; an arc's or ellipse's angles in
/// the first turn, a whole turn as 0 to 2 pi; an ellipse's major axis
/// pointing to positive x (its angles turned by pi); a spline's knots
/// scaled to end at 1.
fn canonical_paths(paths: &Value) -> Value {
    let tau = std::f64::consts::TAU;
    let turn = |s: f64, e: f64| -> (f64, f64) {
        if ((e - s).abs() - tau).abs() < 1e-9 {
            return (0.0, tau);
        }
        let s2 = s.rem_euclid(tau);
        (s2, s2 + (e - s).rem_euclid(tau))
    };
    let mut out = Vec::new();
    for p in paths.as_array().into_iter().flatten() {
        let flags = number(&p["flags"]) as i64;
        if flags & 8 != 0 {
            continue;
        }
        let mut p = p.clone();
        p["flags"] = (flags & !32).into();
        for edge in p["edges"].as_array_mut().into_iter().flatten() {
            match edge["type"].as_str() {
                Some("arc" | "ellipse") => {
                    let (mut s, mut e) = (number(&edge["start_angle"]), number(&edge["end_angle"]));
                    if edge["type"] == "ellipse" {
                        let (x, y) = (
                            number(&edge["major_axis"][0]),
                            number(&edge["major_axis"][1]),
                        );
                        if x < 0.0 || (x == 0.0 && y < 0.0) {
                            edge["major_axis"] = serde_json::json!([-x, -y]);
                            s += std::f64::consts::PI;
                            e += std::f64::consts::PI;
                        }
                    }
                    let (s, e) = turn(s, e);
                    edge["start_angle"] = s.into();
                    edge["end_angle"] = e.into();
                }
                Some("spline") => {
                    let last = edge["knots"]
                        .as_array()
                        .and_then(|k| k.last())
                        .map_or(0.0, number);
                    if last > 0.0 {
                        for k in edge["knots"].as_array_mut().into_iter().flatten() {
                            *k = (number(k) / last).into();
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(p);
    }
    Value::Array(out)
}

/// A LEADER the converter's DXF has without annotation (73 = 3): its
/// annotation is none in the DWG too, or a null handle.
fn leader_without_annotation(e: &Value, t: &Value) -> bool {
    t["creation"] == 3 && (e["creation"] == 3 || e["annotation"] == "0")
}

/// What the converter does to a field of an entity, when the difference is
/// that (the note the pattern gets), from the two readings.
fn note(kind: &str, k: &str, e: &Value, t: &Value, repair: &[String]) -> &'static str {
    match (kind, k) {
        ("SPLINE", "knots" | "control_points" | "weights" | "knot_tolerance")
        | ("SPLINE", "control_point_tolerance")
            if fit_only(e) =>
        {
            " (fit points)"
        }
        ("SPLINE", "flags")
            if spline_bits_agree(number(&e[k]) as i64, number(&t[k]) as i64)
                || fit_spline_bits_agree(e, number(&t[k]) as i64) =>
        {
            " (computed bits)"
        }
        // A DWG's SPLINE has no normal (spec 20.4.40): the model's is the
        // default, the converter's DXF the plane's of a planar spline.
        ("SPLINE", "extrusion") if e[k] == serde_json::json!([0.0, 0.0, 1.0]) => " (plane normal)",
        (_, "extrusion") if e[k] == serde_json::json!([0.0, 0.0, 0.0]) => " (zero normal)",
        ("ATTRIB" | "ATTDEF", "text")
            if e[k]["extrusion"] == serde_json::json!([0.0, 0.0, 0.0]) =>
        {
            " (zero normal)"
        }
        // An associative HATCH with no source objects, which the
        // converter's audit makes not associative.
        ("HATCH", "associative")
            if e[k] == true
                && t[k] == false
                && e["paths"]
                    .as_array()
                    .is_some_and(|l| l.iter().all(|p| len(&p["sources"]) == 0)) =>
        {
            " (no sources)"
        }
        ("LWPOLYLINE", "constant_width" | "vertices") if constant_width(e, t) => {
            " (constant width)"
        }
        ("MTEXT", "text")
            if same_mtext(e[k].as_str().unwrap_or(""), t[k].as_str().unwrap_or("")) =>
        {
            " (formatting)"
        }
        ("MTEXT", "x_direction")
            if t[k].is_null()
                && e[k].as_array().is_some_and(|v| {
                    v.len() == 3
                        && same_number(number(&v[0]), 1.0)
                        && number(&v[1]).abs() < 1e-12
                        && number(&v[2]).abs() < 1e-12
                }) =>
        {
            " (default)"
        }
        ("ATTDEF" | "ATTRIB", "field_length") if number(&t[k]) == 0.0 => " (field length)",
        // A boundary path's undocumented 32 bit, which the converter's DXF
        // leaves out.
        ("HATCH", "paths") => {
            let mut d = Vec::new();
            compare(&canonical_paths(&e[k]), &canonical_paths(&t[k]), "", &mut d);
            if d.is_empty() {
                " (same boundary)"
            } else {
                ""
            }
        }
        ("DIMENSION", _) if e["style"] == "" && t["style"] != "" => " (regenerated)",
        ("VIEWPORT", "id") if number(&e[k]) > 0.0 && number(&t[k]) > 0.0 => " (stacking)",
        ("VIEWPORT", "layer") if t["id"] == 1 && t[k] == "0" => " (overall)",
        ("IMAGE" | "WIPEOUT", "clip_vertices") => {
            // The DXF's vertices are the DWG's and the first again.
            let (a, b) = (&e[k], &t[k]);
            let mut d = Vec::new();
            if let (Some(list), Some(first)) = (b.as_array(), a.get(0)) {
                let mut closed = a.as_array().cloned().unwrap_or_default();
                closed.push(first.clone());
                compare(
                    &Value::Array(closed),
                    &Value::Array(list.clone()),
                    "",
                    &mut d,
                );
            }
            if len(b) == len(a) + 1 && len(a) > 0 && d.is_empty() {
                " (closed)"
            } else {
                ""
            }
        }
        ("LEADER", "hookline_direction") if e["creation"] == 3 => " (no annotation)",
        ("LEADER", "vertices") if t["hookline"] == true && e["hookline"] == false => {
            // The DXF's vertices are the DWG's with the hook's start
            // before the last.
            let (a, b) = (&e[k], &t[k]);
            let mut d = Vec::new();
            if let Some(list) = b.as_array().filter(|l| l.len() >= 2) {
                let mut without = list.clone();
                without.remove(list.len() - 2);
                compare(a, &Value::Array(without), "", &mut d);
            }
            if len(b) == len(a) + 1 && d.is_empty() {
                " (hookline)"
            } else {
                ""
            }
        }
        ("LEADER", "hookline" | "text_height" | "text_width")
            if t["hookline"] == true && e["hookline"] == false =>
        {
            " (hookline)"
        }
        ("LEADER", "text_height" | "text_width") if number(&e[k]) == 0.0 => " (no box)",
        ("LEADER", "text_height" | "text_width" | "creation" | "hookline_direction")
            if leader_without_annotation(e, t) =>
        {
            " (no annotation)"
        }
        ("VIEWPORT", "status") if number(&e[k]) > 0.0 && number(&t[k]) > 0.0 => " (stacking)",
        ("VIEWPORT", "frozen_layers") => {
            let keep = |v: &Value| -> Vec<Value> {
                v.as_array()
                    .into_iter()
                    .flatten()
                    .filter(|h| !repair.iter().any(|r| Some(r.as_str()) == h.as_str()))
                    .cloned()
                    .collect()
            };
            if keep(&e[k]) == keep(&t[k]) {
                " (repair)"
            } else {
                ""
            }
        }
        ("MTEXT", "columns") if e[k].is_null() => " (not in the MTEXT)",
        ("MTEXT", "columns") if t[k].is_null() => " (not in the DXF)",
        // A solid fill the converter's DXF names `SOLID` is `SOLID,_O` or
        // `SOLID,_I` in the DWG (an inner or outer island).
        ("HATCH", "pattern_name")
            if [",_O", ",_I"].iter().any(|suf| {
                e[k].as_str() == t[k].as_str().map(|s| format!("{s}{suf}")).as_deref()
            }) =>
        {
            " (,_O)"
        }
        _ => "",
    }
}

/// The differences of one entity, with the notes [`note`] gives.
pub fn entity_diffs(e: &Value, t: &Value, path: &str, repair: &[String]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    // A type the converter writes another as differs in all its fields.
    if e["type"] != t["type"] {
        compare(&e["type"], &t["type"], &format!("{path}.type"), &mut found);
        return found;
    }
    let kind = e["type"].as_str().unwrap_or("");
    for (k, v) in e.as_object().into_iter().flatten() {
        let p = format!("{path}.{k}");
        let mut sub = Vec::new();
        match (kind, k.as_str()) {
            // A helix's curve is a spline of its own.
            ("HELIX", "spline") => {
                let mut s = v.clone();
                s["type"] = "SPLINE".into();
                let mut u = t[k].clone();
                u["type"] = "SPLINE".into();
                sub = entity_diffs(&s, &u, &p, repair);
            }
            // An insert's attributes are entities of their own.
            ("INSERT", "attributes") if len(v) == len(&t[k]) => {
                let a = v.as_array().into_iter().flatten();
                let b = t[k].as_array().into_iter().flatten();
                for (x, y) in a.zip(b) {
                    sub.extend(entity_diffs(x, y, &format!("{p}[]"), repair));
                }
            }
            ("POLYLINE", "vertices") if len(v) == len(&t[k]) => {
                let a = v.as_array().into_iter().flatten();
                let b = t[k].as_array().into_iter().flatten();
                for (i, (x, y)) in a.zip(b).enumerate() {
                    for (f, xv) in x.as_object().into_iter().flatten() {
                        let mut d = Vec::new();
                        compare(xv, &y[f], &format!("{p}[].{f}"), &mut d);
                        // The converter leaves out a vertex's widths that
                        // equal the polyline's defaults; R13 DXF puts the
                        // elevation in each 2D vertex.
                        let default = match f.as_str() {
                            "start_width" => &e["default_start_width"],
                            "end_width" => &e["default_end_width"],
                            _ => &Value::Null,
                        };
                        let n = if number(&y[f]) == 0.0 && xv == default {
                            " (default width)"
                        } else if f == "location"
                            && x[f][2] == 0.0
                            && same_number(number(&y[f][2]), number(&e["elevation"]))
                        {
                            " (elevation)"
                        } else {
                            ""
                        };
                        sub.extend(d.into_iter().map(|(q, x)| (q + n, format!("[{i}] {x}"))));
                    }
                }
            }
            _ => {
                compare(v, &t[k], &p, &mut sub);
                let n = note(kind, k, e, t, repair);
                for d in &mut sub {
                    d.0.push_str(n);
                }
            }
        }
        found.extend(sub);
    }
    for (k, _) in t.as_object().into_iter().flatten() {
        if e.get(k).is_none() {
            found.push((format!("{path}.{k}"), "only in DXF".into()));
        }
    }
    found
}

/// The object lists of the model, compared by handle.
pub const OBJECTS: [&str; 7] = [
    "layouts",
    "dictionaries",
    "sort_tables",
    "image_defs",
    "underlay_defs",
    "mline_styles",
    "mleader_styles",
];

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap_or(""), 16).unwrap_or(0)
}

fn by_handle(v: &Value) -> BTreeMap<String, &Value> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|e| (e["handle"].as_str().unwrap_or("").to_string(), e))
        .collect()
}

/// What names an object besides its handle, to find the one the converter
/// made again under a new handle: a dictionary's owner and entry names, a
/// layout's or style's name, a sort table's block.
fn identity(kind: &str, o: &Value) -> Option<String> {
    Some(match kind {
        "dictionaries" => {
            let mut names: Vec<String> = o["entries"]
                .as_array()?
                .iter()
                .map(|e| e[0].as_str().unwrap_or("").to_string())
                .collect();
            names.sort();
            format!("{} {}", o["owner"], names.join(","))
        }
        "layouts" | "mline_styles" | "mleader_styles" => o["name"].as_str()?.to_ascii_uppercase(),
        "sort_tables" => o["block_record"].to_string(),
        _ => return None,
    })
}

/// What a dictionary entry the converter does not keep holds, by its name:
/// data it keeps for a round trip through an older version
/// (`ACAD_XREC_ROUNDTRIP`, `ACAD_MTEXT_RT`...), which it consumes when it
/// reads a DWG and writes anew under new handles when it needs it; the
/// data storage index of R2013 (`AcDsDecomposeData`); a material's maps
/// (`DIFFUSETILE`...); polysolid variables (`PSOLWIDTH`); the dictionaries
/// R13 and R14 DXF have no form of (`ACAD_TABLESTYLE`, the layouts of
/// `ACAD_LAYOUT`).
fn entry_family(name: &str) -> &'static str {
    let n = name.to_ascii_uppercase();
    if n.contains("ROUNDTRIP")
        || n.ends_with("_RT")
        || n.starts_with("ASDK_XREC_ANNO")
        || matches!(
            n.as_str(),
            "ACAD_LAYOUTSELFREF" | "ADSK_XREC_LAYOUTTHUMBNAIL" | "ACDB_RECOMPOSE_DATA"
        )
    {
        " (roundtrip)"
    } else if n.starts_with("ACDS") {
        " (data storage)"
    } else if n.starts_with("ACAD_ENHANCEDBLOCK")
        || n.starts_with("ADSK_XREC_VTR")
        || n.starts_with("DIMLTEX")
        || matches!(
            n.as_str(),
            "ACAD_DIMASSOC"
                | "ACAD_ASSOCNETWORK"
                | "ACDBBLOCKREPRESENTATION"
                | "ACDBREPDATA"
                | "APPDATACACHE"
                | "ADVMATERIAL"
                | "ACADLAYERSTATEANNOSCALE"
                | "ACDB_ANNOTATIONSCALE_VIEW_COLLECTION"
                | "ACDBCONTEXTDATAMANAGER"
                | "ACDB_ANNOTATIONSCALES"
                | "DIMARCSYM"
                | "DIMFXL"
                | "DIMFXLON"
                | "DIMJOGANG"
                | "DIMLTYPE"
                | "EDIT"
        )
    {
        " (application data)"
    } else if n == "ACAD_SORTENTS" {
        " (draw order)"
    } else if n.ends_with("TILE") {
        " (material map)"
    } else if n.starts_with("PSOL") {
        " (polysolid)"
    } else if matches!(n.as_str(), "ACAD_TABLESTYLE" | "ACAD_PLOTSTYLENAME") {
        " (R2000 dictionary)"
    } else if n == "ACAD_LAYOUT" {
        " (layout)"
    } else {
        ""
    }
}

/// The family of each dictionary of a DWG reading the converter does not
/// keep: those an entry of a family names, those holding entries of
/// families only, the header variables it keeps for a round trip (the
/// dictionary with `CEPSNTYPE`), and what these own.
fn dictionary_families(d: &Value) -> BTreeMap<String, &'static str> {
    let dicts = by_handle(&d["dictionaries"]);
    let mut out: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut todo: Vec<(String, &'static str)> = Vec::new();
    for x in dicts.values() {
        let names: Vec<&str> = x["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e[0].as_str())
            .collect();
        let own = x["handle"].as_str().unwrap_or("").to_string();
        if names.iter().any(|n| n.eq_ignore_ascii_case("CEPSNTYPE")) {
            todo.push((own.clone(), " (roundtrip)"));
        }
        if let Some(first) = names.first().map(|n| entry_family(n)) {
            if !first.is_empty() && names.iter().all(|n| !entry_family(n).is_empty()) {
                todo.push((own, first));
            }
        }
        for e in x["entries"].as_array().into_iter().flatten() {
            let f = entry_family(e[0].as_str().unwrap_or(""));
            if !f.is_empty() {
                todo.push((e[1].as_str().unwrap_or("").to_string(), f));
            }
        }
    }
    while let Some((h, f)) = todo.pop() {
        if out.contains_key(&h) {
            continue;
        }
        if let Some(x) = dicts.get(&h) {
            for e in x["entries"].as_array().into_iter().flatten() {
                todo.push((e[1].as_str().unwrap_or("").to_string(), f));
            }
        }
        out.insert(h, f);
    }
    // The extension dictionaries of what is in a family.
    loop {
        let more: Vec<(String, &'static str)> = dicts
            .iter()
            .filter(|(h, _)| !out.contains_key(*h))
            .filter_map(|(h, x)| {
                let f = out.get(x["owner"].as_str().unwrap_or(""))?;
                Some((h.clone(), *f))
            })
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    out
}

/// A list of `[name or handle, handle]` pairs as compared: the same pairs
/// in another order (DXF writes a dictionary's entries sorted by name, a
/// sort table's by entity), a sort table's entries for no entity, anonymous
/// names given in another order, pairs one side lacks, and handles that
/// differ; a DXF handle past the DWG's seed is one the converter made
/// (`remade`).
fn pairs_diff(
    kind: &str,
    a: &Value,
    b: &Value,
    seed: u64,
    fams: &BTreeMap<String, &'static str>,
    out: &mut Vec<(String, String)>,
) {
    let list = |v: &Value| -> Vec<(String, Value)> {
        v.as_array()
            .into_iter()
            .flatten()
            .map(|e| (e[0].as_str().unwrap_or("").to_string(), e[1].clone()))
            .collect()
    };
    let (la, lb) = (list(a), list(b));
    if la == lb {
        return;
    }
    // A sort table's entries for no entity (an erased one): the DWG keeps
    // each, the converter's DXF one of them.
    let real = |l: &[(String, Value)]| -> Vec<(String, Value)> {
        l.iter().filter(|(n, _)| n != "0").cloned().collect()
    };
    let (ra, rb) = (real(&la), real(&lb));
    let (mut sa, mut sb) = (ra.clone(), rb.clone());
    sa.sort_by(|x, y| x.0.cmp(&y.0));
    sb.sort_by(|x, y| x.0.cmp(&y.0));
    if sa == sb {
        let null = ra.len() != la.len() || rb.len() != lb.len();
        let sorted = if kind == "dictionaries" {
            rb.windows(2)
                .all(|w| w[0].0.to_ascii_lowercase() <= w[1].0.to_ascii_lowercase())
        } else {
            rb.windows(2)
                .all(|w| hex(&Value::from(w[0].0.as_str())) <= hex(&Value::from(w[1].0.as_str())))
        };
        let note = match (null, sorted, ra == rb) {
            (true, _, true) => " (null entity)",
            (true, true, false) => " (null entity) (order)",
            (false, true, _) => " (order)",
            _ => "",
        };
        out.push((format!("{kind}.entries{note}"), String::new()));
        return;
    }
    // Anonymous names (`*A1`) given in another order to the same objects.
    let mut ha: Vec<String> = la.iter().map(|(_, h)| h.to_string()).collect();
    let mut hb: Vec<String> = lb.iter().map(|(_, h)| h.to_string()).collect();
    ha.sort();
    hb.sort();
    let named: BTreeMap<String, &str> = lb
        .iter()
        .map(|(n, h)| (h.to_string(), n.as_str()))
        .collect();
    if ha == hb
        && la.iter().all(|(n, h)| {
            named
                .get(&h.to_string())
                .is_some_and(|m| *m == n || (n.starts_with('*') && m.starts_with('*')))
        })
    {
        out.push((format!("{kind}.entries (renumbered)"), String::new()));
        return;
    }
    // Names compare without case: R13 and R14 DXF has them in capitals.
    let mb: BTreeMap<String, (&str, &Value)> = lb
        .iter()
        .map(|(n, h)| (n.to_ascii_uppercase(), (n.as_str(), h)))
        .collect();
    let ma: BTreeMap<String, (&str, &Value)> = la
        .iter()
        .map(|(n, h)| (n.to_ascii_uppercase(), (n.as_str(), h)))
        .collect();
    for (key, (n, h)) in &ma {
        if let Some((m, _)) = mb.get(key).filter(|(m, _)| m != n) {
            out.push((format!("{kind}.entries[] (case)"), format!("{n} vs {m}")));
        }
        match mb.get(key).map(|(_, g)| g) {
            None => {
                let note = match entry_family(n) {
                    _ if hex(h) >= seed => " (remade)",
                    // A draw order entry that changes nothing: for no
                    // entity, or the entity's own handle as its sort key.
                    _ if kind == "sort_tables" && (*n == "0" || h.as_str() == Some(*n)) => {
                        " (no-op)"
                    }
                    "" => h.as_str().and_then(|h| fams.get(h).copied()).unwrap_or(""),
                    f => f,
                };
                out.push((
                    format!("{kind}.entries (only DWG){note}"),
                    format!("{n} {h}"),
                ));
            }
            Some(g) if g != h => {
                let note = if hex(g) >= seed { " (remade)" } else { "" };
                out.push((format!("{kind}.entries[]{note}"), format!("{n} {h} vs {g}")));
            }
            _ => {}
        }
    }
    for (n, h) in mb
        .iter()
        .filter(|(k, _)| !ma.contains_key(*k))
        .map(|(_, v)| v)
    {
        let note = if hex(h) >= seed { " (remade)" } else { "" };
        out.push((
            format!("{kind}.entries (only DXF){note}"),
            format!("{n} {h}"),
        ));
    }
}

/// One object against the DXF's: every field, a dictionary's or sort
/// table's entries as pairs; a model layout's last viewport, null in the
/// DWG, noted `model` when the DXF names the *Active VPORT there.
fn object_diffs(
    kind: &str,
    a: &Value,
    b: &Value,
    seed: u64,
    fams: &BTreeMap<String, &'static str>,
    active: &[String],
) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (k, v) in a.as_object().into_iter().flatten() {
        if k == "handle" {
            continue;
        }
        if k == "entries" && matches!(kind, "dictionaries" | "sort_tables") {
            pairs_diff(kind, v, &b[k], seed, fams, &mut found);
        } else if kind == "layouts" && k == "last_viewport" && v == "0" && a["name"] == "Model" {
            if b[k] != "0" {
                let note = if active.iter().any(|x| b[k] == x.as_str()) {
                    " (model)"
                } else {
                    ""
                };
                found.push((format!("{kind}.{k}{note}"), format!("{v} vs {}", b[k])));
            }
        } else {
            compare(v, &b[k], &format!("{kind}.{k}"), &mut found);
        }
    }
    found
}

/// An object's kind, its handle, and its differences: pattern and example.
pub type ObjectDiff = (&'static str, String, Vec<(String, String)>);

/// The objects of a DWG reading against those of its DXF's, by kind and
/// DWG handle (or `DXF <handle>` for one only the DXF has): by handle,
/// then an object one side lacks against one the converter made again
/// with the same identity under a handle at or past `seed` (`remade`); one
/// only one side has at or past the seed is `added`; a dictionary only
/// the DWG has is noted by its family (`empty`, `roundtrip`...). The seed
/// is the DWG's when the DXF was made from it; for a DWG and a DXF the
/// converter both made from a third file, that file's, past which each
/// has objects of its own (the same handle on both sides is then not the
/// same object, and is not compared).
pub fn object_differences(dwg: &Value, dxf: &Value, seed: u64) -> Vec<ObjectDiff> {
    let fams = dictionary_families(dwg);
    let active: Vec<String> = dxf["vports"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| {
            v["name"]
                .as_str()
                .is_some_and(|n| n.eq_ignore_ascii_case("*Active"))
        })
        .filter_map(|v| v["handle"].as_str().map(str::to_string))
        .collect();
    let mut out = Vec::new();
    for kind in OBJECTS {
        let ours = by_handle(&dwg[kind]);
        let theirs = by_handle(&dxf[kind]);
        let mut remade: BTreeMap<String, Vec<&str>> = BTreeMap::new();
        for (h, b) in theirs.iter().filter(|(h, _)| !ours.contains_key(*h)) {
            if hex(&Value::from(h.as_str())) >= seed {
                if let Some(id) = identity(kind, b) {
                    remade.entry(id).or_default().push(h.as_str());
                }
            }
        }
        let mut paired: Vec<&str> = Vec::new();
        for (h, a) in &ours {
            let made = hex(&Value::from(h.as_str())) >= seed;
            let found = match theirs.get(h) {
                Some(_) if made => continue,
                Some(b) => object_diffs(kind, a, b, seed, &fams, &active),
                None if made => vec![(format!("{kind} (only DWG) (added)"), String::new())],
                None => {
                    let twin = identity(kind, a)
                        .and_then(|id| remade.get_mut(&id))
                        .and_then(|l| (!l.is_empty()).then(|| l.remove(0)));
                    match twin {
                        Some(t) => {
                            paired.push(t);
                            let mut f = vec![(format!("{kind} (remade)"), format!("{h} vs {t}"))];
                            f.extend(object_diffs(kind, a, theirs[t], seed, &fams, &active));
                            f
                        }
                        None => {
                            let empty = a["entries"].as_array().is_some_and(|l| l.is_empty());
                            let note = match fams.get(h.as_str()) {
                                _ if kind == "dictionaries" && empty => " (empty)",
                                Some(f) if kind == "dictionaries" => *f,
                                // A draw order table of no block.
                                _ if kind == "sort_tables" && a["block_record"] == "0" => {
                                    " (no block)"
                                }
                                _ => "",
                            };
                            vec![(
                                format!("{kind} (only DWG){note}"),
                                identity(kind, a).unwrap_or_default(),
                            )]
                        }
                    }
                }
            };
            out.push((kind, h.clone(), found));
        }
        for (h, b) in theirs
            .iter()
            .filter(|(h, _)| !ours.contains_key(*h) && !paired.contains(&h.as_str()))
        {
            let note = if hex(&Value::from(h.as_str())) >= seed {
                " (added)"
            } else {
                ""
            };
            let id = identity(kind, b).unwrap_or_default();
            out.push((
                kind,
                format!("DXF {h}"),
                vec![(format!("{kind} (only DXF){note}"), id)],
            ));
        }
    }
    out
}
