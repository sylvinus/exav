//! DWG and DXF drawings into GPU-ready buffers.
//!
//! [`Document::parse`] reads the file into the drawing model
//! ([`crate::cad`]); [`Document::tessellate`] turns one layout into a
//! [`Drawing`]: interleaved stroke instances, fill triangles, text runs and
//! the layer table, so that a renderer never sees an entity. Parsing is the
//! slow part and happens once; switching layout or background tessellates
//! again from the parsed document.
//!
//! What a renderer needs to know about the buffers is on [`Drawing`]'s
//! fields. The stroke font (`stroke_font`) and the advance widths of the
//! bundled outline faces (`metrics`) are compiled in, so text is laid out the
//! same everywhere and nothing is measured by the host.

// `!(a > b)` is how this module says "not greater, or NaN": every float in it
// comes from a file, and a NaN has to fall on the safe side of each test.
#![allow(clippy::neg_cmp_op_on_partial_ord)]

mod clip;
mod curves;
mod fill;
mod font;
mod gradient;
mod hatch;
mod linetype;
mod metrics;
mod palette;
mod proxy;
mod scene;
pub mod stroke_font;
mod tessellate;
mod text;
mod tiles;

pub use curves::{flatten_arc, flatten_circle, flatten_ellipse};
pub use fill::fill_even_odd;
pub use font::{
    resolve_file, resolve_override, resolve_style, Face, Family, Metrics, TrueTypeFace, FACE_COUNT,
};
pub use hatch::nesting_depths;
pub use palette::Palette;
pub use scene::{Affine, Scene, FILL_BYTES, STROKE_BYTES};
pub use tessellate::{expand_bulges, LayerInfo, LayoutInfo, Tessellator, Warnings, SCENE_BUDGET};
pub use text::{mtext_lines, HAlign, TextRun, VAlign, TEXT_RECORD_BYTES};

/// Why a file did not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

/// Which reader a file needs, by its first bytes. `None`: neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dwg,
    Dxf,
}

impl Kind {
    /// A DWG starts with its version string (`AC1015`, `AC1032`...; a
    /// release before R13 with its header too, `AC2.10` among them, so that
    /// the reader refuses it by version). A binary DXF with its sentinel; an
    /// ASCII one with group code 0 and `SECTION`, possibly after a comment
    /// (group 999) and blank padding.
    pub fn detect(head: &[u8]) -> Option<Kind> {
        if head.len() >= 6 && head.starts_with(b"AC10") && head[4..6].iter().all(u8::is_ascii_digit)
            || exav_unpack::dwg::pre_r13_version(head).is_some()
        {
            return Some(Kind::Dwg);
        }
        if head.starts_with(b"AutoCAD Binary DXF") {
            return Some(Kind::Dxf);
        }
        let head = without_bom(head);
        let text = String::from_utf8_lossy(&head[..head.len().min(4096)]);
        let mut lines = text.lines().map(str::trim);
        while let Some(code) = lines.next() {
            match (code, lines.next()) {
                ("0", Some("SECTION")) => return Some(Kind::Dxf),
                ("999", Some(_)) => continue,
                _ => return None,
            }
        }
        None
    }
}

/// An ASCII DXF saved by a text editor may start with UTF-8's byte order mark.
fn without_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// A parsed drawing, kept so its layouts can be drawn without parsing again.
pub struct Document {
    doc: crate::cad::Drawing,
}

impl Document {
    /// Parse a DWG or a DXF, told apart by its first bytes. A reader panic on
    /// a crafted file is caught and reported as an error where unwinding is
    /// available; in a wasm build with `panic = "abort"` it traps the
    /// instance instead, and the host replaces it.
    pub fn parse(bytes: &[u8]) -> Result<Document, ParseError> {
        Self::parse_with(bytes, &crate::cad::Limits::default())
    }

    /// [`parse`](Self::parse) within `limits` (the bytes a DWG's compressed
    /// sections may expand to, string and item counts...).
    pub fn parse_with(bytes: &[u8], limits: &crate::cad::Limits) -> Result<Document, ParseError> {
        match Kind::detect(bytes) {
            Some(Kind::Dwg) => Self::parse_dwg_with(bytes, limits),
            Some(Kind::Dxf) => Self::parse_dxf_with(bytes, limits),
            None => Err(ParseError("not a DWG or DXF file".to_string())),
        }
    }

    pub fn parse_dwg(bytes: &[u8]) -> Result<Document, ParseError> {
        Self::parse_dwg_with(bytes, &crate::cad::Limits::default())
    }

    pub fn parse_dwg_with(
        bytes: &[u8],
        limits: &crate::cad::Limits,
    ) -> Result<Document, ParseError> {
        guarded(|| crate::cad::read_dwg_with(bytes, limits).map_err(|e| ParseError(e.to_string())))
    }

    pub fn parse_dxf(bytes: &[u8]) -> Result<Document, ParseError> {
        Self::parse_dxf_with(bytes, &crate::cad::Limits::default())
    }

    pub fn parse_dxf_with(
        bytes: &[u8],
        limits: &crate::cad::Limits,
    ) -> Result<Document, ParseError> {
        guarded(|| crate::cad::read_dxf_with(bytes, limits).map_err(|e| ParseError(e.to_string())))
    }

    /// The drawing model the layouts are tessellated from.
    pub fn drawing(&self) -> &crate::cad::Drawing {
        &self.doc
    }

    /// The drawing's tabs, model space first.
    pub fn layouts(&self) -> Vec<LayoutInfo> {
        Tessellator::new(&self.doc).layouts()
    }

    /// [`layouts`](Self::layouts) as JSON: `[{"name", "isModel"}]`.
    pub fn layouts_json(&self) -> String {
        let items: Vec<String> = self
            .layouts()
            .iter()
            .map(|l| {
                format!(
                    r#"{{"name":{},"isModel":{}}}"#,
                    json_string(&l.name),
                    l.is_model
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Tessellate one tab: `None`, an empty name or an unknown one draws model
    /// space. `background` is the RGB the drawing will be shown on: an indexed
    /// colour resolves against it, as in AutoCAD, so white on dark model space
    /// is black on paper.
    pub fn tessellate(&self, layout: Option<&str>, background: Option<[u8; 3]>) -> Drawing {
        self.tessellate_within(layout, background, SCENE_BUDGET)
    }

    /// [`tessellate`](Self::tessellate), stopping at `budget` strokes and fill
    /// vertices instead of [`SCENE_BUDGET`]. What is left out is counted in
    /// [`Warnings::scene_truncated`].
    pub fn tessellate_within(
        &self,
        layout: Option<&str>,
        background: Option<[u8; 3]>,
        budget: usize,
    ) -> Drawing {
        let palette = match background {
            Some([r, g, b]) => Palette::for_background(r, g, b),
            None => Palette::default(),
        };
        let mut t = Tessellator::with_palette(&self.doc, palette);
        t.budget = budget;
        let drawn = match layout {
            Some(name) if !name.is_empty() && t.run_layout(name) => name.to_string(),
            _ => {
                t.run();
                String::new()
            }
        };
        let (texts, text_strings) = t.scene.text_buffers();
        Drawing {
            layout: drawn,
            strokes: t.scene.stroke_buffer(),
            fills: t.scene.fill_buffer(),
            texts,
            text_strings,
            origin: t.scene.origin(),
            extents: t.scene.extents_local(),
            max_order: t.scene.max_order(),
            opaque_strokes: t.scene.opaque_strokes(),
            opaque_fills: t.scene.opaque_fills(),
            stroke_tiles: t.scene.stroke_tiles(),
            fill_tiles: t.scene.fill_tiles(),
            opaque_stroke_tiles: t.scene.opaque_stroke_tiles(),
            opaque_fill_tiles: t.scene.opaque_fill_tiles(),
            layers: t.layers,
            warnings: t.warnings,
        }
    }
}

fn guarded<F>(f: F) -> Result<Document, ParseError>
where
    F: FnOnce() -> Result<crate::cad::Drawing, ParseError> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(r) => r.map(|doc| Document { doc }),
        Err(_) => Err(ParseError("the drawing could not be read".to_string())),
    }
}

/// One tessellated layout.
pub struct Drawing {
    /// The layout drawn: empty for model space, including when the one asked
    /// for does not exist.
    pub layout: String,
    /// Stroke instances, [`STROKE_BYTES`] each: `f32 x0, y0, x1, y1 | u32 rgba
    /// | u32 attr | u32 order`, little-endian. `attr` packs the layer id, the
    /// lineweight and the flags (see `scene.rs`).
    pub strokes: Vec<u8>,
    /// Fill vertices, [`FILL_BYTES`] each: `f32 x, y | u32 rgba | u32 attr |
    /// u32 order`.
    pub fills: Vec<u8>,
    /// Text placement records, [`TEXT_RECORD_BYTES`] each, indexing into
    /// `text_strings`: `f32 x, y, height, rotation, widthFactor, oblique | u32
    /// rgba, attr, strOffset | u16 strLen | u8 hAlign, vAlign | u32 order | u8
    /// face | 3 bytes padding`. Only runs in an outline face appear here; a
    /// stroke-font run is drawn as strokes, so that the drawing's lineweight
    /// decides how thick its letters are.
    pub texts: Vec<u8>,
    /// UTF-8, every run's characters back to back.
    pub text_strings: Vec<u8>,
    /// World coordinates the buffers are relative to.
    pub origin: [f64; 2],
    /// `[min_x, min_y, max_x, max_y]`, relative to `origin`.
    pub extents: [f32; 4],
    /// Highest draw-order index, for normalising depth.
    pub max_order: u32,
    /// Leading strokes and fill vertices that are opaque; the rest are
    /// translucent and are drawn after, without writing depth.
    pub opaque_strokes: usize,
    pub opaque_fills: usize,
    /// Spatial buckets: `u32 start, count | f32 min_x, min_y, max_x, max_y`,
    /// 24 bytes each, `start` and `count` in strokes (in vertices for fills).
    /// The box is the true extent of the contents, which can reach outside
    /// the bucket's grid square.
    pub stroke_tiles: Vec<u8>,
    pub fill_tiles: Vec<u8>,
    /// Leading entries of each table covering the opaque half.
    pub opaque_stroke_tiles: usize,
    pub opaque_fill_tiles: usize,
    /// The layer table; a vertex's layer id indexes it.
    pub layers: Vec<LayerInfo>,
    /// What could not be drawn.
    pub warnings: Warnings,
}

impl Drawing {
    pub fn stroke_count(&self) -> usize {
        self.strokes.len() / STROKE_BYTES
    }

    pub fn fill_vertex_count(&self) -> usize {
        self.fills.len() / FILL_BYTES
    }

    pub fn text_count(&self) -> usize {
        self.texts.len() / TEXT_RECORD_BYTES
    }

    /// The layer table as JSON: `[{"name", "color", "lineweight", "off",
    /// "frozen"}]`, `color` packed little-endian RGBA, `lineweight` in
    /// hundredths of a millimetre (0 is a hairline).
    pub fn layers_json(&self) -> String {
        let items: Vec<String> = self
            .layers
            .iter()
            .map(|l| {
                format!(
                    r#"{{"name":{},"color":{},"lineweight":{},"off":{},"frozen":{}}}"#,
                    json_string(&l.name),
                    l.rgba,
                    l.lineweight,
                    l.off,
                    l.frozen
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// [`Warnings`] as JSON. All zeroes means everything was drawn.
    pub fn warnings_json(&self) -> String {
        let w = &self.warnings;
        format!(
            r#"{{"unknownEntities":{},"missingBlocks":{},"textRuns":{},"strokeGlyphs":{},"hatchPatternsMissing":{},"hatchPatternsTruncated":{},"externalReferences":{},"depthExceeded":{},"sceneTruncated":{},"proxyWithoutGraphics":{}}}"#,
            w.unknown_entities,
            w.missing_blocks,
            w.text_runs,
            w.stroke_glyphs,
            w.hatch_patterns_missing,
            w.hatch_patterns_truncated,
            w.external_references,
            w.depth_exceeded,
            w.scene_truncated,
            w.proxy_without_graphics
        )
    }
}

/// JSON string escaping. Layer and layout names are file data and routinely
/// hold quotes, backslashes and control characters.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes_hostile_names() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
        assert_eq!(json_string(r"a\b"), r#""a\\b""#);
        assert_eq!(json_string("a\nb"), r#""a\nb""#);
        assert_eq!(json_string("a\u{1}b"), "\"a\\u0001b\"");
        assert_eq!(json_string("WALLS-EXT"), r#""WALLS-EXT""#);
    }

    #[test]
    fn a_file_is_told_apart_by_its_first_bytes() {
        assert_eq!(Kind::detect(b"AC1032\0\0"), Some(Kind::Dwg));
        assert_eq!(Kind::detect(b"AC10xx"), None);
        assert_eq!(
            Kind::detect(b"AutoCAD Binary DXF\r\n\x1a\0"),
            Some(Kind::Dxf)
        );
        assert_eq!(
            Kind::detect(b"  0\r\nSECTION\r\n  2\r\nHEADER\r\n"),
            Some(Kind::Dxf)
        );
        assert_eq!(
            Kind::detect(b"999\nmade by hand\n0\nSECTION\n"),
            Some(Kind::Dxf)
        );
        assert_eq!(Kind::detect(b"%PDF-1.7"), None);
        assert_eq!(Kind::detect(b""), None);
    }
}
