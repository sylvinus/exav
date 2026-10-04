//! The WebAssembly half of `@exav/viewer`. Built five times (see
//! `Cargo.toml`): with `image`, exav-render's raster decoders; with `dwg`,
//! its DWG and DXF engine; with `model`, its IFC and STL meshes; with
//! `pdf-jpx` and `pdf-jbig2`, the image
//! decoders pdf.js loads in place of its C and C++ ones. Each runs in a
//! worker, and only finished pixels or vertex buffers cross back to the
//! page.

#![forbid(unsafe_code)]

#[cfg(feature = "image")]
mod image {
    use exav_render::image::{decode_any, Error, Format};
    use wasm_bindgen::prelude::*;

    /// A decoded image, as RGBA8.
    #[wasm_bindgen]
    pub struct DecodedImage {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    }

    #[wasm_bindgen]
    impl DecodedImage {
        #[wasm_bindgen(getter)]
        pub fn width(&self) -> u32 {
            self.width
        }

        #[wasm_bindgen(getter)]
        pub fn height(&self) -> u32 {
            self.height
        }

        /// `width * height * 4` bytes, row-major. Moves the pixels out: a
        /// second call returns nothing.
        #[wasm_bindgen(js_name = takeRgba)]
        pub fn take_rgba(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.rgba)
        }
    }

    /// The format the first bytes name, or `undefined`.
    #[wasm_bindgen(js_name = imageFormat)]
    pub fn image_format(head: &[u8]) -> Option<String> {
        Format::detect(head).map(|f| f.name().to_string())
    }

    /// Decode within `max_bytes` of decoded pixels (as RGBA8, the form the
    /// page gets them in, so the limit is what the page will hold).
    #[wasm_bindgen(js_name = decodeImage)]
    pub fn decode_image(bytes: &[u8], max_bytes: f64) -> Result<DecodedImage, JsError> {
        // Saturating: Infinity is no limit but the module's memory, NaN and
        // anything not positive refuse every image.
        let max = max_bytes as u64;
        let p = decode_any(bytes, max).map_err(|e| {
            JsError::new(match e {
                Error::Unsupported => "unsupported",
                Error::TooLarge => "too-large",
                _ => "undecodable",
            })
        })?;
        // Checked before converting: a grey image takes four times its
        // decoded size as RGBA8.
        if u64::from(p.width) * u64::from(p.height) * 4 > max {
            return Err(JsError::new("too-large"));
        }
        Ok(DecodedImage {
            width: p.width,
            height: p.height,
            rgba: p.to_rgba8(),
        })
    }
}

#[cfg(feature = "dwg")]
mod dwg {
    use exav_render::dwg;
    use wasm_bindgen::prelude::*;

    /// A tessellated layout. Each buffer getter moves its buffer out, so
    /// the page can transfer it rather than copy it again.
    #[wasm_bindgen]
    pub struct Drawing(dwg::Drawing);

    #[wasm_bindgen]
    impl Drawing {
        #[wasm_bindgen(getter)]
        pub fn layout(&self) -> String {
            self.0.layout.clone()
        }

        #[wasm_bindgen(js_name = takeStrokes)]
        pub fn take_strokes(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.strokes)
        }

        #[wasm_bindgen(js_name = takeFills)]
        pub fn take_fills(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.fills)
        }

        #[wasm_bindgen(js_name = takeTexts)]
        pub fn take_texts(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.texts)
        }

        #[wasm_bindgen(js_name = takeTextStrings)]
        pub fn take_text_strings(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.text_strings)
        }

        #[wasm_bindgen(js_name = takeStrokeTiles)]
        pub fn take_stroke_tiles(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.stroke_tiles)
        }

        #[wasm_bindgen(js_name = takeFillTiles)]
        pub fn take_fill_tiles(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.fill_tiles)
        }

        pub fn origin(&self) -> Vec<f64> {
            self.0.origin.to_vec()
        }

        pub fn extents(&self) -> Vec<f32> {
            self.0.extents.to_vec()
        }

        #[wasm_bindgen(js_name = maxOrder)]
        pub fn max_order(&self) -> u32 {
            self.0.max_order
        }

        #[wasm_bindgen(js_name = opaqueStrokes)]
        pub fn opaque_strokes(&self) -> usize {
            self.0.opaque_strokes
        }

        #[wasm_bindgen(js_name = opaqueFills)]
        pub fn opaque_fills(&self) -> usize {
            self.0.opaque_fills
        }

        #[wasm_bindgen(js_name = opaqueStrokeTiles)]
        pub fn opaque_stroke_tiles(&self) -> usize {
            self.0.opaque_stroke_tiles
        }

        #[wasm_bindgen(js_name = opaqueFillTiles)]
        pub fn opaque_fill_tiles(&self) -> usize {
            self.0.opaque_fill_tiles
        }

        #[wasm_bindgen(js_name = layersJson)]
        pub fn layers_json(&self) -> String {
            self.0.layers_json()
        }

        #[wasm_bindgen(js_name = warningsJson)]
        pub fn warnings_json(&self) -> String {
            self.0.warnings_json()
        }
    }

    /// A parsed DWG or DXF.
    #[wasm_bindgen]
    pub struct Document(dwg::Document);

    #[wasm_bindgen]
    impl Document {
        /// `[{name, isModel}]`, model space first.
        #[wasm_bindgen(js_name = layoutsJson)]
        pub fn layouts_json(&self) -> String {
            self.0.layouts_json()
        }

        /// One layout; none, empty or unknown is model space. `background` is
        /// the RGB the drawing is shown on, which indexed colours resolve
        /// against. Stops at `max_primitives` strokes and fill vertices.
        pub fn tessellate(
            &self,
            layout: Option<String>,
            background: Option<Vec<u8>>,
            max_primitives: f64,
        ) -> Drawing {
            let bg = background.and_then(|b| (b.len() >= 3).then(|| [b[0], b[1], b[2]]));
            // Saturating: Infinity is no limit but the module's memory, NaN
            // and anything not positive draw nothing.
            let budget = max_primitives as usize;
            Drawing(self.0.tessellate_within(layout.as_deref(), bg, budget))
        }
    }

    /// The thumbnail a drawing was saved with, as an image file.
    #[wasm_bindgen]
    pub struct Preview(exav_render::cad::Preview);

    #[wasm_bindgen]
    impl Preview {
        /// `image/png` or `image/bmp`.
        #[wasm_bindgen(getter)]
        pub fn mime(&self) -> String {
            self.0.format.mime().to_string()
        }

        #[wasm_bindgen(js_name = takeData)]
        pub fn take_data(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.data)
        }
    }

    /// A DWG's or an ASCII DXF's thumbnail, read without reading the
    /// drawing: from where the DWG file header points, from the end of the
    /// DXF.
    #[wasm_bindgen(js_name = drawingPreview)]
    pub fn drawing_preview(bytes: &[u8]) -> Option<Preview> {
        exav_render::cad::preview(bytes).map(Preview)
    }

    /// The version ID of a DWG of a release the engine does not read (R12
    /// and older: `AC1009`, `AC2.10`...), from its first bytes.
    #[wasm_bindgen(js_name = unsupportedDrawingVersion)]
    pub fn unsupported_drawing_version(bytes: &[u8]) -> Option<String> {
        exav_render::cad::pre_r13_version(bytes).map(str::to_string)
    }

    /// Parse a DWG or a DXF, told apart by its first bytes. A DWG whose
    /// compressed sections expand past `max_decompressed_bytes` is refused.
    #[wasm_bindgen(js_name = parseDrawing)]
    pub fn parse_drawing(bytes: &[u8], max_decompressed_bytes: f64) -> Result<Document, JsError> {
        // Saturating: Infinity is no limit, NaN and anything not positive
        // refuse every compressed section.
        let limits = exav_render::cad::Limits {
            max_decompressed_bytes: max_decompressed_bytes as u64,
            ..exav_render::cad::Limits::default()
        };
        dwg::Document::parse_with(bytes, &limits)
            .map(Document)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

#[cfg(feature = "model")]
mod model {
    use exav_render::mesh::Scene;
    use wasm_bindgen::prelude::*;

    /// A meshed model: every batch's buffers end to end, and `metaJson`
    /// saying where each batch's part starts. Each `take` getter moves its
    /// buffer out.
    #[wasm_bindgen]
    pub struct Model {
        positions: Vec<f32>,
        normals: Vec<f32>,
        indices: Vec<u32>,
        edges: Vec<f32>,
        colors: Vec<u8>,
        meta: String,
    }

    #[wasm_bindgen]
    impl Model {
        /// xyz per vertex, relative to the origin `metaJson` gives.
        #[wasm_bindgen(js_name = takePositions)]
        pub fn take_positions(&mut self) -> Vec<f32> {
            std::mem::take(&mut self.positions)
        }

        #[wasm_bindgen(js_name = takeNormals)]
        pub fn take_normals(&mut self) -> Vec<f32> {
            std::mem::take(&mut self.normals)
        }

        /// Three per triangle, each batch's into its own vertices.
        #[wasm_bindgen(js_name = takeIndices)]
        pub fn take_indices(&mut self) -> Vec<u32> {
            std::mem::take(&mut self.indices)
        }

        /// Pairs of xyz: the outline.
        #[wasm_bindgen(js_name = takeEdges)]
        pub fn take_edges(&mut self) -> Vec<f32> {
            std::mem::take(&mut self.edges)
        }

        /// RGB per vertex, for the batches that colour their vertices.
        #[wasm_bindgen(js_name = takeColors)]
        pub fn take_colors(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.colors)
        }

        /// `{origin, bounds, batches: [{class, color, vertex, vertices,
        /// index, indices, edge, edges, color0}], elements: [{id,
        /// globalId, class, name, node, ranges: [[batch, first, count]]}],
        /// nodes: [{id, class, name, parent}], warnings}`; offsets in
        /// elements of their arrays (`color0` in bytes, -1 for none).
        #[wasm_bindgen(js_name = metaJson)]
        pub fn meta_json(&self) -> String {
            self.meta.clone()
        }
    }

    fn string(out: &mut String, s: &str) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    fn number(out: &mut String, v: f64) {
        if v.is_finite() {
            out.push_str(&format!("{v}"));
        } else {
            out.push_str("null");
        }
    }

    fn pack(scene: Scene) -> Model {
        let vertices: usize = scene.batches.iter().map(|b| b.positions.len()).sum();
        let mut m = Model {
            positions: Vec::with_capacity(vertices),
            normals: Vec::with_capacity(vertices),
            indices: Vec::with_capacity(scene.batches.iter().map(|b| b.indices.len()).sum()),
            edges: Vec::with_capacity(scene.batches.iter().map(|b| b.edges.len()).sum()),
            colors: Vec::new(),
            meta: String::new(),
        };
        let o = &mut m.meta;
        o.push_str("{\"origin\":[");
        for (k, v) in scene.origin.iter().enumerate() {
            if k > 0 {
                o.push(',');
            }
            number(o, *v);
        }
        o.push_str("],\"bounds\":");
        match scene.bounds {
            Some(b) => {
                o.push('[');
                for (k, v) in b.iter().flatten().enumerate() {
                    if k > 0 {
                        o.push(',');
                    }
                    number(o, f64::from(*v));
                }
                o.push(']');
            }
            None => o.push_str("null"),
        }
        o.push_str(",\"batches\":[");
        for (i, b) in scene.batches.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str("{\"class\":");
            string(o, &b.class);
            o.push_str(",\"color\":");
            match b.color {
                Some(c) => {
                    o.push('[');
                    for (k, v) in c.iter().enumerate() {
                        if k > 0 {
                            o.push(',');
                        }
                        number(o, f64::from(*v));
                    }
                    o.push(']');
                }
                None => o.push_str("null"),
            }
            let color0 = match &b.colors {
                Some(c) => {
                    let at = m.colors.len() as i64;
                    m.colors.extend_from_slice(c);
                    at
                }
                None => -1,
            };
            o.push_str(&format!(
                ",\"vertex\":{},\"vertices\":{},\"index\":{},\"indices\":{},\"edge\":{},\"edges\":{},\"color0\":{}}}",
                m.positions.len() / 3,
                b.positions.len() / 3,
                m.indices.len(),
                b.indices.len(),
                m.edges.len() / 3,
                b.edges.len() / 3,
                color0
            ));
            m.positions.extend_from_slice(&b.positions);
            m.normals.extend_from_slice(&b.normals);
            m.indices.extend_from_slice(&b.indices);
            m.edges.extend_from_slice(&b.edges);
        }
        o.push_str("],\"elements\":[");
        for (i, e) in scene.elements.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"id\":{},\"globalId\":", e.id));
            string(o, &e.global_id);
            o.push_str(",\"class\":");
            string(o, &e.class);
            o.push_str(",\"name\":");
            string(o, &e.name);
            match e.node {
                Some(n) => o.push_str(&format!(",\"node\":{n}")),
                None => o.push_str(",\"node\":null"),
            }
            o.push_str(",\"ranges\":[");
            for (k, r) in e.ranges.iter().enumerate() {
                if k > 0 {
                    o.push(',');
                }
                o.push_str(&format!("[{},{},{}]", r.batch, r.first, r.count));
            }
            o.push_str("]}");
        }
        o.push_str("],\"nodes\":[");
        for (i, n) in scene.nodes.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            o.push_str(&format!("{{\"id\":{},\"class\":", n.id));
            string(o, &n.class);
            o.push_str(",\"name\":");
            string(o, &n.name);
            match n.parent {
                Some(p) => o.push_str(&format!(",\"parent\":{p}}}")),
                None => o.push_str(",\"parent\":null}"),
            }
        }
        let w = &scene.warnings;
        o.push_str("],\"warnings\":{\"unsupported\":{");
        for (i, (k, v)) in w.unsupported.iter().enumerate() {
            if i > 0 {
                o.push(',');
            }
            string(o, k);
            o.push_str(&format!(":{v}"));
        }
        o.push_str(&format!(
            "}},\"invalid\":{},\"booleansSkipped\":{},\"truncated\":{},\"damaged\":{}}}}}",
            w.invalid, w.booleans_skipped, w.truncated, w.damaged
        ));
        m
    }

    /// Saturating: Infinity is no limit but the module's memory, NaN and
    /// anything not positive draw nothing.
    fn budget(max_triangles: f64) -> usize {
        max_triangles as usize
    }

    /// Reads an IFC model within `max_triangles`.
    #[wasm_bindgen(js_name = parseIfc)]
    pub fn parse_ifc(bytes: &[u8], max_triangles: f64) -> Result<Model, JsError> {
        let limits = exav_render::ifc::Limits {
            max_triangles: budget(max_triangles),
        };
        exav_render::ifc::read(bytes, &limits)
            .map(pack)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Reads a binary or ASCII STL within `max_triangles`.
    #[wasm_bindgen(js_name = parseStl)]
    pub fn parse_stl(bytes: &[u8], max_triangles: f64) -> Result<Model, JsError> {
        exav_render::stl::read(bytes, budget(max_triangles))
            .map(pack)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Most bytes a pdf.js image decode may take in the module.
#[cfg(any(feature = "pdf-jpx", feature = "pdf-jbig2"))]
const PDF_IMAGE_MAX: u64 = 1 << 30;

/// The functions `openjpeg_nowasm_fallback.js` puts behind pdf.js's
/// `_jp2_decode`.
#[cfg(feature = "pdf-jpx")]
mod pdf_jpx {
    use exav_render::pdf_image::{decode_jpx, JpxParams};
    use wasm_bindgen::prelude::*;

    /// The pixels pdf.js reads, or `undefined` where its decoder gives none.
    /// Throws the message pdf.js reports.
    #[wasm_bindgen(js_name = decodeJpx)]
    pub fn decode(
        bytes: &[u8],
        num_components: u32,
        indexed: bool,
        smask_in_data: bool,
        reduce_power: u32,
    ) -> Result<Option<Vec<u8>>, JsError> {
        let params = JpxParams {
            num_components,
            indexed,
            smask_in_data,
            reduce_power,
        };
        decode_jpx(bytes, params, super::PDF_IMAGE_MAX)
            .map(|image| image.map(|i| i.data))
            .map_err(|e| JsError::new(e.message()))
    }
}

/// The functions `jbig2_nowasm_fallback.js` puts behind pdf.js's
/// `_jbig2_decode` and `_ccitt_decode`.
#[cfg(feature = "pdf-jbig2")]
mod pdf_jbig2 {
    use exav_render::pdf_image::{decode_ccitt, decode_jbig2, CcittParams};
    use wasm_bindgen::prelude::*;

    /// Rows of 1-bit pixels, 1 for white. Empty `globals` is none.
    #[wasm_bindgen(js_name = decodeJbig2)]
    pub fn jbig2(
        bytes: &[u8],
        width: u32,
        height: u32,
        globals: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let globals = (!globals.is_empty()).then_some(globals);
        decode_jbig2(bytes, width, height, globals, super::PDF_IMAGE_MAX)
            .map_err(|e| JsError::new(e.message()))
    }

    /// Rows of 1-bit pixels, as `/BlackIs1` has them.
    #[wasm_bindgen(js_name = decodeCcitt)]
    #[allow(clippy::too_many_arguments)]
    pub fn ccitt(
        bytes: &[u8],
        width: u32,
        height: u32,
        k: i32,
        end_of_line: bool,
        encoded_byte_align: bool,
        black_is_1: bool,
        columns: u32,
        rows: u32,
    ) -> Result<Vec<u8>, JsError> {
        let params = CcittParams {
            width,
            height,
            k,
            end_of_line,
            encoded_byte_align,
            black_is_1,
            columns,
            rows,
        };
        decode_ccitt(bytes, params, super::PDF_IMAGE_MAX).map_err(|e| JsError::new(e.message()))
    }
}
