//! The text of a PDF, read by hayro: it interprets each page and hands over
//! its glyphs with their Unicode (the font's `ToUnicode`, else the glyph's name),
//! and this puts them back in lines and words from where they sit.
//!
//! hayro puts no bound on what a stream decompresses to, nor on the size of the
//! image a dictionary or a codec's header declares (a 123 KB PDF with JBIG2
//! data for 100000 by 100000 pixels took it 8.9 GB), so it is given a PDF only
//! after this crate's own reader has taken every stream of it within the budget
//! (what the scanner does anyway) and `pdf_screen` has read no image size past
//! its bound; one that does not pass is cut, not read. A PDF that hayro cannot
//! open (encrypted with a password, too damaged) has no text here. A panic in
//! hayro is contained.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use hayro_interpret::font::{Glyph, GlyphRun};
use hayro_interpret::hayro_cmap::BfString;
use hayro_interpret::{
    interpret_page, BlendMode, CacheKey, ClipPath, Context, Device, DrawMode, DrawProps, Image,
    ImageDrawProps, InterpreterCache, InterpreterSettings, SoftMask,
};
use hayro_syntax::Pdf;
use kurbo::{Affine, BezPath, Point, Rect, Shape};

use super::pdf_screen::images_are_small;
use super::Out;
use crate::{Budget, Format, Limits};

/// Glyph shapes remembered, for how far each reaches.
const MAX_REMEMBERED: usize = 1 << 16;

pub(super) fn read(data: &[u8], limits: &Limits, out: &mut Out) {
    // An encrypted PDF has no text here: hayro opens none, and the scanner
    // reports it as encrypted on its own.
    if memchr::memmem::find(data, b"/Encrypt").is_some() {
        return;
    }
    if !images_are_small(data, limits.max_buffer_bytes) {
        out.cut();
        return;
    }
    // Every stream within the budget first: hayro does not look.
    let mut budget = Budget::new(limits.clone());
    match crate::walk(Format::Pdf, &data, &mut budget, &mut |_, _, _| None::<()>) {
        Ok(_) => {}
        Err(_) => {
            out.cut();
            return;
        }
    }
    let read = catch_unwind(AssertUnwindSafe(|| pages(data, out)));
    if read.is_err() {
        out.cut();
    }
}

fn pages(data: &[u8], out: &mut Out) {
    let Ok(pdf) = Pdf::new(data.to_vec()) else {
        return;
    };
    let cache = InterpreterCache::new();
    let mut device = Lines {
        out,
        last: None,
        reach: HashMap::new(),
    };
    for page in pdf.pages().iter() {
        if device.out.full() {
            return;
        }
        let settings = InterpreterSettings {
            render_annotations: false,
            ..InterpreterSettings::default()
        };
        let mut context = Context::new(
            Affine::IDENTITY,
            Rect::new(0.0, 0.0, 1.0, 1.0),
            &cache,
            pdf.xref(),
            settings,
        );
        interpret_page(page, &mut context, &mut device);
        device.out.newline();
        device.last = None;
    }
}

/// Where the last glyph ended.
struct Last {
    right: f64,
    y: f64,
}

struct Lines<'o> {
    out: &'o mut Out,
    last: Option<Last>,
    /// How far right of its origin each glyph shape reaches, in 1000 units to
    /// the em.
    reach: HashMap<u128, f64>,
}

impl Device<'_> for Lines<'_> {
    fn draw_path(&mut self, _: &BezPath, _: DrawProps<'_>, _: &DrawMode) {}

    fn push_clip_path(&mut self, _: &ClipPath) {}

    fn push_transparency_group(&mut self, _: f32, _: Option<SoftMask<'_>>, _: BlendMode) {}

    fn draw_glyph_run(&mut self, run: &GlyphRun<'_, '_>, props: DrawProps<'_>, _: &DrawMode) {
        for glyph in run.glyphs() {
            if self.out.full() {
                return;
            }
            let m = props.transform * glyph.transform();
            let origin = m * Point::ZERO;
            let em = ((m * Point::new(0.0, 1000.0)) - origin).hypot().max(1e-6);
            let reach = match &**glyph {
                Glyph::Outline(g) => {
                    let key = g.identifier().cache_key();
                    match self.reach.get(&key) {
                        Some(r) => *r,
                        None => {
                            let r = g.outline().bounding_box().x1.max(0.0);
                            if self.reach.len() < MAX_REMEMBERED {
                                self.reach.insert(key, r);
                            }
                            r
                        }
                    }
                }
                Glyph::Type3(_) => 500.0,
            };
            let right = (m * Point::new(reach, 0.0)).x;
            if let Some(last) = &self.last {
                if (origin.y - last.y).abs() > em * 0.5 {
                    self.out.newline();
                } else if origin.x - last.right > em * 0.12 {
                    self.out.space();
                }
            }
            self.last = Some(Last { right, y: origin.y });
            match glyph.as_unicode() {
                Some(BfString::Char(c)) => self.out.text(c.encode_utf8(&mut [0; 4])),
                Some(BfString::String(s)) => self.out.text(&s),
                None => {}
            }
        }
    }

    fn draw_image(&mut self, _: Image<'_, '_>, _: ImageDrawProps<'_>) {}

    fn pop_clip(&mut self) {}

    fn pop_transparency_group(&mut self) {}
}
