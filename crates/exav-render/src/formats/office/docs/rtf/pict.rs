//! Pictures: `\pict` groups with their hexadecimal or binary data.

use super::{Parser, St};
use crate::formats::office::common::image;
use crate::formats::office::docs::error::{Error, Result};
use crate::formats::office::docs::model::*;

#[derive(Default)]
pub(crate) struct Pict {
    pub kind: Option<&'static str>,
    pub picw: i32,
    pub pich: i32,
    pub wgoal: i32,
    pub hgoal: i32,
    pub scale_x: i32,
    pub scale_y: i32,
    pub crop: [i32; 4],
    pub data: Vec<u8>,
    pub half: Option<u8>,
    pub binary: bool,
    pub over: bool,
}

impl Parser<'_> {
    pub(crate) fn pict_word(&mut self, w: &str, n: Option<i32>, _max: u64) -> Result<()> {
        let v = n.unwrap_or(0);
        let Some(p) = self.pict.as_mut() else {
            return Ok(());
        };
        match w {
            "pngblip" => p.kind = Some("png"),
            "jpegblip" => p.kind = Some("jpeg"),
            "emfblip" => p.kind = Some("emf"),
            "wmetafile" => p.kind = Some("wmf"),
            "dibitmap" => p.kind = Some("dib"),
            "wbitmap" | "macpict" | "pmmetafile" => p.kind = Some("unsupported"),
            "picw" => p.picw = v,
            "pich" => p.pich = v,
            "picwgoal" => p.wgoal = v,
            "pichgoal" => p.hgoal = v,
            "picscalex" => p.scale_x = v,
            "picscaley" => p.scale_y = v,
            "piccropl" => p.crop[0] = v,
            "piccropt" => p.crop[1] = v,
            "piccropr" => p.crop[2] = v,
            "piccropb" => p.crop[3] = v,
            "binary" => {}
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn pict_data(&mut self, t: &[u8]) {
        let max = self.b.limits.max_part as usize;
        let Some(p) = self.pict.as_mut() else { return };
        if p.over {
            return;
        }
        for &c in t {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => continue,
            };
            match p.half.take() {
                Some(h) => p.data.push(h << 4 | d),
                None => p.half = Some(d),
            }
            if p.data.len() > max {
                p.over = true;
                p.data.clear();
                return;
            }
        }
    }

    pub(crate) fn pict_bin(&mut self, d: &[u8]) {
        let max = self.b.limits.max_part as usize;
        if let Some(p) = self.pict.as_mut() {
            if p.data.len() + d.len() > max {
                p.over = true;
                return;
            }
            p.data.extend_from_slice(d);
            p.binary = true;
        }
    }

    pub(crate) fn finish_pict(&mut self, st: &St) -> Result<()> {
        let Some(p) = self.pict.take() else {
            return Ok(());
        };
        let _ = st;
        if p.over {
            return Err(Error::TooLarge("a picture"));
        }
        if p.data.is_empty() || p.kind == Some("unsupported") {
            return Ok(());
        }
        let mut data = p.data;
        if p.kind == Some("dib") {
            data = image::dib_to_bmp(&data);
        }
        let Some(ext) = image::ext(&data).or(match p.kind {
            Some("wmf") => Some("wmf"),
            _ => None,
        }) else {
            return Ok(());
        };
        if ext == "wmf" && !data.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) && p.picw > 0 && p.pich > 0
        {
            // A bare metafile: give it the bounds the group states.
            let inch = if p.wgoal > 0 {
                (f64::from(p.picw) / (f64::from(p.wgoal) / 1440.0))
                    .round()
                    .clamp(1.0, 65535.0) as u16
            } else {
                1440
            };
            let mut h = vec![0xD7, 0xCD, 0xC6, 0x9A, 0, 0];
            for v in [
                0i16,
                0,
                p.picw.clamp(0, 32767) as i16,
                p.pich.clamp(0, 32767) as i16,
            ] {
                h.extend_from_slice(&v.to_le_bytes());
            }
            h.extend_from_slice(&inch.to_le_bytes());
            h.extend_from_slice(&[0, 0, 0, 0]);
            let mut sum = 0u16;
            for k in 0..10 {
                sum ^= u16::from_le_bytes([h[2 * k], h[2 * k + 1]]);
            }
            h.extend_from_slice(&sum.to_le_bytes());
            h.extend_from_slice(&data);
            data = h;
        }
        self.b.alloc(data.len() as u64)?;
        let natural = image::natural_emu(&data);
        let sx = if p.scale_x > 0 {
            i64::from(p.scale_x)
        } else {
            100
        };
        let sy = if p.scale_y > 0 {
            i64::from(p.scale_y)
        } else {
            100
        };
        let (cx, cy) = if p.wgoal > 0 && p.hgoal > 0 {
            (
                i64::from(p.wgoal) * 635 * sx / 100,
                i64::from(p.hgoal) * 635 * sy / 100,
            )
        } else if let Some((nx, ny)) = natural {
            (nx * sx / 100, ny * sy / 100)
        } else {
            (
                i64::from(p.picw.max(1)) * 360,
                i64::from(p.pich.max(1)) * 360,
            )
        };
        let gw = f64::from(p.wgoal.max(1));
        let gh = f64::from(p.hgoal.max(1));
        let crop = |v: i32, g: f64| ((f64::from(v) / g) * 100_000.0) as i32;
        let crop = Crop {
            l: crop(p.crop[0], gw),
            t: crop(p.crop[1], gh),
            r: crop(p.crop[2], gw),
            b: crop(p.crop[3], gh),
        };
        let media = self.doc.add_media(ext, data);
        self.add_item(RunItem::Drawing(Box::new(Drawing {
            anchor: None,
            cx: cx.max(1),
            cy: cy.max(1),
            name: "Picture".into(),
            descr: None,
            kind: DrawingKind::Picture { media, crop },
        })));
        Ok(())
    }
}
