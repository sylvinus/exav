//! Static feature extraction and a pluggable scorer.
//!
//! [`extract`] builds an EMBER-style fixed-length feature vector from raw
//! bytes and parsed PE structure. The [`Model`] trait scores those features;
//! implement it to plug in a trained model. The bundled [`HeuristicModel`]
//! is a weighted combination of interpretable signals, not a trained
//! classifier.

use crate::pe::PeInfo;

/// A fixed-length static feature vector.
pub struct Features {
    /// Normalized byte histogram (256 bins summing to 1.0).
    pub byte_histogram: [f32; 256],
    /// Overall Shannon entropy of the file (bits/byte).
    pub file_entropy: f32,
    pub size: u64,
    // PE structural features (zeroed for non-PE inputs).
    pub is_pe: bool,
    pub section_count: f32,
    pub max_section_entropy: f32,
    pub import_count: f32,
    pub suspicious_import_count: f32,
}

impl Features {
    /// Flatten to a single dense vector (histogram followed by scalars).
    /// This is the input a trained model would consume.
    pub fn to_vec(&self) -> Vec<f32> {
        let mut v = Vec::with_capacity(256 + 7);
        v.extend_from_slice(&self.byte_histogram);
        v.push(self.file_entropy);
        v.push(self.size as f32);
        v.push(if self.is_pe { 1.0 } else { 0.0 });
        v.push(self.section_count);
        v.push(self.max_section_entropy);
        v.push(self.import_count);
        v.push(self.suspicious_import_count);
        v
    }
}

/// Extract static features from raw bytes plus optional parsed PE info.
pub fn extract(data: &[u8], pe: Option<&PeInfo>) -> Features {
    let mut hist = [0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let len = data.len().max(1) as f32;
    let mut byte_histogram = [0f32; 256];
    for i in 0..256 {
        byte_histogram[i] = hist[i] as f32 / len;
    }
    let file_entropy = crate::pe::shannon_entropy(data) as f32;

    let mut f = Features {
        byte_histogram,
        file_entropy,
        size: data.len() as u64,
        is_pe: false,
        section_count: 0.0,
        max_section_entropy: 0.0,
        import_count: 0.0,
        suspicious_import_count: 0.0,
    };
    if let Some(pe) = pe {
        f.is_pe = true;
        f.section_count = pe.section_count as f32;
        f.max_section_entropy = pe.max_entropy as f32;
        f.import_count = pe.import_count as f32;
        f.suspicious_import_count = pe.suspicious_imports.len() as f32;
    }
    f
}

/// A static-classifier model. Returns a malice probability in [0, 1].
pub trait Model: Send + Sync {
    fn score(&self, f: &Features) -> f32;
    fn name(&self) -> &str;
}

/// A weighted combination of interpretable signals (entropy, suspicious
/// imports). Not a trained model; a placeholder until one is plugged in.
pub struct HeuristicModel;

impl Model for HeuristicModel {
    fn score(&self, f: &Features) -> f32 {
        if !f.is_pe {
            // Non-PE: only weak signal from overall entropy.
            return ((f.file_entropy - 7.5) / 0.5).clamp(0.0, 1.0) * 0.3;
        }
        let mut s = 0.0f32;
        // Packed/encrypted sections.
        if f.max_section_entropy >= 7.2 {
            s += 0.45 * ((f.max_section_entropy - 7.2) / 0.8).clamp(0.0, 1.0);
        }
        // Presence of injection/download-exec imports.
        s += (f.suspicious_import_count / 5.0).clamp(0.0, 0.45);
        // Very few imports + high entropy is a classic packed-stub shape.
        if f.import_count < 5.0 && f.max_section_entropy >= 7.0 {
            s += 0.15;
        }
        s.clamp(0.0, 1.0)
    }

    fn name(&self) -> &str {
        "heuristic-baseline"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_normalized() {
        let f = extract(b"AAAA", None);
        assert!((f.byte_histogram[b'A' as usize] - 1.0).abs() < 1e-6);
        assert_eq!(f.to_vec().len(), 256 + 7);
    }

    #[test]
    fn heuristic_flags_packed_with_injection() {
        let f = Features {
            byte_histogram: [0.0; 256],
            file_entropy: 7.9,
            size: 100_000,
            is_pe: true,
            section_count: 4.0,
            max_section_entropy: 7.9,
            import_count: 3.0,
            suspicious_import_count: 4.0,
        };
        assert!(HeuristicModel.score(&f) > 0.6);
    }

    #[test]
    fn heuristic_calm_on_benign() {
        let f = Features {
            byte_histogram: [0.0; 256],
            file_entropy: 5.0,
            size: 100_000,
            is_pe: true,
            section_count: 5.0,
            max_section_entropy: 5.5,
            import_count: 80.0,
            suspicious_import_count: 0.0,
        };
        assert!(HeuristicModel.score(&f) < 0.2);
    }
}
