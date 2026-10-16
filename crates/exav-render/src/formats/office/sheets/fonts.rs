//! Font metrics: the width of the digits, which column widths are counted
//! in. Measured from the metric-compatible fonts (Liberation 2.1, Carlito,
//! Caladea, DejaVu Sans), which are data, not code.

/// Advance of the digit '0', in em.
fn digit_em(family: &str) -> f64 {
    let f = family.to_ascii_lowercase();
    if f.contains("dejavu") || f.contains("verdana") || f.contains("bitstream vera") {
        0.63623
    } else if f.starts_with("times") || f.contains("liberation serif") || f.contains("thorndale") {
        0.5
    } else if f.starts_with("courier") || f.contains("liberation mono") || f.contains("cumberland")
    {
        0.6001
    } else if f.starts_with("calibri") || f.starts_with("carlito") {
        0.50684
    } else if f.starts_with("cambria") || f.starts_with("caladea") {
        0.554
    } else {
        0.55615
    }
}

/// Width of '0' in twips, truncated.
pub fn digit_twips(family: &str, size_pt: f64) -> f64 {
    (digit_em(family) * size_pt * 20.0).trunc().max(1.0)
}
