//! Numbers as text.

/// The shortest text that reads back as `v`, as `<v>` holds it: Rust's
/// round-trip formatting, with an `E` exponent. Infinities and NaN, which
/// XLSX cannot hold, are 0.
pub fn xml(v: f64) -> String {
    if !v.is_finite() {
        return "0".into();
    }
    let s = format!("{v}");
    if s.len() > 20 { format!("{v:E}") } else { s }
}

/// At most 15 significant digits, as spreadsheets show a number and write it
/// in a formula.
pub use exav_unpack::biff::formula::number as shortest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(xml(1.5), "1.5");
        assert_eq!(xml(f64::NAN), "0");
        assert_eq!(xml(1e300), "1E300");
        assert_eq!(xml(1.25e-300), "1.25E-300");
    }
}
