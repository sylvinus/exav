//! Numbers as text.

/// The shortest text that reads back as `v`, as `<v>` holds it: Rust's
/// round-trip formatting, with an `E` exponent. Infinities and NaN, which
/// XLSX cannot hold, are 0.
pub fn xml(v: f64) -> String {
    if !v.is_finite() {
        return "0".into();
    }
    let s = format!("{v}");
    if s.len() > 20 {
        format!("{v:E}")
    } else {
        s
    }
}

/// At most 15 significant digits, as spreadsheets show a number and write
/// it in a formula.
pub fn shortest(v: f64) -> String {
    if !v.is_finite() {
        return "0".into();
    }
    if v == v.trunc() && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let e = format!("{v:.14e}");
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let body = if (-5..15).contains(&exp) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                format!("{}{}", digits, "0".repeat(int_len - digits.len()))
            } else {
                format!("{}.{}", &digits[..int_len], &digits[int_len..])
            }
        } else {
            format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
        }
    } else {
        let m = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.to_string()
        };
        format!("{}E{}{}", m, if exp < 0 { "-" } else { "+" }, exp.abs())
    };
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(xml(1.5), "1.5");
        assert_eq!(xml(f64::NAN), "0");
        assert_eq!(xml(1e300), "1E300");
        assert_eq!(xml(1.25e-300), "1.25E-300");
        assert_eq!(shortest(0.1 + 0.2), "0.3");
        assert_eq!(shortest(-2.0), "-2");
        assert_eq!(shortest(1e20), "1E+20");
        assert_eq!(shortest(0.000012), "0.000012");
        assert_eq!(shortest(1.5e-7), "1.5E-7");
    }
}
