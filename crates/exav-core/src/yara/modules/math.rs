//! The `math` module.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X. The
//! numeric algorithms (entropy, deviation, serial correlation, Monte-Carlo Pi,
//! …) are ported from yara-x's `lib/src/modules/math.rs`.

use std::cmp;
use std::collections::HashMap;
use std::f64::consts::PI;
use std::rc::Rc;

use memchr::memchr_iter;

use super::FuncId;
use crate::yara::ir::Value;

type ByteDistribution = [u64; 256];

/// The `math` module has no data fields (only the `MEAN_BYTES` constant, folded
/// at compile time, and functions), so its root is an empty struct.
pub(crate) fn root() -> Value {
    Value::Struct(Rc::new(HashMap::new()))
}

pub(crate) fn call(func: FuncId, data: &[u8], args: &[Value]) -> Option<Value> {
    use FuncId::*;
    match func {
        MathMin => Some(Value::Int(i64::min(args[0].to_i64()?, args[1].to_i64()?))),
        MathMax => Some(Value::Int(i64::max(args[0].to_i64()?, args[1].to_i64()?))),
        MathAbs => Some(Value::Int(args[0].to_i64()?.wrapping_abs())),
        MathToNumber => Some(Value::Int(if truthy(&args[0]) { 1 } else { 0 })),
        MathInRange => {
            let x = args[0].to_f64()?;
            let lo = args[1].to_f64()?;
            let hi = args[2].to_f64()?;
            Some(Value::Bool(lo <= x && x <= hi))
        }
        MathToStringDec => Some(Value::Str(args[0].to_i64()?.to_string().into_bytes())),
        MathToStringBase => {
            let x = args[0].to_i64()?;
            let base = args[1].to_i64()?;
            let s = match base {
                8 => format!("{x:o}"),
                10 => format!("{x}"),
                16 => format!("{x:x}"),
                _ => return None,
            };
            Some(Value::Str(s.into_bytes()))
        }

        MathEntropyData => {
            let (start, end) = data_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            // Reuse exav-core's Shannon-entropy primitive. It is numerically
            // identical to the yara-x port that lived here (same 0..=255 count
            // iteration order, same `p * log2(p)` accumulation, same empty→0.0),
            // so the difftest against yara-x stays at 0 disagreements.
            Some(Value::Float(crate::pe::shannon_entropy(&data[start..end])))
        }
        MathEntropyStr => Some(Value::Float(crate::pe::shannon_entropy(
            args[0].as_bytes()?,
        ))),

        MathMeanData => {
            let (start, end) = data_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            let dist = byte_distribution(&data[start..end]);
            Some(Value::Float(mean_from_distribution(&dist, end - start)?))
        }
        MathMeanStr => Some(Value::Float(mean(args[0].as_bytes()?)?)),

        MathDeviationData => {
            let (start, end) = data_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            let mean = args[2].to_f64()?;
            let dist = byte_distribution(&data[start..end]);
            Some(Value::Float(deviation_from_distribution(
                &dist,
                end - start,
                mean,
            )?))
        }
        MathDeviationStr => {
            let mean = args[1].to_f64()?;
            Some(Value::Float(deviation(args[0].as_bytes()?, mean)?))
        }

        MathSerialCorrelationData => {
            let s = slice_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            Some(Value::Float(serial_correlation(s)?))
        }
        MathSerialCorrelationStr => Some(Value::Float(serial_correlation(args[0].as_bytes()?)?)),

        MathMonteCarloPiData => {
            let s = slice_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            Some(Value::Float(monte_carlo_pi(s)?))
        }
        MathMonteCarloPiStr => Some(Value::Float(monte_carlo_pi(args[0].as_bytes()?)?)),

        MathCountRange => {
            let byte: u8 = args[0].to_i64()?.try_into().ok()?;
            let s = slice_range(data, args[1].to_i64()?, args[2].to_i64()?)?;
            Some(Value::Int(memchr_iter(byte, s).count() as i64))
        }
        MathCountGlobal => {
            let byte: u8 = args[0].to_i64()?.try_into().ok()?;
            Some(Value::Int(memchr_iter(byte, data).count() as i64))
        }

        MathPercentageRange => {
            let byte: u8 = args[0].to_i64()?.try_into().ok()?;
            let s = slice_range(data, args[1].to_i64()?, args[2].to_i64()?)?;
            if s.is_empty() {
                return None;
            }
            Some(Value::Float(
                memchr_iter(byte, s).count() as f64 / s.len() as f64,
            ))
        }
        MathPercentageGlobal => {
            let byte: u8 = args[0].to_i64()?.try_into().ok()?;
            if data.is_empty() {
                return None;
            }
            Some(Value::Float(
                memchr_iter(byte, data).count() as f64 / data.len() as f64,
            ))
        }

        MathModeGlobal => {
            let dist = byte_distribution(data);
            mode_from_distribution(&dist, data.len()).map(Value::Int)
        }
        MathModeRange => {
            let (start, end) = data_range(data, args[0].to_i64()?, args[1].to_i64()?)?;
            let dist = byte_distribution(&data[start..end]);
            mode_from_distribution(&dist, end - start).map(Value::Int)
        }

        _ => unreachable!("non-math FuncId dispatched to math::call"),
    }
}

fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true)) || matches!(v, Value::Int(i) if *i != 0)
}

fn data_range(data: &[u8], offset: i64, length: i64) -> Option<(usize, usize)> {
    let length: usize = length.try_into().ok()?;
    let start: usize = offset.try_into().ok()?;
    let end = cmp::min(data.len(), start.saturating_add(length));
    data.get(start..end)?;
    Some((start, end))
}

fn slice_range(data: &[u8], offset: i64, length: i64) -> Option<&[u8]> {
    let length: usize = length.try_into().ok()?;
    let start: usize = offset.try_into().ok()?;
    let end = cmp::min(data.len(), start.saturating_add(length));
    data.get(start..end)
}

fn byte_distribution(data: &[u8]) -> ByteDistribution {
    let mut distribution = [0u64; 256];
    for byte in data {
        distribution[*byte as usize] += 1;
    }
    distribution
}

fn deviation(data: &[u8], mean: f64) -> Option<f64> {
    deviation_from_distribution(&byte_distribution(data), data.len(), mean)
}

fn deviation_from_distribution(
    distribution: &ByteDistribution,
    len: usize,
    mean: f64,
) -> Option<f64> {
    if len == 0 {
        return None;
    }
    let mut sum: f64 = 0.0;
    for (i, value) in distribution.iter().enumerate() {
        sum += f64::abs(i as f64 - mean) * *value as f64;
    }
    Some(sum / len as f64)
}

fn mean(data: &[u8]) -> Option<f64> {
    mean_from_distribution(&byte_distribution(data), data.len())
}

fn mean_from_distribution(distribution: &ByteDistribution, len: usize) -> Option<f64> {
    if len == 0 {
        return None;
    }
    let mut sum: f64 = 0.0;
    for (i, value) in distribution.iter().enumerate() {
        sum += i as f64 * *value as f64;
    }
    Some(sum / len as f64)
}

fn mode_from_distribution(distribution: &ByteDistribution, len: usize) -> Option<i64> {
    if len == 0 {
        return None;
    }
    let mut mode = 0;
    for (i, x) in distribution.iter().enumerate() {
        if *x > distribution[mode] {
            mode = i
        }
    }
    Some(mode as i64)
}

fn serial_correlation(data: &[u8]) -> Option<f64> {
    let Some((&first, rest)) = data.split_first() else {
        return Some(-100000.0);
    };
    let first = first as f64;
    let mut prev = first;
    let mut adjacent_product_sum = 0.0;
    let mut byte_sum = first;
    let mut byte_square_sum = first * first;

    for byte in rest {
        let byte = *byte as f64;
        adjacent_product_sum += prev * byte;
        byte_sum += byte;
        byte_square_sum += byte * byte;
        prev = byte;
    }

    adjacent_product_sum += first * prev;

    let len = data.len() as f64;
    let byte_sum_squared = byte_sum * byte_sum;
    let scc = (len * adjacent_product_sum - byte_sum_squared)
        / (len * byte_square_sum - byte_sum_squared);

    if scc.is_nan() {
        Some(-100000.0)
    } else {
        Some(scc)
    }
}

fn monte_carlo_pi(data: &[u8]) -> Option<f64> {
    const INCIRC: f64 = 281474943156225.0_f64; // ((256 ^ 3) - 1) ^ 2

    let mut inmont = 0;
    let mut mcount = 0;

    for chunk in data.chunks_exact(6) {
        let mut mx = 0.0_f64;
        let mut my = 0.0_f64;

        for i in 0..3 {
            mx = mx * 256.0 + chunk[i] as f64;
            my = my * 256.0 + chunk[i + 3] as f64;
        }

        if mx * mx + my * my < INCIRC {
            inmont += 1;
        }
        mcount += 1;
    }

    if mcount == 0 {
        return None;
    }

    let mpi = 4.0_f64 * (inmont as f64 / mcount as f64);
    Some((mpi - PI).abs() / PI)
}

#[cfg(test)]
mod tests {
    // Ported from yara-x's `math` module tests (BSD-3-Clause), see
    // LICENSE-YARA-X.
    fn t(src: &str, data: &[u8]) -> bool {
        let rules = crate::yara::compile(src).expect("compile");
        rules.scan(data).matching_rules().len() == 1
    }

    #[test]
    fn min_and_max() {
        assert!(t(
            r#"import "math" rule r { condition: math.min(1,2) == 1 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.min(-1,0) == -1 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.max(1,2) == 2 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.max(-1,0) == 0 }"#,
            &[]
        ));
    }

    #[test]
    fn abs() {
        assert!(t(
            r#"import "math" rule r { condition: math.abs(-1) == 1 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.abs(1) == 1 }"#,
            &[]
        ));
    }

    #[test]
    fn in_range() {
        assert!(t(
            r#"import "math" rule r { condition: math.in_range(1,1,2) }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.in_range(2,1,2) }"#,
            &[]
        ));
        assert!(!t(
            r#"import "math" rule r { condition: math.in_range(3,1,2) }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.in_range(0.5,0.0,0.6) }"#,
            &[]
        ));
    }

    #[test]
    fn entropy() {
        assert!(t(
            r#"import "math" rule r { condition: math.entropy("AAAAA") == 0.0 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.entropy("AABB") == 1.0 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.entropy("") == 0.0 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.entropy(2,3) == 0.0 }"#,
            b"CCAAACCC"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.entropy(2,100) == 1.0 }"#,
            b"CCAAACCC"
        ));
    }

    #[test]
    fn deviation() {
        assert!(t(
            r#"import "math" rule r { condition: math.deviation("AAAAA", 0.0) == 65.0 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.deviation("ABAB", 65.0) == 0.5 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.deviation(2, 4, 65.0) == 0.5 }"#,
            b"ABABABAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.deviation(0, 4, math.MEAN_BYTES) == math.MEAN_BYTES }"#,
            &[0x00, 0xFF, 0x00, 0xFF]
        ));
    }

    #[test]
    fn mean() {
        assert!(t(
            r#"import "math" rule r { condition: math.mean("ABCABC") == 66.0 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.mean(0, 3) == 66.0 }"#,
            b"ABCABC"
        ));
    }

    #[test]
    fn serial_correlation() {
        assert!(t(
            r#"import "math" rule r { condition: math.serial_correlation("BCA") == -0.5 }"#,
            &[]
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.serial_correlation(1, 3) == -0.5 }"#,
            b"ABCABC"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.serial_correlation(0, 0) == -100000.0 }"#,
            b"ABCABC"
        ));
    }

    #[test]
    fn monte_carlo_pi() {
        assert!(t(
            r#"import "math" rule r { condition: math.monte_carlo_pi(3, 15) < 0.3 }"#,
            b"123ABCDEF123456987DE"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.monte_carlo_pi("ABCDEF123456987") < 0.3 }"#,
            &[]
        ));
    }

    #[test]
    fn count() {
        assert!(t(
            r#"import "math" rule r { condition: math.count(0x41, 0, 3) == 2 }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.count(0x41) == 4 }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: not defined math.count(-1) }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: not defined math.count(0x41, 0, -3) }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.count(0x41, 0, 100) == 4 }"#,
            b"AABAAB"
        ));
    }

    #[test]
    fn percentage() {
        assert!(t(
            r#"import "math" rule r { condition: math.percentage(0x41, 4, 10) == 0.5 }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: not defined math.percentage(0x41, 0, 0) }"#,
            b"AABAAB"
        ));
        assert!(t(
            r#"import "math" rule r { condition: not defined math.percentage(0x41, 0, 10) }"#,
            b""
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.percentage(0x41) > 0.66 }"#,
            b"AABAAB"
        ));
    }

    #[test]
    fn mode() {
        assert!(t(
            r#"import "math" rule r { condition: math.mode() == 0x41 }"#,
            b"ABABA"
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.mode(2,3) == 0x41 }"#,
            b"CCABACC"
        ));
    }

    #[test]
    fn to_string_and_number() {
        assert!(t(
            r#"import "math" rule r { condition: math.to_string(1234) == "1234" }"#,
            b""
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.to_string(32, 16) == "20" }"#,
            b""
        ));
        assert!(t(
            r#"import "math" rule r { condition: not defined math.to_string(32, 7) }"#,
            b""
        ));
        assert!(t(
            r#"import "math" rule r { condition: math.to_number(true) == 1 and math.to_number(false) == 0 }"#,
            b""
        ));
    }
}
