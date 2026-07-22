//! The `string` module.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.

use std::collections::HashMap;
use std::rc::Rc;

use super::FuncId;
use crate::yara::ir::Value;

pub(crate) fn root() -> Value {
    Value::Struct(Rc::new(HashMap::new()))
}

pub(crate) fn call(func: FuncId, args: &[Value]) -> Option<Value> {
    match func {
        FuncId::StringToInt => {
            let s = std::str::from_utf8(args[0].as_bytes()?).ok()?;
            s.parse::<i64>().ok().map(Value::Int)
        }
        FuncId::StringToIntBase => {
            let s = std::str::from_utf8(args[0].as_bytes()?).ok()?;
            let base: u32 = args[1].to_i64()?.try_into().ok()?;
            if !(2..=36).contains(&base) {
                return None;
            }
            i64::from_str_radix(s, base).ok().map(Value::Int)
        }
        FuncId::StringLength => Some(Value::Int(args[0].as_bytes()?.len() as i64)),
        _ => unreachable!("non-string FuncId dispatched to stringmod::call"),
    }
}

#[cfg(test)]
mod tests {
    // Ported from yara-x's `string` module tests (BSD-3-Clause), see
    // LICENSE-YARA-X.
    fn t(src: &str) -> bool {
        let rules = crate::yara::compile(src).expect("compile");
        rules.scan(&[]).matching_rules().len() == 1
    }

    #[test]
    fn length() {
        assert!(t(
            r#"import "string" rule r { condition: string.length("AXsx00ERS") == 9 }"#
        ));
        assert!(!t(
            r#"import "string" rule r { condition: string.length("AXsx00ERS") > 9 }"#
        ));
    }

    #[test]
    fn to_int() {
        assert!(t(
            r#"import "string" rule r { condition: string.to_int("1234") == 1234 }"#
        ));
        assert!(t(
            r#"import "string" rule r { condition: string.to_int("-10") == -10 }"#
        ));
        assert!(t(
            r#"import "string" rule r { condition: string.to_int("A", 16) == 10 }"#
        ));
        assert!(t(
            r#"import "string" rule r { condition: string.to_int("011", 8) == 9 }"#
        ));
        assert!(t(
            r#"import "string" rule r { condition: string.to_int("-011", 8) == -9 }"#
        ));
    }
}
