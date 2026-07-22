//! The `time` module.
//!
//! Portions derived from yara-x (BSD-3-Clause), see LICENSE-YARA-X.

use std::collections::HashMap;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::FuncId;
use crate::yara::ir::Value;

pub(crate) fn root() -> Value {
    Value::Struct(Rc::new(HashMap::new()))
}

pub(crate) fn call(func: FuncId) -> Option<Value> {
    match func {
        FuncId::TimeNow => Some(Value::Int(
            SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64,
        )),
        _ => unreachable!("non-time FuncId dispatched to timemod::call"),
    }
}

#[cfg(test)]
mod tests {
    // Ported from yara-x's `time` module tests (BSD-3-Clause), see
    // LICENSE-YARA-X.
    #[test]
    fn now() {
        let rules = crate::yara::compile(r#"import "time" rule r { condition: time.now() >= 0 }"#)
            .expect("compile");
        assert_eq!(rules.scan(&[]).matching_rules().len(), 1);
    }
}
