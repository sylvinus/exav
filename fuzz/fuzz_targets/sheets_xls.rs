#![no_main]
//! XLS on hostile bytes: exav-render's `sheets` reader (the lenient
//! compound file reader, BIFF2 to BIFF8, decryption with the default password,
//! formulas, drawings and charts) and the XLSX writer, as @exav/viewer's
//! sheets module runs them. A panic traps the wasm instance in the browser,
//! so every one is a finding, and so is an output that is not an XLSX.
use exav_render::sheets::{Format, convert};
use libfuzzer_sys::fuzz_target;

#[path = "sheets_check.rs"]
mod sheets_check;

fuzz_target!(|data: &[u8]| {
    let limits = sheets_check::limits();
    if let Ok(c) = convert(data, Format::Xls, &limits) {
        sheets_check::xlsx(&c.xlsx, &limits);
    }
});
