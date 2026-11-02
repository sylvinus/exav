//! The scanner's detection against the format registry (`formats/registry.json`,
//! checked against the rest of the code by `scripts/formats.mjs`): the magic
//! bytes the registry gives a format, written into an otherwise empty buffer,
//! are typed as the format's scanner type.

use exav_core::filetype::identify;

fn registry() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../formats/registry.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("formats/registry.json")).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A buffer holding `conditions` (`offset:hex`) and zeros elsewhere.
fn buffer(conditions: &[&str]) -> Vec<u8> {
    let parts: Vec<(usize, Vec<u8>)> = conditions
        .iter()
        .map(|c| {
            let (offset, bytes) = c.split_once(':').unwrap();
            (offset.parse().unwrap(), hex(bytes))
        })
        .collect();
    let end = parts.iter().map(|(o, b)| o + b.len()).max().unwrap();
    let mut buf = vec![0u8; end.max(1024)];
    for (offset, bytes) in parts {
        buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }
    buf
}

#[test]
fn the_magic_of_a_format_is_typed_as_that_format() {
    let registry = registry();
    let mut checked = 0;
    let mut skipped = 0;
    let mut wrong = Vec::new();
    for f in registry["formats"].as_array().unwrap() {
        let scan = &f["scan"];
        let Some(want) = scan["type"].as_str() else {
            continue;
        };
        if !matches!(scan["mode"].as_str(), Some("container" | "reported")) {
            continue;
        }
        let id = f["id"].as_str().unwrap();
        // A format the scanner types only when more than the magic holds (a
        // header's checksum, a structure that parses) says so in the registry.
        if scan.get("needs").is_some() {
            skipped += 1;
            continue;
        }
        for alt in f["magic"].as_array().into_iter().flatten() {
            let conditions: Vec<&str> = alt
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect();
            let got = identify(&buffer(&conditions)).as_str();
            checked += 1;
            if got != want {
                wrong.push(format!(
                    "{id} {conditions:?}: typed {got}, the registry says {want}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 20, "only {checked} magics were checked");
    assert!(skipped <= 3, "{skipped} formats are excused from the check");
}

#[test]
fn a_buffer_with_no_magic_of_the_registry_is_data() {
    assert_eq!(identify(&vec![0u8; 4096]).as_str(), "data");
}
