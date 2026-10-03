//! Each reference image hashes as `sigtool --fuzzy-img` and Python
//! `imagehash.phash` do (`tests/fixtures/expected.txt`).

use std::path::Path;

use exav_imagehash::{Format, Hasher, Preset};

/// Pillow decodes JPEG with libjpeg-turbo, whose pixels are not zune-jpeg's;
/// a hash that lands near the median can differ by a bit or two.
const JPEG_TOLERANCE: u32 = 2;

#[test]
fn reference_images_hash_as_the_tools_do() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let Ok(expected) = std::fs::read_to_string(dir.join("expected.txt")) else {
        eprintln!("skipping: the fixtures are not in the published crate");
        return;
    };
    let clamav = Hasher::new(Preset::ClamAv);
    let imagehash = Hasher::new(Preset::ImagehashPhash);
    let mut checked = 0;
    for line in expected.lines().filter(|l| !l.starts_with('#')) {
        let [name, sigtool, pillow] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            panic!("bad line: {line}");
        };
        let data = std::fs::read(dir.join("img").join(name)).unwrap();
        // A format left out of this build is not an image here.
        if Format::detect(&data).is_none() {
            continue;
        }
        let ours = clamav.hash(&data).unwrap();
        assert_eq!(ours.to_string(), sigtool, "{name}: ClamAV preset");
        let ours = imagehash.hash(&data).unwrap();
        if Format::detect(&data) == Some(Format::Jpeg) {
            let d = ours.distance(&pillow.parse().unwrap()).unwrap();
            assert!(
                d <= JPEG_TOLERANCE,
                "{name}: imagehash preset {ours}, {d} bits off"
            );
        } else {
            assert_eq!(ours.to_string(), pillow, "{name}: imagehash preset");
        }
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} reference images checked");
}
