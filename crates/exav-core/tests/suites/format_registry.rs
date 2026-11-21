//! The scanner's detection against the format registry (`formats/registry.json`,
//! checked against the rest of the code by `scripts/formats.mjs`): the magic
//! bytes the registry gives a format, written into an otherwise empty buffer,
//! are typed as the format's scanner type; and the detector reads the places
//! the registry says (`detect.at`) of a fixture of the format, and no other.

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::Read;

use exav_core::filetype::identify;
use exav_core::unpack::tree::{Typed, Typing, type_object};
use exav_core::unpack::{ByteSource, read_fixture};

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

// The places the detector reads.
//
// A fixture is put in a long file in each place the registry could name, and
// the detector is run over it, recording what it reads:
//
// - at the start, followed by more than the start it reads holds: found when
//   `start` (or `string`, or `content`) is a place;
// - at the end, preceded by as much: found when `end` is a place;
// - behind a short prefix: a format told by bytes at fixed places is lost, one
//   told by a string is not;
// - for `after-image`, an executable whose image is grown to end past the
//   start, the bytes that follow it where the installer keeps its data.
//
// Whatever is read past the start must be at the end (`end`) or at a place a
// structure names (`structure`, `after-image`).

/// Zeros (spaces, for a text) before or after a fixture: more than the start
/// the detector reads (4 MiB and a KiB).
const PAD: usize = 6 << 20;
/// Bytes put in front of a fixture to move its start.
const SHIFT: usize = 100;
/// A read this near the end of an object, or nearer, is a read of its end.
const END: usize = 70_000;

/// What the detector reads of an object: the ranges asked of it.
struct Recording<'a> {
    bytes: &'a [u8],
    reads: RefCell<Vec<(usize, usize)>>,
}

impl ByteSource for Recording<'_> {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn window(&self, off: usize, len: usize) -> Cow<'_, [u8]> {
        let from = off.min(self.bytes.len());
        let to = from.saturating_add(len).min(self.bytes.len());
        self.reads.borrow_mut().push((from, to));
        Cow::Borrowed(&self.bytes[from..to])
    }

    fn identity(&self) -> (usize, usize) {
        (self.bytes.as_ptr() as usize, self.bytes.len())
    }
}

/// What a registry entry's detector gives.
enum Want {
    /// The walk types the object as this extractor `Format` (its variant name).
    Format(String),
    /// `identify` gives this file type.
    Scan(String),
}

impl Want {
    fn of(f: &serde_json::Value) -> Option<Want> {
        if let Some(format) = f["unpack"]["format"].as_str() {
            return Some(Want::Format(format.to_string()));
        }
        let scan = &f["scan"];
        match (scan["type"].as_str(), scan["mode"].as_str()) {
            (Some(t), Some("type" | "view")) => Some(Want::Scan(t.to_string())),
            _ => None,
        }
    }

    /// A text kind, whose start is judged as text: padded with spaces.
    fn is_text(&self) -> bool {
        matches!(self, Want::Scan(t) if matches!(t.as_str(), "ASCII text" | "HTML" | "script"))
    }
}

/// What the detector did with an object.
struct Run {
    found: bool,
    /// Past the start the detector reads, at the end of the object.
    end: bool,
    /// Past the start, elsewhere than the end.
    elsewhere: bool,
    /// The object's reads, as `(from, to)`.
    reads: Vec<(usize, usize)>,
}

fn run(want: &Want, bytes: &[u8]) -> Run {
    match want {
        Want::Scan(t) => Run {
            found: identify(bytes).as_str() == t,
            end: false,
            elsewhere: false,
            reads: Vec::new(),
        },
        Want::Format(name) => {
            let recording = Recording {
                bytes,
                reads: RefCell::new(Vec::new()),
            };
            // The walk's typing: what `detect` says, then the packers of an
            // executable and the other types the scanner reads.
            let typing = Typing {
                scanner: true,
                clamav: false,
                sfx: true,
            };
            let typed = type_object(&typing, &recording, u64::MAX);
            let found = matches!(typed, Typed::Container(f) if format!("{f:?}") == *name);
            let reads = recording.reads.into_inner();
            // The checks that come before the format's in the detector fail on
            // it, and read what they read (the end of the object, for one that
            // ends in a trailer): of an object of zeros they read the same.
            let zeros = vec![0u8; bytes.len()];
            let none = Recording {
                bytes: &zeros,
                reads: RefCell::new(Vec::new()),
            };
            type_object(&typing, &none, u64::MAX);
            let others = none.reads.into_inner();
            // The start is the longest read from the first byte that is not the
            // whole object.
            let head = reads
                .iter()
                .filter(|&&(from, to)| from == 0 && to < bytes.len())
                .map(|&(_, to)| to)
                .max()
                .unwrap_or(0);
            // Reading all of the object is how an executable is held to look
            // for a packer: not a place.
            let past: Vec<_> = reads
                .iter()
                .filter(|r| r.1 > head && !others.contains(r) && **r != (0, bytes.len()))
                .collect();
            let end = past.iter().any(|&&(from, _)| from + END >= bytes.len());
            let elsewhere = past.iter().any(|&&(from, _)| from + END < bytes.len());
            Run {
                found,
                end,
                elsewhere,
                reads,
            }
        }
    }
}

/// A fixture of the repository (`rel` from `crates/`), masked and gzipped ones
/// included; several joined with `+` are one file, and one marked `seed:` is a
/// fuzz seed without its first byte.
fn fixture(rel: &str) -> Vec<u8> {
    if rel.contains('+') {
        return rel.split('+').flat_map(fixture).collect();
    }
    if let Some(rel) = rel.strip_prefix("seed:") {
        // A seed of a fuzz target: a byte that picks the format, then the file.
        return fixture(rel)[1..].to_vec();
    }
    let (rel, gzipped) = match rel.strip_prefix("gz:") {
        Some(rel) => (rel, true),
        None => (rel, false),
    };
    let path = format!("{}/../{rel}", env!("CARGO_MANIFEST_DIR"));
    let raw = read_fixture(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
    if !gzipped {
        return raw;
    }
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&raw[..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn padded(prefix: usize, fixture: &[u8], suffix: usize, fill: u8) -> Vec<u8> {
    let mut out = vec![fill; prefix];
    out.extend_from_slice(fixture);
    out.resize(out.len() + suffix, fill);
    out
}

/// `pe` with `PAD` zeros put where its image ends, and its last section grown
/// to hold them: what follows the image now starts past the detector's start.
/// The offset where the zeros end, too. `None` for a file with nothing after
/// its image.
fn grow_image(pe: &[u8]) -> Option<(Vec<u8>, usize)> {
    let u16_at = |o: usize| {
        pe.get(o..o + 2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let u32_at = |o: usize| {
        pe.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let nt = u32_at(0x3c)?;
    if pe.get(nt..nt + 4)? != b"PE\0\0" {
        return None;
    }
    let table = nt + 24 + u16_at(nt + 20)?;
    let mut last: Option<(usize, usize)> = None;
    for i in 0..u16_at(nt + 6)? {
        let header = table + i * 40;
        let end = u32_at(header + 16)? + u32_at(header + 20)?;
        if last.is_none_or(|(e, _)| end > e) {
            last = Some((end, header));
        }
    }
    let (end, header) = last?;
    if end >= pe.len() {
        return None;
    }
    let mut out = pe[..end].to_vec();
    out.resize(end + PAD, 0);
    out.extend_from_slice(&pe[end..]);
    let grown = u32::try_from(u32_at(header + 16)? + PAD).ok()?;
    out[header + 16..header + 20].copy_from_slice(&grown.to_le_bytes());
    Some((out, end + PAD))
}

/// Registry entries and the fixtures of the repository that are files of that
/// format (paths from `crates/`; one marked `gz:` is unzipped, a `.xor` is
/// unmasked). An entry told by bytes that is not here has no fixture, and only
/// its magic is checked.
const FIXTURES: &[(&str, &[&str])] = &[
    (
        "zip",
        &["exav-unpack/tests/fixtures/zip/dd_python_stored.zip"],
    ),
    (
        "zip-package",
        &["exav-viewer/demo/examples/files/archives/example.jar"],
    ),
    (
        "split-archive",
        &["exav-core/tests/fixtures/volumes/split.z01"],
    ),
    (
        "comic-book",
        &["exav-viewer/demo/examples/files/archives/pages.cbz"],
    ),
    (
        "gzip",
        &["exav-viewer/demo/examples/files/archives/server.log.gz"],
    ),
    (
        "bzip2",
        &["exav-viewer/demo/examples/files/archives/server.log.bz2"],
    ),
    (
        "xz",
        &["exav-viewer/demo/examples/files/archives/server.log.xz"],
    ),
    (
        "zstd",
        &["exav-viewer/demo/examples/files/archives/sample.tar.zst"],
    ),
    ("lz4", &["exav-unpack/tests/fixtures/lz4/one.lz4"]),
    ("lzma", &["exav-unpack/tests/fixtures/lzma_simple.lzma"]),
    ("rpm", &["exav-unpack/tests/fixtures/rpm/hello.rpm"]),
    ("lzip", &["exav-unpack/tests/fixtures/lzip_simple.lz"]),
    ("compress", &["exav-unpack/tests/fixtures/lzw/short.b12.Z"]),
    (
        "tar",
        &["exav-viewer/demo/examples/files/archives/sample.tar"],
    ),
    (
        "7z",
        &["exav-viewer/demo/examples/files/archives/sample.7z"],
    ),
    (
        "rar",
        &["exav-viewer/demo/examples/files/archives/sample.rar"],
    ),
    (
        "cab",
        &["exav-viewer/demo/examples/files/archives/sample.cab"],
    ),
    ("chm", &["exav-unpack/tests/fixtures/chm/benign-lzx.chm"]),
    ("arj", &["exav-unpack/tests/fixtures/sample.arj"]),
    (
        "ar",
        &["exav-viewer/demo/examples/files/archives/libexample.a"],
    ),
    (
        "cpio",
        &["exav-viewer/demo/examples/files/archives/sample.cpio"],
    ),
    (
        "ishield-cab",
        &[
            "seed:../fuzz/seeds/installers/ishield_v5.bin",
            "seed:../fuzz/seeds/installers/ishield_v6.bin",
        ],
    ),
    ("xar", &["seed:../fuzz/seeds/fsimage/xar.bin"]),
    ("zoo", &["exav-unpack/tests/fixtures/zoo/default.zoo"]),
    (
        "arc",
        &["exav-unpack/tests/fixtures/arc/microsoft_testdata.arc"],
    ),
    ("alz", &["exav-unpack/tests/fixtures/alz/defaults.alz"]),
    ("egg", &["exav-unpack/tests/fixtures/egg/lzma_simple.egg"]),
    ("ishield-z", &["exav-unpack/tests/fixtures/ishieldz/demo.z"]),
    (
        "applesingle",
        &[
            "seed:../fuzz/seeds/installers/applesingle.bin",
            "seed:../fuzz/seeds/installers/appledouble.bin",
        ],
    ),
    (
        "iso",
        &["exav-viewer/demo/examples/files/archives/sample.iso"],
    ),
    (
        "dmg",
        &[
            "exav-unpack/tests/fixtures/dmg/encrypted.dmg",
            "exav-unpack/tests/fixtures/dmg/read_only.dmg",
            "exav-unpack/tests/fixtures/dmg/hfs_plus_udrw.dmg",
        ],
    ),
    (
        "vhd",
        &["gz:exav-unpack/tests/fixtures/diskimage/fat4g.dynamic.vhd.gz"],
    ),
    (
        "vhdx",
        &["gz:exav-unpack/tests/fixtures/diskimage/dynamic.vhdx.gz"],
    ),
    (
        "vmdk",
        &["exav-unpack/tests/fixtures/diskimage/sparse.vmdk"],
    ),
    (
        "qcow2",
        &["exav-unpack/tests/fixtures/diskimage/compressed.qcow2"],
    ),
    ("wim", &["exav-unpack/tests/fixtures/wim/hard_LZX.wim"]),
    (
        "partition",
        &[
            "seed:../fuzz/seeds/fsimage/partition_ext2.bin",
            "seed:../fuzz/seeds/fsimage/partition_exfat.bin",
        ],
    ),
    ("fat", &["gz:exav-unpack/tests/fixtures/fs/fat16.img.gz"]),
    (
        "ntfs",
        &["gz:exav-unpack/tests/fixtures/ntfs/attribute_list.img.gz"],
    ),
    ("ext", &["gz:exav-unpack/tests/fixtures/fs/ext4.img.gz"]),
    ("exfat", &["gz:exav-unpack/tests/fixtures/fs/exfat.img.gz"]),
    (
        "squashfs",
        &["gz:exav-unpack/tests/fixtures/fs/squashfs_gzip.img.gz"],
    ),
    (
        "cramfs",
        &["gz:exav-unpack/tests/fixtures/fs/cramfs.img.gz"],
    ),
    ("romfs", &["gz:exav-unpack/tests/fixtures/fs/romfs.img.gz"]),
    ("erofs", &["gz:exav-unpack/tests/fixtures/fs/erofs.img.gz"]),
    (
        "nsis",
        &["gz:exav-unpack/tests/fixtures/cut_short/nsis_zlib.exe.gz"],
    ),
    ("inno", &["seed:../fuzz/seeds/installers/inno_6.4.0.bin"]),
    ("upx", &["exav-unpack/tests/fixtures/upx_lzma.upx"]),
    // An executable and a ZIP behind it: a self-extractor.
    (
        "sfx",
        &[
            "exav-core/tests/testdata/tiny_pe32.exe+exav-unpack/tests/fixtures/zip/dd_python_stored.zip",
        ],
    ),
    (
        "ole",
        &["exav-unpack/tests/fixtures/ole/malformed_dir_order.ole"],
    ),
    (
        "pdf",
        &["exav-viewer/demo/examples/files/pdf/field-report.pdf"],
    ),
    (
        "docx",
        &["exav-viewer/demo/examples/files/office/handbook.docx"],
    ),
    (
        "xlsx",
        &["exav-viewer/demo/examples/files/office/workbook.xlsx"],
    ),
    (
        "pptx",
        &["exav-viewer/demo/examples/files/office/deck.pptx"],
    ),
    (
        "doc",
        &["exav-viewer/demo/examples/files/converted/handbook.doc"],
    ),
    (
        "xls",
        &["exav-viewer/demo/examples/files/converted/workbook.xls"],
    ),
    (
        "ppt",
        &["exav-viewer/demo/examples/files/converted/deck.ppt"],
    ),
    (
        "rtf",
        &["exav-viewer/demo/examples/files/converted/handbook.rtf"],
    ),
    (
        "odt",
        &["exav-viewer/demo/examples/files/converted/handbook.odt"],
    ),
    (
        "ods",
        &["exav-viewer/demo/examples/files/converted/workbook.ods"],
    ),
    (
        "odp",
        &["exav-viewer/demo/examples/files/converted/deck.odp"],
    ),
    (
        "odg",
        &["exav-viewer/demo/examples/files/converted/diagram.odg"],
    ),
    (
        "keynote",
        &["exav-render/tests/fixtures/office/slides/sample.key"],
    ),
    (
        "numbers",
        &["exav-render/tests/fixtures/office/sheets/sample.numbers"],
    ),
    (
        "hwp3",
        &["exav-unpack/tests/fixtures/hwp3/tika_testHWP_3.0.hwp"],
    ),
    ("binhex", &["exav-unpack/tests/fixtures/binhex/eicar.hqx"]),
    ("uuencode", &["exav-core/tests/fixtures/matryoshka.uu"]),
    ("dwg", &["gz:exav-unpack/tests/fixtures/dwg/R2000.dwg.gz"]),
    (
        "dxf",
        &["gz:exav-unpack/tests/fixtures/dxf/ascii-R2018.dxf.gz"],
    ),
    ("lnk", &["exav-unpack/tests/fixtures/lnk/eicar.lnk"]),
    ("pyc", &["exav-unpack/tests/fixtures/pyc/eicar.pyc"]),
    (
        "swf",
        &["gz:exav-unpack/tests/fixtures/cut_short/swf_cws.swf.gz"],
    ),
    ("pe", &["exav-core/tests/testdata/tiny_pe32.exe"]),
    ("elf", &["exav-core/tests/testdata/tiny_elf64"]),
    ("html", &["exav-viewer/demo/examples/files/text/page.html"]),
    (
        "text",
        &["exav-viewer/demo/examples/files/text/field-notes.txt"],
    ),
    (
        "source",
        &["exav-viewer/demo/examples/files/text/deploy.sh"],
    ),
];

/// The places `detect.at` of an entry names.
fn places(f: &serde_json::Value) -> Vec<&str> {
    match &f["detect"]["at"] {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().map(|p| p.as_str().unwrap()).collect(),
        other => panic!("{}: detect.at is {other}", f["id"]),
    }
}

/// What the detector's reads of `fixtures` say against the places `at`: the
/// ways they do not agree.
fn disagreements(id: &str, at: &[&str], want: &Want, fixtures: &[Vec<u8>]) -> Vec<String> {
    let has = |p: &str| at.contains(&p);
    let text = want.is_text();
    let fill = if text { b' ' } else { 0 };
    let (mut at_start, mut at_end, mut shifted) = (false, false, false);
    let (mut read_end, mut read_elsewhere) = (false, false);
    let (mut grown, mut grown_read) = (false, false);
    for fixture in fixtures {
        let start = padded(0, fixture, PAD, fill);
        let s = run(want, &start);
        at_start |= s.found;
        read_end |= s.found && s.end;
        read_elsewhere |= s.found && s.elsewhere;
        if text {
            continue;
        }
        let e = run(want, &padded(PAD, fixture, 0, fill));
        at_end |= e.found;
        read_end |= e.found && e.end;
        read_elsewhere |= e.found && e.elsewhere;
        shifted |= run(want, &padded(SHIFT, fixture, PAD, fill)).found;
        if has("end") && !at_end && !read_end {
            // A trailer that is part of a long text, as a uuencoded file's
            // last line: the file's last bytes, far from the rest.
            let cut = fixture.len() - fixture.len().min(4096);
            let (head, tail) = fixture.split_at(cut);
            let mut long = padded(0, head, PAD, fill);
            long.extend_from_slice(tail);
            let t = run(want, &long);
            read_end |= t.found && t.end;
        }
        if has("after-image")
            && let Some((long, mark)) = grow_image(fixture)
        {
            let a = run(want, &long);
            grown |= a.found;
            // The bytes after the image are read from where the image ends.
            grown_read |= a.reads.iter().any(|&(from, _)| from == mark);
        }
    }
    let mut out = Vec::new();
    let mut say = |bad: bool, what: &str| {
        if bad {
            out.push(format!("{id} (at {at:?}): {what}"));
        }
    };
    let by_start = has("start") || has("string") || has("content");
    say(
        by_start && !at_start,
        "not found at the start of a long file",
    );
    say(
        !by_start && at_start,
        "found at the start, which `at` does not name",
    );
    if !text {
        say(
            at_end && !has("end"),
            "found at the end, which `at` does not name",
        );
        say(
            has("end") && !at_end && !read_end,
            "`end` is named, and nothing is read there",
        );
        say(
            read_end && !has("end"),
            "reads the end, which `at` does not name",
        );
        say(
            read_elsewhere && !has("structure") && !has("after-image"),
            "reads past the start, away from the end, and `at` names no structure",
        );
        say(
            has("string") && !has("start") && !has("after-image") && !shifted,
            "a string is named, and a prefix hides the format",
        );
        say(
            has("start") && !has("string") && !has("end") && !has("after-image") && shifted,
            "only the start is named, and the format is found behind a prefix",
        );
        if has("after-image") {
            say(
                !grown,
                "not found when its data follow an image that ends past the start",
            );
            say(!grown_read, "the bytes after the image are not read");
        }
    }
    out
}

#[test]
fn the_detector_reads_the_places_the_registry_names() {
    let registry = registry();
    let formats = registry["formats"].as_array().unwrap();
    for (id, _) in FIXTURES {
        assert!(formats.iter().any(|f| f["id"] == *id), "no format {id}");
    }
    let mut wrong = Vec::new();
    let (mut tested, mut untested) = (0, Vec::new());
    for f in formats {
        let id = f["id"].as_str().unwrap();
        let at = places(f);
        // Told by a name alone: no bytes are read.
        if at == ["name"] {
            continue;
        }
        let want = Want::of(f);
        let paths = FIXTURES.iter().find(|(i, _)| *i == id);
        let (Some(want), Some((_, paths))) = (want, paths) else {
            untested.push(id);
            continue;
        };
        let fixtures: Vec<Vec<u8>> = paths.iter().map(|p| fixture(p)).collect();
        wrong.extend(disagreements(id, &at, &want, &fixtures));
        tested += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(
        tested >= 70,
        "only {tested} formats were run, not {untested:?}"
    );
}
