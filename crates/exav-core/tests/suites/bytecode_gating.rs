//! End-to-end test of bytecode trigger-gating: a synthetic `.cbc` whose
//! logical trigger fires on a byte pattern and whose program calls
//! `setvirusname`, exercised through [`BytecodeRuntime`]. No ClamAV data is
//! vendored: the program is assembled with the format's own nibble encoders.

use exav_core::bytecode::runtime::BytecodeRuntime;
use exav_core::filetype::FileType;
use exav_core::{analyze, analyze_all, ScanOptions, Verdict};

const HEADER_MAGIC: u64 = 0x53e5_493e_9f3d_1c30;

fn num(mut n: u64) -> String {
    let mut nibs = Vec::new();
    while n > 0 {
        nibs.push((n & 0xf) as u8);
        n >>= 4;
    }
    let mut s = String::new();
    s.push((0x60 + nibs.len() as u8) as char);
    for nb in nibs {
        s.push((0x60 + nb) as char);
    }
    s
}
fn data(bytes: &[u8]) -> String {
    let mut s = String::from("|");
    s.push_str(&num(bytes.len() as u64));
    for &b in bytes {
        s.push((0x60 + (b & 0xf)) as char);
        s.push((0x60 + (b >> 4)) as char);
    }
    s
}
fn nib(n: u8) -> char {
    (0x60 + n) as char
}

/// A logical (kind 256) program: trigger matches the hex of `marker`; the
/// program calls `setvirusname()` (no args → reports its own name) and returns.
fn synth_cbc(name: &str, marker: &[u8]) -> String {
    let mut h = String::from("ClamBC");
    h.push_str(&num(6)); // format level
    h.push_str(&num(0x5b4f9546)); // timestamp
    h.push_str(&data(b"")); // sigmaker
    h.push_str(&num(0)); // target exclude
    h.push_str(&num(256)); // kind = BC_LOGICAL
    h.push_str(&num(1)); // min flevel
    h.push_str(&num(255)); // max flevel
    h.push_str(&num(0)); // max resource
    h.push_str(&data(b"clambc-test")); // compiler
    h.push_str(&num(2)); // num types
    h.push_str(&num(1)); // num funcs
    h.push_str(&num(HEADER_MAGIC));

    let hex: String = marker.iter().map(|b| format!("{b:02x}")).collect();
    let trigger = format!("{name};Engine:1-255,Target:0;0;{hex}");

    // E: maxapi, count=1, (id=5, type=79, "setvirusname").
    let mut e = String::from("E");
    e.push_str(&num(96));
    e.push_str(&num(1));
    e.push_str(&num(5));
    e.push_str(&num(79));
    e.push_str(&data(b"setvirusname"));

    // A: 0 args, ret type 32, 2 locals (i32), 2 insts, 1 BB.
    let mut a = String::from("A");
    a.push(nib(0)); // numArgs = fixed(1) 0
    a.push_str(&num(32)); // return type
    a.push('L');
    a.push_str(&num(2)); // numLocals
    a.push_str(&num(32)); // local0 type
    a.push(nib(0)); // flag
    a.push_str(&num(32)); // local1 type
    a.push(nib(0)); // flag
    a.push('F');
    a.push_str(&num(2)); // numInsts
    a.push_str(&num(1)); // numBB

    // B: [ call setvirusname -> r1 ] [ T ret_void ] E
    let mut b = String::from("B");
    // non-terminator inst: ty, dest, opcode(fixed2), then CALL payload.
    b.push_str(&num(32)); // inst type
    b.push_str(&num(1)); // dest = value 1
    b.push(nib(1)); // opcode lo nibble  (0x21 = 33 CALL_API)
    b.push(nib(2)); // opcode hi nibble
    b.push(nib(0)); // numOps = fixed(1) 0
    b.push_str(&num(5)); // funcid number (decoded = 5-1 = 4 -> global id 5)
                         // terminator: ret_void (opcode 20 = 0x14).
    b.push('T');
    b.push(nib(4));
    b.push(nib(1));
    b.push('E'); // end-of-function marker (last BB)

    format!("{h}\n{trigger}\n{e}\n{a}\n{b}\n")
}

#[test]
fn trigger_gated_detection() {
    let cbc = synth_cbc("Synth.BC.Detect", b"MALWARE");
    let (rt, triggers) = BytecodeRuntime::standalone(vec![cbc]);
    assert_eq!(rt.len(), 1, "program should load");

    // Input containing the trigger marker -> the program runs and names it.
    let hit = b"....prefix....MALWARE....suffix....";
    assert_eq!(
        rt.scan(&triggers, hit, FileType::Unknown, None).0,
        Some(("Synth.BC.Detect".to_string(), 0))
    );

    // Input without the marker -> trigger doesn't fire -> no detection.
    let clean = b"nothing to see here, totally benign bytes";
    assert_eq!(rt.scan(&triggers, clean, FileType::Unknown, None).0, None);
}

/// In a real scan the trigger is matched by the scanner's own engine, in the
/// sweep that looks for every other signature: the program runs, its
/// detection is reported, and the trigger itself neither alerts nor counts
/// as a signature. Through a built database too.
#[test]
fn trigger_gated_detection_in_a_scan() {
    let mut loader = exav_core::loader::Builder::new();
    loader.add_named_bytes(
        "t.cbc",
        synth_cbc("Synth.BC.Detect", b"MALWARE").as_bytes(),
        true,
    );
    loader.add_named_bytes("t.ndb", b"Other.Sig:0:*:4f54484552\n", true);
    let built = loader.build().unwrap();
    let mut file = Vec::new();
    exav_core::database::write(&built, &mut file).unwrap();
    let stored = exav_core::database::read(&file[..]).unwrap();
    for db in [&built, &stored] {
        // EICAR, the one `.ndb` line, and not the trigger.
        assert_eq!(db.signature_count(), 2);
        let found = |data: &[u8]| match analyze(db, data, &ScanOptions::default()).verdict {
            Verdict::Infected { signature, .. } => Some(signature),
            _ => None,
        };
        assert_eq!(
            found(b"..prefix..MALWARE..suffix.."),
            Some("Synth.BC.Detect".to_string())
        );
        assert_eq!(found(b"..OTHER.."), Some("Other.Sig".to_string()));
        assert_eq!(found(b"nothing to see here"), None);
        let all = analyze_all(db, b"..MALWARE..OTHER..", &ScanOptions::default());
        let mut names: Vec<_> = all.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["Other.Sig", "Synth.BC.Detect"]);
    }
}

#[test]
fn forced_mode_runs_regardless_of_trigger() {
    let cbc = synth_cbc("Synth.BC.Detect", b"MALWARE");
    let (rt, _) = BytecodeRuntime::standalone(vec![cbc]);
    // Forced execution ignores the trigger: even clean input runs the program,
    // which unconditionally names the detection.
    let out = rt.run_forced(0, b"clean input").expect("program exists");
    assert!(!out.hit_unsupported);
    assert_eq!(out.detection.as_deref(), Some("Synth.BC.Detect"));

    let all = rt.run_all_forced(b"clean input");
    assert_eq!(all, vec![("Synth.BC.Detect".to_string(), 0)]);
}
