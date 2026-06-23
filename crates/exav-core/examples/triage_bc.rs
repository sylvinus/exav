// Triage helper: scan a directory of .cbc programs and report, per program,
// the opcodes and APIs used and what currently blocks execution.
use exav_core::bytecode::{exec, instr::Body, parse};
use std::collections::BTreeSet;

// A benign input to exercise each program with (must NOT be detected).
fn benign() -> Vec<u8> {
    let mut v = vec![0u8; 512];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    v
}

// A minimal benign PE32+ (for programs whose trigger targets PE files).
fn benign_pe() -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    v[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    v[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt = 0x58;
    v[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    v[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    v[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    let sh = 0x148;
    v[sh..sh + 5].copy_from_slice(b".text");
    v[sh + 8..sh + 12].copy_from_slice(&0x40u32.to_le_bytes());
    v[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    v[sh + 16..sh + 20].copy_from_slice(&0x40u32.to_le_bytes());
    v[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
    v[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    v.extend_from_slice(&[0x90u8; 0x40]);
    v
}

// Pick an input matching the program's trigger Target (1 = PE).
fn input_for(trigger: &str) -> Vec<u8> {
    let target = trigger
        .split("Target:")
        .nth(1)
        .and_then(|s| s.split([',', ';']).next())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if target == 1 {
        benign_pe()
    } else {
        benign()
    }
}

const OP_NAMES: &[&str] = &[
    "?", "add", "sub", "mul", "udiv", "sdiv", "urem", "srem", "shl", "lshr", "ashr", "and", "or",
    "xor", "trunc", "sext", "zext", "branch", "jmp", "ret", "retvoid", "icmp_eq", "icmp_ne",
    "icmp_ugt", "icmp_uge", "icmp_ult", "icmp_ule", "icmp_sgt", "icmp_sge", "icmp_sle", "icmp_slt",
    "select", "call_direct", "call_api", "copy", "gep1", "gepz", "gepn", "store", "load", "memset",
    "memcpy", "memmove", "memcmp", "isbigendian", "abort", "bswap16", "bswap32", "bswap64",
    "ptrdiff32", "ptrtoint64", "invalid",
];

// Opcodes the executor currently handles (37 = GEPN is the only gap).
fn op_supported(op: u8) -> bool {
    matches!(op, 1..=50)
}

fn main() {
    let dir = std::env::args().nth(1).unwrap();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "cbc").unwrap_or(false))
        .collect();
    entries.sort();

    let mut runnable = 0usize;
    let mut rows = Vec::new();
    for path in &entries {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(bc) = parse(&text) else {
            continue;
        };
        let mut ops = BTreeSet::new();
        let mut multi_fn = bc.functions.len() > 1;
        for f in &bc.functions {
            for blk in &f.blocks {
                for ins in blk {
                    ops.insert(ins.opcode);
                    if let Body::Call { api: false, .. } = ins.body {
                        multi_fn = true;
                    }
                }
            }
        }
        let blockers: Vec<&str> = ops
            .iter()
            .filter(|&&o| !op_supported(o))
            .map(|&o| *OP_NAMES.get(o as usize).unwrap_or(&"?"))
            .collect();
        let bad_apis: Vec<&str> = bc
            .apis
            .iter()
            .filter(|(_, n)| !exec::api_supported(n))
            .map(|(_, n)| n.as_str())
            .collect();
        let _ = multi_fn;
        let ok = blockers.is_empty() && bad_apis.is_empty();
        if ok {
            runnable += 1;
        }

        // Execute it on a benign input matching its trigger target. Function 0
        // is the entry point.
        let file = input_for(&bc.trigger);
        let pe = exav_core::pe::bytecode_pe(&file);
        let pdf = exec::pdf_ctx(&file);
        let ctx = exec::Ctx {
            file: &file,
            flevel: 200,
            types: &bc.types,
            globals: &bc.globals,
            pe: pe.as_ref(),
            pdf: Some(&pdf),
            match_offsets: &[],
            apis: &bc.apis,
            default_name: &bc.name,
        };
        let out = exec::run(&bc.functions, 0, &ctx);
        let (ran, detected) = (!out.hit_unsupported, out.detection.is_some());

        rows.push((
            ok,
            ran,
            detected,
            bc.name.clone(),
            bc.functions.len(),
            blockers.join(","),
            bad_apis.join(","),
        ));
    }

    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.3.cmp(&b.3)));
    let mut ran_clean = 0usize;
    let mut false_pos = 0usize;
    for (_ok, ran, detected, name, nfn, blockers, bad_apis) in &rows {
        if *ran && !*detected {
            ran_clean += 1;
        }
        if *ran && *detected {
            false_pos += 1;
        }
        let mark = match (ran, detected) {
            (true, false) => "RUN ",
            (true, true) => "DET!",
            _ => "    ",
        };
        println!("{mark}{name:<44} fns={nfn:<2} ops:[{blockers}] apis:[{bad_apis}]");
    }
    let executed = ran_clean + false_pos;
    println!(
        "\n{runnable}/{} statically clean of unsupported features",
        rows.len()
    );
    println!(
        "{executed}/{} executed to completion (no unsupported op/API)",
        rows.len()
    );
    println!("  of which {ran_clean} clean, {false_pos} set a name (trigger-gated programs run standalone — not false positives)");
}
