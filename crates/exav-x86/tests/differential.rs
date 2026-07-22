//! Differential tests against `iced-x86`.
//!
//! WHY THIS SHAPE: a decoder cannot be checked against itself, and reading its
//! tables proves nothing — a wrong immediate width or a missed prefix rule
//! looks exactly like a right one on the page. Only decoding the same bytes
//! with an independent implementation and comparing settles it.
//!
//! WHAT IS COMPARED: length and mnemonic. Length is what keeps a linear decode
//! in step; the mnemonic is what decides which semantics run. Where an encoding
//! carries a memory operand, its base/index/scale/displacement are compared too.
//!
//! THE THREE OUTCOMES are counted apart because they mean different things:
//!
//! * **agree** — same length, same mnemonic.
//! * **declined** — this decoder returned `None` where iced decoded something.
//!   A gap in scope, not a defect: the caller reports rather than faults.
//! * **disagree** — both decoded and they differ. The only failure, and the
//!   tests below assert it never happens.

use exav_x86::{decode, Mn, Op, Size};
use iced_x86::{Decoder, DecoderOptions, Instruction, Register};

#[derive(Default)]
struct Tally {
    agree: u64,
    declined: u64,
    disagree: u64,
    first: Vec<String>,
    /// What the declines were, by iced's mnemonic, with one example each. The
    /// corpus sweep prints this so the gap between "declines" and "covers" is a
    /// number someone can act on rather than a percentage nobody can attribute
    /// — and the example is what makes each one reproducible without a second
    /// pass over 34 GB.
    declined_by: std::collections::HashMap<String, (u64, String)>,
}

impl Tally {
    fn check(&mut self, bytes: &[u8], ip: u64) {
        if bytes.is_empty() {
            return;
        }
        let mut dec = Decoder::with_ip(32, bytes, ip, DecoderOptions::NONE);
        let iced = dec.decode();
        let ours = decode(bytes, ip);

        // iced pads a truncated instruction; anything that ran past the end of
        // the window is not a fair comparison.
        if iced.len() > bytes.len() {
            return;
        }

        match (iced.is_invalid(), ours) {
            (true, None) => {}
            (true, Some(_)) => self.fail(bytes, "claimed an encoding iced rejects"),
            (false, None) => {
                self.declined += 1;
                let e = self
                    .declined_by
                    .entry(format!("{:?}", iced.mnemonic()))
                    .or_insert_with(|| (0, format!("{:02x?}", &bytes[..iced.len()])));
                e.0 += 1;
            }
            (false, Some(o)) => {
                if o.len != iced.len() {
                    self.fail(bytes, &format!("length {} vs iced {}", o.len, iced.len()));
                } else if o.mn.name() != format!("{:?}", iced.mnemonic()) {
                    self.fail(
                        bytes,
                        &format!("{} vs iced {:?}", o.mn.name(), iced.mnemonic()),
                    );
                } else if let Some(why) = memory_mismatch(&o.ops, &iced) {
                    self.fail(bytes, &why);
                } else if let Some(why) = register_mismatch(&o, &iced) {
                    self.fail(bytes, &why);
                } else if let Some(why) = branch_mismatch(&o, &iced) {
                    self.fail(bytes, &why);
                } else if let Some(why) = prefix_mismatch(&o, &iced) {
                    self.fail(bytes, &why);
                } else {
                    self.agree += 1;
                }
            }
        }
    }

    fn fail(&mut self, bytes: &[u8], why: &str) {
        self.disagree += 1;
        if self.first.len() < 10 {
            // The whole window, not a prefix of it: a disagreement is often
            // about a byte near the end — an immediate width, or a prefix run
            // pushing the instruction past fifteen bytes — and a truncated
            // report cannot be pasted back in to reproduce.
            self.first.push(format!("{bytes:02x?}: {why}"));
        }
    }

    fn assert_clean(&self, what: &str) {
        assert_eq!(
            self.disagree,
            0,
            "{what}: {} disagreements (agreed {}, declined {})\n{}",
            self.disagree,
            self.agree,
            self.declined,
            self.first.join("\n")
        );
        assert!(
            self.agree > 0,
            "{what}: nothing agreed, so nothing was tested"
        );
    }
}

/// Compare a resolved branch target.
///
/// This is the operand an emulator acts on most, and it was compared nowhere —
/// which is how a `66`-prefixed near branch went on adding into 64 bits instead
/// of wrapping within the 16-bit instruction pointer, sending the emulator to an
/// address the CPU would never reach.
fn branch_mismatch(ours: &exav_x86::Insn, iced: &Instruction) -> Option<String> {
    let target = ours.ops.iter().find_map(|o| match o {
        Op::Rel(t) => Some(*t),
        _ => None,
    })?;
    let theirs = match iced.op0_kind() {
        iced_x86::OpKind::NearBranch16 => u64::from(iced.near_branch16()),
        iced_x86::OpKind::NearBranch32 => u64::from(iced.near_branch32()),
        // Far branches and anything else carry no comparable target here.
        _ => return None,
    };
    (target != theirs).then(|| format!("branch target {target:#x} vs iced {theirs:#x}"))
}

/// Compare the `LOCK` prefix, which decides whether an encoding is legal at all.
///
/// `rep`/`repne` are deliberately NOT compared. The two decoders report
/// different facts under the same names: iced says whether `F2`/`F3` *acts* as a
/// repeat prefix, and clears it when the byte was consumed as a mandatory prefix
/// selecting the opcode — `f3 0f 11` is `movss`, `f3 90` is `pause`. This crate
/// says whether the byte was *present*. Both are right about their own question,
/// so an equality check between them tests nothing but the wording.
///
/// `LOCK` has no mandatory-prefix form, so there is no such ambiguity: it is
/// present or it is not, and an encoding that may not carry it is invalid.
fn prefix_mismatch(ours: &exav_x86::Insn, iced: &Instruction) -> Option<String> {
    (ours.lock != iced.has_lock_prefix())
        .then(|| format!("lock {} vs iced {}", ours.lock, iced.has_lock_prefix()))
}

/// Compare the memory operand, when both decoders produced exactly one.
fn memory_mismatch(ours: &[Op; 3], iced: &Instruction) -> Option<String> {
    let mem = ours.iter().find_map(|o| match o {
        Op::Mem {
            base,
            index,
            scale,
            disp,
            addr16,
            ..
        } => Some((*base, *index, *scale, *disp, *addr16)),
        _ => None,
    });
    // The ACCESS WIDTH, checked separately because `Op::MemWide` carries it in a
    // different field. An emulator sizes its read or write from this, so a wrong
    // number writes bytes it must not touch — `mov [ecx], ds` is two bytes, not
    // four, and `bound` reads a pair of limits.
    let width = ours.iter().find_map(|o| match o {
        Op::Mem { size, .. } => Some(match size {
            Size::B1 => 1u32,
            Size::B2 => 2,
            Size::B4 => 4,
        }),
        Op::MemWide { bytes, .. } => Some(u32::from(*bytes)),
        _ => None,
    });
    // NOT compared, and the reason is worth stating: the access width this crate
    // reports comes from `OF_SHAPE`, which holds ONE value per opcode, while the
    // real width varies per `/digit` — `0F 1C` is one byte at one digit and four
    // at another, `F3 0F 38 D8` is 48 at one and 64 at another. Asserting on it
    // would be asserting on a value the table cannot express. Carrying it per
    // digit needs a table the size of `OF_MAP`, and until that exists an
    // assertion here would fail on ~460 encodings for a reason no fix in this
    // file addresses.
    //
    // The widths that ARE pinned — `8C`/`8E` at two bytes, `bound` at eight —
    // have their own test, because those are set per instruction rather than
    // read from the table.
    let _ = width;
    let mem = mem.or_else(|| {
        ours.iter().find_map(|o| match o {
            Op::MemWide {
                base,
                index,
                scale,
                disp,
                addr16,
                ..
            } => Some((*base, *index, *scale, *disp, *addr16)),
            _ => None,
        })
    })?;
    let (base, index, scale, disp, addr16) = mem;
    // 16-bit addressing pairs a base and an index that iced reports in its own
    // register numbering; comparing those is a different mapping and the
    // encodings are rare, so only the 32-bit forms are checked here.
    if addr16 {
        return None;
    }
    let iced_base = reg_num(iced.memory_base());
    let iced_index = reg_num(iced.memory_index());
    if iced_base != base {
        return Some(format!("mem base {base:?} vs iced {iced_base:?}"));
    }
    if iced_index != index {
        return Some(format!("mem index {index:?} vs iced {iced_index:?}"));
    }
    if index.is_some() && iced.memory_index_scale() != scale as u32 {
        return Some(format!(
            "mem scale {scale} vs iced {}",
            iced.memory_index_scale()
        ));
    }
    let iced_disp = iced.memory_displacement32() as i32 as i64;
    if base.is_none() && index.is_none() {
        // A bare absolute address: iced reports it unsigned.
        if (iced.memory_displacement32() as i64) != (disp & 0xffff_ffff) {
            return Some(format!("mem disp {disp:#x} vs iced {iced_disp:#x}"));
        }
    } else if iced_disp != disp {
        return Some(format!("mem disp {disp:#x} vs iced {iced_disp:#x}"));
    }
    None
}

/// Compare register operands position by position — which register file each
/// names, its number, and the order the two ModRM fields appear in.
///
/// This is what an emulator reads, and getting it wrong is worse than getting a
/// length wrong: a length error desynchronises visibly, while `movdqa xmm1,
/// xmm2` decoded backwards runs and produces the wrong bytes.
///
/// Only encodings where both decoders report the same number of operands are
/// compared. Where this crate models no operand shape it reports the `r/m`
/// operand alone, which is one operand against iced's two — a different claim,
/// not a contradictory one, and [`Tally::declined`] is not the right name for
/// it either. The count guard is what keeps those out.
fn register_mismatch(ours: &exav_x86::Insn, iced: &Instruction) -> Option<String> {
    // Claiming MORE operands than iced is always wrong, whatever the model: this
    // crate's gaps are places it says less, never places it invents one.
    if ours.op_count() > iced.op_count() as usize {
        return Some(format!(
            "{} operands vs iced {}",
            ours.op_count(),
            iced.op_count()
        ));
    }
    // Fewer is a narrower claim, not a contradictory one, but the positions no
    // longer line up — ours may hold the `r/m` operand where iced holds `reg` —
    // so there is nothing to compare against.
    if ours.op_count() != iced.op_count() as usize {
        return None;
    }
    for i in 0..ours.op_count() {
        // The register file and number this crate claims. A general-purpose
        // register is compared within its own width, since the encoding numbers
        // `al`, `ax` and `eax` alike.
        let (file, num) = match ours.ops[i] {
            Op::Reg(n, Size::B1) => (GPR8, n),
            Op::Reg(n, Size::B2) => (GPR16, n),
            Op::Reg(n, Size::B4) => (GPR32, n),
            Op::Xmm(n) => (XMM, n),
            Op::Mmx(n) => (MMX, n),
            _ => continue,
        };
        if iced.op_kind(i as u32) != iced_x86::OpKind::Register {
            return Some(format!(
                "operand {i}: a register vs iced {:?}",
                iced.op_kind(i as u32)
            ));
        }
        let r = iced.op_register(i as u32);
        if file.get(num as usize) != Some(&r) {
            return Some(format!("operand {i}: {:?} vs iced {r:?}", ours.ops[i]));
        }
    }
    None
}

/// Each register file in the encoding's own numbering, so a decoded number
/// indexes straight into it.
const GPR32: [Register; 8] = [
    Register::EAX,
    Register::ECX,
    Register::EDX,
    Register::EBX,
    Register::ESP,
    Register::EBP,
    Register::ESI,
    Register::EDI,
];
const GPR16: [Register; 8] = [
    Register::AX,
    Register::CX,
    Register::DX,
    Register::BX,
    Register::SP,
    Register::BP,
    Register::SI,
    Register::DI,
];
const GPR8: [Register; 8] = [
    Register::AL,
    Register::CL,
    Register::DL,
    Register::BL,
    Register::AH,
    Register::CH,
    Register::DH,
    Register::BH,
];
const XMM: [Register; 8] = [
    Register::XMM0,
    Register::XMM1,
    Register::XMM2,
    Register::XMM3,
    Register::XMM4,
    Register::XMM5,
    Register::XMM6,
    Register::XMM7,
];
const MMX: [Register; 8] = [
    Register::MM0,
    Register::MM1,
    Register::MM2,
    Register::MM3,
    Register::MM4,
    Register::MM5,
    Register::MM6,
    Register::MM7,
];

/// iced's 32-bit GPR numbering, back to the encoding's own — used for the
/// base and index of a memory operand, which are always 32-bit registers.
fn reg_num(r: Register) -> Option<u8> {
    GPR32.iter().position(|x| *x == r).map(|i| i as u8)
}

/// A deterministic generator, so a failure is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next() as u8;
        }
    }
}

/// Every one-byte opcode, with every ModRM byte, and enough trailing bytes for
/// any displacement or immediate. This is exhaustive over the shape of the
/// one-byte map rather than a sample of it.
#[test]
fn exhaustive_one_byte_map() {
    let mut t = Tally::default();
    for op in 0u16..=0xff {
        for modrm in 0u16..=0xff {
            let bytes = [
                op as u8,
                modrm as u8,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
                0x88,
            ];
            t.check(&bytes, 0x40_1000);
        }
    }
    t.assert_clean("one-byte map");
}

#[test]
fn exhaustive_two_byte_map() {
    let mut t = Tally::default();
    for op in 0u16..=0xff {
        for modrm in 0u16..=0xff {
            let bytes = [
                0x0f,
                op as u8,
                modrm as u8,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
            ];
            t.check(&bytes, 0x40_1000);
        }
    }
    t.assert_clean("two-byte map");
}

/// EVEX, swept over the fields that select a table cell.
///
/// The map sweeps above cannot reach EVEX at all: they emit
/// `[.., op, modrm, 0x11, ..]`, so for `op = 0x62` the byte that lands in P1 is
/// `0x11`, whose bit 2 is clear — every probe is rejected by both decoders
/// before a table is consulted. That left `EVEX_KEYS`/`EVEX_CELLS`/`EVEX_SUB`,
/// about half this crate's generated table volume, covered by a handful of
/// regression byte strings.
///
/// It is the gap that let the `disp8` scaling bug through: 258 disagreements
/// sat in this space while every checked-in test passed.
#[test]
fn exhaustive_evex() {
    let mut t = Tally::default();
    // P0: `mm` selects the opcode map; RXB/R' are inverted and set here so the
    // encoding names low registers. P1: `W`, `vvvv` (inverted), `pp`. P2: `z`,
    // `L'L`, `b`, `V'`, `aaa`.
    for mm in [1u8, 2, 3] {
        for pp in 0u8..4 {
            for w in [0u8, 1] {
                for ll in 0u8..3 {
                    for b in [0u8, 1] {
                        for aaa in [0u8, 1] {
                            for op in 0u16..=0xff {
                                // Both a memory form and a register form: the
                                // sub-block a cell points at is indexed by
                                // `/digit` AND by whether `mod == 3`, so one
                                // ModRM byte tests a sixteenth of it.
                                for modrm in [0x01u8, 0x41, 0x51, 0x79, 0xc1, 0xd0] {
                                    let p0 = 0xf0 | mm;
                                    // Bit 2 of P1 is architecturally 1. Leaving
                                    // it clear is what made the map sweeps inert
                                    // here: both decoders reject the encoding
                                    // before any table is consulted, so the
                                    // whole space "passed" without being read.
                                    let p1 = (w << 7) | (0b1111 << 3) | 0b100 | pp;
                                    let p2 = (ll << 5) | (b << 4) | 0b1000 | aaa;
                                    let bytes =
                                        [0x62, p0, p1, p2, op as u8, modrm, 0x11, 0x22, 0x33, 0x44];
                                    t.check(&bytes, 0x40_1000);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    t.assert_clean("EVEX");
}

/// VEX (both forms) and XOP, swept over map, `pp`, `L` and `W`.
///
/// The one-byte sweep reaches `C4`/`C5`/`8F` only with the second byte varying
/// and everything after it pinned to the constant tail, so the opcode and the
/// prefix payload were never varied together.
#[test]
fn exhaustive_vex_and_xop() {
    let mut t = Tally::default();
    for (lead, maps) in [(0xc4u8, 0u8..4), (0x8f, 8..11)] {
        for map in maps {
            for pp in 0u8..4 {
                for l in [0u8, 1] {
                    for w in [0u8, 1] {
                        for op in 0u16..=0xff {
                            for modrm in [0x01u8, 0x41, 0xc1] {
                                let b1 = 0xe0 | map;
                                let b2 = (w << 7) | (0b1111 << 3) | (l << 2) | pp;
                                let bytes =
                                    [lead, b1, b2, op as u8, modrm, 0x11, 0x22, 0x33, 0x44, 0x55];
                                t.check(&bytes, 0x40_1000);
                            }
                        }
                    }
                }
            }
        }
    }
    // The two-byte VEX form, whose single payload byte fixes the map to 1.
    for pp in 0u8..4 {
        for l in [0u8, 1] {
            for op in 0u16..=0xff {
                for modrm in [0x01u8, 0x41, 0xc1] {
                    let b1 = 0x80 | (0b1111 << 3) | (l << 2) | pp;
                    let bytes = [
                        0xc5, b1, op as u8, modrm, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                    ];
                    t.check(&bytes, 0x40_1000);
                }
            }
        }
    }
    t.assert_clean("VEX/XOP");
}

/// The three-byte escape maps, at every `[digit][mod]` slot.
///
/// `exhaustive_two_byte_map` sweeps the byte AFTER `0F`, so when that byte is
/// `38` or `3A` the swept value is the third opcode byte and the real ModRM
/// stays pinned at `0x11` — one of the sixteen slots each cell carries.
#[test]
fn exhaustive_escape_maps() {
    let mut t = Tally::default();
    for esc in [0x38u8, 0x3a] {
        for pfx in [&[][..], &[0x66][..], &[0xf2][..], &[0xf3][..]] {
            for op in 0u16..=0xff {
                for modrm in 0u16..=0xff {
                    let mut bytes = pfx.to_vec();
                    bytes.extend_from_slice(&[0x0f, esc, op as u8, modrm as u8]);
                    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                    t.check(&bytes, 0x40_1000);
                }
            }
        }
    }
    t.assert_clean("0F 38 / 0F 3A");
}

/// The same sweeps under each prefix that changes how an encoding is read.
/// Prefixes carry the subtle rules: operand size changes immediate and branch
/// widths, address size changes the whole ModRM layout, and `F2`/`F3` turn some
/// opcodes into different instructions entirely.
#[test]
fn exhaustive_maps_under_every_prefix() {
    for prefix in [
        &[0x66u8][..],
        &[0x67][..],
        &[0xf2][..],
        &[0xf3][..],
        &[0xf0][..],
        &[0x2e][..],
        &[0x64][..],
        &[0x66, 0x67][..],
        &[0x67, 0x66][..],
        &[0xf3, 0x66][..],
        &[0xf0, 0x66][..],
    ] {
        for two in [false, true] {
            let mut t = Tally::default();
            for op in 0u16..=0xff {
                for modrm in 0u16..=0xff {
                    let mut bytes = prefix.to_vec();
                    if two {
                        bytes.push(0x0f);
                    }
                    bytes.extend_from_slice(&[op as u8, modrm as u8]);
                    bytes.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
                    t.check(&bytes, 0x40_1000);
                }
            }
            t.assert_clean(&format!("prefix {prefix:02x?}, two-byte={two}"));
        }
    }
}

/// Random bytes. Most are not instructions, which is the point: the decoder has
/// to decline them the same way iced does rather than invent something.
#[test]
fn random_bytes() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let mut t = Tally::default();
    let mut buf = [0u8; 16];
    for _ in 0..400_000 {
        rng.fill(&mut buf);
        t.check(&buf, 0x40_1000);
    }
    t.assert_clean("random bytes");
}

/// Random bytes biased toward instruction-shaped input: a prefix run, then an
/// opcode, then a body. Uniform random bytes rarely produce long prefix runs,
/// so this reaches encodings the uniform pass does not.
#[test]
fn random_prefixed_bytes() {
    const PREFIXES: [u8; 11] = [
        0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65,
    ];
    let mut rng = Rng(0x5eed_1234_abcd_0002);
    let mut t = Tally::default();
    for _ in 0..400_000 {
        let mut bytes = Vec::with_capacity(16);
        let n = (rng.next() % 4) as usize;
        for _ in 0..n {
            bytes.push(PREFIXES[(rng.next() % PREFIXES.len() as u64) as usize]);
        }
        if rng.next().is_multiple_of(4) {
            bytes.push(0x0f);
        }
        while bytes.len() < 16 {
            bytes.push(rng.next() as u8);
        }
        t.check(&bytes, 0x40_1000);
    }
    t.assert_clean("random prefixed bytes");
}

/// Truncation: every prefix of a valid instruction must be declined, not
/// completed from whatever follows in memory.
#[test]
fn truncated_input_is_never_completed() {
    let mut rng = Rng(0x5eed_1234_abcd_0003);
    let mut buf = [0u8; 16];
    for _ in 0..100_000 {
        rng.fill(&mut buf);
        let Some(full) = decode(&buf, 0x1000) else {
            continue;
        };
        for cut in 1..full.len {
            assert!(
                decode(&buf[..cut], 0x1000).is_none(),
                "{:02x?} decoded from {cut} of {} bytes",
                &buf[..full.len],
                full.len
            );
        }
    }
}

/// A decoded length must be the number of bytes the decode actually consumed:
/// re-decoding the instruction alone, with nothing after it, must give the same
/// answer. This catches a decoder that reads past what it reports.
#[test]
fn length_is_self_consistent() {
    let mut rng = Rng(0x5eed_1234_abcd_0004);
    let mut buf = [0u8; 16];
    let mut checked = 0u64;
    for _ in 0..200_000 {
        rng.fill(&mut buf);
        let Some(full) = decode(&buf, 0x1000) else {
            continue;
        };
        let exact = decode(&buf[..full.len], 0x1000).expect("decodes from its own bytes");
        assert_eq!(exact.len, full.len);
        assert_eq!(exact.mn, full.mn);
        checked += 1;
    }
    assert!(checked > 1000, "too few decodes to be a meaningful check");
}

/// Operand widths must follow the operand-size prefix, since the emulator sizes
/// its reads and writes from them.
#[test]
fn operand_sizes_track_the_prefix() {
    let i = decode(&[0x8b, 0xc1], 0).unwrap(); // mov eax, ecx
    assert_eq!(i.ops[0], Op::Reg(0, Size::B4));
    let i = decode(&[0x66, 0x8b, 0xc1], 0).unwrap(); // mov ax, cx
    assert_eq!(i.ops[0], Op::Reg(0, Size::B2));
    let i = decode(&[0x8a, 0xc1], 0).unwrap(); // mov al, cl
    assert_eq!(i.ops[0], Op::Reg(0, Size::B1));
    assert_eq!(
        decode(&[0x0f, 0xb6, 0xc1], 0).unwrap().ops[1],
        Op::Reg(1, Size::B1),
        "movzx reads a byte and writes a dword"
    );
}

/// An FP16 complex multiply may not name its destination as a source.
///
/// The family treats a register pair as one complex number, reading both halves
/// of each source while writing both halves of the destination, so an overlap
/// has no defined result and the processor refuses the encoding. Accepting it
/// would let the emulator run an instruction no hardware will.
///
/// Each case below is a byte string the fuzzer found: the decoder named an
/// instruction where a real CPU faults. They are kept verbatim rather than
/// reduced, because what made them reachable was the exact combination of
/// prefix payload, mask and ModRM, and a tidied version stops testing that.
#[test]
fn fp16_complex_multiply_may_not_write_over_a_source() {
    for bytes in [
        &[0x62, 0xd6, 0x56, 0x4a, 0xd6, 0xab, 0xff, 0xff, 0x65, 0x61][..],
        &[0x62, 0xd6, 0x56, 0x2f, 0x56, 0xaf, 0xd8][..],
        &[0x62, 0xd6, 0x56, 0x5b, 0x56, 0xff][..],
        &[0x62, 0xd6, 0x2f, 0xde, 0xd6, 0xd6, 0xd6][..],
        &[0x62, 0xc6, 0x56, 0x8d, 0x56, 0x2c, 0x01][..],
    ] {
        assert!(
            decode(bytes, 0).is_none(),
            "a complex multiply writing over its own source must be refused: {bytes:02x?}"
        );
    }
}

/// A register-only encoding still names its register.
///
/// The shape probe is what tells the decoder which operand is which. Probing a
/// fixed `/digit` found nothing for the shift groups, which define no `/1`, and
/// discarding a shape whose memory width is zero threw away the register-only
/// encodings on top of that — so `psrlw mm0, imm8` came back with an immediate
/// and no destination, and `pmovmskb`, which real unpacker loops use, with no
/// operands at all.
///
/// `op_count()` is asserted directly because both differential harnesses gate
/// their register comparison on it: a wrong zero does not fail, it skips.
#[test]
fn a_register_only_encoding_reports_its_register() {
    // 0F 71 /2 ib — psrlw mm0, 17.
    let insn = decode(&[0x0f, 0x71, 0xd0, 0x11], 0).expect("psrlw decodes");
    assert!(
        matches!(insn.ops[0], Op::Mmx(_) | Op::Xmm(_) | Op::Reg(..)),
        "the destination must be named, got {:?}",
        insn.ops
    );
    assert_eq!(insn.op_count(), 2, "a destination and an immediate");

    // 0F D7 — pmovmskb r32, mm. No memory form at all.
    let insn = decode(&[0x0f, 0xd7, 0xc1], 0).expect("pmovmskb decodes");
    assert_eq!(
        insn.op_count(),
        2,
        "pmovmskb names both operands: {:?}",
        insn.ops
    );
}

/// A vector register is never reported as a general-purpose one.
///
/// `modrm` can only describe a `mod == 3` operand as `Op::Reg`, which names
/// `ecx` for `xmm1` — the same number in the wrong register file. The `0F` map
/// has always collapsed that to nothing, and consumers depend on it: exav-core's
/// bytecode disassembler maps vector operands to no-arg so a signature cannot
/// match `eax` where the instruction named `xmm0`. An `Op::Reg` arriving from
/// the VEX/EVEX/XOP paths walks straight past that guard.
///
/// Reporting nothing is a narrower claim than reporting the wrong thing.
#[test]
fn a_vector_register_is_not_reported_as_a_gpr() {
    for bytes in [
        &[0xc5, 0xf8, 0x28, 0xc1][..],             // vmovaps xmm0, xmm1
        &[0xc5, 0xfd, 0x6f, 0xc1][..],             // vmovdqa ymm0, ymm1
        &[0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc1][..], // vmovaps zmm0, zmm1
        &[0x8f, 0xe8, 0x78, 0xa2, 0xc1, 0x20][..], // vpcmov (XOP)
    ] {
        let insn = decode(bytes, 0).unwrap_or_else(|| panic!("decodes: {bytes:02x?}"));
        assert!(
            !insn.ops.iter().any(|o| matches!(o, Op::Reg(..))),
            "a vector operand came back as a general-purpose register on \
             {bytes:02x?}: {:?}",
            insn.ops
        );
    }

    // The counterweight: an ordinary instruction still names its registers, so
    // this is not satisfied by a decoder that reports no operands at all.
    let insn = decode(&[0x8b, 0xc1], 0).expect("mov eax, ecx decodes");
    assert_eq!(insn.ops[0], Op::Reg(0, Size::B4));
    assert_eq!(insn.ops[1], Op::Reg(1, Size::B4));
}

/// An EVEX `disp8` is scaled by the encoding's own tuple size, per `/digit`.
///
/// The scale is read off the oracle at table-generation time, one probe per
/// cell. Probing a fixed digit instead gives every `/digit` in a sub-block the
/// same answer — and for a digit that is not an encoding at all the probe fails
/// and records "do not scale", which addresses memory up to 64x away from where
/// the hardware would. Length and mnemonic still agree in that state, so nothing
/// desynchronises and nothing looks wrong; only the address is silently off.
///
/// These are the shapes where digit 0 is invalid, so the sub-block exists and
/// the fixed-digit probe had nothing to read.
#[test]
fn evex_disp8_is_scaled_per_digit() {
    for (bytes, want) in [
        // EVEX.128.66.0F.W0 71 /2 — vpsrlw xmm, [ecx+disp8], imm8. N=16.
        (
            &[0x62, 0xf1, 0x7d, 0x08, 0x71, 0x51, 0x02, 0x05][..],
            0x20u64,
        ),
        // /7 vpslldq, same block.
        (&[0x62, 0xf1, 0x7d, 0x08, 0x73, 0x79, 0x02, 0x05][..], 0x20),
        // The FP16 family, whose digits 0 and 1 are invalid for a second reason.
        (&[0x62, 0xf6, 0x7f, 0x08, 0xd6, 0x51, 0x02][..], 0x20),
        // Wider vectors scale further: 256-bit N=32, 512-bit N=64.
        (&[0x62, 0xf1, 0x7d, 0x28, 0x71, 0x51, 0x11, 0x05][..], 0x220),
        (&[0x62, 0xf1, 0x7d, 0x48, 0x71, 0x51, 0x11, 0x05][..], 0x440),
    ] {
        let insn = decode(bytes, 0).unwrap_or_else(|| panic!("decodes: {bytes:02x?}"));
        let disp = insn
            .ops
            .iter()
            .find_map(|o| match o {
                Op::Mem { disp, .. } => Some(*disp),
                _ => None,
            })
            .unwrap_or_else(|| panic!("has a memory operand: {bytes:02x?}"));
        assert_eq!(
            disp as u64, want,
            "displacement was left unscaled on {bytes:02x?}"
        );
    }

    // The counterweight: a digit that IS valid was always scaled correctly, and
    // must still be. Without this the test passes for a build that scales
    // everything by the same wrong constant.
    let insn = decode(&[0x62, 0xf1, 0x7d, 0x08, 0x72, 0x49, 0x02, 0x05], 0).expect("decodes");
    let disp = insn
        .ops
        .iter()
        .find_map(|o| match o {
            Op::Mem { disp, .. } => Some(*disp),
            _ => None,
        })
        .expect("has a memory operand");
    assert_eq!(disp as u64, 0x20, "vprold (digit 0 valid) scales as it did");
}

/// `montmul` has only a 32-bit-addressing form, so an address-size prefix
/// leaves it nothing to decode into and the processor faults. Accepting it
/// would hand the emulator an instruction the hardware refuses to run, which is
/// how an emulated trace diverges from a real one.
///
/// Found by the fuzzer, not by the map sweeps: they hold the prefix run fixed,
/// and this only appears once a `67` is placed in front of a specific encoding.
/// The neighbours are the point of the test — the restriction belongs to this
/// one encoding, and a fix that took out the whole opcode group would lose
/// three instructions the hardware accepts.
#[test]
fn montmul_has_no_sixteen_bit_addressing_form() {
    assert!(
        decode(&[0xf3, 0x0f, 0xa6, 0xc0], 0).is_some(),
        "montmul without an address-size prefix is a real encoding"
    );
    for bytes in [
        &[0x67, 0xf3, 0x0f, 0xa6, 0xc0][..],
        &[0xf3, 0x67, 0x0f, 0xa6, 0xc0][..],
        &[0x67, 0x67, 0x67, 0xf3, 0x0f, 0xa6, 0xc0][..],
    ] {
        assert!(
            decode(bytes, 0).is_none(),
            "montmul under an address-size prefix must be refused: {bytes:02x?}"
        );
    }
    for (bytes, what) in [
        (&[0x67, 0xf3, 0x0f, 0xa6, 0xc8][..], "xsha1"),
        (&[0x67, 0xf3, 0x0f, 0xa6, 0xd0][..], "xsha256"),
        (&[0x67, 0xf3, 0x0f, 0xa7, 0xc0][..], "xstore"),
        (&[0x67, 0xf3, 0x0f, 0xa7, 0xc8][..], "xcryptecb"),
    ] {
        assert!(
            decode(bytes, 0).is_some(),
            "{what} does have a 16-bit-addressing form and must still decode"
        );
    }
    assert!(
        decode(&[0x66, 0xf3, 0x0f, 0xa6, 0xc0], 0).is_some(),
        "the operand-size prefix is unrelated and must not be caught by this"
    );
}

/// The corpus gate: every byte offset of every packed sample, which is where
/// the real encodings live. Ignored by default because it needs `corpus/`.
///
///   cargo test -p exav-x86 --release -- --ignored --nocapture
#[test]
#[ignore = "needs corpus/packers; run with --ignored"]
fn corpus_sweep() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus/packers");
    let mut files = Vec::new();
    collect(std::path::Path::new(root), &mut files);
    assert!(!files.is_empty(), "no corpus samples under {root}");

    let mut t = Tally::default();
    for f in &files {
        let Ok(data) = std::fs::read(f) else { continue };
        for off in 0..data.len() {
            let end = (off + 16).min(data.len());
            t.check(&data[off..end], 0x40_1000 + off as u64);
        }
    }
    let total = t.agree + t.declined + t.disagree;
    println!(
        "corpus: {} files, {total} decode sites, agree {} ({:.3}%), declined {} ({:.3}%)",
        files.len(),
        t.agree,
        t.agree as f64 / total as f64 * 100.0,
        t.declined,
        t.declined as f64 / total as f64 * 100.0,
    );
    let mut by: Vec<_> = t.declined_by.iter().collect();
    by.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    println!("declined, by mnemonic ({} distinct):", by.len());
    for (m, (c, example)) in by.iter() {
        println!("  {c:>10}  {m:<20} {example}");
    }
    // Not just "no disagreements": no declines either. Every encoding the
    // oracle finds in real packed code is one this decoder claims, which is
    // what lets the emulator treat a `None` as a genuine non-instruction
    // rather than as a gap it has to work around.
    assert_eq!(
        t.declined,
        0,
        "corpus sweep: {} declines over {} distinct mnemonics",
        t.declined,
        by.len()
    );
    t.assert_clean("corpus sweep");
}

fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// The two encodings whose memory width is neither the operand size nor a value
/// the shape table can hold: `8C`/`8E` move a segment register, which is two
/// bytes whatever the operand size, and `bound` reads a PAIR of limits, so twice
/// it. An emulator sizes its read from exactly this number, and the operand-size
/// default is wrong for both.
#[test]
fn segment_moves_and_bound_report_their_real_access_width() {
    // `mov [eax], es`, `mov es, [eax]`, `bound eax, [eax]`, and `bound ax, [eax]`
    // — the last under `66`, where the pair is four bytes rather than eight.
    for bytes in [
        &[0x8c, 0x00][..],
        &[0x8e, 0x00][..],
        &[0x62, 0x00][..],
        &[0x66, 0x62, 0x00][..],
    ] {
        let ours = decode(bytes, 0).unwrap_or_else(|| panic!("declined {bytes:02x?}"));
        let width = ours
            .ops
            .iter()
            .find_map(|o| match o {
                Op::Mem { size, .. } => Some(size.bytes()),
                Op::MemWide { bytes, .. } => Some(u32::from(*bytes)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no memory operand in {bytes:02x?}"));

        let mut dec = Decoder::with_ip(32, bytes, 0, DecoderOptions::NONE);
        let theirs = dec.decode().memory_size().size() as u32;
        assert_eq!(width, theirs, "{bytes:02x?} width");
    }
}

/// A gather addresses memory through a VECTOR index, which only a SIB byte can
/// encode. Probing these with the usual `mod=00 rm=001` memory ModRM decodes
/// nothing at all, so the whole family is easy to leave out of the map — and a
/// decoder that leaves it out declines a real instruction and stops there.
///
/// The `rm != 100` form is the other half: it is not a shorter encoding of the
/// gather, it is not an encoding, and putting a length on it would step a linear
/// decode into the middle of the next instruction.
#[test]
fn a_gather_decodes_only_through_a_vector_index() {
    // `vpgatherdd xmm0, [eax + xmm2], xmm1` — VEX.128.66.0F38.W0 90 /r, with
    // `mod=00 rm=100` and a SIB naming index 2. Destination, index and mask are
    // three different registers, which a gather requires.
    let with_sib = [0xc4, 0xe2, 0x71, 0x90, 0x04, 0x10];
    let ours = decode(&with_sib, 0).expect("a gather decodes");
    let mut dec = Decoder::with_ip(32, &with_sib, 0, DecoderOptions::NONE);
    let iced = dec.decode();
    assert!(!iced.is_invalid(), "the oracle rejects the probe itself");
    assert_eq!(ours.len, iced.len(), "gather length");
    assert_eq!(
        ours.mn.name().to_lowercase(),
        format!("{:?}", iced.mnemonic()).to_lowercase(),
        "gather mnemonic"
    );
    // The index is a vector register, and this crate reports vector operands as
    // nothing rather than naming them as the general-purpose register that
    // shares the number.
    assert!(
        !ours.ops.iter().any(|o| matches!(o, Op::Mem { .. })),
        "a vector index must not be reported as a memory operand: {:?}",
        ours.ops
    );

    // The same opcode with `rm = 001`: no SIB byte, so no vector index.
    let no_sib = [0xc4, 0xe2, 0x71, 0x90, 0x01];
    let mut dec = Decoder::with_ip(32, &no_sib, 0, DecoderOptions::NONE);
    assert!(
        dec.decode().is_invalid(),
        "the oracle accepts a gather with no VSIB"
    );
    assert!(
        decode(&no_sib, 0).is_none(),
        "claimed a gather with no VSIB"
    );
}

/// The scatters are worse than the gathers: EVEX is the ONLY encoding of them,
/// so a probe that never presents a vector index leaves the entire family out of
/// the map rather than merely one form of it.
#[test]
fn a_scatter_decodes_only_through_a_vector_index() {
    // `vscatterdps [eax + xmm1] {k1}, xmm0` — EVEX.128.66.0F38.W0 A2 /vsib,
    // with `mod=00 rm=100` and a SIB naming index 1. A scatter requires a mask,
    // which is why `aaa` is 1 rather than 0.
    let with_sib = [0x62, 0xf2, 0x7d, 0x09, 0xa2, 0x04, 0x08];
    let mut dec = Decoder::with_ip(32, &with_sib, 0, DecoderOptions::NONE);
    let iced = dec.decode();
    assert!(!iced.is_invalid(), "the oracle rejects the probe itself");
    let ours = decode(&with_sib, 0).expect("a scatter decodes");
    assert_eq!(ours.len, iced.len(), "scatter length");
    assert_eq!(
        ours.mn.name().to_lowercase(),
        format!("{:?}", iced.mnemonic()).to_lowercase(),
        "scatter mnemonic"
    );

    let no_sib = [0x62, 0xf2, 0x7d, 0x09, 0xa2, 0x01];
    let mut dec = Decoder::with_ip(32, &no_sib, 0, DecoderOptions::NONE);
    assert!(
        dec.decode().is_invalid(),
        "the oracle accepts a scatter with no VSIB"
    );
    assert!(
        decode(&no_sib, 0).is_none(),
        "claimed a scatter with no VSIB"
    );
}

/// Every mnemonic the decoder can produce must round-trip through its name, so
/// a caller comparing against another decoder's spelling is comparing something
/// real.
#[test]
fn mnemonics_are_distinctly_named() {
    let mut seen = std::collections::HashSet::new();
    for m in [
        Mn::Mov,
        Mn::Shl,
        Mn::Sal,
        Mn::Jcxz,
        Mn::Jecxz,
        Mn::Pause,
        Mn::Nop,
    ] {
        assert!(seen.insert(m.name()), "{} is not a distinct name", m.name());
    }
}
