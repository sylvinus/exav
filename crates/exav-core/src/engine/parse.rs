//! Signature-text parsing: `.ndb`/`.ldb` bodies, sub-signatures, offsets, and
//! TDB metadata compiled into the engine IR. Split out of `mod.rs`; every item
//! is `pub(super)` (internal to the `engine` module).

use super::logic::parse_expr;
use super::*;

/// Parse an `.ldb` subsignature: `[Offset:]HexBody[::Modifiers]`. Expands to
/// one or more compiled variants (ASCII and/or wide). `None` if unsupported
/// (PCRE, an unsupported offset, or a wide pattern that isn't pure-literal).
/// A subsignature parsed but not yet committed to the engine.
pub(super) enum ParsedSub {
    Bodies(Vec<Compiled>),
    Pcre(PcreSub),
    Bcomp(BcompSub),
    Fuzzy([u8; 8]),
}

/// Classify and parse one subsignature: byte-compare (`N(..#..#..)`), PCRE
/// (`Trigger/regex/flags`), or a normal hex/pattern body.
pub(super) fn classify_subsig(s: &str) -> Option<ParsedSub> {
    if let Some(rest) = s.strip_prefix("fuzzy_img#") {
        return parse_fuzzy_subsig(rest).map(ParsedSub::Fuzzy);
    }
    if let Some(b) = parse_bcomp_subsig(s) {
        return Some(ParsedSub::Bcomp(b));
    }
    if s.contains('/') {
        return parse_pcre_subsig(s).map(ParsedSub::Pcre);
    }
    parse_subsig(s).map(ParsedSub::Bodies)
}

/// Parse the body of a `fuzzy_img#<16-hex>[#<distance>]` subsignature (the
/// `fuzzy_img#` prefix already stripped). Returns the 8-byte hash. Only Hamming
/// distance 0 is supported by the current signature format, so a non-zero
/// `#distance` suffix makes the subsig unsupported (dropped).
pub(super) fn parse_fuzzy_subsig(rest: &str) -> Option<[u8; 8]> {
    let mut parts = rest.split('#');
    let hash = parts.next()?;
    if let Some(dist) = parts.next() {
        if dist.trim().parse::<u32>().ok()? != 0 {
            return None;
        }
    }
    if parts.next().is_some() || hash.len() != 16 {
        return None;
    }
    // Reject non-ASCII input — multi-byte UTF-8 chars would cause byte-index
    // panics in the hex-decode loop below.
    if !hash.is_ascii() {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse a numeric value that may be hex (`0x..`) or decimal.
pub(super) fn parse_num(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

/// Parse `Trigger/PCRE/[flags]`. The regex is delimited by the first and last
/// `/`; flags `i`/`s`/`m` map to case-insensitive/dotall/multiline (other
/// Flags like `g`/`r`/`e` are accepted but don't change a match/no-match
/// result here).
pub(super) fn parse_pcre_subsig(s: &str) -> Option<PcreSub> {
    let first = s.find('/')?;
    let last = s.rfind('/')?;
    if last <= first {
        return None;
    }
    let trigger = parse_expr(&s[..first])?;
    let pattern = &s[first + 1..last];
    if pattern.is_empty() {
        return None;
    }
    let flags = &s[last + 1..];
    Some(PcreSub {
        trigger,
        pattern: pattern.to_string(),
        ci: flags.contains('i'),
        dotall: flags.contains('s'),
        multiline: flags.contains('m'),
        re: std::sync::OnceLock::new(),
        fancy: std::sync::OnceLock::new(),
    })
}

/// Parse `subsigid(offset#byte_options#comparisons)`.
pub(super) fn parse_bcomp_subsig(s: &str) -> Option<BcompSub> {
    let lp = s.find('(')?;
    let rp = s.strip_suffix(')')?.len(); // index of the trailing ')'
    if rp <= lp {
        return None;
    }
    let trigger: usize = s[..lp].trim().parse().ok()?;
    let inner = &s[lp + 1..rp];
    let mut fields = inner.split('#');
    let off_s = fields.next()?;
    let opts_s = fields.next()?;
    let cmps_s = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    // offset: `>>N` positive, `<<N` negative.
    let (neg, num) = if let Some(n) = off_s.strip_prefix(">>") {
        (false, n)
    } else if let Some(n) = off_s.strip_prefix("<<") {
        (true, n)
    } else {
        return None;
    };
    let mag = parse_num(num)?;
    let offset = if neg { -mag } else { mag };
    // byte_options: [h|d|a|i][l|b]?[e]? num_bytes
    let mut ch = opts_s.chars().peekable();
    let kind = match ch.next()? {
        'h' => BcompKind::Hex,
        'd' => BcompKind::Dec,
        'a' => BcompKind::Auto,
        'i' => BcompKind::Raw,
        _ => return None,
    };
    let mut big_endian = matches!(kind, BcompKind::Dec); // decimal implies big-endian
    let mut exact = matches!(kind, BcompKind::Raw); // raw implies exact
    if matches!(ch.peek(), Some('l') | Some('b')) {
        big_endian = ch.next() == Some('b');
    }
    if ch.peek() == Some(&'e') {
        ch.next();
        exact = true;
    }
    let nb: String = ch.collect();
    let num_bytes = parse_num(&nb)?;
    if num_bytes <= 0 || num_bytes > 1024 {
        return None;
    }
    if kind == BcompKind::Raw && !matches!(num_bytes, 1 | 2 | 4 | 8) {
        return None;
    }
    // comparisons: one or two `symbolvalue`, comma-separated.
    let mut cmps = Vec::new();
    for set in cmps_s.split(',') {
        let set = set.trim();
        // `set` can be empty (e.g. a trailing comma in a hostile `.ldb`/CVD);
        // `split_at(1)` would panic, so reject an empty comparison instead.
        let sym = set.get(..1)?;
        let val = &set[1..];
        let c = match sym {
            "<" => Cmp::Lt,
            ">" => Cmp::Gt,
            "=" => Cmp::Eq,
            _ => return None,
        };
        cmps.push((c, parse_num(val)?));
    }
    if cmps.is_empty() || cmps.len() > 2 {
        return None;
    }
    Some(BcompSub {
        trigger,
        offset,
        kind,
        big_endian,
        num_bytes: num_bytes as usize,
        exact,
        cmps,
    })
}

pub(super) fn parse_subsig(s: &str) -> Option<Vec<Compiled>> {
    if s.is_empty() || s.contains('/') {
        return None; // empty or PCRE
    }
    let (core, flags) = match s.split_once("::") {
        Some((c, f)) => (c, f),
        None => (s, ""),
    };
    // An offset prefix is everything before the first ':' (hex bodies have no
    // ':'). No ':' means offset "any".
    let (offset, body) = match core.split_once(':') {
        Some((o, b)) => (parse_offset(o)?, b),
        None => (Offset::Any, core),
    };
    let nocase = flags.contains('i');
    let wide = flags.contains('w');
    let ascii = flags.contains('a') || !wide;

    let allow_internal = matches!(offset, Offset::Any);
    let mut out = Vec::new();
    if ascii {
        let (e, a, p) = compile_body(body, allow_internal)?;
        out.push((e, a, p, nocase, offset.clone()));
    }
    if wide {
        match compile_wide(body, allow_internal) {
            Some((e, a, p)) => out.push((e, a, p, nocase, offset)),
            // A wide pattern we can't widen (non-literal): keep the ascii
            // variant if we made one, otherwise the subsig is unsupported.
            None if ascii => {}
            None => return None,
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Compile the wide (UTF-16LE) form of a hex body: each byte is interleaved
/// with `0x00`, wildcards each match one wide char, and gaps count wide chars.
pub(super) fn compile_wide(body: &str, allow_internal: bool) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = widen_elems(parse_elems(body)?);
    let prefix = pick_anchor(&elems, allow_internal)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. }
        | Prefix::Floating { anchor_idx }
        | Prefix::Internal { anchor_idx } => anchor_idx,
    };
    let anchor = match &elems[anchor_idx as usize] {
        Elem::Bytes(b) => b.clone(),
        _ => return None,
    };
    Some((elems, anchor, prefix))
}

/// Transform a token program into its UTF-16LE form.
pub(super) fn widen_elems(elems: Vec<Elem>) -> Vec<Elem> {
    fn widen_bytes(v: &[u8]) -> Vec<u8> {
        let mut w = Vec::with_capacity(v.len() * 2);
        for &b in v {
            w.push(b);
            w.push(0);
        }
        w
    }
    let mut out = Vec::with_capacity(elems.len());
    for e in elems {
        match e {
            Elem::Bytes(v) => out.push(Elem::Bytes(widen_bytes(&v))),
            Elem::AnyByte => {
                out.push(Elem::AnyByte);
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::HiNibble(h) => {
                out.push(Elem::HiNibble(h));
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::LoNibble(l) => {
                out.push(Elem::LoNibble(l));
                out.push(Elem::Bytes(vec![0]));
            }
            Elem::Gap { min, max } => out.push(Elem::Gap {
                min: min.saturating_mul(2),
                max: max.map(|m| m.saturating_mul(2)),
            }),
            Elem::Alt { opts, neg } => out.push(Elem::Alt {
                opts: opts.iter().map(|o| widen_bytes(o)).collect(),
                neg,
            }),
        }
    }
    out
}

/// Compile a hex body to (elements, anchor literal, prefix classification).
/// Returns `None` if it uses an unsupported construct or has no usable anchor.
pub(super) fn compile_body(hex: &str, allow_internal: bool) -> Option<(Vec<Elem>, Vec<u8>, Prefix)> {
    let elems = parse_elems(hex)?;
    let prefix = pick_anchor(&elems, allow_internal)?;
    let anchor_idx = match prefix {
        Prefix::Fixed { anchor_idx, .. }
        | Prefix::Floating { anchor_idx }
        | Prefix::Internal { anchor_idx } => anchor_idx,
    };
    let anchor = match &elems[anchor_idx as usize] {
        Elem::Bytes(b) => b.clone(),
        _ => return None,
    };
    Some((elems, anchor, prefix))
}

pub(super) fn parse_elems(hex: &str) -> Option<Vec<Elem>> {
    let bytes = hex.as_bytes();
    let mut i = 0;
    let mut elems: Vec<Elem> = Vec::new();
    let mut lit: Vec<u8> = Vec::new();
    macro_rules! flush {
        () => {
            if !lit.is_empty() {
                elems.push(Elem::Bytes(std::mem::take(&mut lit)));
            }
        };
    }
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => {
                i += 1;
            }
            b'*' => {
                flush!();
                elems.push(Elem::Gap { min: 0, max: None });
                i += 1;
            }
            b'{' => {
                flush!();
                let end = hex[i..].find('}')? + i;
                elems.push(parse_gap(&hex[i + 1..end])?);
                i = end + 1;
            }
            // `[n-m]` (or `[n]`) is a byte-range gap — same matching semantics
            // as `{n-m}`. It is used as an AC boundary (anchoring distance)
            // but for what actually matches it is just a variable gap.
            b'[' => {
                flush!();
                let end = hex[i..].find(']')? + i;
                elems.push(parse_gap(&hex[i + 1..end])?);
                i = end + 1;
            }
            b'!' if bytes.get(i + 1) == Some(&b'(') => {
                flush!();
                let end = hex[i..].find(')')? + i;
                let inner = &hex[i + 2..end];
                // ClamAV special character classes (negated):
                // !(B) = negated word boundary, !(L) = negated line boundary,
                // !(W) = negated non-alphanumeric word marker.
                // These are boundary markers, not hex alternations — skip them.
                if inner.len() == 1 && matches!(inner.as_bytes()[0], b'B' | b'L' | b'W') {
                    i = end + 1;
                    continue;
                }
                elems.push(parse_alt(inner, true)?);
                i = end + 1;
            }
            b'(' => {
                flush!();
                let end = hex[i..].find(')')? + i;
                let inner = &hex[i + 1..end];
                // ClamAV special character classes:
                // (B) = word boundary, (L) = CR/CRLF line boundary,
                // (W) = non-alphanumeric word marker.
                // These are boundary markers, not hex alternations — skip them.
                if inner.len() == 1 && matches!(inner.as_bytes()[0], b'B' | b'L' | b'W') {
                    i = end + 1;
                    continue;
                }
                elems.push(parse_alt(inner, false)?);
                i = end + 1;
            }
            _ => {
                // A nibble pair.
                let a = bytes[i];
                let b = *bytes.get(i + 1)?;
                let hi = nibble(a);
                let lo = nibble(b);
                match (a == b'?', b == b'?', hi, lo) {
                    (true, true, _, _) => {
                        flush!();
                        elems.push(Elem::AnyByte);
                    }
                    (false, true, Some(h), _) => {
                        flush!();
                        elems.push(Elem::HiNibble(h));
                    }
                    (true, false, _, Some(l)) => {
                        flush!();
                        elems.push(Elem::LoNibble(l));
                    }
                    (false, false, Some(h), Some(l)) => lit.push((h << 4) | l),
                    _ => return None,
                }
                i += 2;
            }
        }
    }
    flush!();
    if elems.is_empty() {
        None
    } else {
        Some(elems)
    }
}

pub(super) fn parse_gap(spec: &str) -> Option<Elem> {
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix('-') {
        Some(Elem::Gap {
            min: 0,
            max: Some(rest.trim().parse().ok()?),
        })
    } else if let Some(pre) = spec.strip_suffix('-') {
        Some(Elem::Gap {
            min: pre.trim().parse().ok()?,
            max: None,
        })
    } else if let Some((a, b)) = spec.split_once('-') {
        Some(Elem::Gap {
            min: a.trim().parse().ok()?,
            max: Some(b.trim().parse().ok()?),
        })
    } else {
        let n = spec.parse().ok()?;
        Some(Elem::Gap {
            min: n,
            max: Some(n),
        })
    }
}

pub(super) fn parse_alt(spec: &str, neg: bool) -> Option<Elem> {
    let mut opts = Vec::new();
    for part in spec.split('|') {
        opts.push(decode_plain_hex(part.trim())?);
    }
    if opts.is_empty() || opts.iter().any(|o| o.is_empty()) {
        return None;
    }
    if neg && !opts.iter().all(|o| o.len() == opts[0].len()) {
        return None; // negated alternates must be equal length
    }
    Some(Elem::Alt { opts, neg })
}

/// Choose the literal anchor and classify its prefix.
/// Selectivity score of a candidate anchor run. A low-entropy run (a constant
/// byte like a zero/0xFF pad, or a 2-symbol repeat) matches repetitive content
/// — PE padding, BSS — millions of times, so it is a terrible prefilter even
/// when long. Down-rank such runs sharply so a shorter but varied run wins; a
/// genuinely varied run scores its length (longer = rarer = better).
pub(super) fn anchor_score(b: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &x in b {
        if !seen[x as usize] {
            seen[x as usize] = true;
            distinct += 1;
        }
    }
    match distinct {
        0 | 1 => 1,          // constant run: near-useless anchor
        2 => 3.min(b.len()), // 2-symbol repeat (e.g. ababab): weak
        _ => b.len(),        // varied: length is the selectivity
    }
}

pub(super) fn pick_anchor(elems: &[Elem], allow_internal: bool) -> Option<Prefix> {
    // Pick the most *selective* literal run as the Aho-Corasick anchor (highest
    // [`anchor_score`], tie-break longer), not merely the longest: a long
    // constant run is a far worse prefilter than a shorter varied one. Fewer
    // spurious AC hits → fewer verifies, the dominant scan cost.
    //
    // The anchor in the *fixed-width prefix* (before the first variable gap) is
    // free to verify — its distance back to the pattern start (`len`) is exact.
    // But some patterns have only a useless literal there (a zero-run) while a
    // rare literal sits past a gap. For those, anchoring past the gap (`Internal`)
    // and verifying backward across it slashes AC hits by orders of magnitude.
    // We only take an internal anchor when it is *strictly more selective* than
    // the best fixed-prefix one and the pattern offset is `*` (so the floating
    // start need not satisfy a fixed offset) — passed via `allow_internal`.
    let mut fixed = 0usize;
    let mut in_fixed_prefix = true;
    // (score, len, prefix) for the best fixed-prefix candidate and the best
    // candidate anywhere.
    let mut best_fixed: Option<(usize, usize, Prefix)> = None;
    let mut best_any: Option<(usize, usize, usize)> = None; // (score, len, idx)
    for (i, e) in elems.iter().enumerate() {
        if let Elem::Bytes(b) = e {
            if b.len() >= MIN_ANCHOR {
                let score = anchor_score(b);
                let better = |cur: &Option<(usize, usize, Prefix)>| match cur {
                    Some((s, l, _)) => score > *s || (score == *s && b.len() > *l),
                    None => true,
                };
                if in_fixed_prefix && better(&best_fixed) {
                    best_fixed = Some((
                        score,
                        b.len(),
                        Prefix::Fixed {
                            anchor_idx: i as u32,
                            len: fixed as u32,
                        },
                    ));
                }
                let any_better = match &best_any {
                    Some((s, l, _)) => score > *s || (score == *s && b.len() > *l),
                    None => true,
                };
                if any_better {
                    best_any = Some((score, b.len(), i));
                }
            }
        }
        match e.width() {
            Some(w) => fixed = fixed.saturating_add(w),
            None => in_fixed_prefix = false, // past the first variable element
        }
    }
    // Prefer an internal anchor only when it beats the fixed-prefix one.
    if allow_internal {
        if let Some((any_score, _, idx)) = best_any {
            let fixed_score = best_fixed.as_ref().map(|(s, ..)| *s).unwrap_or(0);
            if any_score > fixed_score {
                // A single leading gap is the cheap `Floating` fast path, not the
                // general backward-matching `Internal`.
                if idx == 1 && matches!(elems.first(), Some(Elem::Gap { .. })) {
                    return Some(Prefix::Floating { anchor_idx: 1 });
                }
                if idx > 0 {
                    return Some(Prefix::Internal { anchor_idx: idx as u32 });
                }
            }
        }
    }
    if let Some((.., p)) = best_fixed {
        return Some(p);
    }
    // Floating: a single leading variable gap, then a usable literal.
    if matches!(elems.first(), Some(Elem::Gap { .. })) {
        if let Some(Elem::Bytes(b)) = elems.get(1) {
            if b.len() >= MIN_ANCHOR {
                return Some(Prefix::Floating { anchor_idx: 1 });
            }
        }
    }
    None
}

pub(super) fn parse_offset(s: &str) -> Option<Offset> {
    let s = s.trim();
    if s == "*" {
        return Some(Offset::Any);
    }
    let (spec, shift) = match s.split_once(',') {
        Some((a, b)) => (a.trim(), b.trim().parse().unwrap_or(0)),
        None => (s, 0),
    };
    let boxed = |k: OffsetKind| Offset::Constrained(Box::new(k));
    if let Some(rest) = spec.strip_prefix("EOF-") {
        Some(boxed(OffsetKind::Eof {
            n: rest.trim().parse().ok()?,
            shift,
        }))
    } else if let Some(rest) = spec.strip_prefix("EP") {
        Some(boxed(OffsetKind::Ep {
            delta: parse_delta(rest)?,
            shift,
        }))
    } else if let Some(rest) = spec.strip_prefix('S') {
        if let Some(d) = rest.strip_prefix('L') {
            Some(boxed(OffsetKind::SecLast {
                delta: parse_delta(d)?,
                shift,
            }))
        } else {
            // S<idx>[+/-delta]
            let cut = rest.find(['+', '-']).unwrap_or(rest.len());
            let idx: usize = rest[..cut].parse().ok()?;
            Some(boxed(OffsetKind::Sec {
                idx,
                delta: parse_delta(&rest[cut..])?,
                shift,
            }))
        }
    } else if let Ok(n) = spec.parse::<u64>() {
        Some(boxed(OffsetKind::Abs { n, shift }))
    } else {
        // VI, SEx, and other offset kinds are not yet supported.
        None
    }
}

/// Parse a signed delta like "", "+5", "-12".
pub(super) fn parse_delta(s: &str) -> Option<i64> {
    if s.is_empty() {
        Some(0)
    } else {
        s.parse().ok()
    }
}

/// A PUA (Potentially Unwanted Application) signature name. ClamAV gates these
/// behind `DetectPUA` (off by default); exav skips them to match that default.
pub(super) fn is_pua(name: &str) -> bool {
    name.starts_with("PUA.")
}

/// exav's reported ClamAV functionality level. Signatures carry an engine
/// `min-max` flevel window (LDB `Engine:` TDB, or trailing `:min:max` fields on
/// `.ndb` lines); ClamAV loads a sig only when its flevel falls in that window.
/// We match that with the flevel of the ClamAV release whose databases we read
/// (1.4.x ⇒ 213), so we load exactly the sigs ClamAV would — skipping ones meant
/// for a newer engine (features we may lack) and, importantly, *deprecated* ones
/// (`max < 213`) that ClamAV no longer runs, which would otherwise false-positive.
pub(crate) const EXAV_FLEVEL: u32 = 213;

/// Whether `EXAV_FLEVEL` falls within a sig's `[min, max]` engine window.
pub(crate) fn flevel_ok(min: u32, max: u32) -> bool {
    EXAV_FLEVEL >= min && EXAV_FLEVEL <= max
}

/// Parse an LDB `Engine:min-max` TDB attribute into `(min, max)`; absent or
/// unparseable ⇒ `(0, u32::MAX)` (no constraint).
pub(super) fn parse_tdb_engine(tdb: &str) -> (u32, u32) {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Engine:") {
            if let Some((a, b)) = v.trim().split_once('-') {
                return (
                    a.trim().parse().unwrap_or(0),
                    b.trim().parse().unwrap_or(u32::MAX),
                );
            }
        }
    }
    (0, u32::MAX)
}

pub(super) fn parse_tdb_target(tdb: &str) -> u8 {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("Target:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Parse a `FileSize:min-max` TDB attribute into an inclusive `(min, max)`
/// range. Accepts `n` (exact), `n-m`, `n-` (min only), and `-m` (max only).
/// Returns `None` if absent or unparseable (treated as "no constraint").
pub(super) fn parse_tdb_filesize(tdb: &str) -> Option<(u64, u64)> {
    for field in tdb.split(',') {
        if let Some(v) = field.trim().strip_prefix("FileSize:") {
            let v = v.trim();
            return match v.split_once('-') {
                Some((a, b)) => {
                    let min = a.trim().parse().unwrap_or(0);
                    let max = b.trim().parse().unwrap_or(u64::MAX);
                    Some((min, max))
                }
                None => v.parse().ok().map(|n| (n, n)),
            };
        }
    }
    None
}

pub(super) fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(super) fn decode_plain_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}
