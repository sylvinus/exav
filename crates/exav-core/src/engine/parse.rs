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
    /// `fuzzy_img#<hash>[#<dist>]`: the 8-byte perceptual hash and the max Hamming
    /// distance (0 when unspecified) at which the scanned image's hash matches.
    Fuzzy([u8; 8], u32),
}

/// Why [`classify_subsig`] rejected `s`. Used to attribute a skipped `.ldb`
/// signature to a concrete missing feature instead of an opaque counter.
pub(super) fn classify_failure_reason(s: &str) -> &'static str {
    // Attribution is a feature ("counted and attributable by cause"), so it has
    // to name the real cause. An earlier version guessed from punctuation and
    // called anything containing '(' a byte-compare subsignature — which
    // mislabelled every *alternation* as byte-compare, i.e. 6 of the 16 skipped
    // signatures in a live daily set were filed under the wrong missing feature.
    if s.starts_with("fuzzy_img#") {
        return "ldb: malformed fuzzy_img# subsignature";
    }
    // Byte-compare has the shape `N(offset#properties#value)`: a subsignature
    // reference, then a parenthesised triple separated by '#'.
    let byte_compare = s
        .split_once('(')
        .is_some_and(|(head, tail)| {
            !head.is_empty()
                && head.chars().all(|c| c.is_ascii_digit())
                && tail.matches('#').count() >= 2
        });
    if byte_compare {
        return "ldb: unsupported byte-compare subsignature";
    }
    if s.contains('/') {
        return "ldb: unsupported PCRE subsignature";
    }
    // `(a|b)` alternations, including the empty-branch form `(abc|)` that makes
    // a run optional, and branches that themselves contain nibble wildcards.
    if s.contains('(') && s.contains('|') {
        return "ldb: unsupported alternation in pattern body";
    }
    "ldb: subsignature body has no usable literal anchor"
}

/// Classify and parse one subsignature: byte-compare (`N(..#..#..)`), PCRE
/// (`Trigger/regex/flags`), or a normal hex/pattern body.
pub(super) fn classify_subsig(s: &str) -> Option<ParsedSub> {
    if let Some(rest) = s.strip_prefix("fuzzy_img#") {
        return parse_fuzzy_subsig(rest).map(|(h, d)| ParsedSub::Fuzzy(h, d));
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
/// `fuzzy_img#` prefix already stripped). Returns the 8-byte perceptual hash and
/// the max Hamming distance at which it matches — the optional `#distance` suffix,
/// defaulting to 0 (exact) when absent. A signature that specifies a tolerance is
/// honored (perceptual hashing is meant to match near-duplicates), where before
/// any non-zero distance dropped the whole signature.
pub(super) fn parse_fuzzy_subsig(rest: &str) -> Option<([u8; 8], u32)> {
    let mut parts = rest.split('#');
    let hash = parts.next()?;
    let dist = match parts.next() {
        Some(d) => d.trim().parse::<u32>().ok()?,
        None => 0,
    };
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
    Some((out, dist))
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
    // `[Offset:]Trigger/PCRE/Flags`. An offset prefix constrains where the match
    // may start; on a live `daily.cvd` 368 of the 369 that use one are `EOF-n`
    // (a trailing marker), so leaving it unparsed dropped those signatures.
    let head = &s[..first];
    let (offset, trigger_src) = match head.split_once(':') {
        Some((o, t)) => (parse_offset(o)?, t),
        None => (Offset::Any, head),
    };
    // Only offsets resolvable from the file length alone. `EP`/`Sx` need a PE
    // layout `PcreSub::is_match` does not carry, and matching one without it
    // would silently never fire — so it stays counted-unsupported instead.
    if !matches!(
        offset,
        Offset::Any | Offset::Constrained(_)
    ) || matches!(
        &offset,
        Offset::Constrained(k)
            if !matches!(k.as_ref(), OffsetKind::Abs { .. } | OffsetKind::Eof { .. })
    ) {
        return None;
    }
    let trigger = parse_expr(trigger_src)?;
    let pattern = &s[first + 1..last];
    if pattern.is_empty() {
        return None;
    }
    let flags = &s[last + 1..];
    Some(PcreSub {
        trigger,
        offset,
        pattern: pattern.to_string(),
        ci: flags.contains('i'),
        dotall: flags.contains('s'),
        multiline: flags.contains('m'),
        re: std::sync::OnceLock::new(),
        fancy: std::sync::OnceLock::new(),
        prefilter: std::sync::OnceLock::new(),
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
    } else {
        let n = off_s.strip_prefix("<<")?;
        (true, n)
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
    // `f` — fullword: the match must be bounded by non-alphanumeric bytes.
    // Carried through to the verifier rather than dropped; dropping it makes the
    // subsignature match as a plain substring, i.e. fire on strictly more than
    // its author asked for.
    let fullword = flags.contains('f');

    let allow_internal = matches!(offset, Offset::Any);
    let mut out = Vec::new();
    if ascii {
        let (e, a, p) = compile_body(body, allow_internal)?;
        out.push((e, a, p, nocase, offset.clone(), fullword));
    }
    if wide {
        match compile_wide(body, allow_internal) {
            Some((e, a, p)) => out.push((e, a, p, nocase, offset, fullword)),
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
            // Widening a masked branch interleaves a literal NUL after each
            // byte, and a NUL is fully known — mask 0xff.
            Elem::AltMasked { opts } => out.push(Elem::AltMasked {
                opts: opts
                    .iter()
                    .map(|o| {
                        let mut w = Vec::with_capacity(o.len() * 2);
                        for &(v, m) in o {
                            w.push((v, m));
                            w.push((0, 0xff));
                        }
                        w
                    })
                    .collect(),
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
    let parts: Vec<&str> = spec.split('|').map(str::trim).collect();
    if parts.is_empty() {
        return None;
    }
    // An empty branch means "or nothing": `(2d4120|)` makes the run optional.
    // The alternation is then variable-width, which the matchers already handle
    // for unequal-length branches — but a *negated* one has a single fixed width
    // by definition, so it cannot have one.
    if neg && parts.iter().any(|p| p.is_empty()) {
        return None;
    }

    // Fast path: every branch is plain hex, so branches stay literal byte
    // strings and keep their substring-search matching.
    if let Some(opts) = parts
        .iter()
        .map(|p| decode_plain_hex(p))
        .collect::<Option<Vec<_>>>()
    {
        if neg && !opts.iter().all(|o| o.len() == opts[0].len()) {
            return None; // negated alternates must be equal length
        }
        return Some(Elem::Alt { opts, neg });
    }

    // A branch carries nibble wildcards (`5?`, `?4`, `??`). Compile every branch
    // to `(value, mask)` pairs. Only for non-negated alternations: a negated
    // masked form does not appear in any database tracked here, and refusing it
    // keeps it counted rather than guessed at.
    if neg {
        return None;
    }
    let mut opts: Vec<Vec<(u8, u8)>> = Vec::with_capacity(parts.len());
    for part in &parts {
        opts.push(decode_masked_hex(part)?);
    }
    Some(Elem::AltMasked { opts })
}

/// Decode a hex run that may carry nibble wildcards into `(value, mask)` pairs:
/// `5?` is `(0x50, 0xf0)`, `?4` is `(0x04, 0x0f)`, `??` is `(0, 0)`. An empty
/// run decodes to an empty branch, which matches zero bytes.
fn decode_masked_hex(s: &str) -> Option<Vec<(u8, u8)>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        let (hi, lo) = (pair[0], pair[1]);
        let (hv, hm) = if hi == b'?' { (0, 0) } else { (nibble(hi)?, 0xf) };
        let (lv, lm) = if lo == b'?' { (0, 0) } else { (nibble(lo)?, 0xf) };
        out.push(((hv << 4) | lv, (hm << 4) | lm));
    }
    Some(out)
}

/// Choose the literal anchor and classify its prefix.
/// Selectivity score of a candidate anchor run. A low-entropy run (a constant
/// byte like a zero/0xFF pad, or a 2-symbol repeat) matches repetitive content
/// — PE padding, BSS — millions of times, so it is a terrible prefilter even
/// when long. Down-rank such runs sharply so a shorter but varied run wins; a
/// varied run scores its length (longer = rarer = better).
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
    if spec == "VI" {
        Some(boxed(OffsetKind::VersionInfo))
    } else if let Some(rest) = spec.strip_prefix("EOF-") {
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
        if let Some(n) = rest.strip_prefix('E') {
            // `SEn` — anywhere inside section n. No delta and no shift: the
            // whole section IS the window.
            Some(boxed(OffsetKind::SecIn {
                idx: n.trim().parse().ok()?,
            }))
        } else if let Some(d) = rest.strip_prefix('L') {
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
/// for a newer engine (features we may lack) and also *deprecated* ones
/// (`max < 213`) that ClamAV no longer runs, which would otherwise false-positive.
pub(crate) const EXAV_FLEVEL: u32 = 213;

/// Whether `EXAV_FLEVEL` falls within a sig's `[min, max]` engine window.
pub(crate) fn flevel_ok(min: u32, max: u32) -> bool {
    EXAV_FLEVEL >= min && EXAV_FLEVEL <= max
}

/// Parse an LDB `Engine:min-max` TDB attribute into `(min, max)`; absent or
/// unparseable ⇒ `(0, u32::MAX)` (no constraint).
/// The `TargetDescriptionBlock` attributes exav evaluates. Anything else in a
/// TDB means the signature carries a constraint this engine cannot apply.
pub(super) const TDB_IMPLEMENTED: &[&str] = &[
    "Target",
    "Engine",
    "FileSize",
    "Container",
    "IconGroup1",
    "IconGroup2",
    "EntryPoint",
    "NumberOfSections",
    "HandlerType",
    "Intermediates",
];

/// The nine section-range attributes. The format defines these names but no
/// engine has ever implemented them: they parse into fields nothing reads, and
/// a signature using one gets dropped at load. exav dropping it too is parity,
/// not a gap, and there are zero occurrences across the official and
/// third-party databases we track.
///
/// (Not to be confused with the `SEn:`/`Sn+n` *subsignature offset* modifiers,
/// which are a different, live feature handled by the offset parser.)
pub(super) const TDB_SECTION_ATTRS: &[&str] = &[
    "SectOff", "SectRVA", "SectVSZ", "SectRAW", "SectRSZ", "SectURVA", "SectUVSZ", "SectURAW",
    "SectURSZ",
];

/// The first TDB attribute present that exav cannot evaluate, if any.
///
/// This exists because the alternative is worse than a missing feature. TDB
/// parsing works by looking for the attributes we know, so an attribute we do
/// NOT know was simply never read — and its constraint silently vanished. A
/// signature restricted to `NumberOfSections:3` then fired on any section count,
/// matching more broadly than ClamAV would allow. That is a false positive
/// waiting to happen, and unlike a missing decoder it is invisible.
///
/// Reporting it turns a silent behavioural difference into a counted, named
/// skip — the same treatment every other unsupported construct gets.
///
/// An attribute name the format does not define at all — a typo, or one added
/// by a newer engine — is refused for the same reason, and no engine does
/// anything else with it either.
pub(super) fn unsupported_tdb_attr(tdb: &str) -> Option<&'static str> {
    for field in tdb.split(',') {
        let Some((key, _)) = field.trim().split_once(':') else {
            continue;
        };
        let key = key.trim();
        if TDB_IMPLEMENTED.contains(&key) {
            continue;
        }
        if let Some(known) = TDB_SECTION_ATTRS.iter().find(|k| **k == key) {
            return Some(known);
        }
        return Some("unknown");
    }
    None
}

/// State of one TDB range attribute (`FileSize`, `EntryPoint`,
/// `NumberOfSections`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum TdbRange {
    /// Attribute not present — no constraint.
    Absent,
    /// Present and well-formed; inclusive on both ends.
    Range(u64, u64),
    /// Present but not of the form `min-max` with digits-only sides. The
    /// signature is refused, because a constraint we cannot read is a
    /// constraint we would otherwise drop — and dropping it makes the signature
    /// fire more widely than intended.
    Malformed,
}

/// Parse an inclusive `Attr:min-max` TDB range as the format actually defines
/// one.
///
/// The hyphen is **mandatory** and the split happens at the first one; each side
/// must be digits or empty, and empty means zero. That last rule is the one
/// worth stating, because it is not what it looks like: `FileSize:100-` is not
/// an open-ended upper bound, it is the range 100..=0, which matches nothing.
/// Reading it as `100..=u64::MAX` — the intuitive interpretation, and the
/// tempting one — turns a signature that never fires into one that fires on
/// every file above 100 bytes. `-100` really is 0..=100.
///
/// A bare `Attr:100` with no hyphen is malformed and aborts the whole database
/// load elsewhere; exav refuses just the one signature, since taking down a
/// database file over one bad line helps nobody.
pub(super) fn parse_tdb_range(tdb: &str, attr: &str) -> TdbRange {
    let want = format!("{attr}:");
    for field in tdb.split(',') {
        let Some(v) = field.trim().strip_prefix(&want) else {
            continue;
        };
        let Some((a, b)) = v.split_once('-') else {
            return TdbRange::Malformed;
        };
        return match (digits_or_empty(a), digits_or_empty(b)) {
            (Some(min), Some(max)) => TdbRange::Range(min, max),
            _ => TdbRange::Malformed,
        };
    }
    TdbRange::Absent
}

/// A digits-only run as a number; the empty string is zero, per the format.
/// Whitespace, signs and hex prefixes are rejected.
fn digits_or_empty(s: &str) -> Option<u64> {
    if s.is_empty() {
        return Some(0);
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Saturate rather than fail — a bound that large is nonsense either way.
    Some(s.parse().unwrap_or(u64::MAX))
}

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
pub(super) fn parse_tdb_filesize(tdb: &str) -> TdbRange {
    parse_tdb_range(tdb, "FileSize")
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
