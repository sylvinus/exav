//! Clean-room JavaScript normalisation for signature matching.
//!
//! Traditional engines (ClamAV) scan `.yar`/`.ndb` JS signatures against a
//! *normalised* rendering of a script rather than its raw bytes, so a single
//! pattern matches regardless of the obfuscation used to evade it. This module
//! reproduces that behaviour **from the public description of the transforms**,
//! not by porting any GPL implementation. It performs the same *classes* of
//! static rewrite ClamAV's `js-norm` does (the output is not byte-identical):
//!
//! * tokenise, dropping comments and redundant whitespace;
//! * decode string-literal escapes (`\xHH`, `\uHHHH`, `\u{..}`, octal, `\n`…)
//!   and fold string concatenation (`"ab"+"cd"` → `"abcd"`);
//! * evaluate `String.fromCharCode(<literals>)` and `unescape("…%XX…")` /
//!   `decodeURIComponent(…)` whose argument is a literal;
//! * re-parse the argument of `eval("…")` as JavaScript (one static layer,
//!   depth-bounded), so `eval("un"+"escape(...)")`-style loaders unroll;
//! * canonicalise user identifiers to `n001`, `n002`… (keeping reserved words
//!   and common built-ins), and normalise integer literals to decimal.
//!
//! Decoded *string content* (URLs, command lines, API names passed as strings)
//! survives verbatim, which is where detection value comes from. This is a
//! purely static rewriter: it never executes code, so runtime-assembled payloads
//! (numeric-array VMs, dynamic dispatch) are intentionally out of scope.
//!
//! Not yet implemented (tracked in tmp/GAPS.md):
//! * **Microsoft Script Encoder** (`#@~^…^#~@`, JScript.Encode/VBScript.Encode)
//!   decoding — needs the exact published 119×3 translation + 64-entry pick
//!   tables; deferred rather than ship an unverified table (and near-absent in
//!   the current corpus).
//! * **base64→script rescan** — decoding long base64 runs to *script/text* (not
//!   just exec-magic payloads, which `exav-unpack::base64_payloads` already
//!   covers). The higher-yield lever per corpus evidence, but needs a distinct
//!   FP-safe gate (base64 text is ubiquitous and benign).
//!
//! Everything walks the input a bounded number of times and cannot panic on any
//! byte sequence.

/// Hard ceilings so a hostile script can't blow up time or memory. Output is
/// capped; `eval` re-parse recursion and total fold passes are bounded.
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_EVAL_DEPTH: u32 = 8;
const MAX_FOLD_PASSES: u32 = 24;

/// A single lexical token. Comments and whitespace are never emitted.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    /// Identifier or keyword (raw source bytes, case preserved).
    Ident(Vec<u8>),
    /// Decoded string-literal content (escapes resolved, quotes removed).
    Str(Vec<u8>),
    /// Numeric literal source text (normalised later).
    Num(Vec<u8>),
    /// A single punctuation / operator byte (multi-byte operators become a run).
    Punct(u8),
    /// A regex literal, emitted verbatim including delimiters.
    Regex(Vec<u8>),
}

/// Normalise a JavaScript/script buffer to its canonical form for matching.
pub fn normalize(data: &[u8]) -> Vec<u8> {
    let mut toks = tokenize(data);
    fold(&mut toks, 0);
    canonicalize_idents(&mut toks);
    emit(&toks)
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

/// Is `b` a JavaScript identifier byte (letters, digits, `_`, `$`, or high bit
/// for the common non-ASCII-identifier case)?
#[inline]
fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

#[inline]
fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80
}

/// Split `data` into tokens, decoding string escapes and dropping comments and
/// whitespace. A `/` is a regex when it appears where a value is expected,
/// otherwise a comment (`//`, `/*`) or the division operator.
fn tokenize(data: &[u8]) -> Vec<Tok> {
    let mut out = Vec::new();
    let n = data.len();
    let mut i = 0usize;
    // "Value expected" position: at the start, or right after an operator /
    // opening bracket / keyword — a `/` here begins a regex, not division.
    let mut value_pos = true;
    while i < n {
        let b = data[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x0b => {
                i += 1;
            }
            b'/' if i + 1 < n && data[i + 1] == b'/' => {
                i += 2;
                while i < n && data[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < n && data[i + 1] == b'*' => {
                i += 2;
                while i + 1 < n && !(data[i] == b'*' && data[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
            }
            b'/' if value_pos => {
                let (re, ni) = read_regex(data, i);
                out.push(Tok::Regex(re));
                i = ni;
                value_pos = false;
            }
            b'\'' | b'"' | b'`' => {
                let (s, ni) = read_string(data, i, b);
                out.push(Tok::Str(s));
                i = ni;
                value_pos = false;
            }
            b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < n
                    && (data[i].is_ascii_alphanumeric()
                        || data[i] == b'.'
                        || data[i] == b'_'
                        || ((data[i] == b'+' || data[i] == b'-')
                            && matches!(data[i - 1], b'e' | b'E')))
                {
                    i += 1;
                }
                out.push(Tok::Num(data[start..i].to_vec()));
                value_pos = false;
            }
            b'.' if i + 1 < n && data[i + 1].is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < n && (data[i].is_ascii_digit() || matches!(data[i], b'e' | b'E' | b'+' | b'-')) {
                    i += 1;
                }
                out.push(Tok::Num(data[start..i].to_vec()));
                value_pos = false;
            }
            _ if is_ident_start(b) => {
                let start = i;
                i += 1;
                while i < n && is_ident(data[i]) {
                    i += 1;
                }
                out.push(Tok::Ident(data[start..i].to_vec()));
                // After an identifier that is a keyword, a value follows.
                value_pos = ident_is_keyword(&data[start..i]);
            }
            _ => {
                out.push(Tok::Punct(b));
                // After most punctuation a value is expected; after `)` `]` a
                // division/regex ambiguity resolves to division.
                value_pos = !matches!(b, b')' | b']');
                i += 1;
            }
        }
    }
    out
}

/// Read a string literal starting at the opening quote `data[i] == quote`.
/// Returns the decoded content (without quotes) and the index past the closer.
fn read_string(data: &[u8], mut i: usize, quote: u8) -> (Vec<u8>, usize) {
    let n = data.len();
    let mut s = Vec::new();
    i += 1; // skip opening quote
    while i < n {
        let b = data[i];
        if b == quote {
            i += 1;
            break;
        }
        if b == b'\\' && i + 1 < n {
            let (bytes, ni) = decode_escape(data, i + 1);
            s.extend_from_slice(&bytes);
            i = ni;
            continue;
        }
        // Unescaped newline terminates a normal string; be lenient and stop.
        if (b == b'\n' || b == b'\r') && quote != b'`' {
            break;
        }
        s.push(b);
        i += 1;
    }
    (s, i)
}

/// Decode one backslash escape whose body starts at `i` (the char after `\`).
/// Returns the decoded bytes and the index past the escape.
fn decode_escape(data: &[u8], i: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    if i >= n {
        return (vec![b'\\'], i);
    }
    match data[i] {
        b'x' if i + 2 < n => {
            if let Some(v) = hex2(data[i + 1], data[i + 2]) {
                return (vec![v], i + 3);
            }
            (vec![data[i]], i + 1)
        }
        b'u' => {
            if i + 1 < n && data[i + 1] == b'{' {
                // \u{HHHHHH}
                let mut j = i + 2;
                let mut cp: u32 = 0;
                let mut any = false;
                while j < n && data[j] != b'}' {
                    let Some(d) = (data[j] as char).to_digit(16) else { break };
                    cp = cp.saturating_mul(16).saturating_add(d);
                    any = true;
                    j += 1;
                }
                if any && j < n && data[j] == b'}' {
                    return (encode_cp(cp), j + 1);
                }
                (vec![b'u'], i + 1)
            } else if i + 4 < n {
                let mut cp: u32 = 0;
                for k in 1..=4 {
                    let Some(d) = (data[i + k] as char).to_digit(16) else {
                        return (vec![b'u'], i + 1);
                    };
                    cp = cp * 16 + d;
                }
                (encode_cp(cp), i + 5)
            } else {
                (vec![b'u'], i + 1)
            }
        }
        b'0'..=b'7' => {
            // Octal escape, up to 3 digits.
            let mut j = i;
            let mut v: u32 = 0;
            while j < n && j < i + 3 && (b'0'..=b'7').contains(&data[j]) {
                v = v * 8 + (data[j] - b'0') as u32;
                j += 1;
            }
            (vec![(v & 0xFF) as u8], j)
        }
        b'n' => (vec![b'\n'], i + 1),
        b't' => (vec![b'\t'], i + 1),
        b'r' => (vec![b'\r'], i + 1),
        b'b' => (vec![0x08], i + 1),
        b'f' => (vec![0x0c], i + 1),
        b'v' => (vec![0x0b], i + 1),
        b'\n' => (vec![], i + 1),               // line continuation
        b'\r' if i + 1 < n && data[i + 1] == b'\n' => (vec![], i + 2),
        b'\r' => (vec![], i + 1),
        other => (vec![other], i + 1),          // \" \\ \/ \' → literal char
    }
}

/// Encode a Unicode code point as UTF-8 (lossless for matching); code points
/// ≤ 0xFF stay a single byte so `\x`/`\u00XX`/entities agree.
fn encode_cp(cp: u32) -> Vec<u8> {
    // ≤ 0xFF is deliberately a raw byte, not UTF-8: `\xE9`, `é` and `&eacute;`
    // must normalize to the same single byte for a signature to match all three.
    if cp <= 0xFF {
        vec![cp as u8]
    } else if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        c.encode_utf8(&mut buf).as_bytes().to_vec()
    } else {
        vec![(cp & 0xFF) as u8]
    }
}

#[inline]
fn hex2(a: u8, b: u8) -> Option<u8> {
    let hi = (a as char).to_digit(16)?;
    let lo = (b as char).to_digit(16)?;
    Some((hi * 16 + lo) as u8)
}

/// Read a regex literal `/.../flags` starting at `data[i] == '/'`.
fn read_regex(data: &[u8], mut i: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    let start = i;
    i += 1; // opening /
    let mut in_class = false;
    while i < n {
        match data[i] {
            b'\\' if i + 1 < n => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                break;
            }
            b'\n' => break, // unterminated
            _ => i += 1,
        }
    }
    while i < n && data[i].is_ascii_alphabetic() {
        i += 1; // flags
    }
    (data[start..i].to_vec(), i)
}

// ---------------------------------------------------------------------------
// Constant folding + eval unrolling
// ---------------------------------------------------------------------------

/// Repeatedly apply string-concatenation folding, `fromCharCode`/`unescape`
/// evaluation and `eval("…")` re-parsing until a fixpoint (bounded).
fn fold(toks: &mut Vec<Tok>, depth: u32) {
    let mut pass = 0;
    loop {
        let mut changed = false;
        changed |= fold_concat(toks);
        changed |= fold_calls(toks, depth);
        pass += 1;
        if !changed || pass >= MAX_FOLD_PASSES {
            break;
        }
    }
}

/// Merge `Str + Str` (with an optional `+` between them) into one `Str`.
fn fold_concat(toks: &mut Vec<Tok>) -> bool {
    let mut out: Vec<Tok> = Vec::with_capacity(toks.len());
    let mut changed = false;
    let mut i = 0;
    while i < toks.len() {
        if let Tok::Str(a) = &toks[i] {
            // Look for `"a" + "b"` (allowing the `+`), collapsing a whole chain.
            let mut merged = a.clone();
            let mut j = i + 1;
            let mut consumed = false;
            loop {
                // optional '+'
                let mut k = j;
                if matches!(toks.get(k), Some(Tok::Punct(b'+'))) {
                    k += 1;
                }
                if let Some(Tok::Str(b)) = toks.get(k) {
                    merged.extend_from_slice(b);
                    j = k + 1;
                    consumed = true;
                    changed = true;
                } else {
                    break;
                }
            }
            if consumed {
                out.push(Tok::Str(merged));
                i = j;
                continue;
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    if changed {
        *toks = out;
    }
    changed
}

/// Evaluate call-shaped patterns: `String.fromCharCode(n,…)`, `fromCharCode(n,…)`,
/// `unescape("…")`, `decodeURIComponent("…")`, and re-parse `eval("…")`.
fn fold_calls(toks: &mut Vec<Tok>, depth: u32) -> bool {
    let mut out: Vec<Tok> = Vec::with_capacity(toks.len());
    let mut changed = false;
    let mut i = 0;
    while i < toks.len() {
        // Identify a callee identifier, possibly `String.fromCharCode`.
        if let Tok::Ident(name) = &toks[i] {
            let lname = name.to_ascii_lowercase();
            // Resolve `String . fromCharCode` to the method name.
            let (callee, after_name) = if lname == b"string"
                && matches!(toks.get(i + 1), Some(Tok::Punct(b'.')))
                && matches!(toks.get(i + 2), Some(Tok::Ident(m)) if m.eq_ignore_ascii_case(b"fromcharcode"))
            {
                (b"fromcharcode".to_vec(), i + 3)
            } else {
                (lname.clone(), i + 1)
            };
            if matches!(toks.get(after_name), Some(Tok::Punct(b'('))) {
                if let Some((args_end, replacement)) =
                    eval_call(&callee, toks, after_name, depth)
                {
                    out.extend(replacement);
                    i = args_end;
                    changed = true;
                    continue;
                }
            }
        }
        out.push(toks[i].clone());
        i += 1;
    }
    if changed {
        *toks = out;
    }
    changed
}

/// Try to evaluate one known call whose `(` is at `toks[lparen]`. Returns the
/// index just past the matching `)` and the token(s) to replace the call with.
fn eval_call(callee: &[u8], toks: &[Tok], lparen: usize, depth: u32) -> Option<(usize, Vec<Tok>)> {
    match callee {
        b"fromcharcode" => {
            // Args must be a comma-separated list of numeric literals.
            let mut bytes = Vec::new();
            let mut k = lparen + 1;
            loop {
                match toks.get(k) {
                    Some(Tok::Num(num)) => {
                        let cp = parse_int(num)?;
                        bytes.extend_from_slice(&encode_cp(cp));
                        k += 1;
                    }
                    _ => return None,
                }
                match toks.get(k) {
                    Some(Tok::Punct(b',')) => k += 1,
                    Some(Tok::Punct(b')')) => {
                        return Some((k + 1, vec![Tok::Str(bytes)]));
                    }
                    _ => return None,
                }
            }
        }
        b"unescape" | b"decodeuricomponent" | b"decodeuri" => {
            if let (Some(Tok::Str(s)), Some(Tok::Punct(b')'))) =
                (toks.get(lparen + 1), toks.get(lparen + 2))
            {
                return Some((lparen + 3, vec![Tok::Str(percent_decode(s))]));
            }
            None
        }
        b"eval" => {
            if depth >= MAX_EVAL_DEPTH {
                return None;
            }
            if let (Some(Tok::Str(s)), Some(Tok::Punct(b')'))) =
                (toks.get(lparen + 1), toks.get(lparen + 2))
            {
                // Re-parse the string as JavaScript and fold it recursively.
                let mut inner = tokenize(s);
                fold(&mut inner, depth + 1);
                return Some((lparen + 3, inner));
            }
            None
        }
        _ => None,
    }
}

/// Decode `%XX` and `%uXXXX` escapes (as `unescape` does); other bytes verbatim.
fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let n = s.len();
    let mut i = 0;
    while i < n {
        if s[i] == b'%' && i + 1 < n && (s[i + 1] == b'u' || s[i + 1] == b'U') && i + 5 < n {
            let mut cp: u32 = 0;
            let mut ok = true;
            for k in 2..6 {
                match (s[i + k] as char).to_digit(16) {
                    Some(d) => cp = cp * 16 + d,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                out.extend_from_slice(&encode_cp(cp));
                i += 6;
                continue;
            }
        }
        if s[i] == b'%' && i + 2 < n {
            if let Some(v) = hex2(s[i + 1], s[i + 2]) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Parse an integer literal (decimal, `0x`, `0o`, `0b`, legacy octal) to its
/// value. Returns `None` for floats / malformed input.
fn parse_int(num: &[u8]) -> Option<u32> {
    let s: Vec<u8> = num.iter().copied().filter(|&b| b != b'_').collect();
    if s.is_empty() {
        return None;
    }
    let (radix, digits): (u32, &[u8]) = if s.len() >= 2 && s[0] == b'0' {
        match s[1] {
            b'x' | b'X' => (16, &s[2..]),
            b'o' | b'O' => (8, &s[2..]),
            b'b' | b'B' => (2, &s[2..]),
            _ => (10, &s[..]),
        }
    } else {
        (10, &s[..])
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &d in digits {
        let dv = (d as char).to_digit(radix)?;
        v = v.checked_mul(radix)?.checked_add(dv)?;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// Identifier canonicalisation + emission
// ---------------------------------------------------------------------------

/// Rename user identifiers to `n001`, `n002`… keeping reserved words and common
/// built-ins so signatures that reference them (and decoded string content)
/// still match.
fn canonicalize_idents(toks: &mut [Tok]) {
    use std::collections::HashMap;
    let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut counter: u32 = 0;
    for t in toks.iter_mut() {
        if let Tok::Ident(name) = t {
            let lname = name.to_ascii_lowercase();
            if ident_is_keyword(name) || KEEP_IDENTS.contains(&lname.as_slice()) {
                continue;
            }
            let canon = map.entry(name.clone()).or_insert_with(|| {
                counter += 1;
                format!("n{counter:03}").into_bytes()
            });
            *name = canon.clone();
        }
    }
}

/// Emit the token stream. A single space separates two tokens only when their
/// touching characters would otherwise merge (two identifier/number chars).
fn emit(toks: &[Tok]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in toks {
        if out.len() >= MAX_OUTPUT {
            break;
        }
        let piece: Vec<u8> = match t {
            Tok::Ident(s) => s.clone(),
            Tok::Num(s) => normalize_num(s),
            Tok::Str(s) => {
                let mut v = Vec::with_capacity(s.len() + 2);
                v.push(b'"');
                v.extend_from_slice(s);
                v.push(b'"');
                v
            }
            Tok::Regex(s) => s.clone(),
            Tok::Punct(b) => vec![*b],
        };
        if let (Some(&last), Some(&first)) = (out.last(), piece.first()) {
            if is_ident(last) && is_ident(first) {
                out.push(b' ');
            }
        }
        out.extend_from_slice(&piece);
    }
    out.truncate(MAX_OUTPUT);
    out
}

/// Render an integer literal as decimal; leave floats/malformed text as-is.
fn normalize_num(num: &[u8]) -> Vec<u8> {
    match parse_int(num) {
        Some(v) => v.to_string().into_bytes(),
        None => num.to_vec(),
    }
}

/// JavaScript reserved words and control keywords — never renamed, and a value
/// is expected right after them (regex disambiguation).
fn ident_is_keyword(name: &[u8]) -> bool {
    let l = name.to_ascii_lowercase();
    matches!(
        l.as_slice(),
        b"var" | b"let" | b"const" | b"function" | b"return" | b"if" | b"else"
            | b"for" | b"while" | b"do" | b"switch" | b"case" | b"default"
            | b"break" | b"continue" | b"new" | b"delete" | b"typeof" | b"instanceof"
            | b"in" | b"of" | b"void" | b"this" | b"throw" | b"try" | b"catch"
            | b"finally" | b"with" | b"yield" | b"await" | b"async" | b"class"
            | b"extends" | b"super" | b"import" | b"export" | b"true" | b"false"
            | b"null" | b"undefined"
    )
}

/// Common built-in / global identifiers kept un-renamed so signatures that key
/// on them still match the normalised stream (lower-cased comparison).
const KEEP_IDENTS: &[&[u8]] = &[
    b"eval",
    b"unescape",
    b"escape",
    b"decodeuricomponent",
    b"decodeuri",
    b"encodeuricomponent",
    b"string",
    b"fromcharcode",
    b"charcodeat",
    b"array",
    b"object",
    b"function",
    b"math",
    b"number",
    b"parseint",
    b"parsefloat",
    b"replace",
    b"split",
    b"join",
    b"concat",
    b"substr",
    b"substring",
    b"slice",
    b"charat",
    b"indexof",
    b"tostring",
    b"document",
    b"window",
    b"location",
    b"navigator",
    b"activexobject",
    b"wscript",
    b"shell",
    b"createobject",
    b"wshshell",
    b"scripting",
    b"filesystemobject",
    b"xmlhttp",
    b"msxml2",
    b"adodb",
    b"stream",
    b"run",
    b"exec",
    b"powershell",
    b"cmd",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &[u8]) -> String {
        String::from_utf8_lossy(&normalize(s)).into_owned()
    }

    #[test]
    fn decodes_string_escapes() {
        // \x68\x69 → "hi"; A → "A"; octal \101 → "A".
        let out = norm(br#"var a = "\x68\x69A\101";"#);
        assert!(out.contains("\"hiAA\""), "got: {out}");
    }

    #[test]
    fn folds_concatenation() {
        let out = norm(br#"x = "ev"+"i"+'l';"#);
        assert!(out.contains("\"evil\""), "got: {out}");
    }

    #[test]
    fn evaluates_fromcharcode() {
        let out = norm(b"y = String.fromCharCode(104,116,116,112);");
        assert!(out.contains("\"http\""), "got: {out}");
        let bare = norm(b"y = fromCharCode(0x41,0x42);");
        assert!(bare.contains("\"AB\""), "got: {bare}");
    }

    #[test]
    fn decodes_unescape() {
        let out = norm(br#"z = unescape("%68%74%74%70%3a%2f%2f");"#);
        assert!(out.contains("\"http://\""), "got: {out}");
        let u = norm(br#"z = unescape("%u0041%u0042");"#);
        assert!(u.contains("\"AB\""), "got: {u}");
    }

    #[test]
    fn reparses_eval_of_concatenation() {
        // eval("un"+"escape(\"%41\")") → unescape("%41") → "A".
        let out = norm(br#"eval("unescape("+"'%41')");"#);
        assert!(out.contains("\"A\""), "eval not unrolled: {out}");
    }

    #[test]
    fn canonicalizes_user_identifiers_but_keeps_builtins() {
        let out = norm(b"var secretName = eval; secretName(payload);");
        // user idents renamed; `eval`/`var` preserved.
        assert!(out.contains("var n001"), "ident not canonicalised: {out}");
        assert!(out.contains("eval"), "builtin renamed: {out}");
        assert!(!out.contains("secretname") && !out.contains("secretName"), "got: {out}");
        // The same original name maps to the same canonical name.
        assert_eq!(out.matches("n001").count(), 2, "unstable mapping: {out}");
    }

    #[test]
    fn normalizes_integer_literals() {
        let out = norm(b"a=0x10; b=0o17; c=255;");
        assert!(out.contains("16") && out.contains("15") && out.contains("255"), "got: {out}");
    }

    #[test]
    fn comment_between_tokens_does_not_separate() {
        // A comment between a (kept) identifier and `(` must not leave a gap.
        let out = norm(b"run/* x */(1)");
        assert!(out.contains("run("), "comment left a gap: {out}");
        // And a comment inside a decode call still decodes the literal argument.
        let d = norm(br#"x = unescape/* c */("%41");"#);
        assert!(d.contains("\"A\""), "got: {d}");
    }

    #[test]
    fn eval_of_decoded_string_unrolls_to_code() {
        // eval(unescape("%41")) → eval("A") → the *code* `A` (canonicalised),
        // i.e. the eval layer is consumed, not left as a literal.
        let out = norm(br#"eval(unescape("%41"))"#);
        assert!(!out.contains("eval("), "eval not unrolled: {out}");
    }

    #[test]
    fn strings_keep_comment_markers_and_regex_survives() {
        let out = norm(br#"var u = "/*keep*/"; var re = /ab\/cd/g;"#);
        assert!(out.contains("/*keep*/"), "string content lost: {out}");
        assert!(out.contains("/ab\\/cd/g"), "regex lost: {out}");
    }

    #[test]
    fn no_panic_on_hostile_input() {
        for bad in [
            &b"eval(\"\\"[..],
            &b"'unterminated"[..],
            &b"String.fromCharCode("[..],
            &b"/regex-no-close"[..],
            &b"\\x\\u\\"[..],
            &[0u8, 1, 2, 3, 0xff, 0xfe][..],
        ] {
            let _ = normalize(bad); // must not panic
        }
    }
}
