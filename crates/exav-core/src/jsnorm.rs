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
//! * re-parse the argument of `eval("…")` as JavaScript (depth-bounded), so
//!   `eval("un"+"escape(...)")`-style loaders unroll;
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
//! The script is read in one pass. Each rewrite is a reduction at the point a
//! token arrives: a string joins the string before it, and a call is replaced
//! when its `)` closes it. Only what can still change is held back: the last
//! few tokens, and the calls still open whose argument can still take the form
//! the call needs. Everything else is renamed and written out as it settles.
//! Memory is therefore the output, one entry per identifier renamed, and the
//! open calls, not the whole script. Nothing here can panic on any byte
//! sequence.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::byte_source::{ByteSource, Bytes, Stepper};

/// Hard ceilings so a hostile script can't blow up time or memory.
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
/// `eval` layers unrolled, counted from the script itself. Each layer re-reads
/// text that the layer above held as a string, so the work is at most this
/// many times the input.
const MAX_EVAL_DEPTH: u32 = 32;
/// Calls open inside one another at once. Past it the outermost is left as
/// written, so the tokens held back stay bounded.
const MAX_OPEN_CALLS: usize = 256;
/// Tokens held back when no call is open: a `String . fromCharCode` callee and
/// the `"…" +` before it are the furthest a later reduction looks back.
const KEEP_BEHIND: usize = 6;
/// Settled tokens are written out in batches of at least this many.
const FLUSH_BATCH: usize = 1024;

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
/// The flag is true when the output was cut at [`MAX_OUTPUT`].
pub fn normalize(data: &[u8]) -> (Vec<u8>, bool) {
    run(Text::Mem(Cow::Borrowed(data))).finish()
}

/// [`normalize`] over a script that need not be held in memory.
pub(crate) fn normalize_source(src: &dyn ByteSource) -> (Vec<u8>, bool) {
    match src.as_slice() {
        Some(data) => normalize(data),
        None => run(Text::Source(Stepper::new(src))).finish(),
    }
}

/// Read all of `data` through the normaliser, leaving the end unwritten.
fn run(data: Text) -> Normalizer {
    let mut n = Normalizer::default();
    // The script, and above it the text of each `eval` being unrolled.
    let mut sources = vec![Lexer::new(data, 0)];
    while let Some(src) = sources.last_mut() {
        if n.out.cut {
            break;
        }
        let depth = src.depth;
        match src.next() {
            Some(tok) => {
                if let Some(inner) = n.push(Held { tok, depth }) {
                    sources.push(inner);
                }
            }
            None => {
                sources.pop();
            }
        }
    }
    n
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

/// Splits text into tokens, decoding string escapes and dropping comments and
/// whitespace. A `/` is a regex when it appears where a value is expected,
/// otherwise a comment (`//`, `/*`) or the division operator.
struct Lexer<'a> {
    data: Text<'a>,
    i: usize,
    /// "Value expected" position: at the start, or right after an operator /
    /// opening bracket / keyword: a `/` here begins a regex, not division.
    value_pos: bool,
    /// How many `eval` layers this text is inside.
    depth: u32,
}

/// Text a lexer reads: the script, held in memory or read from its source,
/// or the decoded text of an `eval`.
enum Text<'a> {
    Mem(Cow<'a, [u8]>),
    Source(Stepper<'a>),
}

impl Bytes for Text<'_> {
    fn len(&self) -> usize {
        match self {
            Text::Mem(d) => d.len(),
            Text::Source(s) => s.len(),
        }
    }

    #[inline]
    fn at(&mut self, i: usize) -> u8 {
        match self {
            Text::Mem(d) => d[i],
            Text::Source(s) => s.at(i),
        }
    }

    fn range(&mut self, from: usize, to: usize) -> Cow<'_, [u8]> {
        match self {
            Text::Mem(d) => {
                let to = to.min(d.len());
                Cow::Borrowed(&d[from.min(to)..to])
            }
            Text::Source(s) => s.range(from, to),
        }
    }
}

impl<'a> Lexer<'a> {
    fn new(data: Text<'a>, depth: u32) -> Self {
        Lexer {
            data,
            i: 0,
            value_pos: true,
            depth,
        }
    }

    fn next(&mut self) -> Option<Tok> {
        let data = &mut self.data;
        let n = data.len();
        let mut i = self.i;
        while i < n {
            let b = data.at(i);
            match b {
                b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x0b => {
                    i += 1;
                }
                b'/' if i + 1 < n && data.at(i + 1) == b'/' => {
                    i += 2;
                    while i < n && data.at(i) != b'\n' {
                        i += 1;
                    }
                }
                b'/' if i + 1 < n && data.at(i + 1) == b'*' => {
                    i += 2;
                    while i + 1 < n && !(data.at(i) == b'*' && data.at(i + 1) == b'/') {
                        i += 1;
                    }
                    i = (i + 2).min(n);
                }
                b'/' if self.value_pos => {
                    let (re, ni) = read_regex(data, i);
                    self.i = ni;
                    self.value_pos = false;
                    return Some(Tok::Regex(re));
                }
                b'\'' | b'"' | b'`' => {
                    let (s, ni) = read_string(data, i, b);
                    self.i = ni;
                    self.value_pos = false;
                    return Some(Tok::Str(s));
                }
                b'0'..=b'9' => {
                    let start = i;
                    i += 1;
                    while i < n && {
                        let c = data.at(i);
                        c.is_ascii_alphanumeric()
                            || c == b'.'
                            || c == b'_'
                            || ((c == b'+' || c == b'-') && matches!(data.at(i - 1), b'e' | b'E'))
                    } {
                        i += 1;
                    }
                    self.i = i;
                    self.value_pos = false;
                    return Some(Tok::Num(data.range(start, i).into_owned()));
                }
                b'.' if i + 1 < n && data.at(i + 1).is_ascii_digit() => {
                    let start = i;
                    i += 1;
                    while i < n && {
                        let c = data.at(i);
                        c.is_ascii_digit() || matches!(c, b'e' | b'E' | b'+' | b'-')
                    } {
                        i += 1;
                    }
                    self.i = i;
                    self.value_pos = false;
                    return Some(Tok::Num(data.range(start, i).into_owned()));
                }
                _ if is_ident_start(b) => {
                    let start = i;
                    i += 1;
                    while i < n && is_ident(data.at(i)) {
                        i += 1;
                    }
                    self.i = i;
                    let ident = data.range(start, i).into_owned();
                    // After an identifier that is a keyword, a value follows.
                    self.value_pos = ident_is_keyword(&ident);
                    return Some(Tok::Ident(ident));
                }
                _ => {
                    self.i = i + 1;
                    // After most punctuation a value is expected; after `)` `]` a
                    // division/regex ambiguity resolves to division.
                    self.value_pos = !matches!(b, b')' | b']');
                    return Some(Tok::Punct(b));
                }
            }
        }
        self.i = i;
        None
    }
}

/// Read a string literal starting at the opening quote `data[i] == quote`.
/// Returns the decoded content (without quotes) and the index past the closer.
fn read_string<B: Bytes>(data: &mut B, mut i: usize, quote: u8) -> (Vec<u8>, usize) {
    let n = data.len();
    let mut s = Vec::new();
    i += 1; // skip opening quote
    while i < n {
        let b = data.at(i);
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
fn decode_escape<B: Bytes>(data: &mut B, i: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    if i >= n {
        return (vec![b'\\'], i);
    }
    match data.at(i) {
        b'x' if i + 2 < n => {
            if let Some(v) = hex2(data.at(i + 1), data.at(i + 2)) {
                return (vec![v], i + 3);
            }
            (vec![b'x'], i + 1)
        }
        b'u' => {
            if i + 1 < n && data.at(i + 1) == b'{' {
                // \u{HHHHHH}
                let mut j = i + 2;
                let mut cp: u32 = 0;
                let mut any = false;
                while j < n && data.at(j) != b'}' {
                    let Some(d) = (data.at(j) as char).to_digit(16) else { break };
                    cp = cp.saturating_mul(16).saturating_add(d);
                    any = true;
                    j += 1;
                }
                if any && j < n && data.at(j) == b'}' {
                    return (encode_cp(cp), j + 1);
                }
                (vec![b'u'], i + 1)
            } else if i + 4 < n {
                let mut cp: u32 = 0;
                for k in 1..=4 {
                    let Some(d) = (data.at(i + k) as char).to_digit(16) else {
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
            while j < n && j < i + 3 && (b'0'..=b'7').contains(&data.at(j)) {
                v = v * 8 + (data.at(j) - b'0') as u32;
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
        b'\r' if i + 1 < n && data.at(i + 1) == b'\n' => (vec![], i + 2),
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
fn read_regex<B: Bytes>(data: &mut B, mut i: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    let start = i;
    i += 1; // opening /
    let mut in_class = false;
    while i < n {
        match data.at(i) {
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
    while i < n && data.at(i).is_ascii_alphabetic() {
        i += 1; // flags
    }
    (data.range(start, i).into_owned(), i)
}

// ---------------------------------------------------------------------------
// Constant folding + eval unrolling
// ---------------------------------------------------------------------------

/// A token not yet written out, with the `eval` depth of the text it came from.
struct Held {
    tok: Tok,
    depth: u32,
}

/// What an open call is waiting for.
enum Kind {
    /// `unescape`, `decodeURI`, `decodeURIComponent`: one string.
    Decode,
    /// `eval`: one string, read again as code.
    Eval,
    /// `fromCharCode` / `String.fromCharCode`: integers, held as their values
    /// rather than as tokens. `want_num` is true at the start and after a `,`.
    FromCharCode { values: Vec<u32>, want_num: bool },
}

/// A call whose `(` has been read and whose `)` has not, and that can still
/// be replaced by its value.
struct Call {
    kind: Kind,
    /// Index in `Normalizer::held` of the callee's first token.
    start: usize,
    /// Index of the `(`. The argument is what is held after it.
    open: usize,
    /// `eval` depth of the callee.
    depth: u32,
}

/// Reduces the token stream as it arrives. `held` is the tail that can still
/// change; `calls` are the open calls in it, outermost first, each inside the
/// argument of the one before.
#[derive(Default)]
struct Normalizer {
    held: Vec<Held>,
    calls: Vec<Call>,
    out: Emitter,
    /// Most tokens held at once.
    #[cfg(test)]
    peak_held: usize,
}

impl Normalizer {
    /// Take one token. Returns the text of an `eval` just reduced, to be read
    /// before the rest of the current text.
    fn push(&mut self, h: Held) -> Option<Lexer<'static>> {
        let inner = match h.tok {
            Tok::Punct(b'(') => {
                self.open(h);
                None
            }
            Tok::Punct(b')') if !self.calls.is_empty() => self.close(h),
            _ => {
                self.take(h);
                None
            }
        };
        #[cfg(test)]
        {
            self.peak_held = self.peak_held.max(self.held.len());
        }
        self.flush();
        inner
    }

    /// A token that neither opens nor closes a call.
    fn take(&mut self, h: Held) {
        if self.absorb_char_code(&h) {
            return;
        }
        self.append(h);
        if let Some(call) = self.calls.last() {
            let arg = &self.held[call.open + 1..];
            let possible = match call.kind {
                // Only an `eval` can still produce numbers here.
                Kind::FromCharCode { want_num, .. } => {
                    matches!(arg, [e] if want_num && callee(e).is_some_and(|k| matches!(k, Kind::Eval)))
                }
                _ => string_arg_possible(arg),
            };
            if !possible {
                self.give_up_all();
            }
        }
    }

    /// A number or `,` in the argument of the innermost call when that is a
    /// `fromCharCode` still reading its list: kept as a value, not a token.
    fn absorb_char_code(&mut self, h: &Held) -> bool {
        let Some(call) = self.calls.last_mut() else {
            return false;
        };
        let Kind::FromCharCode { values, want_num } = &mut call.kind else {
            return false;
        };
        if self.held.len() != call.open + 1 {
            return false;
        }
        match &h.tok {
            // More codes than output bytes would be cut from the output
            // whether the call reduces or not.
            Tok::Num(num) if *want_num && values.len() < MAX_OUTPUT => match parse_int(num) {
                Some(v) => {
                    values.push(v);
                    *want_num = false;
                    true
                }
                None => false,
            },
            Tok::Punct(b',') if !*want_num => {
                *want_num = true;
                true
            }
            _ => false,
        }
    }

    /// Hold `h`, joining a string to the string before it (with or without a
    /// `+` between them).
    fn append(&mut self, h: Held) {
        if let Tok::Str(s) = &h.tok {
            let n = self.held.len();
            let into = if n >= 1 && matches!(self.held[n - 1].tok, Tok::Str(_)) {
                Some(n - 1)
            } else if n >= 2
                && self.held[n - 1].tok == Tok::Punct(b'+')
                && matches!(self.held[n - 2].tok, Tok::Str(_))
            {
                Some(n - 2)
            } else {
                None
            };
            if let Some(into) = into {
                self.held.truncate(into + 1);
                if let Tok::Str(d) = &mut self.held[into].tok {
                    d.extend_from_slice(s);
                }
                return;
            }
        }
        self.held.push(h);
    }

    /// A `(`: the start of a call when a callee is right before it.
    fn open(&mut self, h: Held) {
        let n = self.held.len();
        let found = self.held.last().and_then(callee).map(|kind| {
            let string_dot = n >= 3
                && self.held[n - 2].tok == Tok::Punct(b'.')
                && is_ident_named(&self.held[n - 3], b"string");
            let start = if matches!(kind, Kind::FromCharCode { .. }) && string_dot {
                n - 3
            } else {
                n - 1
            };
            (kind, start, self.held[n - 1].depth)
        });
        match found {
            Some((kind, start, depth)) => {
                if self.calls.len() == MAX_OPEN_CALLS {
                    self.give_up_outermost();
                }
                let start = start.min(self.held.len());
                self.held.push(h);
                self.calls.push(Call {
                    kind,
                    start,
                    open: self.held.len() - 1,
                    depth,
                });
            }
            None => {
                // A bracket in a call's argument: that call cannot reduce, nor
                // can the calls around it.
                self.give_up_all();
                self.held.push(h);
            }
        }
    }

    /// A `)` closing the innermost open call: replace the call by its value
    /// when the argument has the form it needs.
    fn close(&mut self, h: Held) -> Option<Lexer<'static>> {
        let reducible = match self.calls.last() {
            Some(call) => {
                let arg = &self.held[call.open + 1..];
                match &call.kind {
                    Kind::FromCharCode { values, want_num } => {
                        arg.is_empty() && !*want_num && !values.is_empty()
                    }
                    _ => matches!(arg, [Held { tok: Tok::Str(_), .. }]),
                }
            }
            None => false,
        };
        let call = match self.calls.pop() {
            Some(call) if reducible => call,
            other => {
                self.calls.extend(other);
                self.give_up_all();
                self.append(h);
                return None;
            }
        };
        let value = match call.kind {
            Kind::FromCharCode { values, .. } => {
                values.into_iter().flat_map(encode_cp).collect()
            }
            kind => {
                let text = match self.held.pop() {
                    Some(Held {
                        tok: Tok::Str(s), ..
                    }) => s,
                    _ => Vec::new(),
                };
                if matches!(kind, Kind::Eval) {
                    self.held.truncate(call.start);
                    return Some(Lexer::new(Text::Mem(Cow::Owned(text)), call.depth + 1));
                }
                percent_decode(&text)
            }
        };
        self.held.truncate(call.start);
        self.take(Held {
            tok: Tok::Str(value),
            depth: call.depth,
        });
        None
    }

    /// Stop treating the open calls as reducible: their tokens are written as
    /// they were read.
    fn give_up_all(&mut self) {
        let calls = std::mem::take(&mut self.calls);
        let mut written = 0;
        for call in calls {
            // A `fromCharCode`'s list is written in place, after its `(`.
            if let Kind::FromCharCode { values, want_num } = call.kind {
                let upto = call.open + 1 - written;
                self.write_front(upto);
                written += upto;
                self.out.char_codes(&values, want_num);
            }
        }
    }

    /// `give_up_all` for the outermost call only.
    fn give_up_outermost(&mut self) {
        if self.calls.is_empty() {
            return;
        }
        let call = self.calls.remove(0);
        if let Kind::FromCharCode { values, want_num } = call.kind {
            self.write_front(call.open + 1);
            self.out.char_codes(&values, want_num);
        }
    }

    /// Write out what can no longer change, in batches.
    fn flush(&mut self) {
        let settled = match self.calls.first() {
            // A reduced call's value can join a `"…" +` before it, and an
            // unrolled `eval` can supply the `(` of a callee just before it.
            Some(call) => call.start.saturating_sub(3),
            None => self.held.len().saturating_sub(KEEP_BEHIND),
        };
        if settled >= FLUSH_BATCH {
            self.write_front(settled);
        }
    }

    /// Write out the first `n` held tokens.
    fn write_front(&mut self, n: usize) {
        let n = n.min(self.held.len());
        for h in self.held.drain(..n) {
            self.out.emit(&h.tok);
        }
        for call in &mut self.calls {
            call.start -= n;
            call.open -= n;
        }
    }

    fn finish(mut self) -> (Vec<u8>, bool) {
        if !self.out.cut {
            // A call never closed is written as it was read.
            self.give_up_all();
            self.write_front(self.held.len());
        }
        let mut out = self.out.out;
        let cut = self.out.cut || out.len() > MAX_OUTPUT;
        out.truncate(MAX_OUTPUT);
        (out, cut)
    }
}

/// The call a callee token starts, if it is one exav evaluates.
fn callee(h: &Held) -> Option<Kind> {
    let Tok::Ident(name) = &h.tok else {
        return None;
    };
    if name.eq_ignore_ascii_case(b"fromcharcode") {
        Some(Kind::FromCharCode {
            values: Vec::new(),
            want_num: true,
        })
    } else if [&b"unescape"[..], b"decodeuricomponent", b"decodeuri"]
        .iter()
        .any(|c| name.eq_ignore_ascii_case(c))
    {
        Some(Kind::Decode)
    } else if name.eq_ignore_ascii_case(b"eval") && h.depth < MAX_EVAL_DEPTH {
        Some(Kind::Eval)
    } else {
        None
    }
}

fn is_ident_named(h: &Held, name: &[u8]) -> bool {
    matches!(&h.tok, Tok::Ident(n) if n.eq_ignore_ascii_case(name))
}

/// Whether `arg`, what is held after a string-argument call's `(`, can still
/// become one string: a string, optionally with a `+` after it, then at most
/// the callee of a call whose value would join it.
fn string_arg_possible(arg: &[Held]) -> bool {
    let mut rest = arg;
    if let [Held {
        tok: Tok::Str(_), ..
    }, tail @ ..] = rest
    {
        rest = tail;
        if let [Held {
            tok: Tok::Punct(b'+'),
            ..
        }, tail @ ..] = rest
        {
            rest = tail;
        }
    }
    match rest {
        [] => true,
        [c] => callee(c).is_some() || is_ident_named(c, b"string"),
        [s, dot] => is_ident_named(s, b"string") && dot.tok == Tok::Punct(b'.'),
        [s, dot, f] => {
            is_ident_named(s, b"string")
                && dot.tok == Tok::Punct(b'.')
                && is_ident_named(f, b"fromcharcode")
        }
        _ => false,
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

/// Writes settled tokens. User identifiers are renamed `n001`, `n002`… in the
/// order they first appear, keeping reserved words and common built-ins so
/// signatures that reference them (and decoded string content) still match. A
/// single space separates two tokens only when their touching characters would
/// otherwise merge (two identifier/number chars).
#[derive(Default)]
struct Emitter {
    out: Vec<u8>,
    /// The number each renamed identifier was given.
    names: HashMap<Box<[u8]>, u32>,
    /// A token was left out because the output is full.
    cut: bool,
}

impl Emitter {
    fn emit(&mut self, tok: &Tok) {
        if self.cut {
            return;
        }
        if self.out.len() >= MAX_OUTPUT {
            self.cut = true;
            return;
        }
        let number;
        let piece: &[u8] = match tok {
            Tok::Ident(name) if !is_kept(name) => {
                let k = match self.names.get(&name[..]) {
                    Some(&k) => k,
                    None => {
                        let k = self.names.len() as u32 + 1;
                        self.names.insert(name.clone().into_boxed_slice(), k);
                        k
                    }
                };
                number = format!("n{k:03}").into_bytes();
                &number
            }
            Tok::Ident(name) | Tok::Regex(name) => name,
            Tok::Num(s) => {
                number = normalize_num(s);
                &number
            }
            Tok::Str(s) => {
                self.out.push(b'"');
                self.out.extend_from_slice(s);
                self.out.push(b'"');
                return;
            }
            Tok::Punct(b) => std::slice::from_ref(b),
        };
        if let (Some(&last), Some(&first)) = (self.out.last(), piece.first()) {
            if is_ident(last) && is_ident(first) {
                self.out.push(b' ');
            }
        }
        self.out.extend_from_slice(piece);
    }

    /// The list of a `fromCharCode` that was not reduced, as its tokens would
    /// have been written: numbers in decimal, and the trailing `,` if any.
    fn char_codes(&mut self, values: &[u32], want_num: bool) {
        for (k, v) in values.iter().enumerate() {
            if k > 0 {
                self.emit(&Tok::Punct(b','));
            }
            self.emit(&Tok::Num(v.to_string().into_bytes()));
        }
        if want_num && !values.is_empty() {
            self.emit(&Tok::Punct(b','));
        }
    }
}

/// Render an integer literal as decimal; leave floats/malformed text as-is.
fn normalize_num(num: &[u8]) -> Vec<u8> {
    match parse_int(num) {
        Some(v) => v.to_string().into_bytes(),
        None => num.to_vec(),
    }
}

/// An identifier written as it is rather than renamed.
fn is_kept(name: &[u8]) -> bool {
    ident_is_keyword(name) || KEEP_IDENTS.iter().any(|k| name.eq_ignore_ascii_case(k))
}

/// JavaScript reserved words and control keywords — never renamed, and a value
/// is expected right after them (regex disambiguation).
fn ident_is_keyword(name: &[u8]) -> bool {
    KEYWORDS.iter().any(|k| name.eq_ignore_ascii_case(k))
}

const KEYWORDS: &[&[u8]] = &[
    b"var", b"let", b"const", b"function", b"return", b"if", b"else", b"for", b"while",
    b"do", b"switch", b"case", b"default", b"break", b"continue", b"new", b"delete",
    b"typeof", b"instanceof", b"in", b"of", b"void", b"this", b"throw", b"try", b"catch",
    b"finally", b"with", b"yield", b"await", b"async", b"class", b"extends", b"super",
    b"import", b"export", b"true", b"false", b"null", b"undefined",
];

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
        String::from_utf8_lossy(&normalize(s).0).into_owned()
    }

    #[test]
    fn output_past_the_cap_is_flagged() {
        let literal = |len: usize| {
            let mut s = b"var s=\"".to_vec();
            s.resize(s.len() + len, b'A');
            s.extend_from_slice(b"\";");
            s
        };
        // `var n001="…";` is 12 bytes around the literal.
        let (out, cut) = normalize(&literal(MAX_OUTPUT - 12));
        assert_eq!((out.len(), cut), (MAX_OUTPUT, false));
        let (out, cut) = normalize(&literal(MAX_OUTPUT - 11));
        assert_eq!((out.len(), cut), (MAX_OUTPUT, true));
        // Cut between tokens rather than inside one.
        let (out, cut) = normalize(&[literal(MAX_OUTPUT - 12), b"x;".to_vec()].concat());
        assert_eq!((out.len(), cut), (MAX_OUTPUT, true));
    }

    #[test]
    fn the_script_is_not_held_whole() {
        // A long minified script, with a call left open at the start that
        // stops being reducible straight away: tokens are written out as
        // they settle rather than kept to the end.
        let mut script = b"unescape(x".to_vec();
        for k in 0..200_000 {
            script.extend_from_slice(format!("a{k}=b.c(d,e)+\"f\";").as_bytes());
        }
        let n = run(Text::Mem(Cow::Borrowed(&script)));
        assert!(n.peak_held < 2 * FLUSH_BATCH, "held {} tokens", n.peak_held);
        // Calls nested deeper than the cap: the outermost are given up.
        let deep = [b"unescape(".repeat(100_000), b"'%41'".to_vec(), b")".repeat(100_000)].concat();
        let n = run(Text::Mem(Cow::Borrowed(&deep)));
        assert!(n.peak_held < 4 * MAX_OPEN_CALLS + FLUSH_BATCH, "held {} tokens", n.peak_held);
    }

    #[test]
    fn values_join_what_is_around_them() {
        // A reduced call's string joins the strings before and after it.
        assert_eq!(norm(br#"x="a"+unescape("%42")+"c";"#), r#"n001="aBc";"#);
        // So do the strings an unrolled eval produces.
        assert_eq!(norm(br#""a"+eval("'b'")+"c""#), r#""abc""#);
        // An unrolled eval can supply a callee for what follows it.
        assert_eq!(norm(br#"eval("unescape")("%41")"#), r#""A""#);
        assert_eq!(norm(br#"String.eval("fromCharCode")(66)"#), r#""B""#);
    }

    #[test]
    fn a_call_that_cannot_reduce_is_written_as_read() {
        assert_eq!(norm(b"fromCharCode(0x41,x)"), "fromCharCode(65,n001)");
        assert_eq!(norm(b"fromCharCode(0x41,)"), "fromCharCode(65,)");
        assert_eq!(norm(b"String.fromCharCode(65,66"), "String.fromCharCode(65,66");
        assert_eq!(norm(br#"unescape(("%41"))"#), r#"unescape(("%41"))"#);
        assert_eq!(norm(br#"unescape("%41"+x)"#), r#"unescape("%41"+n001)"#);
    }

    #[test]
    fn nesting_is_unrolled_to_the_bottom() {
        // Thirty nested decodes: one repeated fold pass per level would stop
        // short of it.
        let script = [b"unescape(".repeat(30), b"'x'".to_vec(), b")".repeat(30)].concat();
        assert_eq!(norm(&script), r#""x""#);
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

    #[test]
    fn a_script_read_in_blocks_normalizes_as_in_memory() {
        use crate::byte_source::{BlockCache, CHUNK};
        let pieces: &[&[u8]] = &[
            b"eval(", b"unescape(", b"'%61%6c'", b")", b";", b" ", b"\n", b"var x=", b"1e+5", b".5e3",
            b"/*c*/", b"// line\n", b"/re[/]x/g", b"\"a\\x41\\u0042\\u{43}\\101\"", b"String.fromCharCode(",
            b"72,105", b"`t\\`q`", b"a/b", b"(", b"]", b"\\\r\n", b"abc$_\x80",
        ];
        let mut state = 0x6A09_E667_F3BC_C908u64;
        for round in 0..300 {
            let count = if round < 290 { 20 } else { 3 * CHUNK / 4 };
            let mut data = Vec::new();
            for _ in 0..count {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                data.extend_from_slice(pieces[(state % pieces.len() as u64) as usize]);
            }
            let cache = BlockCache::with_sizes(std::io::Cursor::new(data.clone()), 7, 56).unwrap();
            assert_eq!(
                normalize_source(&cache),
                normalize(&data),
                "{:?}",
                String::from_utf8_lossy(&data[..data.len().min(80)])
            );
        }
    }
}
