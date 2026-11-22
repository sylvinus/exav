//! Clean-room JavaScript normalisation for signature matching.
//!
//! Traditional engines (ClamAV) scan `.yar`/`.ndb` JS signatures against a
//! *normalised* rendering of a script rather than its raw bytes, so a single
//! pattern matches regardless of the obfuscation used to evade it. This module
//! reproduces that behaviour **from the public description of the transforms**,
//! not by porting any GPL implementation. It performs the same *classes* of
//! static rewrite ClamAV's `js-norm` does (the output is not byte-identical):
//!
//! * tokenise, dropping block comments and redundant whitespace; a `//` is
//!   dropped and the text of the comment is read as code (see [`Lexer`]);
//! * decode string-literal escapes (`\xHH`, `\uHHHH`, `\u{..}`, octal, `\n`…)
//!   and fold string concatenation (`"ab"+"cd"` → `"abcd"`);
//! * evaluate `unescape("…%XX…")` whose argument is a literal;
//! * re-parse the argument of `eval("…")` as JavaScript (depth-bounded), so
//!   `eval("un"+"escape(...)")`-style loaders unroll;
//! * rename the declared identifiers to `n000`, `n001`… as clamscan does (see
//!   [`Scopes`]): `var` names, function names and parameters, in source order,
//!   by function scope. Every other identifier is written as read. Names are
//!   told apart by case, and everything is written in lower case.
//! * write a number and the letters after it apart (`50em` is `50 em`, `0x1f`
//!   is `0 x1f`), a decimal integer wrapped to 32 bits, a number with a `.`
//!   as a `%g` double.
//!
//! The [`Mode`] says whose output it is. [`Mode::Clamscan`] is clamscan's, for
//! the views signatures written against it match. [`Mode::Decoding`] is the
//! same text, and decodes more, for exav's own views: `String.fromCharCode`
//! of literals, `decodeURI` and `decodeURIComponent`, and an `unescape` whose
//! argument is the value of another.
//!
//! Decoded *string content* (URLs, command lines, API names passed as strings)
//! survives verbatim, which is where detection value comes from. This is a
//! purely static rewriter: it never executes code, so runtime-assembled payloads
//! (numeric-array VMs, dynamic dispatch) are intentionally out of scope.
//!
//! Not done here: Microsoft Script Encoder (`#@~^…^#~@`) blobs are decoded by
//! exav-unpack's `screnc`, which surfaces the plaintext as a member of its own.
//!
//! Not yet implemented:
//! * **base64→script rescan**: decoding long base64 runs to *script/text* (not
//!   just exec-magic payloads, which `exav-unpack::base64_payloads` already
//!   covers). The higher-yield lever per corpus evidence, but needs a distinct
//!   FP-safe gate (base64 text is ubiquitous and benign).
//!
//! The script is read once. Each rewrite is a reduction at the point a token
//! arrives: a string joins the string before it, and a call is replaced when
//! its `)` closes it. Only what can still change is held back: the last few
//! tokens, and the calls still open whose argument can still take the form the
//! call needs. Settled tokens are written to a buffer in which a name is a
//! mark and its id, because a name can be used before the line that declares
//! it; when the script ends, the marks are replaced by the numbers. Memory is
//! therefore the buffer, which has a bound of its own at twice the output cap,
//! one entry per distinct name, and the open calls, not the whole script.
//! Nothing here can panic on any byte sequence.

use std::borrow::Cow;
use std::collections::HashMap;

use crate::byte_source::{ByteSource, Bytes, Stepper};

/// Hard ceilings so a hostile script can't blow up time or memory.
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
/// The buffer an [`Emitter`] writes, which holds a mark for each name and
/// scope change. It has a bound of its own, so that a script of short names
/// no scope declares is not cut sooner than its output would be.
const MAX_BUFFER: usize = 2 * MAX_OUTPUT;
/// `eval` layers unrolled, counted from the script itself. Each layer re-reads
/// text that the layer above held as a string, so the work is at most this
/// many times the input.
const MAX_EVAL_DEPTH: u32 = 32;
/// Calls open inside one another at once. Past it the outermost is left as
/// written, so the tokens held back stay bounded.
const MAX_OPEN_CALLS: usize = 256;
/// Tokens held back when no call is open: a callee and the `"…" +` before it
/// are the furthest a later reduction looks back.
const KEEP_BEHIND: usize = 3;
/// Settled tokens are written out in batches of at least this many.
const FLUSH_BATCH: usize = 1024;

/// A single lexical token. Comments and whitespace are never emitted.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    /// Identifier or keyword (raw source bytes, case preserved).
    Ident(Vec<u8>),
    /// Decoded string-literal content (escapes resolved, quotes removed).
    Str(Vec<u8>),
    /// The string a call was replaced by, in [`Mode::Clamscan`]: written as a
    /// string, but no other call takes it as its argument (an `eval` does), and
    /// it joins no string around it.
    Value(Vec<u8>),
    /// A number as clamscan writes it, and in [`Mode::Decoding`] what the
    /// literal comes to in JavaScript.
    Num(Vec<u8>, Option<Lit>),
    /// A single punctuation / operator byte (multi-byte operators become a run).
    Punct(u8),
    /// A space written whatever is around it: what clamscan leaves of a `\`
    /// before a letter or a digit.
    Space,
    /// The end of one script of a page and the start of the next. Written as
    /// nothing; the names of the script before are not those of the next.
    Split,
}

/// What a numeric literal such as `0x41` is in JavaScript, which is not what
/// clamscan writes for it (`0 x41`).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Lit {
    value: u32,
    /// The literal goes on past the number written: an identifier token
    /// follows, which is the rest of it.
    tail: bool,
}

/// Whose output is written. A value rather than a type parameter, so that the
/// normaliser is compiled once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// What clamscan writes: `unescape` of a literal is the only call
    /// evaluated besides `eval`, and what it gives is not an argument again.
    Clamscan,
    /// Clamscan's text, and also `String.fromCharCode(<literals>)`,
    /// `decodeURI`, `decodeURIComponent`, and a call whose argument is the
    /// value of another, as deep as `MAX_OPEN_CALLS` calls are open at once.
    Decoding,
}

/// Ends a script in the text of the scripts of a page: the byte
/// `normalize::Scripts` writes between them, and drops from the scripts.
const SPLIT: u8 = 0;

/// What a normaliser reads.
#[derive(Clone, Copy)]
enum Input<'a> {
    Mem(&'a [u8]),
    Source(&'a dyn ByteSource),
}

impl<'a> Input<'a> {
    fn of(src: &'a dyn ByteSource) -> Self {
        match src.as_slice() {
            Some(data) => Input::Mem(data),
            None => Input::Source(src),
        }
    }

    fn text(self) -> Text<'a> {
        match self {
            Input::Mem(data) => Text::Mem(Cow::Borrowed(data)),
            Input::Source(src) => Text::Source(Stepper::new(src)),
        }
    }
}

/// Normalise a JavaScript/script buffer to its canonical form for matching.
/// The flag is true when the output was cut at [`MAX_OUTPUT`].
pub fn normalize(data: &[u8], mode: Mode) -> (Vec<u8>, bool) {
    read(Input::Mem(data), false, mode)
}

/// [`normalize`] over a script that need not be held in memory.
pub(crate) fn normalize_source(src: &dyn ByteSource, mode: Mode) -> (Vec<u8>, bool) {
    read(Input::of(src), false, mode)
}

/// [`normalize_source`] in [`Mode::Clamscan`] over the scripts of a page, one
/// after the other, split by [`SPLIT`]. Every script is normalised on its
/// own: its names are numbered from `n000`, as clamscan does for a page.
pub(crate) fn normalize_scripts(src: &dyn ByteSource) -> (Vec<u8>, bool) {
    read(Input::of(src), true, Mode::Clamscan)
}

/// Read `input` once and give the output.
fn read(input: Input, split: bool, mode: Mode) -> (Vec<u8>, bool) {
    run(input.text(), split, Emitter::new(), mode).finish()
}

/// Read all of `data` through the normaliser, leaving the end unwritten.
/// With `split`, a [`SPLIT`] byte at the top level ends a script.
fn run(data: Text, split: bool, out: Emitter, mode: Mode) -> Normalizer {
    let mut n = Normalizer::new(out, mode);
    // The script, and above it the text of each `eval` being unrolled.
    let mut sources = vec![Lexer::new(data, 0, split, mode)];
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

/// How many bytes of an identifier start at `i`: one identifier byte, the six
/// of a `\uXXXX` that clamscan takes as part of a name (the two of a `\u` with
/// no four digits after it), or none.
fn ident_part(data: &mut Text, i: usize, first: bool) -> usize {
    let b = data.at(i);
    if b == b'\\' {
        if i + 1 >= data.len() || data.at(i + 1) != b'u' {
            0
        } else if i + 6 <= data.len() && (2..6).all(|k| data.at(i + k).is_ascii_hexdigit()) {
            6
        } else {
            2
        }
    } else if first {
        usize::from(is_ident_start(b))
    } else {
        usize::from(is_ident(b))
    }
}

/// An identifier as clamscan writes it when it does not rename it: in lower
/// case, and without the `u` of a `\uXXXX`.
fn written(name: &[u8]) -> Cow<'_, [u8]> {
    if !name.iter().any(|b| b.is_ascii_uppercase() || *b == b'\\') {
        return Cow::Borrowed(name);
    }
    let mut out = Vec::with_capacity(name.len());
    for (k, &b) in name.iter().enumerate() {
        if !(b == b'u' && k > 0 && name[k - 1] == b'\\') {
            out.push(b.to_ascii_lowercase());
        }
    }
    Cow::Owned(out)
}

/// Splits text into tokens, decoding string escapes and dropping whitespace
/// and block comments, as clamscan does:
///
/// * `//` is dropped, and so is the word after it when no space or newline
///   follows (`//x y` leaves `y`, `// x y` leaves `x y`): the text of a line
///   comment is read as code.
/// * A `/` otherwise is the operator: there are no regular expression
///   literals, so the `\`, quotes and `//` in one are read as anywhere else.
/// * A `\` that does not start a `\u` name is dropped, and is a space when a
///   letter, a digit, `_`, `$` or another `\` comes right after it, comments
///   set aside. So are the backquotes of a template literal and every `#`
///   outside a string dropped (no space).
/// * A number is the digits, and with a `.` after them a fraction and
///   exponents (see [`read_number`]); a `.` before digits is the operator.
struct Lexer<'a> {
    data: Text<'a>,
    i: usize,
    /// How many `eval` layers this text is inside.
    depth: u32,
    /// [`SPLIT`] ends a script: the text is the scripts of a page.
    split: bool,
    mode: Mode,
    /// A `\` was dropped and the token after it is not read yet.
    pending: bool,
    /// The token to give after the space a `\` made.
    queued: Option<Tok>,
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
    fn new(data: Text<'a>, depth: u32, split: bool, mode: Mode) -> Self {
        Lexer {
            data,
            i: 0,
            depth,
            split,
            mode,
            pending: false,
            queued: None,
        }
    }

    fn next(&mut self) -> Option<Tok> {
        if let Some(tok) = self.queued.take() {
            return Some(tok);
        }
        let tok = self.token()?;
        // A `\` is a space when the token after it starts like a name.
        if std::mem::take(&mut self.pending) && matches!(tok, Tok::Ident(_) | Tok::Num(..)) {
            self.queued = Some(tok);
            return Some(Tok::Space);
        }
        Some(tok)
    }

    fn token(&mut self) -> Option<Tok> {
        let data = &mut self.data;
        let split = self.split;
        let mode = self.mode;
        let ends = |b: u8| split && b == SPLIT;
        let n = data.len();
        let mut i = self.i;
        while i < n {
            let b = data.at(i);
            match b {
                SPLIT if split => {
                    self.i = i + 1;
                    return Some(Tok::Split);
                }
                b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x0b => {
                    i += 1;
                }
                b'/' if i + 1 < n && data.at(i + 1) == b'/' => {
                    i += 2;
                    // The word after `//`, unless a space or newline is next.
                    while i < n && !matches!(data.at(i), b' ' | b'\n') && !ends(data.at(i)) {
                        i += 1;
                    }
                }
                b'/' if i + 1 < n && data.at(i + 1) == b'*' => {
                    i += 2;
                    while i + 1 < n
                        && !(data.at(i) == b'*' && data.at(i + 1) == b'/')
                        && !ends(data.at(i))
                    {
                        i += 1;
                    }
                    if i >= n || !ends(data.at(i)) {
                        i = (i + 2).min(n);
                    }
                }
                b'\'' | b'"' => {
                    let (s, ni) = read_string(data, i, b, split.then_some(SPLIT));
                    self.i = ni;
                    return Some(Tok::Str(s));
                }
                // The backquotes of a template literal and `#` are dropped.
                b'`' | b'#' => {
                    i += 1;
                }
                b'\\' if ident_part(data, i, true) == 0 => {
                    i += 1;
                    if i < n && data.at(i) == b'\\' {
                        self.i = i;
                        return Some(Tok::Space);
                    }
                    self.pending = true;
                }
                b'0'..=b'9' => {
                    let (text, end) = read_number(data, i);
                    let lit = if mode == Mode::Decoding {
                        literal(data, i, end)
                    } else {
                        None
                    };
                    self.i = end;
                    return Some(Tok::Num(text, lit));
                }
                _ if ident_part(data, i, true) > 0 => {
                    let start = i;
                    i += ident_part(data, i, true);
                    while i < n {
                        let k = ident_part(data, i, false);
                        if k == 0 {
                            break;
                        }
                        i += k;
                    }
                    self.i = i;
                    return Some(Tok::Ident(data.range(start, i).into_owned()));
                }
                _ => {
                    self.i = i + 1;
                    return Some(Tok::Punct(b));
                }
            }
        }
        self.i = i;
        None
    }
}

/// Read the number that starts with the digit at `start`, as clamscan does:
/// the digits, and when a `.` follows, that `.`, the digits after it and
/// exponent groups (`e`, an optional sign, digits; another group follows a
/// group that held a sign or a digit). The letters after the number are the
/// next token: `50em` is `50` and `em`, `0x1f` is `0` and `x1f`, `1e5` is `1`
/// and `e5`. A number with a `.` is a double, written as `%g` writes it;
/// another is a decimal integer, wrapped to 32 bits. Returns the text written
/// and the index past the number.
fn read_number<B: Bytes>(data: &mut B, start: usize) -> (Vec<u8>, usize) {
    let n = data.len();
    let mut i = start;
    while i < n && data.at(i).is_ascii_digit() {
        i += 1;
    }
    if i >= n || data.at(i) != b'.' {
        return (integer(&data.range(start, i)), i);
    }
    let int_end = i;
    i += 1;
    let frac_start = i;
    while i < n && data.at(i).is_ascii_digit() {
        i += 1;
    }
    let frac_end = i;
    // The digits (with their sign) of the first exponent group, if it has any:
    // the others, and a group without digits, are read and not counted.
    let mut exp = None;
    let mut first = true;
    while i < n && matches!(data.at(i), b'e' | b'E') {
        let from = i + 1;
        i = from;
        if i < n && matches!(data.at(i), b'+' | b'-') {
            i += 1;
        }
        let digits = i;
        while i < n && data.at(i).is_ascii_digit() {
            i += 1;
        }
        if first && i > digits {
            exp = Some((from, i));
        }
        first = false;
        if i == from {
            break;
        }
    }
    let mut text = data.range(start, int_end).into_owned();
    text.push(b'.');
    if frac_end > frac_start {
        text.extend_from_slice(&data.range(frac_start, frac_end));
    } else {
        text.push(b'0');
    }
    if let Some((from, to)) = exp {
        text.push(b'e');
        text.extend_from_slice(&data.range(from, to));
    }
    let value = std::str::from_utf8(&text)
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    (format_g(value), i)
}

/// A decimal integer as clamscan writes it: read as a 64-bit number that
/// stops at its largest value, then cut to 32 bits.
fn integer(digits: &[u8]) -> Vec<u8> {
    let mut v: i64 = 0;
    for &d in digits {
        match v
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(d - b'0')))
        {
            Some(next) => v = next,
            None => {
                v = i64::MAX;
                break;
            }
        }
    }
    (v as i32).to_string().into_bytes()
}

/// A double as C's `%g` writes it: six significant digits, in the form
/// `1.5e+06` when the exponent is below -4 or from 6 up, trailing zeros
/// removed. The value is never negative.
fn format_g(v: f64) -> Vec<u8> {
    if v.is_infinite() {
        return b"inf".to_vec();
    }
    if v == 0.0 {
        return b"0".to_vec();
    }
    // `d.dddddeX`: six digits, correctly rounded.
    let s = format!("{v:.5e}");
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: Vec<u8> = mant.bytes().filter(u8::is_ascii_digit).collect();
    let trimmed = |d: &[u8]| {
        let end = d.iter().rposition(|&c| c != b'0').map_or(0, |p| p + 1);
        d[..end].to_vec()
    };
    let mut out = Vec::new();
    if !(-4..6).contains(&exp) {
        out.extend(digits.first());
        let frac = trimmed(digits.get(1..).unwrap_or_default());
        if !frac.is_empty() {
            out.push(b'.');
            out.extend(frac);
        }
        out.push(b'e');
        out.push(if exp < 0 { b'-' } else { b'+' });
        out.extend(format!("{:02}", exp.unsigned_abs()).bytes());
    } else if exp >= 0 {
        let whole = exp as usize + 1;
        out.extend(digits.get(..whole).unwrap_or_default());
        let frac = trimmed(digits.get(whole..).unwrap_or_default());
        if !frac.is_empty() {
            out.push(b'.');
            out.extend(frac);
        }
    } else {
        out.extend_from_slice(b"0.");
        out.extend(std::iter::repeat_n(b'0', exp.unsigned_abs() as usize - 1));
        out.extend(trimmed(&digits));
    }
    out
}

/// What the literal that starts at `start` comes to in JavaScript, for the
/// integers that end where an identifier does not go on (`0x41`, `1_000`,
/// `65`). `head` is where the number clamscan reads ends.
fn literal<B: Bytes>(data: &mut B, start: usize, head: usize) -> Option<Lit> {
    let n = data.len();
    let mut i = start + 1;
    while i < n {
        let c = data.at(i);
        let sign = (c == b'+' || c == b'-') && matches!(data.at(i - 1), b'e' | b'E');
        if !(c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || sign) {
            break;
        }
        i += 1;
    }
    if i < n && (is_ident(data.at(i)) || data.at(i) == b'\\') {
        return None;
    }
    let value = parse_int(&data.range(start, i))?;
    Some(Lit {
        value,
        tail: i > head,
    })
}

/// Read a string literal starting at the opening quote `data[i] == quote`.
/// Returns the decoded content (without quotes) and the index past the closer.
/// As in clamscan, a string ends at its quote only: a newline in it is a space,
/// and one never closed runs to the end of the text, or to `stop`. Past
/// [`MAX_OUTPUT`] bytes the rest is read as code, as the output is cut there.
fn read_string<B: Bytes>(
    data: &mut B,
    mut i: usize,
    quote: u8,
    stop: Option<u8>,
) -> (Vec<u8>, usize) {
    let n = data.len();
    let mut s = Vec::new();
    i += 1; // skip opening quote
    while i < n && s.len() < MAX_OUTPUT {
        let b = data.at(i);
        if b == quote {
            i += 1;
            break;
        }
        if stop == Some(b) {
            break;
        }
        if b == b'\\' && i + 1 < n && stop != Some(data.at(i + 1)) {
            let (bytes, ni) = decode_escape(data, i + 1);
            s.extend_from_slice(&bytes);
            i = ni;
            continue;
        }
        s.push(if b.is_ascii_whitespace() || b == 0x0b {
            b' '
        } else {
            b
        });
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
        // Line continuation, a space as any newline in a string.
        b'\n' => (vec![b' '], i + 1),
        b'\r' if i + 1 < n && data.at(i + 1) == b'\n' => (vec![b' '], i + 2),
        b'\r' => (vec![b' '], i + 1),
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
    /// `unescape`, and in [`Mode::Decoding`] `decodeURI` and
    /// `decodeURIComponent`: one string.
    Decode,
    /// `eval`: one string, read again as code.
    Eval,
    /// [`Mode::Decoding`] only. `fromCharCode` / `String.fromCharCode`:
    /// integers, held as their values rather than as tokens. `want_num` is
    /// true at the start and after a `,`.
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
struct Normalizer {
    held: Vec<Held>,
    calls: Vec<Call>,
    out: Emitter,
    mode: Mode,
    /// The token to come is the rest of a literal read as a value.
    skip_tail: bool,
    /// Values held by the open `fromCharCode` calls, all together.
    listed: usize,
    /// Most tokens held at once.
    #[cfg(test)]
    peak_held: usize,
}

impl Normalizer {
    fn new(out: Emitter, mode: Mode) -> Self {
        Normalizer {
            held: Vec::new(),
            calls: Vec::new(),
            out,
            mode,
            skip_tail: false,
            listed: 0,
            #[cfg(test)]
            peak_held: 0,
        }
    }

    /// Take one token. Returns the text of an `eval` just reduced, to be read
    /// before the rest of the current text.
    fn push(&mut self, h: Held) -> Option<Lexer<'static>> {
        if std::mem::take(&mut self.skip_tail) && matches!(h.tok, Tok::Ident(_)) {
            return None;
        }
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
                    matches!(arg, [e] if want_num && callee(e, self.mode).is_some_and(|k| matches!(k, Kind::Eval)))
                }
                _ => string_arg_possible(arg, &call.kind, self.mode),
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
            // The lists are held up to a quarter of the output cap's count
            // together (4 bytes a value, 32 MiB). Past it the numbers are
            // tokens, which the output cap cuts.
            Tok::Num(_, Some(lit)) if *want_num && self.listed < MAX_OUTPUT / 4 => {
                self.listed += 1;
                values.push(lit.value);
                *want_num = false;
                self.skip_tail = lit.tail;
                true
            }
            Tok::Punct(b',') if !*want_num => {
                *want_num = true;
                true
            }
            _ => false,
        }
    }

    /// Hold `h`, joining a string to the string before it when a `+` is
    /// between them.
    fn append(&mut self, h: Held) {
        if let Tok::Str(s) = &h.tok {
            let n = self.held.len();
            if n >= 2
                && self.held[n - 1].tok == Tok::Punct(b'+')
                && matches!(self.held[n - 2].tok, Tok::Str(_))
            {
                self.held.truncate(n - 1);
                if let Tok::Str(d) = &mut self.held[n - 2].tok {
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
        let found = self
            .held
            .last()
            .and_then(|h| callee(h, self.mode))
            .map(|kind| {
                let string_dot = n >= 3
                    && self.held[n - 2].tok == Tok::Punct(b'.')
                    && is_ident_named(&self.held[n - 3], b"String");
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
        let reducible = self.calls.last().is_some_and(|call| {
            let arg = &self.held[call.open + 1..];
            match &call.kind {
                Kind::FromCharCode { values, want_num } => {
                    arg.is_empty() && !*want_num && !values.is_empty()
                }
                kind => matches!(arg, [a] if takes(kind, &a.tok)),
            }
        });
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
                self.listed = self.listed.saturating_sub(values.len());
                values.into_iter().flat_map(encode_cp).collect()
            }
            kind => {
                let text = match self.held.pop() {
                    Some(Held {
                        tok: Tok::Str(s) | Tok::Value(s),
                        ..
                    }) => s,
                    _ => Vec::new(),
                };
                if matches!(kind, Kind::Eval) {
                    self.held.truncate(call.start);
                    return Some(Lexer::new(
                        Text::Mem(Cow::Owned(text)),
                        call.depth + 1,
                        false,
                        self.mode,
                    ));
                }
                percent_decode(&text)
            }
        };
        self.held.truncate(call.start);
        let tok = match self.mode {
            Mode::Clamscan => Tok::Value(value),
            Mode::Decoding => Tok::Str(value),
        };
        self.take(Held {
            tok,
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
        self.listed = 0;
    }

    /// `give_up_all` for the outermost call only.
    fn give_up_outermost(&mut self) {
        if self.calls.is_empty() {
            return;
        }
        let call = self.calls.remove(0);
        if let Kind::FromCharCode { values, want_num } = call.kind {
            self.listed = self.listed.saturating_sub(values.len());
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

    /// Write out what is still held at the end of the text.
    fn settle(&mut self) {
        if !self.out.cut {
            // A call never closed is written as it was read.
            self.give_up_all();
            self.write_front(self.held.len());
        }
    }

    fn finish(mut self) -> (Vec<u8>, bool) {
        self.settle();
        self.out.resolve()
    }
}

/// The call a callee token starts, if it is one exav evaluates.
fn callee(h: &Held, mode: Mode) -> Option<Kind> {
    let Tok::Ident(name) = &h.tok else {
        return None;
    };
    let decoding = mode == Mode::Decoding;
    match &name[..] {
        b"unescape" => Some(Kind::Decode),
        b"decodeURIComponent" | b"decodeURI" if decoding => Some(Kind::Decode),
        b"fromCharCode" if decoding => Some(Kind::FromCharCode {
            values: Vec::new(),
            want_num: true,
        }),
        b"eval" if h.depth < MAX_EVAL_DEPTH => Some(Kind::Eval),
        _ => None,
    }
}

fn is_ident_named(h: &Held, name: &[u8]) -> bool {
    matches!(&h.tok, Tok::Ident(n) if n == name)
}

/// Whether a call of `kind` takes `tok` as its string: the value of a call is
/// not one for another in [`Mode::Clamscan`], except for an `eval`.
fn takes(kind: &Kind, tok: &Tok) -> bool {
    match tok {
        Tok::Str(_) => true,
        Tok::Value(_) => matches!(kind, Kind::Eval),
        _ => false,
    }
}

/// Whether `arg`, what is held after the `(` of a call of `kind` that takes a
/// string, can still become one: a string, optionally with a `+` after it,
/// then at most the callee of a call whose value would join it (in
/// [`Mode::Decoding`], a `String.fromCharCode` too, begun or whole).
fn string_arg_possible(arg: &[Held], kind: &Kind, mode: Mode) -> bool {
    let mut rest = arg;
    if let [first, tail @ ..] = rest
        && takes(kind, &first.tok)
    {
        rest = tail;
        if let [
            Held {
                tok: Tok::Punct(b'+'),
                ..
            },
            tail @ ..,
        ] = rest
        {
            rest = tail;
        }
    }
    let string = |h: &Held| mode == Mode::Decoding && is_ident_named(h, b"String");
    let dot = |h: &Held| h.tok == Tok::Punct(b'.');
    match rest {
        [] => true,
        [c] => callee(c, mode).is_some() || string(c),
        [s, d] => string(s) && dot(d),
        [s, d, f] => string(s) && dot(d) && is_ident_named(f, b"fromCharCode"),
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
        if s[i] == b'%' && i + 2 < n
            && let Some(v) = hex2(s[i + 1], s[i + 2]) {
                out.push(v);
                i += 3;
                continue;
            }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Parse an integer literal (decimal, `0x`, `0o`, `0b`, with `_` separators;
/// a leading `0` is still decimal) to its value. Returns `None` for floats,
/// malformed input and a value past 32 bits.
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
// Declared names + emission
// ---------------------------------------------------------------------------

/// Words that are never a name: the keywords and future reserved words of
/// ECMAScript 3, which is the list clamscan 1.4.3 skips. `let`, `yield`,
/// `await`, `async`, `of`, `get`, `set` and `undefined` are not on it.
#[rustfmt::skip]
const RESERVED: &[&[u8]] = &[
    b"abstract", b"boolean", b"break", b"byte", b"case", b"catch", b"char", b"class", b"const",
    b"continue", b"debugger", b"default", b"delete", b"do", b"double", b"else", b"enum",
    b"export", b"extends", b"false", b"final", b"finally", b"float", b"for", b"function",
    b"goto", b"if", b"implements", b"import", b"in", b"instanceof", b"int", b"interface",
    b"long", b"native", b"new", b"null", b"package", b"private", b"protected", b"public",
    b"return", b"short", b"static", b"super", b"switch", b"synchronized", b"this", b"throw",
    b"throws", b"transient", b"true", b"try", b"typeof", b"var", b"void", b"volatile",
    b"while", b"with",
];

/// Case matters: `VAR` and `Function` are names.
fn is_reserved(name: &[u8]) -> bool {
    (2..=12).contains(&name.len()) && RESERVED.contains(&name)
}

/// What a token is to the names of the script.
#[derive(Clone, Copy)]
enum Role {
    /// Written as read: not an identifier, a reserved word, or a property.
    Raw,
    /// An identifier that is renamed if a scope around it declares it.
    Use,
    /// A name declared here, in the scope of this id.
    Decl(u32),
}

/// What reading one token did to the scopes.
struct Step {
    role: Role,
    /// A function scope opened.
    enter: Option<u32>,
    /// A function scope closed.
    exit: Option<u32>,
    /// A new script began.
    reset: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// `function` read: a name may come, then `(`.
    Name,
    /// In the parameters.
    Params,
    /// After the `)`, until the `{` of the body.
    Body,
}

/// A function whose body has not begun.
struct Head {
    /// `opaque` where the function began.
    opaque_at: u32,
    /// In the parameters, how many `(` deep.
    depth: u32,
    phase: Phase,
    /// Its name has been read.
    named: bool,
}

/// An open `{` or `[`, in `Scopes::levels`.
const BRACE: u8 = 1;
/// Commas inside it do not declare names.
const HIDES: u8 = 2;

/// Which identifiers are declared names, read from the tokens in order the
/// way clamscan 1.4.3 reads them, as its output shows:
///
/// * `var` declares the first name after it. At the top level of a script,
///   outside every `{}` and `[]`, each `,` up to the `;` declares the name
///   after it too, in a call's arguments as well. Inside a block or a function
///   body only the first name of a `var` is declared.
/// * `function` declares its name and each parameter, in a scope of its own.
///   `let`, `const`, `catch` and arrow parameters declare nothing.
/// * After `var` or such a `,` the reserved words are passed over and the next
///   identifier is the name. Operators, strings, numbers and `(` do not end
///   the wait; `.`, `;` and `function` do. A `[` right after it hides nothing.
/// * Only functions are scopes. A name belongs to the nearest scope that
///   declares it anywhere, before its use or after. A function's own name is
///   in its own scope. A name right after `.` is never a name.
#[derive(Default)]
struct Scopes {
    /// Ids handed out so far.
    next: u32,
    /// The open scopes, the script's first, the innermost last.
    chain: Vec<u32>,
    /// The open `{` and `[`, a byte each.
    levels: Vec<u8>,
    /// The index in `levels` of each `{` that opens a function body.
    bodies: Vec<u32>,
    /// How many of `levels` hide commas.
    opaque: u32,
    heads: Vec<Head>,
    /// The next identifier is a declared name.
    waiting: bool,
    /// A `var` at the top level is open until its `;`.
    listing: bool,
    /// The last token was a `.`.
    dot: bool,
}

impl Scopes {
    fn new() -> Self {
        Scopes {
            next: 1,
            chain: vec![0],
            ..Scopes::default()
        }
    }

    fn current(&self) -> u32 {
        self.chain.last().copied().unwrap_or(0)
    }

    /// Start the next script, which shares no name with the one before.
    fn reset(&mut self) {
        let root = self.next;
        *self = Scopes {
            next: root + 1,
            chain: vec![root],
            ..Scopes::default()
        };
    }

    fn feed(&mut self, tok: &Tok) -> Step {
        let mut step = Step {
            role: Role::Raw,
            enter: None,
            exit: None,
            reset: false,
        };
        let after_dot = std::mem::take(&mut self.dot);
        // Only a `(` right after `function` and its name opens the parameters.
        if let Some(head) = self.heads.last_mut()
            && head.phase == Phase::Name
        {
            match tok {
                Tok::Ident(n) if !head.named && !after_dot && !is_reserved(n) => head.named = true,
                Tok::Punct(b'(') => {}
                _ => head.phase = Phase::Body,
            }
        }
        match tok {
            Tok::Split => {
                self.reset();
                step.reset = true;
            }
            Tok::Ident(name) if is_reserved(name) => self.keyword(name, &mut step),
            Tok::Ident(_) if after_dot => {}
            Tok::Ident(_) if self.waiting => {
                self.waiting = false;
                step.role = Role::Decl(self.current());
            }
            Tok::Ident(_) => step.role = Role::Use,
            Tok::Punct(b) => self.punct(*b, &mut step),
            Tok::Str(_) | Tok::Value(_) | Tok::Num(..) | Tok::Space => {}
        }
        step
    }

    fn keyword(&mut self, name: &[u8], step: &mut Step) {
        if name == b"function" {
            // A function still without a body is given up for this one; its
            // scope stays open.
            if self.heads.last().is_some_and(|h| h.phase != Phase::Params) {
                self.heads.pop();
            }
            let scope = self.next;
            self.next += 1;
            self.heads.push(Head {
                opaque_at: self.opaque,
                depth: 0,
                phase: Phase::Name,
                named: false,
            });
            self.chain.push(scope);
            self.waiting = true;
            step.enter = Some(scope);
        } else if name == b"var" {
            self.waiting = true;
            if self.opaque == 0 {
                self.listing = true;
            }
        }
    }

    /// Whether a `,` here declares the name after it.
    fn arms(&self) -> bool {
        match self.heads.last() {
            Some(Head {
                phase: Phase::Params,
                opaque_at,
                ..
            }) => *opaque_at == self.opaque,
            _ => self.listing && self.opaque == 0,
        }
    }

    fn punct(&mut self, b: u8, step: &mut Step) {
        match b {
            b'.' => {
                self.waiting = false;
                self.dot = true;
            }
            b';' => {
                self.waiting = false;
                if self.opaque == 0 {
                    self.listing = false;
                }
            }
            b',' if self.arms() => self.waiting = true,
            b'(' => {
                if let Some(head) = self.heads.last_mut() {
                    match head.phase {
                        Phase::Name => {
                            head.phase = Phase::Params;
                            head.depth = 1;
                            self.waiting = true;
                        }
                        Phase::Params => head.depth += 1,
                        Phase::Body => {}
                    }
                }
            }
            b')' => {
                if let Some(head) = self.heads.last_mut()
                    && head.phase == Phase::Params
                {
                    head.depth -= 1;
                    if head.depth == 0 {
                        head.phase = Phase::Body;
                        self.waiting = false;
                    }
                }
            }
            b'{' => {
                if self.heads.pop_if(|h| h.phase == Phase::Body).is_some() {
                    self.bodies.push(self.levels.len() as u32);
                }
                self.levels.push(BRACE | HIDES);
                self.opaque += 1;
            }
            b'}' => {
                if self.levels.pop_if(|l| *l & BRACE != 0).is_some() {
                    self.opaque -= 1;
                    let index = self.levels.len() as u32;
                    // The innermost scope closes, a function given up inside
                    // the body or the function itself.
                    if self.bodies.pop_if(|b| *b == index).is_some() {
                        step.exit = self.chain.pop();
                    }
                }
            }
            b'[' => {
                let hides = !self.waiting;
                self.levels.push(if hides { HIDES } else { 0 });
                if hides {
                    self.opaque += 1;
                }
            }
            b']' => {
                if let Some(level) = self.levels.pop_if(|l| *l & BRACE == 0)
                    && level & HIDES != 0
                {
                    self.opaque -= 1;
                }
            }
            _ => {}
        }
    }
}

/// Starts a mark in the buffer an [`Emitter`] writes. A zero byte in the text
/// is written as two.
const MARK: u8 = 0;
/// `MARK`, `LITERAL`: a zero byte.
const LITERAL: u8 = 0;
/// A name, then its id: its number if a scope open there declares it, else the
/// name as it is written when not renamed.
const NAME: u8 = 1;
/// A name that follows an identifier byte and does not start with one: a
/// space goes before it if it is renamed.
const NAME_SPACED: u8 = 2;
/// A function scope opens, then its id.
const ENTER: u8 = 3;
/// A function scope closes, then its id.
const EXIT: u8 = 4;
/// A new script begins, then the id of its first scope.
const RESET: u8 = 5;

/// No number: the name is declared by no open scope.
const NONE: u32 = u32::MAX;

fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(buf: &[u8], i: &mut usize) -> u32 {
    let mut v = 0u32;
    let mut shift = 0;
    while let Some(&b) = buf.get(*i) {
        *i += 1;
        v |= u32::from(b & 0x7f) << shift;
        if b < 0x80 {
            break;
        }
        shift += 7;
    }
    v
}

/// `n000`, `n001`…, from the number of a name.
fn put_name(out: &mut Vec<u8>, k: u32) {
    let mut digits = [0u8; 10];
    let mut n = 0;
    let mut v = k;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.push(b'n');
    out.extend(std::iter::repeat_n(b'0', 3usize.saturating_sub(n)));
    out.extend(digits[..n].iter().rev());
}

/// Takes the settled tokens. Names declared in the script are renamed `n000`,
/// `n001`… in the order of their declarations; every other identifier is
/// written as read. A single space separates two tokens only when their
/// touching characters would otherwise merge (two identifier/number chars).
///
/// A name is written as a mark and an id, and `resolve` replaces the marks
/// when the script has ended, because a declaration can come after the use.
struct Emitter {
    /// The output, with a mark for each name and each change of scope.
    buf: Vec<u8>,
    /// Least the output comes to: a name counts as at most the four bytes of
    /// its new name.
    len: usize,
    last: Option<u8>,
    /// A token was left out because the output is full.
    cut: bool,
    scopes: Scopes,
    /// An id for each name that is a use or a declaration.
    ids: HashMap<Box<[u8]>, u32>,
    /// The number each scope gave to a name it declares, by (scope, name id).
    numbers: HashMap<(u32, u32), u32>,
    /// Declarations so far in the script.
    count: u32,
}

impl Emitter {
    fn new() -> Self {
        Emitter {
            buf: Vec::new(),
            len: 0,
            last: None,
            cut: false,
            scopes: Scopes::new(),
            ids: HashMap::new(),
            numbers: HashMap::new(),
            count: 0,
        }
    }

    /// Write `bytes` as text in lower case, as clamscan does, doubling a zero.
    fn text(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.buf.push(b.to_ascii_lowercase());
            if b == MARK {
                self.buf.push(LITERAL);
            }
        }
    }

    fn mark(&mut self, kind: u8, id: u32) {
        self.buf.push(MARK);
        self.buf.push(kind);
        put_varint(&mut self.buf, id);
    }

    fn id_of(&mut self, name: &[u8]) -> u32 {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = self.ids.len() as u32;
        self.ids.insert(name.into(), id);
        id
    }

    fn emit(&mut self, tok: &Tok) {
        if self.cut {
            return;
        }
        if self.len >= MAX_OUTPUT || self.buf.len() >= MAX_BUFFER {
            self.cut = true;
            return;
        }
        let step = self.scopes.feed(tok);
        if step.reset {
            self.count = 0;
            let root = self.scopes.current();
            self.mark(RESET, root);
            return;
        }
        if let Some(scope) = step.enter {
            self.mark(ENTER, scope);
        }
        if let Some(scope) = step.exit {
            self.mark(EXIT, scope);
        }
        let piece: &[u8] = match tok {
            Tok::Ident(name) => {
                self.name(name, step.role);
                return;
            }
            Tok::Space => {
                self.len += 1;
                self.last = Some(b' ');
                self.buf.push(b' ');
                return;
            }
            Tok::Num(s, _) => s,
            Tok::Str(s) | Tok::Value(s) => {
                self.len += s.len() + 2;
                self.last = Some(b'"');
                self.buf.push(b'"');
                self.text(s);
                self.buf.push(b'"');
                return;
            }
            Tok::Punct(b) => std::slice::from_ref(b),
            Tok::Split => return,
        };
        self.space_before(piece.first().copied());
        self.len += piece.len();
        self.last = piece.last().copied();
        self.text(piece);
    }

    /// The list of a `fromCharCode` that was not reduced, as its tokens would
    /// have been written: numbers in decimal, and the trailing `,` if any.
    /// (A literal such as `0x41` was read as one value; it is written as `65`.)
    fn char_codes(&mut self, values: &[u32], want_num: bool) {
        for (k, v) in values.iter().enumerate() {
            if k > 0 {
                self.emit(&Tok::Punct(b','));
            }
            self.emit(&Tok::Num(v.to_string().into_bytes(), None));
        }
        if want_num && !values.is_empty() {
            self.emit(&Tok::Punct(b','));
        }
    }

    /// A space when the byte last written and `first` would merge.
    fn space_before(&mut self, first: Option<u8>) {
        if let (Some(last), Some(first)) = (self.last, first)
            && is_ident(last)
            && is_ident(first)
        {
            self.len += 1;
            self.buf.push(b' ');
        }
    }

    /// An identifier: a mark if a scope can declare it, else as it is written.
    fn name(&mut self, name: &[u8], role: Role) {
        let id = match role {
            Role::Raw => None,
            Role::Use => Some(self.id_of(name)),
            Role::Decl(scope) => {
                let id = self.id_of(name);
                self.numbers.insert((scope, id), self.count);
                self.count += 1;
                Some(id)
            }
        };
        let kept = written(name);
        let first = kept.first().copied();
        match id {
            None => {
                self.space_before(first);
                self.text(&kept);
                self.last = kept.last().copied();
            }
            Some(id) => {
                let kind = match (self.last, first) {
                    (Some(last), Some(first)) if is_ident(last) && !is_ident(first) => NAME_SPACED,
                    _ => {
                        self.space_before(first);
                        NAME
                    }
                };
                self.mark(kind, id);
                // Every name written, kept or not, ends in an identifier byte.
                self.last = Some(b'n');
            }
        }
        self.len += name.len().min(4);
    }

    /// The output: the marks replaced by the names, and whether it was cut.
    fn resolve(self) -> (Vec<u8>, bool) {
        let Emitter {
            buf,
            len,
            mut cut,
            ids,
            numbers,
            ..
        } = self;
        let mut names: Vec<&[u8]> = vec![&[]; ids.len()];
        for (name, &id) in &ids {
            names[id as usize] = name;
        }
        // The numbers each scope gave, by scope.
        let mut by_scope: Vec<(u32, u32, u32)> =
            numbers.into_iter().map(|((s, n), k)| (s, n, k)).collect();
        by_scope.sort_unstable_by_key(|e| e.0);
        let mut seen = Seen {
            by_scope,
            top: vec![NONE; names.len()],
            saved: Vec::new(),
        };
        seen.enter(0);
        let mut out = Vec::with_capacity(len.min(MAX_OUTPUT));
        let mut i = 0;
        while i < buf.len() {
            if out.len() >= MAX_OUTPUT {
                cut = true;
                break;
            }
            let end = buf[i..]
                .iter()
                .position(|&b| b == MARK)
                .map_or(buf.len(), |p| i + p);
            out.extend_from_slice(&buf[i..end]);
            i = end;
            if i >= buf.len() {
                break;
            }
            let kind = buf.get(i + 1).copied().unwrap_or(LITERAL);
            i += 2;
            if kind == LITERAL {
                out.push(MARK);
                continue;
            }
            let id = get_varint(&buf, &mut i);
            match kind {
                NAME | NAME_SPACED => {
                    match seen.top.get(id as usize).copied().filter(|&k| k != NONE) {
                        Some(k) => {
                            if kind == NAME_SPACED {
                                out.push(b' ');
                            }
                            put_name(&mut out, k);
                        }
                        None => {
                            let name = names.get(id as usize).copied().unwrap_or_default();
                            out.extend_from_slice(&written(name));
                        }
                    }
                }
                ENTER => seen.enter(id),
                EXIT => seen.exit(id),
                _ => {
                    seen.exit_all();
                    seen.enter(id);
                }
            }
        }
        cut |= out.len() > MAX_OUTPUT;
        out.truncate(MAX_OUTPUT);
        (out, cut)
    }
}

/// The names the open scopes declare, while the marks are replaced.
struct Seen {
    /// (scope, name id, number) sorted by scope.
    by_scope: Vec<(u32, u32, u32)>,
    /// For each name id, its number in the innermost open scope that declares
    /// it.
    top: Vec<u32>,
    /// What `top` was before each name of the open scopes was set.
    saved: Vec<(u32, u32)>,
}

impl Seen {
    /// The names `scope` declares are now seen.
    fn enter(&mut self, scope: u32) {
        let from = self.by_scope.partition_point(|e| e.0 < scope);
        for &(_, name, k) in self.by_scope[from..].iter().take_while(|e| e.0 == scope) {
            self.saved.push((name, self.top[name as usize]));
            self.top[name as usize] = k;
        }
    }

    /// The names `scope` declares are no longer seen. Scopes close in the
    /// reverse of the order they opened.
    fn exit(&mut self, scope: u32) {
        let from = self.by_scope.partition_point(|e| e.0 < scope);
        let n = self.by_scope[from..]
            .iter()
            .take_while(|e| e.0 == scope)
            .count();
        for _ in 0..n {
            if let Some((name, before)) = self.saved.pop() {
                self.top[name as usize] = before;
            }
        }
    }

    /// Every open scope closes: the script ended.
    fn exit_all(&mut self) {
        while let Some((name, before)) = self.saved.pop() {
            self.top[name as usize] = before;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &[u8]) -> String {
        String::from_utf8_lossy(&normalize(s, Mode::Clamscan).0).into_owned()
    }

    fn decoded(s: &[u8]) -> String {
        String::from_utf8_lossy(&normalize(s, Mode::Decoding).0).into_owned()
    }

    #[test]
    fn output_past_the_cap_is_flagged() {
        let literal = |len: usize| {
            let mut s = b"var s=\"".to_vec();
            s.resize(s.len() + len, b'A');
            s.extend_from_slice(b"\";");
            s
        };
        // `var n000="…";` is 12 bytes around the literal.
        let (out, cut) = normalize(&literal(MAX_OUTPUT - 12), Mode::Clamscan);
        assert_eq!((out.len(), cut), (MAX_OUTPUT, false));
        let (out, cut) = normalize(&literal(MAX_OUTPUT - 11), Mode::Clamscan);
        assert_eq!((out.len(), cut), (MAX_OUTPUT, true));
        // Cut between tokens rather than inside one.
        let (out, cut) = normalize(
            &[literal(MAX_OUTPUT - 12), b"x;".to_vec()].concat(),
            Mode::Clamscan,
        );
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
        for mode in [Mode::Clamscan, Mode::Decoding] {
            let text = Text::Mem(Cow::Borrowed(&script));
            let n = run(text, false, Emitter::new(), mode);
            assert!(n.peak_held < 2 * FLUSH_BATCH, "held {} tokens", n.peak_held);
        }
        // Calls nested deeper than the cap: the outermost are given up.
        let deep = [
            b"unescape(".repeat(100_000),
            b"'%41'".to_vec(),
            b")".repeat(100_000),
        ]
        .concat();
        for mode in [Mode::Clamscan, Mode::Decoding] {
            let n = run(Text::Mem(Cow::Borrowed(&deep)), false, Emitter::new(), mode);
            let bound = 4 * MAX_OPEN_CALLS + FLUSH_BATCH;
            assert!(n.peak_held < bound, "held {} tokens", n.peak_held);
        }
    }

    #[test]
    fn values_join_what_is_around_them() {
        // A reduced call's string joins the strings before and after it.
        assert_eq!(
            decoded(br#"var x="a"+unescape("%42")+"c";"#),
            r#"var n000="abc";"#
        );
        // So do the strings an unrolled eval produces.
        assert_eq!(decoded(br#""a"+eval("'b'")+"c""#), r#""abc""#);
        // An unrolled eval can supply a callee for what follows it.
        assert_eq!(decoded(br#"eval("unescape")("%41")"#), r#""a""#);
    }

    #[test]
    fn a_call_that_cannot_reduce_is_written_as_read() {
        assert_eq!(norm(br#"unescape(("%41"))"#), r#"unescape(("%41"))"#);
        assert_eq!(norm(br#"unescape("%41"+x)"#), r#"unescape("%41"+x)"#);
    }

    #[test]
    fn nesting_is_unrolled_to_the_bottom() {
        // Thirty nested decodes: one repeated fold pass per level would stop
        // short of it.
        let script = [b"unescape(".repeat(30), b"'x'".to_vec(), b")".repeat(30)].concat();
        assert_eq!(decoded(&script), r#""x""#);
    }

    #[test]
    fn decodes_string_escapes() {
        // \x68\x69 → "hi"; A → "a"; octal \101 → "a".
        let out = norm(br#"var a = "\x68\x69A\101";"#);
        assert!(out.contains("\"hiaa\""), "got: {out}");
    }

    #[test]
    fn folds_concatenation() {
        let out = norm(br#"x = "ev"+"i"+'l';"#);
        assert!(out.contains("\"evil\""), "got: {out}");
    }

    #[test]
    fn fromcharcode_is_left_as_written() {
        // clamscan 1.4.3 writes the calls as read, in lower case.
        assert_eq!(
            norm(b"document.write(String.fromCharCode(60,98,62));"),
            "document.write(string.fromcharcode(60,98,62));"
        );
        assert_eq!(
            norm(b"eval(String.fromCharCode(97,108,101,114,116,40,49,41));"),
            "eval(string.fromcharcode(97,108,101,114,116,40,49,41));"
        );
        assert_eq!(
            norm(b"document.write(fromCharCode(60,98));"),
            "document.write(fromcharcode(60,98));"
        );
    }

    #[test]
    fn fromcharcode_is_folded_in_the_decoding_mode_only() {
        let page = b"y = String.fromCharCode(104,116,116,112); z = fromCharCode(0x41,0x42,6_7);";
        assert_eq!(decoded(page), "y=\"http\";z=\"abc\";");
        assert_eq!(
            norm(page),
            "y=string.fromcharcode(104,116,116,112);z=fromcharcode(0 x41,0 x42,6 _7);"
        );
        // The code an `eval` runs.
        assert_eq!(
            decoded(b"eval(String.fromCharCode(97,108,101,114,116,40,49,41))"),
            "alert(1)"
        );
        // Written as read when it cannot be reduced: its numbers in decimal.
        assert_eq!(decoded(b"fromCharCode(0x41,x)"), "fromcharcode(65,x)");
        assert_eq!(decoded(b"fromCharCode(0x41,)"), "fromcharcode(65,)");
        let open = b"String.fromCharCode(65,66";
        assert_eq!(decoded(open), "string.fromcharcode(65,66");
        assert_eq!(decoded(b"String.eval(\"fromCharCode\")(66)"), "\"b\"");
        // A literal followed by a name is not a number to fold.
        assert_eq!(decoded(b"fromCharCode(0x41$)"), "fromcharcode(0 x41$)");
    }

    #[test]
    fn the_values_of_open_fromcharcode_lists_are_bounded() {
        // Past the bound the numbers are written as read, not held.
        let count = MAX_OUTPUT / 4 + 10;
        let script = [
            b"fromCharCode(".to_vec(),
            b"65,".repeat(count),
            b"66)".to_vec(),
        ]
        .concat();
        let (out, cut) = normalize(&script, Mode::Decoding);
        assert!(out.starts_with(b"fromcharcode(65,65,"), "folded");
        assert_eq!(out.len(), 13 + 3 * count + 3);
        assert!(!cut);
    }

    #[test]
    fn decode_uri_is_folded_in_the_decoding_mode_only() {
        let page = br#"a=decodeURI("%41%42"); b=decodeURIComponent("%43");"#;
        assert_eq!(decoded(page), r#"a="ab";b="c";"#);
        let left = r#"a=decodeuri("%41%42");b=decodeuricomponent("%43");"#;
        assert_eq!(norm(page), left);
    }

    #[test]
    fn unescape_nests_in_the_decoding_mode_only() {
        // clamscan reduces the innermost call and leaves the ones around it.
        let page = br#"x=unescape(unescape(unescape("%25252541")));"#;
        assert_eq!(norm(page), r#"x=unescape(unescape("%252541"));"#);
        assert_eq!(decoded(page), r#"x="%41";"#);
        let page = br#"x=unescape(unescape("%2541")+"z"); w=unescape("%2541");"#;
        assert_eq!(norm(page), r#"x=unescape("%41"+"z");w="%41";"#);
        assert_eq!(decoded(page), r#"x="az";w="%41";"#);
        // The value joins no string around it.
        let page = br#"z="a"+unescape("%42")+"c";"#;
        assert_eq!(norm(page), r#"z="a"+"b"+"c";"#);
        assert_eq!(decoded(page), r#"z="abc";"#);
        // An `eval` takes the value.
        let page = br#"eval(unescape("%61%6c%65%72%74%28%31%29"))"#;
        assert_eq!(norm(page), "alert(1)");
        let page = br#"eval(unescape(unescape("%2561")))"#;
        assert_eq!(norm(page), r#"eval(unescape("%61"))"#);
    }

    #[test]
    fn the_cap_counts_the_output_and_the_marks_have_a_bound_of_their_own() {
        // `a;` is two bytes of output and four of buffer (a name is a mark of
        // three bytes): the buffer passes `MAX_OUTPUT` first, which cuts
        // nothing.
        let count = MAX_OUTPUT / 4 + 100_000;
        let (out, cut) = normalize(&b"a;".repeat(count), Mode::Clamscan);
        assert_eq!((out.len(), cut), (2 * count, false));
        // An empty script is a mark and no output: the buffer alone is full.
        let (out, cut) = normalize_scripts(&vec![SPLIT; MAX_BUFFER / 4]);
        assert_eq!((out.len(), cut), (0, true));
    }

    #[test]
    fn decodes_unescape() {
        let out = norm(br#"z = unescape("%68%74%74%70%3a%2f%2f");"#);
        assert!(out.contains("\"http://\""), "got: {out}");
        let u = norm(br#"z = unescape("%u0041%u0042");"#);
        assert!(u.contains("\"ab\""), "got: {u}");
    }

    #[test]
    fn reparses_eval_of_concatenation() {
        // eval("un"+"escape(\"%41\")") → unescape("%41") → "a".
        let out = norm(br#"eval("unescape("+"'%41')");"#);
        assert!(out.contains("\"a\""), "eval not unrolled: {out}");
    }

    /// The scripts of a page as the page view holds them, normalised each on
    /// its own.
    fn page(s: &[u8]) -> String {
        String::from_utf8_lossy(&normalize_scripts(&s.to_vec()).0).into_owned()
    }

    // The expected texts of the tests below are what clamscan 1.4.3 writes
    // for the same scripts.

    #[test]
    fn only_declared_names_are_renamed() {
        assert_eq!(
            norm(b"var a=1; var b=a+2; document.write(b);"),
            "var n000=1;var n001=n000+2;document.write(n001);"
        );
        // `let` and `const` declare nothing.
        assert_eq!(
            norm(b"let a=1; const b=a+2; document.write(b);"),
            "let a=1;const b=a+2;document.write(b);"
        );
    }

    #[test]
    fn names_that_are_kept_are_written_in_lower_case() {
        assert_eq!(
            norm(b"Document.Write(X); var Y=Z;"),
            "document.write(x);var n000=z;"
        );
        // Names differ by case, as in clamscan, before they are written.
        assert_eq!(
            norm(b"var Y=1; var y=2; document.write(Y,y);"),
            "var n000=1;var n001=2;document.write(n000,n001);"
        );
    }

    #[test]
    fn a_name_after_a_dot_is_kept() {
        // A declared name is renamed as an object key, not after a `.`.
        assert_eq!(
            norm(b"var b=1; var o={b:b}; o.b=b; document.write(o.b);"),
            "var n000=1;var n001={n000:n000};n001.b=n000;document.write(n001.b);"
        );
        assert_eq!(
            norm(b"var args=1; f(...args); o?.args;"),
            "var n000=1;f(...args);o?.args;"
        );
    }

    #[test]
    fn numbers_start_at_zero_and_have_no_bound() {
        let script: String = (0..1200).map(|k| format!("var v{k}={k};")).collect();
        let out = norm(script.as_bytes());
        assert!(out.starts_with("var n000=0;var n001=1;"), "{}", &out[..40]);
        assert!(out.contains("var n999=999;var n1000=1000;"));
        assert!(out.ends_with("var n1199=1199;"));
    }

    #[test]
    fn function_names_and_parameters_are_declared() {
        // The name is declared where the function is, not for its callers.
        assert_eq!(
            norm(b"function f(x){return x+1;} var r=f(2); document.write(r);"),
            "function n000(n001){return n001+1;}var n002=f(2);document.write(n002);"
        );
        assert_eq!(
            norm(b"var g=function(x){return x;}; g(1);"),
            "var n000=function(n001){return n001;};n000(1);"
        );
        assert_eq!(
            norm(b"function f(a, b) { return a+b; } function g(c, d) { return c+d; }"),
            "function n000(n001,n002){return n001+n002;}function n003(n004,n005){return n004+n005;}"
        );
    }

    #[test]
    fn a_function_name_is_known_inside_its_function_only() {
        assert_eq!(
            norm(b"var g=function h(x){return h(x);}; g(1); h(2);"),
            "var n000=function n001(n002){return n001(n002);};n000(1);h(2);"
        );
        assert_eq!(
            norm(b"function f(){ function g(){ return f(1); } return g(); } f();"),
            "function n000(){function n001(){return n000(1);}return g();}f();"
        );
    }

    #[test]
    fn a_name_belongs_to_its_function_before_and_after_its_declaration() {
        assert_eq!(
            norm(b"document.write(zz); var zz=3; document.write(zz);"),
            "document.write(n000);var n000=3;document.write(n000);"
        );
        assert_eq!(
            norm(b"function f(a){function g(b){return a+b+c;} var c=1; return g(2);} f(3);"),
            "function n000(n001){function n002(n003){return n001+n003+n004;}var n004=1;return g(2);}f(3);"
        );
        // Not outside it, and a block is no scope.
        assert_eq!(
            norm(b"function f(){var a=1;} document.write(a); if(1){var b=2;} document.write(b);"),
            "function n000(){var n001=1;}document.write(a);if(1){var n002=2;}document.write(n002);"
        );
        assert_eq!(
            norm(b"var a=1; function f(){return a;} function g(){var a=2; return a;} f(); g(); document.write(a);"),
            "var n000=1;function n001(){return n000;}function n002(){var n003=2;return n003;}f();g();document.write(n000);"
        );
    }

    #[test]
    fn a_name_declared_twice_has_the_number_of_the_last() {
        assert_eq!(
            norm(b"var a=1; var a=2; document.write(a);"),
            "var n001=1;var n001=2;document.write(n001);"
        );
        assert_eq!(
            norm(b"function f(a){var a=2; return a;} f(1);"),
            "function n000(n002){var n002=2;return n002;}f(1);"
        );
    }

    #[test]
    fn a_top_level_var_declares_the_name_after_each_comma_to_the_semicolon() {
        // In a call's arguments too, not inside brackets or braces.
        assert_eq!(
            norm(b"var a=f(x,y), b=3, c=[p,q], d; document.write(a,b,c,d,x,y,p,q);"),
            "var n000=f(x,n001),n002=3,n003=[p,q],n004;document.write(n000,n002,n003,n004,x,n001,p,q);"
        );
        assert_eq!(
            norm(b"var a=1, b=2; c=3, d=4; document.write(a,b,c,d);"),
            "var n000=1,n001=2;c=3,d=4;document.write(n000,n001,c,d);"
        );
        // A function body between two names does not end the list.
        assert_eq!(
            norm(b"var a=function(x,y){return x+y;}, b=2; document.write(x);"),
            "var n000=function(n001,n002){return n001+n002;},n003=2;document.write(x);"
        );
    }

    #[test]
    fn inside_braces_a_var_declares_its_first_name_only() {
        assert_eq!(
            norm(b"function f(){var c=1,d=2;} f();"),
            "function n000(){var n001=1,d=2;}f();"
        );
        assert_eq!(
            norm(b"if(1){var a=1,b=2;} var c=1,d=2; document.write(b);"),
            "if(1){var n000=1,b=2;}var n001=1,n002=2;document.write(b);"
        );
    }

    #[test]
    fn reserved_words_are_passed_over_by_a_declaring_comma() {
        assert_eq!(
            norm(b"var a=f(1, new Foo(), typeof zz, this, null); document.write(Foo, zz);"),
            "var n000=f(1,new n001(),typeof n002,this,null);document.write(n001,n002);"
        );
        // `undefined` and `let` are names.
        assert_eq!(
            norm(b"var a=f(1, undefined x); document.write(x);"),
            "var n000=f(1,n001 x);document.write(x);"
        );
        // A `.` ends the wait.
        assert_eq!(
            norm(b"var a=f(1, o.b); document.write(o);"),
            "var n000=f(1,n001.b);document.write(n001);"
        );
    }

    #[test]
    fn a_bracket_right_after_a_declaring_comma_hides_no_comma() {
        assert_eq!(
            norm(b"var a=f(1, [x, y], z); document.write(x,y,z);"),
            "var n000=f(1,[n001,n002],n003);document.write(n001,n002,n003);"
        );
        assert_eq!(
            norm(b"var a=1, b=[x, y], c;"),
            "var n000=1,n001=[x,y],n002;"
        );
    }

    #[test]
    fn only_a_paren_right_after_function_opens_its_parameters() {
        assert_eq!(
            norm(b"var a=f(1, function x); document.write(x);"),
            "var n000=f(1,function n001);document.write(n001);"
        );
    }

    #[test]
    fn a_closing_brace_closes_the_innermost_scope_only() {
        // `function b;` has no body, so its scope is the one `}` closes and the
        // function around it stays open.
        assert_eq!(
            norm(b"function a(x){ function b; var q=1; return x+q; } document.write(x,q); var r=1; document.write(r);"),
            "function n000(n001){function n002;var n003=1;return n001+n003;}document.write(n001,q);var n004=1;document.write(n004);"
        );
    }

    #[test]
    fn each_script_of_a_page_is_numbered_alone() {
        assert_eq!(
            page(b"var a=1;\0var a=2; var b=a; document.write(b,c);\0\0document.write(a,b);function h(x){return x;}"),
            "var n000=1;var n000=2;var n001=n000;document.write(n001,c);document.write(a,b);function n000(n001){return n001;}"
        );
        // One script is not split by its own line breaks being spaces.
        assert_eq!(norm(b"var a=1;\nvar b=2;"), "var n000=1;var n001=2;");
        // A string or a comment left open ends with its script.
        assert_eq!(
            page(b"x=\"open\0var b=1;document.write(b);"),
            "x=\"open\"var n000=1;document.write(n000);"
        );
        assert_eq!(page(b"a //b\0c /* d\0e \\\0f"), "a c e f");
    }

    #[test]
    fn a_name_with_a_unicode_escape_is_one_name_by_its_spelling() {
        assert_eq!(
            norm(b"var \x5cu0061b=1; document.write(\x5cu0061b); x=\x5cu0061b2;"),
            r"var n000=1;document.write(n000);x=\0061b2;"
        );
        // The escaped spelling is not the plain one.
        assert_eq!(
            norm(b"var a=1; var \x5cu0061=5; document.write(a);"),
            "var n000=1;var n001=5;document.write(n000);"
        );
    }

    #[test]
    fn a_line_comment_is_dropped_and_its_text_is_read_as_code() {
        // `// ` leaves the text of the comment.
        assert_eq!(
            norm(b"var a=1; // x y\nvar b=2;"),
            "var n000=1;x y var n001=2;"
        );
        assert_eq!(
            norm(b"var a=1; // x // y z\nvar b=2;"),
            "var n000=1;x y z var n001=2;"
        );
        // `//` and a word right after it go.
        assert_eq!(norm(b"var a=1;//x y\nvar b=2;"), "var n000=1;y var n001=2;");
        assert_eq!(
            norm(b"var a=1; //don't panic\nvar b=2;"),
            "var n000=1;panic var n001=2;"
        );
        assert_eq!(
            norm(b"var a=4,b=2; var x=a//b\n;"),
            "var n000=4,n001=2;var n002=n000;"
        );
        assert_eq!(norm(b"var a=1; //end\n"), "var n000=1;");
        // The words of a comment are tokens: they can open a scope and a block
        // comment.
        assert_eq!(
            norm(b"// function foo(x) {\nvar x; x;"),
            "function n000(n002){var n002;n002;"
        );
        assert_eq!(norm(b"// /* x\nvar a=1; // */\nvar b=2;"), "var n000=2;");
        // So an apostrophe in it opens a string, which a newline does not end.
        assert_eq!(
            norm(b"// don't panic\nvar q=1;\n"),
            "don\"t panic var q=1; \""
        );
    }

    #[test]
    fn a_string_keeps_its_slashes_and_its_newlines_are_spaces() {
        assert_eq!(
            norm(br#"var s="a//b"; var t='http://x.y/z';"#),
            r#"var n000="a//b";var n001="http://x.y/z";"#
        );
        assert_eq!(
            norm(b"var s=\"a\nb\"; var t=1;"),
            "var n000=\"a b\";var n001=1;"
        );
        assert_eq!(
            norm(b"var s=\"a\r\nb\"; var t=1;"),
            "var n000=\"a  b\";var n001=1;"
        );
        assert_eq!(
            norm(b"var s=\"a\\\nb\"; var t=1;"),
            "var n000=\"a b\";var n001=1;"
        );
    }

    #[test]
    fn there_is_no_regular_expression_literal() {
        // A `/` is the operator and a `\` is dropped, so `//` in what is
        // meant as a regexp starts a comment.
        assert_eq!(norm(br"x=/a\/b/;"), "x=/a/b/;");
        assert_eq!(norm(br"x=/\/\//g;"), "x=//");
        assert_eq!(norm(br"x=/\//;y=1;"), "x=/");
        assert_eq!(norm(b"x=/a/ b;"), "x=/a/b;");
        assert_eq!(norm(b"x=/a// b;"), "x=/a b;");
        // A `\` before a name is a space, wherever the comment before that
        // name ends.
        assert_eq!(norm(br"x=/a\.b\d/;y=1;"), "x=/a.b d/;y=1;");
        assert_eq!(norm(br"x=\1;y=2;"), "x= 1;y=2;");
        assert_eq!(norm(b"x=/\\/\\//g; var k=1;"), "x=// var n000=1;");
        assert_eq!(
            norm(br#"var r=/ab+c/g; var s=x.replace(/\s+/g, " ");"#),
            r#"var n000=/ab+c/g;var n001=x.replace(/ n001+/g," ");"#
        );
    }

    #[test]
    fn html_comment_marks_are_read_as_code() {
        assert_eq!(
            norm(b"<!-- first\nvar a=1;\n--> second\nvar b=2;"),
            "<!--first var n000=1;-->second var n001=2;"
        );
    }

    #[test]
    fn a_template_literal_loses_its_backquotes_and_is_read_as_code() {
        assert_eq!(
            norm(b"x=`a b`; y=`c`+`d`; z=a`b`c;"),
            "x=a b;y=c+d;z=a b c;"
        );
        assert_eq!(
            norm(b"var s=`line1\nline2 ${a+1} \"q\" 'r'`; var t=2;"),
            "var n000=line1 line2 ${a+1}\"q\"\"r\";var n001=2;"
        );
        assert_eq!(
            norm(b"var s=`a${`b`}c`; var t=2;"),
            "var n000=a${b}c;var n001=2;"
        );
        // Strings are joined across a `+` only.
        assert_eq!(
            norm(br#"x="a" "b"; y="a"+"b" "c";"#),
            r#"x="a""b";y="ab""c";"#
        );
    }

    #[test]
    fn a_hash_outside_a_string_is_dropped() {
        assert_eq!(norm(b"c=#p; d=e#f; g=1 # h\n;"), "c=p;d=e f;g=1 h;");
        assert_eq!(
            norm(br##"var a="#id"; var b='x#y';"##),
            r##"var n000="#id";var n001="x#y";"##
        );
    }

    #[test]
    fn names_differ_by_case_and_everything_is_written_in_lower_case() {
        assert_eq!(
            norm(b"var Abc=1; var abc=2; document.write(Abc, abc, ABC);"),
            "var n000=1;var n001=2;document.write(n000,n001,abc);"
        );
        assert_eq!(
            norm(br#"var s="ABC Def"; var t='XyZ'; var N=1, n=2; document.write(N+n+s);"#),
            r#"var n000="abc def";var n001="xyz";var n002=1,n003=2;document.write(n002+n003+n000);"#
        );
        // Words with a meaning are told by case too.
        assert_eq!(
            norm(b"VAR a=1; Var b=2; FUNCTION f(x){return x} f(a);"),
            "var a=1;var b=2;function f(x){return x}f(a);"
        );
        assert_eq!(
            norm(b"var NEW, x; var Static y; var STATIC z;"),
            "var n000,n001;var n002 y;var n003 z;"
        );
        assert_eq!(
            norm(br#"Eval(UNESCAPE("%41")); EVAL(unescape("%42"));"#),
            r#"eval(unescape("%41"));eval("b");"#
        );
        assert_eq!(norm(br#"eval("VAR A=1; alert(A)")"#), "var a=1;alert(a)");
    }

    #[test]
    fn a_zero_byte_in_the_text_is_kept() {
        let zero = |s: &[u8]| normalize(s, Mode::Clamscan).0;
        assert_eq!(zero(b"x=\"a\0b\";\0y"), b"x=\"a\0b\";\0y");
        assert_eq!(zero(b"var \0a=1;\0a"), b"var\0n000=1;\0n000");
    }

    /// A number and the letters after it are two tokens (clamscan 1.4.3).
    #[test]
    fn a_number_is_written_apart_from_the_letters_after_it() {
        assert_eq!(
            norm(b"x=[0x1f, 0X1F, 0xFFg, 1e5, 1E5, 1e+5, 1e-5, 1.5e-3, 1.5E+3, 08, 09, 010, 1_000, 50em, 5px, a50, 0b101, 0o17, 5.5px, 5.e3, .5em, 1.5.5, 0x, 0xg];"),
            "x=[0 x1f,0 x1f,0 xffg,1 e5,1 e5,1 e+5,1 e-5,0.0015,1500,8,9,10,1 _000,50 em,5 px,a50,0 b101,0 o17,5.5 px,5000,.5 em,1.5.5,0 x,0 xg];"
        );
        assert_eq!(
            norm(b"x=50em+5px; y=\"width:50em\"; z=a50+b5c+_5x+$5y;"),
            "x=50 em+5 px;y=\"width:50em\";z=a50+b5c+_5x+$5y;"
        );
        assert_eq!(norm(b"x=08+09+010+0777+0128+07a;"), "x=8+9+10+777+128+7 a;");
        assert_eq!(
            norm(b"x=1_000+1__0+0_1+1_+_1;"),
            "x=1 _000+1 __0+0 _1+1 _+_1;"
        );
        // The letters are a name like any other.
        assert_eq!(
            norm(b"var em=1; var x1f=2; x=50em+0x1f; document.write(em);"),
            "var n000=1;var n001=2;x=50 n000+0 n001;document.write(n000);"
        );
        // The same text in the decoding mode.
        assert_eq!(decoded(b"x=50em+0x1f+1e5;"), "x=50 em+0 x1f+1 e5;");
    }

    /// Integers wrap to 32 bits and numbers with a `.` are doubles written as
    /// `%g` writes them, exponents included (clamscan 1.4.3).
    #[test]
    fn integers_wrap_and_doubles_are_written_as_g() {
        assert_eq!(
            norm(b"x=[2147483647, 2147483648, 2147483649, 4294967295, 4294967297, 9223372036854775807, 9223372036854775808, 18446744073709551615, 18446744073709551616];"),
            "x=[2147483647,-2147483648,-2147483647,-1,1,-1,-1,-1,-1];"
        );
        assert_eq!(
            norm(b"x=[1.5e6, 1.5e7, 1.5e10, 1.5e20, 1.5e-4, 1.5e-5, 1.5e-6, 1.5e-7, 1.5e-10, 1.5e-20, 1.5e+300, 1.5e-300];"),
            "x=[1.5e+06,1.5e+07,1.5e+10,1.5e+20,0.00015,1.5e-05,1.5e-06,1.5e-07,1.5e-10,1.5e-20,1.5e+300,1.5e-300];"
        );
        assert_eq!(
            norm(b"x=[1.234567890123, 3.14159265358979, 123456.789, 1234567.891, 0.000001, 0.0000001, 12345678.9, 0.1234567890123456789, 100.0, 1.0000001, 1.00000001];"),
            "x=[1.23457,3.14159,123457,1.23457e+06,1e-06,1e-07,1.23457e+07,0.123457,100,1,1];"
        );
        assert_eq!(
            norm(b"x=[1.5e999, 9.9e307, 1.7976931348623157e308, 123456789.123456789e5];"),
            "x=[inf,9.9e+307,1.79769e+308,1.23457e+13];"
        );
        assert_eq!(
            norm(b"x=[0.1e1, 0.00001e5, 99999.5, 999999.5, 9999995, 0.0001, 0.00001, 123456.5, 123456.4999];"),
            "x=[1,1,99999.5,1e+06,9999995,0.0001,1e-05,123456,123456];"
        );
        assert_eq!(
            norm(b"x=[00123, 0.5, 00.5, 000.50, 0., 0.0, 5.0e0, 5.10e1];"),
            "x=[123,0.5,0.5,0.5,0,0,5,51];"
        );
    }

    /// Where a number with a `.` ends: a `.` after the digits is part of it,
    /// a second one is not, and exponent groups are read when they are empty.
    #[test]
    fn a_number_with_a_dot_ends_where_clamscan_ends_it() {
        assert_eq!(
            norm(b"x=[1..2, 1.a, 1.5a, 1.5.a, 1.5.5.5, .5.5, ..5, 1.e, 1.e5, 1.5e];"),
            "x=[1.2,1 a,1.5 a,1.5.a,1.5.5.5,.5.5,..5,1,100000,1.5];"
        );
        assert_eq!(
            norm(b"x=[1.5ex, 1.5e+, 1.5e+x, 1.e+, 1.ex, 1.5E5x, 1.5e5.5, 5.x, 5.5x, 5..x, 1.5e5e5, 1.5e5e, 0.5e5];"),
            "x=[1.5 x,1.5,1.5 x,1,1 x,150000 x,150000.5,5 x,5.5 x,5.x,150000,150000,50000];"
        );
        assert_eq!(
            norm(b"x=[1.5e5e5e5, 1.5e5e+5, 1.5e5e-, 1.5e5E5, 1.5ee5, 1.5e5ex, 1.5e5e5x, 1.5e5e5.5, 1.5e5+5e5, 1.5e5ee, 1.5e5eee5];"),
            "x=[150000,150000,150000,150000,1.5 e5,150000 x,150000 x,150000.5,150000+5 e5,150000 e,150000 ee5];"
        );
        assert_eq!(
            norm(b"x=[1.5e+5e5, 1.5e-5e5, 1.5e5e5e, 1.5e-e5, 1.5e+e5, 1.5e5-e5, 1.e5e5, 1.e5e, 1.ee5, 1.eee];"),
            "x=[150000,1.5e-05,150000,1.5,1.5,150000-e5,100000,100000,1 e5,1 ee];"
        );
        // A `.` before digits is the operator, then an integer.
        assert_eq!(
            norm(b"x=[.001, .10, .50, .5, .5e5, a.5, a.5b, x.50];"),
            "x=[.1,.10,.50,.5,.5 e5,a.5,a.5 b,x.50];"
        );
        assert_eq!(
            norm(b"x=1.toString()+1.5.toString()+a.b.c+a.1;"),
            "x=1 tostring()+1.5.tostring()+a.b.c+a.1;"
        );
        assert_eq!(
            norm(b"x=5.5em; y=1.5e+3; z=a.5.5e5; w=1.e+;"),
            "x=5.5 m;y=1500;z=a.550000;w=1;"
        );
    }

    #[test]
    fn comment_between_tokens_does_not_separate() {
        // A comment between a (kept) identifier and `(` must not leave a gap.
        let out = norm(b"run/* x */(1)");
        assert!(out.contains("run("), "comment left a gap: {out}");
        // And a comment inside a decode call still decodes the literal argument.
        let d = norm(br#"x = unescape/* c */("%41");"#);
        assert!(d.contains("\"a\""), "got: {d}");
    }

    #[test]
    fn eval_of_decoded_string_unrolls_to_code() {
        // eval(unescape("%41")) → eval("A") → the *code* `A` (canonicalised),
        // i.e. the eval layer is consumed, not left as a literal.
        let out = norm(br#"eval(unescape("%41"))"#);
        assert!(!out.contains("eval("), "eval not unrolled: {out}");
    }

    /// Code wrapped in `layers` of `eval(unescape("..."))`, each layer escaping
    /// the one inside it (`"` and `%` only, so it grows by a few bytes a layer).
    fn evals(layers: usize) -> Vec<u8> {
        let mut code = "'powershell'".to_string();
        for _ in 0..layers {
            let inner = code.replace('%', "%25").replace('"', "%22");
            code = format!("eval(unescape(\"{inner}\"))");
        }
        code.into_bytes()
    }

    /// `eval` layers unroll twenty deep, past the eight they stopped at, down
    /// to the code at the bottom; past the bound of 32 they are left as read.
    #[test]
    fn eval_layers_unroll_twenty_deep_and_stop_past_the_bound() {
        let out = norm(&evals(20));
        assert!(out.contains("powershell"), "{out}");
        assert!(!out.contains("eval"), "a layer was left: {out}");
        let deep = norm(&evals(40));
        assert!(deep.contains("eval"), "unrolled past the bound");
    }

    #[test]
    fn strings_keep_comment_markers() {
        let out = norm(br#"var u = "/*keep*/"; var re = /ab\/cd/g;"#);
        assert!(out.contains("/*keep*/"), "string content lost: {out}");
        assert!(out.contains("/ab/cd/g"), "regex lost: {out}");
    }

    #[test]
    fn no_panic_on_hostile_input() {
        for bad in [
            &b"eval(\"\\"[..],
            &b"'unterminated"[..],
            &b"String.fromCharCode("[..],
            &b"/regex-no-close"[..],
            &b"\\x\\u\\"[..],
            &b"function a(){ function b( { ] } ) }}}]]) var ,,,;;; function ( ( [ \\u00"[..],
            &b"}}}]]]))) function function function((( var var , [ ,"[..],
            &[0u8, 1, 2, 3, 0xff, 0xfe][..],
        ] {
            // Must not panic.
            let _ = normalize(bad, Mode::Clamscan);
            let _ = normalize(bad, Mode::Decoding);
            let _ = page(&[bad, b"\n", bad].concat());
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
            for mode in [Mode::Clamscan, Mode::Decoding] {
                assert_eq!(
                    normalize_source(&cache, mode),
                    normalize(&data, mode),
                    "{mode:?} {:?}",
                    String::from_utf8_lossy(&data[..data.len().min(80)])
                );
            }
        }
    }
}
