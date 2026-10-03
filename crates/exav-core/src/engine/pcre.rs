//! PCRE subsignature patterns rewritten for the Rust engines.
//!
//! ClamAV compiles them with PCRE2 in 8-bit mode, without UTF, with LF as the
//! newline and the default character tables: a pattern character is a byte,
//! and case, `\d`, `\s`, `\w` and the POSIX classes cover ASCII only. `regex`
//! without Unicode and `fancy-regex` in its ASCII bytes mode read some syntax
//! differently (`\v` is a vertical tab there, `\h` a hex digit, `\<` a word
//! boundary, `$` only the end, `[a&&b]` an intersection), so the pattern is
//! parsed with PCRE's grammar and written back in a subset both engines read
//! as PCRE does: every byte as `\xHH`, every class as the explicit set of bytes
//! it matches with case folded in, and anchors spelled out. A construct with
//! no such equivalent is refused, so the signature is reported unsupported
//! rather than matched differently.

/// The options a subsignature's flags give PCRE2 (`i`, `s`, `m`, `x`, `E`,
/// `U`), and those an inline `(?...)` setting changes.
#[derive(Clone, Copy, Default, Debug)]
pub(super) struct Flags {
    pub caseless: bool,
    pub dotall: bool,
    pub multiline: bool,
    pub extended: bool,
    pub extended_more: bool,
    pub no_auto_capture: bool,
    pub ungreedy: bool,
    pub dollar_endonly: bool,
}

/// A set of bytes.
type Set = [u64; 4];

const NONE: Set = [0; 4];
const ALL: Set = [u64::MAX; 4];

fn set_of(f: impl Fn(u8) -> bool) -> Set {
    let mut s = NONE;
    for b in 0..=255u8 {
        if f(b) {
            add(&mut s, b);
        }
    }
    s
}

fn add(s: &mut Set, b: u8) {
    s[usize::from(b >> 6)] |= 1 << (b & 63);
}

fn has(s: &Set, b: u8) -> bool {
    s[usize::from(b >> 6)] & (1 << (b & 63)) != 0
}

fn union(a: &Set, b: &Set) -> Set {
    [a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]]
}

fn not(a: &Set) -> Set {
    [!a[0], !a[1], !a[2], !a[3]]
}

/// `s` with the other case of each ASCII letter in it added.
fn fold(s: &Set) -> Set {
    let mut out = *s;
    for b in 0..=255u8 {
        if has(s, b) && b.is_ascii_alphabetic() {
            add(&mut out, b ^ 0x20);
        }
    }
    out
}

const LF: u8 = 0x0a;

/// `\d`, `\s`, `\w`, `\h`, `\v` in non-UTF mode with the default tables.
fn digit() -> Set {
    set_of(|b| b.is_ascii_digit())
}
fn space() -> Set {
    set_of(|b| matches!(b, 0x09..=0x0d | b' '))
}
fn word() -> Set {
    set_of(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn hspace() -> Set {
    set_of(|b| matches!(b, 0x09 | b' ' | 0xa0))
}
fn vspace() -> Set {
    set_of(|b| matches!(b, 0x0a..=0x0d | 0x85))
}

fn posix(name: &str) -> Option<Set> {
    Some(match name {
        "alnum" => set_of(|b| b.is_ascii_alphanumeric()),
        "alpha" => set_of(|b| b.is_ascii_alphabetic()),
        "ascii" => set_of(|b| b < 0x80),
        "blank" => set_of(|b| b == b' ' || b == b'\t'),
        "cntrl" => set_of(|b| b < 0x20 || b == 0x7f),
        "digit" => digit(),
        "graph" => set_of(|b| (0x21..=0x7e).contains(&b)),
        "lower" => set_of(|b| b.is_ascii_lowercase()),
        "print" => set_of(|b| (0x20..=0x7e).contains(&b)),
        "punct" => set_of(|b| b.is_ascii_punctuation()),
        "space" => space(),
        "upper" => set_of(|b| b.is_ascii_uppercase()),
        "word" => word(),
        "xdigit" => set_of(|b| b.is_ascii_hexdigit()),
        _ => return None,
    })
}

/// The bytes whose code point (as Latin-1) has Unicode property `name`, for
/// `\p`: the general categories and PCRE2's own `X` properties. Under
/// `caseless`, `Lu`, `Ll` and `Lt` mean `Lc`, as from PCRE2 10.45.
fn property(name: &str, caseless: bool) -> Option<Set> {
    // Unicode's loose matching: case, spaces, hyphens and underscores ignored.
    let key: String = name
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '-' | '_'))
        .collect::<String>()
        .to_ascii_lowercase();
    let category = |cat: &str| -> Option<Set> {
        let hir = regex_syntax::ParserBuilder::new()
            .build()
            .parse(&format!(r"\p{{{cat}}}"))
            .ok()?;
        let regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) = hir.kind() else {
            return None;
        };
        Some(set_of(|b| {
            let c = char::from(b);
            class.ranges().iter().any(|r| r.start() <= c && c <= r.end())
        }))
    };
    let key = match key.as_str() {
        "lu" | "ll" | "lt" if caseless => "lc",
        "l&" => "lc",
        k => k,
    };
    match key {
        "any" => Some(ALL),
        "xan" => Some(union(&category("L")?, &category("N")?)),
        "xps" | "xsp" => Some(union(&category("Z")?, &set_of(|b| (0x09..=0x0d).contains(&b)))),
        "xwd" => {
            let an = union(&category("L")?, &category("N")?);
            Some(union(&an, &union(&category("Mn")?, &category("Pc")?)))
        }
        "xuc" => Some(set_of(|b| matches!(b, b'$' | b'@' | b'`') || b >= 0xa0)),
        "c" | "cc" | "cf" | "cn" | "co" | "cs" | "l" | "lc" | "ll" | "lm" | "lo" | "lt" | "lu" | "m"
        | "mc" | "me" | "mn" | "n" | "nd" | "nl" | "no" | "p" | "pc" | "pd" | "pe" | "pf" | "pi"
        | "po" | "ps" | "s" | "sc" | "sk" | "sm" | "so" | "z" | "zl" | "zp" | "zs" => {
            // Surrogates have no code point below 256.
            if key == "cs" {
                return Some(NONE);
            }
            let mut cat = key.to_string();
            cat[..1].make_ascii_uppercase();
            if cat == "Lc" {
                cat = "LC".to_string();
            }
            category(&cat)
        }
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Look {
    Ahead,
    NotAhead,
    Behind,
    NotBehind,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Capture,
    NonCapture,
    Atomic,
    Look(Look),
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Assert {
    /// `\A`, or `^` outside multiline mode.
    Start,
    /// `\z`, or `$` under PCRE2_DOLLAR_ENDONLY.
    End,
    /// `\Z`, or `$` outside multiline mode: the end, or before a final newline.
    EndOrFinalNewline,
    /// `^` in multiline mode: the start, or after a newline that does not end
    /// the subject.
    LineStart,
    /// `$` in multiline mode: before any newline, or the end.
    LineEnd,
    WordBoundary,
    NotWordBoundary,
    /// `[[:<:]]`.
    WordStart,
    /// `[[:>:]]`.
    WordEnd,
}

#[derive(Clone, Debug)]
enum Ref {
    Number(u32),
    Name(String),
}

#[derive(Clone, Debug)]
enum Node {
    /// One byte of the set.
    Bytes(Set),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Group(Kind, Box<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        mode: Mode,
    },
    Backref {
        target: Ref,
        caseless: bool,
    },
    Assert(Assert),
    /// `\R`, kept apart because a lookbehind may not contain it.
    Newline,
    Fail,
    /// `\K`.
    KeepOut,
    /// `(?(n)yes|no)` or `(?(?=..)yes|no)`.
    Cond {
        group: Option<Ref>,
        look: Option<Box<Node>>,
        yes: Box<Node>,
        no: Option<Box<Node>>,
    },
}

const EMPTY_SEQ: fn() -> Node = || Node::Seq(Vec::new());

/// The longest a lookbehind branch of variable length may match: PCRE2's
/// default (`PCRE2_MAX_VARLOOKBEHIND`).
const MAX_VAR_LOOKBEHIND: u32 = 255;
/// How deep groups may nest.
const MAX_DEPTH: usize = 250;

struct Parser {
    p: Vec<char>,
    i: usize,
    groups: u32,
    names: Vec<(String, u32)>,
}

type Res<T> = Result<T, &'static str>;

/// `pattern` as `regex` and `fancy-regex` read it the way ClamAV's PCRE2 does
/// under `flags`, or why it has no such form.
pub(super) fn translate(pattern: &str, flags: Flags) -> Res<String> {
    let mut parser = Parser {
        p: pattern.chars().collect(),
        i: 0,
        groups: 0,
        names: Vec::new(),
    };
    parser.start_items()?;
    let mut f = flags;
    let node = parser.alternation(&mut f, 0)?;
    if parser.i < parser.p.len() {
        return Err("PCRE: unmatched closing parenthesis");
    }
    parser.check(&node, false)?;
    let mut out = String::new();
    parser.emit(&node, true, &mut out)?;
    Ok(out)
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.p.get(self.i).copied()
    }

    fn peek_at(&self, k: usize) -> Option<char> {
        self.p.get(self.i + k).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_str(&mut self, s: &str) -> bool {
        let n = s.chars().count();
        if self.p[self.i.min(self.p.len())..].iter().take(n).copied().eq(s.chars()) {
            self.i += n;
            true
        } else {
            false
        }
    }

    /// The `(*...)` items allowed only at the start of a pattern. Those that
    /// tune PCRE2's optimizations or limits change no answer and are dropped;
    /// the others change what the pattern means and are refused.
    fn start_items(&mut self) -> Res<()> {
        const KEEP: [&str; 6] = [
            "NO_AUTO_POSSESS",
            "NO_START_OPT",
            "NO_DOTSTAR_ANCHOR",
            "NO_JIT",
            "LF",
            "BSR_UNICODE",
        ];
        const LIMITS: [&str; 4] = ["LIMIT_HEAP=", "LIMIT_MATCH=", "LIMIT_DEPTH=", "LIMIT_RECURSION="];
        const REFUSE: [&str; 13] = [
            "UTF",
            "UCP",
            "CRLF",
            "CR",
            "ANYCRLF",
            "ANY",
            "NUL",
            "BSR_ANYCRLF",
            "NOTEMPTY_ATSTART",
            "NOTEMPTY",
            "CASELESS_RESTRICT",
            "TURKISH_CASING",
            "LIMIT_",
        ];
        loop {
            let rest: String = self.p[self.i..].iter().take(40).collect();
            let Some(body) = rest.strip_prefix("(*") else {
                return Ok(());
            };
            let Some(close) = body.find(')') else {
                return Ok(());
            };
            let item = &body[..close];
            if KEEP.contains(&item)
                || LIMITS
                    .iter()
                    .any(|l| item.strip_prefix(l).is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())))
            {
                self.i += 2 + item.chars().count() + 1;
            } else if REFUSE.iter().any(|r| item == *r || (r.ends_with('_') && item.starts_with(r))) {
                return Err("PCRE: a (*...) option at the start of the pattern");
            } else {
                return Ok(());
            }
        }
    }

    /// Skip what PCRE2_EXTENDED ignores: white space and `#` comments.
    fn skip_extended(&mut self, f: &Flags) {
        if !f.extended {
            return;
        }
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r') => self.i += 1,
                Some('#') => {
                    while let Some(c) = self.next() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn alternation(&mut self, f: &mut Flags, depth: usize) -> Res<Node> {
        if depth > MAX_DEPTH {
            return Err("PCRE: groups nested too deep");
        }
        let mut alts = vec![self.sequence(f, depth)?];
        while self.eat('|') {
            alts.push(self.sequence(f, depth)?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap_or_else(EMPTY_SEQ) } else { Node::Alt(alts) })
    }

    fn sequence(&mut self, f: &mut Flags, depth: usize) -> Res<Node> {
        let mut items = Vec::new();
        loop {
            self.skip_extended(f);
            if matches!(self.peek(), None | Some('|' | ')')) {
                break;
            }
            let Some(atom) = self.atom(f, &mut items, depth)? else {
                continue;
            };
            self.skip_extended(f);
            match self.quantifier(f)? {
                None => items.push(atom),
                Some((min, max, mode)) => items.push(repeat(atom, min, max, mode)?),
            }
        }
        Ok(if items.len() == 1 { items.pop().unwrap_or_else(EMPTY_SEQ) } else { Node::Seq(items) })
    }

    /// A brace quantifier at the current position (on its `{`): its bounds and
    /// how many characters it spans, or `None` when the brace is a literal.
    fn brace(&self) -> Res<Option<(u32, Option<u32>, usize)>> {
        let mut j = self.i + 1;
        let ws = |j: &mut usize| {
            while matches!(self.p.get(*j), Some(' ' | '\t')) {
                *j += 1;
            }
        };
        let num = |j: &mut usize| -> Option<u64> {
            let start = *j;
            while self.p.get(*j).is_some_and(char::is_ascii_digit) {
                *j += 1;
            }
            (*j > start).then(|| {
                self.p[start..*j]
                    .iter()
                    .fold(0u64, |n, c| (n * 10 + u64::from(*c as u8 - b'0')).min(u64::from(u32::MAX)))
            })
        };
        ws(&mut j);
        let lo = num(&mut j);
        ws(&mut j);
        let (hi, comma) = if self.p.get(j) == Some(&',') {
            j += 1;
            ws(&mut j);
            let hi = num(&mut j);
            ws(&mut j);
            (hi, true)
        } else {
            (lo, false)
        };
        if self.p.get(j) != Some(&'}') || (lo.is_none() && hi.is_none()) || (lo.is_none() && !comma) {
            return Ok(None);
        }
        let min = lo.unwrap_or(0);
        if min > 65535 || hi.is_some_and(|h| h > 65535) {
            return Err("PCRE: number too big in {} quantifier");
        }
        if hi.is_some_and(|h| h < min) {
            return Err("PCRE: numbers out of order in {} quantifier");
        }
        Ok(Some((min as u32, hi.map(|h| h as u32), j + 1 - self.i)))
    }

    fn quantifier(&mut self, f: &Flags) -> Res<Option<(u32, Option<u32>, Mode)>> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.i += 1;
                (0, None)
            }
            Some('+') => {
                self.i += 1;
                (1, None)
            }
            Some('?') => {
                self.i += 1;
                (0, Some(1))
            }
            Some('{') => match self.brace()? {
                Some((min, max, len)) => {
                    self.i += len;
                    (min, max)
                }
                None => return Ok(None),
            },
            _ => return Ok(None),
        };
        let mode = if self.eat('?') {
            Mode::Lazy
        } else if self.eat('+') {
            Mode::Possessive
        } else {
            Mode::Greedy
        };
        let mode = match (mode, f.ungreedy) {
            (Mode::Greedy, true) => Mode::Lazy,
            (Mode::Lazy, true) => Mode::Greedy,
            (m, _) => m,
        };
        let again = match self.peek() {
            Some('*' | '+' | '?') => true,
            Some('{') => self.brace()?.is_some(),
            _ => false,
        };
        if again {
            return Err("PCRE: quantifier does not follow a repeatable item");
        }
        Ok(Some((min, max, mode)))
    }

    /// One item of a sequence, the one a quantifier would repeat. Items before
    /// it that a quantifier cannot reach (all but the last byte of a non-ASCII
    /// character, all but the last character of `\Q...\E`) go to `items`.
    fn atom(&mut self, f: &mut Flags, items: &mut Vec<Node>, depth: usize) -> Res<Option<Node>> {
        let Some(c) = self.next() else {
            return Ok(None);
        };
        Ok(match c {
            '\\' => self.escape(f, items)?,
            '[' => {
                if self.eat_str("[:<:]]") {
                    Some(Node::Assert(Assert::WordStart))
                } else if self.eat_str("[:>:]]") {
                    Some(Node::Assert(Assert::WordEnd))
                } else {
                    Some(Node::Bytes(self.class(f)?))
                }
            }
            '(' => self.group(f, depth)?,
            '.' => Some(Node::Bytes(if f.dotall { ALL } else { not(&set_of(|b| b == LF)) })),
            '^' => Some(Node::Assert(if f.multiline { Assert::LineStart } else { Assert::Start })),
            '$' => Some(Node::Assert(if f.multiline {
                Assert::LineEnd
            } else if f.dollar_endonly {
                Assert::End
            } else {
                Assert::EndOrFinalNewline
            })),
            '*' | '+' | '?' => return Err("PCRE: quantifier does not follow a repeatable item"),
            '{' => {
                self.i -= 1;
                let quantifier = self.brace()?.is_some();
                self.i += 1;
                if quantifier {
                    return Err("PCRE: quantifier does not follow a repeatable item");
                }
                Some(literal(b'{', f))
            }
            c => literal_char(c, f, items)?,
        })
    }

    /// A character given by number or name in an escape, in or out of a class.
    fn char_escape(&mut self, c: char) -> Res<Option<u8>> {
        Ok(Some(match c {
            'a' => 0x07,
            'e' => 0x1b,
            'f' => 0x0c,
            'n' => 0x0a,
            'r' => 0x0d,
            't' => 0x09,
            'c' => {
                let x = self.next().ok_or("PCRE: \\c at end of pattern")?;
                if !(' '..='~').contains(&x) {
                    return Err("PCRE: \\c must be followed by a printable ASCII character");
                }
                (x.to_ascii_uppercase() as u8) ^ 0x40
            }
            'o' => {
                if !self.eat('{') {
                    return Err("PCRE: \\o must be followed by {");
                }
                let v = self.braced_number(8)?;
                byte(v)?
            }
            'x' => {
                if self.eat('{') {
                    let v = self.braced_number(16)?;
                    byte(v)?
                } else {
                    let mut v = 0u32;
                    let mut n = 0;
                    while n < 2 && self.peek().is_some_and(|d| d.is_ascii_hexdigit()) {
                        v = v * 16 + self.next().and_then(|d| d.to_digit(16)).unwrap_or(0);
                        n += 1;
                    }
                    if n == 0 {
                        return Err("PCRE: \\x must be followed by a hex digit or {");
                    }
                    v as u8
                }
            }
            _ => return Ok(None),
        }))
    }

    /// The digits of `\x{...}` or `\o{...}` after the brace, through the
    /// closing one.
    fn braced_number(&mut self, radix: u32) -> Res<u32> {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.i += 1;
        }
        let mut v: u32 = 0;
        let mut n = 0;
        while let Some(d) = self.peek().and_then(|d| d.to_digit(radix)) {
            v = v.saturating_mul(radix).saturating_add(d);
            self.i += 1;
            n += 1;
        }
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.i += 1;
        }
        if n == 0 || !self.eat('}') {
            return Err("PCRE: malformed \\x{...} or \\o{...}");
        }
        Ok(v)
    }

    /// A character type escape (`\d`, `\h`, `\p{..}`, ...) in or out of a class.
    fn type_escape(&mut self, c: char, f: &Flags) -> Res<Option<Set>> {
        Ok(Some(match c {
            'd' => digit(),
            'D' => not(&digit()),
            's' => space(),
            'S' => not(&space()),
            'w' => word(),
            'W' => not(&word()),
            'h' => hspace(),
            'H' => not(&hspace()),
            'v' => vspace(),
            'V' => not(&vspace()),
            'p' | 'P' => {
                let (name, negated) = if self.eat('{') {
                    let negated = self.eat('^');
                    let start = self.i;
                    while self.peek().is_some_and(|c| c != '}') {
                        self.i += 1;
                    }
                    if !self.eat('}') {
                        return Err("PCRE: malformed \\p{...}");
                    }
                    (self.p[start..self.i - 1].iter().collect::<String>(), negated)
                } else {
                    (self.next().ok_or("PCRE: \\p at end of pattern")?.to_string(), false)
                };
                let s = property(&name, f.caseless).ok_or("PCRE: a \\p property other than a general category")?;
                if negated != (c == 'P') {
                    not(&s)
                } else {
                    s
                }
            }
            _ => return Ok(None),
        }))
    }

    /// The escape after a `\` outside a class.
    fn escape(&mut self, f: &mut Flags, items: &mut Vec<Node>) -> Res<Option<Node>> {
        let c = self.next().ok_or("PCRE: \\ at end of pattern")?;
        if let Some(b) = self.char_escape(c)? {
            return Ok(Some(literal(b, f)));
        }
        if let Some(s) = self.type_escape(c, f)? {
            return Ok(Some(Node::Bytes(s)));
        }
        Ok(Some(match c {
            '0' => {
                self.i -= 1;
                let v = self.octal(3);
                literal(byte(v)?, f)
            }
            '1'..='9' => {
                let start = self.i - 1;
                while self.peek().is_some_and(|d| d.is_ascii_digit()) {
                    self.i += 1;
                }
                let digits: String = self.p[start..self.i].iter().collect();
                let n: u32 = digits.parse().unwrap_or(u32::MAX);
                if n < 10 || c == '8' || c == '9' || n <= self.groups {
                    Node::Backref {
                        target: Ref::Number(n),
                        caseless: f.caseless,
                    }
                } else {
                    self.i = start;
                    let v = self.octal(3);
                    literal(byte(v)?, f)
                }
            }
            'N' => {
                if self.peek() == Some('{') {
                    return Err("PCRE: \\N{U+...} needs UTF mode");
                }
                Node::Bytes(not(&set_of(|b| b == LF)))
            }
            'R' => Node::Newline,
            'C' => Node::Bytes(ALL),
            'X' => return Err("PCRE: \\X"),
            'b' => Node::Assert(Assert::WordBoundary),
            'B' => Node::Assert(Assert::NotWordBoundary),
            'A' => Node::Assert(Assert::Start),
            'z' => Node::Assert(Assert::End),
            'Z' => Node::Assert(Assert::EndOrFinalNewline),
            'G' => return Err("PCRE: \\G"),
            'K' => Node::KeepOut,
            'E' => return Ok(None),
            'Q' => {
                let mut quoted = Vec::new();
                while self.peek().is_some() && !self.eat_str("\\E") {
                    quoted.push(self.next().unwrap_or_default());
                }
                let Some(last) = quoted.pop() else {
                    return Ok(None);
                };
                for q in quoted {
                    if let Some(n) = literal_char(q, f, items)? {
                        items.push(n);
                    }
                }
                return literal_char(last, f, items);
            }
            'g' => {
                if matches!(self.peek(), Some('<' | '\'')) {
                    return Err("PCRE: a subroutine call");
                }
                let braced = self.eat('{');
                let start = self.i;
                while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-')) {
                    self.i += 1;
                }
                let id: String = self.p[start..self.i].iter().collect();
                if braced && !self.eat('}') {
                    return Err("PCRE: malformed \\g");
                }
                Node::Backref {
                    target: self.reference(&id)?,
                    caseless: f.caseless,
                }
            }
            'k' => {
                let close = match self.next() {
                    Some('<') => '>',
                    Some('\'') => '\'',
                    Some('{') => '}',
                    _ => return Err("PCRE: malformed \\k"),
                };
                let name = self.name(close)?;
                Node::Backref {
                    target: Ref::Name(name),
                    caseless: f.caseless,
                }
            }
            c if c.is_ascii_alphanumeric() => return Err("PCRE: an unrecognized escape"),
            c => return literal_char(c, f, items),
        }))
    }

    /// Up to `max` octal digits from the current position.
    fn octal(&mut self, max: usize) -> u32 {
        let mut v = 0;
        let mut n = 0;
        while n < max {
            match self.peek().and_then(|d| d.to_digit(8)) {
                Some(d) => {
                    v = v * 8 + d;
                    self.i += 1;
                    n += 1;
                }
                None => break,
            }
        }
        v
    }

    /// A group reference written as a number, a signed (relative) number, or
    /// a name.
    fn reference(&self, id: &str) -> Res<Ref> {
        if let Some(n) = id.strip_prefix('-') {
            let n: u32 = n.parse().map_err(|_| "PCRE: malformed group reference")?;
            if n == 0 || n > self.groups {
                return Err("PCRE: reference to a non-existent group");
            }
            Ok(Ref::Number(self.groups + 1 - n))
        } else if let Some(n) = id.strip_prefix('+') {
            let n: u32 = n.parse().map_err(|_| "PCRE: malformed group reference")?;
            if n == 0 {
                return Err("PCRE: reference to a non-existent group");
            }
            Ok(Ref::Number(self.groups + n))
        } else if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Ref::Number(id.parse().map_err(|_| "PCRE: malformed group reference")?))
        } else if !id.is_empty() {
            Ok(Ref::Name(id.to_string()))
        } else {
            Err("PCRE: malformed group reference")
        }
    }

    /// A group name up to its `close` delimiter.
    fn name(&mut self, close: char) -> Res<String> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            self.i += 1;
        }
        let name: String = self.p[start..self.i].iter().collect();
        if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) || name.len() > 128 || !self.eat(close) {
            return Err("PCRE: malformed group name");
        }
        Ok(name)
    }

    /// A character class, after its `[`.
    fn class(&mut self, f: &Flags) -> Res<Set> {
        let negated = self.eat('^');
        let mut set = NONE;
        let mut first = true;
        // Characters of a `\Q...\E` still to be taken as items.
        let mut quoted: Vec<u8> = Vec::new();
        loop {
            let item = if let Some(b) = (!quoted.is_empty()).then(|| quoted.remove(0)) {
                Item::Byte(b)
            } else {
                if f.extended_more {
                    while matches!(self.peek(), Some(' ' | '\t')) {
                        self.i += 1;
                    }
                }
                let c = self.next().ok_or("PCRE: missing terminating ] for character class")?;
                if c == ']' && !first {
                    break;
                }
                first = false;
                match c {
                    '[' => match self.peek() {
                        Some(':') => match self.posix_class()? {
                            Some(s) => Item::Set(s),
                            None => Item::Byte(b'['),
                        },
                        Some('.' | '=') if self.posix_like() => return Err("PCRE: POSIX collating elements"),
                        _ => Item::Byte(b'['),
                    },
                    '\\' => {
                        let e = self.next().ok_or("PCRE: \\ at end of pattern")?;
                        if let Some(b) = self.char_escape(e)? {
                            Item::Byte(b)
                        } else if let Some(s) = self.type_escape(e, f)? {
                            Item::Set(s)
                        } else {
                            match e {
                                '0'..='7' => {
                                    self.i -= 1;
                                    Item::Byte(byte(self.octal(3))?)
                                }
                                '8' | '9' => Item::Byte(e as u8),
                                'b' => Item::Byte(0x08),
                                'E' => Item::None,
                                'Q' => {
                                    while self.peek().is_some() && !self.eat_str("\\E") {
                                        let q = self.next().unwrap_or_default();
                                        let mut buf = [0u8; 4];
                                        quoted.extend_from_slice(q.encode_utf8(&mut buf).as_bytes());
                                    }
                                    Item::None
                                }
                                e if e.is_ascii_alphanumeric() => return Err("PCRE: an unrecognized escape in a class"),
                                e => self.class_char(e)?,
                            }
                        }
                    }
                    c => self.class_char(c)?,
                }
            };
            match item {
                Item::None => {}
                Item::Set(s) => {
                    if self.peek() == Some('-') && !matches!(self.peek_at(1), Some(']') | None) {
                        return Err("PCRE: invalid range in character class");
                    }
                    set = union(&set, &s);
                }
                Item::Byte(lo) => {
                    if quoted.is_empty() && self.peek() == Some('-') && !matches!(self.peek_at(1), Some(']') | None) {
                        self.i += 1;
                        let hi = match self.next() {
                            Some('\\') => {
                                let e = self.next().ok_or("PCRE: \\ at end of pattern")?;
                                if let Some(b) = self.char_escape(e)? {
                                    b
                                } else {
                                    match e {
                                        '0'..='7' => {
                                            self.i -= 1;
                                            byte(self.octal(3))?
                                        }
                                        '8' | '9' => e as u8,
                                        'b' => 0x08,
                                        e if e.is_ascii_alphanumeric() => {
                                            return Err("PCRE: invalid range in character class")
                                        }
                                        e => ascii(e)?,
                                    }
                                }
                            }
                            Some('[') if self.peek() == Some(':') && self.posix_like() => {
                                return Err("PCRE: invalid range in character class")
                            }
                            Some(c) => ascii(c)?,
                            None => return Err("PCRE: missing terminating ] for character class"),
                        };
                        if hi < lo {
                            return Err("PCRE: range out of order in character class");
                        }
                        for b in lo..=hi {
                            add(&mut set, b);
                        }
                    } else {
                        add(&mut set, lo);
                    }
                }
            }
        }
        if f.caseless {
            set = fold(&set);
        }
        Ok(if negated { not(&set) } else { set })
    }

    /// A literal character in a class: a byte, or the bytes of a non-ASCII
    /// character, each its own member.
    fn class_char(&mut self, c: char) -> Res<Item> {
        if c == '\u{fffd}' {
            return Err("PCRE: a byte the database text did not keep");
        }
        if c.is_ascii() {
            return Ok(Item::Byte(c as u8));
        }
        if self.peek() == Some('-') && !matches!(self.peek_at(1), Some(']') | None) {
            return Err("PCRE: a range from a non-ASCII character");
        }
        let mut buf = [0u8; 4];
        Ok(Item::Set(c.encode_utf8(&mut buf).bytes().fold(NONE, |mut s, b| {
            add(&mut s, b);
            s
        })))
    }

    /// Whether `[` (already read) starts `[:...:]`, `[.....]` or `[=...=]`.
    fn posix_like(&self) -> bool {
        let Some(open) = self.peek() else {
            return false;
        };
        let mut j = self.i + 1;
        while let Some(&c) = self.p.get(j) {
            if c == open && self.p.get(j + 1) == Some(&']') {
                return true;
            }
            if c == ']' || c == '\\' || c == '[' {
                return false;
            }
            j += 1;
        }
        false
    }

    /// A POSIX class after `[` with the `:` next, or `None` when the `[` is
    /// a literal.
    fn posix_class(&mut self) -> Res<Option<Set>> {
        if !self.posix_like() {
            return Ok(None);
        }
        self.i += 1;
        let negated = self.eat('^');
        let start = self.i;
        while self.peek() != Some(':') {
            self.i += 1;
        }
        let name: String = self.p[start..self.i].iter().collect();
        self.i += 2;
        let s = posix(&name).ok_or("PCRE: unknown POSIX class name")?;
        Ok(Some(if negated { not(&s) } else { s }))
    }

    /// A group, after its `(`.
    fn group(&mut self, f: &mut Flags, depth: usize) -> Res<Option<Node>> {
        if self.eat_str("?#") {
            while let Some(c) = self.next() {
                if c == ')' {
                    return Ok(None);
                }
            }
            return Err("PCRE: missing ) after (?# comment");
        }
        if self.eat('*') {
            return self.verb(f, depth).map(Some);
        }
        if !self.eat('?') {
            let kind = if f.no_auto_capture { Kind::NonCapture } else { Kind::Capture };
            return self.group_body(kind, f, depth).map(Some);
        }
        let Some(c) = self.next() else {
            return Err("PCRE: missing ) after (?");
        };
        Ok(Some(match c {
            ':' => self.group_body(Kind::NonCapture, f, depth)?,
            '>' => self.group_body(Kind::Atomic, f, depth)?,
            '=' => self.group_body(Kind::Look(Look::Ahead), f, depth)?,
            '!' => self.group_body(Kind::Look(Look::NotAhead), f, depth)?,
            '<' => {
                if self.eat('=') {
                    self.group_body(Kind::Look(Look::Behind), f, depth)?
                } else if self.eat('!') {
                    self.group_body(Kind::Look(Look::NotBehind), f, depth)?
                } else if self.peek() == Some('*') {
                    return Err("PCRE: a non-atomic assertion");
                } else {
                    self.named_group('>', f, depth)?
                }
            }
            '\'' => self.named_group('\'', f, depth)?,
            'P' => match self.next() {
                Some('<') => self.named_group('>', f, depth)?,
                Some('=') => Node::Backref {
                    target: Ref::Name(self.name(')')?),
                    caseless: f.caseless,
                },
                _ => return Err("PCRE: a subroutine call"),
            },
            '(' => self.conditional(f, depth)?,
            '|' => return Err("PCRE: a branch reset group"),
            '*' => return Err("PCRE: a non-atomic assertion"),
            '&' | 'R' | '0'..='9' => return Err("PCRE: a subroutine call"),
            '+' => return Err("PCRE: a subroutine call"),
            '-' if self.peek().is_some_and(|d| d.is_ascii_digit()) => return Err("PCRE: a subroutine call"),
            'C' => return Err("PCRE: a callout"),
            '[' => return Err("PCRE: a Perl extended character class"),
            _ => {
                self.i -= 1;
                return self.options(f, depth);
            }
        }))
    }

    /// `(?<name>...)`, after the opening delimiter.
    fn named_group(&mut self, close: char, f: &Flags, depth: usize) -> Res<Node> {
        let name = self.name(close)?;
        if self.names.iter().any(|(n, _)| *n == name) {
            return Err("PCRE: a duplicate group name");
        }
        self.names.push((name, self.groups + 1));
        self.group_body(Kind::Capture, f, depth)
    }

    fn group_body(&mut self, kind: Kind, f: &Flags, depth: usize) -> Res<Node> {
        if kind == Kind::Capture {
            self.groups += 1;
        }
        let mut inner = *f;
        let body = self.alternation(&mut inner, depth + 1)?;
        if !self.eat(')') {
            return Err("PCRE: missing )");
        }
        Ok(Node::Group(kind, Box::new(body)))
    }

    /// An option setting, `(?flags)` or `(?flags:...)`, after its `(?`.
    fn options(&mut self, f: &mut Flags, depth: usize) -> Res<Option<Node>> {
        let mut g = *f;
        if self.eat('^') {
            g.caseless = false;
            g.multiline = false;
            g.no_auto_capture = false;
            g.dotall = false;
            g.extended = false;
            g.extended_more = false;
        }
        let mut on = true;
        loop {
            match self.next().ok_or("PCRE: missing ) after (?")? {
                ')' => {
                    *f = g;
                    return Ok(None);
                }
                ':' => return self.group_body(Kind::NonCapture, &g, depth).map(Some),
                '-' if on => on = false,
                'i' => g.caseless = on,
                'm' => g.multiline = on,
                'n' => g.no_auto_capture = on,
                's' => g.dotall = on,
                'U' => g.ungreedy = on,
                'x' => {
                    if on && self.eat('x') {
                        g.extended = true;
                        g.extended_more = true;
                    } else {
                        g.extended = on;
                        if !on {
                            g.extended_more = false;
                        }
                    }
                }
                // Meaningful only with UTF or UCP, or allowing duplicate names,
                // which a duplicate name is refused for anyway.
                'J' | 'r' => {}
                'a' => {
                    while matches!(self.peek(), Some('D' | 'S' | 'W' | 'P' | 'T')) {
                        self.i += 1;
                    }
                }
                _ => return Err("PCRE: an unrecognized character after (? or (?-"),
            }
        }
    }

    /// `(*...)`, after its `(*`.
    fn verb(&mut self, f: &Flags, depth: usize) -> Res<Node> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
            self.i += 1;
        }
        let word: String = self.p[start..self.i].iter().collect();
        if self.eat(':') {
            let look = match word.as_str() {
                "atomic" => Some(Kind::Atomic),
                "pla" | "positive_lookahead" => Some(Kind::Look(Look::Ahead)),
                "nla" | "negative_lookahead" => Some(Kind::Look(Look::NotAhead)),
                "plb" | "positive_lookbehind" => Some(Kind::Look(Look::Behind)),
                "nlb" | "negative_lookbehind" => Some(Kind::Look(Look::NotBehind)),
                _ => None,
            };
            if let Some(kind) = look {
                return self.group_body(kind, f, depth);
            }
            if matches!(word.as_str(), "FAIL" | "F") {
                while self.peek().is_some_and(|c| c != ')') {
                    self.i += 1;
                }
            }
        }
        if !self.eat(')') {
            return Err("PCRE: a backtracking control verb or (*...) group");
        }
        match word.as_str() {
            "FAIL" | "F" => Ok(Node::Fail),
            _ => Err("PCRE: a backtracking control verb or (*...) group"),
        }
    }

    /// A conditional group, after its `(?(`.
    fn conditional(&mut self, f: &Flags, depth: usize) -> Res<Node> {
        let (group, look) = if self.eat('?') {
            let kind = match self.next() {
                Some('=') => Look::Ahead,
                Some('!') => Look::NotAhead,
                Some('<') if self.eat('=') => Look::Behind,
                Some('<') if self.eat('!') => Look::NotBehind,
                _ => return Err("PCRE: a conditional other than on a group or an assertion"),
            };
            (None, Some(Box::new(self.group_body(Kind::Look(kind), f, depth)?)))
        } else {
            let id = if self.eat('<') {
                self.name('>')?
            } else if self.eat('\'') {
                self.name('\'')?
            } else {
                let start = self.i;
                while self.peek().is_some_and(|c| c.is_ascii_digit() || c == '+' || c == '-') {
                    self.i += 1;
                }
                let id: String = self.p[start..self.i].iter().collect();
                if id.is_empty() || !self.eat(')') {
                    return Err("PCRE: a conditional other than on a group or an assertion");
                }
                id
            };
            if id.chars().next().is_some_and(|c| !c.is_ascii_digit() && c != '+' && c != '-') && !self.eat(')') {
                return Err("PCRE: malformed conditional");
            }
            (Some(self.reference(&id)?), None)
        };
        let mut inner = *f;
        let body = self.alternation(&mut inner, depth + 1)?;
        if !self.eat(')') {
            return Err("PCRE: missing )");
        }
        let (yes, no) = match body {
            Node::Alt(mut alts) => {
                if alts.len() > 2 {
                    return Err("PCRE: a conditional group with more than two branches");
                }
                let no = alts.pop().map(Box::new);
                (Box::new(alts.pop().unwrap_or_else(EMPTY_SEQ)), no)
            }
            body => (Box::new(body), None),
        };
        Ok(Node::Cond { group, look, yes, no })
    }

    /// The group number `target` names.
    fn resolve(&self, target: &Ref) -> Res<u32> {
        let n = match target {
            Ref::Number(n) => *n,
            Ref::Name(name) => self
                .names
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, g)| *g)
                .ok_or("PCRE: reference to a non-existent group name")?,
        };
        if n == 0 || n > self.groups {
            return Err("PCRE: reference to a non-existent group");
        }
        Ok(n)
    }

    /// What PCRE2 refuses at compile time that the parse lets through:
    /// references to missing groups, `\K` in an assertion, and lookbehinds
    /// whose length is unbounded or past PCRE2's limits.
    fn check(&self, node: &Node, in_look: bool) -> Res<()> {
        match node {
            Node::Seq(v) | Node::Alt(v) => v.iter().try_for_each(|n| self.check(n, in_look)),
            Node::Group(kind, body) => {
                let look = matches!(kind, Kind::Look(_));
                if let Kind::Look(Look::Behind | Look::NotBehind) = kind {
                    let branches: Vec<&Node> = match body.as_ref() {
                        Node::Alt(v) => v.iter().collect(),
                        b => vec![b],
                    };
                    for b in branches {
                        let (lo, hi) = self.length(b).ok_or("PCRE: a lookbehind whose length is not bounded")?;
                        if hi > 65535 || (lo != hi && hi > MAX_VAR_LOOKBEHIND) {
                            return Err("PCRE: a lookbehind longer than PCRE2 allows");
                        }
                    }
                }
                self.check(body, in_look || look)
            }
            Node::Repeat { node, .. } => self.check(node, in_look),
            Node::Backref { target, .. } => self.resolve(target).map(|_| ()),
            Node::KeepOut if in_look => Err("PCRE: \\K in an assertion"),
            Node::Cond { group, look, yes, no } => {
                if let Some(g) = group {
                    self.resolve(g)?;
                }
                if let Some(l) = look {
                    self.check(l, in_look)?;
                }
                self.check(yes, in_look)?;
                no.as_ref().map_or(Ok(()), |n| self.check(n, in_look))
            }
            _ => Ok(()),
        }
    }

    /// The fewest and most bytes `node` can match, for a lookbehind: `None`
    /// when unbounded, or when it holds what a lookbehind may not.
    fn length(&self, node: &Node) -> Option<(u32, u32)> {
        Some(match node {
            Node::Bytes(_) => (1, 1),
            Node::Seq(v) => v.iter().try_fold((0u32, 0u32), |(lo, hi), n| {
                let (a, b) = self.length(n)?;
                Some((lo.saturating_add(a), hi.saturating_add(b)))
            })?,
            Node::Alt(v) => v.iter().try_fold((u32::MAX, 0u32), |(lo, hi), n| {
                let (a, b) = self.length(n)?;
                Some((lo.min(a), hi.max(b)))
            })?,
            Node::Group(Kind::Look(_), _) | Node::Assert(_) | Node::Fail => (0, 0),
            Node::Group(_, body) => self.length(body)?,
            Node::Repeat { node, min, max, .. } => {
                let (a, b) = self.length(node)?;
                (a.saturating_mul(*min), b.saturating_mul((*max)?))
            }
            Node::Backref { .. } | Node::Newline | Node::KeepOut | Node::Cond { .. } => return None,
        })
    }

    fn emit(&self, node: &Node, tail: bool, out: &mut String) -> Res<()> {
        match node {
            Node::Bytes(s) => emit_set(s, out),
            Node::Seq(v) => {
                for (k, n) in v.iter().enumerate() {
                    self.emit(n, tail && k + 1 == v.len(), out)?;
                }
            }
            Node::Alt(v) => {
                out.push_str("(?:");
                for (k, n) in v.iter().enumerate() {
                    if k > 0 {
                        out.push('|');
                    }
                    self.emit(n, tail, out)?;
                }
                out.push(')');
            }
            Node::Group(kind, body) => {
                let (open, inner_tail) = match kind {
                    Kind::Capture => ("(", tail),
                    Kind::NonCapture => ("(?:", tail),
                    Kind::Atomic => ("(?>", tail),
                    Kind::Look(Look::Ahead) => ("(?=", true),
                    Kind::Look(Look::NotAhead) => ("(?!", true),
                    Kind::Look(Look::Behind) => ("(?<=", false),
                    Kind::Look(Look::NotBehind) => ("(?<!", false),
                };
                out.push_str(open);
                self.emit(body, inner_tail, out)?;
                out.push(')');
            }
            Node::Repeat { node, min, max, mode } => {
                let bounds = match max {
                    Some(m) if m == min => format!("{{{min}}}"),
                    Some(m) => format!("{{{min},{m}}}"),
                    None => format!("{{{min},}}"),
                };
                let inner_tail = tail && max.is_some_and(|m| m <= 1);
                if *mode == Mode::Possessive {
                    out.push_str("(?>");
                }
                out.push_str("(?:");
                self.emit(node, inner_tail, out)?;
                out.push(')');
                out.push_str(&bounds);
                match mode {
                    Mode::Lazy => out.push('?'),
                    Mode::Possessive => out.push(')'),
                    Mode::Greedy => {}
                }
            }
            Node::Backref { target, caseless } => {
                let n = self.resolve(target)?;
                if *caseless {
                    out.push_str(&format!(r"(?i:\k<{n}>)"));
                } else {
                    out.push_str(&format!(r"\k<{n}>"));
                }
            }
            Node::Assert(a) => out.push_str(match a {
                Assert::Start => r"\A",
                Assert::End => r"\z",
                // Consuming the newline moves no match's start, and at the end
                // of the pattern nothing after it sees the difference.
                Assert::EndOrFinalNewline if tail => r"(?:\x0a?\z)",
                Assert::EndOrFinalNewline => r"(?=\x0a?\z)",
                Assert::LineStart => r"(?:\A|(?<=\x0a)(?=[\x00-\xff]))",
                Assert::LineEnd => r"(?m:$)",
                Assert::WordBoundary => r"\b",
                Assert::NotWordBoundary => r"\B",
                Assert::WordStart => r"\b(?=[0-9A-Z_a-z])",
                Assert::WordEnd => r"\b(?<=[0-9A-Z_a-z])",
            }),
            Node::Newline => out.push_str(r"(?>\x0d\x0a|[\x0a-\x0d\x85])"),
            Node::Fail => out.push_str("(?!)"),
            Node::KeepOut => out.push_str(r"\K"),
            Node::Cond { group, look, yes, no } => {
                out.push_str("(?(");
                match (group, look) {
                    (Some(g), _) => out.push_str(&self.resolve(g)?.to_string()),
                    (None, Some(l)) => self.emit(l, false, out)?,
                    (None, None) => return Err("PCRE: malformed conditional"),
                }
                out.push(')');
                self.emit(yes, false, out)?;
                if let Some(no) = no {
                    out.push('|');
                    self.emit(no, false, out)?;
                }
                out.push(')');
            }
        }
        Ok(())
    }
}

/// A class item: one byte, which may start a range, a set, or nothing (`\E`).
enum Item {
    Byte(u8),
    Set(Set),
    None,
}

/// `node` repeated, as PCRE2 allows: never a simple assertion, and a
/// lookaround as many times as it takes, once or not at all.
fn repeat(node: Node, min: u32, max: Option<u32>, mode: Mode) -> Res<Node> {
    match node {
        Node::Assert(_) | Node::Fail | Node::KeepOut => Err("PCRE: quantifier does not follow a repeatable item"),
        Node::Group(Kind::Look(_), _) if min >= 1 => Ok(node),
        Node::Group(Kind::Look(_), ref body) => {
            if captures(body) {
                Err("PCRE: an optional assertion with capture groups")
            } else {
                Ok(EMPTY_SEQ())
            }
        }
        node => Ok(Node::Repeat {
            node: Box::new(node),
            min,
            max,
            mode,
        }),
    }
}

fn captures(node: &Node) -> bool {
    match node {
        Node::Group(Kind::Capture, _) => true,
        Node::Group(_, b) => captures(b),
        Node::Seq(v) | Node::Alt(v) => v.iter().any(captures),
        Node::Repeat { node, .. } => captures(node),
        Node::Cond { look, yes, no, .. } => {
            look.as_deref().is_some_and(captures) || captures(yes) || no.as_deref().is_some_and(captures)
        }
        _ => false,
    }
}

fn byte(v: u32) -> Res<u8> {
    u8::try_from(v).map_err(|_| "PCRE: a character value above 0xff without UTF")
}

fn ascii(c: char) -> Res<u8> {
    if c == '\u{fffd}' {
        Err("PCRE: a byte the database text did not keep")
    } else if c.is_ascii() {
        Ok(c as u8)
    } else {
        Err("PCRE: a range to a non-ASCII character")
    }
}

/// A literal byte: itself, or both cases of an ASCII letter under `caseless`.
fn literal(b: u8, f: &Flags) -> Node {
    let mut s = NONE;
    add(&mut s, b);
    Node::Bytes(if f.caseless { fold(&s) } else { s })
}

/// A literal pattern character: its UTF-8 bytes as consecutive literals, the
/// last returned (the one a quantifier repeats) and the others pushed.
fn literal_char(c: char, f: &Flags, items: &mut Vec<Node>) -> Res<Option<Node>> {
    if c == '\u{fffd}' {
        return Err("PCRE: a byte the database text did not keep");
    }
    let mut buf = [0u8; 4];
    let bytes = c.encode_utf8(&mut buf).as_bytes();
    let (last, rest) = bytes.split_last().ok_or("PCRE: empty character")?;
    for b in rest {
        items.push(literal(*b, f));
    }
    Ok(Some(literal(*last, f)))
}

fn emit_set(s: &Set, out: &mut String) {
    let n: u32 = s.iter().map(|w| w.count_ones()).sum();
    if n == 0 {
        out.push_str(r"[^\x00-\xff]");
        return;
    }
    if n == 1 {
        let b = (0..=255u8).find(|&b| has(s, b)).unwrap_or(0);
        out.push_str(&format!(r"\x{b:02x}"));
        return;
    }
    out.push('[');
    let mut b = 0u16;
    while b < 256 {
        if has(s, b as u8) {
            let lo = b;
            while b + 1 < 256 && has(s, (b + 1) as u8) {
                b += 1;
            }
            if lo == b {
                out.push_str(&format!(r"\x{lo:02x}"));
            } else {
                out.push_str(&format!(r"\x{lo:02x}-\x{b:02x}"));
            }
        }
        b += 1;
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(s: &str) -> Flags {
        Flags {
            caseless: s.contains('i'),
            dotall: s.contains('s'),
            multiline: s.contains('m'),
            extended: s.contains('x'),
            dollar_endonly: s.contains('E'),
            ungreedy: s.contains('U'),
            ..Default::default()
        }
    }

    /// Whether `pattern` under `flags` matches `hay` once translated. When the
    /// linear engine takes the translation, the backtracking one must agree
    /// with it: the subset is read the same by both.
    fn matches(pattern: &str, f: &str, hay: &[u8]) -> bool {
        let t = translate(pattern, flags(f)).unwrap_or_else(|e| panic!("/{pattern}/{f}: {e}"));
        let fancy = crate::fancy_regex::RegexBuilder::new(&t)
            .bytes_mode(crate::fancy_regex::BytesMode::Ascii)
            .build()
            .unwrap_or_else(|e| panic!("/{pattern}/{f} as {t}: {e}"));
        let backtracking = fancy.is_match(hay).unwrap();
        if let Ok(linear) = regex::bytes::RegexBuilder::new(&t).unicode(false).build() {
            assert_eq!(linear.is_match(hay), backtracking, "/{pattern}/{f} as {t}: the engines disagree");
        }
        backtracking
    }

    /// Each answer is clamscan 1.5.4's for a logical signature with this PCRE
    /// subsignature on these bytes.
    #[test]
    fn matches_as_clamav() {
        let cases: &[(&str, &str, &[u8], bool)] = &[
            // Bytes, not UTF-8 characters.
            (r"\xe9t\xe9", "", b"MARK \xe9t\xe9 \n", true),
            (r"\xe9t\xe9", "", b"MARK \xc3\xa9t\xc3\xa9 \n", false),
            (r"\x{e9}t", "", b"MARK \xe9t \n", true),
            (r"x\x9y", "", b"MARKx\x09y", true),
            (r"a.b", "", b"MARK a\xffb \n", true),
            (r"a.b", "", b"MARK a\xc3\xa9b \n", false),
            (r"a..b", "", b"MARK a\xc3\xa9b \n", true),
            (r"a.b", "", b"MARK a\nb \n", false),
            (r"a.b", "s", b"MARK a\nb \n", true),
            (r"a.b", "", b"MARKa\rb", true),
            (r"a.b", "", b"MARKa\x85b", true),
            // Case and classes over ASCII only.
            (r"abc", "i", b"MARK ABC \n", true),
            (r"\xc9t", "i", b"MARK \xe9t \n", false),
            (r"\xc9t", "i", b"MARK \xc9t \n", true),
            (r"x[[:lower:]]y", "i", b"MARKxAy", true),
            (r"x[[:upper:]]y", "i", b"MARKxay", true),
            (r"x[^a]y", "i", b"MARKxAy", false),
            (r"a\wb", "", b"MARK a\xe9b \n", false),
            (r"a\Wb", "", b"MARK a\xe9b \n", true),
            (r"a\sb", "", b"MARK a\xa0b \n", false),
            (r"a\sb", "", b"MARK a\x85b \n", false),
            (r"a\sb", "", b"MARK a\x0bb \n", true),
            (r"a\db", "", b"MARK a\xb2b \n", false),
            (r"x[^a]y", "", b"MARK x\xffy \n", true),
            (r"x[\x80-\xff]y", "", b"MARK x\xe9y \n", true),
            (r"x[\x80-\xff]y", "", b"MARK x\xc3\xa9y \n", false),
            (r"\bfoo", "", b"MARK \xe9foo \n", true),
            (r"a[[:alpha:]]b", "", b"MARK a\xe9b \n", false),
            (r"a[[:print:]]b", "", b"MARK a\xe9b \n", false),
            // Class syntax PCRE reads literally.
            (r"x[a&&b]y", "", b"MARKx&y", true),
            (r"x[a~~b]y", "", b"MARKx~y", true),
            (r"x[a[b]y", "", b"MARKx[]y", false),
            (r"x[]a]y", "", b"MARKx]y", true),
            (r"[W-]46]", "", b"MARK-46]", true),
            (r"x[a-c-e]y", "", b"MARKx-y", true),
            (r"x[\b]y", "", b"MARKx\x08y", true),
            (r"x[^\x00-\xff]?y", "", b"MARKxy", true),
            (r"x[\0]y", "", b"MARKx\x00y", true),
            // Octal and other escapes.
            (r"x[\22]y", "", b"MARK x\x12y \n", true),
            (r"x[\2d]y", "", b"MARK x\x02y \n", true),
            (r"x[\2d]y", "", b"MARK xdy \n", true),
            (r"x\022y", "", b"MARK x\x12y \n", true),
            (r"x\0y", "", b"MARK x\x00y \n", true),
            (r"\o{101}", "", b"MARKZAxxxxxxxx", true),
            (r"x\cAy", "", b"MARKx\x01y", true),
            (r"\Qa.b\E", "", b"MARKa.b", true),
            (r"\Qa.b\E", "", b"MARKaxb", false),
            (r"\<rel", "", b"MARK <rel \n", true),
            (r"\<rel", "", b"MARK  rel \n", false),
            (r"a\>", "", b"MARK a> \n", true),
            (r"a\Nb", "s", b"MARKa\nb", false),
            (r"a\Rb", "", b"MARKa\r\nb", true),
            (r"a\Rb", "", b"MARKa\x85b", true),
            (r"a\hb", "", b"MARKa\xa0b", true),
            (r"a\hb", "", b"MARKa5b", false),
            (r"a\vb", "", b"MARKa\x85b", true),
            (r"a\vb", "", b"MARKa\x0bb", true),
            (r"a\Cb", "", b"MARKa\nb", true),
            (r"a\p{L}b", "", b"MARKa\xe9b", true),
            (r"a\p{N}b", "", b"MARKa\xb2b", true),
            // Anchors.
            (r"^foo", "", b"MARK \nfoo \n", false),
            (r"^foo", "m", b"MARK \nfoo \n", true),
            (r"foo$", "", b"MARK foo\n \n", false),
            (r"svg>$", "", b"MARK </svg>\n", true),
            (r"svg>$", "", b"MARK </svg>", true),
            (r"svg>$", "", b"MARK </svg>\n\n", false),
            (r"svg>$", "m", b"MARK </svg>\nmore", true),
            (r"svg>$", "", b"MARK </svg>\nmore", false),
            (r"(?=s)svg>$", "", b"MARK </svg>\n", true),
            (r"(ab)\1$", "s", b"MARK abab\n", true),
            (r"a[$]b", "", b"MARK a$b \n", true),
            (r"foo$", "E", b"MARKfoo\n", false),
            (r"foo\Z", "", b"MARKfoo\n\n", false),
            (r"foo\Z", "", b"MARKfoo\n", true),
            (r"foo$\n", "", b"MARKfoo\n", true),
            (r"\n^", "m", b"MARKfoo\n", false),
            (r"\n^f", "m", b"MARKx\nfoo", true),
            (r"[[:<:]]foo", "", b"MARK foo", true),
            // Quantifiers, groups and options.
            (r"xa{,2}y", "", b"MARKxaay", true),
            (r"x{y", "", b"MARKx{y", true),
            (r"x{,}y", "", b"MARKx{,}y", true),
            (r"xa{ 2 , 3 }y", "", b"MARKxaay", true),
            (r"a++a", "", b"MARKaaa", false),
            (r"(?>a+)a", "", b"MARKaaa", false),
            (r"(?=a){2}a", "", b"MARKa", true),
            (r"a b # comment", "x", b"MARKab", true),
            (r"x[ ]y", "x", b"MARKx y", true),
            (r"(?xx)x[ a]y", "", b"MARKx y", false),
            (r"(?n)(a)(?<q>b)\k<q>", "", b"MARKabb", true),
            (r"a(?#hi)b", "", b"MARKab", true),
            (r"a(*FAIL)|b", "", b"MARKbxxxxxxxx", true),
            (r"(a)?(?(1)b|c)", "", b"MARKcxxxxxxx", true),
            // Lookaround and back references.
            (r"(?<=\xe9)t", "", b"MARK \xe9t \n", true),
            (r"t(?=\xe9)", "", b"MARK t\xe9 \n", true),
            (r"(\xe9)x\1", "", b"MARK \xe9x\xe9 \n", true),
            (r"(ab)x\1", "i", b"MARK abxAB \n", true),
            (r"(?=a)a.b", "", b"MARK a\xffb \n", true),
            (r"(?=\xc9)\xc9t", "i", b"MARK \xe9t \n", false),
            (r"(?=a)a\wb", "", b"MARK a\xe9b \n", false),
            (r"(?=f)\bfoo", "", b"MARK \xe9foo \n", true),
            (r"(?=x)x[^a]y", "", b"MARK x\xffy \n", true),
            (r"(?<=a|bc)d", "", b"MARKbcd", true),
            (r"(?<=ab?)c", "", b"MARKac", true),
            (r"(a)(b)\g{-2}", "", b"MARKaba", true),
            (r"(a)\g1", "", b"MARKaa", true),
            (r"(?<n>a)\k{n}", "", b"MARKaa", true),
            (r"(a|(b))\2", "", b"MARKa", false),
        ];
        for &(pattern, f, hay, want) in cases {
            assert_eq!(matches(pattern, f, hay), want, "/{pattern}/{f} on {hay:?}");
        }
    }

    /// `U` swaps greedy and lazy.
    #[test]
    fn ungreedy_swaps_quantifiers() {
        assert_eq!(translate("a+", flags("U")).unwrap(), r"(?:\x61){1,}?");
        assert_eq!(translate("a+?", flags("U")).unwrap(), r"(?:\x61){1,}");
        assert_eq!(translate("a++", flags("U")).unwrap(), r"(?>(?:\x61){1,})");
    }

    /// What PCRE2 refuses to compile, and what PCRE2 runs that has no exact
    /// form here: refused either way.
    #[test]
    fn refuses_what_it_cannot_reproduce() {
        for pattern in [
            // PCRE2 compile errors.
            r"x[\d-z]y",
            r"(?<=a+)b",
            r"(?:\2b|(a))+",
            r"(?<n>a)|(?<n>b)",
            concat!(r"\", "u0041"),
            r"\b*a",
            r"a**",
            r"[[.a.]]",
            r"\N{U+41}",
            r"\x{100}",
            r"(a)\2",
            r"\k<nope>",
            r"(?<=\Ka)",
            r"[z-a]",
            r"(",
            r")",
            r"[a",
            // No exact equivalent.
            r"\X",
            r"\G",
            r"(?|(a)|(b))",
            r"a(*ACCEPT)b",
            r"(*UTF)a",
            r"(*CR)a.b",
            r"(a)(?1)",
            r"\((?:[^()]|(?R))*\)",
            r"\g<1>",
            r"(?C1)a",
            r"\p{Greek}",
            r"(?(R)a)",
            r"(?(DEFINE)a)",
            "a\u{fffd}b",
        ] {
            assert!(translate(pattern, Flags::default()).is_err(), "{pattern} was accepted");
        }
    }

    /// The start-of-pattern items that only tune PCRE2 are dropped.
    #[test]
    fn drops_tuning_items() {
        assert_eq!(translate("(*NO_JIT)(*LIMIT_MATCH=10)ab", Flags::default()).unwrap(), r"\x61\x62");
    }
}
