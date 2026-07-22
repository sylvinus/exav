//! Lowering of the borrowed parser AST into the owned, `'static` IR.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use yara_x_parser::ast::AST;
use yara_x_parser::ast::{
    Expr, Ident, Item, MatchAnchor, MetaValue, NAryExpr, Pattern, PatternModifier, PatternSet,
    Quantifier, Range, RuleFlags,
};

use crate::yara::atoms::{self, Gate, PatternGate};
use crate::yara::base64::base64_patterns;
use crate::yara::error::{Error, Result};
use crate::yara::ir::{
    Access, Anchor, ArithOp, CmpOp, CompiledRegex, Cond, ExternalType, IntKind, Iter, OfItems,
    Quant, StrOp, Value,
};
use crate::yara::matcher::{
    build_regex, build_wide_regex, widen, Base64SubDef, Needle, PatternDef, PatternMatcher,
};
use crate::yara::modules::{self, FieldName, ModuleKind, SchemaNode};
use crate::yara::scanner::{CompiledRule, Rules};

/// The value/type of a host-supplied external variable, mirroring yara-x's
/// `Variable`. Passed to [`Compiler::define_external`] to DECLARE an external
/// (only its variant — i.e. its type — is significant there; the concrete value
/// used during a scan is supplied separately via `Scanner::set_global`) and to
/// `Scanner::set_global` to SET its value for a scan.
#[derive(Debug, Clone, PartialEq)]
pub enum ExternalValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

impl From<i64> for ExternalValue {
    fn from(v: i64) -> Self {
        ExternalValue::Int(v)
    }
}
impl From<f64> for ExternalValue {
    fn from(v: f64) -> Self {
        ExternalValue::Float(v)
    }
}
impl From<bool> for ExternalValue {
    fn from(v: bool) -> Self {
        ExternalValue::Bool(v)
    }
}
impl From<&str> for ExternalValue {
    fn from(v: &str) -> Self {
        ExternalValue::Str(v.to_string())
    }
}
impl From<String> for ExternalValue {
    fn from(v: String) -> Self {
        ExternalValue::Str(v)
    }
}

impl ExternalValue {
    /// The declared type this value implies.
    pub(crate) fn ty(&self) -> ExternalType {
        match self {
            ExternalValue::Int(_) => ExternalType::Int,
            ExternalValue::Float(_) => ExternalType::Float,
            ExternalValue::Bool(_) => ExternalType::Bool,
            ExternalValue::Str(_) => ExternalType::Str,
        }
    }

    /// The runtime value this external carries when set for a scan.
    pub(crate) fn into_value(self) -> Value {
        match self {
            ExternalValue::Int(i) => Value::Int(i),
            ExternalValue::Float(f) => Value::Float(f),
            ExternalValue::Bool(b) => Value::Bool(b),
            ExternalValue::Str(s) => Value::Str(s.into_bytes()),
        }
    }
}

/// The standard external variables a THOR/signature-base-style scanner supplies
/// about the file being scanned. All are STRING-typed. Pre-declared by
/// [`Compiler::new`] so the ~10% of signature-base rules that reference them
/// compile out of the box; their per-scan values are set via
/// `Scanner::set_global` (see `YaraDb::scan`).
pub const STANDARD_EXTERNALS: [&str; 5] =
    ["filename", "filepath", "extension", "filetype", "owner"];

/// Incrementally compiles one or more YARA sources into a [`Rules`] set.
#[derive(Default)]
pub struct Compiler {
    patterns: Vec<PatternMatcher>,
    /// Per-pattern serializable definition (index == global pattern id), kept in
    /// lockstep with `patterns`. Carried into [`Rules`] so the compiled rule set
    /// can be serialized and later recompiled without re-parsing the sources.
    defs: Vec<PatternDef>,
    /// Per-pattern prefilter gate (index == global pattern id), kept in lockstep
    /// with `patterns` and consumed by [`PatternGate::from_gates`] in `build`.
    atom_gates: Vec<Gate>,
    pattern_names: Vec<String>,
    rules: Vec<CompiledRule>,
    rule_index: HashMap<String, usize>,
    imported: Vec<ModuleKind>,
    uses_entrypoint: bool,
    /// Declared external variables (name -> type). A bare identifier that
    /// resolves to one of these lowers to `Cond::External`; identifiers matching
    /// no declared external remain compile errors (matching yara-x).
    externals: HashMap<String, ExternalType>,
}

/// A pattern local to the rule being compiled.
struct LocalPat {
    /// The pattern name with its `$` sigil stripped (empty for anonymous `$`).
    key: String,
    id: usize,
}

impl Compiler {
    pub fn new() -> Self {
        let mut c = Self::default();
        // Pre-declare the standard scanner externals (all STRING) so rules that
        // reference them compile without the host having to declare them.
        for name in STANDARD_EXTERNALS {
            c.externals.insert(name.to_string(), ExternalType::Str);
        }
        c
    }

    /// Declares a host-supplied external variable (mirrors yara-x's
    /// `Compiler::define_global`). Only the *type* of `value` is recorded here;
    /// the concrete value used during a scan is supplied via
    /// `Scanner::set_global`. After this call, a bare identifier `name` in a rule
    /// condition compiles to a reference resolved at scan time (undefined until
    /// set). Re-declaring an existing external replaces its type.
    pub fn define_external(&mut self, name: &str, value: impl Into<ExternalValue>) -> &mut Self {
        self.externals.insert(name.to_string(), value.into().ty());
        self
    }

    /// Compiles the rules in `src` and appends them to this compiler. Later
    /// sources may reference rules defined in earlier ones. Returns an error on
    /// the first parse error or unsupported construct.
    pub fn add_source(&mut self, src: &str) -> Result<&mut Self> {
        let ast = AST::from(src);
        if let Some(err) = ast.errors().first() {
            return Err(Error::new(format!("parse error: {err:?}")));
        }

        for item in ast.items() {
            match item {
                Item::Rule(rule) => self.compile_rule(rule)?,
                Item::Import(import) => {
                    // Track imported modules so their values are only built for
                    // rule sets that use them. Unknown modules are rejected.
                    let kind = ModuleKind::from_name(import.module_name).ok_or_else(|| {
                        Error::unsupported(format!("module `{}`", import.module_name))
                    })?;
                    if !self.imported.contains(&kind) {
                        self.imported.push(kind);
                    }
                }
                Item::Include(_) => {
                    return Err(Error::unsupported("include statement"));
                }
            }
        }
        Ok(self)
    }

    /// Like [`add_source`](Self::add_source), but compiles each rule in `src`
    /// **independently**: a rule that fails to compile (an unsupported
    /// construct, an unknown module, etc.) is skipped and recorded rather than
    /// aborting the rest of the source. `import` statements still apply to all
    /// following rules, and later rules may still reference earlier ones that
    /// compiled successfully.
    ///
    /// Returns the rejected items as `(name, error)` pairs, where `name` is the
    /// rule identifier (or `import <module>` / `include` for those items). A
    /// parse error — which prevents recovering any rules at all — is returned
    /// as a single rejection with an empty name.
    ///
    /// This exists so a single unsupported rule in a large third-party feed does
    /// not silently drop the whole feed: every dropped rule is accounted for in
    /// the returned list.
    pub fn add_source_lenient(&mut self, src: &str) -> Vec<(String, Error)> {
        let mut rejected = Vec::new();
        let ast = AST::from(src);
        if let Some(err) = ast.errors().first() {
            rejected.push((String::new(), Error::new(format!("parse error: {err:?}"))));
            return rejected;
        }

        for item in ast.items() {
            match item {
                Item::Rule(rule) => {
                    // Snapshot the accumulators so a rule that fails partway
                    // through (e.g. after its patterns were pushed but its
                    // condition failed to lower) leaves no orphan state behind.
                    let pat_len = self.patterns.len();
                    let name_len = self.pattern_names.len();
                    let rules_len = self.rules.len();
                    if let Err(e) = self.compile_rule(rule) {
                        self.patterns.truncate(pat_len);
                        self.defs.truncate(pat_len);
                        self.atom_gates.truncate(pat_len);
                        self.pattern_names.truncate(name_len);
                        self.rules.truncate(rules_len);
                        rejected.push((rule.identifier.name.to_string(), e));
                    }
                }
                Item::Import(import) => match ModuleKind::from_name(import.module_name) {
                    Some(kind) => {
                        if !self.imported.contains(&kind) {
                            self.imported.push(kind);
                        }
                    }
                    None => rejected.push((
                        format!("import {}", import.module_name),
                        Error::unsupported(format!("module `{}`", import.module_name)),
                    )),
                },
                Item::Include(_) => rejected.push((
                    "include".to_string(),
                    Error::unsupported("include statement"),
                )),
            }
        }
        rejected
    }

    /// Finalizes compilation.
    pub fn build(self) -> Rules {
        let gate = PatternGate::from_gates(&self.atom_gates);
        Rules {
            patterns: self.patterns,
            defs: self.defs,
            pattern_names: self.pattern_names,
            rules: self.rules,
            imported: self.imported,
            uses_entrypoint: self.uses_entrypoint,
            gate,
        }
    }

    fn compile_rule(&mut self, rule: &yara_x_parser::ast::Rule) -> Result<()> {
        let name = rule.identifier.name.to_string();
        let private = rule.flags.contains(RuleFlags::Private);
        let global = rule.flags.contains(RuleFlags::Global);

        // Compile patterns, assigning global ids.
        let mut locals: Vec<LocalPat> = Vec::new();
        let mut pattern_ids: Vec<usize> = Vec::new();
        if let Some(patterns) = &rule.patterns {
            for pat in patterns {
                let (matcher, gate, def) = compile_pattern(pat)?;
                let id = self.patterns.len();
                let full_name = pat.identifier().name.to_string();
                let key = strip_sigil(&full_name).to_string();
                self.patterns.push(matcher);
                self.defs.push(def);
                self.atom_gates.push(gate);
                self.pattern_names.push(full_name);
                locals.push(LocalPat { key, id });
                pattern_ids.push(id);
            }
        }

        // Collect the rule's metadata identifiers (not evaluated, but exposed).
        let meta: Vec<(String, String)> = rule
            .meta
            .as_ref()
            .map(|ms| {
                ms.iter()
                    .map(|m| (m.identifier.name.to_string(), meta_to_string(&m.value)))
                    .collect()
            })
            .unwrap_or_default();

        let rctx = RuleCtx {
            locals: &locals,
            rule_index: &self.rule_index,
            imported: &self.imported,
            externals: &self.externals,
            uses_entrypoint: Cell::new(false),
            scope: RefCell::new(Vec::new()),
            for_of_slots: RefCell::new(Vec::new()),
        };
        let cond = rctx.lower(&rule.condition)?;
        if rctx.uses_entrypoint.get() {
            self.uses_entrypoint = true;
        }

        let idx = self.rules.len();
        self.rules.push(CompiledRule {
            name: name.clone(),
            private,
            global,
            pattern_ids,
            meta,
            cond,
        });
        // Register only after compiling the condition, so a rule cannot
        // reference itself.
        self.rule_index.insert(name, idx);
        Ok(())
    }
}

fn meta_to_string(v: &MetaValue) -> String {
    match v {
        MetaValue::Bool((b, _)) => b.to_string(),
        MetaValue::Integer((i, _)) => i.to_string(),
        MetaValue::Float((f, _)) => f.to_string(),
        MetaValue::String((s, _)) => s.to_string(),
        MetaValue::Bytes((s, _)) => s.to_string(),
    }
}

/// Strips one leading sigil byte (`$`, `#`, `@`, `!`) from a pattern reference.
fn strip_sigil(s: &str) -> &str {
    match s.as_bytes().first() {
        Some(b'$') | Some(b'#') | Some(b'@') | Some(b'!') => &s[1..],
        _ => s,
    }
}

// ---------------------------------------------------------------------------
// Pattern compilation
// ---------------------------------------------------------------------------

fn ls_bytes(ls: &yara_x_parser::ast::LiteralString) -> Vec<u8> {
    ls.value.iter().copied().collect()
}

fn compile_pattern(pat: &Pattern) -> Result<(PatternMatcher, Gate, PatternDef)> {
    match pat {
        Pattern::Text(tp) => compile_text(tp),
        Pattern::Regexp(rp) => compile_regexp(rp),
        Pattern::Hex(hp) => {
            let re_src = hex_to_regex(hp)?;
            // Hex jumps lower to lazy `.{a,b}?` over any byte; the prefilter
            // gates on the required literal runs between/around the jumps.
            let gate = atoms::regex_gate(&re_src, false, false);
            let matcher = PatternMatcher::Hex {
                re: build_regex(&re_src, false, false)?,
            };
            let def = PatternDef::Hex { re_src };
            Ok((matcher, gate, def))
        }
    }
}

fn compile_text(
    tp: &yara_x_parser::ast::TextPattern,
) -> Result<(PatternMatcher, Gate, PatternDef)> {
    let value = ls_bytes(&tp.text);
    let m = &tp.modifiers;

    let nocase = m.nocase().is_some();
    let ascii_flag = m.ascii().is_some();
    let wide_flag = m.wide().is_some();
    let fullword = m.fullword().is_some();

    let ascii_applies = ascii_flag || !wide_flag;
    let wide_applies = wide_flag;

    let xor = match m.xor() {
        Some(PatternModifier::Xor { start, end, .. }) => Some((*start, *end)),
        _ => None,
    };

    // base64 / base64wide take a different code path (they replace the plain
    // and wide forms and are mutually exclusive with xor/nocase/fullword).
    let b64 = match m.base64() {
        Some(PatternModifier::Base64 { alphabet, .. }) => Some(alphabet_str(alphabet.as_ref())?),
        _ => None,
    };
    let b64w = match m.base64wide() {
        Some(PatternModifier::Base64Wide { alphabet, .. }) => {
            Some(alphabet_str(alphabet.as_ref())?)
        }
        _ => None,
    };

    if b64.is_some() || b64w.is_some() {
        if value.len() < 3 {
            return Err(Error::new(
                "base64/base64wide modifier requires a string of length >= 3",
            ));
        }
        // Build the serializable sub-pattern DEFS; the runtime matcher (with its
        // base64 engines) is then rebuilt from the def via `PatternDef::compile`,
        // so the fresh-compiled matcher is constructed by the exact same code
        // path as one loaded from a database.
        let mut def_entries: Vec<Base64SubDef> = Vec::new();
        let wv = widen(&value);
        // `base64`: searched bytes are the plain base64 output; the pre-encoded
        // `pattern` is `value` (ascii) or `widen(value)` (wide-applies).
        if let Some(alph) = &b64 {
            if ascii_applies {
                for (padding, p) in base64_patterns(&value, alph.as_deref()) {
                    def_entries.push(Base64SubDef {
                        searched: p,
                        pattern: value.clone(),
                        padding,
                        wide: false,
                        alphabet: alph.clone(),
                    });
                }
            }
            if wide_applies {
                for (padding, p) in base64_patterns(&wv, alph.as_deref()) {
                    def_entries.push(Base64SubDef {
                        searched: p,
                        pattern: wv.clone(),
                        padding,
                        wide: false,
                        alphabet: alph.clone(),
                    });
                }
            }
        }
        // `base64wide`: searched bytes are the base64 output made wide.
        if let Some(alph) = &b64w {
            if ascii_applies {
                for (padding, p) in base64_patterns(&value, alph.as_deref()) {
                    def_entries.push(Base64SubDef {
                        searched: widen(&p),
                        pattern: value.clone(),
                        padding,
                        wide: true,
                        alphabet: alph.clone(),
                    });
                }
            }
            if wide_applies {
                for (padding, p) in base64_patterns(&wv, alph.as_deref()) {
                    def_entries.push(Base64SubDef {
                        searched: widen(&p),
                        pattern: wv.clone(),
                        padding,
                        wide: true,
                        alphabet: alph.clone(),
                    });
                }
            }
        }
        let def = PatternDef::Base64 {
            entries: def_entries,
        };
        let matcher = def.compile()?;
        let gate = match &matcher {
            PatternMatcher::Base64 { entries } => atoms::base64_gate(entries),
            _ => unreachable!("PatternDef::Base64 compiles to PatternMatcher::Base64"),
        };
        return Ok((matcher, gate, def));
    }

    // Plain / wide (optionally xor). xor is always an exact comparison, so it
    // never combines with nocase.
    let nocase = nocase && xor.is_none();
    let mut needles = Vec::new();
    if ascii_applies {
        needles.push(Needle {
            bytes: value.clone(),
            nocase,
            wide: false,
        });
    }
    if wide_applies {
        needles.push(Needle {
            bytes: widen(&value),
            nocase,
            wide: true,
        });
    }
    let gate = atoms::literal_gate(&needles, xor.is_some());
    let def = PatternDef::Literal {
        needles,
        xor,
        fullword,
    };
    let matcher = def.compile()?;
    Ok((matcher, gate, def))
}

fn alphabet_str(ls: Option<&yara_x_parser::ast::LiteralString>) -> Result<Option<String>> {
    match ls {
        None => Ok(None),
        Some(ls) => ls
            .as_str()
            .map(|s| Some(s.to_string()))
            .map_err(|_| Error::new("base64 alphabet is not valid UTF-8")),
    }
}

fn compile_regexp(
    rp: &yara_x_parser::ast::RegexpPattern,
) -> Result<(PatternMatcher, Gate, PatternDef)> {
    let m = &rp.modifiers;
    if m.xor().is_some() || m.base64().is_some() || m.base64wide().is_some() {
        return Err(Error::unsupported(
            "xor/base64 modifier on a regexp pattern",
        ));
    }
    let ci = rp.regexp.case_insensitive || m.nocase().is_some();
    let dotall = rp.regexp.dot_matches_new_line;
    let fullword = m.fullword().is_some();
    let src = rp.regexp.src.to_string();
    // A `wide` regexp matches the UTF-16LE (zero-interleaved) form of the
    // pattern. Like yara-x: `wide` without `ascii` matches ONLY that form
    // (WideOnly), whereas `wide ascii` (WideAndAscii) matches EITHER the wide
    // form OR the plain form. yara-x models this as two sub-patterns over the
    // same regexp — one run against the zero-interleaved stream, one against the
    // raw stream — so we compile the widened HIR and (for `ascii`) the plain HIR
    // and union their matches.
    let wide = m.wide().is_some();
    let ascii_too = m.ascii().is_some();
    if wide {
        let wide_re = build_wide_regex(rp.regexp.src, ci, dotall)?;
        let wide_gate = atoms::regex_gate_ex(rp.regexp.src, ci, dotall, true);
        if ascii_too {
            // `wide ascii`: match either the widened OR the plain form.
            let ascii_re = build_regex(rp.regexp.src, ci, dotall)?;
            let ascii_gate = atoms::regex_gate_ex(rp.regexp.src, ci, dotall, false);
            let gate = atoms::combine_gates(ascii_gate, wide_gate);
            let def = PatternDef::RegexMulti {
                src,
                ci,
                dotall,
                fullword,
            };
            return Ok((
                PatternMatcher::RegexMulti {
                    ascii: ascii_re,
                    wide: wide_re,
                    fullword,
                },
                gate,
                def,
            ));
        }
        let def = PatternDef::Regex {
            src,
            ci,
            dotall,
            fullword,
            wide: true,
        };
        return Ok((
            PatternMatcher::Regex {
                re: wide_re,
                fullword,
                wide: true,
            },
            wide_gate,
            def,
        ));
    }
    let re = build_regex(rp.regexp.src, ci, dotall)?;
    let gate = atoms::regex_gate_ex(rp.regexp.src, ci, dotall, false);
    let def = PatternDef::Regex {
        src,
        ci,
        dotall,
        fullword,
        wide: false,
    };
    Ok((
        PatternMatcher::Regex {
            re,
            fullword,
            wide: false,
        },
        gate,
        def,
    ))
}

// ---------------------------------------------------------------------------
// Hex -> byte-regex compilation
// ---------------------------------------------------------------------------

fn hex_to_regex(hp: &yara_x_parser::ast::HexPattern) -> Result<String> {
    let mut out = String::new();
    hex_sub_to_regex(&hp.sub_patterns, &mut out);
    Ok(out)
}

fn hex_sub_to_regex(sub: &yara_x_parser::ast::HexSubPattern, out: &mut String) {
    use yara_x_parser::ast::HexToken;
    for tok in sub.iter() {
        match tok {
            HexToken::Byte(b) => {
                if b.mask == 0xFF {
                    out.push_str(&format!("\\x{:02x}", b.value));
                } else {
                    out.push_str(&byte_class(&mask_set(b.value, b.mask), false));
                }
            }
            HexToken::NotByte(b) => {
                out.push_str(&byte_class(&mask_set(b.value, b.mask), true));
            }
            HexToken::Alternative(alt) => {
                out.push_str("(?:");
                for (i, a) in alt.alternatives.iter().enumerate() {
                    if i > 0 {
                        out.push('|');
                    }
                    hex_sub_to_regex(a, out);
                }
                out.push(')');
            }
            HexToken::Jump(j) => {
                let lo = j.start.unwrap_or(0);
                match j.end {
                    Some(hi) if hi == lo => {
                        out.push_str(&format!("[\\x00-\\xff]{{{lo}}}"));
                    }
                    Some(hi) => {
                        out.push_str(&format!("[\\x00-\\xff]{{{lo},{hi}}}?"));
                    }
                    None => {
                        out.push_str(&format!("[\\x00-\\xff]{{{lo},}}?"));
                    }
                }
            }
        }
    }
}

/// The set of bytes `b` for which `(b & mask) == value`.
fn mask_set(value: u8, mask: u8) -> [bool; 256] {
    let mut set = [false; 256];
    for (b, s) in set.iter_mut().enumerate() {
        if (b as u8 & mask) == value {
            *s = true;
        }
    }
    set
}

/// Emits a regex character class for `set`. If `negate`, emits `[^...]`, whose
/// complement is exactly the bytes NOT in `set`.
fn byte_class(set: &[bool; 256], negate: bool) -> String {
    let mut s = String::from(if negate { "[^" } else { "[" });
    let mut i = 0usize;
    while i < 256 {
        if !set[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < 256 && set[i] {
            i += 1;
        }
        let end = i - 1;
        if start == end {
            s.push_str(&format!("\\x{start:02x}"));
        } else {
            s.push_str(&format!("\\x{start:02x}-\\x{end:02x}"));
        }
    }
    s.push(']');
    s
}

// ---------------------------------------------------------------------------
// Condition lowering
// ---------------------------------------------------------------------------

/// The compile-time type of a loop/`with`-bound variable, used to resolve and
/// validate uses of the variable in the body.
#[derive(Clone, Copy)]
enum VarKind {
    /// A scalar (int/float/string/bool) — usable as a value, not navigable.
    Scalar,
    /// A `pe` struct/array sub-value at schema position `node` — navigable via
    /// field/index access, not usable as a bare value.
    Struct(SchemaNode),
}

/// A variable in scope (a `for … in`/`with` loop variable, or the reserved `$`
/// slot of a `for … of`). Its position in the scope stack is its runtime slot.
struct ScopeVar {
    name: String,
    kind: VarKind,
}

struct RuleCtx<'a> {
    locals: &'a [LocalPat],
    rule_index: &'a HashMap<String, usize>,
    imported: &'a [ModuleKind],
    /// Declared external variables (name -> type); an undeclared bare identifier
    /// is a compile error.
    externals: &'a HashMap<String, ExternalType>,
    uses_entrypoint: Cell<bool>,
    /// The lexical scope stack of bound variables. Slot == index in this stack.
    scope: RefCell<Vec<ScopeVar>>,
    /// Stack of the current `for … of` pattern slots; the top is what an
    /// anonymous `$`/`#`/`@`/`!` in the body refers to.
    for_of_slots: RefCell<Vec<usize>>,
}

impl RuleCtx<'_> {
    fn resolve_pattern(&self, name: &str) -> Result<usize> {
        let key = strip_sigil(name);
        let mut found = None;
        for lp in self.locals {
            if lp.key == key {
                if found.is_some() {
                    return Err(Error::new(format!("ambiguous pattern reference `{name}`")));
                }
                found = Some(lp.id);
            }
        }
        found.ok_or_else(|| Error::new(format!("reference to undefined pattern `{name}`")))
    }

    fn resolve_set(&self, set: &PatternSet) -> Vec<usize> {
        match set {
            PatternSet::Them { .. } => self.locals.iter().map(|lp| lp.id).collect(),
            PatternSet::Set(items) => {
                let mut ids = Vec::new();
                for item in items {
                    let prefix = strip_sigil(item.identifier);
                    for lp in self.locals {
                        let hit = if item.wildcard {
                            lp.key.starts_with(prefix)
                        } else {
                            lp.key == prefix
                        };
                        if hit && !ids.contains(&lp.id) {
                            ids.push(lp.id);
                        }
                    }
                }
                ids
            }
        }
    }

    fn lower(&self, e: &Expr) -> Result<Cond> {
        Ok(match e {
            Expr::True { .. } => Cond::Bool(true),
            Expr::False { .. } => Cond::Bool(false),
            Expr::Filesize { .. } => Cond::Filesize,
            Expr::Entrypoint { .. } => {
                self.uses_entrypoint.set(true);
                Cond::Entrypoint
            }
            Expr::LiteralInteger(i) => Cond::Int(i.value),
            Expr::LiteralFloat(f) => Cond::Float(f.value),
            Expr::LiteralString(s) => Cond::Str(ls_bytes(s)),
            Expr::Regexp(_) => {
                return Err(Error::unsupported("bare regular expression in condition"))
            }

            Expr::Ident(id) => {
                if let Some((slot, kind)) = self.lookup_var(id.name) {
                    match kind {
                        VarKind::Scalar => Cond::Var(slot),
                        VarKind::Struct(_) => {
                            return Err(Error::new(format!(
                                "variable `{}` is a struct and cannot be used as a value \
                                 (access one of its fields)",
                                id.name
                            )))
                        }
                    }
                } else if let Some(&idx) = self.rule_index.get(id.name) {
                    Cond::RuleRef(idx)
                } else if let Some(&ty) = self.externals.get(id.name) {
                    Cond::External(id.name.to_string(), ty)
                } else {
                    return Err(Error::unsupported(format!(
                        "identifier `{}` (module or undefined rule)",
                        id.name
                    )));
                }
            }

            Expr::PatternMatch(pm) => {
                let anchor = self.lower_anchor(&pm.anchor)?;
                if pm.identifier.name == "$" && self.in_for_of() {
                    Cond::PatternVar(self.for_of_slot()?, anchor)
                } else {
                    let id = self.resolve_pattern(pm.identifier.name)?;
                    Cond::Pattern(id, anchor)
                }
            }
            Expr::PatternCount(pc) => {
                let range = match &pc.range {
                    Some(r) => Some(self.lower_range(r)?),
                    None => None,
                };
                if pc.identifier.name == "#" && self.in_for_of() {
                    Cond::CountVar(self.for_of_slot()?, range)
                } else {
                    let id = self.resolve_pattern(pc.identifier.name)?;
                    Cond::Count(id, range)
                }
            }
            Expr::PatternOffset(po) => {
                let idx = match &po.index {
                    Some(e) => Some(Box::new(self.lower(e)?)),
                    None => None,
                };
                if po.identifier.name == "@" && self.in_for_of() {
                    Cond::OffsetVar(self.for_of_slot()?, idx)
                } else {
                    let id = self.resolve_pattern(po.identifier.name)?;
                    Cond::Offset(id, idx)
                }
            }
            Expr::PatternLength(pl) => {
                let idx = match &pl.index {
                    Some(e) => Some(Box::new(self.lower(e)?)),
                    None => None,
                };
                if pl.identifier.name == "!" && self.in_for_of() {
                    Cond::LengthVar(self.for_of_slot()?, idx)
                } else {
                    let id = self.resolve_pattern(pl.identifier.name)?;
                    Cond::Length(id, idx)
                }
            }

            Expr::Defined(u) => Cond::Defined(Box::new(self.lower(&u.operand)?)),
            Expr::Not(u) => Cond::Not(Box::new(self.lower(&u.operand)?)),
            Expr::Minus(u) => Cond::Neg(Box::new(self.lower(&u.operand)?)),
            Expr::BitwiseNot(u) => Cond::BitNot(Box::new(self.lower(&u.operand)?)),

            Expr::And(n) => Cond::And(self.lower_all(n.as_slice())?),
            Expr::Or(n) => Cond::Or(self.lower_all(n.as_slice())?),

            Expr::Add(n) => self.fold_arith(ArithOp::Add, n.as_slice())?,
            Expr::Sub(n) => self.fold_arith(ArithOp::Sub, n.as_slice())?,
            Expr::Mul(n) => self.fold_arith(ArithOp::Mul, n.as_slice())?,
            Expr::Div(n) => self.fold_arith(ArithOp::Div, n.as_slice())?,
            Expr::Mod(n) => self.fold_arith(ArithOp::Mod, n.as_slice())?,

            Expr::Shl(b) => self.bin_arith(ArithOp::Shl, b)?,
            Expr::Shr(b) => self.bin_arith(ArithOp::Shr, b)?,
            Expr::BitwiseAnd(b) => self.bin_arith(ArithOp::BitAnd, b)?,
            Expr::BitwiseOr(b) => self.bin_arith(ArithOp::BitOr, b)?,
            Expr::BitwiseXor(b) => self.bin_arith(ArithOp::BitXor, b)?,

            Expr::Eq(b) => self.bin_cmp(CmpOp::Eq, b)?,
            Expr::Ne(b) => self.bin_cmp(CmpOp::Ne, b)?,
            Expr::Lt(b) => self.bin_cmp(CmpOp::Lt, b)?,
            Expr::Gt(b) => self.bin_cmp(CmpOp::Gt, b)?,
            Expr::Le(b) => self.bin_cmp(CmpOp::Le, b)?,
            Expr::Ge(b) => self.bin_cmp(CmpOp::Ge, b)?,

            Expr::Contains(b) => self.bin_str(StrOp::Contains, b)?,
            Expr::IContains(b) => self.bin_str(StrOp::IContains, b)?,
            Expr::StartsWith(b) => self.bin_str(StrOp::StartsWith, b)?,
            Expr::IStartsWith(b) => self.bin_str(StrOp::IStartsWith, b)?,
            Expr::EndsWith(b) => self.bin_str(StrOp::EndsWith, b)?,
            Expr::IEndsWith(b) => self.bin_str(StrOp::IEndsWith, b)?,
            Expr::IEquals(b) => self.bin_str(StrOp::IEquals, b)?,

            Expr::Matches(b) => {
                let lhs = Box::new(self.lower(&b.lhs)?);
                let re = match &b.rhs {
                    Expr::Regexp(r) => CompiledRegex::new(
                        r.src.to_string(),
                        r.case_insensitive,
                        r.dot_matches_new_line,
                    )?,
                    _ => return Err(Error::new("right operand of `matches` must be a regexp")),
                };
                Cond::Matches(lhs, Box::new(re))
            }

            Expr::Of(of) => {
                let quant = self.lower_quant(&of.quantifier)?;
                let items = match &of.items {
                    yara_x_parser::ast::OfItems::PatternSet(ps) => {
                        OfItems::Patterns(self.resolve_set(ps))
                    }
                    yara_x_parser::ast::OfItems::BoolExprTuple(exprs) => {
                        OfItems::Exprs(self.lower_all(exprs)?)
                    }
                };
                let anchor = self.lower_anchor(&of.anchor)?;
                Cond::Of(quant, items, anchor)
            }

            Expr::ForIn(fi) => self.lower_for_in(fi)?,
            Expr::ForOf(fo) => self.lower_for_of(fo)?,
            Expr::With(w) => self.lower_with(w)?,

            Expr::FieldAccess(_) | Expr::Lookup(_) => {
                let resolved = self.resolve_module_expr(e)?;
                self.resolved_to_cond(resolved)?
            }
            Expr::FuncCall(fc) => self.lower_func_call(fc)?,
        })
    }

    /// Lowers a function call: either a bare integer file read (`uint16(0)`),
    /// or a module function (`pe.imphash()`, `hash.md5(o,l)`, …).
    fn lower_func_call(&self, fc: &yara_x_parser::ast::FuncCall) -> Result<Cond> {
        let name = fc.identifier.name;
        match &fc.object {
            // Bare function: an integer file read, or unsupported.
            None => {
                if let Some(kind) = int_kind(name) {
                    if fc.args.len() != 1 {
                        return Err(Error::new(format!("`{name}()` takes exactly one argument")));
                    }
                    Ok(Cond::IntRead(kind, Box::new(self.lower(&fc.args[0])?)))
                } else {
                    Err(Error::unsupported(format!("function call `{name}()`")))
                }
            }
            // Module function: the object must resolve to a (bare) module.
            Some(obj) => {
                let module = match self.resolve_module_expr(obj)? {
                    Resolved::Module(kind) => kind,
                    _ => {
                        return Err(Error::unsupported(format!(
                            "method call `{name}()` on a non-module value"
                        )))
                    }
                };
                let args: Vec<Cond> = fc
                    .args
                    .iter()
                    .map(|a| self.lower(a))
                    .collect::<Result<_>>()?;
                let func = modules::resolve_func(module, name, &args)?;
                Ok(Cond::ModCall(func, args))
            }
        }
    }

    /// Converts a resolved module chain into a condition, validating field
    /// accesses against the module schema.
    fn resolved_to_cond(&self, r: Resolved) -> Result<Cond> {
        match r {
            Resolved::Value(c) => Ok(c),
            Resolved::Access(kind, path) => {
                let names: Vec<FieldName> = path
                    .iter()
                    .map(|a| match a {
                        Access::Field(n) => FieldName::Field(n.clone()),
                        Access::Index(_) => FieldName::Index,
                    })
                    .collect();
                modules::validate_access(kind, &names)?;
                Ok(Cond::ModAccess(kind, path))
            }
            Resolved::VarValue(slot) => Ok(Cond::Var(slot)),
            Resolved::VarAccess(slot, _node, path) => {
                if path.is_empty() {
                    Err(Error::new(
                        "struct-typed variable used as a value (access one of its fields)",
                    ))
                } else {
                    Ok(Cond::VarAccess(slot, path))
                }
            }
            Resolved::Module(_) => Err(Error::unsupported("bare module reference used as a value")),
        }
    }

    /// Recursively resolves a module field-access / lookup / ident chain.
    fn resolve_module_expr(&self, e: &Expr) -> Result<Resolved> {
        match e {
            Expr::Ident(id) => {
                if let Some((slot, kind)) = self.lookup_var(id.name) {
                    return Ok(match kind {
                        VarKind::Scalar => Resolved::VarValue(slot),
                        VarKind::Struct(node) => Resolved::VarAccess(slot, node, Vec::new()),
                    });
                }
                if let Some(&ty) = self.externals.get(id.name) {
                    // An external used where a value is expected (e.g. a `with`
                    // binding or a bare-ident operand of a comparison reached via
                    // this resolver) — treat it as a scalar value.
                    return Ok(Resolved::Value(Cond::External(id.name.to_string(), ty)));
                }
                match ModuleKind::from_name(id.name) {
                    Some(kind) if self.imported.contains(&kind) => Ok(Resolved::Module(kind)),
                    Some(_) => Err(Error::new(format!(
                        "module `{}` used without `import`",
                        id.name
                    ))),
                    None => Err(Error::unsupported(format!(
                        "identifier `{}` (module or undefined rule)",
                        id.name
                    ))),
                }
            }
            Expr::FieldAccess(nary) => self.resolve_field_access(nary),
            Expr::Lookup(lk) => {
                let base = self.resolve_module_expr(&lk.primary)?;
                let idx = self.lower(&lk.index)?;
                append_index(base, idx)
            }
            _ => Err(Error::unsupported("unsupported module expression")),
        }
    }

    fn resolve_field_access(&self, nary: &NAryExpr) -> Result<Resolved> {
        let mut ops = nary.operands();
        let first = ops.next().ok_or_else(|| Error::new("empty field access"))?;
        let mut r = self.resolve_module_expr(first)?;
        for op in ops {
            r = self.append_step(r, op)?;
        }
        Ok(r)
    }

    /// Apply one step of a dotted chain to the accumulated path.
    ///
    /// A chain like `dotnet.assembly_refs[0].version.major` does not arrive as a
    /// flat list of identifiers: the parser hands back a subscripted step as a
    /// `Lookup` and groups what follows into a nested `FieldAccess`. Handling
    /// only bare identifiers rejected every chain with a subscript anywhere but
    /// the last position — a good deal of ordinary `pe` and `dotnet` rules.
    fn append_step(&self, r: Resolved, op: &Expr) -> Result<Resolved> {
        match op {
            Expr::Ident(id) => self.append_field(r, id),
            // The lookup's primary is its own identifier; the prefix built so
            // far stays in `r`. So this is a field step, then an index step.
            Expr::Lookup(lk) => {
                let Expr::Ident(id) = &lk.primary else {
                    return Err(Error::unsupported("unsupported module field access"));
                };
                let r = self.append_field(r, id.as_ref())?;
                let idx = self.lower(&lk.index)?;
                append_index(r, idx)
            }
            // A nested chain: flatten it onto the same path.
            Expr::FieldAccess(inner) => {
                let mut r = r;
                for step in inner.operands() {
                    r = self.append_step(r, step)?;
                }
                Ok(r)
            }
            _ => Err(Error::unsupported("unsupported module field access")),
        }
    }

    fn append_field(&self, base: Resolved, id: &Ident) -> Result<Resolved> {
        let name = id.name;
        match base {
            Resolved::Module(kind) => {
                if let Some(v) = modules::module_constant(kind, name) {
                    Ok(Resolved::Value(const_to_cond(v)))
                } else {
                    Ok(Resolved::Access(
                        kind,
                        vec![Access::Field(name.to_string())],
                    ))
                }
            }
            Resolved::Access(kind, mut path) => {
                path.push(Access::Field(name.to_string()));
                Ok(Resolved::Access(kind, path))
            }
            Resolved::VarAccess(slot, node, mut path) => {
                // Navigate + validate the field against the bound value's schema.
                let node = node.field(name)?;
                path.push(Access::Field(name.to_string()));
                Ok(Resolved::VarAccess(slot, node, path))
            }
            Resolved::VarValue(_) => {
                Err(Error::new("field access on a scalar loop/`with` variable"))
            }
            Resolved::Value(_) => Err(Error::unsupported("field access on a scalar value")),
        }
    }

    fn lower_all(&self, exprs: &[Expr]) -> Result<Vec<Cond>> {
        exprs.iter().map(|e| self.lower(e)).collect()
    }

    fn fold_arith(&self, op: ArithOp, operands: &[Expr]) -> Result<Cond> {
        let mut it = operands.iter();
        let mut acc = self.lower(it.next().expect("non-empty n-ary"))?;
        for e in it {
            acc = Cond::Arith(op, Box::new(acc), Box::new(self.lower(e)?));
        }
        Ok(acc)
    }

    fn bin_arith(&self, op: ArithOp, b: &yara_x_parser::ast::BinaryExpr) -> Result<Cond> {
        Ok(Cond::Arith(
            op,
            Box::new(self.lower(&b.lhs)?),
            Box::new(self.lower(&b.rhs)?),
        ))
    }

    fn bin_cmp(&self, op: CmpOp, b: &yara_x_parser::ast::BinaryExpr) -> Result<Cond> {
        Ok(Cond::Cmp(
            op,
            Box::new(self.lower(&b.lhs)?),
            Box::new(self.lower(&b.rhs)?),
        ))
    }

    fn bin_str(&self, op: StrOp, b: &yara_x_parser::ast::BinaryExpr) -> Result<Cond> {
        Ok(Cond::StrCmp(
            op,
            Box::new(self.lower(&b.lhs)?),
            Box::new(self.lower(&b.rhs)?),
        ))
    }

    fn lower_quant(&self, q: &Quantifier) -> Result<Quant> {
        Ok(match q {
            Quantifier::All { .. } => Quant::All,
            Quantifier::Any { .. } => Quant::Any,
            Quantifier::None { .. } => Quant::None,
            Quantifier::Expr(e) => Quant::Count(Box::new(self.lower(e)?)),
            Quantifier::Percentage(e) => Quant::Percent(Box::new(self.lower(e)?)),
        })
    }

    fn lower_anchor(&self, anchor: &Option<MatchAnchor>) -> Result<Option<Anchor>> {
        Ok(match anchor {
            None => None,
            Some(MatchAnchor::At(at)) => Some(Anchor::At(Box::new(self.lower(&at.expr)?))),
            Some(MatchAnchor::In(in_)) => {
                let (lo, hi) = self.lower_range(&in_.range)?;
                Some(Anchor::In(lo, hi))
            }
        })
    }

    fn lower_range(&self, r: &Range) -> Result<(Box<Cond>, Box<Cond>)> {
        Ok((
            Box::new(self.lower(&r.lower_bound)?),
            Box::new(self.lower(&r.upper_bound)?),
        ))
    }

    // -----------------------------------------------------------------------
    // Scope + loop / with lowering (Phase C)
    // -----------------------------------------------------------------------

    /// Looks up a bound variable by name (innermost scope wins).
    fn lookup_var(&self, name: &str) -> Option<(usize, VarKind)> {
        let scope = self.scope.borrow();
        scope
            .iter()
            .enumerate()
            .rev()
            .find(|(_, v)| v.name == name)
            .map(|(i, v)| (i, v.kind))
    }

    fn in_for_of(&self) -> bool {
        !self.for_of_slots.borrow().is_empty()
    }

    /// The slot of the innermost `for … of`'s current pattern.
    fn for_of_slot(&self) -> Result<usize> {
        self.for_of_slots.borrow().last().copied().ok_or_else(|| {
            Error::new("anonymous pattern (`$`/`#`/`@`/`!`) used outside a `for … of` body")
        })
    }

    fn lower_for_in(&self, fi: &yara_x_parser::ast::ForIn) -> Result<Cond> {
        let quant = self.lower_quant(&fi.quantifier)?;
        // The iterable and quantifier are evaluated in the OUTER scope (they
        // cannot reference the loop variable), so lower them before binding.
        let base = self.scope.borrow().len();
        let (iter, kinds) = self.lower_iterable(&fi.iterable)?;
        if fi.variables.len() != kinds.len() {
            return Err(Error::new(format!(
                "`for` loop binds {} variable(s) but the iterable yields {}",
                fi.variables.len(),
                kinds.len()
            )));
        }
        {
            let mut scope = self.scope.borrow_mut();
            for (v, kind) in fi.variables.iter().zip(kinds) {
                scope.push(ScopeVar {
                    name: v.name.to_string(),
                    kind,
                });
            }
        }
        let body = self.lower(&fi.body);
        self.scope.borrow_mut().truncate(base);
        let body = body?;
        Ok(Cond::ForIn(Box::new(crate::yara::ir::ForIn {
            quant,
            iter,
            base,
            body,
        })))
    }

    fn lower_for_of(&self, fo: &yara_x_parser::ast::ForOf) -> Result<Cond> {
        let quant = self.lower_quant(&fo.quantifier)?;
        let patterns = self.resolve_set(&fo.pattern_set);
        let slot = self.scope.borrow().len();
        // Reserve the slot with a name that can never be an identifier, so
        // nested loops get correct slots but this entry is never looked up.
        self.scope.borrow_mut().push(ScopeVar {
            name: "$".to_string(),
            kind: VarKind::Scalar,
        });
        self.for_of_slots.borrow_mut().push(slot);
        let body = self.lower(&fo.body);
        self.for_of_slots.borrow_mut().pop();
        self.scope.borrow_mut().truncate(slot);
        let body = body?;
        Ok(Cond::ForOf(Box::new(crate::yara::ir::ForOf {
            quant,
            patterns,
            slot,
            body,
        })))
    }

    fn lower_with(&self, w: &yara_x_parser::ast::With) -> Result<Cond> {
        let base = self.scope.borrow().len();
        let mut decls = Vec::with_capacity(w.declarations.len());
        // Each declaration is bound before the next is lowered, so a later
        // declaration may reference an earlier one.
        let result = (|| {
            for d in &w.declarations {
                let (cond, kind) = self.lower_with_decl(&d.expression)?;
                decls.push(cond);
                self.scope.borrow_mut().push(ScopeVar {
                    name: d.identifier.name.to_string(),
                    kind,
                });
            }
            self.lower(&w.body)
        })();
        self.scope.borrow_mut().truncate(base);
        let body = result?;
        Ok(Cond::With(Box::new(crate::yara::ir::With {
            decls,
            base,
            body,
        })))
    }

    /// Lowers a `with` declaration expression, returning its condition and the
    /// compile-time kind to bind the name to.
    fn lower_with_decl(&self, e: &Expr) -> Result<(Cond, VarKind)> {
        // Module-shaped expressions (ident / field access / lookup) may resolve
        // to a struct value, which we must type so the body can navigate it.
        if matches!(e, Expr::Ident(_) | Expr::FieldAccess(_) | Expr::Lookup(_)) {
            match self.resolve_module_expr(e)? {
                Resolved::Value(c) => return Ok((c, VarKind::Scalar)),
                Resolved::VarValue(slot) => return Ok((Cond::Var(slot), VarKind::Scalar)),
                Resolved::Access(kind, path) => {
                    let node = module_terminal_node(kind, &path)?;
                    let cond = self.resolved_to_cond(Resolved::Access(kind, path))?;
                    return Ok((cond, node_var_kind(node)));
                }
                Resolved::VarAccess(slot, node, path) => {
                    let cond = if path.is_empty() {
                        Cond::Var(slot)
                    } else {
                        Cond::VarAccess(slot, path)
                    };
                    return Ok((cond, node_var_kind(node)));
                }
                Resolved::Module(kind) => {
                    // Bind the whole module struct (e.g. `with p = pe : (p.is_pe)`).
                    let node = SchemaNode::root(kind).ok_or_else(|| {
                        Error::unsupported(format!(
                            "binding a bare `{}` module value in `with` (it exposes \
                             no navigable fields)",
                            kind.label()
                        ))
                    })?;
                    return Ok((Cond::ModAccess(kind, Vec::new()), VarKind::Struct(node)));
                }
            }
        }
        // Any other expression is scalar-valued.
        Ok((self.lower(e)?, VarKind::Scalar))
    }

    /// Lowers a `for … in` iterable, returning its runtime form plus the
    /// compile-time kind of each loop variable it binds.
    fn lower_iterable(&self, it: &yara_x_parser::ast::Iterable) -> Result<(Iter, Vec<VarKind>)> {
        use yara_x_parser::ast::Iterable as I;
        match it {
            I::Range(r) => {
                let (lo, hi) = self.lower_range(r)?;
                Ok((Iter::Range(lo, hi), vec![VarKind::Scalar]))
            }
            I::ExprTuple(exprs) => {
                let conds = self.lower_all(exprs)?;
                Ok((Iter::Tuple(conds), vec![VarKind::Scalar]))
            }
            I::Expr(e) => {
                // Must be a module array/map value.
                let (node, cond) = match self.resolve_module_expr(e)? {
                    Resolved::Access(kind, path) => {
                        let node = module_terminal_node(kind, &path)?;
                        let cond = self.resolved_to_cond(Resolved::Access(kind, path))?;
                        (node, cond)
                    }
                    Resolved::VarAccess(slot, node, path) => {
                        let cond = if path.is_empty() {
                            Cond::Var(slot)
                        } else {
                            Cond::VarAccess(slot, path)
                        };
                        (node, cond)
                    }
                    _ => {
                        return Err(Error::new(
                            "expression is not iterable (expected an array or map)",
                        ))
                    }
                };
                let (elem, nvars) = node.iterable().ok_or_else(|| {
                    Error::new("expression is not iterable (expected an array or map)")
                })?;
                let kinds = if nvars == 2 {
                    // map: key (scalar) + value.
                    vec![VarKind::Scalar, node_var_kind(elem)]
                } else {
                    vec![node_var_kind(elem)]
                };
                Ok((Iter::Collection(Box::new(cond)), kinds))
            }
        }
    }
}

/// The variable kind for a value at `pe` schema node `node`.
fn node_var_kind(node: SchemaNode) -> VarKind {
    if node.is_scalar() {
        VarKind::Scalar
    } else {
        VarKind::Struct(node)
    }
}

/// Walks a module access path from the root, returning the terminal schema node.
/// Modules that expose only functions and constants have no navigable data.
fn module_terminal_node(kind: ModuleKind, path: &[Access]) -> Result<SchemaNode> {
    let mut node = SchemaNode::root(kind).ok_or_else(|| {
        Error::new(format!(
            "the `{}` module exposes no navigable struct/array fields",
            kind.label()
        ))
    })?;
    for seg in path {
        node = match seg {
            Access::Field(n) => node.field(n)?,
            Access::Index(_) => node.index()?,
        };
    }
    Ok(node)
}

/// A partially-resolved module expression (see `resolve_module_expr`).
enum Resolved {
    /// A bare, imported module (`pe`) — only valid as the base of an access or
    /// as the object of a function call.
    Module(ModuleKind),
    /// A field/index chain producing a value at scan time.
    Access(ModuleKind, Vec<Access>),
    /// A fully-resolved constant value (a folded module constant).
    Value(Cond),
    /// A scalar loop/`with` variable used as a value.
    VarValue(usize),
    /// A field/index chain rooted at a struct loop/`with` variable, with the
    /// current schema node tracked for validation.
    VarAccess(usize, SchemaNode, Vec<Access>),
}

/// Appends an index step to a resolved access chain.
fn append_index(base: Resolved, idx: Cond) -> Result<Resolved> {
    match base {
        Resolved::Access(kind, mut path) => {
            path.push(Access::Index(Box::new(idx)));
            Ok(Resolved::Access(kind, path))
        }
        Resolved::VarAccess(slot, node, mut path) => {
            let node = node.index()?;
            path.push(Access::Index(Box::new(idx)));
            Ok(Resolved::VarAccess(slot, node, path))
        }
        Resolved::VarValue(_) => Err(Error::new("indexing a scalar loop/`with` variable")),
        Resolved::Module(_) => Err(Error::unsupported("indexing a module")),
        Resolved::Value(_) => Err(Error::unsupported("indexing a scalar value")),
    }
}

fn const_to_cond(v: crate::yara::ir::Value) -> Cond {
    match v {
        crate::yara::ir::Value::Int(i) => Cond::Int(i),
        crate::yara::ir::Value::Float(f) => Cond::Float(f),
        crate::yara::ir::Value::Bool(b) => Cond::Bool(b),
        crate::yara::ir::Value::Str(s) => Cond::Str(s),
        _ => unreachable!("module constants are scalar"),
    }
}

/// Maps an integer file-read function name to its [`IntKind`], or `None` for
/// non-integer reads (e.g. `float32`, which is not implemented). Single-byte
/// `_be` variants are equivalent to their little-endian forms.
fn int_kind(name: &str) -> Option<IntKind> {
    Some(match name {
        "uint8" | "uint8be" => IntKind::U8,
        "int8" | "int8be" => IntKind::I8,
        "uint16" => IntKind::U16,
        "int16" => IntKind::I16,
        "uint32" => IntKind::U32,
        "int32" => IntKind::I32,
        "uint16be" => IntKind::U16be,
        "int16be" => IntKind::I16be,
        "uint32be" => IntKind::U32be,
        "int32be" => IntKind::I32be,
        _ => return None,
    })
}
