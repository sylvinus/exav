//! Owned intermediate representation of a rule condition, plus its native
//! tree-walking evaluator. The parser's AST borrows the source, so conditions
//! are lowered into this `'static` IR at compile time.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use regex_automata::{meta::Regex, Input};
use serde::{Deserialize, Serialize};

use crate::yara::matcher::{build_regex, Match};
use crate::yara::modules::{self, FuncId, ModuleCtx, ModuleKind};

/// A compiled `matches` regexp plus the source it was built from.
///
/// `regex_automata::meta::Regex` is not serde-serializable and cannot hand back
/// its source, so this wrapper stores the regex SOURCE + flags and, on
/// deserialize, recompiles the `Regex` from them (via [`build_regex`], the same
/// builder the compiler uses). This lets the surrounding [`Cond`] tree derive
/// `Serialize`/`Deserialize` while the on-disk form carries only the cheap
/// source, recompiled on load.
pub(crate) struct CompiledRegex {
    re: Regex,
    src: String,
    case_insensitive: bool,
    dot_matches_new_line: bool,
}

impl CompiledRegex {
    /// Compiles a `matches` regexp from its source + flags.
    pub(crate) fn new(
        src: String,
        case_insensitive: bool,
        dot_matches_new_line: bool,
    ) -> crate::yara::error::Result<Self> {
        let re = build_regex(&src, case_insensitive, dot_matches_new_line)?;
        Ok(Self {
            re,
            src,
            case_insensitive,
            dot_matches_new_line,
        })
    }

    fn is_match(&self, input: Input) -> bool {
        self.re.is_match(input)
    }
}

impl Serialize for CompiledRegex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.src, self.case_insensitive, self.dot_matches_new_line).serialize(s)
    }
}

impl<'de> Deserialize<'de> for CompiledRegex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (src, ci, dotall): (String, bool, bool) = Deserialize::deserialize(d)?;
        CompiledRegex::new(src, ci, dotall).map_err(serde::de::Error::custom)
    }
}

/// Named fields of a module struct value.
pub(crate) type Fields = HashMap<String, Value>;

/// A module map/dictionary value: keyed by string or by integer.
///
/// Part of the module value model. The `eval_access` resolver handles both key
/// kinds; module producers that expose maps (a future `pe.version_info`, etc.)
/// construct these. Currently no shipped module populates a map, hence the
/// `allow(dead_code)`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum MapVal {
    Str(HashMap<Vec<u8>, Value>),
    Int(HashMap<i64, Value>),
}

/// A runtime value. `None` (returned as `Option<Value>`) means *undefined*.
///
/// The scalar variants (`Bool`/`Int`/`Float`/`Str`) are what rule conditions
/// ultimately reduce to; the structured variants (`Struct`/`Array`/`Map`) carry
/// the values produced by imported modules (e.g. `pe.sections[0]`).
#[derive(Debug, Clone)]
pub(crate) enum Value {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Struct(Rc<Fields>),
    Array(Rc<Vec<Value>>),
    #[allow(dead_code)] // populated once a module exposes a map (see `MapVal`).
    Map(Rc<MapVal>),
}

impl Value {
    /// Cast to a boolean (YARA boolean context). Undefined casts to false; that
    /// is handled by the caller via `truthy`.
    fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            // Structured values never appear in boolean context in a
            // well-formed rule; treat their presence as truthy.
            _ => true,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Extract an `i64`, accepting int/float/bool. Used by module functions.
    pub(crate) fn to_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) => Some(*f as i64),
            Value::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    /// Extract an `f64` (int or float).
    pub(crate) fn to_f64(&self) -> Option<f64> {
        self.as_f64()
    }

    /// Extract a byte string.
    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

fn truthy(v: &Option<Value>) -> bool {
    matches!(v, Some(x) if x.as_bool())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Shl,
    Shr,
    BitAnd,
    BitOr,
    BitXor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum StrOp {
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    IEquals,
}

/// Quantifier for an `of` expression.
#[derive(Serialize, Deserialize)]
pub(crate) enum Quant {
    All,
    Any,
    None,
    Count(Box<Cond>),
    Percent(Box<Cond>),
}

/// Items of an `of` expression.
#[derive(Serialize, Deserialize)]
pub(crate) enum OfItems {
    /// Pattern ids (global) — `them`, `($a, $b)`, `($a*)`.
    Patterns(Vec<usize>),
    /// Boolean expressions — `(true, $a, 1 == 1)`.
    Exprs(Vec<Cond>),
}

/// Anchor for pattern-match / of expressions: `at N` or `in (a..b)`.
#[derive(Serialize, Deserialize)]
pub(crate) enum Anchor {
    At(Box<Cond>),
    In(Box<Cond>, Box<Cond>),
}

/// The iterable of a `for <quant> <vars> in <iterable>` expression.
#[derive(Serialize, Deserialize)]
pub(crate) enum Iter {
    /// An inclusive integer range `(a..b)`. Binds one integer variable.
    Range(Box<Cond>, Box<Cond>),
    /// A tuple of scalar expressions `(e1, e2, …)`. Binds one variable.
    Tuple(Vec<Cond>),
    /// An expression yielding a module array or map value. Binds one variable
    /// (array element) or two variables (map key + value).
    Collection(Box<Cond>),
}

/// A `for <quant> <vars> in <iterable> : ( <body> )` expression.
#[derive(Serialize, Deserialize)]
pub(crate) struct ForIn {
    pub quant: Quant,
    pub iter: Iter,
    /// The first environment slot the loop variable(s) occupy. Ranges/tuples
    /// use one slot (`base`); maps use two (`base` = key, `base + 1` = value).
    pub base: usize,
    pub body: Cond,
}

/// A `for <quant> of <pattern-set> : ( <body> )` expression. Inside the body,
/// `$`/`#`/`@`/`!` refer to the pattern bound at `slot` on each iteration.
#[derive(Serialize, Deserialize)]
pub(crate) struct ForOf {
    pub quant: Quant,
    pub patterns: Vec<usize>,
    pub slot: usize,
    pub body: Cond,
}

/// A `with <ident> = <expr>, … : ( <body> )` expression. `decls` are evaluated
/// in order into consecutive environment slots starting at `base`; a later
/// declaration may reference an earlier one.
#[derive(Serialize, Deserialize)]
pub(crate) struct With {
    pub decls: Vec<Cond>,
    pub base: usize,
    pub body: Cond,
}

/// One step in a module field-access chain (`pe.sections[0].name`).
#[derive(Serialize, Deserialize)]
pub(crate) enum Access {
    /// `.field`
    Field(String),
    /// `[expr]` — array index (int) or map key (int/string).
    Index(Box<Cond>),
}

/// The declared type of a host-supplied external variable (`filename`,
/// `extension`, …). Recorded at compile time when a bare identifier resolves to
/// a declared external; the concrete value is supplied per scan (see
/// `EvalCtx::externals`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalType {
    Int,
    Float,
    Bool,
    Str,
}

/// An integer file-read function (`uint16(off)`, `int8be(off)`, …).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum IntKind {
    U8,
    U16,
    U32,
    I8,
    I16,
    I32,
    U16be,
    U32be,
    I16be,
    I32be,
}

/// The owned condition tree.
#[derive(Serialize, Deserialize)]
pub(crate) enum Cond {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(Vec<u8>),
    Filesize,
    /// Pattern presence `$a`, optionally anchored (`$a at N`, `$a in (a..b)`).
    Pattern(usize, Option<Anchor>),
    /// `#a`, optionally counted within a range (`#a in (a..b)`).
    Count(usize, Option<(Box<Cond>, Box<Cond>)>),
    /// `@a[i]` (1-based; `@a` == `@a[1]`).
    Offset(usize, Option<Box<Cond>>),
    /// `!a[i]`.
    Length(usize, Option<Box<Cond>>),
    /// Reference to another rule's result (by rule index).
    RuleRef(usize),
    Defined(Box<Cond>),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Neg(Box<Cond>),
    BitNot(Box<Cond>),
    Arith(ArithOp, Box<Cond>, Box<Cond>),
    Cmp(CmpOp, Box<Cond>, Box<Cond>),
    StrCmp(StrOp, Box<Cond>, Box<Cond>),
    /// `<expr> matches /regex/`.
    Matches(Box<Cond>, Box<CompiledRegex>),
    Of(Quant, OfItems, Option<Anchor>),
    /// Module field access, resolved against the per-scan module value tree.
    ModAccess(ModuleKind, Vec<Access>),
    /// Module function call (`pe.imphash()`, `hash.md5(o,l)`, `math.entropy(…)`).
    ModCall(FuncId, Vec<Cond>),
    /// Integer file read (`uintN`/`intN`/`_be`).
    IntRead(IntKind, Box<Cond>),
    /// The `entrypoint` keyword (PE entry-point file offset; undefined for
    /// non-PE inputs). Note: yara-x rejects this keyword at compile time; exav
    /// keeps the classic-YARA behaviour, so it is excluded from the yara-x diff
    /// harness.
    Entrypoint,
    /// A host-supplied external variable referenced by bare identifier
    /// (`filename`, `extension`, …). Declared at compile time (with a type); its
    /// value is looked up per scan in [`EvalCtx::externals`] and is *undefined*
    /// (`None`) when the host did not set it for this scan.
    External(String, ExternalType),

    // --- loop / with bindings (Phase C) ------------------------------------
    /// A bound loop/`with` variable, resolved to its current value.
    Var(usize),
    /// A field/index-access chain starting from a bound variable's value (a
    /// module struct/array element bound by `for … in` or `with`).
    VarAccess(usize, Vec<Access>),
    /// `for <quant> <vars> in <iterable> : ( <body> )`.
    ForIn(Box<ForIn>),
    /// `for <quant> of <pattern-set> : ( <body> )`.
    ForOf(Box<ForOf>),
    /// `with <decls> : ( <body> )`.
    With(Box<With>),
    /// Anonymous `$` inside a `for … of` body: presence of the current pattern.
    PatternVar(usize, Option<Anchor>),
    /// Anonymous `#` inside a `for … of` body: match count of the current
    /// pattern, optionally within a range.
    CountVar(usize, Option<(Box<Cond>, Box<Cond>)>),
    /// Anonymous `@`/`@[i]` inside a `for … of` body: match offset.
    OffsetVar(usize, Option<Box<Cond>>),
    /// Anonymous `!`/`![i]` inside a `for … of` body: match length.
    LengthVar(usize, Option<Box<Cond>>),
}

/// A value bound to an environment slot by a loop or `with` expression.
pub(crate) enum Binding {
    /// A `for … in` / `with` variable value (`None` = undefined).
    Val(Option<Value>),
    /// A `for … of` current-pattern global id.
    Pat(usize),
}

/// Everything the evaluator needs at scan time.
pub(crate) struct EvalCtx<'a> {
    pub data: &'a [u8],
    /// Per global-pattern-id, the sorted match list.
    pub matches: &'a [Vec<Match>],
    /// Results of rules that were evaluated earlier (by rule index).
    pub rule_results: &'a [bool],
    /// Per-scan module state (value trees + PE entry point + parsed imports).
    pub modules: &'a ModuleCtx,
    /// Host-supplied external variable values for this scan, keyed by name. A
    /// name absent from this map is *undefined* and propagates as such through
    /// every operator (exactly like any other undefined value).
    pub externals: &'a HashMap<String, Value>,
    /// The binding environment: a stack of loop/`with` variable values, indexed
    /// by the compile-time slot. Nested loops push/pop; `for` loops mutate the
    /// top binding on each iteration. Interior-mutable because evaluation runs
    /// through shared references.
    pub env: RefCell<Vec<Binding>>,
    /// Condition-evaluation steps left for this scan, shared by every rule in
    /// it. See [`crate::yara::ir::EVAL_STEP_BUDGET`].
    pub steps: &'a Cell<u64>,
}

/// Condition-evaluation steps one scan may spend across all of its rules.
///
/// A YARA range loop takes its bounds from the rule, not from the file, so
/// `for any i in (0..200000000) : ( … )` is a well-formed rule that runs two
/// hundred million iterations on every buffer it is offered. Nothing in the
/// language caps that, and the scan has no other clock: without a step budget a
/// single such rule stalls every scan for as long as it takes.
///
/// The ceiling is far above what real rulesets reach — large community feeds
/// evaluate in the low millions of steps for a whole scan — so it costs
/// legitimate rules nothing and bounds a runaway one to a fraction of a second.
pub(crate) const EVAL_STEP_BUDGET: u64 = 20_000_000;

impl EvalCtx<'_> {
    /// Spend one step. Returns `false` once the scan's budget is gone, which the
    /// evaluator turns into *undefined* — the same value any other unanswerable
    /// sub-expression yields, so it propagates through every operator without a
    /// special case.
    fn charge_step(&self) -> bool {
        let left = self.steps.get();
        if left == 0 {
            return false;
        }
        self.steps.set(left - 1);
        true
    }
    fn env_len(&self) -> usize {
        self.env.borrow().len()
    }
    fn env_push(&self, b: Binding) {
        self.env.borrow_mut().push(b);
    }
    fn env_set(&self, slot: usize, b: Binding) {
        self.env.borrow_mut()[slot] = b;
    }
    fn env_truncate(&self, len: usize) {
        self.env.borrow_mut().truncate(len);
    }
    /// The value bound at `slot` (undefined for a pattern binding).
    fn env_val(&self, slot: usize) -> Option<Value> {
        match &self.env.borrow()[slot] {
            Binding::Val(v) => v.clone(),
            Binding::Pat(_) => None,
        }
    }
    /// The pattern id bound at `slot`.
    fn env_pat(&self, slot: usize) -> usize {
        match &self.env.borrow()[slot] {
            Binding::Pat(p) => *p,
            Binding::Val(_) => unreachable!("expected a pattern binding"),
        }
    }
}

impl Cond {
    /// Evaluate in boolean context (top-level rule condition).
    pub(crate) fn eval_bool(&self, ctx: &EvalCtx) -> bool {
        truthy(&self.eval(ctx))
    }

    fn eval(&self, ctx: &EvalCtx) -> Option<Value> {
        // Charged per node, so a loop body costs at least one step per
        // iteration and no shape of condition can run unbounded.
        if !ctx.charge_step() {
            return None;
        }
        match self {
            Cond::Bool(b) => Some(Value::Bool(*b)),
            Cond::Int(i) => Some(Value::Int(*i)),
            Cond::Float(f) => Some(Value::Float(*f)),
            Cond::Str(s) => Some(Value::Str(s.clone())),
            Cond::Filesize => Some(Value::Int(ctx.data.len() as i64)),

            Cond::Pattern(id, anchor) => {
                let ms = &ctx.matches[*id];
                let ok = match anchor {
                    None => !ms.is_empty(),
                    Some(Anchor::At(e)) => {
                        let n = eval_int(e, ctx)?;
                        n >= 0 && ms.iter().any(|m| m.offset as i64 == n)
                    }
                    Some(Anchor::In(lo, hi)) => {
                        let lo = eval_int(lo, ctx)?;
                        let hi = eval_int(hi, ctx)?;
                        ms.iter().any(|m| {
                            let o = m.offset as i64;
                            o >= lo && o <= hi
                        })
                    }
                };
                Some(Value::Bool(ok))
            }

            Cond::Count(id, range) => {
                let ms = &ctx.matches[*id];
                let c = match range {
                    None => ms.len() as i64,
                    Some((lo, hi)) => {
                        let lo = eval_int(lo, ctx)?;
                        let hi = eval_int(hi, ctx)?;
                        ms.iter()
                            .filter(|m| {
                                let o = m.offset as i64;
                                o >= lo && o <= hi
                            })
                            .count() as i64
                    }
                };
                Some(Value::Int(c))
            }

            Cond::Offset(id, idx) => {
                let i = index_value(idx, ctx)?;
                let ms = &ctx.matches[*id];
                ms.get(i).map(|m| Value::Int(m.offset as i64))
            }

            Cond::Length(id, idx) => {
                let i = index_value(idx, ctx)?;
                let ms = &ctx.matches[*id];
                ms.get(i).map(|m| Value::Int(m.len as i64))
            }

            Cond::RuleRef(idx) => Some(Value::Bool(ctx.rule_results[*idx])),

            Cond::Defined(e) => Some(Value::Bool(e.eval(ctx).is_some())),

            Cond::Not(e) => Some(Value::Bool(!truthy(&e.eval(ctx)))),

            Cond::And(v) => {
                for c in v {
                    if !truthy(&c.eval(ctx)) {
                        return Some(Value::Bool(false));
                    }
                }
                Some(Value::Bool(true))
            }

            Cond::Or(v) => {
                for c in v {
                    if truthy(&c.eval(ctx)) {
                        return Some(Value::Bool(true));
                    }
                }
                Some(Value::Bool(false))
            }

            Cond::Neg(e) => match e.eval(ctx)? {
                Value::Int(i) => Some(Value::Int(i.wrapping_neg())),
                Value::Float(f) => Some(Value::Float(-f)),
                _ => None,
            },

            Cond::BitNot(e) => match e.eval(ctx)? {
                Value::Int(i) => Some(Value::Int(!i)),
                _ => None,
            },

            Cond::Arith(op, a, b) => eval_arith(*op, a, b, ctx),

            Cond::Cmp(op, a, b) => eval_cmp(*op, a, b, ctx),

            Cond::StrCmp(op, a, b) => {
                let a = eval_str(a, ctx)?;
                let b = eval_str(b, ctx)?;
                Some(Value::Bool(str_op(*op, &a, &b)))
            }

            Cond::Matches(a, re) => {
                let a = eval_str(a, ctx)?;
                Some(Value::Bool(re.is_match(Input::new(&a))))
            }

            Cond::Of(quant, items, anchor) => eval_of(quant, items, anchor, ctx),

            Cond::ModAccess(module, path) => eval_access(*module, path, ctx),

            Cond::ModCall(func, args) => {
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    // An undefined argument propagates: the call is undefined.
                    vals.push(a.eval(ctx)?);
                }
                modules::call(*func, ctx, &vals)
            }

            Cond::IntRead(kind, addr) => {
                let off = eval_int(addr, ctx)?;
                read_int(*kind, ctx.data, off)
            }

            Cond::Entrypoint => ctx.modules.entry_point.map(Value::Int),

            // An external is undefined unless the host set a value for this
            // scan; the declared type is not re-checked here (the compiler
            // validated the reference), so we return whatever value was set.
            Cond::External(name, _ty) => ctx.externals.get(name).cloned(),

            Cond::Var(slot) => ctx.env_val(*slot),

            Cond::VarAccess(slot, path) => {
                let base = ctx.env_val(*slot)?;
                walk_access(base, path, ctx)
            }

            Cond::ForIn(f) => eval_for_in(f, ctx),
            Cond::ForOf(f) => eval_for_of(f, ctx),
            Cond::With(w) => eval_with(w, ctx),

            Cond::PatternVar(slot, anchor) => {
                let id = ctx.env_pat(*slot);
                Some(Value::Bool(pattern_present(id, anchor, ctx)?))
            }
            Cond::CountVar(slot, range) => {
                let id = ctx.env_pat(*slot);
                count_in_range(id, range, ctx).map(Value::Int)
            }
            Cond::OffsetVar(slot, idx) => {
                let id = ctx.env_pat(*slot);
                let i = index_value(idx, ctx)?;
                ctx.matches[id].get(i).map(|m| Value::Int(m.offset as i64))
            }
            Cond::LengthVar(slot, idx) => {
                let id = ctx.env_pat(*slot);
                let i = index_value(idx, ctx)?;
                ctx.matches[id].get(i).map(|m| Value::Int(m.len as i64))
            }
        }
    }
}

/// Counts a pattern's matches, optionally restricted to an offset range.
fn count_in_range(id: usize, range: &Option<(Box<Cond>, Box<Cond>)>, ctx: &EvalCtx) -> Option<i64> {
    let ms = &ctx.matches[id];
    Some(match range {
        None => ms.len() as i64,
        Some((lo, hi)) => {
            let lo = eval_int(lo, ctx)?;
            let hi = eval_int(hi, ctx)?;
            ms.iter()
                .filter(|m| {
                    let o = m.offset as i64;
                    o >= lo && o <= hi
                })
                .count() as i64
        }
    })
}

/// Reads an integer of the given kind at `offset` (little- or big-endian).
/// Out-of-bounds or negative offsets yield undefined (`None`), matching yara-x.
fn read_int(kind: IntKind, data: &[u8], offset: i64) -> Option<Value> {
    let off: usize = offset.try_into().ok()?;
    macro_rules! rd {
        ($n:literal, $conv:expr) => {{
            let bytes: [u8; $n] = data.get(off..off + $n)?.try_into().ok()?;
            $conv(bytes)
        }};
    }
    let v: i64 = match kind {
        IntKind::U8 => *data.get(off)? as i64,
        IntKind::I8 => *data.get(off)? as i8 as i64,
        IntKind::U16 => rd!(2, |b| u16::from_le_bytes(b) as i64),
        IntKind::I16 => rd!(2, |b| i16::from_le_bytes(b) as i64),
        IntKind::U32 => rd!(4, |b| u32::from_le_bytes(b) as i64),
        IntKind::I32 => rd!(4, |b| i32::from_le_bytes(b) as i64),
        IntKind::U16be => rd!(2, |b| u16::from_be_bytes(b) as i64),
        IntKind::I16be => rd!(2, |b| i16::from_be_bytes(b) as i64),
        IntKind::U32be => rd!(4, |b| u32::from_be_bytes(b) as i64),
        IntKind::I32be => rd!(4, |b| i32::from_be_bytes(b) as i64),
    };
    Some(Value::Int(v))
}

/// Resolves a module field-access chain against the per-scan value tree. A
/// missing field / out-of-bounds index / wrong key yields undefined (`None`),
/// which propagates to the enclosing expression exactly as in yara-x.
fn eval_access(module: ModuleKind, path: &[Access], ctx: &EvalCtx) -> Option<Value> {
    let base = ctx.modules.root(module)?.clone();
    walk_access(base, path, ctx)
}

/// Walks a field/index-access chain starting from an already-resolved base
/// value (a module root, or a loop/`with`-bound struct/array). Shared by
/// `eval_access` and `Cond::VarAccess`.
fn walk_access(base: Value, path: &[Access], ctx: &EvalCtx) -> Option<Value> {
    let mut cur = base;
    for seg in path {
        cur = match seg {
            Access::Field(name) => match &cur {
                Value::Struct(fields) => fields.get(name)?.clone(),
                _ => return None,
            },
            Access::Index(idx) => match &cur {
                Value::Array(items) => {
                    let i = eval_int(idx, ctx)?;
                    let i: usize = i.try_into().ok()?;
                    items.get(i)?.clone()
                }
                Value::Map(map) => match map.as_ref() {
                    MapVal::Str(m) => {
                        let key = eval_str(idx, ctx)?;
                        m.get(&key)?.clone()
                    }
                    MapVal::Int(m) => {
                        let key = eval_int(idx, ctx)?;
                        m.get(&key)?.clone()
                    }
                },
                _ => return None,
            },
        };
    }
    Some(cur)
}

fn eval_int(c: &Cond, ctx: &EvalCtx) -> Option<i64> {
    match c.eval(ctx)? {
        Value::Int(i) => Some(i),
        Value::Float(f) => Some(f as i64),
        Value::Bool(b) => Some(b as i64),
        _ => None,
    }
}

fn eval_str(c: &Cond, ctx: &EvalCtx) -> Option<Vec<u8>> {
    match c.eval(ctx)? {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

/// A 1-based YARA index (`@a[i]`, `!a[i]`) converted to a 0-based array index.
/// A missing index defaults to 1. Indices < 1 are undefined.
fn index_value(idx: &Option<Box<Cond>>, ctx: &EvalCtx) -> Option<usize> {
    let i = match idx {
        None => 1,
        Some(e) => eval_int(e, ctx)?,
    };
    if i < 1 {
        None
    } else {
        Some((i - 1) as usize)
    }
}

fn eval_arith(op: ArithOp, a: &Cond, b: &Cond, ctx: &EvalCtx) -> Option<Value> {
    let a = a.eval(ctx)?;
    let b = b.eval(ctx)?;

    // Bitwise / shift operators are integer-only.
    let int_only = matches!(
        op,
        ArithOp::Shl
            | ArithOp::Shr
            | ArithOp::BitAnd
            | ArithOp::BitOr
            | ArithOp::BitXor
            | ArithOp::Mod
    );

    if int_only {
        let (Value::Int(x), Value::Int(y)) = (&a, &b) else {
            return None;
        };
        let (x, y) = (*x, *y);
        return match op {
            ArithOp::Mod => {
                if y == 0 {
                    None
                } else {
                    Some(Value::Int(x.wrapping_rem(y)))
                }
            }
            ArithOp::Shl => Some(Value::Int(if !(0..64).contains(&y) { 0 } else { x << y })),
            ArithOp::Shr => Some(Value::Int(if !(0..64).contains(&y) { 0 } else { x >> y })),
            ArithOp::BitAnd => Some(Value::Int(x & y)),
            ArithOp::BitOr => Some(Value::Int(x | y)),
            ArithOp::BitXor => Some(Value::Int(x ^ y)),
            _ => unreachable!(),
        };
    }

    // Arithmetic: integer if both integer, otherwise float.
    if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
        let (x, y) = (*x, *y);
        return match op {
            ArithOp::Add => Some(Value::Int(x.wrapping_add(y))),
            ArithOp::Sub => Some(Value::Int(x.wrapping_sub(y))),
            ArithOp::Mul => Some(Value::Int(x.wrapping_mul(y))),
            ArithOp::Div => {
                if y == 0 {
                    None
                } else {
                    Some(Value::Int(x.wrapping_div(y)))
                }
            }
            _ => unreachable!(),
        };
    }

    let x = a.as_f64()?;
    let y = b.as_f64()?;
    match op {
        ArithOp::Add => Some(Value::Float(x + y)),
        ArithOp::Sub => Some(Value::Float(x - y)),
        ArithOp::Mul => Some(Value::Float(x * y)),
        ArithOp::Div => Some(Value::Float(x / y)),
        _ => unreachable!(),
    }
}

fn eval_cmp(op: CmpOp, a: &Cond, b: &Cond, ctx: &EvalCtx) -> Option<Value> {
    let a = a.eval(ctx)?;
    let b = b.eval(ctx)?;

    let ord = match (&a, &b) {
        (Value::Str(x), Value::Str(y)) => x.cmp(y),
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        _ => {
            let x = a.as_f64()?;
            let y = b.as_f64()?;
            x.partial_cmp(&y)?
        }
    };
    use std::cmp::Ordering::*;
    let r = match op {
        CmpOp::Eq => ord == Equal,
        CmpOp::Ne => ord != Equal,
        CmpOp::Lt => ord == Less,
        CmpOp::Gt => ord == Greater,
        CmpOp::Le => ord != Greater,
        CmpOp::Ge => ord != Less,
    };
    Some(Value::Bool(r))
}

fn str_op(op: StrOp, a: &[u8], b: &[u8]) -> bool {
    // yara-x lowercases case-insensitively with full Unicode folding when the
    // operands are valid UTF-8 (e.g. `"CAFÉ" icontains "fé"`), falling back to
    // ASCII folding for arbitrary bytes.
    fn lower(s: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(s) {
            Ok(v) => v.to_lowercase().into_bytes(),
            Err(_) => s.iter().map(|c| c.to_ascii_lowercase()).collect(),
        }
    }
    match op {
        StrOp::Contains => contains(a, b),
        StrOp::IContains => contains(&lower(a), &lower(b)),
        StrOp::StartsWith => a.starts_with(b),
        StrOp::IStartsWith => lower(a).starts_with(&lower(b)),
        StrOp::EndsWith => a.ends_with(b),
        StrOp::IEndsWith => lower(a).ends_with(&lower(b)),
        StrOp::IEquals => a.eq_ignore_ascii_case(b),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn eval_of(
    quant: &Quant,
    items: &OfItems,
    anchor: &Option<Anchor>,
    ctx: &EvalCtx,
) -> Option<Value> {
    // Count how many items are satisfied, and the total number of items.
    let (total, satisfied) = match items {
        OfItems::Patterns(ids) => {
            let mut sat = 0i64;
            for &id in ids {
                if pattern_present(id, anchor, ctx)? {
                    sat += 1;
                }
            }
            (ids.len() as i64, sat)
        }
        OfItems::Exprs(exprs) => {
            let mut sat = 0i64;
            for e in exprs {
                if truthy(&e.eval(ctx)) {
                    sat += 1;
                }
            }
            (exprs.len() as i64, sat)
        }
    };

    let required = match quant {
        Quant::All => total,
        Quant::Any => 1,
        Quant::None => {
            return Some(Value::Bool(satisfied == 0));
        }
        Quant::Count(n) => eval_int(n, ctx)?,
        Quant::Percent(p) => {
            let p = match p.eval(ctx)? {
                Value::Int(i) => i as f64,
                Value::Float(f) => f,
                _ => return None,
            };
            ((total as f64) * p / 100.0).ceil() as i64
        }
    };
    Some(Value::Bool(satisfied >= required))
}

fn pattern_present(id: usize, anchor: &Option<Anchor>, ctx: &EvalCtx) -> Option<bool> {
    let ms = &ctx.matches[id];
    Some(match anchor {
        None => !ms.is_empty(),
        Some(Anchor::At(e)) => {
            let n = eval_int(e, ctx)?;
            n >= 0 && ms.iter().any(|m| m.offset as i64 == n)
        }
        Some(Anchor::In(lo, hi)) => {
            let lo = eval_int(lo, ctx)?;
            let hi = eval_int(hi, ctx)?;
            ms.iter().any(|m| {
                let o = m.offset as i64;
                o >= lo && o <= hi
            })
        }
    })
}

// ---------------------------------------------------------------------------
// Loop / with evaluation (Phase C)
// ---------------------------------------------------------------------------

/// The requirement mode of a quantifier, after resolving `<expr>`/`<expr>%`
/// against the iteration count `n`.
enum Mode {
    All,
    Any,
    None,
    /// The number of `true` iterations required (`Count`/`Percent`); `0` means
    /// "behave as `none`" (matching yara-x).
    Count(i64),
}

impl Mode {
    fn resolve(quant: &Quant, n: usize, ctx: &EvalCtx) -> Option<Mode> {
        Some(match quant {
            Quant::All => Mode::All,
            Quant::Any => Mode::Any,
            Quant::None => Mode::None,
            Quant::Count(e) => Mode::Count(eval_int(e, ctx)?),
            Quant::Percent(e) => {
                let p = match e.eval(ctx)? {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f,
                    _ => return None,
                };
                Mode::Count(((n as f64) * p / 100.0).ceil() as i64)
            }
        })
    }
}

/// Drives the quantifier over `n` iterations, short-circuiting like yara-x
/// (`any` stops at the first true, `all` at the first false). `eval_item(k)`
/// binds iteration `k` and returns its body's boolean result (undefined → false,
/// via [`Cond::eval_bool`]).
fn quantify<F>(quant: &Quant, n: usize, ctx: &EvalCtx, mut eval_item: F) -> Option<Value>
where
    F: FnMut(usize, &EvalCtx) -> bool,
{
    let mode = Mode::resolve(quant, n, ctx)?;
    let mut count_true: i64 = 0;
    for k in 0..n {
        // The body charges the budget, but a body that is refused still returns
        // a boolean, so the loop itself has to stop as well: `n` comes from the
        // rule and can be hundreds of millions.
        if ctx.steps.get() == 0 {
            return None;
        }
        let b = eval_item(k, ctx);
        if b {
            count_true += 1;
        }
        match mode {
            Mode::All => {
                if !b {
                    return Some(Value::Bool(false));
                }
            }
            Mode::Any => {
                if b {
                    return Some(Value::Bool(true));
                }
            }
            Mode::None => {
                if b {
                    return Some(Value::Bool(false));
                }
            }
            Mode::Count(mx) => {
                // Mirror yara-x: the threshold is only checked after a *true*
                // iteration. Reaching it returns `mx != 0`, so `for 0`/`for 0%`
                // behaves like `none` (any satisfied item makes the loop false).
                if b && count_true >= mx {
                    return Some(Value::Bool(mx != 0));
                }
            }
        }
    }
    Some(Value::Bool(match mode {
        Mode::All | Mode::None => true,
        Mode::Any => false,
        Mode::Count(mx) => mx == 0,
    }))
}

/// The number of integers in the inclusive range `lo..=hi` (0 when `hi < lo`).
fn range_len(lo: i64, hi: i64) -> usize {
    if hi < lo {
        0
    } else {
        // `hi - lo` cannot overflow towards +inf here because hi >= lo; use i128
        // to be safe against extreme bounds, then saturate into usize.
        ((hi as i128) - (lo as i128) + 1)
            .try_into()
            .unwrap_or(usize::MAX)
    }
}

fn eval_for_in(f: &ForIn, ctx: &EvalCtx) -> Option<Value> {
    debug_assert_eq!(ctx.env_len(), f.base);
    match &f.iter {
        Iter::Range(lo, hi) => {
            // An undefined or empty (hi < lo) range yields no iterations, and
            // yara-x makes the whole `for` false in that case.
            let (Some(lo), Some(hi)) = (eval_int(lo, ctx), eval_int(hi, ctx)) else {
                return Some(Value::Bool(false));
            };
            let n = range_len(lo, hi);
            if n == 0 {
                return Some(Value::Bool(false));
            }
            ctx.env_push(Binding::Val(None));
            let r = quantify(&f.quant, n, ctx, |k, ctx| {
                ctx.env_set(f.base, Binding::Val(Some(Value::Int(lo + k as i64))));
                f.body.eval_bool(ctx)
            });
            ctx.env_truncate(f.base);
            r
        }
        Iter::Tuple(items) => {
            // A tuple always has at least one element (the grammar forbids an
            // empty tuple), so no empty-iterable special case is needed.
            ctx.env_push(Binding::Val(None));
            let r = quantify(&f.quant, items.len(), ctx, |k, ctx| {
                let v = items[k].eval(ctx);
                ctx.env_set(f.base, Binding::Val(v));
                f.body.eval_bool(ctx)
            });
            ctx.env_truncate(f.base);
            r
        }
        Iter::Collection(expr) => {
            // An undefined collection makes the whole `for` false.
            let Some(coll) = expr.eval(ctx) else {
                return Some(Value::Bool(false));
            };
            match coll {
                Value::Array(items) => {
                    if items.is_empty() {
                        return Some(Value::Bool(false));
                    }
                    ctx.env_push(Binding::Val(None));
                    let r = quantify(&f.quant, items.len(), ctx, |k, ctx| {
                        ctx.env_set(f.base, Binding::Val(Some(items[k].clone())));
                        f.body.eval_bool(ctx)
                    });
                    ctx.env_truncate(f.base);
                    r
                }
                Value::Map(map) => {
                    // Two variables (key, value). No shipped module exposes a
                    // map yet, so this path is currently unreachable in
                    // practice; it mirrors the array path for completeness.
                    let entries: Vec<(Value, Value)> = match map.as_ref() {
                        MapVal::Str(m) => m
                            .iter()
                            .map(|(k, v)| (Value::Str(k.clone()), v.clone()))
                            .collect(),
                        MapVal::Int(m) => {
                            m.iter().map(|(k, v)| (Value::Int(*k), v.clone())).collect()
                        }
                    };
                    if entries.is_empty() {
                        return Some(Value::Bool(false));
                    }
                    ctx.env_push(Binding::Val(None));
                    ctx.env_push(Binding::Val(None));
                    let r = quantify(&f.quant, entries.len(), ctx, |k, ctx| {
                        let (key, val) = &entries[k];
                        ctx.env_set(f.base, Binding::Val(Some(key.clone())));
                        ctx.env_set(f.base + 1, Binding::Val(Some(val.clone())));
                        f.body.eval_bool(ctx)
                    });
                    ctx.env_truncate(f.base);
                    r
                }
                _ => Some(Value::Bool(false)),
            }
        }
    }
}

fn eval_for_of(f: &ForOf, ctx: &EvalCtx) -> Option<Value> {
    debug_assert_eq!(ctx.env_len(), f.slot);
    ctx.env_push(Binding::Pat(0));
    let r = quantify(&f.quant, f.patterns.len(), ctx, |k, ctx| {
        ctx.env_set(f.slot, Binding::Pat(f.patterns[k]));
        f.body.eval_bool(ctx)
    });
    ctx.env_truncate(f.slot);
    r
}

fn eval_with(w: &With, ctx: &EvalCtx) -> Option<Value> {
    debug_assert_eq!(ctx.env_len(), w.base);
    // Evaluate each declaration in order, pushing it into scope so a later
    // declaration can reference an earlier one. Undefined values are bound as
    // undefined and propagate when used.
    for decl in &w.decls {
        let v = decl.eval(ctx);
        ctx.env_push(Binding::Val(v));
    }
    let r = w.body.eval(ctx);
    ctx.env_truncate(w.base);
    r
}
