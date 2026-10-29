//! Values and formulas of ShapeSheet cells ([MS-VSDX] 2.2.11 and 2.5). A V
//! attribute holds a value in internal units (inches, radians), and an F
//! attribute the formula it came from. A shape's own cells are read by value;
//! the formulas of the cells it inherits from its master are evaluated again,
//! as they may depend on the shape's own size (`Width*0.5`).

use std::f64::consts::PI;

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Num(f64),
    Str(String),
    /// 0xRRGGBB.
    Color(u32),
}

impl Val {
    pub fn num(&self) -> Option<f64> {
        match self {
            Val::Num(n) if n.is_finite() => Some(*n),
            Val::Num(_) => None,
            Val::Str(s) => parse_number(s),
            Val::Color(c) => Some(f64::from(*c)),
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Val::Num(n) => *n != 0.0,
            Val::Str(s) => !s.is_empty(),
            Val::Color(c) => *c != 0,
        }
    }

    fn text(&self) -> String {
        match self {
            Val::Num(n) => format!("{n}"),
            Val::Str(s) => s.clone(),
            Val::Color(c) => format!("#{c:06X}"),
        }
    }
}

/// Internal units per unit word: inches for lengths, radians for angles.
fn unit_factor(u: &str) -> Option<f64> {
    Some(match u.to_ascii_lowercase().as_str() {
        "in" | "inch" | "inches" | "\"" | "dl" => 1.0,
        "ft" => 12.0,
        "yd" => 36.0,
        "mi" => 63_360.0,
        "mm" => 1.0 / 25.4,
        "cm" => 1.0 / 2.54,
        "m" => 1.0 / 0.0254,
        "km" => 1.0 / 0.000_025_4,
        "pt" => 1.0 / 72.0,
        "deg" | "d" => PI / 180.0,
        "rad" => 1.0,
        "%" => 0.01,
        _ => return None,
    })
}

/// The longest number at the start of `s` (sign, digits, fraction,
/// exponent): its value and the bytes it takes.
fn scan_number(s: &[u8]) -> Option<(f64, usize)> {
    let mut i = 0;
    if matches!(s.first(), Some(b'+' | b'-')) {
        i += 1;
    }
    let digits = |s: &[u8], mut i: usize| {
        while s.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        i
    };
    let a = digits(s, i);
    let mut end = a;
    let mut any = a > i;
    if s.get(end) == Some(&b'.') {
        let b = digits(s, end + 1);
        any |= b > end + 1;
        end = b;
    }
    if !any {
        return None;
    }
    if matches!(s.get(end), Some(b'e' | b'E')) {
        let mut j = end + 1;
        if matches!(s.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let k = digits(s, j);
        if k > j {
            end = k;
        }
    }
    let t = std::str::from_utf8(&s[..end]).ok()?;
    let v: f64 = t.parse().ok()?;
    v.is_finite().then_some((v, end))
}

/// A number as a cell holds it: plain, TRUE or FALSE, or followed by a unit
/// (`2 in`, `45 deg`), in internal units.
pub fn parse_number(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("true") {
        return Some(1.0);
    }
    if t.eq_ignore_ascii_case("false") {
        return Some(0.0);
    }
    let (v, n) = scan_number(t.as_bytes())?;
    let rest = t[n..].trim();
    if rest.is_empty() {
        return Some(v);
    }
    unit_factor(rest).map(|f| v * f)
}

/// What a formula refers to.
pub trait Env {
    /// The cell `path` (`Width`, `Geometry1.X2`, `User.Name`), of the shape
    /// `Sheet.N` names or of the shape the formula is in.
    fn cell(&mut self, sheet: Option<u32>, path: &str) -> Option<Val>;
    fn themeval(&mut self, args: &[Val]) -> Option<Val>;
}

/// Evaluates `f`; `None` for what is not supported or fails.
pub fn eval(f: &str, env: &mut dyn Env) -> Option<Val> {
    let mut p = Parser {
        s: f.as_bytes(),
        i: 0,
        env,
        steps: 0,
    };
    let v = p.expr(0)?;
    p.ws();
    (p.i == p.s.len()).then_some(v)
}

/// More tokens than any real formula has.
const MAX_STEPS: u32 = 4000;
const MAX_DEPTH: u32 = 48;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    env: &'a mut dyn Env,
    steps: u32,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(u8::is_ascii_whitespace) {
            self.i += 1;
        }
    }

    fn eat(&mut self, t: &str) -> bool {
        self.ws();
        if self.s[self.i.min(self.s.len())..].starts_with(t.as_bytes()) {
            self.i += t.len();
            true
        } else {
            false
        }
    }

    fn peek_is(&mut self, t: &str) -> bool {
        self.ws();
        self.s[self.i.min(self.s.len())..].starts_with(t.as_bytes())
    }

    /// Comparison and arithmetic from the loosest operators to the tightest.
    fn expr(&mut self, depth: u32) -> Option<Val> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.binary(0, depth)
    }

    fn binary(&mut self, level: usize, depth: u32) -> Option<Val> {
        const LEVELS: [&[&str]; 5] = [
            &["<>", "="],
            &["<=", ">=", "<", ">"],
            &["&"],
            &["+", "-"],
            &["*", "/"],
        ];
        if level == LEVELS.len() {
            return self.power(depth);
        }
        let mut left = self.binary(level + 1, depth)?;
        'outer: loop {
            for op in LEVELS[level] {
                // "<" and ">" must not take the front of "<>" and "<=".
                if self.peek_is(op) && !(level == 1 && self.peek_is("<>")) {
                    self.eat(op);
                    self.steps += 1;
                    if self.steps > MAX_STEPS {
                        return None;
                    }
                    let right = self.binary(level + 1, depth)?;
                    left = apply(op, left, right)?;
                    continue 'outer;
                }
            }
            return Some(left);
        }
    }

    fn power(&mut self, depth: u32) -> Option<Val> {
        let mut v = self.unary(depth)?;
        while self.eat("^") {
            let r = self.unary(depth)?;
            v = Val::Num(v.num()?.powf(r.num()?));
        }
        Some(v)
    }

    /// The signs in front of an operand, taken in a loop: a recursion per
    /// sign is a frame of the stack for each byte of a formula.
    fn unary(&mut self, depth: u32) -> Option<Val> {
        let mut minus = 0u32;
        loop {
            if self.eat("-") {
                minus += 1;
            } else if !self.eat("+") {
                break;
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return None;
            }
        }
        let v = self.primary(depth)?;
        if minus == 0 {
            return Some(v);
        }
        let n = v.num()?;
        Some(Val::Num(if minus % 2 == 1 { -n } else { n }))
    }

    fn primary(&mut self, depth: u32) -> Option<Val> {
        self.ws();
        self.steps += 1;
        if self.steps > MAX_STEPS || depth > MAX_DEPTH {
            return None;
        }
        let c = *self.s.get(self.i)?;
        if c == b'(' {
            self.i += 1;
            let v = self.expr(depth + 1)?;
            return self.eat(")").then_some(v);
        }
        if c == b'"' {
            return self.string();
        }
        if c == b'#' {
            let h = self.s.get(self.i + 1..self.i + 7)?;
            let t = std::str::from_utf8(h).ok()?;
            let v = u32::from_str_radix(t, 16).ok()?;
            self.i += 7;
            return Some(Val::Color(v));
        }
        if c.is_ascii_digit() || c == b'.' {
            let (v, n) = scan_number(&self.s[self.i..])?;
            self.i += n;
            // A unit word right after the number, with or without a space.
            let save = self.i;
            self.ws();
            let start = self.i;
            if self.s.get(start) == Some(&b'"') {
                // A quote after a number is the inch sign.
                self.i += 1;
                return Some(Val::Num(v));
            }
            while self
                .s
                .get(self.i)
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'%')
            {
                self.i += 1;
            }
            let word = std::str::from_utf8(&self.s[start..self.i]).ok()?;
            let next = self.s.get(self.i).copied();
            if !word.is_empty()
                && !matches!(next, Some(b'(' | b'.' | b'!'))
                && let Some(f) = unit_factor(word)
            {
                return Some(Val::Num(v * f));
            }
            self.i = save;
            return Some(Val::Num(v));
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            return self.name(depth);
        }
        None
    }

    fn string(&mut self) -> Option<Val> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            if c == b'"' {
                if self.s.get(self.i) == Some(&b'"') {
                    out.push(b'"');
                    self.i += 1;
                    continue;
                }
                return Some(Val::Str(String::from_utf8_lossy(&out).into_owned()));
            }
            out.push(c);
        }
    }

    fn name(&mut self, depth: u32) -> Option<Val> {
        let start = self.i;
        while self.s.get(self.i).is_some_and(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'!' | b'[' | b']')
        }) {
            self.i += 1;
        }
        let name = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if self.s.get(self.i) == Some(&b'(') {
            self.i += 1;
            let mut args: Vec<Option<Val>> = vec![];
            if !self.eat(")") {
                loop {
                    args.push(self.expr(depth + 1));
                    // An argument that failed is kept as `None`: IF and
                    // IFERROR may not need it. Resume at its end.
                    if args.last().is_some_and(Option::is_none) && !self.skip_arg() {
                        return None;
                    }
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat(")") {
                        break;
                    }
                    return None;
                }
            }
            return self.call(&name.to_ascii_uppercase(), args);
        }
        let low = name.to_ascii_lowercase();
        match low.as_str() {
            "true" => return Some(Val::Num(1.0)),
            "false" => return Some(Val::Num(0.0)),
            _ => {}
        }
        if let Some(rest) = low.strip_prefix("sheet.") {
            let bang = rest.find('!')?;
            let id: u32 = rest[..bang].parse().ok()?;
            let path = &name[6 + bang + 1..];
            if path.contains('!') || path.is_empty() {
                return None;
            }
            return self.env.cell(Some(id), path);
        }
        if name.contains('!') {
            return None;
        }
        self.env.cell(None, name)
    }

    /// Moves past the argument that did not evaluate: to the next comma or
    /// closing parenthesis at its own nesting level.
    fn skip_arg(&mut self) -> bool {
        let mut depth = 0u32;
        let mut quoted = false;
        while let Some(&c) = self.s.get(self.i) {
            match c {
                b'"' => quoted = !quoted,
                b'(' if !quoted => depth += 1,
                b')' if !quoted => {
                    if depth == 0 {
                        return true;
                    }
                    depth -= 1;
                }
                b',' if !quoted && depth == 0 => return true,
                _ => {}
            }
            self.i += 1;
        }
        false
    }

    fn call(&mut self, f: &str, args: Vec<Option<Val>>) -> Option<Val> {
        let n = |i: usize| args.get(i).and_then(|a| a.as_ref()).and_then(Val::num);
        let all = || -> Option<Vec<f64>> {
            args.iter()
                .map(|a| a.as_ref().and_then(Val::num))
                .collect::<Option<Vec<f64>>>()
        };
        let num = |v: f64| v.is_finite().then_some(Val::Num(v));
        match f {
            "IF" => {
                let c = args.first()?.as_ref()?.truthy();
                args.get(if c { 1 } else { 2 })?.clone()
            }
            "IFERROR" => match args.first()? {
                Some(v) => Some(v.clone()),
                None => args.get(1)?.clone(),
            },
            "GUARD" | "UPLUS" => args.first()?.clone(),
            "AND" => Some(Val::Num(
                args.iter().all(|a| a.as_ref().is_some_and(Val::truthy)) as u8 as f64,
            )),
            "OR" => Some(Val::Num(
                args.iter().any(|a| a.as_ref().is_some_and(Val::truthy)) as u8 as f64,
            )),
            "NOT" => Some(Val::Num(!args.first()?.as_ref()?.truthy() as u8 as f64)),
            "ABS" => num(n(0)?.abs()),
            "SQRT" => {
                let v = n(0)?;
                (v >= 0.0).then(|| Val::Num(v.sqrt()))
            }
            "SIN" => num(n(0)?.sin()),
            "COS" => num(n(0)?.cos()),
            "TAN" => num(n(0)?.tan()),
            "ASIN" => num(n(0)?.asin()),
            "ACOS" => num(n(0)?.acos()),
            "ATAN" => num(n(0)?.atan()),
            "ATAN2" => num(n(0)?.atan2(n(1)?)),
            "POW" => num(n(0)?.powf(n(1)?)),
            "LN" => num(n(0)?.ln()),
            "LOG10" => num(n(0)?.log10()),
            "INT" | "FLOOR" if args.len() == 1 => num(n(0)?.floor()),
            "FLOOR" => {
                let (x, s) = (n(0)?, n(1)?);
                (s != 0.0).then(|| Val::Num((x / s).floor() * s))
            }
            "CEILING" => {
                let (x, s) = (n(0)?, n(1).unwrap_or(1.0));
                (s != 0.0).then(|| Val::Num((x / s).ceil() * s))
            }
            "TRUNC" => num(n(0)?.trunc()),
            "ROUND" => {
                let p = 10f64.powi(n(1).unwrap_or(0.0).clamp(-15.0, 15.0) as i32);
                num((n(0)? * p).round() / p)
            }
            "SIGN" => num(n(0)?.signum() * (n(0)? != 0.0) as u8 as f64),
            "MOD" => {
                let (x, d) = (n(0)?, n(1)?);
                (d != 0.0).then(|| Val::Num(x - d * (x / d).floor()))
            }
            "PI" => Some(Val::Num(PI)),
            "DEG" => num(n(0)? * PI / 180.0),
            "RAD" => num(n(0)?),
            "MAX" => all()?.into_iter().reduce(f64::max).map(Val::Num),
            "MIN" => all()?.into_iter().reduce(f64::min).map(Val::Num),
            "SUM" => num(all()?.into_iter().sum()),
            "DEPENDSON" => Some(Val::Num(0.0)),
            "CAT" => Some(Val::Str(
                args.iter()
                    .map(|a| a.as_ref().map(Val::text))
                    .collect::<Option<Vec<_>>>()?
                    .concat(),
            )),
            "RGB" => {
                let c = |i: usize| n(i).map(|v| v.round().clamp(0.0, 255.0) as u32);
                Some(Val::Color((c(0)? << 16) | (c(1)? << 8) | c(2)?))
            }
            "THEMEVAL" => {
                let vals: Vec<Val> = args.into_iter().flatten().collect();
                self.env.themeval(&vals)
            }
            _ => None,
        }
    }
}

fn apply(op: &str, a: Val, b: Val) -> Option<Val> {
    if op == "&" {
        return Some(Val::Str(a.text() + &b.text()));
    }
    if matches!(op, "=" | "<>" | "<" | ">" | "<=" | ">=") {
        let ord = match (&a, &b) {
            (Val::Str(x), Val::Str(y)) => x.to_lowercase().cmp(&y.to_lowercase()),
            _ => {
                let (x, y) = (a.num()?, b.num()?);
                // Equal to the precision cells are stored at.
                if (x - y).abs() < 1e-9 * x.abs().max(y.abs()).max(1.0) {
                    std::cmp::Ordering::Equal
                } else {
                    x.partial_cmp(&y)?
                }
            }
        };
        use std::cmp::Ordering::*;
        let r = match op {
            "=" => ord == Equal,
            "<>" => ord != Equal,
            "<" => ord == Less,
            ">" => ord == Greater,
            "<=" => ord != Greater,
            _ => ord != Less,
        };
        return Some(Val::Num(r as u8 as f64));
    }
    let (x, y) = (a.num()?, b.num()?);
    let r = match op {
        "+" => x + y,
        "-" => x - y,
        "*" => x * y,
        _ => {
            if y == 0.0 {
                return None;
            }
            x / y
        }
    };
    r.is_finite().then_some(Val::Num(r))
}

/// A colour as a V attribute holds it: `#RRGGBB`, or an index of the colour
/// table (`table` answers for the indexes past 23).
pub fn parse_color(v: &str, table: &dyn Fn(u32) -> Option<u32>) -> Option<u32> {
    let t = v.trim();
    if let Some(h) = t.strip_prefix('#') {
        if h.len() == 6 {
            return u32::from_str_radix(h, 16).ok();
        }
        return None;
    }
    let n = parse_number(t)?;
    if !(0.0..=16_777_215.0).contains(&n) {
        return None;
    }
    let ix = n as u32;
    // Custom colours ("RGB(r,g,b)" read as numbers) are past the table.
    if ix <= 23 {
        return Some(DEFAULT_COLORS[ix as usize]);
    }
    table(ix)
}

/// The colour table's first 24 entries ([MS-VSDX] 2.2.7.6).
pub const DEFAULT_COLORS: [u32; 24] = [
    0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF, 0x800000,
    0x008000, 0x000080, 0x808000, 0x800080, 0x008080, 0xC0C0C0, 0xE6E6E6, 0xCDCDCD, 0xB3B3B3,
    0x9A9A9A, 0x808080, 0x666666, 0x4D4D4D, 0x333333, 0x1A1A1A,
];

#[cfg(test)]
mod tests {
    use super::*;

    struct Cells;

    impl Env for Cells {
        fn cell(&mut self, sheet: Option<u32>, path: &str) -> Option<Val> {
            match (sheet, path) {
                (None, "Width") => Some(Val::Num(4.0)),
                (None, "Height") => Some(Val::Num(2.0)),
                (Some(5), "Width") => Some(Val::Num(10.0)),
                (None, "User.Name") => Some(Val::Str("a".into())),
                _ => None,
            }
        }

        fn themeval(&mut self, args: &[Val]) -> Option<Val> {
            args.get(1).cloned()
        }
    }

    fn num(f: &str) -> Option<f64> {
        eval(f, &mut Cells).and_then(|v| v.num())
    }

    #[test]
    fn plain_numbers_and_units() {
        assert_eq!(parse_number("0.25"), Some(0.25));
        assert_eq!(parse_number(" -1.5E-1 "), Some(-0.15));
        assert_eq!(parse_number("TRUE"), Some(1.0));
        assert!((parse_number("25.4 mm").unwrap() - 1.0).abs() < 1e-12);
        assert_eq!(parse_number("72 pt"), Some(1.0));
        assert!((parse_number("180 deg").unwrap() - PI).abs() < 1e-12);
        assert_eq!(parse_number("12 ft"), Some(144.0));
        assert_eq!(parse_number("Themed"), None);
        assert_eq!(parse_number("1 parsec"), None);
        assert_eq!(parse_number(""), None);
        assert_eq!(parse_number("inf"), None);
    }

    #[test]
    fn arithmetic_follows_the_order_of_operations() {
        assert_eq!(num("Width*0.5"), Some(2.0));
        assert_eq!(num("1+2*3"), Some(7.0));
        assert_eq!(num("(1+2)*3"), Some(9.0));
        assert_eq!(num("-2^2"), Some(4.0));
        assert_eq!(num("2^3^2"), Some(64.0));
        assert_eq!(num("Width/Height*0.5"), Some(1.0));
        assert_eq!(num("Width-1-1"), Some(2.0));
        assert_eq!(num("1/0"), None);
    }

    #[test]
    fn signs_in_front_of_an_operand() {
        assert_eq!(num("--3"), Some(3.0));
        assert_eq!(num("-+-3"), Some(3.0));
        assert_eq!(num("-+3"), Some(-3.0));
        assert_eq!(num("+-Width"), Some(-4.0));
        assert_eq!(eval("+User.Name", &mut Cells), Some(Val::Str("a".into())));
        assert_eq!(eval("-User.Name", &mut Cells), None);
        assert_eq!(eval("--User.Name", &mut Cells), None);
    }

    /// 200,000 signs on a 256 KB stack: a recursion per sign overflows it.
    #[test]
    fn a_formula_of_signs_is_refused_not_recursed_into() {
        let f = format!("{}1", "-".repeat(200_000));
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || assert_eq!(eval(&f, &mut Cells), None))
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn functions_and_comparisons() {
        assert_eq!(num("IF(Width>3,10,20)"), Some(10.0));
        assert_eq!(num("IF(Width<>4,10,20)"), Some(20.0));
        assert_eq!(num("IF(Width<=4,1,2)"), Some(1.0));
        assert_eq!(num("MAX(Height,3)*2"), Some(6.0));
        assert_eq!(num("SQRT(Width)"), Some(2.0));
        assert_eq!(num("AND(1,Width=4)"), Some(1.0));
        assert_eq!(num("NOT(OR(0,0))"), Some(1.0));
        assert_eq!(num("GUARD(Width*2)"), Some(8.0));
        assert_eq!(num("IFERROR(Nope,7)"), Some(7.0));
        // The branch not taken may fail.
        assert_eq!(num("IF(1,5,Nope)"), Some(5.0));
        assert_eq!(num("IF(0,5,Nope)"), None);
        assert_eq!(num("THEMEVAL(\"LineWeight\",3)"), Some(3.0));
    }

    #[test]
    fn units_in_formulas_and_references_to_other_shapes() {
        assert_eq!(num("Sheet.5!Width*2"), Some(20.0));
        assert_eq!(num("0.19685039370079DL"), Some(0.19685039370079));
        assert!((num("25.4 mm+1").unwrap() - 2.0).abs() < 1e-12);
        assert!((num("DEG(180)").unwrap() - PI).abs() < 1e-12);
        assert_eq!(num("thePage!PageWidth"), None);
        assert_eq!(num("Sheet.5!"), None);
    }

    #[test]
    fn strings_colors_and_garbage() {
        assert_eq!(eval("\"a\"&\"b\"", &mut Cells), Some(Val::Str("ab".into())));
        assert_eq!(
            eval("RGB(255,0,16)", &mut Cells),
            Some(Val::Color(0xFF0010))
        );
        assert_eq!(eval("#00ff7f", &mut Cells), Some(Val::Color(0x00FF7F)));
        assert_eq!(eval("User.Name=\"A\"", &mut Cells), Some(Val::Num(1.0)));
        for bad in ["", "(", "1+", "*2", "ABS(", "\"x", "#12", "1 2"] {
            assert_eq!(eval(bad, &mut Cells), None, "{bad:?}");
        }
        let deep = "(".repeat(5000) + "1" + &")".repeat(5000);
        assert_eq!(eval(&deep, &mut Cells), None);
        let long = "1+".repeat(10_000) + "1";
        assert_eq!(eval(&long, &mut Cells), None);
    }

    #[test]
    fn colors_by_table_and_by_value() {
        let table = |i: u32| (i == 30).then_some(0x112233);
        assert_eq!(parse_color("#FF8800", &table), Some(0xFF8800));
        assert_eq!(parse_color("2", &table), Some(0xFF0000));
        assert_eq!(parse_color("30", &table), Some(0x112233));
        assert_eq!(parse_color("31", &table), None);
        assert_eq!(parse_color("Themed", &table), None);
        assert_eq!(parse_color("#12", &table), None);
    }
}
