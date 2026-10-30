//! Drawing geometry of ODF shapes as DrawingML paths: SVG path data
//! (svg:d, [SVG 1.1] 8.3, which ODF uses for draw:path and draw:polygon),
//! and enhanced geometry ([ODF 1.2] part 1, 19.145 and 19.171: draw:equation
//! formulas, modifiers and draw:enhanced-path commands), evaluated here into
//! absolute points.

use crate::formats::office::common::xml::Node;
use crate::formats::office::slides::model::{Geometry, Path, PathCmd};
use std::f64::consts::PI;

/// Path units per view box unit, so that small view boxes keep precision.
fn scale_for(w: f64, h: f64) -> f64 {
    let m = w.abs().max(h.abs());
    if m <= 0.0 || !m.is_finite() {
        1.0
    } else if m < 100_000.0 {
        100_000.0 / m
    } else {
        1.0
    }
}

/// Builds paths, converting points to path units.
struct Builder {
    s: f64,
    ox: f64,
    oy: f64,
    paths: Vec<Path>,
    cur: Path,
    pos: (f64, f64),
    start: (f64, f64),
    open: bool,
}

impl Builder {
    fn new(vb: [f64; 4]) -> Builder {
        let s = scale_for(vb[2], vb[3]);
        Builder {
            s,
            ox: vb[0],
            oy: vb[1],
            paths: vec![],
            cur: Path {
                w: (vb[2] * s).round().max(1.0) as i64,
                h: (vb[3] * s).round().max(1.0) as i64,
                fill: true,
                stroke: true,
                cmds: vec![],
            },
            pos: (0.0, 0.0),
            start: (0.0, 0.0),
            open: false,
        }
    }

    fn p(&self, x: f64, y: f64) -> (i64, i64) {
        let f = |v: f64| {
            if v.is_finite() {
                v.clamp(-1e12, 1e12).round() as i64
            } else {
                0
            }
        };
        (f((x - self.ox) * self.s), f((y - self.oy) * self.s))
    }

    fn move_to(&mut self, x: f64, y: f64) {
        let (a, b) = self.p(x, y);
        self.cur.cmds.push(PathCmd::Move(a, b));
        self.pos = (x, y);
        self.start = (x, y);
        self.open = true;
    }

    fn line_to(&mut self, x: f64, y: f64) {
        if !self.open {
            // A path that starts with a line starts at its point.
            if self.cur.cmds.is_empty() && self.paths.is_empty() {
                self.move_to(x, y);
                return;
            }
            self.move_to(self.pos.0, self.pos.1);
        }
        let (a, b) = self.p(x, y);
        self.cur.cmds.push(PathCmd::Line(a, b));
        self.pos = (x, y);
    }

    fn cubic(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, x: f64, y: f64) {
        if !self.open {
            self.move_to(self.pos.0, self.pos.1);
        }
        let (a, b) = self.p(x1, y1);
        let (c, d) = self.p(x2, y2);
        let (e, f) = self.p(x, y);
        self.cur.cmds.push(PathCmd::Cubic(a, b, c, d, e, f));
        self.pos = (x, y);
    }

    fn quad(&mut self, x1: f64, y1: f64, x: f64, y: f64) {
        let (p0x, p0y) = self.pos;
        self.cubic(
            p0x + 2.0 / 3.0 * (x1 - p0x),
            p0y + 2.0 / 3.0 * (y1 - p0y),
            x + 2.0 / 3.0 * (x1 - x),
            y + 2.0 / 3.0 * (y1 - y),
            x,
            y,
        );
    }

    fn close(&mut self) {
        if self.open {
            self.cur.cmds.push(PathCmd::Close);
            self.pos = self.start;
        }
    }

    /// An elliptical arc from angle `a0` sweeping `sweep` (radians, in the
    /// y-down plane), as cubics; a line or move to its start first.
    #[allow(clippy::too_many_arguments)]
    fn arc(&mut self, cx: f64, cy: f64, rx: f64, ry: f64, a0: f64, sweep: f64, mv: bool) {
        let sx = cx + rx * a0.cos();
        let sy = cy + ry * a0.sin();
        if mv || !self.open {
            self.move_to(sx, sy);
        } else {
            self.line_to(sx, sy);
        }
        if sweep == 0.0 || !sweep.is_finite() {
            return;
        }
        let n = (sweep.abs() / (PI / 2.0)).ceil().clamp(1.0, 64.0) as usize;
        let step = sweep / n as f64;
        let k = 4.0 / 3.0 * (step / 4.0).tan();
        let mut a = a0;
        for _ in 0..n {
            let b = a + step;
            let (ca, sa, cb, sb) = (a.cos(), a.sin(), b.cos(), b.sin());
            self.cubic(
                cx + rx * (ca - k * sa),
                cy + ry * (sa + k * ca),
                cx + rx * (cb + k * sb),
                cy + ry * (sb - k * cb),
                cx + rx * cb,
                cy + ry * sb,
            );
            a = b;
        }
    }

    /// Ends the current subpath group (N): later commands start a new path.
    fn end(&mut self) {
        if !self.cur.cmds.is_empty() {
            let next = Path {
                w: self.cur.w,
                h: self.cur.h,
                fill: true,
                stroke: true,
                cmds: vec![],
            };
            self.paths.push(std::mem::replace(&mut self.cur, next));
        }
        self.open = false;
    }

    fn finish(mut self) -> Option<Geometry> {
        self.end();
        if self.paths.is_empty() || self.paths.len() > 4096 {
            return None;
        }
        for p in &mut self.paths {
            even_odd(p);
        }
        Some(Geometry::Custom(self.paths))
    }
}

/// One subpath's commands with its bounds and signed area (of the polygon
/// through its points).
struct Sub {
    cmds: Vec<PathCmd>,
    bounds: [i64; 4],
    area: f64,
}

fn points_of(c: &PathCmd) -> Vec<(i64, i64)> {
    match *c {
        PathCmd::Move(x, y) | PathCmd::Line(x, y) => vec![(x, y)],
        PathCmd::Cubic(a, b, c, d, e, f) => vec![(a, b), (c, d), (e, f)],
        PathCmd::Quad(a, b, c, d) => vec![(a, b), (c, d)],
        PathCmd::Close => vec![],
    }
}

/// The end point of a command, if it has one.
fn end_of(c: &PathCmd) -> Option<(i64, i64)> {
    match *c {
        PathCmd::Move(x, y) | PathCmd::Line(x, y) => Some((x, y)),
        PathCmd::Cubic(.., x, y) | PathCmd::Quad(_, _, x, y) => Some((x, y)),
        PathCmd::Close => None,
    }
}

/// `cmds` traversed backwards: the same outline in the other direction.
fn reversed(cmds: &[PathCmd]) -> Vec<PathCmd> {
    let closed = matches!(cmds.last(), Some(PathCmd::Close));
    let body = &cmds[..cmds.len() - usize::from(closed)];
    // The points the outline passes through, with the segments between.
    let mut start = (0, 0);
    let mut segs: Vec<((i64, i64), &PathCmd)> = vec![];
    let mut cur = (0, 0);
    for c in body {
        match c {
            PathCmd::Move(x, y) => {
                start = (*x, *y);
                cur = start;
            }
            c => {
                segs.push((cur, c));
                cur = end_of(c).unwrap_or(cur);
            }
        }
    }
    let mut out = vec![PathCmd::Move(cur.0, cur.1)];
    for (from, c) in segs.into_iter().rev() {
        out.push(match *c {
            PathCmd::Line(..) => PathCmd::Line(from.0, from.1),
            PathCmd::Cubic(a, b, c, d, ..) => PathCmd::Cubic(c, d, a, b, from.0, from.1),
            PathCmd::Quad(a, b, ..) => PathCmd::Quad(a, b, from.0, from.1),
            _ => continue,
        });
    }
    let _ = start;
    if closed {
        out.push(PathCmd::Close);
    }
    out
}

/// Fills a path with the even-odd rule, as ODF's renderers do and DrawingML
/// does not: a subpath inside an odd number of others is drawn in the
/// direction opposite to the first one's, so that the nonzero rule leaves
/// it a hole. Nesting is told by the subpaths' bounds.
fn even_odd(p: &mut Path) {
    if !p.fill {
        return;
    }
    let mut subs: Vec<Sub> = vec![];
    for c in &p.cmds {
        if matches!(c, PathCmd::Move(..)) || subs.is_empty() {
            subs.push(Sub {
                cmds: vec![],
                bounds: [i64::MAX, i64::MAX, i64::MIN, i64::MIN],
                area: 0.0,
            });
        }
        let s = subs.last_mut().expect("pushed above");
        s.cmds.push(*c);
        for (x, y) in points_of(c) {
            s.bounds = [
                s.bounds[0].min(x),
                s.bounds[1].min(y),
                s.bounds[2].max(x),
                s.bounds[3].max(y),
            ];
        }
    }
    if subs.len() < 2 || subs.len() > 64 {
        return;
    }
    for s in &mut subs {
        let pts: Vec<(i64, i64)> = s.cmds.iter().filter_map(end_of).collect();
        let mut a = 0.0;
        for i in 0..pts.len() {
            let (x0, y0) = pts[i];
            let (x1, y1) = pts[(i + 1) % pts.len()];
            a += x0 as f64 * y1 as f64 - x1 as f64 * y0 as f64;
        }
        s.area = a;
    }
    let inside = |inner: &[i64; 4], outer: &[i64; 4]| {
        inner[0] >= outer[0]
            && inner[1] >= outer[1]
            && inner[2] <= outer[2]
            && inner[3] <= outer[3]
            && inner != outer
    };
    let first_sign = subs[0].area.signum();
    let mut changed = false;
    for i in 1..subs.len() {
        let depth = (0..i)
            .filter(|&j| inside(&subs[i].bounds, &subs[j].bounds))
            .count();
        let want = if depth % 2 == 1 {
            -first_sign
        } else {
            first_sign
        };
        if subs[i].area != 0.0 && subs[i].area.signum() != want {
            subs[i].cmds = reversed(&subs[i].cmds);
            changed = true;
        }
    }
    if changed {
        p.cmds = subs.into_iter().flat_map(|s| s.cmds).collect();
    }
}

/// Parses a view box ("x y w h").
pub fn view_box(s: Option<&str>) -> Option<[f64; 4]> {
    let v: Vec<f64> = s?
        .split([' ', ','])
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse().ok())
        .collect();
    (v.len() == 4 && v[2] > 0.0 && v[3] > 0.0).then(|| [v[0], v[1], v[2], v[3]])
}

/// Tokens of SVG path data: commands and numbers.
fn svg_tokens(d: &str) -> Vec<Result<char, f64>> {
    let mut out = vec![];
    let b = d.as_bytes();
    let mut i = 0;
    while i < b.len() && out.len() < 1 << 20 {
        let c = b[i] as char;
        if c.is_ascii_alphabetic() && c != 'e' && c != 'E' {
            out.push(Ok(c));
            i += 1;
        } else if c == '-' || c == '+' || c == '.' || c.is_ascii_digit() {
            let start = i;
            i += 1;
            let mut dot = c == '.';
            while i < b.len() {
                let d = b[i] as char;
                if d.is_ascii_digit() {
                    i += 1;
                } else if d == '.' && !dot {
                    dot = true;
                    i += 1;
                } else if (d == 'e' || d == 'E') && i + 1 < b.len() {
                    i += 1;
                    if b[i] == b'-' || b[i] == b'+' {
                        i += 1;
                    }
                } else {
                    break;
                }
            }
            if let Ok(v) = d[start..i].parse::<f64>() {
                out.push(Err(v));
            }
        } else {
            i += 1;
        }
    }
    out
}

/// SVG arc in endpoint form to the builder ([SVG 1.1] F.6.5). The x-axis
/// rotation is left out: ODF writers emit unrotated arcs.
fn svg_arc(b: &mut Builder, (rx, ry): (f64, f64), large: bool, sweep: bool, x: f64, y: f64) {
    let (x1, y1) = b.pos;
    let (mut rx, mut ry) = (rx.abs(), ry.abs());
    if rx == 0.0 || ry == 0.0 || (x1 == x && y1 == y) {
        b.line_to(x, y);
        return;
    }
    let dx = (x1 - x) / 2.0;
    let dy = (y1 - y) / 2.0;
    let l = (dx * dx) / (rx * rx) + (dy * dy) / (ry * ry);
    if l > 1.0 {
        rx *= l.sqrt();
        ry *= l.sqrt();
    }
    let num = rx * rx * ry * ry - rx * rx * dy * dy - ry * ry * dx * dx;
    let den = rx * rx * dy * dy + ry * ry * dx * dx;
    let mut co = if den == 0.0 {
        0.0
    } else {
        (num / den).max(0.0).sqrt()
    };
    if large == sweep {
        co = -co;
    }
    let cxp = co * rx * dy / ry;
    let cyp = -co * ry * dx / rx;
    let cx = cxp + (x1 + x) / 2.0;
    let cy = cyp + (y1 + y) / 2.0;
    let a0 = ((y1 - cy) / ry).atan2((x1 - cx) / rx);
    let a1 = ((y - cy) / ry).atan2((x - cx) / rx);
    let mut d = a1 - a0;
    if sweep && d < 0.0 {
        d += 2.0 * PI;
    } else if !sweep && d > 0.0 {
        d -= 2.0 * PI;
    }
    b.arc(cx, cy, rx, ry, a0, d, false);
}

/// SVG path data in view box `vb` as a custom geometry.
pub fn svg_path(d: &str, vb: [f64; 4], closed: bool) -> Option<Geometry> {
    let t = svg_tokens(d);
    let mut b = Builder::new(vb);
    if !closed {
        b.cur.fill = false;
    }
    let mut i = 0;
    let mut cmd = 'M';
    let mut last_ctrl: Option<(f64, f64)> = None;
    let num = |i: &mut usize| -> Option<f64> {
        match t.get(*i) {
            Some(Err(v)) => {
                *i += 1;
                Some(*v)
            }
            _ => None,
        }
    };
    while i < t.len() {
        if let Ok(c) = t[i] {
            cmd = c;
            i += 1;
            if matches!(c, 'Z' | 'z') {
                b.close();
                last_ctrl = None;
                continue;
            }
        }
        let rel = cmd.is_ascii_lowercase();
        let (px, py) = b.pos;
        let o = |x: f64, y: f64| if rel { (px + x, py + y) } else { (x, y) };
        let before = i;
        match cmd.to_ascii_uppercase() {
            'M' => {
                let (Some(x), Some(y)) = (num(&mut i), num(&mut i)) else {
                    break;
                };
                let (x, y) = o(x, y);
                b.move_to(x, y);
                cmd = if rel { 'l' } else { 'L' };
                last_ctrl = None;
            }
            'L' => {
                let (Some(x), Some(y)) = (num(&mut i), num(&mut i)) else {
                    break;
                };
                let (x, y) = o(x, y);
                b.line_to(x, y);
                last_ctrl = None;
            }
            'H' => {
                let Some(x) = num(&mut i) else { break };
                b.line_to(if rel { px + x } else { x }, py);
                last_ctrl = None;
            }
            'V' => {
                let Some(y) = num(&mut i) else { break };
                b.line_to(px, if rel { py + y } else { y });
                last_ctrl = None;
            }
            'C' => {
                let v: Vec<f64> = (0..6).filter_map(|_| num(&mut i)).collect();
                if v.len() < 6 {
                    break;
                }
                let (a, bb) = o(v[0], v[1]);
                let (c, d) = o(v[2], v[3]);
                let (e, f) = o(v[4], v[5]);
                b.cubic(a, bb, c, d, e, f);
                last_ctrl = Some((c, d));
            }
            'S' => {
                let v: Vec<f64> = (0..4).filter_map(|_| num(&mut i)).collect();
                if v.len() < 4 {
                    break;
                }
                let (a, bb) = last_ctrl
                    .map(|(cx, cy)| (2.0 * px - cx, 2.0 * py - cy))
                    .unwrap_or((px, py));
                let (c, d) = o(v[0], v[1]);
                let (e, f) = o(v[2], v[3]);
                b.cubic(a, bb, c, d, e, f);
                last_ctrl = Some((c, d));
            }
            'Q' => {
                let v: Vec<f64> = (0..4).filter_map(|_| num(&mut i)).collect();
                if v.len() < 4 {
                    break;
                }
                let (a, bb) = o(v[0], v[1]);
                let (e, f) = o(v[2], v[3]);
                b.quad(a, bb, e, f);
                last_ctrl = Some((a, bb));
            }
            'T' => {
                let v: Vec<f64> = (0..2).filter_map(|_| num(&mut i)).collect();
                if v.len() < 2 {
                    break;
                }
                let (a, bb) = last_ctrl
                    .map(|(cx, cy)| (2.0 * px - cx, 2.0 * py - cy))
                    .unwrap_or((px, py));
                let (e, f) = o(v[0], v[1]);
                b.quad(a, bb, e, f);
                last_ctrl = Some((a, bb));
            }
            'A' => {
                let v: Vec<f64> = (0..7).filter_map(|_| num(&mut i)).collect();
                if v.len() < 7 {
                    break;
                }
                let (x, y) = o(v[5], v[6]);
                svg_arc(&mut b, (v[0], v[1]), v[3] != 0.0, v[4] != 0.0, x, y);
                last_ctrl = None;
            }
            _ => {
                i += 1;
            }
        }
        if i == before {
            i += 1;
        }
    }
    b.finish()
}

/// svg:points ("x,y x,y ...") as a polyline or polygon path.
pub fn points(s: &str, vb: [f64; 4], closed: bool) -> Option<Geometry> {
    let v: Vec<f64> = s
        .split([' ', ',', '\n', '\t'])
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse().ok())
        .take(1 << 20)
        .collect();
    if v.len() < 4 {
        return None;
    }
    let mut b = Builder::new(vb);
    b.cur.fill = closed;
    b.move_to(v[0], v[1]);
    for [x, y] in v[2..].as_chunks::<2>().0 {
        b.line_to(*x, *y);
    }
    if closed {
        b.close();
    }
    b.finish()
}

// ------------------------------------------------------------ enhanced geometry

/// What enhanced-geometry formulas see.
struct Env<'a> {
    vb: [f64; 4],
    /// The shape's size in 1/100 mm (logwidth, logheight).
    log: (f64, f64),
    modifiers: Vec<f64>,
    equations: &'a [(String, String)],
    values: Vec<Option<f64>>,
    depth: u32,
}

impl Env<'_> {
    fn equation(&mut self, name: &str) -> f64 {
        let Some(i) = self.equations.iter().position(|e| e.0 == name) else {
            return 0.0;
        };
        if let Some(v) = self.values[i] {
            return v;
        }
        if self.depth > 64 {
            return 0.0;
        }
        self.depth += 1;
        // A cycle reads as zero.
        self.values[i] = Some(0.0);
        let f = self.equations[i].1.clone();
        let v = self.eval(&f);
        self.values[i] = Some(v);
        self.depth -= 1;
        v
    }

    fn eval(&mut self, s: &str) -> f64 {
        let toks = tokens(s);
        let mut p = Parser {
            t: &toks,
            i: 0,
            env: self,
        };
        let v = p.expr(0);
        if v.is_finite() { v } else { 0.0 }
    }

    /// A path parameter: number, ?equation, $modifier or keyword.
    fn param(&mut self, s: &str) -> f64 {
        if let Ok(v) = s.parse::<f64>() {
            return v;
        }
        if let Some(n) = s.strip_prefix('?') {
            return self.equation(n);
        }
        if let Some(n) = s.strip_prefix('$') {
            return n
                .parse::<usize>()
                .ok()
                .and_then(|i| self.modifiers.get(i).copied())
                .unwrap_or(0.0);
        }
        self.keyword(s)
    }

    fn keyword(&self, s: &str) -> f64 {
        match s {
            "pi" => PI,
            "left" => self.vb[0],
            "top" => self.vb[1],
            "right" => self.vb[0] + self.vb[2],
            "bottom" => self.vb[1] + self.vb[3],
            "width" => self.vb[2],
            "height" => self.vb[3],
            "logwidth" => self.log.0,
            "logheight" => self.log.1,
            "xstretch" | "ystretch" => 0.0,
            "hasstroke" | "hasfill" => 1.0,
            _ => 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Ident(String),
    Op(char),
}

fn tokens(s: &str) -> Vec<Tok> {
    let mut out = vec![];
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < c.len() && out.len() < 4096 {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_digit() || ch == '.' {
            let st = i;
            while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
                i += 1;
            }
            let t: String = c[st..i].iter().collect();
            out.push(Tok::Num(t.parse().unwrap_or(0.0)));
        } else if ch.is_alphabetic() || ch == '?' || ch == '$' || ch == '_' {
            let st = i;
            i += 1;
            while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(c[st..i].iter().collect()));
        } else {
            out.push(Tok::Op(ch));
            i += 1;
        }
    }
    out
}

struct Parser<'t, 'e, 'a> {
    t: &'t [Tok],
    i: usize,
    env: &'e mut Env<'a>,
}

impl Parser<'_, '_, '_> {
    fn expr(&mut self, depth: u32) -> f64 {
        if depth > 64 {
            return 0.0;
        }
        let mut v = self.term(depth);
        while let Some(Tok::Op(o @ ('+' | '-'))) = self.t.get(self.i) {
            let o = *o;
            self.i += 1;
            let r = self.term(depth);
            v = if o == '+' { v + r } else { v - r };
        }
        v
    }

    fn term(&mut self, depth: u32) -> f64 {
        let mut v = self.unary(depth);
        while let Some(Tok::Op(o @ ('*' | '/'))) = self.t.get(self.i) {
            let o = *o;
            self.i += 1;
            let r = self.unary(depth);
            v = if o == '*' {
                v * r
            } else if r == 0.0 {
                0.0
            } else {
                v / r
            };
        }
        v
    }

    fn unary(&mut self, depth: u32) -> f64 {
        match self.t.get(self.i) {
            Some(Tok::Op('-')) => {
                self.i += 1;
                -self.unary(depth + 1)
            }
            Some(Tok::Op('+')) => {
                self.i += 1;
                self.unary(depth + 1)
            }
            _ => self.atom(depth),
        }
    }

    fn args(&mut self, depth: u32) -> Vec<f64> {
        let mut v = vec![];
        if let Some(Tok::Op('(')) = self.t.get(self.i) {
            self.i += 1;
            loop {
                if let Some(Tok::Op(')')) = self.t.get(self.i) {
                    self.i += 1;
                    break;
                }
                v.push(self.expr(depth + 1));
                match self.t.get(self.i) {
                    Some(Tok::Op(',')) => self.i += 1,
                    Some(Tok::Op(')')) => {
                        self.i += 1;
                        break;
                    }
                    _ => break,
                }
                if v.len() > 8 {
                    break;
                }
            }
        }
        v
    }

    fn atom(&mut self, depth: u32) -> f64 {
        let Some(t) = self.t.get(self.i).cloned() else {
            return 0.0;
        };
        self.i += 1;
        match t {
            Tok::Num(v) => v,
            Tok::Op('(') => {
                let v = self.expr(depth + 1);
                if let Some(Tok::Op(')')) = self.t.get(self.i) {
                    self.i += 1;
                }
                v
            }
            Tok::Op(_) => 0.0,
            Tok::Ident(id) => {
                let a = |v: &Vec<f64>, k: usize| v.get(k).copied().unwrap_or(0.0);
                match id.as_str() {
                    "abs" | "sqrt" | "sin" | "cos" | "tan" | "atan" | "atan2" | "min" | "max"
                    | "if" => {
                        let v = self.args(depth);
                        match id.as_str() {
                            "abs" => a(&v, 0).abs(),
                            "sqrt" => a(&v, 0).max(0.0).sqrt(),
                            "sin" => a(&v, 0).sin(),
                            "cos" => a(&v, 0).cos(),
                            "tan" => a(&v, 0).tan(),
                            "atan" => a(&v, 0).atan(),
                            "atan2" => a(&v, 0).atan2(a(&v, 1)),
                            "min" => a(&v, 0).min(a(&v, 1)),
                            "max" => a(&v, 0).max(a(&v, 1)),
                            _ => {
                                if a(&v, 0) > 0.0 {
                                    a(&v, 1)
                                } else {
                                    a(&v, 2)
                                }
                            }
                        }
                    }
                    s => self.env.param(s),
                }
            }
        }
    }
}

/// A draw:custom-shape's geometry from its draw:enhanced-geometry, or
/// `None` when it has no path.
/// A custom shape's geometry, whether it is mirrored horizontally and
/// vertically, and its text area (see below).
pub type Enhanced = (Geometry, bool, bool, Option<[f64; 4]>);

pub fn enhanced(eg: &Node, w_emu: i64, h_emu: i64) -> Option<Enhanced> {
    // The extended path (with OOXML arcs) where its writer gave one.
    let path = eg
        .attr("drawooo:enhanced-path")
        .or(eg.attr("draw:enhanced-path"))?;
    let log = (w_emu as f64 / 360.0, h_emu as f64 / 360.0);
    // An empty view box means the shape's own size in 1/100 mm.
    let vb = match eg.attr("svg:viewBox") {
        None => [0.0, 0.0, 21600.0, 21600.0],
        Some(v) => view_box(Some(v)).unwrap_or([0.0, 0.0, log.0.max(1.0), log.1.max(1.0)]),
    };
    let equations: Vec<(String, String)> = eg
        .all("draw:equation")
        .take(4096)
        .filter_map(|e| {
            Some((
                e.attr("draw:name")?.to_string(),
                e.attr("draw:formula")?.to_string(),
            ))
        })
        .collect();
    let modifiers = eg
        .attr("draw:modifiers")
        .map(|m| {
            m.split_whitespace()
                .filter_map(|t| t.parse().ok())
                .take(64)
                .collect()
        })
        .unwrap_or_default();
    let mut env = Env {
        vb,
        log,
        modifiers,
        values: vec![None; equations.len()],
        equations: &equations,
        depth: 0,
    };
    let mut b = Builder::new(vb);
    let toks: Vec<&str> = path
        .split([' ', ',', '\n', '\t'])
        .filter(|t| !t.is_empty())
        .take(1 << 18)
        .collect();
    // Commands may be glued to their first parameter ("M0 0").
    let mut items: Vec<String> = vec![];
    for t in toks {
        let first = t.chars().next().unwrap_or(' ');
        if first.is_ascii_uppercase()
            && t.len() > 1
            && !t[1..].starts_with(|c: char| c.is_ascii_alphabetic())
        {
            items.push(first.to_string());
            items.push(t[1..].to_string());
        } else {
            items.push(t.to_string());
        }
    }
    let is_cmd = |s: &str| s.len() == 1 && s.chars().all(|c| c.is_ascii_uppercase());
    let mut i = 0;
    let mut cmd = "M".to_string();
    while i < items.len() {
        if is_cmd(&items[i]) {
            cmd = items[i].clone();
            i += 1;
        }
        let need = match cmd.as_str() {
            "M" | "L" | "X" | "Y" => 2,
            "C" => 6,
            "Q" => 4,
            "T" | "U" => 6,
            "A" | "B" | "W" | "V" => 8,
            "G" => 4,
            _ => 0,
        };
        if need == 0 {
            match cmd.as_str() {
                "Z" => b.close(),
                "N" => b.end(),
                "F" => b.cur.fill = false,
                "S" => b.cur.stroke = false,
                _ => {}
            }
            if !is_cmd(items.get(i).map(String::as_str).unwrap_or("M")) {
                i += 1;
            }
            cmd = String::new();
            continue;
        }
        if i + need > items.len() {
            break;
        }
        let v: Vec<f64> = items[i..i + need].iter().map(|s| env.param(s)).collect();
        i += need;
        match cmd.as_str() {
            "M" => b.move_to(v[0], v[1]),
            "L" => b.line_to(v[0], v[1]),
            "C" => b.cubic(v[0], v[1], v[2], v[3], v[4], v[5]),
            "Q" => b.quad(v[0], v[1], v[2], v[3]),
            "T" | "U" => {
                // Centre, radii, start and end angles in degrees, turning
                // clockwise on screen from the start to the end.
                let (rx, ry) = (v[2], v[3]);
                // The angles are those of the line from the centre, not
                // the ellipse's own parameter.
                let param = |deg: f64| {
                    let a = deg.to_radians();
                    (rx * a.sin()).atan2(ry * a.cos())
                };
                let a0 = param(v[4]);
                let mut a1 = param(v[5]);
                while a1 <= a0 {
                    a1 += 2.0 * PI;
                }
                b.arc(v[0], v[1], rx, ry, a0, a1 - a0, cmd == "U");
            }
            "A" | "B" | "W" | "V" => {
                let (cx, cy) = ((v[0] + v[2]) / 2.0, (v[1] + v[3]) / 2.0);
                let (rx, ry) = (((v[2] - v[0]) / 2.0).abs(), ((v[3] - v[1]) / 2.0).abs());
                if rx < 1e-9 || ry < 1e-9 {
                    b.line_to(v[6], v[7]);
                    continue;
                }
                let ang = |x: f64, y: f64| ((y - cy) / ry).atan2((x - cx) / rx);
                let a0 = ang(v[4], v[5]);
                let a1 = ang(v[6], v[7]);
                let cw = cmd == "W" || cmd == "V";
                let mut d = a1 - a0;
                if cw {
                    if d <= 0.0 {
                        d += 2.0 * PI;
                    }
                } else if d >= 0.0 {
                    d -= 2.0 * PI;
                }
                b.arc(cx, cy, rx, ry, a0, d, cmd == "B" || cmd == "V");
            }
            "X" | "Y" => {
                // A quarter ellipse, first along x (X) or y (Y).
                let (x0, y0) = b.pos;
                let (x, y) = (v[0], v[1]);
                let k = 0.552_284_75;
                if cmd == "X" {
                    b.cubic(x0 + (x - x0) * k, y0, x, y - (y - y0) * k, x, y);
                    cmd = "Y".into();
                } else {
                    b.cubic(x0, y0 + (y - y0) * k, x - (x - x0) * k, y, x, y);
                    cmd = "X".into();
                }
            }
            "G" => {
                // Width and height radii, start angle and swing (degrees,
                // clockwise), from the current point.
                let (wr, hr, st, sw) = (v[0], v[1], v[2].to_radians(), v[3].to_radians());
                let (x0, y0) = b.pos;
                let cx = x0 - wr * st.cos();
                let cy = y0 - hr * st.sin();
                b.arc(cx, cy, wr, hr, st, sw, false);
            }
            _ => {}
        }
    }
    let mh = eg.attr("draw:mirror-horizontal") == Some("true");
    let mv = eg.attr("draw:mirror-vertical") == Some("true");
    // The text area: left, top, right, bottom in the view box, as the
    // fractions of it they cover.
    let text_area = eg.attr("draw:text-areas").and_then(|t| {
        let v: Vec<f64> = t.split_whitespace().take(4).map(|s| env.param(s)).collect();
        let [l, tp, r, bt] = v[..] else { return None };
        let f = |x: f64, o: f64, d: f64| ((x - o) / d).clamp(0.0, 1.0);
        let a = [
            f(l, vb[0], vb[2]),
            f(tp, vb[1], vb[3]),
            f(r, vb[0], vb[2]),
            f(bt, vb[1], vb[3]),
        ];
        (vb[2] > 0.0 && vb[3] > 0.0 && a[0] < a[2] && a[1] < a[3]).then_some(a)
    });
    b.finish().map(|g| (g, mh, mv, text_area))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds(g: &Geometry) -> Vec<String> {
        match g {
            Geometry::Custom(p) => p[0].cmds.iter().map(|c| format!("{c:?}")).collect(),
            _ => vec![],
        }
    }

    #[test]
    fn svg_paths_absolute_and_relative() {
        let g = svg_path(
            "M0 0 l100 0 V50 h-100z",
            [0.0, 0.0, 100_000.0, 100_000.0],
            true,
        )
        .unwrap();
        assert_eq!(
            cmds(&g),
            vec![
                "Move(0, 0)",
                "Line(100, 0)",
                "Line(100, 50)",
                "Line(0, 50)",
                "Close"
            ]
        );
        // Small view boxes are scaled up.
        let g = svg_path("M1 1L2 2", [1.0, 1.0, 10.0, 10.0], false).unwrap();
        assert_eq!(cmds(&g), vec!["Move(0, 0)", "Line(10000, 10000)"]);
    }

    #[test]
    fn enhanced_paths_with_equations_and_modifiers() {
        let x = br#"<draw:enhanced-geometry xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" svg:viewBox="0 0 21600 21600" draw:modifiers="5400" draw:enhanced-path="M $0 0 L right ?f0 ?f1 bottom Z N"><draw:equation draw:name="f0" draw:formula="$0 * 2"/><draw:equation draw:name="f1" draw:formula="if(-1, 3, max(?f0, 7) - 10800)"/></draw:enhanced-geometry>"#;
        let n = crate::formats::office::common::xml::parse(
            x,
            &mut crate::formats::office::common::xml::within(1 << 20),
        )
        .unwrap();
        let (g, _, _, _) = enhanced(&n, 100, 100).unwrap();
        // In path units: the 21600 view box scaled to 100000.
        assert_eq!(
            cmds(&g),
            vec![
                "Move(25000, 0)",
                "Line(100000, 50000)",
                "Line(0, 100000)",
                "Close"
            ]
        );
    }
}
