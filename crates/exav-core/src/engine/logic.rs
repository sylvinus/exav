//! `.ldb` logical-signature boolean-expression parser and evaluator. Split out
//! of `mod.rs`; every item is `pub(super)` (internal to the `engine` module).

use super::*;

/// A parsed logical expression.
#[derive(Serialize, Deserialize)]
pub(super) enum Node {
    /// Bare subsig: matched at least once.
    Sub(usize),
    /// Subsig match-count compared to x.
    SubCmp(usize, Cmp, u32),
    /// Group: total matches across `ids` compared to x, and (if Some) at least
    /// y *distinct* subsigs in the group matched.
    GroupCmp(Vec<usize>, Cmp, u32, Option<u32>),
    And(Vec<Node>),
    Or(Vec<Node>),
}

pub(super) fn cmp_ok(c: Cmp, v: u32, x: u32) -> bool {
    match c {
        Cmp::Eq => v == x,
        Cmp::Gt => v > x,
        Cmp::Lt => v < x,
    }
}

impl Node {
    pub(super) fn eval(&self, count: &dyn Fn(usize) -> u32) -> bool {
        match self {
            Node::Sub(i) => count(*i) > 0,
            Node::SubCmp(i, c, x) => cmp_ok(*c, count(*i), *x),
            Node::GroupCmp(ids, c, x, y) => {
                let total: u32 = ids.iter().map(|&i| count(i)).sum();
                if !cmp_ok(*c, total, *x) {
                    return false;
                }
                match y {
                    Some(y) => ids.iter().filter(|&&i| count(i) > 0).count() as u32 >= *y,
                    None => true,
                }
            }
            Node::And(v) => v.iter().all(|n| n.eval(count)),
            Node::Or(v) => v.iter().any(|n| n.eval(count)),
        }
    }

    fn collect_ids(&self, out: &mut Vec<usize>) {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => out.push(*i),
            Node::GroupCmp(ids, ..) => out.extend_from_slice(ids),
            Node::And(v) | Node::Or(v) => v.iter().for_each(|n| n.collect_ids(out)),
        }
    }

    /// True if every subsig id referenced is `< nsubs`.
    pub(super) fn ids_within(&self, nsubs: usize) -> bool {
        match self {
            Node::Sub(i) | Node::SubCmp(i, _, _) => *i < nsubs,
            Node::GroupCmp(ids, ..) => ids.iter().all(|&i| i < nsubs),
            Node::And(v) | Node::Or(v) => v.iter().all(|n| n.ids_within(nsubs)),
        }
    }
}

pub(super) fn parse_expr(expr: &str) -> Option<Node> {
    let tokens: Vec<u8> = expr.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut p = Parser { s: &tokens, i: 0 };
    let node = p.or()?;
    if p.i == p.s.len() {
        Some(node)
    } else {
        None
    }
}

pub(super) struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn or(&mut self) -> Option<Node> {
        let mut v = vec![self.and()?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            v.push(self.and()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::Or(v)
        })
    }

    fn and(&mut self) -> Option<Node> {
        let mut v = vec![self.atom()?];
        while self.peek() == Some(b'&') {
            self.i += 1;
            v.push(self.atom()?);
        }
        Some(if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Node::And(v)
        })
    }

    fn atom(&mut self) -> Option<Node> {
        match self.peek()? {
            b'(' => {
                self.i += 1;
                let inner = self.or()?;
                if self.peek() != Some(b')') {
                    return None;
                }
                self.i += 1;
                // A count modifier on a group counts total matches across the
                // group's subsigs (and, with `,y`, distinct subsigs matched).
                if let Some(cmp) = self.cmp() {
                    let (x, y) = self.count_args()?;
                    let mut ids = Vec::new();
                    inner.collect_ids(&mut ids);
                    Some(Node::GroupCmp(ids, cmp, x, y))
                } else {
                    Some(inner)
                }
            }
            b'0'..=b'9' => {
                let sub = self.number()?;
                if let Some(cmp) = self.cmp() {
                    let (x, _y) = self.count_args()?; // single subsig: y is ignored
                    Some(Node::SubCmp(sub, cmp, x))
                } else {
                    Some(Node::Sub(sub))
                }
            }
            _ => None,
        }
    }

    fn cmp(&mut self) -> Option<Cmp> {
        let c = match self.peek()? {
            b'=' => Cmp::Eq,
            b'>' => Cmp::Gt,
            b'<' => Cmp::Lt,
            _ => return None,
        };
        self.i += 1;
        Some(c)
    }

    /// Parse `x` or `x,y` after a comparison operator.
    fn count_args(&mut self) -> Option<(u32, Option<u32>)> {
        let x = self.number()? as u32;
        if self.peek() == Some(b',') {
            self.i += 1;
            Some((x, Some(self.number()? as u32)))
        } else {
            Some((x, None))
        }
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()?
            .parse()
            .ok()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
}

