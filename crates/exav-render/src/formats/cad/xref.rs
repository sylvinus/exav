//! Binding an external reference: the caller reads the drawing a reference
//! names, and its model space becomes the content of the block that refers
//! to it. What it brings along is named as AutoCAD names it in the host,
//! `XREF|NAME`: its layers, linetypes, text and dimension styles, and its
//! blocks. A reference inside it keeps its path, and is bound in turn.

use super::model::{Block, Drawing, Entity, EntityKind, Handle};

/// How many references deep a binding goes: `A|B|C|...`.
const MAX_DEPTH: usize = 8;

/// The entities a drawing may hold once references are bound into it.
pub const MAX_BOUND_ENTITIES: usize = 8_000_000;

/// The handles of what is bound in carry the number of the binding in the
/// byte above those a drawing uses, so they do not meet the host's.
const TAG_SHIFT: u32 = 56;

fn depth(name: &str) -> usize {
    name.matches('|').count()
}

/// An xref block with no content yet, deep enough to be shown: an overlay
/// inside a reference is not.
fn is_open(b: &Block) -> bool {
    b.is_xref()
        && b.entities.is_empty()
        && depth(&b.name) < MAX_DEPTH
        && !(b.flags & 8 != 0 && depth(&b.name) > 0)
}

fn untouched(linetype: &str) -> bool {
    ["BYLAYER", "BYBLOCK", "CONTINUOUS"]
        .iter()
        .any(|k| linetype.eq_ignore_ascii_case(k))
}

struct Bind<'a> {
    prefix: &'a str,
    tag: u64,
}

impl Bind<'_> {
    fn name(&self, s: &str) -> String {
        format!("{}|{}", self.prefix, s)
    }

    fn handle(&self, h: Handle) -> Handle {
        if h.is_null() {
            h
        } else {
            Handle(h.0 & ((1 << TAG_SHIFT) - 1) | self.tag << TAG_SHIFT)
        }
    }

    fn linetype(&self, s: &str) -> String {
        if untouched(s) {
            s.to_string()
        } else {
            self.name(s)
        }
    }

    fn entity(&self, e: &Entity, nesting: usize) -> Entity {
        let mut e = e.clone();
        e.handle = self.handle(e.handle);
        e.owner = self.handle(e.owner);
        e.layer = self.name(&e.layer);
        e.linetype = self.linetype(&e.linetype);
        match &mut e.kind {
            EntityKind::Insert(i) => {
                i.block_name = self.name(&i.block_name);
                if nesting > 0 {
                    i.attributes = i
                        .attributes
                        .iter()
                        .map(|a| self.entity(a, nesting - 1))
                        .collect();
                }
            }
            EntityKind::Dimension(d) => {
                if !d.block_name.is_empty() {
                    d.block_name = self.name(&d.block_name);
                }
                d.style = self.name(&d.style);
            }
            EntityKind::Text(t) => t.style = self.name(&t.style),
            EntityKind::MText(m) => m.style = self.name(&m.style),
            EntityKind::Attribute(a) | EntityKind::AttributeDefinition(a) => {
                a.text.style = self.name(&a.text.style);
                if let Some(m) = &mut a.mtext {
                    m.style = self.name(&m.style);
                }
            }
            EntityKind::Leader(l) => l.style = self.name(&l.style),
            EntityKind::Tolerance(t) => t.dimstyle = self.name(&t.dimstyle),
            EntityKind::Table(t) => {
                if !t.block_name.is_empty() {
                    t.block_name = self.name(&t.block_name);
                }
            }
            EntityKind::Image(i) | EntityKind::Wipeout(i) => {
                i.image_def = self.handle(i.image_def);
                i.reactor = self.handle(i.reactor);
            }
            EntityKind::Underlay(u) => u.definition = self.handle(u.definition),
            _ => {}
        }
        e
    }
}

impl Drawing {
    /// The files the drawing's unbound external references name, each once:
    /// as the drawing wrote them, a path of the machine that made it.
    pub fn unresolved_xrefs(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for b in self.blocks.iter().filter(|b| is_open(b)) {
            if !b.xref_path.is_empty() && !out.iter().any(|p| p.eq_ignore_ascii_case(&b.xref_path))
            {
                out.push(b.xref_path.clone());
            }
        }
        out
    }

    /// The entities of every block, which a binding is limited by.
    fn entity_count(&self) -> usize {
        self.blocks.iter().map(|b| b.entities.len()).sum()
    }

    /// Bind `xref`, the drawing the path `path` names, into every block of
    /// this drawing that refers to that path and has no content. Returns how
    /// many blocks it filled: none for a path nothing refers to, and for a
    /// drawing that would bring this one past [`MAX_BOUND_ENTITIES`].
    pub fn attach_xref(&mut self, path: &str, xref: &Drawing) -> usize {
        let Some(model) = xref.model_space() else {
            return 0;
        };
        let targets: Vec<usize> = self
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| is_open(b) && b.xref_path.eq_ignore_ascii_case(path))
            .map(|(i, _)| i)
            .collect();
        let mut bound = 0;
        for i in targets {
            if self.entity_count().saturating_add(xref.entity_count()) > MAX_BOUND_ENTITIES {
                break;
            }
            let Some(prefix) = self.blocks.get(i).map(|b| b.name.clone()) else {
                continue;
            };
            let used = self.handle_tags();
            if used >= u64::from(u8::MAX) {
                break;
            }
            let bind = Bind {
                prefix: &prefix,
                tag: used + 1,
            };
            self.bring(&bind, xref);
            let content: Vec<Entity> = model.entities.iter().map(|e| bind.entity(e, 2)).collect();
            if let Some(b) = self.blocks.get_mut(i) {
                b.entities = content;
            }
            bound += 1;
        }
        bound
    }

    /// The highest tag among the handles of what was bound in.
    fn handle_tags(&self) -> u64 {
        let tag = |h: Handle| h.0 >> TAG_SHIFT;
        let layers = self.layers.iter().map(|l| tag(l.handle));
        let blocks = self.blocks.iter().map(|b| tag(b.record));
        let images = self.image_defs.iter().map(|d| tag(d.handle));
        layers.chain(blocks).chain(images).max().unwrap_or(0)
    }

    /// Add what the entities of `xref` refer to, under the names a binding
    /// gives them, except what the host already has under that name.
    fn bring(&mut self, bind: &Bind<'_>, xref: &Drawing) {
        for l in &xref.layers {
            let name = bind.name(&l.name);
            if self.layer(&name).is_none() {
                let mut l = l.clone();
                l.name = name;
                l.handle = bind.handle(l.handle);
                l.linetype = bind.linetype(&l.linetype);
                self.layers.push(l);
            }
        }
        for t in &xref.linetypes {
            let name = bind.name(&t.name);
            if !untouched(&t.name) && self.linetype(&name).is_none() {
                let mut t = t.clone();
                t.name = name;
                t.handle = bind.handle(t.handle);
                self.linetypes.push(t);
            }
        }
        for s in &xref.text_styles {
            let name = bind.name(&s.name);
            if self.text_style(&name).is_none() {
                let mut s = s.clone();
                s.name = name;
                s.handle = bind.handle(s.handle);
                self.text_styles.push(s);
            }
        }
        for d in &xref.dim_styles {
            let name = bind.name(&d.name);
            if !self
                .dim_styles
                .iter()
                .any(|e| e.name.eq_ignore_ascii_case(&name))
            {
                let mut d = d.clone();
                d.name = name;
                d.handle = bind.handle(d.handle);
                self.dim_styles.push(d);
            }
        }
        for b in &xref.blocks {
            if b.is_model_space() || b.is_paper_space() {
                continue;
            }
            let name = bind.name(&b.name);
            if self.block(&name).is_some() {
                continue;
            }
            let mut copy = b.clone();
            copy.name = name;
            copy.record = bind.handle(b.record);
            copy.handle = bind.handle(b.handle);
            copy.end_handle = bind.handle(b.end_handle);
            copy.layout = Handle::NULL;
            copy.layer = bind.name(&b.layer);
            copy.entities = b.entities.iter().map(|e| bind.entity(e, 2)).collect();
            self.blocks.push(copy);
        }
        for d in &xref.image_defs {
            let mut d = d.clone();
            d.handle = bind.handle(d.handle);
            self.image_defs.push(d);
        }
        for d in &xref.underlay_defs {
            let mut d = d.clone();
            d.handle = bind.handle(d.handle);
            self.underlay_defs.push(d);
        }
        for t in &xref.sort_tables {
            let mut t = t.clone();
            t.handle = bind.handle(t.handle);
            t.block_record = bind.handle(t.block_record);
            t.entries = t
                .entries
                .iter()
                .map(|(a, b)| (bind.handle(*a), bind.handle(*b)))
                .collect();
            self.sort_tables.push(t);
        }
    }
}
