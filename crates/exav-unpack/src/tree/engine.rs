//! The recursion: the members of a container handed to a consumer, the
//! objects found inside an object, and the driver that goes down by itself.
//!
//! A consumer that scans in an order of its own (the scanner) calls
//! [`Cx::members`] and [`Cx::child`] where it chooses. One that only wants to
//! see every node (a search, a listing) hands a [`Visitor`] to [`Walker::run`],
//! which types each node and opens the containers.

use super::{
    Body, Content, Declined, DeriveKind, End, Hold, Intake, Name, NameKind, Origin, Path, Reason,
    ReasonKind, Reasons, SecondReading, Sets, StreamCell, derive, intake,
};
use crate::source::ByteSource;
use crate::stream::Visit;
use crate::{Budget, Format, LimitHit, LimitKind, MemberMeta};
use std::cell::OnceCell;

/// How a walk is set up.
pub struct Walk<'a> {
    /// What of a member is held in memory, and where the rest may go.
    pub hold: Hold<'a>,
    /// Whether the parts of a byte-split set found among the members of a
    /// container are held, to be rejoined when the container ends.
    pub sets: bool,
    /// Whether [`Walker::run`] reads a container a second way when its bytes
    /// allow it, after its members: a ZIP appended to it, or the other format
    /// it also is. Each is visited as a node one level down. A consumer that
    /// walks by itself asks for [`Cx::derived`] where it chooses.
    pub second_readings: bool,
}

/// What a consumer is told of a node.
pub struct Node<'a> {
    pub path: Path<'a>,
    /// The levels above it: 0 for the object the walk was given.
    pub depth: u32,
    pub origin: Origin,
    /// What its container says of it, for a member.
    pub meta: Option<&'a MemberMeta>,
    /// The bytes to scan now. [`Content::None`] when it has none, or when it is
    /// a part of a split set that is held to be scanned with the rest.
    pub content: Content<'a>,
    /// How the content ends.
    pub end: End,
    /// Its place among the members of its container, from 1: the members
    /// that were not skipped as the container itself count.
    pub index: u64,
    /// Its size for a rule on sizes: the length it decoded to, or its size in
    /// its container when it was not decoded.
    pub size: u64,
    /// When the content is the first bytes of a member too large to hold and
    /// nowhere to write, why the rest was not taken.
    pub capped: Option<&'a str>,
    /// The format of the container it is a member of.
    pub container: Option<Format>,
    /// What decides [`Self::format`]: the driver's typer, if there is one.
    typer: Option<&'a dyn Typer>,
    /// The most bytes a walk holds of an object: what a typer may read whole.
    hold: u64,
    typed: OnceCell<Typed>,
}

impl<'a> Node<'a> {
    /// An object that is not a member of a container, found as `origin` says.
    pub fn of(path: Path<'a>, depth: u32, origin: Origin, src: &'a dyn ByteSource) -> Self {
        Node {
            path,
            depth,
            origin,
            meta: None,
            content: Content::Source(src),
            end: End::Complete,
            index: 0,
            size: src.len() as u64,
            capped: None,
            container: None,
            typer: None,
            hold: u64::MAX,
            typed: OnceCell::new(),
        }
    }

    /// The node, typed by `typer` when [`Self::format`] is asked.
    fn typed_by(mut self, typer: Option<&'a dyn Typer>, hold: u64) -> Self {
        self.typer = typer;
        self.hold = hold;
        self
    }

    /// The node, already typed: what the walk found out of it as it took it.
    fn typed_as(self, typed: Option<Typed>) -> Self {
        if let Some(typed) = typed {
            let _ = self.typed.set(typed);
        }
        self
    }

    /// The bytes, when there are some.
    pub fn source(&self) -> Option<&'a dyn ByteSource> {
        match self.content {
            Content::Source(src) => Some(src),
            Content::None | Content::Stream(_) => None,
        }
    }

    /// The most bytes the walk holds of an object.
    pub fn hold(&self) -> u64 {
        self.hold
    }

    /// What the node is, asked of the driver's typer the first time. A node
    /// with no bytes to look at, and a walk with no typer, make it plain.
    pub fn format(&self) -> &Typed {
        self.typed.get_or_init(|| match (&self.origin, self.typer) {
            // The same bytes, read as the format they were found to be.
            (Origin::Second(SecondReading::AlsoReadsAs(format)), _) => Typed::Container(*format),
            (_, Some(typer)) if self.source().is_some() => typer.type_of(self),
            _ => Typed::Plain,
        })
    }
}

/// What a consumer says of a node it was told of.
pub enum Flow<T> {
    /// Open it, if it is a container: its members are visited next. A consumer
    /// that walks by itself never says so.
    Descend,
    /// Nothing more to do with it: go on with its siblings.
    Leaf,
    /// End the walk, with `T`.
    Stop(T),
}

/// Told of each node, once, before what is under it.
pub trait Visitor<T> {
    /// `reasons` are the container's: a reason found for the node goes there,
    /// after those that came before it.
    fn visit(&mut self, node: &Node<'_>, cx: &mut Cx<'_>, reasons: &mut Reasons) -> Flow<T>;

    /// A reason the walk itself found at `at`, as it is found, when the node
    /// does not show it: a bound reached under a container, a body that could
    /// not be read back, a set that is not whole, a check that could not be
    /// made, a panic of the visitor. How a member's bytes were taken is on the
    /// node (`end`, `capped`, no content) and is not told here. The reason is
    /// also in the container's `reasons`.
    fn reason(&mut self, at: &Path<'_>, reason: &Reason) {
        let _ = (at, reason);
    }

    /// The members of the container `node` have been visited, `members` of
    /// them ([`Walker::run`] only): before its second readings, if it has any.
    /// A consumer that wants something of a container itself, after what is in
    /// it, does it here.
    fn leave(
        &mut self,
        node: &Node<'_>,
        members: u64,
        cx: &mut Cx<'_>,
        reasons: &mut Reasons,
    ) -> Flow<T> {
        let _ = (node, members, cx, reasons);
        Flow::Leaf
    }
}

/// How the walk of one container ended.
#[derive(Debug)]
pub enum Ended<T> {
    /// Every member was visited.
    Complete,
    /// A visitor ended it.
    Stopped(T),
    /// A budget ran out, or the container could not be read.
    Limit(LimitHit),
}

/// What a walk of one container leaves.
#[derive(Debug)]
pub struct Descent<T> {
    pub ended: Ended<T>,
    /// The reasons found under the container, the first of each class.
    pub reasons: Reasons,
    /// The members the visitor was told of (not the rejoined files of a set,
    /// nor the members that were the container itself).
    pub members: u64,
}

/// A child that was not taken.
#[derive(Debug)]
pub struct Refused<'p> {
    pub hit: LimitHit,
    /// Where the child would have been.
    pub at: Path<'p>,
}

/// A reason the walk found at `at`: told to the visitor as it is found, and
/// kept in `reasons`.
fn note<T>(v: &mut dyn Visitor<T>, reasons: &mut Reasons, at: &Path<'_>, reason: Reason) {
    v.reason(at, &reason);
    reasons.add_at(reason, at);
}

/// [`note`] for each reason of `found` that is kept.
fn note_all<T>(v: &mut dyn Visitor<T>, reasons: &mut Reasons, at: &Path<'_>, found: Reasons) {
    for reason in found.kept() {
        v.reason(at, reason);
    }
    reasons.merge_at(found, at);
}

/// Run what a consumer does at a node. A panic in it is a reason, for the
/// caller to note at the node: the walk goes on with the node's siblings, and
/// nothing under the node is visited. (Where panics abort, there is nothing to
/// catch.)
fn guarded<R>(run: impl FnOnce() -> R) -> Result<R, Reason> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).map_err(|_| Reason {
        kind: ReasonKind::Panic,
        text: "a panic while the object was being examined: it was not fully examined".to_string(),
        at: String::new(),
    })
}

/// The state a walk carries down: the budget, and how it is set up.
pub struct Cx<'c> {
    budget: &'c mut Budget,
    walk: &'c Walk<'c>,
    /// What types the nodes of a walk that opens containers by itself.
    typer: Option<&'c dyn Typer>,
}

impl<'c> Cx<'c> {
    pub fn new(walk: &'c Walk<'c>, budget: &'c mut Budget) -> Self {
        Cx {
            budget,
            walk,
            typer: None,
        }
    }

    pub fn budget(&mut self) -> &mut Budget {
        self.budget
    }

    /// The bound reached when a container at `depth` is opened, if it is
    /// reached: a container at the limit is not opened.
    pub fn depth_hit(&self, depth: u32) -> Option<LimitHit> {
        let max = self.budget.limits().max_recursion;
        (depth >= max).then(|| {
            LimitHit::of_kind(
                LimitKind::MaxRecursion,
                format!("recursion depth exceeds {max}"),
            )
        })
    }

    /// Visit the members of the container `src`, of format `format`, which is
    /// at `at` and `depth`. Each member is taken as [`intake`] says, and its
    /// parts of a split set held, before its visitor sees it; the container
    /// ends with the rejoined sets, each visited as a file of its own.
    pub fn members<T>(
        &mut self,
        at: &Path<'_>,
        depth: u32,
        src: &dyn ByteSource,
        format: Format,
        v: &mut dyn Visitor<T>,
    ) -> Descent<T> {
        self.members_with(at, depth, src, Some(format), v, |budget, visit| {
            crate::walk(format, src, budget, visit)
        })
    }

    /// [`Self::members`] with the reader given: it hands each member to the
    /// function it is called with. A reader stops with `()`, and the visitor's
    /// own value is kept by the walk.
    fn members_with<T>(
        &mut self,
        at: &Path<'_>,
        depth: u32,
        src: &dyn ByteSource,
        format: Option<Format>,
        v: &mut dyn Visitor<T>,
        read: impl FnOnce(&mut Budget, Visit<'_, ()>) -> Result<Option<()>, LimitHit>,
    ) -> Descent<T> {
        if let Some(hit) = self.depth_hit(depth) {
            return Descent {
                ended: Ended::Limit(hit),
                reasons: Reasons::default(),
                members: 0,
            };
        }
        let walk = self.walk;
        let typer = self.typer;
        let mut reasons = Reasons::default();
        let mut sets = Sets::new(walk.sets, self.budget.limits().max_buffer_bytes);
        let mut index = 0u64;
        let mut stopped_with = None;
        let walked = read(&mut *self.budget, &mut |meta, content, budget| {
            let kind = match meta.stream_member {
                true => NameKind::Stream,
                false => NameKind::Stored,
            };
            let path = at.child(Name::new(&meta.name, kind));
            // What takes the member and what visits it is not the reader: a
            // panic there is a reason at this member, and the reader goes on.
            let flow = guarded(|| {
                let Intake {
                    mut body,
                    rest,
                    end,
                    reasons: found,
                } = match intake(meta, content, &walk.hold, budget, src) {
                    Ok(taken) => taken,
                    // Nothing was unwrapped: these bytes are scanned as the container.
                    Err(Declined::Same) => return Flow::Leaf,
                    // The reader reports the limit once this returns. A part
                    // of a split set left out is missing from its set.
                    Err(Declined::Stopped) => {
                        sets.lose(&meta.name, &Body::None, &End::Complete, true);
                        return Flow::Leaf;
                    }
                };
                index += 1;
                // How the bytes were taken is on the node: not told.
                reasons.merge_at(found, &path);
                let size = match &body {
                    Body::Mem(data) => data.len() as u64,
                    Body::Spilled(spilled) => spilled.len() as u64,
                    Body::Range(sub) => sub.len() as u64,
                    Body::None | Body::Prefix { .. } | Body::Stream { .. } => meta.comp_size,
                };
                // Nothing decoded: the metadata is all this member has.
                let nothing = matches!(&body, Body::Mem(data) if data.is_empty())
                    && meta.unsupported.is_some();
                // A part of a split set too large to hold, cut short or with
                // nothing decoded is scanned where it lies, and its set is
                // missing it.
                let cut = sets.lose(&meta.name, &body, &end, nothing);
                // A part held for its set is not scanned on its own.
                if !cut
                    && !nothing
                    && matches!(body, Body::Mem(_))
                    && let Body::Mem(data) = std::mem::replace(&mut body, Body::None)
                    && let Some(data) = sets.offer(&meta.name, data)
                {
                    body = Body::Mem(data);
                }
                // What a stream member is, when its start has said so.
                let typed = match &body {
                    Body::Stream {
                        unchecked: Some(reason),
                        ..
                    } => Some(Typed::Unchecked(reason.clone())),
                    Body::Stream { .. } => Some(Typed::Plain),
                    _ => None,
                };
                let (content, capped) = match (&body, rest) {
                    (Body::None, _) => (Content::None, None),
                    (Body::Mem(_), _) if nothing => (Content::None, None),
                    (Body::Mem(data), _) => (Content::Source(data), None),
                    (Body::Spilled(spilled), _) => (Content::Source(spilled), None),
                    (Body::Prefix { data, reason }, _) => {
                        (Content::Source(data), Some(reason.as_str()))
                    }
                    (Body::Range(sub), _) => (Content::Source(sub), None),
                    (Body::Stream { head, .. }, Some(rest)) => {
                        (Content::Stream(StreamCell::new(head, rest)), None)
                    }
                    // A stream was taken with nothing left of it: no content.
                    (Body::Stream { .. }, None) => (Content::None, None),
                };
                let node = Node {
                    path,
                    depth: depth + 1,
                    origin: Origin::Member,
                    meta: Some(meta),
                    content,
                    end,
                    index,
                    size,
                    capped,
                    container: format,
                    typer: None,
                    hold: 0,
                    typed: OnceCell::new(),
                }
                .typed_by(typer, walk.hold.limit)
                .typed_as(typed);
                let flow = v.visit(
                    &node,
                    &mut Cx {
                        budget,
                        walk,
                        typer,
                    },
                    &mut reasons,
                );
                // A read error of a body shows only once it was read.
                let at = node.path;
                drop(node);
                note_all(v, &mut reasons, &at, body.unread());
                flow
            });
            match flow {
                Ok(Flow::Stop(stopped)) => {
                    stopped_with = Some(stopped);
                    Some(())
                }
                Ok(Flow::Descend | Flow::Leaf) => None,
                Err(reason) => {
                    note(v, &mut reasons, &path, reason);
                    None
                }
            }
        });
        let mut ended = match (walked, stopped_with) {
            // A limit of the reader replaces the visitor's stop.
            (Err(hit), _) => Ended::Limit(hit),
            (Ok(_), Some(stopped)) => Ended::Stopped(stopped),
            (Ok(_), None) => Ended::Complete,
        };
        // Reassembly happens only now: nothing in a part's name says how many
        // parts a set has, so a set is known whole only when the container
        // ends. What could not be joined is visited too: bytes withheld from
        // the scan and then dropped would be a silent clean. A walk a limit
        // ended keeps its limit unless the visitor stops on a set.
        if !matches!(ended, Ended::Stopped(_)) {
            for part in sets.rejoined() {
                let path = at.child(Name::stored(&part.name));
                if let Some(reason) = part.incomplete {
                    note(v, &mut reasons, &path, reason);
                }
                // The parts were charged as they were read; a set's buffer is
                // new bytes, a part that did not join is not.
                if part.joined
                    && let Err(hit) = self.budget.charge_scan(part.data.len() as u64)
                {
                    if matches!(ended, Ended::Complete) {
                        ended = Ended::Limit(hit);
                    }
                    break;
                }
                let node = Node {
                    path,
                    depth: depth + 1,
                    origin: Origin::Joined { parts: part.parts },
                    meta: None,
                    content: Content::Source(&part.data),
                    end: End::Complete,
                    index: 0,
                    size: part.data.len() as u64,
                    capped: None,
                    container: format,
                    typer: None,
                    hold: 0,
                    typed: OnceCell::new(),
                }
                .typed_by(typer, walk.hold.limit);
                let cx = &mut Cx {
                    budget: &mut *self.budget,
                    walk,
                    typer,
                };
                match guarded(|| v.visit(&node, cx, &mut reasons)) {
                    Ok(Flow::Stop(stopped)) => {
                        ended = Ended::Stopped(stopped);
                        break;
                    }
                    Ok(Flow::Descend | Flow::Leaf) => {}
                    Err(reason) => note(v, &mut reasons, &node.path, reason),
                }
            }
        }
        Descent {
            ended,
            reasons,
            members: index,
        }
    }

    /// Visit what [`derive()`] finds of `kind` in the object `src`, which is at
    /// `at` and `depth`, each as a node one level down. What is made of the
    /// object's bytes is charged to the scan budget as [`Self::child`] says;
    /// the object read as another format is the same bytes again and is not.
    /// A child a budget cannot take ends the walk of the kind with that limit.
    ///
    /// Nothing found is a walk that completed, at any depth. Something found
    /// at the depth limit is not entered and is a limit, as for a container.
    pub fn derived<T>(
        &mut self,
        at: &Path<'_>,
        depth: u32,
        src: &dyn ByteSource,
        kind: DeriveKind,
        v: &mut dyn Visitor<T>,
    ) -> Descent<T> {
        let found = derive(src, kind, self.budget.limits());
        let mut reasons = Reasons::default();
        // A kind cut short before it found anything goes on, to say so.
        if found.children.is_empty() && !found.capped {
            return Descent {
                ended: Ended::Complete,
                reasons,
                members: 0,
            };
        }
        if let Some(hit) = self.depth_hit(depth) {
            return Descent {
                ended: Ended::Limit(hit),
                reasons,
                members: 0,
            };
        }
        if found.capped {
            let reason = Reason {
                kind: ReasonKind::Limit(LimitKind::MaxFiles),
                text: "more payloads were found in the object than are decoded: \
                       the rest were not examined"
                    .to_string(),
                at: String::new(),
            };
            note(v, &mut reasons, at, reason);
        }
        let mut ended = Ended::Complete;
        let (typer, hold) = (self.typer, self.walk.hold.limit);
        for child in &found.children {
            let mut enter = |cx: &mut Cx<'_>, path: Path<'_>, content: &dyn ByteSource| {
                let node =
                    Node::of(path, depth + 1, child.origin.clone(), content).typed_by(typer, hold);
                match guarded(|| v.visit(&node, cx, &mut reasons)) {
                    Ok(flow) => flow,
                    Err(reason) => {
                        note(v, &mut reasons, &node.path, reason);
                        Flow::Leaf
                    }
                }
            };
            let flow = match child.source() {
                Some(content) => self.child(at, child.name(), content.len(), |cx, path| {
                    enter(cx, path, content)
                }),
                None => Ok(enter(self, *at, src)),
            };
            match flow {
                Ok(Flow::Stop(stopped)) => {
                    ended = Ended::Stopped(stopped);
                    break;
                }
                Ok(Flow::Descend | Flow::Leaf) => {}
                Err(refused) => {
                    ended = Ended::Limit(refused.hit);
                    break;
                }
            }
        }
        Descent {
            ended,
            reasons,
            members: 0,
        }
    }

    /// Enter an object found inside the one at `at`: charge its `len` bytes to
    /// the scan budget, which a container's members are charged to as they are
    /// read, and give it its place. `name` is its segment of a path, when it
    /// has one: what is carved out of an object, or read from it a second
    /// way, has none. `visit` is given its path.
    pub fn child<'p, R>(
        &mut self,
        at: &'p Path<'p>,
        name: Option<Name<'p>>,
        len: usize,
        visit: impl FnOnce(&mut Cx<'_>, Path<'p>) -> R,
    ) -> Result<R, Refused<'p>> {
        let path = match name {
            Some(name) => at.child(name),
            None => *at,
        };
        match self.budget.charge_scan(len as u64) {
            Ok(()) => Ok(visit(self, path)),
            Err(hit) => Err(Refused { hit, at: path }),
        }
    }
}

/// What a node is.
pub enum Typed {
    /// A container of this format.
    Container(Format),
    /// Not one.
    Plain,
    /// Whether it is one could not be told, and why.
    Unchecked(Reason),
}

/// Decides what a node is, for a driver that opens containers by itself.
pub trait Typer {
    fn type_of(&self, node: &Node<'_>) -> Typed;
}

/// What an object that is not a member of a container is, for a consumer that
/// reads one level by itself: asked of `typer`, which may read up to `hold`
/// bytes of it whole.
pub fn type_object(typer: &dyn Typer, src: &dyn ByteSource, hold: u64) -> Typed {
    let node = Node::of(Path::root(Name::stored("")), 0, Origin::Root, src).typed_by(None, hold);
    typer.type_of(&node)
}

/// Why an executable over `hold` bytes is not typed as packed or not.
pub(super) fn packer_not_checked(hold: u64) -> Reason {
    Reason {
        kind: ReasonKind::NotChecked,
        text: format!(
            "an executable over the {hold}-byte limit: whether it is packed was not checked"
        ),
        at: String::new(),
    }
}

/// The object a driver is given.
pub struct Root<'a> {
    /// What to call it: a path, say. It is the first name of a node's path.
    pub name: &'a str,
    pub source: &'a dyn ByteSource,
}

/// Goes down by itself: visits the root, then the members of each container a
/// visitor answers [`Flow::Descend`] for.
pub struct Walker<'a> {
    walk: Walk<'a>,
    typer: &'a dyn Typer,
}

impl<'a> Walker<'a> {
    pub fn new(walk: Walk<'a>, typer: &'a dyn Typer) -> Self {
        Walker { walk, typer }
    }

    /// Walk `root`. A container that could not be walked to the end (a budget
    /// ran out, the container could not be read) is a reason, and the walk
    /// goes on with its siblings.
    pub fn run<T>(
        &self,
        root: Root<'_>,
        budget: &mut Budget,
        v: &mut dyn Visitor<T>,
    ) -> Descent<T> {
        let node = Node::of(
            Path::root(Name::stored(root.name)),
            0,
            Origin::Root,
            root.source,
        )
        .typed_by(Some(self.typer), self.walk.hold.limit);
        let mut reasons = Reasons::default();
        let mut cx = Cx::new(&self.walk, budget);
        cx.typer = Some(self.typer);
        let mut down = Down { visitor: v };
        let ended = match guarded(|| down.visit(&node, &mut cx, &mut reasons)) {
            Ok(Flow::Stop(stopped)) => Ended::Stopped(stopped),
            Ok(Flow::Descend | Flow::Leaf) => Ended::Complete,
            Err(reason) => {
                note(down.visitor, &mut reasons, &node.path, reason);
                Ended::Complete
            }
        };
        Descent {
            ended,
            reasons,
            members: 0,
        }
    }
}

/// A visitor that opens what its own visitor says to.
struct Down<'a, T> {
    visitor: &'a mut dyn Visitor<T>,
}

impl<T> Visitor<T> for Down<'_, T> {
    fn visit(&mut self, node: &Node<'_>, cx: &mut Cx<'_>, reasons: &mut Reasons) -> Flow<T> {
        match self.visitor.visit(node, cx, reasons) {
            Flow::Descend => {}
            done => return done,
        }
        let format = match node.format() {
            Typed::Container(format) => *format,
            Typed::Plain => return Flow::Leaf,
            Typed::Unchecked(reason) => {
                note(&mut *self.visitor, reasons, &node.path, reason.clone());
                return Flow::Leaf;
            }
        };
        let Some(src) = node.source() else {
            return Flow::Leaf;
        };
        let below = cx.members(&node.path, node.depth, src, format, self);
        let members = below.members;
        if let Some(done) = self.settle(below, node, reasons) {
            return done;
        }
        // A container that was not opened for its depth has nothing more said
        // of it, and a second reading is not read a second way again.
        if cx.depth_hit(node.depth).is_some() {
            return Flow::Leaf;
        }
        if let Flow::Stop(stopped) = self.visitor.leave(node, members, cx, reasons) {
            return Flow::Stop(stopped);
        }
        if cx.walk.second_readings && !matches!(node.origin, Origin::Second(_)) {
            let kinds = [DeriveKind::AppendedZip, DeriveKind::AlsoReadsAs(format)];
            for kind in kinds {
                if kind == DeriveKind::AppendedZip && format == Format::Zip {
                    continue;
                }
                let found = cx.derived(&node.path, node.depth, src, kind, self);
                if let Some(done) = self.settle(found, node, reasons) {
                    return done;
                }
            }
        }
        Flow::Leaf
    }

    fn reason(&mut self, at: &Path<'_>, reason: &Reason) {
        self.visitor.reason(at, reason);
    }
}

impl<T> Down<'_, T> {
    /// Take what a walk under `node` left: its reasons, and a limit it ended
    /// at as one more. `Some` when the walk is to stop.
    fn settle(
        &mut self,
        done: Descent<T>,
        node: &Node<'_>,
        reasons: &mut Reasons,
    ) -> Option<Flow<T>> {
        reasons.merge_at(done.reasons, &node.path);
        match done.ended {
            Ended::Complete => None,
            Ended::Stopped(stopped) => Some(Flow::Stop(stopped)),
            Ended::Limit(hit) => {
                let reason = Reason {
                    kind: ReasonKind::from_limit(hit.kind),
                    text: hit.reason,
                    at: String::new(),
                };
                note(&mut *self.visitor, reasons, &node.path, reason);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "base64scan")]
    use super::super::EncodedKind;
    use super::super::{Large, PathStyle, Typing};
    use super::*;
    use crate::Limits;
    use crate::Member;
    use crate::spill::MemSpill;
    use crate::stream::BudgetReader;
    use std::cell::Cell;
    use std::io::{Cursor, Read};

    fn meta(name: &str) -> MemberMeta {
        MemberMeta {
            name: name.to_string(),
            ..MemberMeta::default()
        }
    }

    fn budget(max_recursion: u32) -> Budget {
        Budget::new(Limits {
            max_recursion,
            ..Limits::default()
        })
    }

    fn walk(limit: u64, spill: Option<&dyn crate::spill::Spill>, sets: bool) -> Walk<'_> {
        Walk {
            hold: Hold {
                limit,
                spill,
                cache: (4096, 1 << 20),
                large: Large::Source,
            },
            sets,
            second_readings: false,
        }
    }

    /// A reader that hands over `members` as decoded in full, until a visitor
    /// stops it.
    fn play(
        members: Vec<(MemberMeta, Vec<u8>)>,
    ) -> impl FnOnce(&mut Budget, Visit<'_, ()>) -> Result<Option<()>, LimitHit> {
        move |budget, visit| {
            for (meta, data) in members {
                if let Some(stopped) = visit(&meta, Some(Member::Bytes(data)), budget) {
                    return Ok(Some(stopped));
                }
            }
            Ok(None)
        }
    }

    fn named(members: &[(&str, &[u8])]) -> Vec<(MemberMeta, Vec<u8>)> {
        members
            .iter()
            .map(|(name, data)| (meta(name), data.to_vec()))
            .collect()
    }

    /// A 100-byte container that fails once it is read.
    struct Broken(Cell<bool>);

    impl ByteSource for Broken {
        fn len(&self) -> usize {
            100
        }
        fn window(&self, _: usize, _: usize) -> std::borrow::Cow<'_, [u8]> {
            self.0.set(true);
            std::borrow::Cow::Borrowed(&[])
        }
        fn read_error(&self) -> Option<String> {
            self.0.get().then(|| "disk gone".to_string())
        }
        fn identity(&self) -> (usize, usize) {
            (0, 100)
        }
    }

    /// What a visitor was told of a node.
    #[derive(Debug, PartialEq)]
    struct Rec {
        path: String,
        depth: u32,
        index: u64,
        size: u64,
        content: Option<Vec<u8>>,
        capped: Option<String>,
        end: End,
        origin: Origin,
    }

    /// A visitor that records what it sees and does what it is told.
    #[derive(Default)]
    struct Script {
        seen: Vec<Rec>,
        /// Stop at the node with this last name.
        stop_at: Option<&'static str>,
        /// Add a reason when the node with this last name is visited.
        notes: Vec<(&'static str, ReasonKind, &'static str)>,
        descend: bool,
        /// The reasons the walk told, with where (nested) and what.
        told: Vec<(String, ReasonKind, String)>,
        /// The containers left, with how many members each had.
        left: Vec<(String, u64)>,
        /// Stop when the container with this last name is left.
        leave_stop: Option<&'static str>,
    }

    impl Visitor<String> for Script {
        fn reason(&mut self, at: &Path<'_>, reason: &Reason) {
            self.told.push((
                at.render(PathStyle::Nested),
                reason.kind,
                reason.text.clone(),
            ));
        }

        fn leave(
            &mut self,
            node: &Node<'_>,
            members: u64,
            _: &mut Cx<'_>,
            _: &mut Reasons,
        ) -> Flow<String> {
            let last = node.path.render(PathStyle::Last);
            self.left
                .push((node.path.render(PathStyle::Nested), members));
            match self.leave_stop == Some(last.as_str()) {
                true => Flow::Stop(last),
                false => Flow::Leaf,
            }
        }

        fn visit(
            &mut self,
            node: &Node<'_>,
            _: &mut Cx<'_>,
            reasons: &mut Reasons,
        ) -> Flow<String> {
            let last = node.path.render(PathStyle::Last);
            self.seen.push(Rec {
                path: node.path.render(PathStyle::Nested),
                depth: node.depth,
                index: node.index,
                size: node.size,
                content: node
                    .source()
                    .map(|src| src.window(0, src.len()).into_owned()),
                capped: node.capped.map(str::to_string),
                end: node.end.clone(),
                origin: node.origin.clone(),
            });
            for (at, kind, text) in &self.notes {
                if *at == last {
                    let reason = Reason {
                        kind: *kind,
                        text: text.to_string(),
                        at: String::new(),
                    };
                    reasons.add_at(reason, &node.path);
                }
            }
            if self.stop_at == Some(last.as_str()) {
                return Flow::Stop(last);
            }
            if self.descend {
                Flow::Descend
            } else {
                Flow::Leaf
            }
        }
    }

    fn paths(script: &Script) -> Vec<&str> {
        script.seen.iter().map(|r| r.path.as_str()).collect()
    }

    /// Visit `members` of a container of `container` bytes at `depth`.
    fn members_of(
        walk: &Walk<'_>,
        budget: &mut Budget,
        depth: u32,
        container: &[u8],
        members: Vec<(MemberMeta, Vec<u8>)>,
        v: &mut Script,
    ) -> Descent<String> {
        let root = Path::root(Name::stored("root"));
        Cx::new(walk, budget).members_with(
            &root,
            depth,
            &container,
            Some(Format::Tar),
            v,
            play(members),
        )
    }

    /// [`members_of`] for any visitor, at depth 0.
    fn members_of_with(
        walk: &Walk<'_>,
        members: Vec<(MemberMeta, Vec<u8>)>,
        v: &mut dyn Visitor<String>,
    ) -> Descent<String> {
        let root = Path::root(Name::stored("root"));
        Cx::new(walk, &mut budget(16)).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            v,
            play(members),
        )
    }

    #[test]
    fn a_container_at_the_depth_limit_is_not_opened_and_one_below_it_is() {
        let w = walk(100, None, true);
        for (depth, opened) in [(0, true), (1, true), (2, true), (3, false), (4, false)] {
            let called = Cell::new(false);
            let mut script = Script::default();
            let root = Path::root(Name::stored("root"));
            let mut b = budget(3);
            let got = Cx::new(&w, &mut b).members_with(
                &root,
                depth,
                &b"container".as_slice(),
                None,
                &mut script,
                |_: &mut Budget, _: Visit<'_, ()>| {
                    called.set(true);
                    Ok(None)
                },
            );
            assert_eq!(called.get(), opened, "depth {depth}");
            match got.ended {
                Ended::Complete => assert!(opened, "depth {depth}"),
                Ended::Limit(hit) => {
                    assert!(!opened, "depth {depth}");
                    assert_eq!(hit.kind, LimitKind::MaxRecursion);
                    assert_eq!(hit.reason, "recursion depth exceeds 3");
                }
                Ended::Stopped(_) => panic!("stopped"),
            }
        }
        let w = walk(100, None, true);
        let mut b = budget(3);
        let cx = Cx::new(&w, &mut b);
        assert!(cx.depth_hit(2).is_none());
        assert_eq!(cx.depth_hit(3).unwrap().reason, "recursion depth exceeds 3");
    }

    #[test]
    fn each_member_is_visited_in_order_with_its_place() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let got = members_of(
            &w,
            &mut budget(16),
            2,
            b"container bytes",
            named(&[("a", b"one"), ("dir/b", b"twotwo")]),
            &mut script,
        );
        assert!(matches!(got.ended, Ended::Complete));
        assert!(got.reasons.is_empty());
        let want = |path: &str, index, content: &[u8]| Rec {
            path: path.to_string(),
            depth: 3,
            index,
            size: content.len() as u64,
            content: Some(content.to_vec()),
            capped: None,
            end: End::Complete,
            origin: Origin::Member,
        };
        assert_eq!(
            script.seen,
            vec![want("root!a", 1, b"one"), want("root!dir/b", 2, b"twotwo")]
        );
    }

    #[test]
    fn a_member_with_no_content_is_visited_with_its_size_in_its_container() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let mut m = meta("gone");
        m.comp_size = 77;
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| Ok(visit(&m, None, budget)),
        );
        let [seen] = &script.seen[..] else {
            panic!("{:?}", script.seen)
        };
        assert_eq!((seen.content.clone(), seen.size), (None, 77));
    }

    #[test]
    fn a_member_identical_to_its_container_is_not_visited_or_counted() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        members_of(
            &w,
            &mut budget(16),
            0,
            b"same bytes",
            named(&[("me", b"same bytes"), ("other", b"not the same")]),
            &mut script,
        );
        assert_eq!(paths(&script), ["root!other"]);
        assert_eq!(script.seen[0].index, 1);
    }

    #[test]
    fn a_visitor_that_stops_ends_the_walk_after_the_members_it_has_seen() {
        let w = walk(100, None, true);
        let mut script = Script {
            stop_at: Some("b"),
            ..Script::default()
        };
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            named(&[("a", b"1"), ("b", b"2"), ("c", b"3")]),
            &mut script,
        );
        assert_eq!(paths(&script), ["root!a", "root!b"]);
        assert!(matches!(got.ended, Ended::Stopped(ref s) if s == "b"));
    }

    #[test]
    fn a_limit_the_reader_meets_after_a_stop_replaces_the_stop() {
        let w = walk(100, None, true);
        let mut script = Script {
            stop_at: Some("a"),
            ..Script::default()
        };
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                let m = meta("a");
                assert_eq!(
                    visit(&m, Some(Member::Bytes(b"1".to_vec())), budget),
                    Some(())
                );
                Err(LimitHit::of_kind(
                    LimitKind::MaxScanSize,
                    "over".to_string(),
                ))
            },
        );
        assert_eq!(paths(&script), ["root!a"]);
        match got.ended {
            Ended::Limit(hit) => assert_eq!(hit.reason, "over"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_member_the_budget_cannot_take_is_not_visited_and_the_walks_own_limit_stands() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                let mut src = Cursor::new(vec![9u8; 50]);
                let mut capped = BudgetReader::new(&mut src, 10);
                let told = visit(&meta("big"), Some(Member::Stream(&mut capped)), budget);
                assert!(told.is_none(), "the visitor was not asked");
                Err(LimitHit::of_kind(
                    LimitKind::MaxScanSize,
                    "the walk's own".to_string(),
                ))
            },
        );
        assert!(script.seen.is_empty());
        assert!(matches!(got.ended, Ended::Limit(hit) if hit.reason == "the walk's own"));
    }

    #[test]
    fn reasons_follow_the_order_of_the_walk_and_say_where_they_arose() {
        let w = walk(100, None, true);
        let mut script = Script {
            notes: vec![("m1", ReasonKind::Unsupported, "from the visitor of m1")],
            ..Script::default()
        };
        let mut m2 = meta("m2");
        m2.unsupported = Some("from the reader");
        let mut m3 = meta("m3");
        m3.encrypted = true;
        m3.unsupported = Some("needs a password");
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            vec![
                (meta("m1"), b"x".to_vec()),
                (m2, b"y".to_vec()),
                (m3, b"z".to_vec()),
            ],
            &mut script,
        );
        // The reasons a visitor adds are those of the container, in the order
        // of the walk: the first of a class stays, with the place it arose at.
        let first = got.reasons.unscannable.expect("an unscannable reason");
        assert_eq!(first.text, "from the visitor of m1");
        assert_eq!(first.at, "m1");
        assert_eq!(got.reasons.total, 1);
    }

    #[test]
    fn a_read_error_of_a_body_is_reported_after_what_the_visitor_added_for_the_member() {
        // The member, over the hold limit, is read in place.
        let w = walk(40, None, true);
        let mut m = meta("late");
        m.range = Some((0, 60));
        let root = Path::root(Name::stored("root"));
        for note in [true, false] {
            let mut script = Script {
                notes: if note {
                    vec![("late", ReasonKind::Damaged, "from the visitor")]
                } else {
                    Vec::new()
                },
                ..Script::default()
            };
            let mut b = budget(16);
            let m = m.clone();
            let container = Broken(Cell::new(false));
            let got = Cx::new(&w, &mut b).members_with(
                &root,
                0,
                &container,
                None,
                &mut script,
                |budget: &mut Budget, visit: Visit<'_, ()>| {
                    let mut unread = Cursor::new(Vec::new());
                    Ok(visit(&m, Some(Member::Stream(&mut unread)), budget))
                },
            );
            let kept = got.reasons.unscannable.expect("a reason");
            if note {
                assert_eq!(kept.text, "from the visitor");
                assert_eq!(got.reasons.total, 2);
            } else {
                assert_eq!(kept.text, "member unreadable: disk gone");
                assert_eq!(kept.kind, ReasonKind::ReadFailed);
                assert_eq!(kept.at, "late");
            }
            assert_eq!(script.seen[0].size, 60);
        }
    }

    /// A member declared as a range of its container that runs past its end
    /// is cut there, held or read in place: the node says so, and no reason
    /// is added (the rest is absent, not hidden).
    #[test]
    fn a_range_past_the_end_of_its_container_is_a_cut() {
        let container = vec![5u8; 100];
        let root = Path::root(Name::stored("root"));
        for (hold, size) in [(40, 20), (1000, 20)] {
            let w = walk(hold, None, true);
            let mut m = meta("late");
            m.range = Some((80, 60));
            let mut script = Script::default();
            let mut b = budget(16);
            let got = Cx::new(&w, &mut b).members_with(
                &root,
                0,
                &container.as_slice(),
                None,
                &mut script,
                |budget: &mut Budget, visit: Visit<'_, ()>| {
                    let mut stream = Cursor::new(vec![5u8; 20]);
                    Ok(visit(&m, Some(Member::Stream(&mut stream)), budget))
                },
            );
            assert_eq!(got.reasons.total, 0, "hold {hold}");
            assert!(script.told.is_empty(), "hold {hold}: {:?}", script.told);
            assert_eq!(script.seen[0].size, size, "hold {hold}");
            let End::Cut(why) = &script.seen[0].end else {
                panic!("hold {hold}: {:?}", script.seen[0].end);
            };
            assert_eq!(
                why,
                "member 'late' is 60 bytes at 80, past the end of its 100-byte container: \
                 only 20 bytes of it are in the container"
            );
        }
    }

    /// A reader that gives `data`, then fails with `err`.
    struct Failing {
        data: Cursor<Vec<u8>>,
        err: fn() -> std::io::Error,
    }

    impl std::io::Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.data.read(buf)? {
                0 => Err((self.err)()),
                n => Ok(n),
            }
        }
    }

    fn bad_block() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "bad block")
    }

    fn eof() -> std::io::Error {
        std::io::Error::from(std::io::ErrorKind::UnexpectedEof)
    }

    #[test]
    fn what_the_taking_of_a_member_left_comes_before_what_its_visitor_adds() {
        let w = walk(100, None, true);
        let mut script = Script {
            notes: vec![("m", ReasonKind::Unsupported, "from the visitor")],
            ..Script::default()
        };
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                // Nothing decodes before the error, and the error hides content.
                let mut rdr = Failing {
                    data: Cursor::new(Vec::new()),
                    err: bad_block,
                };
                Ok(visit(&meta("m"), Some(Member::Stream(&mut rdr)), budget))
            },
        );
        let first = got.reasons.unscannable.expect("a reason");
        assert_eq!(first.kind, ReasonKind::Damaged);
        assert_eq!(first.text, "member decode error: bad block");
        assert_eq!(first.at, "m");
        assert_eq!(got.reasons.total, 2);
        // The member is visited all the same, with nothing in it.
        assert_eq!(script.seen[0].content, None);
        assert_eq!(script.seen[0].end, End::Damaged("bad block".to_string()));
    }

    #[test]
    fn a_member_nothing_of_which_decoded_has_no_content_and_is_lost_to_its_set() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let mut m = meta("x.7z.001");
        m.unsupported = Some("unsupported method");
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            vec![(m, Vec::new()), (meta("x.7z.002"), b"cd".to_vec())],
            &mut script,
        );
        assert_eq!(script.seen[0].content, None);
        // Not offered to the set, which is missing it: the other part is not
        // joined with a hole, and the set is reported.
        assert_eq!(
            paths(&script),
            ["root!x.7z.001", "root!x.7z.002", "root!x.7z.002"]
        );
        assert_eq!(script.seen[2].content.as_deref(), Some(&b"cd"[..]));
        let why = got.reasons.unscannable.expect("the set is reported");
        assert_eq!(
            (why.kind, why.text.as_str(), why.at.as_str()),
            (ReasonKind::SetIncomplete, LOST, "x.7z.002")
        );
    }

    #[test]
    fn a_member_with_no_body_is_lost_to_its_set() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(
                    &meta("x.7z.001"),
                    Some(Member::Bytes(b"ab".to_vec())),
                    budget,
                );
                // The reader gave no content at all for this part.
                visit(&meta("x.7z.002"), None, budget);
                Ok(None)
            },
        );
        assert_eq!(
            paths(&script),
            ["root!x.7z.001", "root!x.7z.002", "root!x.7z.001"]
        );
        let why = got.reasons.unscannable.expect("the set is reported");
        assert_eq!(
            (why.kind, why.text.as_str(), why.at.as_str()),
            (ReasonKind::SetIncomplete, LOST, "x.7z.001")
        );
        // A part that did not join is its bytes as its reader handed them
        // over, and charged them (`emit_bytes`): not charged again.
        assert_eq!(b.scanned, 0);
    }

    #[test]
    fn a_held_part_whose_stream_ends_cut_is_visited_as_far_as_it_decoded_and_lost_to_its_set() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(
                    &meta("x.7z.001"),
                    Some(Member::Bytes(b"ab".to_vec())),
                    budget,
                );
                let mut rdr = Failing {
                    data: Cursor::new(b"cd".to_vec()),
                    err: eof,
                };
                visit(&meta("x.7z.002"), Some(Member::Stream(&mut rdr)), budget);
                Ok(None)
            },
        );
        // What decoded is visited, as a cut: it is not held for the set.
        assert_eq!(script.seen[1].content.as_deref(), Some(&b"cd"[..]));
        assert!(matches!(script.seen[1].end, End::Cut(_)));
        let why = got.reasons.unscannable.expect("the set is reported");
        assert_eq!(why.text, LOST);
        assert_eq!(why.at, "x.7z.001");
    }

    const LOST: &str =
        "part of a multi-volume set one of whose volumes could not be held for rejoining";

    #[test]
    fn a_part_held_for_its_set_is_visited_without_bytes_and_the_set_is_rejoined_at_the_end() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let mut b = budget(16);
        let got = members_of(
            &w,
            &mut b,
            1,
            b"container",
            named(&[
                ("x.7z.001", b"ab"),
                ("note.txt", b"hi"),
                ("x.7z.002", b"cd"),
            ]),
            &mut script,
        );
        assert!(matches!(got.ended, Ended::Complete));
        let seen: Vec<_> = script
            .seen
            .iter()
            .map(|r| (r.path.as_str(), r.depth, r.index, r.content.as_deref()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("root!x.7z.001", 2, 1, None),
                ("root!note.txt", 2, 2, Some(&b"hi"[..])),
                ("root!x.7z.002", 2, 3, None),
                ("root!x.7z", 2, 0, Some(&b"abcd"[..])),
            ]
        );
        assert_eq!(
            script.seen[3].origin,
            Origin::Joined {
                parts: vec!["x.7z.001".to_string(), "x.7z.002".to_string()]
            }
        );
        assert_eq!(script.seen[3].size, 4);
        // The joined buffer is charged to the scan budget, as the parts were
        // not: they were not read through a stream.
        assert_eq!(b.scanned, 4);
        assert!(got.reasons.is_empty());
    }

    #[test]
    fn a_part_too_large_to_hold_is_lost_to_its_set_and_the_part_held_is_given_back_with_why() {
        let w = walk(3, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(
                    &meta("x.7z.001"),
                    Some(Member::Bytes(b"ab".to_vec())),
                    budget,
                );
                let mut long = Cursor::new(b"cdefghij".to_vec());
                visit(&meta("x.7z.002"), Some(Member::Stream(&mut long)), budget);
                Ok(None)
            },
        );
        assert_eq!(
            paths(&script),
            ["root!x.7z.001", "root!x.7z.002", "root!x.7z.001"]
        );
        // Past the hold limit with nowhere to write: the first bytes are seen,
        // and why the rest is not.
        assert_eq!(script.seen[1].content.as_deref(), Some(&b"cde"[..]));
        assert!(
            script.seen[1]
                .capped
                .as_deref()
                .unwrap()
                .contains("could not be spilled")
        );
        assert_eq!(script.seen[2].content.as_deref(), Some(&b"ab"[..]));
        assert_eq!(
            script.seen[2].origin,
            Origin::Joined {
                parts: vec!["x.7z.001".to_string()]
            }
        );
        let why = got.reasons.unscannable.expect("the set is reported");
        assert_eq!(
            (why.kind, why.text.as_str()),
            (ReasonKind::SetIncomplete, LOST)
        );
        assert_eq!(why.at, "x.7z.001");
    }

    #[test]
    fn a_part_cut_short_is_lost_to_its_set_and_a_spilled_one_too() {
        let spill = MemSpill::new();
        let w = walk(3, Some(&spill), true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(
                    &meta("y.7z.001"),
                    Some(Member::Bytes(b"ab".to_vec())),
                    budget,
                );
                let mut long = Cursor::new(b"cdefghij".to_vec());
                visit(&meta("y.7z.002"), Some(Member::Stream(&mut long)), budget);
                Ok(None)
            },
        );
        // Written to the spill, and read back whole.
        assert_eq!(script.seen[1].content.as_deref(), Some(&b"cdefghij"[..]));
        assert!(script.seen[1].capped.is_none());
        let why = got.reasons.unscannable.expect("the set is reported");
        assert_eq!(why.text, LOST);
    }

    #[test]
    fn a_set_is_not_rejoined_when_the_walk_did_not_finish() {
        let w = walk(100, None, true);
        let mut script = Script {
            stop_at: Some("stop"),
            ..Script::default()
        };
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            named(&[("x.7z.001", b"ab"), ("x.7z.002", b"cd"), ("stop", b"s")]),
            &mut script,
        );
        assert_eq!(
            paths(&script),
            ["root!x.7z.001", "root!x.7z.002", "root!stop"]
        );
        assert!(matches!(got.ended, Ended::Stopped(_)));
        assert!(got.reasons.is_empty());
    }

    #[test]
    fn a_visitor_that_stops_at_a_rejoined_file_ends_the_walk_there() {
        let w = walk(100, None, true);
        let mut script = Script {
            stop_at: Some("x.7z"),
            ..Script::default()
        };
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            named(&[
                ("x.7z.001", b"ab"),
                ("x.7z.002", b"cd"),
                ("y.7z.001", b"1"),
                ("y.7z.002", b"2"),
            ]),
            &mut script,
        );
        let last = script.seen.last().unwrap();
        assert_eq!(last.path, "root!x.7z");
        assert!(matches!(got.ended, Ended::Stopped(ref s) if s == "x.7z"));
    }

    #[test]
    fn a_rejoined_file_over_the_scan_budget_ends_the_walk_with_the_limit() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = Budget::new(Limits {
            max_scanned_bytes: 3,
            ..Limits::default()
        });
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            play(named(&[("x.7z.001", b"ab"), ("x.7z.002", b"cd")])),
        );
        // Not visited: the buffer was refused.
        assert_eq!(script.seen.len(), 2);
        match got.ended {
            Ended::Limit(hit) => {
                assert_eq!(hit.kind, LimitKind::MaxScanSize);
                assert_eq!(hit.reason, "scanned bytes > 3");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn with_sets_off_nothing_is_held_or_rejoined() {
        let w = walk(100, None, false);
        let mut script = Script::default();
        let got = members_of(
            &w,
            &mut budget(16),
            0,
            b"container",
            named(&[("x.7z.001", b"ab"), ("x.7z.002", b"cd")]),
            &mut script,
        );
        assert_eq!(paths(&script), ["root!x.7z.001", "root!x.7z.002"]);
        assert_eq!(script.seen[0].content.as_deref(), Some(&b"ab"[..]));
        assert!(got.reasons.is_empty());
    }

    #[test]
    fn a_child_is_charged_to_the_scan_budget_named_and_refused_over_it() {
        let w = walk(100, None, true);
        let mut b = Budget::new(Limits {
            max_scanned_bytes: 10,
            ..Limits::default()
        });
        let mut cx = Cx::new(&w, &mut b);
        let top = Path::root(Name::stored("top"));
        let at = top.child(Name::stored("mid"));
        // Named: one level below `at`. Unnamed: where `at` is.
        let named = cx
            .child(
                &at,
                Some(Name::new("base64-payload-1", NameKind::Derived)),
                4,
                |_, p| p.render(PathStyle::Located),
            )
            .unwrap();
        assert_eq!(named, "mid/base64-payload-1");
        let unnamed = cx
            .child(&at, None, 6, |_, p| p.render(PathStyle::Located))
            .unwrap();
        assert_eq!(unnamed, "mid");
        // 10 of 10 are charged: one more byte is refused, and still counted.
        let refused = cx
            .child(&at, Some(Name::stored("late")), 1, |_, _| panic!("visited"))
            .unwrap_err();
        assert_eq!(refused.hit.kind, LimitKind::MaxScanSize);
        assert_eq!(refused.hit.reason, "scanned bytes > 10");
        assert_eq!(refused.at.render(PathStyle::Located), "mid/late");
        assert_eq!(cx.budget().scanned, 11);
    }

    /// A tar of `entries`.
    #[cfg(feature = "tar")]
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut b = ::tar::Builder::new(&mut buf);
            for (name, data) in entries {
                let mut h = ::tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, *data).unwrap();
            }
            b.finish().unwrap();
        }
        buf
    }

    #[cfg(feature = "tar")]
    fn run(bytes: &[u8], max_recursion: u32, v: &mut Script, typer: &dyn Typer) -> Descent<String> {
        let w = walk(1 << 20, None, true);
        let walker = Walker::new(w, typer);
        let mut b = budget(max_recursion);
        walker.run(
            Root {
                name: "top.tar",
                source: &bytes,
            },
            &mut b,
            v,
        )
    }

    #[cfg(all(feature = "tar", feature = "gzip"))]
    #[test]
    fn the_one_member_of_a_compressor_is_named_as_a_stream_and_a_stored_one_is_not() {
        use std::io::Write;

        struct Kinds(Vec<(u32, NameKind)>);
        impl Visitor<()> for Kinds {
            fn visit(&mut self, node: &Node<'_>, _: &mut Cx<'_>, _: &mut Reasons) -> Flow<()> {
                self.0.push((node.depth, node.path.name().kind));
                Flow::Descend
            }
        }

        // A tar member called as the reader calls a gzip stream's.
        let tar = tar_of(&[("gzip-content", b"hello")]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let bytes = gz.finish().unwrap();
        let mut kinds = Kinds(Vec::new());
        let walker = Walker::new(walk(1 << 20, None, true), &Typing::WALK);
        walker.run(
            Root {
                name: "top.tgz",
                source: &bytes,
            },
            &mut budget(16),
            &mut kinds,
        );
        assert_eq!(
            kinds.0,
            [
                (0, NameKind::Stored),
                (1, NameKind::Stream),
                (2, NameKind::Stored)
            ]
        );
    }

    #[cfg(feature = "tar")]
    #[test]
    fn the_driver_opens_what_the_visitor_says_to_and_only_that() {
        let inner = tar_of(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let outer = tar_of(&[("in.tar", &inner), ("c.txt", b"plain")]);
        let mut script = Script {
            descend: true,
            notes: vec![("b.txt", ReasonKind::Damaged, "found deep down")],
            ..Script::default()
        };
        let got = run(&outer, 16, &mut script, &Typing::WALK);
        assert!(matches!(got.ended, Ended::Complete));
        // What was found under a container is the reasons of the one above it.
        let deep = got.reasons.unscannable.as_ref().expect("a reason");
        assert_eq!(
            (deep.text.as_str(), deep.at.as_str()),
            ("found deep down", "in.tar/b.txt")
        );
        let depths: Vec<_> = script
            .seen
            .iter()
            .map(|r| (r.path.as_str(), r.depth))
            .collect();
        assert_eq!(
            depths,
            vec![
                ("top.tar", 0),
                ("top.tar!in.tar", 1),
                ("top.tar!in.tar!a.txt", 2),
                ("top.tar!in.tar!b.txt", 2),
                ("top.tar!c.txt", 1),
            ]
        );
        // The root is not a member; every other node is.
        assert_eq!(script.seen[0].origin, Origin::Root);
        assert_eq!(script.seen[1].origin, Origin::Member);
        // A visitor that does not descend sees only the root.
        let mut flat = Script::default();
        run(&outer, 16, &mut flat, &Typing::WALK);
        assert_eq!(paths(&flat), ["top.tar"]);
    }

    #[cfg(feature = "tar")]
    #[test]
    fn the_driver_does_not_open_a_container_at_the_depth_limit_and_says_so() {
        let deep = tar_of(&[("leaf.txt", b"x")]);
        let mid = tar_of(&[("deep.tar", &deep), ("leaf2.txt", b"y")]);
        let top = tar_of(&[("mid.tar", &mid)]);
        // Limit 2: the root (depth 0) and mid.tar (1) are opened; deep.tar is
        // at depth 2, a container at the limit, and is not; a leaf at the
        // limit is visited.
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        let got = run(&top, 2, &mut script, &Typing::WALK);
        assert_eq!(
            paths(&script),
            [
                "top.tar",
                "top.tar!mid.tar",
                "top.tar!mid.tar!deep.tar",
                "top.tar!mid.tar!leaf2.txt"
            ]
        );
        let why = got.reasons.limits.expect("the limit is a reason");
        assert_eq!(why.text, "recursion depth exceeds 2");
        assert_eq!(why.kind, ReasonKind::Limit(LimitKind::MaxRecursion));
        assert_eq!(why.at, "mid.tar/deep.tar");
        // One level more and the leaf of deep.tar is reached.
        let mut more = Script {
            descend: true,
            ..Script::default()
        };
        let got = run(&top, 3, &mut more, &Typing::WALK);
        assert!(
            more.seen
                .iter()
                .any(|r| r.path.ends_with("deep.tar!leaf.txt"))
        );
        assert!(got.reasons.limits.is_none());
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_container_that_cannot_be_read_is_a_reason_and_its_siblings_are_visited() {
        // A tar whose header checksum is wrong is not a tar: the walk of it
        // ends with the reader's own error, and the node after it is visited.
        let mut broken = tar_of(&[("a.txt", b"x")]);
        broken[148] = b'9';
        let good = tar_of(&[("b.txt", b"y")]);
        let outer = tar_of(&[("broken.tar", &broken), ("good.tar", &good)]);
        struct Always;
        impl Typer for Always {
            fn type_of(&self, node: &Node<'_>) -> Typed {
                match node.path.render(PathStyle::Last).ends_with(".tar") {
                    true => Typed::Container(Format::Tar),
                    false => Typed::Plain,
                }
            }
        }
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        let got = run(&outer, 16, &mut script, &Always);
        assert!(
            paths(&script).contains(&"top.tar!good.tar!b.txt"),
            "{:?}",
            paths(&script)
        );
        assert!(got.reasons.total >= 1, "{:?}", got.reasons);
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_node_the_typer_cannot_type_is_a_reason_and_is_not_opened() {
        struct Unsure;
        impl Typer for Unsure {
            fn type_of(&self, _: &Node<'_>) -> Typed {
                Typed::Unchecked(Reason {
                    kind: ReasonKind::NotChecked,
                    text: "too large to look at".to_string(),
                    at: String::new(),
                })
            }
        }
        let outer = tar_of(&[("a.txt", b"x")]);
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        let got = run(&outer, 16, &mut script, &Unsure);
        assert_eq!(paths(&script), ["top.tar"]);
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!(why.text, "too large to look at");
        assert_eq!(why.at, "");
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_stop_of_the_visitor_ends_the_whole_walk() {
        let inner = tar_of(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        let outer = tar_of(&[("in.tar", &inner), ("c.txt", b"plain")]);
        let mut script = Script {
            descend: true,
            stop_at: Some("a.txt"),
            ..Script::default()
        };
        let got = run(&outer, 16, &mut script, &Typing::WALK);
        assert_eq!(
            paths(&script),
            ["top.tar", "top.tar!in.tar", "top.tar!in.tar!a.txt"]
        );
        assert!(matches!(got.ended, Ended::Stopped(ref s) if s == "a.txt"));
    }

    /// A visitor that panics at the nodes `when` says, sees them all, and
    /// descends if it is told to.
    struct Panics<F: Fn(&Node<'_>) -> bool> {
        when: F,
        descend: bool,
        seen: Vec<(String, Origin)>,
    }

    impl<F: Fn(&Node<'_>) -> bool> Panics<F> {
        fn new(descend: bool, when: F) -> Self {
            Panics {
                when,
                descend,
                seen: Vec::new(),
            }
        }

        fn last_names(&self) -> Vec<&str> {
            self.seen.iter().map(|(name, _)| name.as_str()).collect()
        }
    }

    impl<F: Fn(&Node<'_>) -> bool> Visitor<String> for Panics<F> {
        fn visit(&mut self, node: &Node<'_>, _: &mut Cx<'_>, _: &mut Reasons) -> Flow<String> {
            self.seen
                .push((node.path.render(PathStyle::Last), node.origin.clone()));
            if (self.when)(node) {
                panic!("the visitor");
            }
            match self.descend {
                true => Flow::Descend,
                false => Flow::Leaf,
            }
        }
    }

    /// A panic of a visitor is not the decoder of the container panicking: it
    /// is a reason at the node it panicked at, the walk goes on with the nodes
    /// after it, and the container ends as complete.
    #[cfg(feature = "tar")]
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
    fn a_panic_in_a_visitor_is_a_reason_at_its_node_and_its_siblings_are_visited() {
        let tar = tar_of(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
        let w = walk(100, None, true);
        let mut b = budget(16);
        let mut v = Panics::new(false, |n| n.path.render(PathStyle::Last) == "b.txt");
        let root = Path::root(Name::stored("top"));
        let got = Cx::new(&w, &mut b).members(&root, 0, &tar, Format::Tar, &mut v);
        assert_eq!(v.last_names(), ["a.txt", "b.txt", "c.txt"]);
        assert!(matches!(got.ended, Ended::Complete), "{:?}", got.ended);
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!(why.kind, ReasonKind::Panic);
        assert_eq!(why.at, "b.txt");
        assert!(why.text.contains("panic"), "{}", why.text);
        assert_eq!(got.reasons.total, 1);
    }

    /// The same for a node the walk derives (a ZIP appended to a container),
    /// and for the root: a reason there, and the rest of the walk goes on.
    #[cfg(all(feature = "tar", feature = "zip"))]
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
    fn a_panic_in_a_visitor_at_a_second_reading_or_at_the_root_is_a_reason_there() {
        let mut bytes = tar_of(&[("a.txt", b"hello")]);
        bytes.extend_from_slice(&super::super::derive::stored_zip("z.txt", b"inside"));
        let second = Origin::Second(SecondReading::AppendedZip);
        let run = |v: &mut dyn Visitor<String>| {
            let mut w = walk(1 << 20, None, true);
            w.second_readings = true;
            let walker = Walker::new(w, &Typing::WALK);
            walker.run(
                Root {
                    name: "top.tar",
                    source: &bytes.as_slice(),
                },
                &mut budget(16),
                v,
            )
        };
        // At the second reading: it is a node of the root's path, nothing is
        // opened under it, and the walk is complete.
        let mut v = Panics::new(true, |n| n.origin == second);
        let got = run(&mut v);
        assert_eq!(v.last_names(), ["top.tar", "a.txt", "top.tar"]);
        assert!(matches!(got.ended, Ended::Complete), "{:?}", got.ended);
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!((why.kind, why.at.as_str()), (ReasonKind::Panic, ""));
        // At the root: nothing else is visited.
        let mut v = Panics::new(true, |n| n.origin == Origin::Root);
        let got = run(&mut v);
        assert_eq!(v.last_names(), ["top.tar"]);
        assert!(matches!(got.ended, Ended::Complete), "{:?}", got.ended);
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!((why.kind, why.at.as_str()), (ReasonKind::Panic, ""));
    }

    /// And for a payload decoded out of a text: the next one is visited.
    #[cfg(feature = "base64scan")]
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
    fn a_panic_in_a_visitor_at_a_derived_child_is_a_reason_there_and_the_next_is_visited() {
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let at = top.child(Name::stored("page"));
        let text = super::super::derive::pe_carrier(&[1, 2]);
        let mut v = Panics::new(false, |n| {
            n.path.render(PathStyle::Last) == "base64-payload-1"
        });
        let got = Cx::new(&w, &mut budget(16)).derived(
            &at,
            0,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut v,
        );
        assert_eq!(v.last_names(), ["base64-payload-1", "base64-payload-2"]);
        assert!(matches!(got.ended, Ended::Complete));
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!(
            (why.kind, why.at.as_str()),
            (ReasonKind::Panic, "page/base64-payload-1")
        );
    }

    /// And for a file rejoined from the parts of a set.
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
    fn a_panic_in_a_visitor_at_a_rejoined_file_is_a_reason_there() {
        let w = walk(100, None, true);
        let mut v = Panics::new(false, |n| matches!(n.origin, Origin::Joined { .. }));
        let got = members_of_with(
            &w,
            named(&[("x.7z.001", b"ab"), ("x.7z.002", b"cd")]),
            &mut v,
        );
        assert_eq!(v.last_names(), ["x.7z.001", "x.7z.002", "x.7z"]);
        assert!(matches!(got.ended, Ended::Complete));
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!((why.kind, why.at.as_str()), (ReasonKind::Panic, "x.7z"));
    }

    /// A spill that panics when a file is asked for.
    struct PanickingSpill;

    impl crate::spill::Spill for PanickingSpill {
        fn create(&self) -> Result<Box<dyn crate::spill::SpillWriter>, String> {
            panic!("the host's spill panicked");
        }
    }

    /// Taking a member runs the host's code (its spill): a panic there is a
    /// reason at that member, not the container's decoder panicking.
    #[test]
    #[cfg_attr(target_family = "wasm", ignore = "a panic aborts under WASI")]
    fn a_panic_of_the_host_taking_a_member_is_a_reason_at_that_member() {
        let w = walk(3, Some(&PanickingSpill), true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(&meta("small"), Some(Member::Bytes(b"ab".to_vec())), budget);
                let mut long = Cursor::new(b"cdefghij".to_vec());
                visit(&meta("long"), Some(Member::Stream(&mut long)), budget);
                visit(&meta("after"), Some(Member::Bytes(b"kl".to_vec())), budget);
                Ok(None)
            },
        );
        assert_eq!(paths(&script), ["root!small", "root!after"]);
        assert!(matches!(got.ended, Ended::Complete));
        let why = got.reasons.unscannable.expect("a reason");
        assert_eq!((why.kind, why.at.as_str()), (ReasonKind::Panic, "long"));
    }

    /// [`run`] with second readings on.
    #[cfg(feature = "tar")]
    fn run_second(bytes: &[u8], max_recursion: u32, v: &mut Script) -> Descent<String> {
        let mut w = walk(1 << 20, None, true);
        w.second_readings = true;
        let walker = Walker::new(w, &Typing::WALK);
        let mut b = budget(max_recursion);
        walker.run(
            Root {
                name: "top.tar",
                source: &bytes,
            },
            &mut b,
            v,
        )
    }

    #[cfg(any(
        feature = "base64scan",
        feature = "iso",
        all(feature = "tar", feature = "zip")
    ))]
    fn seen_with_origin(script: &Script) -> Vec<(&str, u32, Origin)> {
        script
            .seen
            .iter()
            .map(|r| (r.path.as_str(), r.depth, r.origin.clone()))
            .collect()
    }

    #[cfg(all(feature = "tar", feature = "zip"))]
    #[test]
    fn a_zip_appended_to_a_container_is_read_after_its_members_when_second_readings_are_on() {
        let mut bytes = tar_of(&[("a.txt", b"hello")]);
        bytes.extend_from_slice(&super::super::derive::stored_zip("z.txt", b"inside"));
        let mut off = Script {
            descend: true,
            ..Script::default()
        };
        run(&bytes, 16, &mut off, &Typing::WALK);
        assert_eq!(paths(&off), ["top.tar", "top.tar!a.txt"]);

        let mut on = Script {
            descend: true,
            ..Script::default()
        };
        let got = run_second(&bytes, 16, &mut on);
        // The second reading has no name: it is where the container is, one
        // level down, and its members are below it.
        assert_eq!(
            seen_with_origin(&on),
            vec![
                ("top.tar", 0, Origin::Root),
                ("top.tar!a.txt", 1, Origin::Member),
                ("top.tar", 1, Origin::Second(SecondReading::AppendedZip)),
                ("top.tar!z.txt", 2, Origin::Member),
            ]
        );
        assert_eq!(on.seen[3].content.as_deref(), Some(&b"inside"[..]));
        assert!(matches!(got.ended, Ended::Complete));
        assert!(got.reasons.is_empty());
    }

    #[cfg(all(feature = "tar", feature = "zip", feature = "iso"))]
    #[test]
    fn a_second_reading_is_not_read_a_second_way_again() {
        // A tar that is also an ISO image, with a ZIP appended.
        let mut big = vec![0u8; 40000];
        big[32769 - 512..][..5].copy_from_slice(b"CD001");
        let mut bytes = tar_of(&[("big.bin", &big)]);
        bytes.extend_from_slice(&super::super::derive::stored_zip("z.txt", b"inside"));
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        run_second(&bytes, 16, &mut script);
        let iso = Origin::Second(SecondReading::AlsoReadsAs(Format::Iso));
        assert!(script.seen.iter().any(|r| r.origin == iso));
        // The ZIP is read once, from the container, not again from the ISO.
        let zips = paths(&script)
            .into_iter()
            .filter(|p| *p == "top.tar!z.txt")
            .count();
        assert_eq!(zips, 1, "{:?}", paths(&script));
    }

    #[cfg(all(feature = "tar", feature = "zip"))]
    #[test]
    fn a_zip_is_not_read_as_a_zip_appended_to_itself() {
        // Two ZIPs one after the other: the reader opens the last one, and
        // the one appended to the first is that same ZIP.
        let mut bytes = super::super::derive::stored_zip("a.txt", b"first");
        bytes.extend_from_slice(&super::super::derive::stored_zip("b.txt", b"second"));
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        run_second(&bytes, 16, &mut script);
        assert!(
            script
                .seen
                .iter()
                .all(|r| r.origin != Origin::Second(SecondReading::AppendedZip)),
            "{:?}",
            seen_with_origin(&script)
        );
    }

    #[cfg(all(feature = "tar", feature = "zip"))]
    #[test]
    fn a_container_at_the_depth_limit_is_not_read_a_second_way_and_one_below_it_is() {
        let mut bytes = tar_of(&[("a.txt", b"hello")]);
        bytes.extend_from_slice(&super::super::derive::stored_zip("z.txt", b"inside"));
        // The root is not opened, so there is one reason, not two.
        let mut at = Script {
            descend: true,
            ..Script::default()
        };
        let got = run_second(&bytes, 0, &mut at);
        assert_eq!(paths(&at), ["top.tar"]);
        assert_eq!(got.reasons.total, 1);
        // Opened, with room for the second reading but not for its members.
        let mut below = Script {
            descend: true,
            ..Script::default()
        };
        let got = run_second(&bytes, 1, &mut below);
        assert_eq!(paths(&below), ["top.tar", "top.tar!a.txt", "top.tar"]);
        let why = got.reasons.limits.expect("the zip is not opened");
        assert_eq!(why.text, "recursion depth exceeds 1");
        assert_eq!(got.reasons.total, 1);
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn what_is_derived_at_the_depth_limit_is_a_limit_and_nothing_derived_is_not() {
        use super::super::derive::pe_carrier;
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let at = top.child(Name::stored("page"));
        let text = pe_carrier(&[1]);
        // Limit 2: a payload of an object at depth 1 is at depth 2 and is
        // entered; one of an object at depth 2 is not.
        let mut script = Script::default();
        let mut b = budget(2);
        let got = Cx::new(&w, &mut b).derived(
            &at,
            1,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert!(matches!(got.ended, Ended::Complete));
        assert_eq!(
            seen_with_origin(&script),
            vec![(
                "top!page!base64-payload-1",
                2,
                Origin::Encoded(EncodedKind::Base64Run, 1)
            )]
        );
        assert_eq!(
            script.seen[0].content.as_deref(),
            Some(&super::super::derive::pe_of(1)[..])
        );
        let mut script = Script::default();
        let mut b = budget(2);
        let got = Cx::new(&w, &mut b).derived(
            &at,
            2,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert!(script.seen.is_empty());
        match got.ended {
            Ended::Limit(hit) => {
                assert_eq!(hit.kind, LimitKind::MaxRecursion);
                assert_eq!(hit.reason, "recursion depth exceeds 2");
            }
            other => panic!("{other:?}"),
        }
        // Nothing to derive at the limit is nothing to report.
        let mut script = Script::default();
        let mut b = budget(2);
        let got = Cx::new(&w, &mut b).derived(
            &at,
            2,
            &b"just text".as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert!(matches!(got.ended, Ended::Complete));
        assert!(got.reasons.is_empty());
    }

    /// A kind cut short before it found anything still says so.
    #[cfg(feature = "base64scan")]
    #[test]
    fn a_kind_cut_short_with_nothing_found_is_a_reason() {
        use super::super::derive::pe_carrier;
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let mut script = Script::default();
        let mut b = Budget::new(Limits {
            max_base64_runs: 0,
            ..Limits::default()
        });
        let got = Cx::new(&w, &mut b).derived(
            &top,
            0,
            &pe_carrier(&[1]).as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert!(script.seen.is_empty());
        assert!(matches!(got.ended, Ended::Complete));
        let why = got.reasons.limits.expect("the cut is a reason");
        assert_eq!(why.kind, ReasonKind::Limit(LimitKind::MaxFiles));
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn derived_children_are_charged_to_the_scan_budget_and_a_refusal_ends_the_kind() {
        use super::super::derive::pe_carrier;
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let text = pe_carrier(&[1, 2, 3]);
        let mut script = Script::default();
        let mut b = Budget::new(Limits {
            max_scanned_bytes: 1500,
            ..Limits::default()
        });
        let got = Cx::new(&w, &mut b).derived(
            &top,
            0,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        // The first payload (1200 bytes) is taken, the second is not, and the
        // third is not looked at.
        assert_eq!(script.seen.len(), 1);
        match got.ended {
            Ended::Limit(hit) => assert_eq!(hit.kind, LimitKind::MaxScanSize),
            other => panic!("{other:?}"),
        }
        assert_eq!(b.scanned, 2400);
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn a_visitor_that_stops_at_a_derived_child_ends_the_kind_there() {
        use super::super::derive::pe_carrier;
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let text = pe_carrier(&[1, 2]);
        let mut script = Script {
            stop_at: Some("base64-payload-1"),
            ..Script::default()
        };
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).derived(
            &top,
            0,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert_eq!(script.seen.len(), 1);
        assert!(matches!(got.ended, Ended::Stopped(ref s) if s == "base64-payload-1"));
    }

    #[cfg(feature = "base64scan")]
    #[test]
    fn more_payloads_than_are_decoded_are_a_reason_of_the_object() {
        use super::super::derive::pe_carrier;
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let text = pe_carrier(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut script = Script::default();
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).derived(
            &top,
            0,
            &text.as_slice(),
            DeriveKind::Base64Runs,
            &mut script,
        );
        assert_eq!(script.seen.len(), 8);
        assert!(matches!(got.ended, Ended::Complete));
        let why = got.reasons.limits.expect("the cap is a reason");
        assert_eq!(why.kind, ReasonKind::Limit(LimitKind::MaxFiles));
        assert_eq!(got.reasons.total, 1);
    }

    #[cfg(feature = "iso")]
    #[test]
    fn the_object_read_as_another_format_is_visited_where_it_is_and_not_charged() {
        let w = walk(100, None, true);
        let top = Path::root(Name::stored("top"));
        let at = top.child(Name::stored("disk"));
        let mut data = vec![0u8; 32769 + 8];
        data[32769..32774].copy_from_slice(b"CD001");
        let mut script = Script::default();
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).derived(
            &at,
            1,
            &data,
            DeriveKind::AlsoReadsAs(Format::Tar),
            &mut script,
        );
        assert!(matches!(got.ended, Ended::Complete));
        assert_eq!(
            seen_with_origin(&script),
            vec![(
                "top!disk",
                2,
                Origin::Second(SecondReading::AlsoReadsAs(Format::Iso))
            )]
        );
        assert_eq!(script.seen[0].content.as_deref(), Some(&data[..]));
        assert_eq!(b.scanned, 0);
    }

    #[test]
    fn a_reason_the_walk_finds_and_the_node_does_not_show_is_told_as_it_is_found() {
        // A set missing a part: told at the part that is missing.
        let w = walk(3, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(
                    &meta("x.7z.001"),
                    Some(Member::Bytes(b"ab".to_vec())),
                    budget,
                );
                let mut long = Cursor::new(b"cdefghij".to_vec());
                visit(&meta("x.7z.002"), Some(Member::Stream(&mut long)), budget);
                Ok(None)
            },
        );
        assert_eq!(
            script.told,
            [(
                "root!x.7z.001".to_string(),
                ReasonKind::SetIncomplete,
                LOST.to_string()
            )]
        );
        // A body read in place that fails when it is read: told after it was
        // read.
        let container = Broken(Cell::new(false));
        let mut m = meta("m");
        m.range = Some((0, 60));
        let mut script = Script::default();
        let w = walk(3, None, true);
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &container,
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                let mut stream = Cursor::new(vec![0u8; 60]);
                visit(&m, Some(Member::Stream(&mut stream)), budget);
                Ok(None)
            },
        );
        assert_eq!(script.told.len(), 1);
        assert_eq!(
            (script.told[0].0.as_str(), script.told[0].1),
            ("root!m", ReasonKind::ReadFailed)
        );
        assert_eq!(got.reasons.total, 1);
    }

    #[test]
    fn how_a_member_was_taken_is_not_told_for_the_node_shows_it() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                // Nothing decoded before an error that hides content.
                let mut failing = Failing {
                    data: Cursor::new(Vec::new()),
                    err: bad_block,
                };
                visit(&meta("m"), Some(Member::Stream(&mut failing)), budget);
                Ok(None)
            },
        );
        assert!(script.told.is_empty(), "{:?}", script.told);
        // It is in the reasons of the container, and on the node.
        assert_eq!(got.reasons.total, 1);
        assert!(matches!(script.seen[0].end, End::Damaged(_)));
        assert_eq!(script.seen[0].content, None);
    }

    #[test]
    fn a_bound_reached_under_a_container_is_told_at_the_container() {
        let w = walk(100, None, true);
        let mut script = Script::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut script,
            |_: &mut Budget, _: Visit<'_, ()>| {
                Err(LimitHit::of_kind(
                    LimitKind::MaxFiles,
                    "members > 1".to_string(),
                ))
            },
        );
        // The walk of one container ends with the limit; it is the driver that
        // tells it, for the container it opened.
        assert!(matches!(got.ended, Ended::Limit(_)));
        assert!(script.told.is_empty());
    }

    #[test]
    fn the_driver_tells_the_bound_a_container_ended_with_where_it_is() {
        // A tar whose header checksum is wrong ends its walk with the reader's
        // own error, at the container.
        #[cfg(feature = "tar")]
        {
            let mut broken = tar_of(&[("a.txt", b"x")]);
            broken[148] = b'9';
            let outer = tar_of(&[("broken.tar", &broken), ("b.txt", b"y")]);
            let mut script = Script {
                descend: true,
                ..Script::default()
            };
            let got = run(&outer, 16, &mut script, &Typing::WALK);
            assert_eq!(script.told.len(), 1, "{:?}", script.told);
            assert_eq!(script.told[0].0, "top.tar!broken.tar");
            assert_eq!(script.told[0].1, ReasonKind::Damaged);
            assert_eq!(got.reasons.total, 1);
            // The node after it was visited.
            assert!(paths(&script).contains(&"top.tar!b.txt"));
        }
    }

    /// A typer that says every `.tar` is a tar, and counts how often it is asked.
    struct CountingTyper(Cell<u32>);

    impl Typer for CountingTyper {
        fn type_of(&self, node: &Node<'_>) -> Typed {
            self.0.set(self.0.get() + 1);
            match node.path.render(PathStyle::Last).ends_with(".tar") {
                true => Typed::Container(Format::Tar),
                false => Typed::Plain,
            }
        }
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_node_is_typed_once_however_often_it_is_asked_what_it_is() {
        struct Asks(Vec<String>);
        impl Visitor<String> for Asks {
            fn visit(&mut self, node: &Node<'_>, _: &mut Cx<'_>, _: &mut Reasons) -> Flow<String> {
                let first = matches!(node.format(), Typed::Container(_));
                let again = matches!(node.format(), Typed::Container(_));
                assert_eq!(first, again);
                self.0.push(node.path.render(PathStyle::Last));
                Flow::Descend
            }
        }
        let outer = tar_of(&[("in.tar", &tar_of(&[("a.txt", b"hi")])), ("b.txt", b"yo")]);
        let typer = CountingTyper(Cell::new(0));
        let walker = Walker::new(walk(1 << 20, None, true), &typer);
        let mut v = Asks(Vec::new());
        walker.run(
            Root {
                name: "top.tar",
                source: &outer.as_slice(),
            },
            &mut budget(16),
            &mut v,
        );
        assert_eq!(v.0, ["top.tar", "in.tar", "a.txt", "b.txt"]);
        // top.tar, in.tar, a.txt and b.txt: once each, though each was asked
        // twice by the visitor and once more by the driver.
        assert_eq!(typer.0.get(), 4);
    }

    #[test]
    fn a_node_is_plain_without_a_typer_or_without_bytes() {
        let bytes = b"bytes".as_slice();
        let node = Node::of(Path::root(Name::stored("n.tar")), 0, Origin::Root, &bytes);
        assert!(matches!(node.format(), Typed::Plain));
        // Read as the format it was found to be, whatever a typer says.
        let again = Node::of(
            Path::root(Name::stored("x.bin")),
            1,
            Origin::Second(SecondReading::AlsoReadsAs(Format::Iso)),
            &bytes,
        );
        assert!(matches!(again.format(), Typed::Container(Format::Iso)));
        let typer = CountingTyper(Cell::new(0));
        let empty = b"".as_slice();
        let mut none = Node::of(Path::root(Name::stored("n.tar")), 0, Origin::Root, &empty)
            .typed_by(Some(&typer), 100);
        none.content = Content::None;
        assert!(matches!(none.format(), Typed::Plain));
        assert_eq!(typer.0.get(), 0, "no bytes to look at, no question");
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_container_is_left_after_its_members_and_before_its_second_reading() {
        let mut bytes = tar_of(&[("a.txt", b"hello"), ("b.txt", b"world")]);
        bytes.extend_from_slice(b"junk");
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        run_second(&bytes, 16, &mut script);
        // Told once, with the members it had, after them in the order of the walk.
        assert_eq!(script.left, [("top.tar".to_string(), 2)]);
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        run(
            &tar_of(&[("a.txt", b"hello")]),
            16,
            &mut script,
            &Typing::WALK,
        );
        assert_eq!(script.left, [("top.tar".to_string(), 1)]);
    }

    #[cfg(all(feature = "tar", feature = "zip"))]
    #[test]
    fn a_container_is_left_before_what_is_read_from_it_a_second_way() {
        struct Order(Vec<String>);
        impl Visitor<String> for Order {
            fn visit(&mut self, node: &Node<'_>, _: &mut Cx<'_>, _: &mut Reasons) -> Flow<String> {
                self.0.push(format!("visit {:?}", node.origin));
                Flow::Descend
            }

            fn leave(
                &mut self,
                node: &Node<'_>,
                _: u64,
                _: &mut Cx<'_>,
                _: &mut Reasons,
            ) -> Flow<String> {
                self.0.push(format!("leave {:?}", node.origin));
                Flow::Leaf
            }
        }
        let mut bytes = tar_of(&[("a.txt", b"hello")]);
        bytes.extend_from_slice(&super::super::derive::stored_zip("z.txt", b"inside"));
        let mut w = walk(1 << 20, None, true);
        w.second_readings = true;
        let walker = Walker::new(w, &Typing::WALK);
        let mut v = Order(Vec::new());
        walker.run(
            Root {
                name: "top.tar",
                source: &bytes.as_slice(),
            },
            &mut budget(16),
            &mut v,
        );
        assert_eq!(
            v.0,
            [
                "visit Root",
                "visit Member",
                "leave Root",
                "visit Second(AppendedZip)",
                "visit Member",
                "leave Second(AppendedZip)",
            ]
        );
    }

    #[cfg(feature = "tar")]
    #[test]
    fn a_container_the_depth_limit_did_not_open_is_not_left_and_a_stop_there_ends_the_walk() {
        let outer = tar_of(&[("in.tar", &tar_of(&[("a.txt", b"hi")]))]);
        let mut script = Script {
            descend: true,
            ..Script::default()
        };
        // Limit 1: the root is opened, in.tar is at the limit and is not.
        run(&outer, 1, &mut script, &Typing::WALK);
        assert_eq!(script.left, [("top.tar".to_string(), 1)]);
        let mut script = Script {
            descend: true,
            leave_stop: Some("in.tar"),
            ..Script::default()
        };
        let outer = tar_of(&[("in.tar", &tar_of(&[("a.txt", b"hi")])), ("c.txt", b"x")]);
        let got = run(&outer, 16, &mut script, &Typing::WALK);
        assert!(matches!(got.ended, Ended::Stopped(ref s) if s == "in.tar"));
        assert!(!paths(&script).contains(&"top.tar!c.txt"));
    }

    /// A stream node's head and rest, and what it was typed as.
    #[derive(Default)]
    struct Streams {
        seen: Vec<(String, Vec<u8>, Vec<u8>, String)>,
    }

    impl Visitor<String> for Streams {
        fn visit(&mut self, node: &Node<'_>, _: &mut Cx<'_>, _: &mut Reasons) -> Flow<String> {
            if let Content::Stream(cell) = &node.content {
                let head = cell.head().to_vec();
                let mut rest = Vec::new();
                cell.take().unwrap().read_to_end(&mut rest).unwrap();
                // The stream is read from its start: the head, then the rest.
                assert_eq!(&rest[..head.len()], &head[..]);
                rest.drain(..head.len());
                let kind = match node.format() {
                    Typed::Container(f) => format!("{f:?}"),
                    Typed::Plain => "plain".to_string(),
                    Typed::Unchecked(r) => format!("unchecked {:?}", r.kind),
                };
                self.seen
                    .push((node.path.render(PathStyle::Last), head, rest, kind));
            }
            Flow::Descend
        }
    }

    #[test]
    fn a_streamed_member_is_a_node_with_its_start_and_its_rest() {
        let mut w = walk(8, None, true);
        w.hold.large = Large::StreamLeaves;
        let mut v = Streams::default();
        let root = Path::root(Name::stored("root"));
        let mut b = budget(16);
        let long = vec![b'z'; crate::DETECT_HEAD + 100];
        let short = b"text of a hundred bytes ......".repeat(4);
        let got = Cx::new(&w, &mut b).members_with(
            &root,
            0,
            &b"container".as_slice(),
            None,
            &mut v,
            |budget: &mut Budget, visit: Visit<'_, ()>| {
                visit(&meta("fits"), Some(Member::Bytes(b"ab".to_vec())), budget);
                let mut a = Cursor::new(short.clone());
                visit(&meta("short"), Some(Member::Stream(&mut a)), budget);
                let mut b = Cursor::new(long.clone());
                visit(&meta("long"), Some(Member::Stream(&mut b)), budget);
                Ok(None)
            },
        );
        assert!(matches!(got.ended, Ended::Complete));
        // The member held is not a stream; the others are, with their start
        // and the rest, and the node is typed as what the start could say.
        assert_eq!(v.seen.len(), 2);
        assert_eq!(v.seen[0].0, "short");
        assert_eq!((v.seen[0].1.as_slice(), v.seen[0].2.len()), (&short[..], 0));
        assert_eq!(v.seen[0].3, "plain");
        assert_eq!(v.seen[1].0, "long");
        assert_eq!(v.seen[1].1.len(), crate::DETECT_HEAD);
        assert_eq!(v.seen[1].2.len(), 100);
        assert_eq!(v.seen[1].3, "unchecked NotChecked");
        assert_eq!(got.members, 3);
    }

    #[test]
    fn an_executable_over_what_is_held_is_not_checked_for_a_packer_and_says_so() {
        use crate::source::BlockCache;
        let mut exe = b"MZ".to_vec();
        exe.resize(500, 0);
        let cache = BlockCache::with_sizes(Cursor::new(exe.clone()), 64, 256).unwrap();
        let node = Node::of(Path::root(Name::stored("a.exe")), 0, Origin::Root, &cache)
            .typed_by(Some(&Typing::WALK), 100);
        match node.format() {
            Typed::Unchecked(why) => {
                assert_eq!(why.kind, ReasonKind::NotChecked);
                assert_eq!(
                    why.text,
                    "an executable over the 100-byte limit: whether it is packed was not checked"
                );
            }
            _ => panic!("not unchecked"),
        }
        // Held, it is looked at, and an unpacked executable is plain.
        let held = Node::of(Path::root(Name::stored("a.exe")), 0, Origin::Root, &exe)
            .typed_by(Some(&Typing::WALK), 100);
        assert!(matches!(held.format(), Typed::Plain));
        // The same, for a consumer that types one object by itself.
        assert!(matches!(
            type_object(&Typing::WALK, &cache, 100),
            Typed::Unchecked(_)
        ));
        assert!(matches!(
            type_object(&Typing::WALK, &exe, 100),
            Typed::Plain
        ));
        assert!(matches!(
            type_object(&Typing::WALK, &cache, 1000),
            Typed::Plain
        ));
        // Over what is held but not an executable: nothing to check.
        let text = vec![b'a'; 500];
        let cache = BlockCache::with_sizes(Cursor::new(text), 64, 256).unwrap();
        let plain = Node::of(Path::root(Name::stored("a.txt")), 0, Origin::Root, &cache)
            .typed_by(Some(&Typing::WALK), 100);
        assert!(matches!(plain.format(), Typed::Plain));
    }
}
