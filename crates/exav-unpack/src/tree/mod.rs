//! The walk of nested containers: what it hands to its consumers (names and
//! paths, the reasons something was not fully examined, how a node's content
//! came to be and ended, how a member's bytes are taken from its reader, the
//! split sets rejoined from them) and the recursion itself.
//!
//! [`crate::walk`] reads one level of a container. [`Cx::members`] hands each
//! member of a container to a [`Visitor`], and [`Cx::child`] enters an object
//! found inside another; a consumer that scans in an order of its own (the
//! scanner) calls them where it chooses. [`Walker::run`] goes down by itself,
//! for a consumer that wants every node. [`derive()`] finds the objects inside
//! an object that are not its members (a ZIP appended to it, the payloads
//! encoded in its text).

mod derive;
mod engine;
mod intake;
mod name;
mod node;
mod reason;
mod sets;
mod typing;

pub use derive::{DeriveKind, Derived, DerivedBody, DerivedChild, derive};
pub use engine::{
    Cx, Descent, Ended, Flow, Node, Refused, Root, Typed, Typer, Visitor, Walk, Walker, type_object,
};
pub use intake::{Body, Declined, Hold, Intake, Large, intake, range_cut};
pub(crate) use name::quoted;
pub use name::{Name, NameKind, Path, PathStyle, shown_text, unsafe_to_show};
pub use node::{Content, EncodedKind, End, Origin, SecondReading, StreamCell};
pub use reason::{Reason, ReasonClass, ReasonKind, Reasons};
pub use sets::{Rejoined, Sets};
pub use typing::{
    Declared, EXECUTABLE_CONTAINERS, MAGIC_DISPATCH_ONLY, NOT_OPENED_BY_CLAMAV, Observed, Typing,
    clamav_opens_szdd,
};
