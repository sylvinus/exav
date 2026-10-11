//! gzip: one member, every gzip member of the file decoded in turn as it is
//! read.
use std::io::{BufReader, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{stream_single, Visit};
use crate::{Budget, LimitHit};

pub(crate) fn walk<T>(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<T>,
) -> Result<Option<T>, LimitHit> {
    stream_single(&mut Reader::new(src), budget, visit, "gzip-content", |r| {
        Ok(Box::new(crate::inflate::Gunzip::new(BufReader::new(r))) as Box<dyn Read + '_>)
    })
}
