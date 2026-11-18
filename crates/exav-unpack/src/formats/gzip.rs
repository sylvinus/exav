//! gzip: one member, every gzip member of the file decoded in turn as it is
//! read.
use std::io::{BufReader, Read};

use crate::source::{ByteSource, Reader};
use crate::stream::{Visit, stream_single};
use crate::{Budget, LimitHit};

pub(crate) fn walk(
    src: &dyn ByteSource,
    budget: &mut Budget,
    visit: Visit<()>,
) -> Result<Option<()>, LimitHit> {
    stream_single(
        &mut Reader::new(src),
        budget,
        visit,
        "gzip-content",
        &mut |r| Ok(Box::new(crate::inflate::Gunzip::new(BufReader::new(r))) as Box<dyn Read + '_>),
    )
}
