//! [`SansIo`], the reader exav puts around `lzma_rust2`'s sans-I/O LZMA and
//! LZMA2 decoders, for every format that carries one of them.
use std::io::{self, Read};

use lzma_rust2::{Action, Lzma2Stream, LzmaStream, Status, StreamResult};

/// A sans-I/O decoder of `lzma_rust2`: they share one shape.
pub(crate) trait Process {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> lzma_rust2::Result<StreamResult>;

    /// Bytes handed to the caller so far, those of a call that failed
    /// included.
    fn total_out(&self) -> u64;
}

impl Process for LzmaStream {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> lzma_rust2::Result<StreamResult> {
        LzmaStream::process(self, input, output, action)
    }

    fn total_out(&self) -> u64 {
        LzmaStream::total_out(self)
    }
}

impl Process for Lzma2Stream {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        action: Action,
    ) -> lzma_rust2::Result<StreamResult> {
        Lzma2Stream::process(self, input, output, action)
    }

    fn total_out(&self) -> u64 {
        Lzma2Stream::total_out(self)
    }
}

/// Input bytes per decoder call. A call that meets damage loses what it
/// decoded and had not yet handed over, which is at most what this much
/// input decodes to.
const STEP: usize = 1024;

/// A sans-I/O decoder read as it decodes. `lzma_rust2`'s own readers drop
/// the output of a `read` that meets an error, which for a stream cut short
/// is everything decoded since the previous `read`. Here a stream that runs
/// out of input is an `UnexpectedEof` error once the bytes decoded before it
/// are handed over; only the symbols of its last few bytes, which need input
/// that is not there, are lost. Damage is an error once the bytes decoded
/// before it are handed over, but for those of the last [`STEP`] bytes of
/// input.
pub(crate) struct SansIo<R, S> {
    inner: R,
    stream: S,
    input: Box<[u8]>,
    start: usize,
    end: usize,
    input_ended: bool,
    /// The input is all in, and decoding it as if more might come made
    /// nothing more: decode as at the end of the stream.
    finishing: bool,
    done: bool,
    /// The error that ended a call whose output was handed over first.
    failed: Option<io::Error>,
}

impl<R: Read, S: Process> SansIo<R, S> {
    pub(crate) fn new(inner: R, stream: S) -> Self {
        SansIo {
            inner,
            stream,
            input: vec![0; 4096].into_boxed_slice(),
            start: 0,
            end: 0,
            input_ended: false,
            finishing: false,
            done: false,
            failed: None,
        }
    }

    /// The decoder, for what it says once its stream has ended.
    #[cfg_attr(not(feature = "lzip"), allow(dead_code))]
    pub(crate) fn stream(&self) -> &S {
        &self.stream
    }
}

impl<R: Read, S: Process> Read for SansIo<R, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        if buf.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.start == self.end && !self.input_ended {
                self.start = 0;
                self.end = loop {
                    match self.inner.read(&mut self.input) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        r => break r?,
                    }
                };
                self.input_ended = self.end == 0;
            }
            let action = if self.finishing {
                Action::Finish
            } else {
                Action::Run
            };
            let step = self.end.min(self.start + STEP);
            let before = self.stream.total_out();
            let r = match self
                .stream
                .process(&self.input[self.start..step], buf, action)
            {
                Ok(r) => r,
                Err(e) => {
                    self.done = true;
                    let given = (self.stream.total_out() - before) as usize;
                    if given == 0 {
                        return Err(e);
                    }
                    self.failed = Some(e);
                    return Ok(given);
                }
            };
            self.start += r.bytes_consumed;
            if r.status == Status::StreamEnd {
                self.done = true;
                return Ok(r.bytes_produced);
            }
            if r.bytes_produced > 0 {
                return Ok(r.bytes_produced);
            }
            if self.start < self.end || !self.input_ended {
                // A call takes all the input it is given unless the output
                // fills or the stream ends, so input left here is a stall.
                if r.bytes_consumed == 0 && self.start < self.end {
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "lzma: decoder made no progress",
                    ));
                }
                continue;
            }
            if self.finishing {
                self.done = true;
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "lzma: stream cut short",
                ));
            }
            self.finishing = true;
        }
    }
}
