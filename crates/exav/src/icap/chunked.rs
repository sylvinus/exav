//! Chunked transfer decoding for encapsulated bodies.
//!
//! ICAP always chunk-encodes the body it carries, whatever the original HTTP
//! message used. The decoder here is deliberately its own thing rather than a
//! borrowed HTTP one, because ICAP adds a terminator HTTP does not have: inside
//! a preview, `0; ieof` means "that last chunk was the entire object", and a
//! decoder that treats it as a plain end-of-body cannot tell a complete small
//! object from the head of a large one.
//!
//! Every limit below exists because the sender is not trusted: a chunk header
//! is read into a bounded buffer, a chunk length is checked against the body
//! ceiling *before* anything is allocated for it, and the trailer section is
//! bounded the same way as the head.

use std::io::{self, BufRead, Read, Write};

use crate::daemon::StreamPayload;
use crate::spill::{self, SpillError, SpillFile};

/// A decoded body on its way to the scanner: held in RAM while it is small,
/// spilled to a temp file past [`STREAM_SPILL_THRESHOLD`].
///
/// The same policy, and the same [`StreamPayload`], as the daemon's stream
/// verbs. An object arriving over ICAP is therefore buffered exactly the way the
/// same object arriving over `INSTREAM` is, and gets the same seekable
/// container-aware scan — a ZIP's central directory is at its end, so a scan
/// that cannot seek is a scan that cannot open the archive.
///
/// What this buys the listener is a memory bound that does not depend on what
/// clients send: a connection costs the spill threshold, not the size of the
/// object on it. Without that, the only way to bound memory is to refuse large
/// objects, which turns a resource decision into a verdict.
pub(super) struct Body {
    /// The head, up to the configured threshold. Kept after a spill as well,
    /// because the preview scan reads it and it is bounded either way.
    ram: Vec<u8>,
    /// Present once the body outgrew RAM; holds the whole body, head included.
    spill: Option<SpillFile>,
    len: u64,
}

impl Body {
    pub(super) fn new() -> Self {
        Self {
            ram: Vec::new(),
            spill: None,
            len: 0,
        }
    }

    /// Bytes accumulated so far.
    pub(super) fn len(&self) -> u64 {
        self.len
    }

    /// The head that is in RAM, for the preview scan. Everything when the body
    /// never spilled, which is every preview worth the name.
    pub(super) fn head(&self) -> &[u8] {
        &self.ram
    }

    /// Append decoded bytes. The spill budgets are enforced by [`SpillFile`].
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<(), SpillError> {
        if let Some(tmp) = self.spill.as_mut() {
            tmp.write_all(bytes)?;
            self.len += bytes.len() as u64;
            return Ok(());
        }

        let room = (spill::config().threshold - self.ram.len() as u64) as usize;
        if bytes.len() <= room {
            self.ram.extend_from_slice(bytes);
            self.len += bytes.len() as u64;
            return Ok(());
        }

        // Crossing the threshold: fill RAM to the brim, then move the whole body
        // — head included, so the file alone is the object — to disk.
        let (fits, rest) = bytes.split_at(room);
        self.ram.extend_from_slice(fits);
        self.len += fits.len() as u64;
        let mut tmp = SpillFile::create()?;
        tmp.write_all(&self.ram)?;
        self.spill = Some(tmp);
        self.write(rest)
    }

    /// Hand the body over as something the scanner can seek in.
    pub(super) fn finish(self) -> io::Result<StreamPayload> {
        match self.spill {
            None => Ok(StreamPayload::Mem(self.ram)),
            Some(tmp) => {
                let len = tmp.len()?;
                Ok(StreamPayload::Disk(tmp, len))
            }
        }
    }
}

/// How a body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyEnd {
    /// A plain `0` last-chunk. In a preview this means more of the object
    /// exists and the client is waiting for `100 Continue`.
    Eof,
    /// A `0; ieof` last-chunk: the preview *was* the whole object, so there is
    /// nothing further to ask for.
    Ieof,
}

/// Why a body could not be decoded.
#[derive(Debug)]
pub(super) enum BodyError {
    /// The chunk framing is not valid.
    Malformed(&'static str),
    /// The transport or the temp filesystem failed.
    Io(io::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed chunked body: {m}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// What a decode produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BodyOutcome {
    /// How the body ended.
    pub(super) end: BodyEnd,
    /// The body was larger than `limit`, so the buffer holds only its head and
    /// the rest was read and thrown away.
    pub(super) over_limit: bool,
    /// The discard hit its own ceiling before the body ended, so the stream is
    /// still somewhere inside the body and the connection cannot be reused.
    pub(super) abandoned: bool,
    /// A spill budget refused the object part-way through, and this says which.
    ///
    /// An outcome rather than an error, because it is one: the decode carries on
    /// discarding so the stream still reaches the next request boundary, exactly
    /// as it does for a body past its size limit. Aborting instead would leave
    /// the client mid-send, and answering into a socket that still has unread
    /// bytes makes the kernel reset the connection — taking the verdict with it.
    pub(super) rejected: Option<String>,
}

impl std::error::Error for BodyError {}

impl From<io::Error> for BodyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Longest a chunk-size line (length plus extensions) may be.
const MAX_CHUNK_LINE: usize = 1024;

/// Most trailer lines accepted after the last chunk. A trailer section is
/// almost always empty; this bounds the one case where it is not.
const MAX_TRAILER_LINES: usize = 32;

/// Read one line, including its terminating newline, without buffering more
/// than `max` bytes.
///
/// `Ok(None)` means end of stream at a line boundary.
pub(super) fn read_line<R: BufRead>(r: &mut R, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let (found, consumed) = {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                return if out.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended mid-line",
                    ))
                };
            }
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    out.extend_from_slice(&buf[..=i]);
                    (true, i + 1)
                }
                None => {
                    out.extend_from_slice(buf);
                    (false, buf.len())
                }
            }
        };
        r.consume(consumed);
        if found {
            return Ok(Some(out));
        }
        if out.len() > max {
            return Err(io::Error::other("line exceeds the configured ceiling"));
        }
    }
}

/// Trim a line's trailing `\r\n` (or bare `\n`).
fn trim_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Decode a chunk-encoded body from `r`, appending to `out` but never keeping
/// more than `limit` bytes.
///
/// `limit` is `--max-input-bytes`, the same ceiling every other surface scans
/// under, and `None` — the default — means the object's size is not a reason to
/// stop. Memory does not depend on it: `out` spills past the shared threshold.
///
/// Past `limit` the decoding continues with the bytes thrown away, up to
/// `drain_limit` further bytes. Reading the tail of a body whose verdict is
/// already decided is what leaves the stream at a request boundary, and that is
/// what lets the verdict be *delivered*: answer and close with the client still
/// sending, and the close resets the connection with the answer still in
/// flight — the client learns nothing. It is worth a bounded amount of work and
/// no more, since an unbounded discard is an invitation to keep a thread busy
/// forever with reads that individually never time out.
///
/// A chunk length is compared against the limits *before* the chunk is read, so
/// a header claiming 4 GiB costs nothing.
pub(super) fn read_chunked_body<R: BufRead>(
    r: &mut R,
    limit: Option<u64>,
    drain_limit: u64,
    out: &mut Body,
) -> Result<BodyOutcome, BodyError> {
    let limit = limit.unwrap_or(u64::MAX);
    let mut over_limit = false;
    let mut drained: u64 = 0;
    let mut rejected: Option<String> = None;
    // One buffer reused for every discarded chunk: discarding exists so the
    // bytes are not held.
    let mut sink = [0u8; 16 * 1024];

    loop {
        let line = read_line(r, MAX_CHUNK_LINE)?
            .ok_or(BodyError::Malformed("stream ended before the last chunk"))?;
        let line = trim_eol(&line);
        let (size_text, ext) = match line.iter().position(|&b| b == b';') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => (line, &b""[..]),
        };
        let size = parse_chunk_size(size_text)?;

        if size == 0 {
            let end = if has_ieof(ext) {
                BodyEnd::Ieof
            } else {
                BodyEnd::Eof
            };
            read_trailer(r)?;
            return Ok(BodyOutcome {
                end,
                over_limit,
                abandoned: false,
                rejected,
            });
        }

        // Split the chunk at the ceiling: what fits is kept so it can still be
        // scanned, the rest is read and dropped. Keeping the head matters
        // because a detection in the part that fitted is a detection, and
        // refusing by size without looking would throw it away. Once a budget
        // has refused the object nothing more is kept at all.
        let mut keep = if rejected.is_some() {
            0
        } else {
            limit.saturating_sub(out.len()).min(size)
        };
        let mut discard = size - keep;
        // Charged before a byte is read, so a chunk header claiming 4 GiB is
        // answered by the header alone.
        let charge_drain = |n: u64, drained: &mut u64| -> bool {
            if n == 0 {
                return true;
            }
            *drained = drained.saturating_add(n);
            *drained <= drain_limit
        };
        if discard > 0 {
            over_limit = true;
            if !charge_drain(discard, &mut drained) {
                return Ok(BodyOutcome {
                    end: BodyEnd::Eof,
                    over_limit: true,
                    abandoned: true,
                    rejected,
                });
            }
        }

        // Copied through a fixed buffer rather than read whole: `keep` is
        // whatever a client put in a chunk header, so allocating it up front
        // would let one line of text ask for a gigabyte.
        while keep > 0 {
            let want = keep.min(sink.len() as u64) as usize;
            let got = r.read(&mut sink[..want])?;
            if got == 0 {
                return Err(BodyError::Malformed("chunk shorter than its declared size"));
            }
            match out.write(&sink[..got]) {
                Ok(()) => keep -= got as u64,
                Err(SpillError::Io(e)) => return Err(BodyError::Io(e)),
                // Nowhere to put the rest. Stop keeping, keep *reading*: the
                // verdict is decided but it still has to be delivered, and that
                // needs the stream to reach the next request boundary.
                Err(SpillError::Budget(reason)) => {
                    rejected = Some(reason);
                    over_limit = true;
                    let unread = keep - got as u64;
                    keep = 0;
                    discard += unread;
                    if !charge_drain(unread, &mut drained) {
                        return Ok(BodyOutcome {
                            end: BodyEnd::Eof,
                            over_limit: true,
                            abandoned: true,
                            rejected,
                        });
                    }
                }
            }
        }
        while discard > 0 {
            let want = discard.min(sink.len() as u64) as usize;
            let got = r.read(&mut sink[..want])?;
            if got == 0 {
                return Err(BodyError::Malformed("chunk shorter than its declared size"));
            }
            discard -= got as u64;
        }

        // The CRLF that closes the chunk data. Its absence means the length and
        // the data disagree, which is the framing confusion that lets one byte
        // stream be read two ways.
        let eol = read_line(r, 64)?.ok_or(BodyError::Malformed("chunk not terminated"))?;
        if !trim_eol(&eol).is_empty() {
            return Err(BodyError::Malformed(
                "chunk data overruns its declared size",
            ));
        }
    }
}

/// Parse a hexadecimal chunk length.
fn parse_chunk_size(text: &[u8]) -> Result<u64, BodyError> {
    let text = text.trim_ascii();
    if text.is_empty() {
        return Err(BodyError::Malformed("empty chunk size"));
    }
    // 16 hex digits is the whole of `u64`; anything longer is not a length a
    // client meant to send, and leading-zero padding past that is how a parser
    // gets talked into wrapping.
    if text.len() > 16 || !text.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(BodyError::Malformed("malformed chunk size"));
    }
    let text =
        std::str::from_utf8(text).map_err(|_| BodyError::Malformed("malformed chunk size"))?;
    u64::from_str_radix(text, 16).map_err(|_| BodyError::Malformed("malformed chunk size"))
}

/// Whether a chunk-extension list carries the `ieof` marker.
fn has_ieof(ext: &[u8]) -> bool {
    ext.split(|&b| b == b';')
        .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"ieof"))
}

/// Consume the trailer section that follows the last chunk, up to and including
/// its blank line.
fn read_trailer<R: BufRead>(r: &mut R) -> Result<(), BodyError> {
    for _ in 0..MAX_TRAILER_LINES {
        // A stream that stops right after `0\r\n` is a client that framed its
        // body badly, but the body itself is complete and already decoded;
        // treating that as a decode failure would throw away a good scan.
        let line = match read_line(r, MAX_CHUNK_LINE)? {
            Some(l) => l,
            None => return Ok(()),
        };
        if trim_eol(&line).is_empty() {
            return Ok(());
        }
    }
    Err(BodyError::Malformed("trailer section too long"))
}

/// Chunk-encode a buffered body straight into `w`, without collecting it.
///
/// Written in fixed-size chunks rather than one big one so that handing back a
/// body that spilled costs the block below and not the object: a response that
/// had to be assembled in memory first would give back on the way out exactly
/// the bound the spill buys on the way in.
pub(super) fn encode_into<W: Write>(w: &mut W, payload: &StreamPayload) -> io::Result<()> {
    /// Bytes per chunk. Large enough that the per-chunk header is noise, small
    /// enough to be an unremarkable allocation.
    const BLOCK: usize = 64 * 1024;

    let mut src: Box<dyn Read> = match payload {
        StreamPayload::Mem(v) => Box::new(io::Cursor::new(v.clone())),
        // A fresh handle positioned at 0; the payload owns the file.
        StreamPayload::Disk(tmp, _) => Box::new(tmp.reopen()?),
    };
    let mut buf = vec![0u8; BLOCK];
    loop {
        let got = src.read(&mut buf)?;
        if got == 0 {
            break;
        }
        w.write_all(format!("{got:x}\r\n").as_bytes())?;
        w.write_all(&buf[..got])?;
        w.write_all(b"\r\n")?;
    }
    w.write_all(b"0\r\n\r\n")
}

/// Chunk-encode `body` as a single chunk followed by the last-chunk marker.
pub(super) fn encode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 32);
    if !body.is_empty() {
        // An empty data chunk would be a `0` length line, i.e. the terminator,
        // so the empty body case skips straight to it.
        out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Decode with a drain ceiling generous enough that it never fires; the
    /// tests that care about the drain set their own.
    fn decode(input: &[u8], limit: u64) -> Result<(Vec<u8>, BodyEnd), BodyError> {
        let (body, outcome) = decode_full(input, limit, u64::MAX)?;
        assert!(!outcome.over_limit, "unexpected over-limit body");
        Ok((body, outcome.end))
    }

    fn decode_full(
        input: &[u8],
        limit: u64,
        drain_limit: u64,
    ) -> Result<(Vec<u8>, BodyOutcome), BodyError> {
        let mut r = BufReader::new(input);
        let mut out = Body::new();
        let outcome = read_chunked_body(&mut r, Some(limit), drain_limit, &mut out)?;
        Ok((bytes(out), outcome))
    }

    /// The decoded body, read back the way the scanner would get it — through
    /// the payload, so a test says nothing about whether it spilled.
    fn bytes(body: Body) -> Vec<u8> {
        match body.finish().expect("materialise the body") {
            StreamPayload::Mem(v) => v,
            StreamPayload::Disk(tmp, _) => {
                let mut buf = Vec::new();
                tmp.reopen()
                    .expect("reopen the spill file")
                    .read_to_end(&mut buf)
                    .expect("read the spill file");
                buf
            }
        }
    }

    fn reason(e: BodyError) -> String {
        e.to_string()
    }

    #[test]
    fn decodes_a_single_chunk() {
        let (body, end) = decode(b"5\r\nhello\r\n0\r\n\r\n", 1024).unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(end, BodyEnd::Eof);
    }

    #[test]
    fn decodes_several_chunks() {
        let (body, end) = decode(b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n", 1024).unwrap();
        assert_eq!(body, b"abcdefg");
        assert_eq!(end, BodyEnd::Eof);
    }

    #[test]
    fn decodes_an_empty_body() {
        let (body, end) = decode(b"0\r\n\r\n", 1024).unwrap();
        assert!(body.is_empty());
        assert_eq!(end, BodyEnd::Eof);
    }

    #[test]
    fn recognises_the_ieof_terminator() {
        let (body, end) = decode(b"4\r\nabcd\r\n0; ieof\r\n\r\n", 1024).unwrap();
        assert_eq!(body, b"abcd");
        assert_eq!(end, BodyEnd::Ieof);
        // Spelling variants deployed clients actually emit.
        for term in [
            &b"0;ieof\r\n\r\n"[..],
            &b"0 ; ieof \r\n\r\n"[..],
            &b"0; IEOF\r\n\r\n"[..],
            &b"0; foo; ieof\r\n\r\n"[..],
        ] {
            assert_eq!(decode(term, 1024).unwrap().1, BodyEnd::Ieof, "{term:?}");
        }
        // A chunk extension that merely contains the letters is not the marker.
        assert_eq!(decode(b"0; ieofx\r\n\r\n", 1024).unwrap().1, BodyEnd::Eof);
    }

    #[test]
    fn accepts_a_trailer_section() {
        let (body, _) = decode(b"2\r\nhi\r\n0\r\nX-Trailer: v\r\n\r\n", 1024).unwrap();
        assert_eq!(body, b"hi");
    }

    #[test]
    fn stops_at_the_end_of_the_body_and_leaves_the_rest() {
        let mut r = BufReader::new(&b"2\r\nhi\r\n0\r\n\r\nNEXT REQUEST"[..]);
        let mut out = Body::new();
        read_chunked_body(&mut r, Some(1024), u64::MAX, &mut out).unwrap();
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"NEXT REQUEST");
    }

    #[test]
    fn a_body_past_the_limit_keeps_its_head_and_discards_the_rest() {
        let (body, outcome) =
            decode_full(b"4\r\nAAAA\r\n4\r\nBBBB\r\n0\r\n\r\n", 6, u64::MAX).unwrap();
        // Exactly the ceiling's worth of head is kept, cutting mid-chunk where
        // it has to: refusing by size without looking would miss a detection
        // sitting in the part that did fit.
        assert_eq!(body, b"AAAABB");
        assert!(outcome.over_limit);
        assert!(!outcome.abandoned);
        assert_eq!(outcome.end, BodyEnd::Eof);
    }

    #[test]
    fn an_over_limit_body_still_ends_at_a_request_boundary() {
        // The verdict is only useful if it can be delivered, and it can only be
        // delivered if the stream is left where the next request starts.
        let mut wire = Vec::new();
        wire.extend_from_slice(b"10000\r\n");
        wire.extend_from_slice(&[b'A'; 0x10000]);
        wire.extend_from_slice(b"\r\n0\r\n\r\nNEXT REQUEST");
        let mut r = BufReader::new(&wire[..]);
        let mut out = Body::new();
        let outcome = read_chunked_body(&mut r, Some(1024), u64::MAX, &mut out).unwrap();
        assert!(outcome.over_limit && !outcome.abandoned);
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"NEXT REQUEST");
    }

    #[test]
    fn the_discard_is_itself_bounded() {
        // A header claiming 4 GiB costs nothing: it is compared against the
        // ceilings before a single byte of that chunk is read.
        let (_, outcome) = decode_full(b"ffffffff\r\nAAAA", 1024, 1024).unwrap();
        assert!(outcome.over_limit && outcome.abandoned);
        // And a body that keeps going past the discard ceiling is given up on
        // rather than read forever.
        let mut wire = Vec::new();
        for _ in 0..8 {
            wire.extend_from_slice(b"400\r\n");
            wire.extend_from_slice(&[b'A'; 0x400]);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let (_, outcome) = decode_full(&wire, 512, 2048).unwrap();
        assert!(outcome.abandoned);
    }

    #[test]
    fn rejects_malformed_framing() {
        let cases: [(&[u8], &str); 6] = [
            (b"", "stream ended before the last chunk"),
            (b"\r\n0\r\n\r\n", "empty chunk size"),
            (b"zz\r\nab\r\n0\r\n\r\n", "malformed chunk size"),
            (b"00000000000000000\r\n", "malformed chunk size"),
            (b"5\r\nabc", "chunk shorter than its declared size"),
            (
                b"2\r\nabcd\r\n0\r\n\r\n",
                "chunk data overruns its declared size",
            ),
        ];
        for (input, want) in cases {
            let got = reason(decode(input, 1024).unwrap_err());
            assert!(
                got.contains(want),
                "input {input:?}: got {got:?}, want {want:?}"
            );
        }
    }

    #[test]
    fn rejects_an_endless_chunk_header() {
        let mut input = b"1".repeat(MAX_CHUNK_LINE * 2);
        input.extend_from_slice(b"\r\n");
        assert!(decode(&input, 1024).is_err());
    }

    #[test]
    fn rejects_an_endless_trailer() {
        let mut input = b"0\r\n".to_vec();
        for _ in 0..(MAX_TRAILER_LINES + 5) {
            input.extend_from_slice(b"X: y\r\n");
        }
        input.extend_from_slice(b"\r\n");
        let got = reason(decode(&input, 1024).unwrap_err());
        assert!(got.contains("trailer section too long"), "{got}");
    }

    #[test]
    fn a_body_that_ends_right_after_the_last_chunk_still_decodes() {
        // No trailing blank line. The body is complete; refusing it would
        // discard a finished scan over a missing CRLF.
        let (body, end) = decode(b"2\r\nhi\r\n0\r\n", 1024).unwrap();
        assert_eq!(body, b"hi");
        assert_eq!(end, BodyEnd::Eof);
    }

    #[test]
    fn a_body_past_the_spill_threshold_goes_to_disk_intact() {
        // What removes the need for a per-listener size ceiling: an object costs
        // the spill threshold in RAM however large it is, so how big a client's
        // object may be is a scan question rather than a memory one.
        let threshold = spill::config().threshold as usize;
        let mut body = Body::new();
        let block = vec![b'Z'; 1024 * 1024];
        let blocks = (threshold / block.len()) + 2;
        for _ in 0..blocks {
            body.write(&block).unwrap();
        }
        let total = (blocks * block.len()) as u64;
        assert_eq!(body.len(), total);
        // The head stays available for the preview scan, and stays bounded.
        assert_eq!(body.head().len(), threshold);

        let payload = body.finish().unwrap();
        assert!(
            matches!(payload, StreamPayload::Disk(_, _)),
            "a body this size must not be held in RAM"
        );
        assert_eq!(payload.len(), total, "the spill file is the whole object");
    }

    #[test]
    fn a_body_under_the_threshold_never_touches_the_disk() {
        let mut body = Body::new();
        body.write(b"small").unwrap();
        assert_eq!(body.head(), b"small");
        assert!(matches!(body.finish().unwrap(), StreamPayload::Mem(_)));
    }

    #[test]
    fn a_streamed_body_encodes_back_to_what_went_in() {
        // The echo path: a message handed back to a client that wanted one is
        // written straight out of wherever it was buffered.
        for len in [0usize, 1, 4096, spill::config().threshold as usize + 7] {
            let mut body = Body::new();
            let payload_bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            body.write(&payload_bytes).unwrap();
            let payload = body.finish().unwrap();

            let mut wire = Vec::new();
            encode_into(&mut wire, &payload).unwrap();
            let (back, end) = decode(&wire, u64::MAX).unwrap();
            assert_eq!(back, payload_bytes, "len {len}");
            assert_eq!(end, BodyEnd::Eof);
        }
    }

    #[test]
    fn encodes_a_body_a_decoder_reads_back() {
        for payload in [&b""[..], &b"x"[..], &b"hello world"[..]] {
            let wire = encode(payload);
            let (back, end) = decode(&wire, 1024).unwrap();
            assert_eq!(back, payload);
            assert_eq!(end, BodyEnd::Eof);
        }
    }
}
