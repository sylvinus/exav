# Signature files for the fuzz targets

Written for exav, one or more lines of each kind the loader reads, with no
ClamAV content. `analyze` loads them once and scans the fuzzed bytes against
them, so the matcher, the logical-signature evaluator, the YARA engine, the
bytecode interpreter and the whole-file hash checks run on hostile data and not
on an empty database. `full_pipeline` and `loader` start from them too, and
mutate them.

The names that end in a number or carry an offset do so on purpose: each line
is the shape of one feature (an anchor at `EP+0`, an alternative group, a PCRE
subsignature with a back-reference, a YARA `for` over a module's array). A line
the loader rejects is a line the fuzzer never reaches, so `fuzz/db.rs` refuses
to start a target when one does not load or a YARA rule does not compile.

`fuzz.cbc` is `WRITE_32` from `crates/exav-core/tests/suites/bytecode_gating.rs`.
