# Differential test triage: every difference explained

Companion to [DIFF_TESTING.md](DIFF_TESTING.md). That file says how to run the
harness. This one records what each difference in the 2026-10-23 full run turned
out to be, so a corpus file does not have to be investigated twice. Files are
named by the first 16 hex digits of their sha256 (the file name under
`corpus/samples/**`).

## The run

| | |
|---|---|
| date | 2026-10-23 |
| scope | all 8,979 files of the manifest (size cap 20 MB), `daily.cvd` only, 340,136 signatures |
| ClamAV | 1.5.4, `clamav/clamav-debian`, clamd with 6000 MB, `MaxFileSize`/`MaxScanSize` 2000M |
| exav | release build, `--clamav-compat --max-object-bytes 2000M --max-scan-secs 120`, `--detect macros,broken,broken-media,phishing,partition-intersection`, `--partial-as password-protected=found,limits-exceeded=found`, 6 workers |
| host | 3 cores, 16 GB, `JOBS=6` |

| bucket | files |
|---|---|
| clean for both | 5,844 |
| identical detections | 2,836 |
| exav only | 124 |
| partial overlap | 80 |
| careful (exav "not fully scanned", ClamAV OK) | 46 |
| ClamAV error (exav answered) | 31 |
| ClamAV gave up on its own limit | 14 |
| missed by exav | 2 (0 real, see below) |
| different name | 2 |

Throughput under 6 concurrent jobs (a compliance run, not a benchmark): exav 602 s
(14.9 files/s), ClamAV 3,674 s (2.3 files/s). Per file median 75 ms against
311 ms, 95th percentile 1.3 s against 11.9 s.

**Verdict: no false negative and no false positive in exav was found.** Two
real bugs turned up in the PDF lexer while triaging, the carver counted one
zip's entries as separate archives, and a document holding copies of itself was
scanned once per copy (all fixed, see "Code changes").

## How a difference was settled

* **Oracle (the main tool).** `cargo run -p exav-unpack --example dump_members
  --all-features -- FILE OUTDIR` writes every member exav extracts. Scanning that
  directory with `clamscan -r --allmatch` shows whether ClamAV flags the same
  bytes under the same name. If it does, exav reached content ClamAV never
  unpacked.
* **Mutation bisect.** Zero out a slice of the file and rescan with exav. The
  slice whose removal kills the detection is where the match comes from. Halve
  it until it is a few bytes.
* **Instrumentation.** A temporary `eprintln!` in `core_matches` (the
  `engine_pass` closure, `crates/exav-core/src/lib.rs`) printing object depth and
  name tells which derived object matched (for example `upx-rebuilt-pe`). Never
  committed.
* **Packers.** `cargo run -p exav-unpack --example pepack_emu -- --dump DIR
  --all FILE` runs exav's PE emulator and writes the recovered image.
* **ClamAV debug.** `clamscan --debug` names the step that raised a heuristic
  (`FP SIGNATURE: ...:Heuristics.Encrypted.PDF # Name: oleObject1.bin`).
* **Standalone rerun.** A limit alert that disappears when exav runs once,
  without the daemon's memory cap, is a harness artefact.
* **Do not read ClamAV's source** to explain its behaviour (provenance rule).
  Mutate the input and watch `clamscan` instead; that is how the XLM case below
  was settled.

## Findings

Legend: **TP** exav is right and ClamAV does not reach it. **CFP** ClamAV is
wrong. **Policy** a deliberate difference. **Artefact** caused by the harness.

### Exav only: named signatures (73 files)

All confirmed by the oracle unless noted. ClamAV, handed the right piece alone,
reports the same name.

| what | files | verdict |
|---|---|---|
| `Win.Tool.CobaltStrike`, `Win.Malware.Generic-10058807`, `Win.Malware.Poison`, `Win.Packed.Barys` in docx (30) and rtf (7): a PE written as hex inside the RTF (a docx carries `word/*.rtf`). ClamAV's RTF reader only dumps well-formed `\objdata`. The hex blob decoded by hand is flagged by ClamAV | 37 | TP |
| `Win.Packed.Tedy`, `Agenttesla`, `Generic-9987673` in cab members: the exe holds a gzip-compressed .NET assembly in its resources. The inflated assembly is flagged by ClamAV | 3 | TP |
| `Win.Trojan.Modiloader`: a gzip-named file (6) that is a `.bat` which is itself a CAB behind a 3-byte `PNG` prefix (`PNGMSCF`), holding `x.exe`; and cab `ae147ea53272`. `x.exe` of `0fd3605f5f1625a2` flagged by ClamAV, the others have the same structure or were settled by the member oracle | 7 | TP |
| `Win.Ransomware.Ryzerlo` (cab `8fe7b55ea28e`), `Win.Malware.Generic-10008460`, `Msilperseus`, `Win.Trojan.Remcos` (3 msi), `Ole2.Dropper.Corona` (doc `6a22c0f7cafd`): members of the container, flagged by ClamAV alone | 6 | TP |
| MPRESS-packed exe (`Darkkomet`, `Zeus`, `Tinba` extras). Exav's emulator unpacks it; ClamAV finds all six names in the unpacked image | 1 | TP |
| Enigma-protected exe in a cab (`Zpevdo`, `Generic-9846514`, `Generic-9885003`). Same oracle | 1 | TP |
| `Win.Tool.Valley` in two DLLs: x64 UPX nested in x64 UPX (`upx-rebuilt-pe`). ClamAV finds the name in the inner PE. 8 verified, 9 same shape | 2 | TP |
| `Rtf.Exploit.CVE_2026_21509`, `Win.Exploit.CVE_2026_21514` | 16 | Policy, documented in [quirks](../www/src/content/docs/scanner/concepts/quirks.md) ("A pure-ASCII RTF is text"): the CLSID is upper case in the file and lower case in the signature, and exav also scans the lower-cased text view |
| `Xls.Malware.Stratos-7506050` on `249bc00ea0798f78` | 1 | Policy, open question. Exav adds an original-case concatenation of all VBA modules (`vba_project_raw`) and the signature's four strings sit in different modules. ClamAV only builds the lower-cased dump. Likely a false positive on a benign workbook; decide whether `Target:2` signatures should see the raw copy |

Signature definitions can be read from the extracted database:
`tail -c +513 daily.cvd | tar -xz` then `grep NAME daily.ldb`.

### Exav only: heuristics

| class | files | verdict |
|---|---|---|
| `Heuristics.Encrypted.Zip` on WannaCry exe and dll (23): the PE carries an encrypted zip in a resource (`b.wnry`). ClamAV flags the zip when carved out by hand | 23 | TP, reach |
| `Heuristics.Encrypted.7Zip`: msi installers carrying a 7z AES archive, one top-level 7z, one zip holding an msi. ClamAV 1.5.4 never reports an encrypted 7z, even for the plain 7z file. The name is not documented anywhere and `--clamav-compat` still emits it | 18 | Policy, undocumented. Document it or drop it in compat mode |
| `Heuristics.Encrypted.RAR` on `97bbe277773cc10b`: RAR SFX payload inside `compat.exe` in a cab. ClamAV flags the carved payload | 1 | TP, reach |
| `Heuristics.Encrypted.PDF` on `97d7221dddca52d1`: AES-128 (R4) PDF that opens with an empty password (qpdf agrees). Exav reported it password-protected | 1 | **Exav bug, fixed** (`\b` escape in the PDF string lexer broke `/O`) |
| `Heuristics.Broken.Executable` in three MSI installers (ScreenConnect and friends): members that are broken PEs. ClamAV flags the same members alone | 3 | TP, reach |
| `Heuristics.Broken.Media.*` (JPEG dup APP marker, PNG chunk errors, spurious bytes): pdf, xlsx, zip and apk members. ClamAV flags the same members alone | 6 | TP, reach |
| `Heuristics.OLE2.ContainsMacros.VBA`: four xls with a default-password encrypted workbook (exav decrypts, finds the project); one xlsm named `.xls` (`26b8ea7bb37f273a`, VBA in `xl/vbaProject.bin`, ClamAV does not alert on OOXML) | 5 | TP |

### Limits (85 files carry an exav-only limit alert)

85 = 54 files where ClamAV answered (39 persist standalone, 15 vanish) plus 31
where ClamAV errored (7 persist, 24 vanish). The class lists at the end split
the 54; the 31 are under "ClamAV error".

| class | files | verdict |
|---|---|---|
| Vanish when exav runs standalone without the daemon cap | 39 | Artefact. With 6 workers on 16 GB each scan gets 1.66 GB and may hold 415 MB in one object. A nested 866 MB zip, or a 797 MB member, is refused ("its format is read whole"). Run fewer workers or a bigger host. A nested zip over the object cap is a real exav limitation |
| Persist standalone | 46 | see below |

What the 46 are:

* **Carving cap** (ppt, doc, xls, dll): "more embedded files than carving scans in
  one object (16 executables, 32 archives)". The "archives" are the local file
  headers of one embedded zip, each taken as its own candidate and scanned to the
  end of the object, so a zip with N entries cost about N squared member visits.
  **Fixed** by counting a zip once (see "Code changes"). What remains are real
  executables: `a9de34a3741cd8b3` has 20 distinct PEs. Raising the caps to 64 and
  256 was tried and rejected: it made `8c586cec56193cd2` 14 times slower (9 s to
  126 s) for the same verdict. `26b8ea7bb37f273a` (5 MB, 28 s, 937 MB fed to the
  matcher) is not this: see "Open items".
* **Member count** (jars, apks, msi, ppt, xls): `file count > 10000`, the compat
  limit. Exav counts members of nested archives; ClamAV scans fewer. In normal
  mode the limit is 100,000.
* **Compression ratio 1000** (pdf, 6 files): a blank scanned page is a Flate
  stream at the format's ceiling of about 1032:1, so it trips a ratio of 1000
  once past the 4 MB floor. Kept: it is a security default
  (`Limits::max_compression_ratio`) with a test.
* **PCRE size, compat** (`e8fe51be55737313`): a 22 KB RAR that unpacks to a
  116 MB padded `.js`. In compat exav keeps ClamAV's 100 MB PCRE limit and
  reports it; ClamAV skips PCRE silently. Normal mode scans it completely.
* **Embedded 7z/zip beyond `--max-members` in msi** (`d457af10c19d93d9`,
  `8c586cec56193cd2`): same member count limit.

### ClamAV only (exav lacks it), all ClamAV false positives

| class | files | explanation |
|---|---|---|
| `Heuristics.OLE2.ContainsMacros.XLM` | 10 | All are FILEPASS-encrypted workbooks. ClamAV reads the encrypted `BOUNDSHEET` bytes as sheet types and one byte equals 1 ("macro sheet"). Mutating the BOUNDSHEET records of the sample removes the alert. Decrypted, there is no macro sheet; exav decrypts first |
| `Heuristics.Encrypted.PDF` on xls | 10 | An encrypted PDF embedded in an Excel object. It opens with an empty password; exav decrypts it and reads it. Alerting would be wrong |
| `Heuristics.Encrypted.RAR` on `e8b64acacdce1f67` | 1 | A Go binary (chisel). The "RAR" is `Rar!\x1a\x07\x00` in `net/http`'s content-sniffing table. Exav correctly ignores it |

### Careful: exav says "not fully scanned", ClamAV says OK (46 files)

Each has a stated reason; none is a surprise.

* 22: executable protected by a code virtualizer (VMProtect, Themida and the
  like, 17 of them inside ISOs); no original code exists to recover.
* 4 truncated 7z ("next header extends past end of file"), 4 corrupt deflate
  streams, 4 PDF streams that do not decode, 2 zip members cut part way, 2 NSIS
  streams cut part way, 2 MSI chunks that end early, 1 MSZIP failure, 1 AutoIt
  member ending early, 1 UPX with a damaged `PackHeader`, 1 unknown packer, 1
  AppleDouble container (no reader), 1 tar with a bad checksum field.

### ClamAV gave up, exav completed (14 ISOs and cabs)

ClamAV reports `Heuristics.Limits.Exceeded.MaxScanSize` although the limit is
2000M. Exav scans them to the end and finds nothing.

### ClamAV errors (31 files)

Client timeouts (120 s) on slow archives. Exav answered all 31 within its own
limits, and ClamAV has no verdict to compare with. Rerun with a longer `TMO` if
the comparison is wanted.

### "Missed by exav" (2) and "different name" (2)

* `b3970ff836f096cb` (iso): not a real miss. A row cut off when a run was killed
  was glued to the next one, so the "verdict" was the file size. ClamAV found
  nothing. **Kill runs cleanly, or check the clam table for a row with no tab.**
* `b7dacc50bebb59e3` (msi): a damaged CAB appended to the MSI (bad CFDATA
  checksums; cabextract and 7z fail). ClamAV extracts the first 61 KB, finds a
  truncated exe and alerts `Heuristics.Broken.Executable`. Exav reads the whole
  2,988,896-byte exe, a valid PE with every section inside the file, and finds
  nothing. Exav ignores CFDATA checksums on purpose. No fix.
* `53812d7bdaf5e8e5` (pdf): both alert on a corrupt JPEG; the flate stream is
  corrupt, so the engines salvage different amounts of it and name the error
  differently (`CantReadSegmentSize` against `SpuriousBytesBeforeSegment`).
  Benign.
* `15d1a76ada779d4d` (zip): ClamAV `MaxScanTime`, exav `MaxFileSize` (memory cap
  in the daemon; clean standalone).

## Code changes made because of this triage

* `crates/exav-unpack/src/formats/pdf_parse/lex.rs`: `\b` and `\f` in a PDF
  literal string were read as the letters `b` and `f`; a short octal escape
  (`\0)`) swallowed the byte after it, including the closing parenthesis.
  Tests: `backspace_and_form_feed_escapes_are_decoded`,
  `a_short_octal_escape_does_not_eat_the_next_byte`, and in `crypt.rs`
  `an_owner_key_with_a_backspace_escape_still_opens_with_the_empty_password`
  (the dictionary of `97d7221dddca52d1`). Each fails without its fix.
* `crates/exav-core/src/pe.rs`, `Carving::feed`: a ZIP local header at the offset
  the previous one says the next entry begins (`zip_next_header`: no data
  descriptor, no encryption, no ZIP64 size) is not an archive candidate; the
  walk of the first one reads it, wherever the central directory points. A zip
  at offset 0 is treated the same. The caps stay at 16 and 32. Tests in `pe.rs`
  (entries of a zip stapled in, at offset 0, headers that cannot place the next
  one, a size that misses it) and `suites/embedded_carve.rs` (a 300-entry zip
  stapled into a document is clean; a second zip at the offset the first names,
  inside its span or after its end, is still found). The unit tests and the
  300-entry test fail with the skip disabled.

* `crates/exav-core/src/lib.rs` (`member_content_scan`, `clean_memo_key`) and
  `engine/mod.rs` (`clean_seen`, `clean_seen_insert`): a container member that
  was scanned clean and complete is remembered for the rest of the scan, by a
  SHA-256 of its bytes and of its place (container type, forced type, the types
  above it, name extension). An identical member in the same place at the same
  depth or deeper is not scanned again. Only members of 64 KiB to 512 MiB; a
  scan that raised a truncation flag is not remembered; at most 4,096 entries;
  cleared with the truncation flags at the start of each top-level scan. A copy
  that is not clean, or sits shallower than the one remembered, is scanned as
  before. The scan budget is still charged when a member is decoded, so a
  bomb of copies still trips it. Unit tests in `lib.rs` (`copies_of_a_clean_member_are_scanned_once`,
  `members_that_differ_are_each_scanned`, `small_copies_are_each_scanned`,
  `an_infected_member_after_clean_copies_is_found`,
  `a_clean_copy_covers_only_the_same_depth_or_deeper`); the first and the last
  fail when the insert or the depth rule is removed. Measured: `26b8ea7bb37f273a`
  30.6 s to 2.8 s, same verdict; whole manifest, no verdict differs from the
  run without the memo; CPU on 250 files of 0.2 to 8 MB, 218 s against 216 s
  (the digest costs nothing measurable).

Why skipping a zip's later entries is safe: a plain walk of a zip (no carving) reaches the local
headers of a second zip placed anywhere after its own, in the span before its
central directory or after its end record. So the second archive is read when
the first is.

Measured effect, old build against the final one, whole manifest (8,979 files,
the harness flags):

* Verdicts: 12 files differ and nothing else. 11 lose a `MaxFiles` alert (all
  from the carving cap) and `97d7221dddca52d1` loses `Encrypted.PDF` (the lexer
  fix). No detection of any kind is lost or gained.
* `652df9c24dcf0110` (xls): 3.6 s to 0.9 s and the macro alert is kept in
  compat mode, which it lost when only the caps were raised.
* Time: the same. Alternating old and new per file on 300 files, wall 134 s
  against 132 s and CPU 212 s against 209 s. The full pass took 791 s against
  602 s for the first one, and that gap is the machine, not the code: it is
  uniform (median 1.2 times even on files under 100 KB, where carving cannot
  matter) and the same with the caps raised.

## Open items

* `26b8ea7bb37f273a` (xlsm): explained, not a bug, and now 3 s instead of 30 s
  by the clean-copy memo (see "Code changes"). Diagnosis: `xl/embeddings/oleObject3.bin` is a 5.2 MB RAR holding a matryoshka: 152
  members nine levels deep, 660 MB extracted from a 5.3 MB file (125 times), a
  fan-out of 3 at the deepest levels (36 copies of the same 7.7 MB OLE object,
  which carries three copies of a 2.5 MB jpg and the next RAR). Only 50 of the
  152 members are distinct (113 MB). No limit trips: each member expands about
  3 times (the ratio guard is per stream), and the totals stay under the 1 GiB
  extracted and 10 GiB scanned budgets. Time is linear in volume: about 35 MB/s
  in the matcher (26 s for 937 MB, which is more than 660 MB because an OLE
  object is matched whole and again as its streams) plus about 10 s of RAR
  decoding. ClamAV answers in 0.3 s and scans 5.4 MiB: it does not open the
  embedded RAR.
* Carving more than 16 executables costs a rescan of the object per executable;
  the cap is what bounds it.
* `Heuristics.Encrypted.7Zip` in compat mode (document or drop).
* `vba_project_raw` and `Target:2` signatures (Stratos).
* A nested zip past `--max-object-bytes` is not walked, because zip is read
  whole. A spill-backed seekable source would remove the limit.
* `difftest.sh`: let exav run with fewer workers than `JOBS` (or a larger
  per-scan memory) so memory-capped limits do not appear as differences; note in
  DIFF_TESTING.md that changing `JOBS` discards the ClamAV cache.
* Leaked clamd temp files in `$SOCK_DIR` (5 GB after two killed runs) filled
  the disk and stopped a run; clean them after a kill.

## Class lists

Every file that is not clean or identical, by class. 16 hex digits of the sha256.

**CAREFUL (46):**
0087b35d4460c970 0299d636802f5d8c 0aa66c62d8af0501 0d9f37e5ada1fcfc 0ea67d58d900c9ed 1d9bb14a95d46244 201cf8213fddeeb6 2171f783d2f705d4 2b104743dece0009 34c7d56bc43c8aa3 38cf37207571e68e 3bd2ce406aa9c310 431f16e6453e3c9b 44210eecc61cae50 4a241076b4b1b372 56829efc5cf4c9b5 6648302d497ee236 6b2c53eed24e6c3c 6b60813635717e89 7576a22aada711e4 77ccda79bc51c0da 86573dc0e6d066e8 86d89c68b57ffff1 8860960d7edfc8cc 8cd1cf28115cc9fd 9231e59452c8297f 939614ca17f25bf3 988c7108d9edc3cc a32c6199248e2488 a44ebeeeeffe7e9d a4f4382f361ea243 a54d2448c10f63a4 a750f3b2120e9f9d b76c5a4e63236a72 be01508c3e99f52c c2d04e162c733153 c32bdee0ec38c782 c613bf6e2b7e0f9a c8e8339ac7378085 da885760aaf9f56c e44250c76f444640 ed634afb236ae762 f3ee455a8ec625fe f9b1c6d7ef48f258 fbc0e4ee9167fa13 fd9bb6bf944bfc60

**ClamAV only, Encrypted.PDF (10):**
1d97f8703f3e94db 561cfc0f5af02ed7 7df9619f4ebfbfae 7fa36027da764a24 cbcd9d42fda0f69e d91c0e47050b3d3a e71e1bcc0bd45ce8 e9c2928799e29531 f67949219e9c1e55 fcd959770e20be2a

**ClamAV only, ContainsMacros.XLM (10):**
0f88cba6937a7f4a 1e78bfe5597be0fd 6d577060ff3bad7b 73633e1552e9b4e4 a84724da7ca93094 a9739ca257abe963 c38f7442f831322e cad4c2a58e1d8cd6 e221d54c29eeb719 f9f6314fc9f333b1

**ClamAV gave up (14):**
03d10e05ff7dfcfa 11c0447506a592e4 188f9b719f24aaf7 26a28dac52985b93 4794fecfc7532249 4b4d817797a5c425 806e0a2d8c8969ee 8108aa3ea1ff072b 82990ff6892d6d93 911406cbc8a9d8bc bbcdfc21a8d4d990 e295cf56fdf900cc e7496d72cecd5f73 e98ec2e2ecb0b4c0

**ClamAV error (31):**
0218fd850ca27f53 17b3f2dddbdacfb5 214fabef5dcd9bb9 24636cfe302fe7c7 34edcaeb64151e66 3536ccb7f3849791 42d624f5eabbfd15 4b5931e2e1c61bdc 513992d7076984d5 5fbed74e14ac6672 60241999f0f2d24b 664f2e71b527adad 7050c741d67e3335 76f50197193ece03 778ec9e6e0eb33d0 7f9a904a75df61c4 8c586cec56193cd2 b999fba4d4db5bdb be83d2ef39936814 bf5f96257e0d62bf c3001c3c4bd90844 c4b117f30786d0b3 cbede93869b3b49b ccc32204d9b5248e cfe903227ef28b4d d9d65ba90d1cb339 df3ec74c7affc6c3 e89e7065ed449be6 ea692f472d83dad2 fa14e758d5603486 ff760476038ffcc8

**Exav only, Broken.Executable (3):** 51acbd2c6429c059 a299d16325dd6c79 a8a2148d6cf70d06

**Exav only, Broken.Media (6):** 1ed821fcc96cd12b 3a451d6440924ddc 4d279990b1f785d5 590a05ad978d5230 ad32afe426639f17 fd8ad8f256f063e3

**Exav only, ContainsMacros.VBA (5):** 26b8ea7bb37f273a 47d8113a537e43ae 8bd46e4d069be47d 91f07d3af97ccccd c1733e867b91d2f1

**Exav only, Encrypted.7Zip (18):**
39d523a5486403cf 3e041fca1afb1896 46b7a1b85bcfcf53 486a26f35e5fa61c 4893de26be7c3014 60432d6eb939fc6d 69fb8fb0615a92ba 7af9b52392570350 969fa1cca8aaba23 9fc308606f49a3e3 a497a5a4aee23b53 aeb00742bc7f53f1 c5732e595ea5e2cc c6d11a362a134273 d49a51bbc86b8626 e28825d93ba61c9e e28bc04a6fab5755 e30b63d095dbedef

**Exav only, Encrypted.PDF (1, fixed):** 97d7221dddca52d1

**Exav only, Encrypted.RAR (1):** 97bbe277773cc10b

**Exav only, Encrypted.Zip, embedded (23):**
0b2d6d916b7c65a1 0e42e5927b3e7628 1241d39ed7c577d2 139bf62f701613c6 17b502febe4c9576 19ede46effb82553 1d2f1a8c2962658d 1d9427b7739d112e 405eeccd5e87474b 4c0aad4c85da91d9 608371b1c6e84d84 66c883ff13b81204 66ddd0edb16bfb04 764c5e5d18af9185 a32575ab0959baee a5bbdd39bf6360c3 a9bf6b54b485f91e b4f0148df9332a4c be6b529a5d73a362 d3961de88685bcad d435698c0c6075d6 d833fe282b1e2630 f0d29fc579b7f0c9

**Exav only, CVE-2026 RTF (16):**
1ed863a32372160b 27cc24191592acbb 3cb09154a839a5de 479fd5e5bd5566a0 506e7512c897514e 5a17cfaea0cc3a82 969d2776df0674a1 b2ba51b4491da860 baad1153e58c86aa bbfd93dbf43236b7 be859b4f4576ec09 c91183175ce77360 e8889528e2114a70 f7bda19543074c78 f81e70c6951855e2 fd3f13db41cd5b44

**Exav only, limit alerts that persist standalone (39).** Measured before the
carving fix; these 11 no longer alert `MaxFiles`: 02fcfa3661eba24f
036d5c207e08a9ca 10f7d98a3aad55a9 30a9c4190942560c 652df9c24dcf0110
7721fa12ed38f464 a0f1d5d0b561c148 b70d94fd7da398d1 eb575107f62e36ff
f107f93896e13db2 fd8ad8f256f063e3.
02fcfa3661eba24f 036d5c207e08a9ca 06328e27d906ef06 0807bbceb5b347cc 10f7d98a3aad55a9 1efa9a6e2c80769b 214831e29e52473a 30a9c4190942560c 3dbc39f220287603 45415f110b7961ee 5b2ea57a1e98320b 6423a95d9bb21f69 652df9c24dcf0110 6842d3f39591663c 7721fa12ed38f464 7c19a1542080f401 7d887e39bbb67f8c 81ec61a49b5fcc4e 8d42d425d003480d 91183972e908c013 93916b2b689b390b 9f238ad7ee69f9a5 a0f1d5d0b561c148 a83d05b6e86692f1 a9de34a3741cd8b3 ab878c9b957b90ff afd6aa4c10a70772 b70d94fd7da398d1 c2d0d7e20939319d c3106f5489c1b841 c47a2e761bd82ed8 d1bceccf5d2b900a d457af10c19d93d9 d9ddf328b6151bb6 e6fd06228e30648d e8fe51be55737313 eb575107f62e36ff f107f93896e13db2 fd8ad8f256f063e3

**Exav only, limit alerts from the daemon memory cap (15):**
11936fb09c6770b6 1220d2250778f214 14ac0c55100d957d 299d637461aec046 2ea2ab216b5e157d 3415bc316b67dce3 583b4d60eef20ddc 783008a032b58cbc 79f7b67ce8b39070 85046369ce3c2d3c 8a63e287500e0342 8edbc1689fba83ce ab5d1a42babf7a6f c86b1625d01dbd8c e27696135b673b81

**Exav only, named signatures (see the table above for causes):**
Win.Tool: 0141cd8c1c36de1d 0501889bf03e8049 051a19599ed53c23 1144433760a06834 1427bf3d809e8767 153892f70403de44 221f0dfce9d3d8c7 3dd4e4abfaddb0fa 40fc5865bb2b7e10 51aae172a88c1a03 5cceb6359a30fa49 6cf095b62941364c 6f5f9a315f359101 795190db4f5689c3 866a9be2f90b18f5 8d5b587491c4d79f 94be6da9598a9ed8 a355998ff9943113 b3afa94cb798f205 b4de258f62843f57 c56e550224f2e3f6 cdc7c2d40b1e404f e29c6a8615c0203a f6051498dc45e053
Win.Malware: 14de56ac48083584 25849d134335eebf 2a94c09245788e2e 3573fe242daee183 4903fbe3e8ee4bc4 52f6d81aa40d054f 7b6eb29b43e63f8f 9985f58f259ed1e6 9e71d743c8956c70 ac39ac04e808d8c9 c8f6c1c71ed253a5 d5df428380aaa991 dcf6fd6d07ff8c38 ea1a5491338fdb51
Win.Packed: 1c90e49314b25bd2 3ade60b953e17c45 4f8211d757f5e212 71b906576bc68097 e31a6cc18a18d992 ee812fa860c2283d
Win.Trojan: 0fd3605f5f1625a2 4a23c9ce67eb22b9 5201e83114e993d0 54be39b2a6c2a4b8 669f370d2e5a1c65 6ec4a56cbf21b654 86fb86b96de68b5a a2425da7336b3db5 ae147ea532725b24 f993c4798c266775
Other: 6a22c0f7cafd717d (Ole2.Dropper.Corona) 6ec4a56cbf21b654 (MPRESS) 8fe7b55ea28e5c83 (Ryzerlo) 249bc00ea0798f78 (Stratos)

**Misc:** missed `b3970ff836f096cb` (corrupt row) `b7dacc50bebb59e3` (damaged CAB); different name `15d1a76ada779d4d` `53812d7bdaf5e8e5`.
