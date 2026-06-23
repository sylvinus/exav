# Bytecode interpreter — validation & test corpus

exav runs ClamAV `.cbc` bytecode programs in a memory-safe sandbox (see
`crates/exav-core/src/bytecode/`). Execution is gated behind each program's
trigger; a forced mode (`BytecodeRuntime::run_forced` / `run_all_forced`, and
`Database::run_bytecodes_forced`) runs programs regardless of their gate for
testing and differential validation.

Validating the interpreter has two layers: **opcode/API conformance** (benign,
no malware needed) and **detection accuracy** (needs real family/CVE samples).

## 1. Opcode/API conformance — no malware required

ClamAV's own repository ships a benign bytecode test corpus that exercises the
opcodes and host APIs directly. This is the first thing to differential-test
against, before touching any live sample:

- `Cisco-Talos/clamav` → `unit_tests/input/bytecode_sigs/*.cbc`
  (e.g. `arith.cbc`, `apicalls.cbc`, `inflate.cbc`, `pdf.cbc`, `div0.cbc`)
- scan target: `unit_tests/input/bytecode_scanfiles/apitestfile`
- expected-results oracle: `unit_tests/check_bytecode.c`
- bytecode compiler (to build your own `.cbc`): `Cisco-Talos/clamav-bytecode-compiler`

Extracting the real production programs (the 85 we target) from a DB:

```
freshclam                       # fetch main/daily/bytecode.cvd
sigtool -u bytecode.cvd         # unpack the .cbc programs
sigtool -l bytecode.cvd         # list signature (detection) names
```

`EICAR` (https://secure.eicar.org/eicar.com.txt) is the trivial smoke test —
its `.cbc` is our validated ground-truth anchor.

## 2. Detection accuracy — real samples (handle in an isolated VM)

The differential test: run a known sample through `clamscan` (with
`bytecode.cvd`) and through exav, and compare verdicts. The useful sources are
the ones that let you fetch **specific** families / CVEs, not random malware.

| Source | Access | Filter by family / ClamAV sig | URL |
|---|---|---|---|
| **MalwareBazaar** (abuse.ch) | free, Auth-Key required | **yes** — `get_siginfo`/`get_taginfo` (family), `get_clamavinfo` (ClamAV detection name) | https://bazaar.abuse.ch/ , API https://mb-api.abuse.ch/api/v1/ , key https://auth.abuse.ch/ |
| **VirusTotal Intelligence** | **paid** (VT Lite ~$5k/yr+) | yes — `engines:<name>`, `tag:cve-*` | https://www.virustotal.com/ |
| **Contagio** | free, email author for zip pwd | CVE-indexed exploit **documents** (RTF/PDF/SWF) | https://contagiodump.blogspot.com/ |
| **vx-underground** | free | by family ("Families" collection) | https://vx-underground.org/ |
| **theZoo** | free (GitHub) | by family (one folder each) | https://github.com/ytisf/theZoo |
| **MalShare** | free, API key | type/source only (no family) | https://malshare.com/ |
| **VirusShare** | invite-only | no search (hash lists / torrents) | https://virusshare.com/ |
| **Exploit-DB** | free | by CVE — but PoC/Metasploit, not in-the-wild samples | https://www.exploit-db.com/ , `searchsploit --cve` |

### Recommended workflow

1. **MalwareBazaar (primary)** — the only public source that filters by the
   actual ClamAV detection name. Get an Auth-Key, then query
   `get_clamavinfo`/`get_taginfo` for the families our programs detect
   (Locky, GandCrab, Virut, Xpaj, ConfuserEx, …). Downloads are AES-128 zips,
   password `infected` — note Python's stdlib `zipfile` can't open these; use
   `pyzipper` or `7z`.
2. **Contagio (for CVE exploit docs)** — where real CVE-2012-0158 RTF and
   malicious PDFs/SWF actually live (CVE-indexed). Email the author for the
   password scheme; expect some dead links.
3. **ClamAV `unit_tests` + `sigtool`** — the opcode oracle (layer 1) and the
   source of the real `.cbc` programs.

### Safe handling

All sample zips use the password **`infected`** (Contagio: `infected666<char>`).
Decrypt and run **only inside an isolated, network-free VM** — assume the
samples are live, self-spreading code. Use official domains only (there have
been impersonation cases).

## Caveats

- No public source filters by CVE *and* ClamAV signature together.
- The disasm-dependent detections (Xpaj/Virut/Ransom/Swrort) and the
  exploit/packer clusters are **executed but not yet detection-validated** —
  they need real samples per the above before their verdicts are trusted.
