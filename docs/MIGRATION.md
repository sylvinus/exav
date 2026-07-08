# Migrating from ClamAV to exav

exav is designed as a **drop-in**: it uses ClamAV's signature formats, matches
`clamscan`'s flags/output/exit codes, and speaks the `clamd` wire protocol. In
most setups the switch is changing one command or one socket — your signature
databases, updater, and client tooling stay exactly as they are.

> ⚠️ exav is **alpha** and unaudited. Migrate in a test environment first, and
> keep ClamAV available to fall back to.

---

## 1. Keep your existing signatures

exav reads ClamAV's own DB files — point it at the directory `freshclam` (or
`cvdupdate`) already populates:

```sh
exav -d /var/lib/clamav -r /data     # Debian/Ubuntu default DB dir
```

Nothing changes about updating signatures: keep running `freshclam` /
`cvdupdate` on your normal schedule. exav loads `.cvd`/`.cld`/`.ndb`/`.ldb`/… and
YARA `.yar`/`.yara` from that directory.

**Faster startup on big databases:** build a cache once and load it instantly:

```sh
exav -d /var/lib/clamav --build-cache /var/lib/clamav/exav.cache   # run after each freshclam
exav -d /var/lib/clamav/exav.cache -r /data                        # sub-second cold start
```

---

## 2. Replacing `clamscan` (one-shot scanning)

Same output format (`PATH: Signature FOUND` / `PATH: OK`), same core flags
(`-r -i --bell -d --max-filesize --max-scansize --allmatch --exclude
--exclude-dir --include --quiet --no-summary`). The simplest swap:

```sh
alias clamscan='exav'
# or install the `exav` binary earlier in $PATH than clamscan
```

**The deliberate difference to know** (it makes exav *safer*, but a script may
notice):

| | ClamAV | exav |
|---|---|---|
| A file it couldn't fully scan (size/ratio/recursion limit, unsupported codec, encrypted) | often reports `OK`, exit **0** | reports `LIMITS-EXCEEDED`/`UNSCANNABLE`/`PASSWORD-PROTECTED`, exit **2** |

So a CI job that treats exit 2 as "scanner error" may need to treat it as "could
not fully scan" (which is not a pass). Exit codes: `0` clean, `1` found, `2`
error/not-fully-scanned — same scheme as clamscan.

By default exav runs at full capability. To match a stock ClamAV build's
documented limits and extractor set for apples-to-apples differential testing,
use `--clamav-compat` (or set its individual flags — `--max-filesize`,
`--max-scansize`, `--max-recursion`, `--max-files`, `--clamav-formats`,
`--unofficial-names`). See the [README compatibility section](../README.md#clamav-compatibility---clamav-compat).
`--max-scansize` is the distinct total-data-scanned budget (deep-analysis size +
summed extracted bytes), not an alias of `--max-filesize`.

---

## 3. Replacing `clamd` (the resident daemon)

This is the high-value swap for servers and mail gateways: run exav's daemon on
the **same socket `clamd` uses**, and `clamdscan`, milters (`clamav-milter`,
Amavis, Rspamd, MailScanner), and every clamd client library keep working
**unchanged**.

### Quick manual swap

```sh
# 1. Find clamd's socket (LocalSocket in clamd.conf). Debian/Ubuntu default:
grep -i localsocket /etc/clamav/clamd.conf   # e.g. /run/clamav/clamd.ctl

# 2. Stop clamd so the socket is free.
sudo systemctl stop clamav-daemon

# 3. Run exav on that socket, reading the same DB dir.
sudo -u clamav exav --daemon --socket /run/clamav/clamd.ctl -d /var/lib/clamav

# 4. Verify from another shell — existing clamd clients work as-is:
clamdscan --ping 1
clamdscan /etc/hosts
```

### As a managed service

Install the provided unit (shipped in the `.deb`, or copy
`packaging/exav-clamd.service`):

```sh
sudo systemctl stop clamav-daemon && sudo systemctl disable clamav-daemon
sudo systemctl enable --now exav-clamd
clamdscan --ping 1
```

The unit runs as the existing `clamav` user on the Debian socket path; edit
`ExecStart`/`RuntimeDirectory` for Fedora/RHEL (`/run/clamd.scan/clamd.sock`) or
to match your `clamd.conf`.

### clamd protocol coverage

Supported: `PING`, `VERSION`, `STATS`, `RELOAD`, `SCAN`, `CONTSCAN`,
`MULTISCAN`, `INSTREAM`, `FILDES`, `IDSESSION`/`END`, plus the exav extension
`SCANURL`. Commands may be `z`- or `n`-framed. A not-fully-scanned member is
returned as `... ERROR` carrying `LIMITS-EXCEEDED`/`UNSCANNABLE`/
`PASSWORD-PROTECTED` — never a silent `OK`.

---

## 4. Encrypted archives & passwords

Encrypted members are reported `PASSWORD-PROTECTED` (never a silent clean).
Supply passwords to decrypt and scan inside them:

```sh
exav --password secret --password hunter2 -r /data     # try a pool
# or a ClamAV .pwdb password database in the signature dir
```

ZIP (ZipCrypto + WinZip AES) and encrypted DMG are decrypted today; 7z/RAR/PDF
native encryption are detected but not yet decrypted.

---

## 5. What to watch for

- **Signature coverage** is ClamAV's — exav runs those signatures but adds none
  of its own. A handful (PCRE subsignatures, some bytecode) are skipped and
  **counted**, never silently ignored (see the README's Limitations).
- **Large-DB memory** is currently higher in exav than ClamAV (being worked on);
  use `--build-cache` and give the loader host enough RAM.
- exav is **alpha**: treat non-detections with appropriate caution and keep
  ClamAV as a fallback until you've validated coverage on your own corpus (see
  `docs/DIFF_TESTING.md` for a differential harness against real `clamd`).
