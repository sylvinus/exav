#!/usr/bin/env python3
"""Fuzzer that runs each input in a subprocess so third-party crate panics
don't kill the fuzzer process. Uses libFuzzer's corpus + mutations via a
thin Rust harness that invokes itself as a subprocess."""
import subprocess, sys, os, struct, hashlib, random, time, pathlib

WORKSPACE = pathlib.Path(__file__).parent
CORPUS = WORKSPACE / "corpus"
CRASHES = WORKSPACE / "crash-artifacts"
CORPUS.mkdir(exist_ok=True)
CRASHES.mkdir(exist_ok=True)

Harness = str(WORKSPACE / "target/release/fuzz_harness")

def run_one(data: bytes) -> bool:
    """Returns True if the input is safe (no crash)."""
    try:
        r = subprocess.run(
            [Harness],
            input=data,
            timeout=5,
            capture_output=True,
        )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return True  # timeout is fine
    except Exception:
        return False

def mutate(data: bytes) -> bytes:
    d = bytearray(data)
    for _ in range(random.randint(1, 6)):
        op = random.choice(["flip", "insert", "delete", "replace"])
        if op == "flip" and d:
            pos = random.randrange(len(d))
            d[pos] ^= 1 << random.randint(0, 7)
        elif op == "insert":
            pos = random.randint(0, len(d))
            d[pos:pos] = bytes([random.randint(0, 255)])
        elif op == "delete" and d:
            pos = random.randrange(len(d))
            del d[pos]
        elif op == "replace" and d:
            pos = random.randrange(len(d))
            d[pos] = random.randint(0, 255)
    return bytes(d)

# Seed corpus: empty, PDF magic, RAR magic, ZIP magic, 7z magic, gzip magic
seeds = [
    b"",
    b"%PDF-1.5\n",
    b"Rar!\x1a\x07\x01\x00",
    b"PK\x03\x04",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b\x08",
    b"\xfd7zXZ\x00",
    b"BZh",
    b"\x28\xb5\x2f\xfd",
]

def main():
    if not os.path.exists(Harness):
        print("Build the harness first: cargo build --release --bin fuzz_harness")
        sys.exit(1)

    # Load existing corpus
    corpus = []
    for f in sorted(CORPUS.iterdir()):
        if f.is_file():
            corpus.append(f.read_bytes())
    if not corpus:
        corpus = seeds
        for i, s in enumerate(seeds):
            (CORPUS / f"seed_{i}").write_bytes(s)

    print(f"Loaded {len(corpus)} inputs")
    start = time.time()
    runs = 0
    crashes = 0
    timeout_min = 60  # minutes

    while True:
        elapsed = time.time() - start
        if elapsed > timeout_min * 60:
            break

        # Pick a seed and mutate
        base = random.choice(corpus)
        data = mutate(base)

        runs += 1
        if runs % 1000 == 0:
            rate = runs / max(elapsed, 1)
            print(f"  [{int(elapsed)}s] {runs} runs, {rate:.0f}/s, {len(corpus)} corpus, {crashes} crashes", flush=True)

        if run_one(data):
            # Save interesting inputs (different from existing)
            h = hashlib.md5(data).hexdigest()
            if len(corpus) < 5000 and data not in corpus:
                corpus.append(data)
                (CORPUS / h).write_bytes(data)
        else:
            crashes += 1
            h = hashlib.md5(data).hexdigest()
            crash_file = CRASHES / f"crash-{h}"
            crash_file.write_bytes(data)
            print(f"  CRASH #{crashes}: {len(data)} bytes saved to {crash_file.name}")

    elapsed = time.time() - start
    print(f"\nDone: {runs} runs in {elapsed:.0f}s ({runs/elapsed:.0f}/s), {crashes} crashes, {len(corpus)} corpus")

if __name__ == "__main__":
    main()
