// Diagnostic: why does a signature database contribute signatures exav does not
// load? Feeds every `.ndb`/`.ldb` line from a `.cvd` (or a loose file) to a
// fresh `EngineBuilder` and prints the per-reason breakdown, WITHOUT building
// the automaton — so it is fast and needs no automaton-sized RAM.
//
// "Counted, never silently ignored" is only half a guarantee if the count has
// no attribution; this is what turns the number into a work list.
use exav_core::engine::EngineBuilder;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: skipcensus <db.cvd|dir>");
    let raw = std::fs::read(&path).expect("read database");

    let mut ndb = String::new();
    let mut ldb = String::new();
    let mut take = |name: &str, body: &[u8]| {
        let text = String::from_utf8_lossy(body);
        if name.ends_with(".ndb") {
            ndb.push_str(&text);
        } else if name.ends_with(".ldb") {
            ldb.push_str(&text);
        }
    };
    match exav_core::cvd::read(&raw) {
        Ok((_hdr, files)) => {
            for f in &files {
                take(&f.name, &f.data);
            }
        }
        // Not a CVD: treat the argument as a loose signature file.
        Err(_) => take(&path, &raw),
    }

    let mut b = EngineBuilder::new();
    let ndb_lines = ndb.lines().filter(|l| !l.trim().is_empty()).count();
    let ldb_lines = ldb.lines().filter(|l| !l.trim().is_empty()).count();
    b.add_ndb(&ndb, false);
    b.add_ldb(&ldb, false);

    let total = ndb_lines + ldb_lines;
    let skipped = b.unsupported();
    println!("source signature lines   {total}  (.ndb {ndb_lines}, .ldb {ldb_lines})");
    println!(
        "not loaded               {skipped}  ({:.4}%)",
        if total == 0 {
            0.0
        } else {
            100.0 * skipped as f64 / total as f64
        }
    );
    println!("\nby cause:");
    for (reason, n) in b.unsupported_reasons() {
        println!(
            "  {n:>8}  {:.4}%  {reason}",
            if total == 0 {
                0.0
            } else {
                100.0 * n as f64 / total as f64
            }
        );
    }

    // Re-run line by line to show worked examples per cause — a count says how
    // big the gap is, an example says what to implement.
    println!("\nexamples (up to 6 per cause):");
    let mut seen: std::collections::HashMap<&'static str, Vec<String>> = Default::default();
    for line in ldb.lines().chain(ndb.lines()) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut one = EngineBuilder::new();
        if line.split(';').count() >= 4 {
            one.add_ldb(line, false);
        } else {
            one.add_ndb(line, false);
        }
        if let Some((reason, _)) = one.unsupported_reasons().first() {
            let e = seen.entry(reason).or_default();
            if e.len() < 6 {
                // Show the failing SUBSIGNATURE, not the whole line: the line is
                // mostly hex bodies that loaded fine, and the interesting part
                // (e.g. the regex construct we can't parse) is what got rejected.
                let subs: Vec<&str> = line.split(';').skip(3).collect();
                let culprit = subs
                    .iter()
                    .find(|s| {
                        let mut one = EngineBuilder::new();
                        let probe = format!("P;Engine:0-255,Target:0;0;{s}");
                        one.add_ldb(&probe, false);
                        one.unsupported() > 0
                    })
                    .copied()
                    .unwrap_or("<whole line>");
                let name = line.split(';').next().unwrap_or("?");
                e.push(format!(
                    "{name}\n      {}",
                    culprit.chars().take(220).collect::<String>()
                ));
            }
        }
    }
    for (reason, lines) in &seen {
        println!("\n  {reason}:");
        for l in lines {
            println!("    {l}");
        }
    }
}
