// Run exav's bytecode runtime (gated + forced) over files, for differential
// validation against clamscan's bytecode engine.
//
//   bc_scan <cbc_dir> <file>...
//
// Prints, per file: the gated detection (trigger fired) and any forced
// detections (program run regardless of trigger).
use exav_core::bytecode::runtime::BytecodeRuntime;
use exav_core::{filetype, pe};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("usage: bc_scan <cbc_dir> <file>...");

    let mut sources = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().map(|x| x == "cbc").unwrap_or(false) {
            if let Ok(t) = std::fs::read_to_string(&p) {
                sources.push(t);
            }
        }
    }
    let rt = BytecodeRuntime::from_sources(sources);
    eprintln!("loaded {} bytecode programs", rt.len());

    for path in args {
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                println!("{path}\tERR\t{e}");
                continue;
            }
        };
        let ft = filetype::identify(&data);
        let layout = if ft == filetype::FileType::Pe {
            pe::layout(&data)
        } else {
            None
        };
        let (det, _extracted) = rt.scan(&data, ft, layout.as_ref());
        let gated = det.map(|(n, _)| n).unwrap_or_else(|| "-".into());
        // The forced pass (every program, ignoring triggers) is expensive on
        // real binaries; only run it when explicitly requested.
        let forced = if std::env::var("EXAV_FORCED").is_ok() {
            let f: Vec<String> = rt
                .run_all_forced(&data)
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            if f.is_empty() {
                "-".into()
            } else {
                f.join(",")
            }
        } else {
            "off".to_string()
        };
        println!("{path}\tgated={gated}\tforced={forced}");
    }
}
