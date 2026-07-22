// Diagnostic: load a signature database and report the census of body prefix
// kinds, sizing how much of the matcher still reaches the backtracking
// `match_backward` walk. Temporary analysis tool for the gap-split matcher work.
use exav_core::loader;

fn main() {
    let db_path = std::env::args().nth(1).expect("usage: prefixcensus <db>");
    let scanner = loader::load(std::path::Path::new(&db_path)).expect("load database");
    println!(
        "unsupported (engine-authoritative) {}",
        scanner.unsupported_count()
    );
    let eng = scanner.engine();
    let [lit, fixed, floating, internal, int_var, max_toks, worst] = eng.diag_prefix_census();
    let total = lit + fixed + floating + internal;
    let pct = |n: u64| {
        if total == 0 {
            0.0
        } else {
            100.0 * n as f64 / total as f64
        }
    };
    println!("bodies                 {total}");
    println!("  literal-only         {lit:>10}  {:.3}%", pct(lit));
    println!("  Fixed    (sim only)  {fixed:>10}  {:.3}%", pct(fixed));
    println!(
        "  Floating (sim only)  {floating:>10}  {:.3}%",
        pct(floating)
    );
    println!(
        "  Internal (sim+walk)  {internal:>10}  {:.3}%",
        pct(internal)
    );
    println!("    of which the backward walk crosses a VARIABLE gap/alt:");
    println!("      {int_var} ({:.4}% of all bodies)", pct(int_var));
    println!("  max pre-anchor tokens        {max_toks}");
    if worst == u64::MAX {
        println!("  worst pre-anchor combinations UNBOUNDED (open-ended gap)");
    } else {
        println!("  worst pre-anchor combinations {worst}");
    }
}
