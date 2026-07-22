fn main() {
    let raw = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let (_h, files) = exav_core::cvd::read(&raw).unwrap();
    for f in &files {
        if f.name.ends_with(".ldb") {
            print!("{}", String::from_utf8_lossy(&f.data));
        }
    }
}
