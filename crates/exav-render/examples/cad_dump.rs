//! Print a DWG or DXF file's drawing model as JSON: `cargo run -p exav-render
//! --features dwg --example cad_dump -- drawing.dxf`. With `--native`, a DWG
//! goes to `cad::read_dwg` directly rather than through the renderer's
//! `Document::parse` (which reads it with the same reader and catches a
//! panic).

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    let native = args.first().is_some_and(|a| a == "--native");
    if native {
        args.remove(0);
    }
    let Some(path) = args.first() else {
        eprintln!("usage: cad_dump [--native] <file.dxf|file.dwg>");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: {e}", path.to_string_lossy());
            return ExitCode::FAILURE;
        }
    };
    if native {
        return match exav_render::cad::read_dwg(&bytes) {
            Ok(d) => {
                println!("{}", exav_render::cad::to_json(&d));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{}: {e}", path.to_string_lossy());
                ExitCode::FAILURE
            }
        };
    }
    match exav_render::dwg::Document::parse(&bytes) {
        Ok(d) => {
            println!("{}", exav_render::cad::to_json(d.drawing()));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {e}", path.to_string_lossy());
            ExitCode::FAILURE
        }
    }
}
