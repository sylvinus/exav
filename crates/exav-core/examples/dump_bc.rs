use exav_core::bytecode::{parse, instr::Body, exec};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let bc = parse(&text).unwrap();

    // If a second arg is given, run the program over that file and report.
    if let Some(target) = std::env::args().nth(2) {
        let file = std::fs::read(&target).unwrap();
        let pe = exav_core::pe::bytecode_pe(&file);
        let pdf = exec::pdf_ctx(&file);
        let ctx = exec::Ctx {
            file: &file,
            flevel: 200,
            types: &bc.types,
            globals: &bc.globals,
            pe: pe.as_ref(),
            pdf: Some(&pdf),
            match_offsets: &[],
            apis: &bc.apis,
            default_name: &bc.name,
        };
        let out = exec::run(&bc.functions, 0, &ctx);
        println!("RUN on {target} ({} bytes):", file.len());
        println!("  detection: {:?}", out.detection);
        println!("  steps: {}  unsupported: {}", out.steps, out.hit_unsupported);
        return;
    }
    println!("name: {}", bc.name);
    println!("apis: {:?}", bc.apis);
    for (id, name) in &bc.apis {
        println!("  api global_id {id} = {name}");
    }
    println!("kind: {}  trigger: {}", bc.header.kind, bc.trigger);
    println!("num_types: {} num_funcs: {}", bc.header.num_types, bc.header.num_funcs);
    println!("globals: {} entries", bc.globals.values.len());
    for (gi, g) in bc.globals.values.iter().enumerate() {
        println!("  G[{gi}] = {:?}", g);
    }
    for (fi, f) in bc.functions.iter().enumerate() {
        println!("--- fn {fi}: args={} ret={} locals={:?} insts={} bb={}",
            f.num_args, f.return_type, f.types, f.num_insts, f.num_bb);
        for (bi, blk) in f.blocks.iter().enumerate() {
            println!("  BB{bi}:");
            for ins in blk {
                let b = match &ins.body {
                    Body::Ops(o) => format!("OPS {:?}", o),
                    Body::Call{api,func,args} => format!("CALL api={} func={} args={:?}", api, func, args),
                    Body::Gep{first,ops} => format!("GEP first={:?} ops={:?}", first, ops),
                    Body::Jmp(t) => format!("JMP {t}"),
                    Body::Branch{cond,t,f} => format!("BR {:?} t{t} f{f}", cond),
                    Body::Ret(o) => format!("RET {:?}", o),
                };
                println!("    op={:>2} dest={:>2} ty={:>2}  {}", ins.opcode, ins.dest, ins.ty, b);
            }
        }
    }
}
