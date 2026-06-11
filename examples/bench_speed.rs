use proveno::{
    bytecode::verify,
    compiler::compile,
    parser::parse,
    types::value::LuaValue,
    vm::engine::{NoopHost, Vm, VmConfig},
};
use std::time::Instant;

fn run_bench(name: &str, src: &str, iters: u32) {
    let block = parse(src).expect("parse");
    let program = compile(&block).expect("compile");
    verify(&program).expect("verify");

    let make_config = || VmConfig {
        gas_limit: u64::MAX,
        memory_limit_bytes: u64::MAX,
        ..VmConfig::default()
    };

    // warmup
    {
        let mut vm = Vm::new(make_config(), NoopHost);
        vm.execute(&program, LuaValue::Nil).expect("warmup");
    }

    let start = Instant::now();
    for _ in 0..iters {
        let config = make_config();
        let mut vm = Vm::new(config, NoopHost);
        vm.execute(&program, LuaValue::Nil).expect("execute");
    }
    let elapsed = start.elapsed();

    let ms_total = elapsed.as_secs_f64() * 1000.0;
    let ms_per = ms_total / iters as f64;
    println!("{name:<14} {iters:>4} iters  {ms_total:>8.1}ms total  {ms_per:>8.3}ms/iter");
}

fn main() {
    println!("=== proveno (Rust) ===");

    run_bench(
        "loop-100k",
        r#"
local sum = 0
for i = 1, 100000 do
    sum = sum + i
end
return sum
"#,
        100,
    );

    run_bench(
        "fib(28)",
        r#"
local function fib(n)
    if n <= 1 then return n end
    return fib(n-1) + fib(n-2)
end
return fib(28)
"#,
        10,
    );
}
