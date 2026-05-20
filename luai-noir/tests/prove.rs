#[cfg(feature = "nargo_integration")]
mod nargo_tests {
    use luai::compiler::compile;
    use luai::noir::encoder::encode_program;
    use luai::parser::parse;
    use luai::types::value::LuaValue;
    use luai::{NoopHost, Vm, VmConfig, VmOutput};
    use luai_noir::prover::NoirProver;
    use luai_noir::witness::build_witness;
    use std::path::PathBuf;

    fn circuit_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../noir")
    }

    fn run_lua(src: &str) -> (luai::noir::encoder::NoirBytecode, VmOutput) {
        let program = compile(&parse(src).unwrap()).unwrap();
        let bytecode = encode_program(&program).unwrap();
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };
        let output = Vm::new(config, NoopHost)
            .execute(&program, LuaValue::Nil)
            .unwrap();
        (bytecode, output)
    }

    fn return_i64(v: &LuaValue) -> i64 {
        match v {
            LuaValue::Integer(n) => *n,
            _ => 0,
        }
    }

    #[test]
    fn end_to_end_prove_and_verify() {
        let (bytecode, output) = run_lua("return 1 + 2");
        let ret = return_i64(&output.return_value);
        let witness = build_witness(&bytecode, &output.trace, ret).unwrap();
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "proof should verify");
        assert_eq!(proof.public_inputs.return_value, 3);
    }

    #[test]
    fn tampered_return_value_fails_verify() {
        let (bytecode, output) = run_lua("return 1 + 2");
        let ret = return_i64(&output.return_value);
        let mut witness = build_witness(&bytecode, &output.trace, ret).unwrap();
        witness.return_value = 999; // tamper
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let result = prover.prove(&witness);
        match result {
            Ok(proof) => {
                let verified = prover.verify(&proof).unwrap_or(false);
                assert!(!verified, "tampered proof should not verify");
            }
            Err(_) => {
                // nargo execute/prove fails on bad witness — also acceptable
            }
        }
    }

    #[test]
    fn multi_function_proves_correctly() {
        let src = "local function add(a, b) return a + b end; return add(10, 32)";
        let (bytecode, output) = run_lua(src);
        let ret = return_i64(&output.return_value);
        assert_eq!(ret, 42);
        let witness = build_witness(&bytecode, &output.trace, ret).unwrap();
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "multi-function proof should verify");
        assert_eq!(proof.public_inputs.return_value, 42);
    }
}
