mod nargo_tests {
    use luai::compiler::compile;
    use luai::noir::encoder::encode_program;
    use luai::parser::parse;
    use luai::types::table::{LuaKey, LuaTable};
    use luai::types::value::{LuaString, LuaValue};
    use luai::{HostInterface, OracleTape, Vm, VmConfig, VmOutput};
    use luai_noir::prover::NoirProver;
    use luai_noir::witness::build_witness;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::Instant;

    /// Every test in this module shares `noir/Prover.toml` and the `noir/target/`
    /// nargo+bb artifact directory. Serialise so parallel runners don't stomp.
    fn prover_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn circuit_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../noir")
    }

    fn run_lua(src: &str) -> (luai::noir::encoder::NoirBytecode, VmOutput) {
        run_lua_with_host(src, luai::NoopHost)
    }

    fn run_lua_with_host<H: HostInterface>(
        src: &str,
        host: H,
    ) -> (luai::noir::encoder::NoirBytecode, VmOutput) {
        let program = compile(&parse(src).unwrap()).unwrap();
        let bytecode = encode_program(&program).unwrap();
        let config = VmConfig {
            record_trace: true,
            ..VmConfig::default()
        };
        let output = Vm::new(config, host)
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

    /// A host that returns a fixed table `{value = 42}` for any tool call.
    struct FixedResponseHost;

    impl HostInterface for FixedResponseHost {
        fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
            let mut t = LuaTable::new();
            t.rawset(
                LuaKey::String(LuaString::from_str("value")),
                luai::types::value::LuaValue::Integer(42),
            )
            .unwrap();
            Ok(t)
        }
    }

    #[test]
    fn end_to_end_prove_and_verify() {
        let _lock = prover_lock();
        let (bytecode, output) = run_lua("return 1 + 2");
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let prove_start = Instant::now();
        let proof = prover.prove(&witness).expect("prove failed");
        let prove_elapsed = prove_start.elapsed();
        let verify_start = Instant::now();
        let verified = prover.verify(&proof).expect("verify failed");
        let verify_elapsed = verify_start.elapsed();
        eprintln!(
            "end_to_end_prove_and_verify: prove={:.2}s verify={:.2}s",
            prove_elapsed.as_secs_f64(),
            verify_elapsed.as_secs_f64()
        );
        assert!(verified, "proof should verify");
        assert_eq!(proof.public_inputs.program_hash, witness.program_hash);
        assert_ne!(proof.public_inputs.tool_responses_hash, [0u8; 32]);
    }

    #[test]
    fn tampered_return_value_fails_verify() {
        let _lock = prover_lock();
        let (bytecode, output) = run_lua("return 1 + 2");
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        let mut witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
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
        let _lock = prover_lock();
        let src = "local function add(a, b) return a + b end; return add(10, 32)";
        let (bytecode, output) = run_lua(src);
        let ret = return_i64(&output.return_value);
        assert_eq!(ret, 42);
        let tape = OracleTape::from_records(&output.transcript);
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "multi-function proof should verify");
        assert_eq!(proof.public_inputs.program_hash, witness.program_hash);
    }

    #[test]
    fn prove_with_tool_calls() {
        let _lock = prover_lock();
        // Program makes one tool call; the oracle tape carries the response.
        let src = "tool.call(\"kv_get\", {key = \"x\"}); return 1";
        let (bytecode, output) = run_lua_with_host(src, FixedResponseHost);
        let ret = return_i64(&output.return_value);
        assert_eq!(ret, 1);
        let tape = OracleTape::from_records(&output.transcript);
        assert!(!tape.is_empty(), "tape should have one entry");
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(witness.num_tool_calls, 1);
        assert_ne!(
            witness.tool_responses_hash, [0u8; 32],
            "tool_responses_hash must be non-zero"
        );
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "proof with tool calls should verify");
        assert_ne!(proof.public_inputs.tool_responses_hash, [0u8; 32]);
    }

    #[test]
    fn tampered_tape_entry_fails_verify() {
        let _lock = prover_lock();
        let src = "tool.call(\"kv_get\", {key = \"x\"}); return 1";
        let (bytecode, output) = run_lua_with_host(src, FixedResponseHost);
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        let mut witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        // Flip the first byte of the first tape entry payload.
        witness.tape_entry_data[0][0] ^= 0xFF;
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let result = prover.prove(&witness);
        match result {
            Ok(proof) => {
                let verified = prover.verify(&proof).unwrap_or(false);
                assert!(!verified, "tampered tape entry should not verify");
            }
            Err(_) => {
                // nargo execute/prove rejects the bad witness — also acceptable
            }
        }
    }

    #[test]
    fn no_tool_calls_zero_hash() {
        let _lock = prover_lock();
        // With no tool calls the commitment is Poseidon2 over zero leaves;
        // assert parity with the tape implementation rather than pinning bytes.
        let empty_hash = OracleTape::new().commitment_hash();
        let (bytecode, output) = run_lua("return 7");
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        assert!(tape.is_empty());
        let witness = build_witness(
            &bytecode,
            &output.trace,
            ret,
            &tape,
            &LuaValue::Nil,
            &output,
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(witness.num_tool_calls, 0);
        assert_eq!(witness.tool_responses_hash, empty_hash);
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "no-tool-call proof should verify");
        assert_eq!(proof.public_inputs.tool_responses_hash, empty_hash);
    }
}
