#[cfg(feature = "nargo_integration")]
mod nargo_tests {
    use luai::compiler::compile;
    use luai::noir::encoder::encode_program;
    use luai::parser::parse;
    use luai::types::table::LuaTable;
    use luai::types::value::LuaValue;
    use luai::{HostInterface, OracleTape, Vm, VmConfig, VmOutput};
    use luai_noir::prover::NoirProver;
    use luai_noir::witness::build_witness;
    use std::path::PathBuf;

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
                luai::types::value::LuaValue::from("value"),
                luai::types::value::LuaValue::Integer(42),
            );
            Ok(t)
        }
    }

    #[test]
    fn end_to_end_prove_and_verify() {
        let (bytecode, output) = run_lua("return 1 + 2");
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        let witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
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
        let tape = OracleTape::from_records(&output.transcript);
        let mut witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
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
        let tape = OracleTape::from_records(&output.transcript);
        let witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "multi-function proof should verify");
        assert_eq!(proof.public_inputs.return_value, 42);
    }

    #[test]
    fn prove_with_tool_calls() {
        // Program makes one tool call; the oracle tape carries the response.
        let src = "tool.call(\"kv_get\", {key = \"x\"}); return 1";
        let (bytecode, output) = run_lua_with_host(src, FixedResponseHost);
        let ret = return_i64(&output.return_value);
        assert_eq!(ret, 1);
        let tape = OracleTape::from_records(&output.transcript);
        assert!(!tape.is_empty(), "tape should have one entry");
        let witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
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
        let src = "tool.call(\"kv_get\", {key = \"x\"}); return 1";
        let (bytecode, output) = run_lua_with_host(src, FixedResponseHost);
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        let mut witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
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
        // SHA-256 of empty input (no tool calls → commitment_hash over empty sequence).
        let sha256_empty: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let (bytecode, output) = run_lua("return 7");
        let ret = return_i64(&output.return_value);
        let tape = OracleTape::from_records(&output.transcript);
        assert!(tape.is_empty());
        let witness = build_witness(&bytecode, &output.trace, ret, &tape).unwrap();
        assert_eq!(witness.num_tool_calls, 0);
        assert_eq!(witness.tool_responses_hash, sha256_empty);
        let prover = NoirProver {
            circuit_dir: circuit_dir(),
        };
        let proof = prover.prove(&witness).expect("prove failed");
        let verified = prover.verify(&proof).expect("verify failed");
        assert!(verified, "no-tool-call proof should verify");
        assert_eq!(proof.public_inputs.tool_responses_hash, sha256_empty);
    }
}
