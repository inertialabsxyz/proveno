use proveno::compiler::compile;
use proveno::noir::encoder::encode_program;
use proveno::parser::parse;
use proveno::types::value::LuaValue;
use proveno::zkvm::commitment::compute_public_inputs;
use proveno::{NoopHost, OracleTape, Vm, VmConfig};
use proveno_noir::witness::build_witness;

#[test]
fn noir_and_openvm_produce_identical_public_inputs() {
    let src = "return 1 + 2";
    let program = compile(&parse(src).unwrap()).unwrap();
    let bytecode = encode_program(&program).unwrap();
    let config = VmConfig {
        record_trace: true,
        ..VmConfig::default()
    };
    let input_value = LuaValue::Nil;
    let output = Vm::new(config, NoopHost)
        .execute(&program, input_value.clone())
        .unwrap();
    let tape = OracleTape::from_records(&output.transcript);
    let program_hash = bytecode.program_hash;

    // OpenVM public inputs path.
    let openvm_pi = compute_public_inputs(program_hash, &input_value, &tape, &output);

    // Noir witness path.
    let ret = match &output.return_value {
        LuaValue::Integer(n) => *n,
        _ => 0,
    };
    let witness = build_witness(
        &bytecode,
        &output.trace,
        ret,
        &tape,
        &input_value,
        &output,
        [0u8; 32],
    )
    .unwrap();

    assert_eq!(
        witness.program_hash, openvm_pi.program_hash,
        "program_hash mismatch"
    );
    assert_eq!(
        witness.input_hash, openvm_pi.input_hash,
        "input_hash mismatch"
    );
    assert_eq!(
        witness.tool_responses_hash, openvm_pi.tool_responses_hash,
        "tool_responses_hash mismatch"
    );
    assert_eq!(
        witness.output_hash, openvm_pi.output_hash,
        "output_hash mismatch"
    );
    assert_eq!(
        witness.attestation_hash, openvm_pi.attestation_hash,
        "attestation_hash mismatch"
    );
    assert_eq!(
        witness.policy_hash, openvm_pi.policy_hash,
        "policy_hash mismatch"
    );
}
