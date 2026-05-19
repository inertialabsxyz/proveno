mod encoder;

use encoder::OpenVMInput;
use luai::{
    bytecode::verify,
    host::tape::TapeHost,
    tls::verify::{reverify_attestations, verify_p256_chain},
    types::value::LuaValue,
    vm::engine::{Vm, VmConfig},
    zkvm::commitment::compute_public_inputs,
};

fn main() {
    let input = openvm::io::read::<OpenVMInput>();
    let program = input.compiled_program;
    let dry_run_result = input.dry_run_result;

    let vm_config = VmConfig::default();
    let input_value = LuaValue::Nil;

    verify(&program).expect("bytecode verification failed");

    let tape_host = TapeHost::new(dry_run_result.oracle_tape.clone());
    let mut vm = Vm::new(vm_config.clone(), tape_host);

    let output = vm
        .execute(&program, input_value.clone())
        .expect("VM execution failed");

    // Re-verify TLS attestations in-guest: P-256 ECDSA signatures + hostname
    // match must pass here (inside the proof), not just in the prover host.
    let verified_attestations = reverify_attestations(&dry_run_result.tls_attestations);

    let mut public_inputs = compute_public_inputs(
        program.program_hash,
        &input_value,
        &dry_run_result.oracle_tape,
        &output,
        &verified_attestations,
    );
    // The prover commits to the policy hash; the guest copies it and reveals it.
    // The on-chain LuaiVerifier checks it. The guest does not re-derive it from
    // a policy document because the policy is not part of the guest's input.
    public_inputs.policy_hash = dry_run_result.public_inputs.policy_hash;

    assert!(public_inputs == dry_run_result.public_inputs);

    openvm::io::reveal_bytes32(public_inputs.program_hash);
    openvm::io::reveal_bytes32(public_inputs.input_hash);
    openvm::io::reveal_bytes32(public_inputs.tool_responses_hash);
    openvm::io::reveal_bytes32(public_inputs.output_hash);
    openvm::io::reveal_bytes32(public_inputs.tls_attestation_hash);
    openvm::io::reveal_bytes32(public_inputs.policy_hash);
}
