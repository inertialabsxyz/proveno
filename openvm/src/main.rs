mod encoder;

use encoder::OpenVMInput;
use luai::{
    bytecode::verify,
    host::tape::{TapeEntry, TapeHost},
    types::value::LuaValue,
    vm::engine::{Vm, VmConfig},
    zkvm::{commitment::compute_public_inputs, tls_verify::verify_tls_attestation},
};

#[allow(unused_imports)]
use openvm_p256::P256Point; // Required for sw_init! linkage

use openvm_algebra_guest::IntMod;
use openvm_ecc_guest::{ecdsa::verify_prehashed, weierstrass::WeierstrassPoint};
use openvm_p256::{NistP256, P256Coord};

openvm::init!("openvm_init.rs");

fn main() {
    let input = openvm::io::read::<OpenVMInput>();
    let program = input.compiled_program;
    let dry_run_result = input.dry_run_result;

    let vm_config = VmConfig::default();

    let input_value = LuaValue::Nil;
    println!("verify bytecode");
    verify(&program).expect("bytecode verification failed");

    let tape_host = TapeHost::new(dry_run_result.oracle_tape.clone());
    let mut vm = Vm::new(vm_config.clone(), tape_host);

    let output = vm
        .execute(&program, input_value.clone())
        .expect("VM execution failed");

    let public_inputs = compute_public_inputs(
        program.program_hash,
        &input_value,
        &dry_run_result.oracle_tape,
        &output,
    );

    println!("len={}", dry_run_result.oracle_tape.entries.len());
    // Verify TLS attestations for all tool calls with attestation data
    for entry in &dry_run_result.oracle_tape.entries {
        if let TapeEntry::Ok {
            tls_attestation: Some(att),
            ..
        } = entry
        {
            println!("entry = {:?}", entry);
            // Structural checks: cert chain, root trust, hostname match.
            // Returns ECDSA verification tasks for the caller to execute.
            let tasks = verify_tls_attestation(att).expect("TLS attestation verification failed");

            // Execute each ECDSA verification using hardware-accelerated P-256
            for task in &tasks {
                let x = P256Coord::from_be_bytes(&task.pubkey[1..33])
                    .expect("invalid P-256 x coordinate");
                let y = P256Coord::from_be_bytes(&task.pubkey[33..65])
                    .expect("invalid P-256 y coordinate");
                let pubkey = P256Point::from_xy(x, y).expect("public key not on P-256 curve");

                // verify_prehashed expects 64 bytes: r_be || s_be
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&task.sig_r);
                sig[32..].copy_from_slice(&task.sig_s);

                verify_prehashed::<NistP256>(pubkey, &task.message_hash, &sig)
                    .expect("P-256 ECDSA signature verification failed");
            }
        } else {
            println!("an error");
        }
    }

    assert!(public_inputs == dry_run_result.public_inputs);
    openvm::io::reveal_bytes32(public_inputs.program_hash);
    openvm::io::reveal_bytes32(public_inputs.input_hash);
    openvm::io::reveal_bytes32(public_inputs.tool_responses_hash);
    openvm::io::reveal_bytes32(public_inputs.output_hash);
    openvm::io::reveal_bytes32(public_inputs.tls_attestation_hash);
}
