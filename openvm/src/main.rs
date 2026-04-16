mod encoder;

use encoder::OpenVMInput;
use luai::{
    bytecode::verify,
    host::tape::TapeHost,
    tls::TlsAttestationRecord,
    types::value::LuaValue,
    vm::engine::{Vm, VmConfig},
    zkvm::commitment::compute_public_inputs,
};

// ── P-256 certificate chain verification ─────────────────────────────────────

/// Verify a DER-encoded P-256 certificate chain against Mozilla root CAs.
///
/// Returns `true` when:
/// 1. The leaf certificate's public key uses the P-256 curve (OID 1.2.840.10045.3.1.7).
/// 2. Each certificate's signature is valid under the next issuer's P-256 key.
/// 3. The root certificate's SubjectPublicKeyInfo matches a Mozilla trust anchor.
///
/// Returns `false` on any parse error, unsupported algorithm, or chain validation
/// failure. The caller treats `false` as "TLS attestation unavailable" and
/// contributes zero to the `tls_attestation_hash`.
fn verify_p256_chain(cert_chain_der: &[Vec<u8>]) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use x509_cert::Certificate;
    use x509_cert::der::{Decode, Encode};

    if cert_chain_der.is_empty() {
        return false;
    }

    // Parse every cert in the chain.
    let certs: Vec<Certificate> = match cert_chain_der
        .iter()
        .map(|der| Certificate::from_der(der.as_slice()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => return false,
    };

    // ── 1. Leaf cert must use P-256 public key ────────────────────────────────
    if !spki_is_p256(&certs[0]) {
        return false;
    }

    // ── 2. Verify each cert's signature against the next issuer's key ─────────
    for i in 0..certs.len().saturating_sub(1) {
        if !verify_cert_sig(&certs[i], &certs[i + 1]) {
            return false;
        }
    }

    // ── 3. Root cert SPKI must match a Mozilla trust anchor ───────────────────
    let root = &certs[certs.len() - 1];
    let root_spki_der = match root.tbs_certificate.subject_public_key_info.to_der() {
        Ok(b) => b,
        Err(_) => return false,
    };
    is_mozilla_root(&root_spki_der)
}

/// `true` when the certificate's SubjectPublicKeyInfo declares a P-256 public key.
///
/// Checks for algorithm OID `id-ecPublicKey` (1.2.840.10045.2.1) with
/// named-curve parameter OID `secp256r1` / `prime256v1` (1.2.840.10045.3.1.7).
fn spki_is_p256(cert: &x509_cert::Certificate) -> bool {
    use x509_cert::der::asn1::ObjectIdentifier;

    // id-ecPublicKey: 1.2.840.10045.2.1
    const ID_EC_PUBLIC_KEY: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    // prime256v1 / secp256r1: 1.2.840.10045.3.1.7
    const SECP256R1: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return false;
    }
    // The named curve OID is in the algorithm parameters.
    match &spki.algorithm.parameters {
        Some(params) => {
            // Parameters is an Any — decode as OID and compare.
            params.decode_as::<ObjectIdentifier>().map_or(false, |oid| oid == SECP256R1)
        }
        None => false,
    }
}

/// Verify `child`'s signature using `issuer`'s P-256 public key.
fn verify_cert_sig(child: &x509_cert::Certificate, issuer: &x509_cert::Certificate) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use x509_cert::der::Encode;

    // Get issuer's public key bytes (uncompressed SEC1 EC point).
    let parent_spki = &issuer.tbs_certificate.subject_public_key_info;
    let key_bytes = match parent_spki.subject_public_key.as_bytes() {
        Some(b) => b,
        None => return false,
    };
    let verify_key = match VerifyingKey::from_sec1_bytes(key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // Re-encode the TBSCertificate — this is the data that was signed.
    let tbs_der = match child.tbs_certificate.to_der() {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Extract the DER-encoded ECDSA signature from the cert's BIT STRING.
    let sig_bytes = match child.signature.as_bytes() {
        Some(b) => b,
        None => return false,
    };
    let sig = match Signature::from_der(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // `VerifyingKey::verify` hashes the message with SHA-256 internally.
    verify_key.verify(&tbs_der, &sig).is_ok()
}

/// `true` when `spki_der` matches a Mozilla root CA's SubjectPublicKeyInfo.
fn is_mozilla_root(spki_der: &[u8]) -> bool {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .any(|anchor| anchor.subject_public_key_info.as_ref() == spki_der)
}

/// Re-verify TLS attestation records in-guest.
///
/// For each record, if the raw DER cert chain passes `verify_p256_chain`,
/// the record is emitted with `p256_verified = true`. Otherwise the record
/// is emitted with `p256_verified = false` (unavailable). This ensures the
/// proof only commits a non-zero `tls_attestation_hash` when the P-256 chain
/// verification actually passes inside the zkVM.
fn reverify_attestations(records: &[TlsAttestationRecord]) -> Vec<TlsAttestationRecord> {
    records
        .iter()
        .map(|r| {
            if !r.cert_chain_der.is_empty() && verify_p256_chain(&r.cert_chain_der) {
                TlsAttestationRecord::p256_verified(r.cert_chain_der.clone())
            } else {
                TlsAttestationRecord::unavailable()
            }
        })
        .collect()
}

// ── Entry point ───────────────────────────────────────────────────────────────

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

    // Re-verify TLS attestations in-guest: P-256 ECDSA signatures must pass
    // here (inside the proof) not just in the prover host.
    let verified_attestations = reverify_attestations(&dry_run_result.tls_attestations);

    let public_inputs = compute_public_inputs(
        program.program_hash,
        &input_value,
        &dry_run_result.oracle_tape,
        &output,
        &verified_attestations,
    );

    assert!(public_inputs == dry_run_result.public_inputs);

    openvm::io::reveal_bytes32(public_inputs.program_hash);
    openvm::io::reveal_bytes32(public_inputs.input_hash);
    openvm::io::reveal_bytes32(public_inputs.tool_responses_hash);
    openvm::io::reveal_bytes32(public_inputs.output_hash);
    openvm::io::reveal_bytes32(public_inputs.tls_attestation_hash);
    openvm::io::reveal_bytes32(public_inputs.policy_hash);
}
