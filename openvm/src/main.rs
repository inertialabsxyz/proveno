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

/// Verify a DER-encoded P-256 certificate chain against Mozilla root CAs,
/// and confirm that the leaf certificate covers `hostname`.
///
/// Returns `true` when:
/// 1. The leaf certificate's public key uses the P-256 curve (OID 1.2.840.10045.3.1.7).
/// 2. Each certificate's signature is valid under the next issuer's P-256 key.
/// 3. The root certificate's SubjectPublicKeyInfo matches a Mozilla trust anchor.
/// 4. The leaf certificate's Subject Alternative Names include `hostname`.
///
/// Returns `false` on any parse error, unsupported algorithm, hostname mismatch,
/// or chain validation failure. The caller treats `false` as "TLS attestation
/// unavailable" and contributes zero to the `tls_attestation_hash`.
fn verify_p256_chain(cert_chain_der: &[Vec<u8>], hostname: &str) -> bool {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

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
    if !is_mozilla_root(&root_spki_der) {
        return false;
    }

    // ── 4. Leaf cert SANs must cover the requested hostname ───────────────────
    hostname_matches_cert(hostname, &certs[0])
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

/// `true` when the leaf certificate's Subject Alternative Names include `hostname`.
///
/// Parses the SAN extension (OID 2.5.29.17) from the certificate's raw DER
/// bytes to extract dNSName entries. Wildcard patterns (`*.example.com`) are
/// matched against a single label. If no SAN extension is present, returns
/// `false` — CN fallback is not supported.
fn hostname_matches_cert(hostname: &str, cert: &x509_cert::Certificate) -> bool {
    use x509_cert::der::asn1::ObjectIdentifier;

    // OID for Subject Alternative Names: 2.5.29.17
    const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    let exts = match &cert.tbs_certificate.extensions {
        Some(e) => e,
        None => return false,
    };

    for ext in exts.iter() {
        if ext.extn_id != SAN_OID {
            continue;
        }
        // ext.extn_value is an OCTET STRING whose content is a DER-encoded
        // SEQUENCE OF GeneralName. Parse it with our minimal DER reader to
        // avoid lifetime and alloc complexity with x509-cert's GeneralName.
        return san_contains_hostname(ext.extn_value.as_bytes(), hostname);
    }

    // No SAN extension — CN fallback not supported for security reasons.
    false
}

/// Parse the DER bytes of a SubjectAltName extension value (a SEQUENCE OF
/// GeneralName) and return `true` if any dNSName entry matches `hostname`.
///
/// dNSName is encoded as context tag `[2]` (0x82) followed by IA5String bytes.
fn san_contains_hostname(san_der: &[u8], hostname: &str) -> bool {
    const DNS_NAME_TAG: u8 = 0x82; // [2] IMPLICIT IA5String

    let seq_content = match der_inner(san_der, 0x30) {
        Some(b) => b,
        None => return false,
    };

    let mut pos = 0;
    while pos < seq_content.len() {
        let (tag, content, total_len) = match der_read_tlv(&seq_content[pos..]) {
            Some(x) => x,
            None => break,
        };
        if tag == DNS_NAME_TAG {
            if let Ok(s) = core::str::from_utf8(content) {
                if dns_name_matches(s, hostname) {
                    return true;
                }
            }
        }
        pos += total_len;
    }
    false
}

/// Extract the content bytes of a DER TLV with the given tag.
/// Returns `None` on parse error or tag mismatch.
fn der_inner(data: &[u8], expected_tag: u8) -> Option<&[u8]> {
    if data.is_empty() || data[0] != expected_tag {
        return None;
    }
    let (len, header_len) = der_read_length(&data[1..])?;
    let end = 1 + header_len + len;
    if data.len() < end {
        return None;
    }
    Some(&data[1 + header_len..end])
}

/// Read one DER TLV from `data`. Returns `(tag, content, total_bytes_consumed)`.
fn der_read_tlv(data: &[u8]) -> Option<(u8, &[u8], usize)> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (len, header_len) = der_read_length(&data[1..])?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return None;
    }
    Some((tag, &data[1 + header_len..total], total))
}

/// Parse a DER length field. Returns `(length_value, bytes_consumed)`.
fn der_read_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        return Some((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if data.len() < 1 + num_bytes || num_bytes == 0 || num_bytes > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | (data[1 + i] as usize);
    }
    Some((len, 1 + num_bytes))
}

/// Case-insensitive DNS name matching with single-label wildcard support.
///
/// `*.example.com` matches `foo.example.com` but not `example.com` or
/// `foo.bar.example.com`. Exact matches are case-insensitive.
fn dns_name_matches(pattern: &str, hostname: &str) -> bool {
    if let Some(wc_suffix) = pattern.strip_prefix("*.") {
        // Wildcard: hostname must be exactly one dot-free label + "." + wc_suffix.
        if let Some(dot_pos) = hostname.find('.') {
            let label = &hostname[..dot_pos];
            let rest = &hostname[dot_pos + 1..];
            return !label.contains('.') && rest.eq_ignore_ascii_case(wc_suffix);
        }
        return false;
    }
    pattern.eq_ignore_ascii_case(hostname)
}

/// Extract the leaf certificate's `not_after` validity timestamp as Unix seconds.
/// Returns 0 on parse failure (cert already passed `verify_p256_chain`, so this
/// is a safety fallback).
fn extract_cert_not_after(cert_der: &[u8]) -> u64 {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    match Certificate::from_der(cert_der) {
        Ok(cert) => cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs(),
        Err(_) => 0,
    }
}

/// Re-verify TLS attestation records in-guest.
///
/// For each record, if the raw DER cert chain passes `verify_p256_chain`
/// (P-256 signatures + Mozilla root + hostname match), the record is emitted
/// with `p256_verified = true` and the guest-derived `cert_not_after`.
/// Otherwise the record is emitted as unavailable. This ensures the proof only
/// commits a non-zero `tls_attestation_hash` when all checks pass inside the
/// zkVM, and that the committed `cert_not_after` is extracted from the cert
/// itself (not trusted from the prover).
fn reverify_attestations(records: &[TlsAttestationRecord]) -> Vec<TlsAttestationRecord> {
    records
        .iter()
        .map(|r| {
            if r.cert_chain_der.is_empty() || r.hostname.is_empty() {
                return TlsAttestationRecord::unavailable();
            }
            if !verify_p256_chain(&r.cert_chain_der, &r.hostname) {
                return TlsAttestationRecord::unavailable();
            }
            // Re-derive not_after from the leaf cert DER so a malicious prover
            // cannot supply a forged timestamp.
            let not_after = extract_cert_not_after(&r.cert_chain_der[0]);
            TlsAttestationRecord::p256_verified(
                r.cert_chain_der.clone(),
                r.hostname.clone(),
                not_after,
            )
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_matches_exact() {
        assert!(dns_name_matches("example.com", "example.com"));
        assert!(dns_name_matches("Example.COM", "example.com")); // case-insensitive
        assert!(!dns_name_matches("other.com", "example.com"));
    }

    #[test]
    fn dns_name_matches_wildcard() {
        assert!(dns_name_matches("*.example.com", "foo.example.com"));
        assert!(dns_name_matches("*.example.com", "bar.example.com"));
        assert!(!dns_name_matches("*.example.com", "example.com")); // no bare label
        assert!(!dns_name_matches("*.example.com", "foo.bar.example.com")); // two labels
    }

    #[test]
    fn san_empty_gives_no_match() {
        // SEQUENCE {} — empty SAN
        let empty_seq = &[0x30u8, 0x00];
        assert!(!san_contains_hostname(empty_seq, "example.com"));
    }

    #[test]
    fn san_with_dns_name_matches() {
        // Build a minimal SAN DER: SEQUENCE { [2] "example.com" }
        let dns_bytes = b"example.com";
        let mut san = Vec::new();
        san.push(0x82u8); // [2] IMPLICIT IA5String
        san.push(dns_bytes.len() as u8);
        san.extend_from_slice(dns_bytes);
        let mut seq = Vec::new();
        seq.push(0x30u8);
        seq.push(san.len() as u8);
        seq.extend_from_slice(&san);
        assert!(san_contains_hostname(&seq, "example.com"));
        assert!(!san_contains_hostname(&seq, "other.com"));
    }
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

    // Re-verify TLS attestations in-guest: P-256 ECDSA signatures + hostname
    // match must pass here (inside the proof), not just in the prover host.
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
