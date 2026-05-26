//! P-256 certificate chain verification and TLS attestation re-verification.
//!
//! These functions run inside the zkVM guest (`reverify_attestations`) to ensure
//! that only cert chains which genuinely pass P-256 + Mozilla root + hostname
//! checks contribute to `tls_attestation_hash`.  Exposing them in the library
//! crate lets the test suite exercise the same code path against real certs
//! without running the full OpenVM proving pipeline.

use super::TlsAttestationRecord;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

// ── P-256 certificate chain verification ─────────────────────────────────────

/// Verify a DER-encoded P-256 certificate chain against Mozilla root CAs,
/// and confirm that the leaf certificate's SAN covers `hostname`.
///
/// Returns `true` when:
/// 1. The leaf certificate's public key uses the P-256 curve (OID 1.2.840.10045.3.1.7).
/// 2. Each certificate's signature is valid under the next issuer's P-256 key.
/// 3. The root certificate's SubjectPublicKeyInfo matches a Mozilla trust anchor.
/// 4. The leaf certificate's Subject Alternative Names include `hostname`.
///
/// Returns `false` on any parse error, unsupported algorithm, hostname mismatch,
/// or chain validation failure.
pub fn verify_p256_chain(cert_chain_der: &[Vec<u8>], hostname: &str) -> bool {
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
        if !verify_cert_sig(&cert_chain_der[i], &certs[i], &certs[i + 1]) {
            return false;
        }
    }

    // ── 3. Topmost cert must be signed by a Mozilla trust anchor ─────────────
    //      TLS servers send [leaf, intermediates...] — the root CA is NOT
    //      included since clients hold it in their local trust store.
    //      We verify that a Mozilla trust anchor can verify the last cert.
    //      Pass the original DER to avoid re-encoding drift in TBS bytes.
    let last_idx = certs.len() - 1;
    if !is_signed_by_mozilla_root(&cert_chain_der[last_idx], &certs[last_idx]) {
        return false;
    }

    // ── 4. Leaf cert SANs must cover the requested hostname ───────────────────
    hostname_matches_cert(hostname, &certs[0])
}

/// `true` when the certificate's SubjectPublicKeyInfo declares a P-256 public key.
fn spki_is_p256(cert: &x509_cert::Certificate) -> bool {
    use x509_cert::der::asn1::ObjectIdentifier;

    // id-ecPublicKey: 1.2.840.10045.2.1
    const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    // prime256v1 / secp256r1: 1.2.840.10045.3.1.7
    const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return false;
    }
    match &spki.algorithm.parameters {
        Some(params) => params
            .decode_as::<ObjectIdentifier>()
            .map_or(false, |oid| oid == SECP256R1),
        None => false,
    }
}

/// Verify `child_der`'s signature using `issuer`'s public key.
///
/// `child_der` is the original DER encoding of `child`; TBS bytes are
/// extracted directly from it to ensure bit-identical matching with the
/// signed bytes.
///
/// Dispatches on the issuer's key algorithm (EC P-256/P-384 or RSA) and the
/// child's signature algorithm (ECDSA-SHA2xx or SHA2xxWithRSAEncryption).
///
/// Returns `false` for any unsupported key type or signature algorithm.
fn verify_cert_sig(
    child_der: &[u8],
    child: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> bool {
    use x509_cert::der::asn1::ObjectIdentifier;

    // id-ecPublicKey  1.2.840.10045.2.1
    const EC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    // rsaEncryption   1.2.840.113549.1.1.1
    const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    // secp256r1 / P-256   1.2.840.10045.3.1.7
    const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    // secp384r1 / P-384   1.3.132.0.34
    const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_key_alg = issuer_spki.algorithm.oid;

    // Extract the original TBS bytes from child_der.
    let tbs_der = match extract_tbs_der(child_der) {
        Some(b) => b,
        None => return false,
    };
    let sig_bytes = match child.signature.as_bytes() {
        Some(b) => b,
        None => return false,
    };
    let sig_alg = child.signature_algorithm.oid;

    if issuer_key_alg == EC_OID {
        let key_bytes = match issuer_spki.subject_public_key.as_bytes() {
            Some(b) => b,
            None => return false,
        };
        // Detect the EC curve from the AlgorithmIdentifier parameters.
        let curve_oid = issuer_spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        match curve_oid {
            Some(c) if c == P256_OID => ecdsa_p256_verify(tbs_der, sig_bytes, sig_alg, key_bytes),
            Some(c) if c == P384_OID => ecdsa_p384_verify(tbs_der, sig_bytes, sig_alg, key_bytes),
            _ => false,
        }
    } else if issuer_key_alg == RSA_OID {
        verify_cert_sig_rsa(tbs_der, sig_bytes, sig_alg, issuer)
    } else {
        false
    }
}

/// Verify an ECDSA P-256 signature over `tbs_der` using the raw SEC1 public key bytes.
///
/// Dispatches on `sig_alg` to hash with SHA-256, SHA-384, or SHA-512.
/// For SHA-384 and SHA-512, the digest is truncated to 32 bytes (P-256 field
/// width) per the ECDSA specification before calling `verify_prehash`.
fn ecdsa_p256_verify(
    tbs_der: &[u8],
    sig_bytes: &[u8],
    sig_alg: x509_cert::der::asn1::ObjectIdentifier,
    key_bytes: &[u8],
) -> bool {
    use p256::ecdsa::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_cert::der::asn1::ObjectIdentifier;

    // ecdsa-with-SHA256  1.2.840.10045.4.3.2
    const SHA256_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    // ecdsa-with-SHA384  1.2.840.10045.4.3.3
    const SHA384_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    // ecdsa-with-SHA512  1.2.840.10045.4.3.4
    const SHA512_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    let vk = match VerifyingKey::from_sec1_bytes(key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Hash the TBS bytes and truncate to 32 bytes (P-256 scalar size).
    let prehash: [u8; 32] = if sig_alg == SHA256_ECDSA {
        Sha256::digest(tbs_der).into()
    } else if sig_alg == SHA384_ECDSA {
        let h = Sha384::digest(tbs_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h[..32]);
        out
    } else if sig_alg == SHA512_ECDSA {
        let h = Sha512::digest(tbs_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h[..32]);
        out
    } else {
        return false;
    };

    vk.verify_prehash(&prehash, &sig).is_ok()
}

/// Verify an ECDSA P-384 signature over `tbs_der` using the raw SEC1 public key bytes.
///
/// Dispatches on `sig_alg` to hash with SHA-256, SHA-384, or SHA-512.
/// Per the ECDSA spec, the hash is used directly if its bit length ≤ 384,
/// or truncated to the leftmost 48 bytes if longer.
fn ecdsa_p384_verify(
    tbs_der: &[u8],
    sig_bytes: &[u8],
    sig_alg: x509_cert::der::asn1::ObjectIdentifier,
    key_bytes: &[u8],
) -> bool {
    use p384::ecdsa::{Signature, VerifyingKey};
    use rsa::signature::hazmat::PrehashVerifier;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use x509_cert::der::asn1::ObjectIdentifier;

    const SHA256_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const SHA384_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    const SHA512_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    let vk = match VerifyingKey::from_sec1_bytes(key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Hash and produce a 48-byte prehash (P-384 scalar size).
    let prehash: [u8; 48] = if sig_alg == SHA256_ECDSA {
        // SHA-256 output is 32 bytes; pad with leading zeros to 48 bytes.
        let h = Sha256::digest(tbs_der);
        let mut out = [0u8; 48];
        out[16..].copy_from_slice(&h);
        out
    } else if sig_alg == SHA384_ECDSA {
        Sha384::digest(tbs_der).into()
    } else if sig_alg == SHA512_ECDSA {
        // SHA-512 output is 64 bytes; truncate to leftmost 48 bytes.
        let h = Sha512::digest(tbs_der);
        let mut out = [0u8; 48];
        out.copy_from_slice(&h[..48]);
        out
    } else {
        return false;
    };

    vk.verify_prehash(&prehash, &sig).is_ok()
}

/// Verify a signature over `tbs_der` using `issuer`'s RSA public key (PKCS#1 v1.5).
fn verify_cert_sig_rsa(
    tbs_der: &[u8],
    sig_bytes: &[u8],
    sig_alg: x509_cert::der::asn1::ObjectIdentifier,
    issuer: &x509_cert::Certificate,
) -> bool {
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
    use sha2::{Sha256, Sha384, Sha512};
    use x509_cert::der::asn1::ObjectIdentifier;

    // sha256WithRSAEncryption  1.2.840.113549.1.1.11
    const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    // sha384WithRSAEncryption  1.2.840.113549.1.1.12
    const SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    // sha512WithRSAEncryption  1.2.840.113549.1.1.13
    const SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    // Decode RSA public key from SubjectPublicKeyInfo key bytes (PKCS#1 DER).
    let key_bytes = match issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
    {
        Some(b) => b,
        None => return false,
    };
    let rsa_key = match RsaPublicKey::from_pkcs1_der(key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    if sig_alg == SHA256_RSA {
        let vk = VerifyingKey::<Sha256>::new(rsa_key);
        let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(&tbs_der, &sig).is_ok()
    } else if sig_alg == SHA384_RSA {
        let vk = VerifyingKey::<Sha384>::new(rsa_key);
        let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(&tbs_der, &sig).is_ok()
    } else if sig_alg == SHA512_RSA {
        let vk = VerifyingKey::<Sha512>::new(rsa_key);
        let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(&tbs_der, &sig).is_ok()
    } else {
        false // Unsupported RSA hash algorithm
    }
}

/// Extract the raw TBSCertificate DER bytes from a Certificate DER encoding.
///
/// Certificate ::= SEQUENCE { TBSCertificate, signatureAlgorithm, signature }
///
/// Returns a slice into `cert_der` pointing at the full TBSCertificate TLV
/// (including its SEQUENCE tag and length), which is the byte range that was
/// signed.  Returns `None` on parse failure.
fn extract_tbs_der(cert_der: &[u8]) -> Option<&[u8]> {
    // Strip outer Certificate SEQUENCE wrapper.
    if cert_der.len() < 2 || cert_der[0] != 0x30 {
        return None;
    }
    let (outer_len, outer_hdr) = der_read_length(&cert_der[1..])?;
    let inner_start = 1 + outer_hdr;
    if cert_der.len() < inner_start + outer_len {
        return None;
    }
    let inner = &cert_der[inner_start..inner_start + outer_len];

    // The first TLV in the Certificate body is the TBSCertificate SEQUENCE.
    if inner.len() < 2 || inner[0] != 0x30 {
        return None;
    }
    let (tbs_len, tbs_hdr) = der_read_length(&inner[1..])?;
    let tbs_total = 1 + tbs_hdr + tbs_len;
    if inner.len() < tbs_total {
        return None;
    }
    // Return the full TBS TLV (tag + length + content).
    Some(&inner[..tbs_total])
}

/// `true` when `cert` is trusted via a Mozilla trust anchor.
///
/// Two cases are accepted:
/// 1. `cert`'s SPKI inner content directly matches a trust anchor's SPKI
///    (i.e., `cert` IS a trusted root — e.g. a cross-signed root whose EC key
///    is independently trusted in the store).
/// 2. A trust anchor's key can verify `cert`'s signature (standard chain
///    validation: the trust anchor issued `cert`).
///
/// `cert_der` is the original DER for `cert`; TBS bytes are extracted from it
/// directly to avoid re-encoding drift during signature verification.
fn is_signed_by_mozilla_root(cert_der: &[u8], cert: &x509_cert::Certificate) -> bool {
    use x509_cert::der::{Encode, asn1::ObjectIdentifier};

    // ── Case 1: cert IS a trust anchor (SPKI direct match) ───────────────────
    // Trust anchors store SPKI as inner content (no outer SEQUENCE wrapper).
    // We strip the outer SEQUENCE from cert's SPKI to get the same format.
    if let Ok(full_spki) = cert.tbs_certificate.subject_public_key_info.to_der() {
        if let Some(inner_spki) = der_inner(&full_spki, 0x30) {
            if webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .any(|a| a.subject_public_key_info.as_ref() == inner_spki)
            {
                return true;
            }
        }
    }

    // ── Case 2: a trust anchor's key verifies cert's signature ───────────────
    const EC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    // Extract TBSCertificate bytes from the original DER so we use the exact
    // bytes that were signed, not a re-encoded representation.
    let tbs_der = match extract_tbs_der(cert_der) {
        Some(b) => b,
        None => return false,
    };
    let sig_bytes = match cert.signature.as_bytes() {
        Some(b) => b,
        None => return false,
    };
    let sig_alg = cert.signature_algorithm.oid;

    // Try every Mozilla trust anchor.
    for anchor in webpki_roots::TLS_SERVER_ROOTS.iter() {
        let spki_der = anchor.subject_public_key_info.as_ref();
        // Parse (key_alg_oid, key_bytes) from the DER-encoded SPKI.
        let (key_alg, key_bytes) = match spki_alg_and_key(spki_der) {
            Some(v) => v,
            None => continue,
        };

        if key_alg == EC_OID {
            // Try P-256 then P-384 — we don't know the anchor's curve from
            // the OID alone; one will fail parsing, the other may succeed.
            if ecdsa_p256_verify(tbs_der, sig_bytes, sig_alg, key_bytes)
                || ecdsa_p384_verify(tbs_der, sig_bytes, sig_alg, key_bytes)
            {
                return true;
            }
        } else if key_alg == RSA_OID {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::signature::Verifier;
            use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
            use sha2::{Sha256, Sha384, Sha512};

            let rsa_key = match RsaPublicKey::from_pkcs1_der(key_bytes) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let sig = match rsa::pkcs1v15::Signature::try_from(sig_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let ok = if sig_alg == SHA256_RSA {
                VerifyingKey::<Sha256>::new(rsa_key)
                    .verify(&tbs_der, &sig)
                    .is_ok()
            } else if sig_alg == SHA384_RSA {
                VerifyingKey::<Sha384>::new(rsa_key)
                    .verify(&tbs_der, &sig)
                    .is_ok()
            } else if sig_alg == SHA512_RSA {
                VerifyingKey::<Sha512>::new(rsa_key)
                    .verify(&tbs_der, &sig)
                    .is_ok()
            } else {
                false
            };
            if ok {
                return true;
            }
        }
    }
    false
}

/// Parse the content bytes of a SubjectPublicKeyInfo and return
/// (algorithm OID, raw public key bytes).  Returns `None` on any parse error.
///
/// `spki_inner` is the **inner content** of the SubjectPublicKeyInfo SEQUENCE —
/// i.e. the bytes that `webpki_roots::TrustAnchor::subject_public_key_info`
/// provides (they omit the outer SEQUENCE tag+length wrapper):
///
///   AlgorithmIdentifier   -- SEQUENCE { OID, optional params }
///   BIT STRING            -- public key, first byte = unused-bits count
///
/// `key_bytes` points into `spki_inner` with the leading unused-bits octet
/// of the BIT STRING stripped.
fn spki_alg_and_key(spki_inner: &[u8]) -> Option<(x509_cert::der::asn1::ObjectIdentifier, &[u8])> {
    use x509_cert::der::Decode;
    use x509_cert::der::asn1::ObjectIdentifier;

    // Minimal hand-rolled DER TLV reader.  Returns (content, remainder).
    fn tl(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        if data.len() < 2 || data[0] != tag {
            return None;
        }
        let (len, hdr) = if data[1] & 0x80 == 0 {
            (data[1] as usize, 2)
        } else {
            let nb = (data[1] & 0x7f) as usize;
            if data.len() < 2 + nb {
                return None;
            }
            let mut l = 0usize;
            for &b in &data[2..2 + nb] {
                l = l << 8 | b as usize;
            }
            (l, 2 + nb)
        };
        if data.len() < hdr + len {
            return None;
        }
        Some((&data[hdr..hdr + len], &data[hdr + len..]))
    }

    // spki_inner already omits the outer SEQUENCE wrapper —
    // parse AlgorithmIdentifier then BIT STRING directly.
    let (alg_seq, rest) = tl(spki_inner, 0x30)?; // AlgorithmIdentifier
    let (oid_bytes, _) = tl(alg_seq, 0x06)?; // OID
    let (bs, _) = tl(rest, 0x03)?; // BIT STRING
    if bs.is_empty() {
        return None;
    }
    let key_bytes = &bs[1..]; // strip unused-bits octet

    // Reconstruct full OID DER (tag + length + content) for from_der.
    let mut oid_der = Vec::with_capacity(2 + oid_bytes.len());
    oid_der.push(0x06);
    oid_der.push(oid_bytes.len() as u8);
    oid_der.extend_from_slice(oid_bytes);
    let oid = ObjectIdentifier::from_der(&oid_der).ok()?;

    Some((oid, key_bytes))
}

/// `true` when the leaf certificate's Subject Alternative Names include `hostname`.
///
/// Parses the SAN extension (OID 2.5.29.17) from the certificate's raw DER
/// bytes. If no SAN extension is present, returns `false` — CN fallback is
/// not supported.
pub fn hostname_matches_cert(hostname: &str, cert: &x509_cert::Certificate) -> bool {
    use x509_cert::der::asn1::ObjectIdentifier;

    const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    let exts = match &cert.tbs_certificate.extensions {
        Some(e) => e,
        None => return false,
    };

    for ext in exts.iter() {
        if ext.extn_id != SAN_OID {
            continue;
        }
        return san_contains_hostname(ext.extn_value.as_bytes(), hostname);
    }

    false
}

/// Parse the DER bytes of a SubjectAltName extension value (a SEQUENCE OF
/// GeneralName) and return `true` if any dNSName entry matches `hostname`.
///
/// dNSName is encoded as context tag `[2]` (0x82) followed by IA5String bytes.
pub fn san_contains_hostname(san_der: &[u8], hostname: &str) -> bool {
    const DNS_NAME_TAG: u8 = 0x82;

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
pub fn dns_name_matches(pattern: &str, hostname: &str) -> bool {
    if let Some(wc_suffix) = pattern.strip_prefix("*.") {
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
/// Returns 0 on parse failure.
pub fn extract_cert_not_after(cert_der: &[u8]) -> u64 {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    match Certificate::from_der(cert_der) {
        Ok(cert) => cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        Err(_) => 0,
    }
}

/// Extract the P-256 public-key x and y affine coordinates from a DER-encoded
/// certificate. Returns `None` when the cert cannot be parsed, the SPKI is not
/// P-256, or the SubjectPublicKey is not a 65-byte uncompressed SEC1 point.
///
/// The 32-byte halves are exactly the bytes the Noir circuit hashes for
/// `tls_attestation_hash`; both sides commit to the same content.
pub fn extract_p256_pubkey_xy(cert_der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    let cert = Certificate::from_der(cert_der).ok()?;
    if !spki_is_p256(&cert) {
        return None;
    }
    let key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()?;
    // Uncompressed SEC1 encoding: 0x04 || x[32] || y[32]
    if key_bytes.len() != 65 || key_bytes[0] != 0x04 {
        return None;
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&key_bytes[1..33]);
    y.copy_from_slice(&key_bytes[33..65]);
    Some((x, y))
}

/// Re-verify TLS attestation records, producing a clean set suitable for hashing.
///
/// For each record, independently runs P-256 + Mozilla root + hostname checks
/// and re-derives `cert_not_after` from the cert DER. This is the same logic
/// the zkVM guest executes; exposing it here lets the test suite verify it
/// against real cert chains without running the full proving pipeline.
pub fn reverify_attestations(records: &[TlsAttestationRecord]) -> Vec<TlsAttestationRecord> {
    records
        .iter()
        .map(|r| {
            if r.cert_chain_der.is_empty() || r.hostname.is_empty() {
                return TlsAttestationRecord::unavailable();
            }
            if !verify_p256_chain(&r.cert_chain_der, &r.hostname) {
                return TlsAttestationRecord::unavailable();
            }
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
