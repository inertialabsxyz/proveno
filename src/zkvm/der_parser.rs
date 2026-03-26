//! Minimal DER/X.509 parser for extracting P-256 public keys, SAN DNS names,
//! and TBS/signature fields from certificates.
//!
//! This parser handles only the subset of ASN.1 DER encoding needed for TLS
//! attestation verification: enough to navigate X.509 v3 certificate structures,
//! extract SubjectPublicKeyInfo for P-256 keys, and read SAN extensions.
//!
//! `no_std`-compatible.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

/// ASN.1 DER tag constants.
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
// const TAG_SET: u8 = 0x31;

/// Context-specific constructed tag [0] (X.509 version).
const TAG_CTX_0: u8 = 0xA0;
/// Context-specific constructed tag [3] (X.509 extensions).
const TAG_CTX_3: u8 = 0xA3;
/// Context-specific primitive tag [2] (dNSName in SAN).
const TAG_CTX_2_PRIM: u8 = 0x82;

/// OID for id-ecPublicKey (1.2.840.10045.2.1)
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// OID for secp256r1 / prime256v1 (1.2.840.10045.3.1.7)
const OID_SECP256R1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// OID for subjectAltName (2.5.29.17)
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

#[derive(Debug)]
pub enum DerError {
    /// Unexpected end of input.
    Truncated,
    /// Expected a different tag.
    UnexpectedTag { expected: u8, found: u8 },
    /// Indefinite-length encoding (not DER).
    IndefiniteLength,
    /// Length exceeds remaining input.
    LengthOverflow,
    /// The certificate is not a P-256 key.
    NotP256,
    /// Required field not found.
    NotFound,
}

/// Parse a DER tag-length header. Returns `(tag, content_slice, rest)`.
pub fn parse_tl(input: &[u8]) -> Result<(u8, &[u8], &[u8]), DerError> {
    if input.is_empty() {
        return Err(DerError::Truncated);
    }
    let tag = input[0];
    let (len, header_len) = parse_length(&input[1..])?;
    let total_header = 1 + header_len;
    if input.len() < total_header + len {
        return Err(DerError::LengthOverflow);
    }
    let content = &input[total_header..total_header + len];
    let rest = &input[total_header + len..];
    Ok((tag, content, rest))
}

/// Parse DER length bytes. Returns `(length_value, bytes_consumed)`.
fn parse_length(input: &[u8]) -> Result<(usize, usize), DerError> {
    if input.is_empty() {
        return Err(DerError::Truncated);
    }
    let first = input[0];
    if first == 0x80 {
        return Err(DerError::IndefiniteLength);
    }
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes > 4 || input.len() < 1 + num_bytes {
        return Err(DerError::Truncated);
    }
    let mut len: usize = 0;
    for i in 0..num_bytes {
        len = len.checked_shl(8).ok_or(DerError::LengthOverflow)?;
        len |= input[1 + i] as usize;
    }
    Ok((len, 1 + num_bytes))
}

/// Parse a SEQUENCE tag-length, returning the inner content.
fn expect_sequence(input: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    let (tag, content, rest) = parse_tl(input)?;
    if tag != TAG_SEQUENCE {
        return Err(DerError::UnexpectedTag {
            expected: TAG_SEQUENCE,
            found: tag,
        });
    }
    Ok((content, rest))
}

/// Skip one TLV element, returning the rest of the input.
fn skip_tlv(input: &[u8]) -> Result<&[u8], DerError> {
    let (_, _, rest) = parse_tl(input)?;
    Ok(rest)
}

/// Extract the uncompressed P-256 public key (65 bytes: 0x04 || x || y) from a
/// DER-encoded X.509 certificate.
///
/// Navigates: Certificate → TBSCertificate → SubjectPublicKeyInfo → BIT STRING.
/// Verifies that the algorithm is id-ecPublicKey with secp256r1 parameters.
pub fn extract_p256_pubkey(cert_der: &[u8]) -> Result<[u8; 65], DerError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_inner, _) = expect_sequence(cert_der)?;

    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    let (tbs_inner, _) = expect_sequence(cert_inner)?;

    let mut pos = tbs_inner;

    // Optional version [0] EXPLICIT
    if !pos.is_empty() && pos[0] == TAG_CTX_0 {
        pos = skip_tlv(pos)?;
    }

    // serialNumber INTEGER
    pos = skip_tlv(pos)?;
    // signature AlgorithmIdentifier SEQUENCE
    pos = skip_tlv(pos)?;
    // issuer Name SEQUENCE
    pos = skip_tlv(pos)?;
    // validity Validity SEQUENCE
    pos = skip_tlv(pos)?;
    // subject Name SEQUENCE
    pos = skip_tlv(pos)?;

    // subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE
    let (spki_inner, _) = expect_sequence(pos)?;

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    // AlgorithmIdentifier for EC: SEQUENCE { OID id-ecPublicKey, OID namedCurve }
    let (alg_inner, spki_rest) = expect_sequence(spki_inner)?;

    // Check algorithm OID
    let (tag, oid_content, alg_rest) = parse_tl(alg_inner)?;
    if tag != TAG_OID {
        return Err(DerError::UnexpectedTag {
            expected: TAG_OID,
            found: tag,
        });
    }
    if oid_content != OID_EC_PUBLIC_KEY {
        return Err(DerError::NotP256);
    }

    // Check curve OID
    let (tag, curve_oid, _) = parse_tl(alg_rest)?;
    if tag != TAG_OID {
        return Err(DerError::UnexpectedTag {
            expected: TAG_OID,
            found: tag,
        });
    }
    if curve_oid != OID_SECP256R1 {
        return Err(DerError::NotP256);
    }

    // subjectPublicKey BIT STRING
    let (tag, bitstring_content, _) = parse_tl(spki_rest)?;
    if tag != TAG_BIT_STRING {
        return Err(DerError::UnexpectedTag {
            expected: TAG_BIT_STRING,
            found: tag,
        });
    }

    // BIT STRING: first byte is unused bits count (should be 0 for keys)
    if bitstring_content.is_empty() || bitstring_content[0] != 0x00 {
        return Err(DerError::NotP256);
    }
    let key_bytes = &bitstring_content[1..];
    if key_bytes.len() != 65 || key_bytes[0] != 0x04 {
        return Err(DerError::NotP256);
    }

    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(key_bytes);
    Ok(pubkey)
}

/// Extract SAN (Subject Alternative Name) DNS names from a DER-encoded X.509 certificate.
///
/// Returns a list of DNS names as byte slices from the SAN extension.
pub fn extract_san_dns_names(cert_der: &[u8]) -> Result<Vec<Vec<u8>>, DerError> {
    // Certificate → TBSCertificate
    let (cert_inner, _) = expect_sequence(cert_der)?;
    let (tbs_inner, _) = expect_sequence(cert_inner)?;

    let mut pos = tbs_inner;

    // Skip to extensions: version?, serialNumber, signature, issuer, validity, subject, spki
    if !pos.is_empty() && pos[0] == TAG_CTX_0 {
        pos = skip_tlv(pos)?;
    }
    pos = skip_tlv(pos)?; // serialNumber
    pos = skip_tlv(pos)?; // signature
    pos = skip_tlv(pos)?; // issuer
    pos = skip_tlv(pos)?; // validity
    pos = skip_tlv(pos)?; // subject
    pos = skip_tlv(pos)?; // subjectPublicKeyInfo

    // Optional issuerUniqueID [1], subjectUniqueID [2]
    while !pos.is_empty() && (pos[0] == 0xA1 || pos[0] == 0xA2) {
        pos = skip_tlv(pos)?;
    }

    // extensions [3] EXPLICIT
    if pos.is_empty() || pos[0] != TAG_CTX_3 {
        return Ok(vec![]);
    }
    let (_, ext_content, _) = parse_tl(pos)?;

    // Extensions ::= SEQUENCE OF Extension
    let (extensions_inner, _) = expect_sequence(ext_content)?;

    let mut ext_pos = extensions_inner;
    while !ext_pos.is_empty() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
        let (ext_inner, rest) = expect_sequence(ext_pos)?;
        ext_pos = rest;

        let (tag, oid, ext_rest) = parse_tl(ext_inner)?;
        if tag != TAG_OID {
            continue;
        }

        if oid != OID_SUBJECT_ALT_NAME {
            continue;
        }

        // Skip optional critical BOOLEAN
        let mut val_pos = ext_rest;
        if !val_pos.is_empty() && val_pos[0] == 0x01 {
            val_pos = skip_tlv(val_pos)?;
        }

        // extnValue OCTET STRING containing DER-encoded GeneralNames
        let (tag, octet_content, _) = parse_tl(val_pos)?;
        if tag != TAG_OCTET_STRING {
            return Ok(vec![]);
        }

        // GeneralNames ::= SEQUENCE OF GeneralName
        let (san_inner, _) = expect_sequence(octet_content)?;

        let mut names = Vec::new();
        let mut san_pos = san_inner;
        while !san_pos.is_empty() {
            let (tag, content, rest) = parse_tl(san_pos)?;
            san_pos = rest;
            // dNSName [2] IA5String
            if tag == TAG_CTX_2_PRIM {
                names.push(content.to_vec());
            }
        }
        return Ok(names);
    }

    Ok(vec![])
}

/// Extract the TBS (To Be Signed) data and the signature value from a DER-encoded certificate.
///
/// Returns `(tbs_der, signature_algorithm_der, signature_bytes)`.
/// - `tbs_der` is the raw DER bytes of the TBSCertificate (including tag+length).
/// - `signature_bytes` is the raw signature value (BIT STRING content, minus unused-bits byte).
pub fn extract_tbs_and_signature(cert_der: &[u8]) -> Result<(&[u8], &[u8]), DerError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_inner, _) = expect_sequence(cert_der)?;

    // Parse TBSCertificate — we need its raw bytes (tag+length+content)
    let (_, _tbs_content, after_tbs) = parse_tl(cert_inner)?;
    // The TBS raw bytes include the tag and length
    let tbs_len = cert_inner.len() - after_tbs.len();
    let tbs_der = &cert_inner[..tbs_len];

    // Skip signatureAlgorithm SEQUENCE
    let after_alg = skip_tlv(after_tbs)?;

    // signatureValue BIT STRING
    let (tag, sig_content, _) = parse_tl(after_alg)?;
    if tag != TAG_BIT_STRING {
        return Err(DerError::UnexpectedTag {
            expected: TAG_BIT_STRING,
            found: tag,
        });
    }

    // First byte of BIT STRING is unused bits count
    if sig_content.is_empty() {
        return Err(DerError::Truncated);
    }
    let sig_bytes = &sig_content[1..];

    Ok((tbs_der, sig_bytes))
}

/// Parse a DER-encoded ECDSA signature into (r, s) as 32-byte big-endian arrays.
///
/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
pub fn parse_ecdsa_signature(sig_der: &[u8]) -> Result<([u8; 32], [u8; 32]), DerError> {
    let (inner, _) = expect_sequence(sig_der)?;

    let (tag, r_content, rest) = parse_tl(inner)?;
    if tag != TAG_INTEGER {
        return Err(DerError::UnexpectedTag {
            expected: TAG_INTEGER,
            found: tag,
        });
    }

    let (tag, s_content, _) = parse_tl(rest)?;
    if tag != TAG_INTEGER {
        return Err(DerError::UnexpectedTag {
            expected: TAG_INTEGER,
            found: tag,
        });
    }

    Ok((integer_to_32(r_content)?, integer_to_32(s_content)?))
}

/// Convert a DER INTEGER (which may have a leading 0x00 padding byte) to a 32-byte big-endian array.
fn integer_to_32(bytes: &[u8]) -> Result<[u8; 32], DerError> {
    // Strip leading zero padding
    let stripped = if bytes.first() == Some(&0x00) && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    };
    if stripped.len() > 32 {
        return Err(DerError::LengthOverflow);
    }
    let mut out = [0u8; 32];
    out[32 - stripped.len()..].copy_from_slice(stripped);
    Ok(out)
}

/// Build a minimal self-signed P-256 certificate DER for testing.
/// Exposed for use by tls_verify tests.
#[cfg(test)]
pub fn build_test_cert_for_testing(pubkey: &[u8; 65], dns_names: &[&str]) -> Vec<u8> {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else if content.len() < 0x100 {
            out.push(0x81);
            out.push(content.len() as u8);
        } else {
            out.push(0x82);
            out.push((content.len() >> 8) as u8);
            out.push(content.len() as u8);
        }
        out.extend_from_slice(content);
        out
    }
    fn seq(content: &[u8]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, content)
    }
    fn oid(bytes: &[u8]) -> Vec<u8> {
        tlv(TAG_OID, bytes)
    }
    fn integer(val: &[u8]) -> Vec<u8> {
        tlv(TAG_INTEGER, val)
    }

    let version = tlv(TAG_CTX_0, &integer(&[0x02]));
    let serial = integer(&[0x01]);
    let sig_alg = seq(&oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]));
    let issuer = seq(&[]);
    let utc_time = |s: &[u8]| tlv(0x17, s);
    let validity = seq(
        &[utc_time(b"240101000000Z"), utc_time(b"340101000000Z")].concat(),
    );
    let subject = seq(&[]);
    let alg_id = seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_SECP256R1)].concat());
    let mut bs_content = vec![0x00];
    bs_content.extend_from_slice(pubkey);
    let spki = seq(&[alg_id, tlv(TAG_BIT_STRING, &bs_content)].concat());

    let mut san_names_content = Vec::new();
    for name in dns_names {
        san_names_content.extend_from_slice(&tlv(TAG_CTX_2_PRIM, name.as_bytes()));
    }
    let san_value = seq(&san_names_content);
    let san_ext = seq(
        &[oid(OID_SUBJECT_ALT_NAME), tlv(TAG_OCTET_STRING, &san_value)].concat(),
    );
    let extensions = tlv(TAG_CTX_3, &seq(&san_ext));

    let tbs = seq(
        &[
            version, serial, sig_alg.clone(), issuer, validity, subject, spki, extensions,
        ]
        .concat(),
    );

    let sig_value = tlv(TAG_BIT_STRING, &[0x00, 0x30, 0x00]);
    seq(&[tbs, sig_alg, sig_value].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal self-signed P-256 certificate DER for testing.
    fn build_test_cert(pubkey: &[u8; 65], dns_names: &[&str]) -> Vec<u8> {
        // Helper: wrap content in a TLV
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 0x80 {
                out.push(content.len() as u8);
            } else if content.len() < 0x100 {
                out.push(0x81);
                out.push(content.len() as u8);
            } else {
                out.push(0x82);
                out.push((content.len() >> 8) as u8);
                out.push(content.len() as u8);
            }
            out.extend_from_slice(content);
            out
        }
        fn seq(content: &[u8]) -> Vec<u8> {
            tlv(TAG_SEQUENCE, content)
        }
        fn oid(bytes: &[u8]) -> Vec<u8> {
            tlv(TAG_OID, bytes)
        }
        fn integer(val: &[u8]) -> Vec<u8> {
            tlv(TAG_INTEGER, val)
        }

        // version [0] EXPLICIT INTEGER 2 (v3)
        let version = tlv(TAG_CTX_0, &integer(&[0x02]));
        // serialNumber
        let serial = integer(&[0x01]);
        // signature AlgorithmIdentifier (placeholder)
        let sig_alg = seq(&oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])); // ecdsaWithSHA256
        // issuer (empty SEQUENCE)
        let issuer = seq(&[]);
        // validity (two dummy UTCTime values)
        let utc_time = |s: &[u8]| tlv(0x17, s);
        let validity = seq(
            &[
                utc_time(b"240101000000Z"),
                utc_time(b"340101000000Z"),
            ]
            .concat(),
        );
        // subject (empty SEQUENCE)
        let subject = seq(&[]);

        // SubjectPublicKeyInfo for P-256
        let alg_id = seq(
            &[oid(OID_EC_PUBLIC_KEY), oid(OID_SECP256R1)].concat(),
        );
        let mut bs_content = vec![0x00]; // unused bits = 0
        bs_content.extend_from_slice(pubkey);
        let spki = seq(&[alg_id, tlv(TAG_BIT_STRING, &bs_content)].concat());

        // Extensions [3]
        let mut san_names_content = Vec::new();
        for name in dns_names {
            san_names_content.extend_from_slice(&tlv(TAG_CTX_2_PRIM, name.as_bytes()));
        }
        let san_value = seq(&san_names_content);
        let san_ext = seq(
            &[
                oid(OID_SUBJECT_ALT_NAME),
                tlv(TAG_OCTET_STRING, &san_value),
            ]
            .concat(),
        );
        let extensions = tlv(TAG_CTX_3, &seq(&san_ext));

        // TBSCertificate
        let tbs = seq(
            &[
                version, serial, sig_alg.clone(), issuer, validity, subject, spki, extensions,
            ]
            .concat(),
        );

        // signatureValue (dummy)
        let sig_value = tlv(TAG_BIT_STRING, &[0x00, 0x30, 0x00]); // dummy signature

        // Certificate
        seq(&[tbs, sig_alg, sig_value].concat())
    }

    fn dummy_pubkey() -> [u8; 65] {
        let mut key = [0u8; 65];
        key[0] = 0x04; // uncompressed point prefix
        key[1] = 0x01; // dummy x
        key[33] = 0x02; // dummy y
        key
    }

    #[test]
    fn extract_pubkey_from_test_cert() {
        let pk = dummy_pubkey();
        let cert = build_test_cert(&pk, &["example.com"]);
        let extracted = extract_p256_pubkey(&cert).unwrap();
        assert_eq!(extracted, pk);
    }

    #[test]
    fn extract_san_dns_names_single() {
        let cert = build_test_cert(&dummy_pubkey(), &["example.com"]);
        let names = extract_san_dns_names(&cert).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(&names[0], b"example.com");
    }

    #[test]
    fn extract_san_dns_names_multiple() {
        let cert = build_test_cert(&dummy_pubkey(), &["example.com", "*.example.com", "api.example.com"]);
        let names = extract_san_dns_names(&cert).unwrap();
        assert_eq!(names.len(), 3);
        assert_eq!(&names[0], b"example.com");
        assert_eq!(&names[1], b"*.example.com");
        assert_eq!(&names[2], b"api.example.com");
    }

    #[test]
    fn extract_san_no_names() {
        let cert = build_test_cert(&dummy_pubkey(), &[]);
        let names = extract_san_dns_names(&cert).unwrap();
        assert_eq!(names.len(), 0);
    }

    #[test]
    fn extract_tbs_and_sig() {
        let cert = build_test_cert(&dummy_pubkey(), &["example.com"]);
        let (tbs, sig) = extract_tbs_and_signature(&cert).unwrap();
        // TBS should start with SEQUENCE tag
        assert_eq!(tbs[0], TAG_SEQUENCE);
        // Sig should be the dummy bytes (0x30 0x00)
        assert_eq!(sig, &[0x30, 0x00]);
    }

    #[test]
    fn parse_ecdsa_sig() {
        // Build a DER ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }
        let r = [0u8; 32];
        let s = [1u8; 32];
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.push(content.len() as u8);
            out.extend_from_slice(content);
            out
        }
        // DER INTEGER needs leading 0x00 if high bit set
        let r_int = tlv(TAG_INTEGER, &{
            let mut v = vec![0x00];
            v.extend_from_slice(&r);
            v
        });
        let s_int = tlv(TAG_INTEGER, &{
            let mut v = vec![0x00];
            v.extend_from_slice(&s);
            v
        });
        let sig_der = tlv(TAG_SEQUENCE, &[r_int, s_int].concat());

        let (parsed_r, parsed_s) = parse_ecdsa_signature(&sig_der).unwrap();
        assert_eq!(parsed_r, r);
        assert_eq!(parsed_s, s);
    }

    #[test]
    fn truncated_input_errors() {
        assert!(matches!(parse_tl(&[]), Err(DerError::Truncated)));
        assert!(matches!(parse_tl(&[0x30]), Err(DerError::Truncated)));
    }

    #[test]
    fn wrong_tag_errors() {
        // Try to parse a non-sequence as a pubkey certificate
        let data = vec![0x02, 0x01, 0x00]; // INTEGER 0
        assert!(matches!(extract_p256_pubkey(&data), Err(DerError::UnexpectedTag { .. })));
    }
}
