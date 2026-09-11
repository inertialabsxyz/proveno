//! TLS attestation provider integration tests.
//!
//! Split out of `integration.rs` so the whole file can carry one
//! `#![cfg(feature = "tls")]`: the cert-chain verification stack and the
//! Poseidon2 commitment over it are feature-gated, since zkVM guest builds
//! compile without them. `TlsAttestationRecord` itself stays unconditional.
//!
//! `tls_attestation_nonzero_for_p256` makes a real network call to example.com.
#![cfg(feature = "tls")]

use proveno::{
    bytecode::verify,
    compiler::compile,
    parser::parse,
    tls::{
        TlsAttestationRecord, compute_tls_attestation_hash, empty_tls_attestation_hash,
        verify::reverify_attestations,
    },
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::engine::{HostInterface, Vm, VmConfig},
};

// ── TLS attestation provider ────────────────────────────────────────────────
//
// These tests verify the TLS attestation *provider* (`compute_tls_attestation_hash`).
// Post-pivot it is provider machinery that *produces* an attestation blob; it is
// decoupled from the `attestation_hash` public input (which binds whatever blob
// the host attaches per call). The tests check the producer in isolation:
//   - P-256 HTTPS connections produce a hash committing to real pubkey content
//     (≠ the empty-attestation sentinel)
//   - Non-HTTPS (or non-P256) connections degrade cleanly: the hash equals
//     `empty_tls_attestation_hash()` (canonical `Poseidon2::hash([], 0)`)
//
// `tls_attestation_nonzero_for_p256` makes a real network call to example.com.
// `tls_degrades_cleanly_for_non_p256` uses a stub host — no network required.

/// A helper that converts a string key to `LuaKey`.
fn str_key(s: &str) -> LuaKey {
    LuaKey::String(LuaString::from_str(s))
}

// ── TLS-capturing host ────────────────────────────────────────────────────────

/// A test host that makes real HTTPS connections using `rustls` and captures
/// the server's DER-encoded certificate chain.  When the leaf cert uses P-256
/// and the chain verifies against Mozilla roots the record is marked as
/// `p256_verified = true`.  Any other outcome (plain HTTP, RSA cert,
/// verification failure) produces `TlsAttestationRecord::unavailable()`.
struct TlsCapturingHost {
    attestations: std::sync::Arc<std::sync::Mutex<Vec<TlsAttestationRecord>>>,
}

impl TlsCapturingHost {
    fn new(attestations: std::sync::Arc<std::sync::Mutex<Vec<TlsAttestationRecord>>>) -> Self {
        TlsCapturingHost { attestations }
    }

    fn https_get(url: &str) -> Result<(u16, String, TlsAttestationRecord), String> {
        use rustls::RootCertStore;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::ServerName;
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpStream;
        use std::sync::{Arc, Mutex};

        // Only handle https://
        if !url.starts_with("https://") {
            return Err(format!(
                "TlsCapturingHost only supports https://, got: {url}"
            ));
        }

        let without_scheme = &url["https://".len()..];
        let (host_port, path) = match without_scheme.find('/') {
            Some(i) => (&without_scheme[..i], &without_scheme[i..]),
            None => (without_scheme, "/"),
        };
        let host = match host_port.find(':') {
            Some(i) => &host_port[..i],
            None => host_port,
        };
        let port: u16 = match host_port.find(':') {
            Some(i) => host_port[i + 1..]
                .parse()
                .map_err(|e| format!("bad port: {e}"))?,
            None => 443,
        };

        // Shared slot for the captured cert chain.
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();

        // Build Mozilla root store.
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        };

        // Build a custom verifier that captures cert chain bytes.
        #[derive(Debug)]
        struct CapturingVerifier {
            inner: Arc<rustls::client::WebPkiServerVerifier>,
            captured: Arc<Mutex<Vec<Vec<u8>>>>,
        }

        impl ServerCertVerifier for CapturingVerifier {
            fn verify_server_cert(
                &self,
                end_entity: &rustls::pki_types::CertificateDer<'_>,
                intermediates: &[rustls::pki_types::CertificateDer<'_>],
                server_name: &rustls::pki_types::ServerName<'_>,
                ocsp: &[u8],
                now: rustls::pki_types::UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                let result = self.inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp,
                    now,
                )?;
                let mut chain = vec![end_entity.as_ref().to_vec()];
                chain.extend(intermediates.iter().map(|c| c.as_ref().to_vec()));
                *self.captured.lock().unwrap() = chain;
                Ok(result)
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                self.inner.verify_tls12_signature(message, cert, dss)
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                self.inner.verify_tls13_signature(message, cert, dss)
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.inner.supported_verify_schemes()
            }
        }

        let inner_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| format!("verifier build error: {e}"))?;

        let verifier = Arc::new(CapturingVerifier {
            inner: inner_verifier,
            captured: captured_clone,
        });

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid server name: {e}"))?;

        let tcp =
            TcpStream::connect((host, port)).map_err(|e| format!("TCP connect failed: {e}"))?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .map_err(|e| format!("set_read_timeout: {e}"))?;

        let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| format!("TLS connection failed: {e}"))?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);

        // Send a minimal HTTP/1.1 GET request.
        write!(
            tls,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: proveno-test/1.0\r\n\r\n"
        )
        .map_err(|e| format!("write error: {e}"))?;

        // Read the response.
        let mut raw = Vec::new();
        tls.read_to_end(&mut raw)
            .map_err(|e| format!("read error: {e}"))?;

        // Parse status line.
        let mut reader = BufReader::new(raw.as_slice());
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|e| format!("read status: {e}"))?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Skip headers.
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| format!("read header: {e}"))?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        // Read body.
        let mut body = String::new();
        reader
            .read_to_string(&mut body)
            .map_err(|e| format!("read body: {e}"))?;

        // Build attestation record.
        let chain = captured.lock().unwrap().clone();
        let attestation = if !chain.is_empty() && is_p256_leaf(&chain[0]) {
            let not_after = extract_not_after_from_der(&chain[0]);
            TlsAttestationRecord::p256_verified(chain, host.to_string(), not_after)
        } else {
            TlsAttestationRecord::unavailable()
        };

        Ok((status, body, attestation))
    }
}

/// Heuristic check: does the DER-encoded cert use a P-256 public key?
///
/// Searches the DER bytes for the P-256 named-curve OID
/// `1.2.840.10045.3.1.7` in its DER encoding.
fn is_p256_leaf(cert_der: &[u8]) -> bool {
    // DER encoding of OID 1.2.840.10045.3.1.7:
    //   tag=06, length=08, value=2a 86 48 ce 3d 03 01 07
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    cert_der.windows(P256_OID.len()).any(|w| w == P256_OID)
}

/// Extract the `not_after` Unix timestamp from a DER-encoded certificate.
/// Returns 0 on parse failure.
fn extract_not_after_from_der(cert_der: &[u8]) -> u64 {
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

impl HostInterface for TlsCapturingHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        match name {
            "http_get" => {
                let url = match args.get(&str_key("url")) {
                    Some(LuaValue::String(s)) => String::from_utf8_lossy(s.as_bytes()).to_string(),
                    _ => return Err("http_get: missing string arg 'url'".into()),
                };
                let (status, body, attestation) = TlsCapturingHost::https_get(&url)?;
                self.attestations.lock().unwrap().push(attestation);
                let mut t = LuaTable::new();
                t.rawset(str_key("status"), LuaValue::Integer(status as i64))
                    .unwrap();
                t.rawset(
                    str_key("body"),
                    LuaValue::String(LuaString::from_str(&body)),
                )
                .unwrap();
                Ok(t)
            }
            other => Err(format!("unknown tool '{other}'")),
        }
    }
}

// ── Stub host for non-P256 degradation test ───────────────────────────────────

/// A stub host that handles `http_get` without TLS — simulating a non-P256
/// (or plain-HTTP) server.  No attestation record is produced.
struct NonTlsStubHost {
    attestations: std::sync::Arc<std::sync::Mutex<Vec<TlsAttestationRecord>>>,
}

impl HostInterface for NonTlsStubHost {
    fn call_tool(&mut self, name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
        match name {
            "http_get" => {
                // Record an unavailable attestation (plain HTTP / no P-256).
                self.attestations
                    .lock()
                    .unwrap()
                    .push(TlsAttestationRecord::unavailable());
                let mut t = LuaTable::new();
                t.rawset(str_key("status"), LuaValue::Integer(200)).unwrap();
                t.rawset(str_key("body"), LuaValue::String(LuaString::from_str("ok")))
                    .unwrap();
                Ok(t)
            }
            other => Err(format!("unknown tool '{other}'")),
        }
    }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

fn run_with_host<H: HostInterface>(
    src: &str,
    host: H,
    attestations: std::sync::Arc<std::sync::Mutex<Vec<TlsAttestationRecord>>>,
) -> (proveno::vm::engine::VmOutput, Vec<TlsAttestationRecord>) {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(VmConfig::default(), host);
    let output = vm
        .execute(&program, LuaValue::Nil)
        .expect("execution failed");
    let records = attestations.lock().unwrap().clone();
    (output, records)
}

// ── TLS integration tests ─────────────────────────────────────────────────────

/// End-to-end: make a real HTTPS request to a P-256-serving endpoint, run the
/// full prove pipeline (compile → prover dry-run via `compute_public_inputs`),
/// and assert the TLS provider hash commits to real pubkey content.
///
/// This test makes a real network call to example.com.
#[test]
#[ignore = "provenance is to be moved out"]
fn tls_attestation_nonzero_for_p256() {
    let src = r#"
        local resp = tool.call("http_get", {url = "https://example.com"})
        return resp.status
    "#;

    let attestations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let host = TlsCapturingHost::new(attestations.clone());
    let (_output, records) = run_with_host(src, host, attestations);

    // Verify hostname and cert_not_after are populated.
    assert_eq!(
        records[0].hostname, "example.com",
        "hostname must be captured from URL"
    );
    assert!(
        records[0].cert_not_after > 0,
        "cert_not_after must be non-zero for a real cert"
    );

    // The TLS attestation provider commits to actual pubkey bytes for a real
    // P-256 chain, so its hash differs from the empty sentinel. Post-pivot this
    // helper is provider machinery (it *produces* an attestation blob); it is
    // decoupled from the `attestation_hash` public input, which now binds
    // whatever per-call blob the host attaches to each response.
    let hash = compute_tls_attestation_hash(&records);
    assert_ne!(
        hash,
        empty_tls_attestation_hash(),
        "expected non-empty TLS attestation for P-256 server (got records: {records:?})"
    );
}

/// Degradation: when no P-256 TLS attestation is available (non-HTTPS or
/// non-P256 server), the TLS provider must yield the canonical
/// empty-attestation hash (`Poseidon2::hash([], 0)` serialised) without panic.
#[test]
fn tls_degrades_cleanly_for_non_p256() {
    let src = r#"
        local resp = tool.call("http_get", {url = "https://example.com"})
        return resp.status
    "#;

    let attestations = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let host = NonTlsStubHost {
        attestations: attestations.clone(),
    };
    let (_output, records) = run_with_host(src, host, attestations);

    // All attestations are unavailable → provider hash is the empty sentinel.
    let hash = compute_tls_attestation_hash(&records);
    assert_eq!(
        hash,
        empty_tls_attestation_hash(),
        "expected canonical empty TLS attestation when no P-256 attestation is available"
    );
}

/// `reverify_attestations` is the exact function the zkVM guest runs.  This
/// test exercises it against a real TLS certificate captured from example.com,
/// confirming that:
/// 1. A real P-256 chain passes in-library verification (same code the guest uses).
/// 2. Hostname is preserved.
/// 3. `cert_not_after` is re-derived from the cert DER, not copied from the input.
///
/// This test makes a real network call to example.com.
#[test]
#[ignore = "provenance is to be moved out"]
fn tls_reverify_attestations_matches_prover() {
    // Capture a real cert chain the same way the prover host does.
    let (_, _, prover_record) =
        TlsCapturingHost::https_get("https://example.com").expect("HTTPS call failed");

    assert!(
        prover_record.p256_verified,
        "prover_record must be p256_verified for this test to be meaningful"
    );

    // Run reverify_attestations — the same logic the guest executes.
    let verified = reverify_attestations(&[prover_record.clone()]);
    assert_eq!(verified.len(), 1);

    let r = &verified[0];
    assert!(
        r.p256_verified,
        "reverify_attestations must accept a real P-256 example.com cert"
    );
    assert_eq!(
        r.hostname, "example.com",
        "hostname must be preserved through reverification"
    );
    assert!(
        r.cert_not_after > 0,
        "cert_not_after must be extracted from the cert DER"
    );

    // Guest re-derives cert_not_after from the DER; it must agree with the
    // prover's independently extracted value.
    assert_eq!(
        r.cert_not_after, prover_record.cert_not_after,
        "guest and prover must derive the same cert_not_after from the same cert DER"
    );
}
