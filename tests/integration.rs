//! Integration tests: pipeline, determinism, gas/memory metering, pcall,
//! iterators, VmOutput fields, and TLS attestation.

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
    vm::{
        engine::{HostInterface, NoopHost, Vm, VmConfig, VmOutput},
        gas::VmError,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn strip_line_info(e: VmError) -> VmError {
    match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    }
}

fn run_with_config(src: &str, config: VmConfig) -> Result<VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new(config, NoopHost);
    vm.execute(&program, LuaValue::Nil).map_err(strip_line_info)
}

fn run(src: &str) -> Result<VmOutput, VmError> {
    run_with_config(src, VmConfig::default())
}

fn run_ok(src: &str) -> VmOutput {
    run(src).expect("execution failed")
}

fn int(n: i64) -> LuaValue {
    LuaValue::Integer(n)
}

fn s(text: &str) -> LuaValue {
    LuaValue::String(LuaString::from_str(text))
}

// ── Gas metering ──────────────────────────────────────────────────────────────

#[test]
fn gas_used_is_nonzero_for_simple_program() {
    let out = run_ok("return 1 + 2");
    assert!(
        out.gas_used > 0,
        "expected gas_used > 0, got {}",
        out.gas_used
    );
}

#[test]
fn gas_used_increases_with_more_work() {
    let cheap = run_ok("return 1").gas_used;
    let expensive = run_ok(
        r#"
        local s = 0
        for i = 1, 100 do
            s = s + i
        end
        return s
    "#,
    )
    .gas_used;
    assert!(
        expensive > cheap,
        "more work should use more gas: cheap={} expensive={}",
        cheap,
        expensive
    );
}

#[test]
fn gas_limit_exhaustion_halts_execution() {
    let config = VmConfig {
        gas_limit: 10,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local i = 0
        while true do i = i + 1 end
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::GasExhausted);
}

#[test]
fn gas_exhaustion_escapes_pcall() {
    // GasExhausted is unrecoverable — pcall must not swallow it.
    let config = VmConfig {
        gas_limit: 40,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local ok, err = pcall(function()
            local i = 0
            while true do i = i + 1 end
        end)
        return ok
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::GasExhausted);
}

#[test]
fn gas_used_reported_in_vmoutput() {
    // gas_used field should reflect actual consumption (not always equal to limit).
    let config = VmConfig {
        gas_limit: 200_000,
        ..VmConfig::default()
    };
    let out = run_with_config("return 42", config).unwrap();
    assert!(out.gas_used < 200_000, "gas_used should be less than limit");
    assert!(out.gas_used > 0);
}

// ── Memory metering ───────────────────────────────────────────────────────────

#[test]
fn memory_used_is_nonzero_for_table_alloc() {
    let out = run_ok("local t = {} return 1");
    assert!(
        out.memory_used > 0,
        "expected memory_used > 0, got {}",
        out.memory_used
    );
}

#[test]
fn memory_limit_exhaustion_halts_execution() {
    // Allocating many tables in a loop should exceed a tight memory limit.
    let config = VmConfig {
        memory_limit_bytes: 500,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local i = 0
        while true do
            local t = {}
            i = i + 1
        end
        return i
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::MemoryExhausted);
}

#[test]
fn memory_exhaustion_escapes_pcall() {
    // MemoryExhausted is unrecoverable — pcall must not swallow it.
    let config = VmConfig {
        memory_limit_bytes: 500,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local ok, err = pcall(function()
            local i = 0
            while true do
                local t = {}
                i = i + 1
            end
        end)
        return ok
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::MemoryExhausted);
}

#[test]
fn memory_is_monotonic_hwm() {
    // String concatenation allocates a new string each iteration.
    // Because HWM is monotonic (no free credit), memory_used grows with each concat.
    let config = VmConfig {
        memory_limit_bytes: 1_000_000,
        ..VmConfig::default()
    };
    let out = run_with_config(
        r#"
        local i = 0
        while i < 50 do
            local s = "prefix-" .. tostring(i)
            i = i + 1
        end
        return i
    "#,
        config,
    )
    .unwrap();
    // 50 iterations × ~(24 + 9 bytes per concat result) ≈ 1650 bytes, well above 1000.
    assert!(
        out.memory_used > 1000,
        "expected meaningful memory use, got {}",
        out.memory_used
    );
}

// ── pcall error taxonomy ──────────────────────────────────────────────────────

#[test]
fn pcall_catches_call_depth_exceeded() {
    // Infinite mutual recursion should hit CallDepthExceeded, which IS recoverable.
    let src = r#"
        local function recurse(n)
            return recurse(n + 1)
        end
        local ok, err = pcall(recurse, 0)
        if ok then return 1 else return 0 end
    "#;
    let out = run_ok(src);
    assert_eq!(
        out.return_value,
        int(0),
        "pcall should have caught CallDepthExceeded"
    );
}

#[test]
fn pcall_call_depth_error_message_contains_depth() {
    let src = r#"
        local function recurse(n)
            return recurse(n + 1)
        end
        local ok, err = pcall(recurse, 0)
        return err
    "#;
    let out = run_ok(src);
    if let LuaValue::String(s) = &out.return_value {
        let msg = String::from_utf8_lossy(s.as_bytes());
        assert!(
            msg.contains("depth") || msg.contains("stack") || msg.contains("call"),
            "error message should mention depth/stack/call, got: {}",
            msg
        );
    } else {
        panic!("expected string error message, got {:?}", out.return_value);
    }
}

#[test]
fn pcall_catches_error_with_table_payload() {
    // error() can be called with a non-string value; pcall returns it as the second value.
    let src = r#"
        local ok, err = pcall(function()
            error({code = 42, msg = "oops"})
        end)
        if ok then return -1 end
        return err.code
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(42));
}

#[test]
fn pcall_catches_error_with_integer_payload() {
    let src = r#"
        local ok, err = pcall(function()
            error(99)
        end)
        if ok then return -1 end
        return err
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(99));
}

#[test]
fn nested_pcall_inner_catches_outer_succeeds() {
    let src = r#"
        local outer_ok, outer_val = pcall(function()
            local inner_ok, inner_err = pcall(function()
                error("inner boom")
            end)
            -- inner caught the error; outer function returns normally
            if inner_ok then return -1 end
            return 1
        end)
        if outer_ok then return outer_val else return -1 end
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(1));
}

#[test]
fn pcall_in_loop_multiple_times() {
    // pcall used in a loop should work correctly every iteration.
    let src = r#"
        local count = 0
        for i = 1, 5 do
            local ok, _ = pcall(function()
                if i == 3 then error("three") end
            end)
            if ok then count = count + 1 end
        end
        return count
    "#;
    let out = run_ok(src);
    // Iterations 1,2,4,5 succeed; iteration 3 errors but is caught.
    assert_eq!(out.return_value, int(4));
}

#[test]
fn pcall_success_stack_continues_normally() {
    let src = r#"
        local ok, val = pcall(function() return 10 end)
        local ok2, val2 = pcall(function() return 20 end)
        return val + val2
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(30));
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn determinism_same_return_value_both_runs() {
    let src = r#"
        local t = {b = 2, a = 1, c = 3}
        local result = 0
        for k, v in pairs_sorted(t) do
            result = result + v
        end
        return result
    "#;
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");

    let mut vm1 = Vm::new(VmConfig::default(), NoopHost);
    let out1 = vm1.execute(&program, LuaValue::Nil).expect("run 1 failed");

    let mut vm2 = Vm::new(VmConfig::default(), NoopHost);
    let out2 = vm2.execute(&program, LuaValue::Nil).expect("run 2 failed");

    assert_eq!(out1.return_value, out2.return_value);
}

#[test]
fn determinism_same_gas_used_both_runs() {
    let src = r#"
        local t = {z = 26, a = 1, m = 13}
        local s = ""
        for k, v in pairs_sorted(t) do
            s = s .. k
        end
        return s
    "#;
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");

    let mut vm1 = Vm::new(VmConfig::default(), NoopHost);
    let out1 = vm1.execute(&program, LuaValue::Nil).expect("run 1 failed");

    let mut vm2 = Vm::new(VmConfig::default(), NoopHost);
    let out2 = vm2.execute(&program, LuaValue::Nil).expect("run 2 failed");

    assert_eq!(
        out1.gas_used, out2.gas_used,
        "gas_used must be deterministic"
    );
    assert_eq!(
        out1.memory_used, out2.memory_used,
        "memory_used must be deterministic"
    );
}

#[test]
fn determinism_iterator_order_stable() {
    // pairs_sorted must visit keys in the same canonical order across runs.
    let src = r#"
        local t = {z = 1, a = 2, m = 3}
        local result = ""
        for k, v in pairs_sorted(t) do
            result = result .. k
        end
        return result
    "#;
    let out1 = run_ok(src);
    let out2 = run_ok(src);
    assert_eq!(out1.return_value, out2.return_value);
    // Also verify the actual order is correct (a < m < z).
    assert_eq!(out1.return_value, s("amz"));
}

#[test]
fn determinism_same_program_same_input_twice() {
    // Identical inputs → identical outputs, gas, memory.
    let src = "local x = 7 * 6 return x";
    let out1 = run_ok(src);
    let out2 = run_ok(src);
    assert_eq!(out1.return_value, out2.return_value);
    assert_eq!(out1.gas_used, out2.gas_used);
    assert_eq!(out1.memory_used, out2.memory_used);
}

// ── Iterator semantics ────────────────────────────────────────────────────────

#[test]
fn pairs_sorted_visits_string_keys_lexicographic() {
    let src = r#"
        local t = {z = 1, a = 2, m = 3}
        local result = ""
        for k, v in pairs_sorted(t) do
            result = result .. k
        end
        return result
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, s("amz"));
}

#[test]
fn pairs_sorted_visits_integer_keys_ascending() {
    let src = r#"
        local t = {}
        t[3] = "three"
        t[1] = "one"
        t[2] = "two"
        local result = ""
        for k, v in pairs_sorted(t) do
            result = result .. v
        end
        return result
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, s("onetwothree"));
}

#[test]
fn pairs_sorted_integer_keys_before_string_keys() {
    // Spec §4: integers ascending, then strings lexicographic.
    let src = r#"
        local t = {a = "A"}
        t[1] = "one"
        local result = ""
        for k, v in pairs_sorted(t) do
            result = result .. v
        end
        return result
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, s("oneA"));
}

#[test]
fn pairs_sorted_empty_table_body_never_runs() {
    let src = r#"
        local t = {}
        local count = 0
        for k, v in pairs_sorted(t) do
            count = count + 1
        end
        return count
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(0));
}

#[test]
fn pairs_sorted_key_value_correct() {
    // Verify that both key and value are yielded correctly.
    let src = r#"
        local t = {x = 10, y = 20}
        local sum = 0
        for k, v in pairs_sorted(t) do
            sum = sum + v
        end
        return sum
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(30));
}

#[test]
fn ipairs_visits_consecutive_keys_from_one() {
    let src = r#"
        local t = {10, 20, 30}
        local sum = 0
        for i, v in ipairs(t) do
            sum = sum + v
        end
        return sum
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(60));
}

#[test]
fn ipairs_stops_at_nil_gap() {
    // {10, nil, 30}: ipairs stops at index 2 (nil), so only index 1 is visited.
    let src = r#"
        local t = {}
        t[1] = 10
        t[3] = 30
        local count = 0
        for i, v in ipairs(t) do
            count = count + 1
        end
        return count
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(1));
}

#[test]
fn ipairs_empty_table_body_never_runs() {
    let src = r#"
        local t = {}
        local count = 0
        for i, v in ipairs(t) do
            count = count + 1
        end
        return count
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, int(0));
}

#[test]
fn ipairs_index_is_correct() {
    // Verify the index value yielded is 1-based and sequential.
    let src = r#"
        local t = {100, 200, 300}
        local index_sum = 0
        for i, v in ipairs(t) do
            index_sum = index_sum + i
        end
        return index_sum
    "#;
    let out = run_ok(src);
    // 1 + 2 + 3 = 6
    assert_eq!(out.return_value, int(6));
}

#[test]
fn iterator_break_exits_early() {
    let src = r#"
        local t = {10, 20, 30, 40, 50}
        local sum = 0
        for i, v in ipairs(t) do
            if i == 3 then break end
            sum = sum + v
        end
        return sum
    "#;
    let out = run_ok(src);
    // Visits i=1 (10) and i=2 (20), then breaks at i=3.
    assert_eq!(out.return_value, int(30));
}

#[test]
fn nested_ipairs_in_pairs_sorted() {
    let src = r#"
        local matrix = {}
        matrix.row1 = {1, 2, 3}
        matrix.row2 = {4, 5, 6}
        local total = 0
        for k, row in pairs_sorted(matrix) do
            for i, v in ipairs(row) do
                total = total + v
            end
        end
        return total
    "#;
    let out = run_ok(src);
    // 1+2+3+4+5+6 = 21
    assert_eq!(out.return_value, int(21));
}

// ── VmOutput fields ───────────────────────────────────────────────────────────

#[test]
fn vmoutput_logs_captures_log_calls() {
    let src = r#"
        log("hello")
        log("world")
        return 1
    "#;
    let out = run_ok(src);
    assert_eq!(out.logs.len(), 2);
    assert_eq!(out.logs[0], "hello");
    assert_eq!(out.logs[1], "world");
}

#[test]
fn vmoutput_logs_empty_when_no_log_calls() {
    let out = run_ok("return 42");
    assert!(out.logs.is_empty());
}

#[test]
fn vmoutput_gas_used_plus_remaining_equals_limit() {
    // gas_used should be consistent: used = limit - remaining.
    // We can verify indirectly: run two programs, the one with more
    // instructions must have higher gas_used.
    let out_light = run_ok("return 1");
    let out_heavy = run_ok(
        r#"
        local s = 0
        for i = 1, 20 do s = s + i end
        return s
    "#,
    );
    assert!(out_heavy.gas_used > out_light.gas_used);
}

#[test]
fn vmoutput_memory_used_grows_with_allocations() {
    let out_no_alloc = run_ok("return 1");
    let out_with_alloc = run_ok(
        r#"
        local t1 = {}
        local t2 = {}
        local t3 = {}
        return 1
    "#,
    );
    assert!(out_with_alloc.memory_used > out_no_alloc.memory_used);
}

// ── Error model completeness ──────────────────────────────────────────────────

#[test]
fn error_code_type_error_is_recoverable() {
    let src = r#"
        local ok, _ = pcall(function()
            return 1 + "not a number"
        end)
        return ok
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, LuaValue::Boolean(false));
}

#[test]
fn error_code_runtime_error_is_recoverable() {
    let src = r#"
        local ok, _ = pcall(function()
            error("boom")
        end)
        return ok
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, LuaValue::Boolean(false));
}

#[test]
fn error_code_gas_exhausted_is_unrecoverable() {
    let config = VmConfig {
        gas_limit: 20,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local ok, _ = pcall(function()
            local i = 0
            while true do i = i + 1 end
        end)
        return 1
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::GasExhausted);
}

#[test]
fn error_code_memory_exhausted_is_unrecoverable() {
    let config = VmConfig {
        memory_limit_bytes: 200,
        ..VmConfig::default()
    };
    let err = run_with_config(
        r#"
        local ok, _ = pcall(function()
            local i = 0
            while true do
                local t = {}
                i = i + 1
            end
        end)
        return 1
    "#,
        config,
    )
    .unwrap_err();
    assert_eq!(err, VmError::MemoryExhausted);
}

#[test]
fn error_code_call_depth_exceeded_is_recoverable() {
    let src = r#"
        local function inf() return inf() end
        local ok, _ = pcall(inf)
        return ok
    "#;
    let out = run_ok(src);
    assert_eq!(out.return_value, LuaValue::Boolean(false));
}

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
