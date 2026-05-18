//! Integration tests for Phase 2: OraclePolicy enforcement and reproducibility.

use luai::{
    bytecode::verify,
    compiler::compile,
    parser::parse,
    policy::profiles::{constrained_http_v1, template_price_feed_v1},
    policy::{OraclePolicy, TlsRequirement},
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::{
        engine::{HostInterface, Vm, VmConfig},
        gas::VmError,
    },
};
use std::collections::HashMap;

// ── Helpers ───────────────────────────────────────────────────────────────────

struct MockHost {
    responses: Vec<Result<LuaTable, String>>,
    index: usize,
}

impl MockHost {
    fn new() -> Self {
        MockHost {
            responses: Vec::new(),
            index: 0,
        }
    }

    fn add_ok(&mut self, t: LuaTable) {
        self.responses.push(Ok(t));
    }

    fn add_err(&mut self, msg: &str) {
        self.responses.push(Err(msg.to_owned()));
    }
}

impl HostInterface for MockHost {
    fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
        if self.index >= self.responses.len() {
            return Err("no more mock responses".to_owned());
        }
        let resp = self.responses[self.index].clone();
        self.index += 1;
        resp
    }
}

fn make_table(key: &str, val: LuaValue) -> LuaTable {
    let mut t = LuaTable::new();
    t.rawset(LuaKey::String(LuaString::from_str(key)), val)
        .unwrap();
    t
}

fn strip_line_info(e: VmError) -> VmError {
    match e {
        VmError::WithLine(_, inner) => *inner,
        other => other,
    }
}

fn run_with_policy(
    src: &str,
    host: MockHost,
    policy: OraclePolicy,
) -> Result<luai::VmOutput, VmError> {
    let block = parse(src).expect("parse failed");
    let program = compile(&block).expect("compile failed");
    verify(&program).expect("verify failed");
    let mut vm = Vm::new_with_policy(VmConfig::default(), host, policy);
    vm.execute(&program, LuaValue::Nil).map_err(strip_line_info)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn domain_allowlist_rejects_unapproved_domain() {
    let policy = OraclePolicy {
        allowed_domains: vec!["approved.com".to_owned()],
        allowed_http_methods: vec![],
        max_tool_calls: 10,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions: HashMap::new(),
    };

    let mut host = MockHost::new();
    host.add_ok(make_table("result", LuaValue::Integer(1)));

    let src = r#"
        local resp = tool.call("http_get", {url = "https://evil.com/data"})
        return resp.result
    "#;

    let err = run_with_policy(src, host, policy).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
    if let VmError::RuntimeError(LuaValue::String(s)) = err {
        let msg = String::from_utf8_lossy(s.as_bytes());
        assert!(msg.contains("policy"), "expected 'policy' in error: {msg}");
    }
}

#[test]
fn domain_allowlist_permits_approved_domain() {
    let policy = OraclePolicy {
        allowed_domains: vec!["approved.com".to_owned()],
        allowed_http_methods: vec![],
        max_tool_calls: 10,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions: HashMap::new(),
    };

    let mut host = MockHost::new();
    host.add_ok(make_table("result", LuaValue::Integer(42)));

    let src = r#"
        local resp = tool.call("http_get", {url = "https://approved.com/data"})
        return resp.result
    "#;

    let output = run_with_policy(src, host, policy).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(42));
}

#[test]
fn policy_hash_is_stable() {
    let h1 = template_price_feed_v1().policy_hash();
    let h2 = template_price_feed_v1().policy_hash();
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32], "policy hash must not be the zero stub");
}

#[test]
fn constrained_http_v1_hash_is_stable() {
    let h1 = constrained_http_v1().policy_hash();
    let h2 = constrained_http_v1().policy_hash();
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32]);
}

#[test]
fn profiles_have_distinct_hashes() {
    assert_ne!(
        constrained_http_v1().policy_hash(),
        template_price_feed_v1().policy_hash()
    );
}

#[test]
fn schema_mismatch_returns_vm_error() {
    let mut schema_versions = HashMap::new();
    schema_versions.insert(
        "api.prices.com".to_owned(),
        serde_json::json!({"price": 0, "currency": ""}),
    );
    let policy = OraclePolicy {
        allowed_domains: vec![],
        allowed_http_methods: vec![],
        max_tool_calls: 10,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions,
    };

    // Response has "price" as a string, schema expects number.
    let mut resp = LuaTable::new();
    resp.rawset(
        LuaKey::String(LuaString::from_str("price")),
        LuaValue::String(LuaString::from_str("not-a-number")),
    )
    .unwrap();
    resp.rawset(
        LuaKey::String(LuaString::from_str("currency")),
        LuaValue::String(LuaString::from_str("USD")),
    )
    .unwrap();

    let mut host = MockHost::new();
    host.add_ok(resp);

    let src = r#"
        local resp = tool.call("http_get", {url = "https://api.prices.com/eth"})
        return 1
    "#;

    let err = run_with_policy(src, host, policy).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
    if let VmError::RuntimeError(LuaValue::String(s)) = err {
        let msg = String::from_utf8_lossy(s.as_bytes());
        assert!(msg.contains("policy"), "expected 'policy' in: {msg}");
    }
}

#[test]
fn schema_match_succeeds() {
    let mut schema_versions = HashMap::new();
    schema_versions.insert(
        "api.prices.com".to_owned(),
        serde_json::json!({"price": 0, "currency": ""}),
    );
    let policy = OraclePolicy {
        allowed_domains: vec![],
        allowed_http_methods: vec![],
        max_tool_calls: 10,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions,
    };

    let mut resp = LuaTable::new();
    resp.rawset(
        LuaKey::String(LuaString::from_str("price")),
        LuaValue::Integer(3500),
    )
    .unwrap();
    resp.rawset(
        LuaKey::String(LuaString::from_str("currency")),
        LuaValue::String(LuaString::from_str("USD")),
    )
    .unwrap();

    let mut host = MockHost::new();
    host.add_ok(resp);

    let src = r#"
        local resp = tool.call("http_get", {url = "https://api.prices.com/eth"})
        return resp.price
    "#;

    let output = run_with_policy(src, host, policy).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(3500));
}

#[test]
fn http_post_rejected_when_only_get_allowed() {
    let policy = constrained_http_v1(); // http_get only

    let mut host = MockHost::new();
    host.add_ok(make_table("result", LuaValue::Integer(1)));

    let src = r#"
        local resp = tool.call("http_post", {url = "https://example.com/", body = "{}"})
        return resp.result
    "#;

    let err = run_with_policy(src, host, policy).unwrap_err();
    assert!(matches!(err, VmError::RuntimeError(_)));
    if let VmError::RuntimeError(LuaValue::String(s)) = err {
        let msg = String::from_utf8_lossy(s.as_bytes());
        assert!(msg.contains("policy"), "expected 'policy' in: {msg}");
    }
}

#[test]
fn non_http_tools_bypass_policy_domain_check() {
    // kv_get / search / etc. are not subject to domain restriction.
    let policy = OraclePolicy {
        allowed_domains: vec!["only-this.com".to_owned()],
        allowed_http_methods: vec![],
        max_tool_calls: 10,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions: HashMap::new(),
    };

    let mut host = MockHost::new();
    host.add_ok(make_table("value", LuaValue::Integer(99)));

    // "kv_get" is not an HTTP tool, should bypass domain check.
    let src = r#"
        local resp = tool.call("kv_get", {key = "foo"})
        return resp.value
    "#;

    let output = run_with_policy(src, host, policy).unwrap();
    assert_eq!(output.return_value, LuaValue::Integer(99));
}
