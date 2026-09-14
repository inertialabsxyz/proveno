//! A `HostInterface` wrapper that enforces an `OraclePolicy` host-side.
//!
//! The std-side counterpart to [`PolicyEnforcingHost`](crate::policy::guest::PolicyEnforcingHost),
//! which enforces the `no_std` subset inside the guest. This one additionally
//! validates response schemas, which needs `serde_json`.
//!
//! Enforcement lives in a host wrapper rather than inside `ToolRegistry` so
//! that `host` does not have to know about `policy` at all. It also means a
//! denial travels the same path as any other tool failure: the registry records
//! it in the transcript and raises `VmError::ToolError`, which `pcall` can
//! catch. Enforcing inside the registry rejected the call *before* the host was
//! reached, so the attempt left no trace in the artifact at all.

use alloc::{format, string::String, vec::Vec};

use crate::{
    host::{canonicalize::canonical_serialize_table, tool_registry::get_url_from_args},
    policy::{OraclePolicy, canonical::is_http_tool},
    types::table::LuaTable,
    vm::engine::HostInterface,
};

/// Wraps a host and rejects tool calls an `OraclePolicy` does not permit.
pub struct OraclePolicyHost<'a, H> {
    inner: H,
    policy: &'a OraclePolicy,
}

impl<'a, H: HostInterface> OraclePolicyHost<'a, H> {
    pub fn new(inner: H, policy: &'a OraclePolicy) -> Self {
        OraclePolicyHost { inner, policy }
    }
}

impl<H: HostInterface> HostInterface for OraclePolicyHost<'_, H> {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        if !is_http_tool(name) {
            return self.inner.call_tool(name, args);
        }

        // A missing or non-string `url` becomes "", which fails the domain
        // check whenever an allowlist is set. Defaulting to permitted here
        // would let a program dodge the allowlist by omitting the argument.
        let url = get_url_from_args(args).unwrap_or_default();
        self.policy.check_http_call(name, &url)?;

        let resp = self.inner.call_tool(name, args)?;

        let resp_canonical = canonical_serialize_table(&resp)
            .map_err(|e| format!("policy: tool response is not serializable ({e:?})"))?;
        self.policy.check_response_schema(&url, &resp_canonical)?;

        Ok(resp)
    }

    fn take_attestation(&mut self) -> Option<Vec<u8>> {
        self.inner.take_attestation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        host::{
            tool_registry::ToolRegistry,
            transcript::{ToolCallStatus, Transcript},
        },
        policy::TlsRequirement,
        types::{
            table::LuaKey,
            value::{LuaString, LuaValue},
        },
        vm::{engine::VmConfig, gas::GasMeter, gas::VmError},
    };
    use std::collections::HashMap;

    struct MockHost {
        response: Result<LuaTable, String>,
    }

    impl HostInterface for MockHost {
        fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
            self.response.clone()
        }
    }

    fn response_table() -> LuaTable {
        let mut t = LuaTable::new();
        t.rawset(
            LuaKey::String(LuaString::from_str("ok")),
            LuaValue::Boolean(true),
        )
        .unwrap();
        t
    }

    fn http_args(url: &str) -> LuaTable {
        let mut t = LuaTable::new();
        t.rawset(
            LuaKey::String(LuaString::from_str("url")),
            LuaValue::String(LuaString::from_str(url)),
        )
        .unwrap();
        t
    }

    fn base_policy() -> OraclePolicy {
        OraclePolicy {
            allowed_domains: vec![],
            allowed_http_methods: vec![],
            max_tool_calls: 10,
            max_payload_bytes_per_call: 64 * 1024,
            tls_requirement: TlsRequirement::UnattestedPermitted,
            required_output_schema: None,
            schema_versions: HashMap::new(),
        }
    }

    /// Drive a call through the same stack the VM uses: registry over the
    /// policy wrapper over the host.
    fn call_through(
        policy: &OraclePolicy,
        response: Result<LuaTable, String>,
        tool: &str,
        url: &str,
    ) -> (Result<LuaTable, VmError>, Transcript) {
        let mut registry = ToolRegistry::new(OraclePolicyHost::new(MockHost { response }, policy));
        let mut gas = GasMeter::new(1_000_000);
        let mut transcript = Transcript::new();
        let config = VmConfig::default();
        let args = http_args(url);
        let out = registry.call(tool, &args, &config, &mut gas, &mut transcript);
        (out, transcript)
    }

    #[test]
    fn blocks_http_post_when_only_get_allowed() {
        let mut policy = base_policy();
        policy.allowed_http_methods = vec!["http_get".to_owned()];
        let (result, _) =
            call_through(&policy, Ok(response_table()), "http_post", "https://x.com/");
        let err = result.unwrap_err();
        assert!(matches!(err, VmError::ToolError(ref m) if m.contains("policy")));
    }

    #[test]
    fn allows_http_get_when_in_allowed_methods() {
        let mut policy = base_policy();
        policy.allowed_http_methods = vec!["http_get".to_owned()];
        let (result, _) = call_through(&policy, Ok(response_table()), "http_get", "https://x.com/");
        assert!(result.is_ok());
    }

    #[test]
    fn blocks_domain_not_in_allowlist() {
        let mut policy = base_policy();
        policy.allowed_domains = vec!["approved.com".to_owned()];
        let (result, _) = call_through(
            &policy,
            Ok(response_table()),
            "http_get",
            "https://evil.com/data",
        );
        let err = result.unwrap_err();
        assert!(matches!(err, VmError::ToolError(ref m) if m.contains("policy")));
    }

    #[test]
    fn schema_mismatch_is_rejected() {
        let mut policy = base_policy();
        policy.schema_versions.insert(
            "api.example.com".to_owned(),
            serde_json::json!({"price": 0, "currency": ""}),
        );

        // `price` is a string where the schema wants a number.
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

        let (result, _) = call_through(
            &policy,
            Ok(resp),
            "http_get",
            "https://api.example.com/price",
        );
        let err = result.unwrap_err();
        assert!(matches!(err, VmError::ToolError(ref m) if m.contains("policy")));
    }

    #[test]
    fn denial_is_recorded_in_the_transcript() {
        // Enforcing inside ToolRegistry rejected the call before the host was
        // reached, so a denied attempt left no record at all. Going through a
        // host wrapper routes it into the normal tool-failure path.
        let mut policy = base_policy();
        policy.allowed_domains = vec!["approved.com".to_owned()];
        let (result, transcript) = call_through(
            &policy,
            Ok(response_table()),
            "http_get",
            "https://evil.com/data",
        );

        assert!(result.is_err());
        assert_eq!(transcript.len(), 1);
        let record = &transcript.records()[0];
        assert_eq!(record.status, ToolCallStatus::Error);
        assert_eq!(record.tool_name, "http_get");
        assert!(record.error_message.contains("policy"));
        assert_eq!(record.gas_charged, 0);
    }

    #[test]
    fn non_http_tools_bypass_the_policy() {
        let mut policy = base_policy();
        policy.allowed_domains = vec!["approved.com".to_owned()];
        let (result, _) = call_through(&policy, Ok(response_table()), "kv_get", "");
        assert!(result.is_ok());
    }
}
