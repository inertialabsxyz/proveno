//! `ToolRegistry` — wraps `HostInterface` and enforces VM-side quotas and policy.

use crate::{
    host::{
        canonicalize::{CanonError, canonical_serialize_table},
        transcript::Transcript,
    },
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::{
        engine::{HostInterface, VmConfig},
        gas::{GasMeter, VmError, gas_cost},
    },
};

/// Wraps a `HostInterface` and enforces VM-side quotas for tool calls.
pub struct ToolRegistry<H: HostInterface> {
    host: H,
    calls_made: usize,
    total_bytes_in: usize,
    total_bytes_out: usize,
    #[cfg(feature = "std")]
    policy: Option<crate::policy::OraclePolicy>,
}

impl<H: HostInterface> ToolRegistry<H> {
    pub fn new(host: H) -> Self {
        ToolRegistry {
            host,
            calls_made: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            #[cfg(feature = "std")]
            policy: None,
        }
    }

    /// Create a registry with an attached policy. Tool calls are checked against
    /// the policy's domain allowlist, method restriction, and response schemas.
    #[cfg(feature = "std")]
    pub fn with_policy(host: H, policy: crate::policy::OraclePolicy) -> Self {
        ToolRegistry {
            host,
            calls_made: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            policy: Some(policy),
        }
    }

    /// Reset counters for a new execution.
    pub fn reset(&mut self) {
        self.calls_made = 0;
        self.total_bytes_in = 0;
        self.total_bytes_out = 0;
    }

    /// Attempt a tool call, enforcing quotas, recording the transcript entry,
    /// and charging gas via the gas meter.
    ///
    /// Returns the response `LuaTable` on success, or a `VmError` on failure.
    pub fn call(
        &mut self,
        name: &str,
        args_table: &LuaTable,
        config: &VmConfig,
        gas: &mut GasMeter,
        transcript: &mut Transcript,
    ) -> Result<LuaTable, VmError> {
        // 1. Serialize args.
        let args_canonical = canonical_serialize_table(args_table).map_err(|e| match e {
            CanonError::TableDepthExceeded => VmError::RuntimeError(LuaValue::String(
                LuaString::from_str("tool args: table depth exceeded"),
            )),
            other => VmError::from(other),
        })?;

        // 2. Check call count quota.
        if self.calls_made >= config.max_tool_calls {
            return Err(VmError::RuntimeError(LuaValue::String(
                LuaString::from_str("tool call limit exceeded"),
            )));
        }

        // 3. Check bytes-in quota.
        if self.total_bytes_in + args_canonical.len() > config.max_tool_bytes_in {
            return Err(VmError::RuntimeError(LuaValue::String(
                LuaString::from_str("tool input bytes limit exceeded"),
            )));
        }

        // 4. Policy: HTTP method and domain allowlist checks.
        #[cfg(feature = "std")]
        if let Some(ref policy) = self.policy
            && is_http_tool(name)
        {
            let url = get_url_from_args(args_table).unwrap_or_default();
            policy.check_http_call(name, &url).map_err(|reason| {
                VmError::RuntimeError(LuaValue::String(LuaString::from_str(&reason)))
            })?;
        }

        // 5. Increment counters.
        self.calls_made += 1;
        self.total_bytes_in += args_canonical.len();

        // 6. Call the host.
        let result = self.host.call_tool(name, args_table);

        match result {
            Ok(resp_table) => {
                // 7a. Serialize response.
                let resp_canonical =
                    canonical_serialize_table(&resp_table).map_err(|e| match e {
                        CanonError::TableDepthExceeded => VmError::RuntimeError(LuaValue::String(
                            LuaString::from_str("tool response: table depth exceeded"),
                        )),
                        other => VmError::from(other),
                    })?;

                // 7b. Check bytes-out quota.
                if self.total_bytes_out + resp_canonical.len() > config.max_tool_bytes_out {
                    return Err(VmError::RuntimeError(LuaValue::String(
                        LuaString::from_str("tool output bytes limit exceeded"),
                    )));
                }

                // 7c. Policy: response schema validation.
                #[cfg(feature = "std")]
                if let Some(ref policy) = self.policy
                    && is_http_tool(name)
                {
                    let url = get_url_from_args(args_table).unwrap_or_default();
                    policy
                        .check_response_schema(&url, &resp_canonical)
                        .map_err(|reason| {
                            VmError::RuntimeError(LuaValue::String(LuaString::from_str(&reason)))
                        })?;
                }

                // 7d. Update bytes-out counter.
                self.total_bytes_out += resp_canonical.len();

                // 7e. Charge gas: 100 + args_bytes + resp_bytes.
                let gas_cost = gas_cost::TOOL_CALL_BASE
                    + args_canonical.len() as u64
                    + resp_canonical.len() as u64;
                gas.charge(gas_cost)?;

                // 7f. Record transcript.
                transcript.record_ok(name, args_canonical, resp_canonical, gas_cost);

                // 7g. Return table.
                Ok(resp_table)
            }
            Err(msg) => {
                // 8. Record error transcript with gas_charged = 0.
                transcript.record_error(name, args_canonical, 0, &msg);
                Err(VmError::ToolError(msg))
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_http_tool(name: &str) -> bool {
    matches!(name, "http_get" | "http_post")
}

/// Extract the `url` string from a LuaTable args argument.
#[cfg(feature = "std")]
fn get_url_from_args(args: &LuaTable) -> Option<String> {
    let key = LuaKey::String(LuaString::from_str("url"));
    match args.get(&key) {
        Some(LuaValue::String(s)) => Some(String::from_utf8_lossy(s.as_bytes()).into_owned()),
        _ => None,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        host::transcript::{ToolCallStatus, Transcript},
        types::{table::LuaKey, value::LuaValue},
        vm::{
            engine::{HostInterface, NoopHost, VmConfig},
            gas::GasMeter,
        },
    };

    struct MockHost {
        response: Result<LuaTable, String>,
    }

    impl MockHost {
        fn ok(t: LuaTable) -> Self {
            MockHost { response: Ok(t) }
        }
        fn err(msg: &str) -> Self {
            MockHost {
                response: Err(msg.to_owned()),
            }
        }
    }

    impl HostInterface for MockHost {
        fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
            self.response.clone()
        }
    }

    fn make_config() -> VmConfig {
        VmConfig::default()
    }
    fn make_gas() -> GasMeter {
        GasMeter::new(1_000_000)
    }
    fn make_empty_table() -> LuaTable {
        LuaTable::new()
    }

    fn make_response_table() -> LuaTable {
        let mut t = LuaTable::new();
        t.rawset(
            LuaKey::String(crate::types::value::LuaString::from_str("result")),
            LuaValue::Integer(42),
        )
        .unwrap();
        t
    }

    #[test]
    fn successful_call_records_ok() {
        let resp = make_response_table();
        let mut registry = ToolRegistry::new(MockHost::ok(resp));
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let config = make_config();
        let args = make_empty_table();

        let result = registry.call("search", &args, &config, &mut gas, &mut transcript);
        assert!(result.is_ok());
        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript.records()[0].status, ToolCallStatus::Ok);
        assert_eq!(transcript.records()[0].tool_name, "search");
    }

    #[test]
    fn max_tool_calls_exceeded() {
        let mut registry = ToolRegistry::new(MockHost::ok(make_empty_table()));
        let config = VmConfig {
            max_tool_calls: 2,
            ..VmConfig::default()
        };
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        // First two calls succeed.
        registry
            .call("t", &args, &config, &mut gas, &mut transcript)
            .unwrap();
        registry
            .call("t", &args, &config, &mut gas, &mut transcript)
            .unwrap();
        // Third call fails.
        let err = registry
            .call("t", &args, &config, &mut gas, &mut transcript)
            .unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
        if let VmError::RuntimeError(LuaValue::String(s)) = err {
            assert!(String::from_utf8_lossy(s.as_bytes()).contains("limit exceeded"));
        }
    }

    #[test]
    fn max_bytes_in_exceeded_before_host_called() {
        // Set bytes_in limit to 1 byte; even empty table {} = 2 bytes > 1.
        let config = VmConfig {
            max_tool_bytes_in: 1,
            ..VmConfig::default()
        };
        // Use NoopHost — it should NOT be called.
        let mut registry = ToolRegistry::new(NoopHost);
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        let err = registry
            .call("t", &args, &config, &mut gas, &mut transcript)
            .unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
        // No transcript entry because we failed before calling host.
        assert_eq!(transcript.len(), 0);
    }

    #[test]
    fn max_bytes_out_exceeded_after_host_responds() {
        let resp = make_response_table();
        let config = VmConfig {
            max_tool_bytes_out: 1,
            ..VmConfig::default()
        };
        let mut registry = ToolRegistry::new(MockHost::ok(resp));
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        let err = registry
            .call("t", &args, &config, &mut gas, &mut transcript)
            .unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
        if let VmError::RuntimeError(LuaValue::String(s)) = err {
            assert!(String::from_utf8_lossy(s.as_bytes()).contains("output"));
        }
    }

    #[test]
    fn host_error_records_error_in_transcript() {
        let mut registry = ToolRegistry::new(MockHost::err("tool failed"));
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let config = make_config();
        let args = make_empty_table();

        let err = registry
            .call("broken", &args, &config, &mut gas, &mut transcript)
            .unwrap_err();
        assert!(matches!(err, VmError::ToolError(_)));
        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript.records()[0].status, ToolCallStatus::Error);
        assert_eq!(transcript.records()[0].gas_charged, 0);
    }

    #[test]
    fn gas_charged_for_successful_call() {
        let resp = make_response_table();
        let mut registry = ToolRegistry::new(MockHost::ok(resp));
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let config = make_config();
        let args = make_empty_table();

        let initial_gas = gas.used();
        registry
            .call("search", &args, &config, &mut gas, &mut transcript)
            .unwrap();
        assert!(gas.used() > initial_gas);
        // gas_charged in transcript matches gas used.
        let record = &transcript.records()[0];
        assert!(record.gas_charged >= gas_cost::TOOL_CALL_BASE);
    }

    #[cfg(feature = "std")]
    mod policy_tests {
        use super::*;
        use crate::policy::{OraclePolicy, TlsRequirement};
        use std::collections::HashMap;

        fn http_args(url: &str) -> LuaTable {
            let mut t = LuaTable::new();
            t.rawset(
                LuaKey::String(LuaString::from_str("url")),
                LuaValue::String(LuaString::from_str(url)),
            )
            .unwrap();
            t
        }

        fn allow_get_policy() -> OraclePolicy {
            OraclePolicy {
                allowed_domains: vec![],
                allowed_http_methods: vec!["http_get".to_owned()],
                max_tool_calls: 10,
                max_payload_bytes_per_call: 64 * 1024,
                tls_requirement: TlsRequirement::UnattestedPermitted,
                required_output_schema: None,
                schema_versions: HashMap::new(),
            }
        }

        #[test]
        fn policy_blocks_http_post_when_only_get_allowed() {
            let mut registry =
                ToolRegistry::with_policy(MockHost::ok(make_response_table()), allow_get_policy());
            let mut gas = make_gas();
            let mut transcript = Transcript::new();
            let config = make_config();
            let args = http_args("https://example.com/");

            let err = registry
                .call("http_post", &args, &config, &mut gas, &mut transcript)
                .unwrap_err();
            assert!(matches!(err, VmError::RuntimeError(_)));
            if let VmError::RuntimeError(LuaValue::String(s)) = err {
                let msg = String::from_utf8_lossy(s.as_bytes());
                assert!(msg.contains("policy"), "expected 'policy' in: {msg}");
            }
        }

        #[test]
        fn policy_allows_http_get_when_in_allowed_methods() {
            let mut registry =
                ToolRegistry::with_policy(MockHost::ok(make_response_table()), allow_get_policy());
            let mut gas = make_gas();
            let mut transcript = Transcript::new();
            let config = make_config();
            let args = http_args("https://example.com/");

            let result = registry.call("http_get", &args, &config, &mut gas, &mut transcript);
            assert!(result.is_ok());
        }

        #[test]
        fn policy_blocks_domain_not_in_allowlist() {
            let policy = OraclePolicy {
                allowed_domains: vec!["approved.com".to_owned()],
                allowed_http_methods: vec![],
                max_tool_calls: 10,
                max_payload_bytes_per_call: 64 * 1024,
                tls_requirement: TlsRequirement::UnattestedPermitted,
                required_output_schema: None,
                schema_versions: HashMap::new(),
            };
            let mut registry =
                ToolRegistry::with_policy(MockHost::ok(make_response_table()), policy);
            let mut gas = make_gas();
            let mut transcript = Transcript::new();
            let config = make_config();
            let args = http_args("https://evil.com/data");

            let err = registry
                .call("http_get", &args, &config, &mut gas, &mut transcript)
                .unwrap_err();
            assert!(matches!(err, VmError::RuntimeError(_)));
            if let VmError::RuntimeError(LuaValue::String(s)) = err {
                let msg = String::from_utf8_lossy(s.as_bytes());
                assert!(msg.contains("policy"), "expected 'policy' in: {msg}");
            }
        }

        #[test]
        fn policy_schema_mismatch_returns_vm_error() {
            let mut schema_versions = HashMap::new();
            schema_versions.insert(
                "api.example.com".to_owned(),
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

            let mut registry = ToolRegistry::with_policy(MockHost::ok(resp), policy);
            let mut gas = make_gas();
            let mut transcript = Transcript::new();
            let config = make_config();
            let args = http_args("https://api.example.com/price");

            let err = registry
                .call("http_get", &args, &config, &mut gas, &mut transcript)
                .unwrap_err();
            assert!(matches!(err, VmError::RuntimeError(_)));
            if let VmError::RuntimeError(LuaValue::String(s)) = err {
                let msg = String::from_utf8_lossy(s.as_bytes());
                assert!(msg.contains("policy"), "expected 'policy' in: {msg}");
            }
        }
    }
}
