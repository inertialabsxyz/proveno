//! `ToolRegistry` — wraps `HostInterface` and enforces VM-side quotas for tool calls.

use crate::{
    host::{
        canonicalize::{canonical_serialize_table, CanonError},
        transcript::Transcript,
    },
    types::{
        table::LuaTable,
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
}

impl<H: HostInterface> ToolRegistry<H> {
    pub fn new(host: H) -> Self {
        ToolRegistry {
            host,
            calls_made: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
        }
    }

    /// Reset counters for a new execution.
    pub fn reset(&mut self) {
        self.calls_made = 0;
        self.total_bytes_in = 0;
        self.total_bytes_out = 0;
    }

    /// Consume the registry and return the underlying host.
    pub fn into_host(self) -> H {
        self.host
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
            return Err(VmError::RuntimeError(LuaValue::String(LuaString::from_str(
                "tool call limit exceeded",
            ))));
        }

        // 3. Check bytes-in quota.
        if self.total_bytes_in + args_canonical.len() > config.max_tool_bytes_in {
            return Err(VmError::RuntimeError(LuaValue::String(LuaString::from_str(
                "tool input bytes limit exceeded",
            ))));
        }

        // 4. Increment counters.
        self.calls_made += 1;
        self.total_bytes_in += args_canonical.len();

        // 5. Call the host.
        let result = self.host.call_tool(name, args_table);

        match result {
            Ok(resp_table) => {
                // 6a. Serialize response.
                let resp_canonical =
                    canonical_serialize_table(&resp_table).map_err(|e| match e {
                        CanonError::TableDepthExceeded => VmError::RuntimeError(LuaValue::String(
                            LuaString::from_str("tool response: table depth exceeded"),
                        )),
                        other => VmError::from(other),
                    })?;

                // 6b. Check bytes-out quota.
                if self.total_bytes_out + resp_canonical.len() > config.max_tool_bytes_out {
                    return Err(VmError::RuntimeError(LuaValue::String(LuaString::from_str(
                        "tool output bytes limit exceeded",
                    ))));
                }

                // 6c. Update bytes-out counter.
                self.total_bytes_out += resp_canonical.len();

                // 6d. Charge gas: 100 + args_bytes + resp_bytes.
                let gas_cost = gas_cost::TOOL_CALL_BASE
                    + args_canonical.len() as u64
                    + resp_canonical.len() as u64;
                gas.charge(gas_cost)?;

                // 6e. Record transcript.
                transcript.record_ok(name, args_canonical, resp_canonical, gas_cost);

                // 6f. Return table.
                Ok(resp_table)
            }
            Err(msg) => {
                // 7. Record error transcript with gas_charged = 0.
                transcript.record_error(name, args_canonical, 0, &msg);
                Err(VmError::ToolError(msg))
            }
        }
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
        fn ok(t: LuaTable) -> Self { MockHost { response: Ok(t) } }
        fn err(msg: &str) -> Self { MockHost { response: Err(msg.to_owned()) } }
    }

    impl HostInterface for MockHost {
        fn call_tool(&mut self, _name: &str, _args: &LuaTable) -> Result<LuaTable, String> {
            self.response.clone()
        }
    }

    fn make_config() -> VmConfig { VmConfig::default() }
    fn make_gas() -> GasMeter { GasMeter::new(1_000_000) }
    fn make_empty_table() -> LuaTable { LuaTable::new() }

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
        let config = VmConfig { max_tool_calls: 2, ..VmConfig::default() };
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        // First two calls succeed.
        registry.call("t", &args, &config, &mut gas, &mut transcript).unwrap();
        registry.call("t", &args, &config, &mut gas, &mut transcript).unwrap();
        // Third call fails.
        let err = registry.call("t", &args, &config, &mut gas, &mut transcript).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
        if let VmError::RuntimeError(LuaValue::String(s)) = err {
            assert!(String::from_utf8_lossy(s.as_bytes()).contains("limit exceeded"));
        }
    }

    #[test]
    fn max_bytes_in_exceeded_before_host_called() {
        // Set bytes_in limit to 1 byte; even empty table {} = 2 bytes > 1.
        let config = VmConfig { max_tool_bytes_in: 1, ..VmConfig::default() };
        // Use NoopHost — it should NOT be called.
        let mut registry = ToolRegistry::new(NoopHost);
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        let err = registry.call("t", &args, &config, &mut gas, &mut transcript).unwrap_err();
        assert!(matches!(err, VmError::RuntimeError(_)));
        // No transcript entry because we failed before calling host.
        assert_eq!(transcript.len(), 0);
    }

    #[test]
    fn max_bytes_out_exceeded_after_host_responds() {
        let resp = make_response_table();
        let config = VmConfig { max_tool_bytes_out: 1, ..VmConfig::default() };
        let mut registry = ToolRegistry::new(MockHost::ok(resp));
        let mut gas = make_gas();
        let mut transcript = Transcript::new();
        let args = make_empty_table();

        let err = registry.call("t", &args, &config, &mut gas, &mut transcript).unwrap_err();
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

        let err = registry.call("broken", &args, &config, &mut gas, &mut transcript).unwrap_err();
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
        registry.call("search", &args, &config, &mut gas, &mut transcript).unwrap();
        assert!(gas.used() > initial_gas);
        // gas_charged in transcript matches gas used.
        let record = &transcript.records()[0];
        assert!(record.gas_charged >= gas_cost::TOOL_CALL_BASE);
    }
}
