//! A `HostInterface` wrapper that enforces the `no_std` part of a policy.
//!
//! The zkVM guest replays against a [`TapeHost`](super::tape::TapeHost), which
//! ignores the tool name and arguments entirely and just hands back the next
//! recorded response. But the program *computes* those arguments inside the
//! guest, so the URL a program asked for is proven data that was simply being
//! discarded. Wrapping the tape host lets the guest check it.
//!
//! This is what turns `policy_hash` from a label into a claim. Without it the
//! proof says "this execution declares policy X" while nothing in the proof
//! depends on X; with it, an execution that violates the policy cannot produce
//! a proof at all, because the replay fails.
//!
//! Scope: method restriction, domain allowlist and the tool-call cap, all of
//! which are decidable from data the guest already has. JSON schema validation
//! stays host-side, since it needs `serde_json`, and payload size is checked
//! against the tape before replay rather than here (the tape entries *are* the
//! canonical response bytes, so re-serializing to measure them would be wasted
//! guest cycles).

use alloc::{format, string::String, vec::Vec};

use crate::{
    policy::canonical::{PolicyView, get_url_from_args, is_http_tool},
    types::table::LuaTable,
    vm::engine::HostInterface,
};

/// Wraps a host and rejects tool calls the policy does not permit.
pub struct PolicyEnforcingHost<'a, H> {
    inner: H,
    policy: PolicyView<'a>,
    calls_made: u64,
}

impl<'a, H: HostInterface> PolicyEnforcingHost<'a, H> {
    pub fn new(inner: H, policy: PolicyView<'a>) -> Self {
        PolicyEnforcingHost {
            inner,
            policy,
            calls_made: 0,
        }
    }

    /// Number of calls attempted, including any the policy rejected.
    pub fn calls_made(&self) -> u64 {
        self.calls_made
    }
}

impl<H: HostInterface> HostInterface for PolicyEnforcingHost<'_, H> {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        // Counted before the checks below, so a rejected call still consumes
        // budget. Otherwise a program could probe disallowed domains for free.
        self.calls_made += 1;
        if self.calls_made > self.policy.max_tool_calls {
            return Err(format!(
                "policy: tool call limit {} exceeded",
                self.policy.max_tool_calls
            ));
        }

        if is_http_tool(name) {
            // A missing or non-string `url` becomes "", which fails the domain
            // check whenever an allowlist is set. Defaulting to permitted here
            // would let a program dodge the allowlist by omitting the argument.
            let url = get_url_from_args(args).unwrap_or_default();
            self.policy.check_http_call(name, &url)?;
        }

        self.inner.call_tool(name, args)
    }

    fn take_attestation(&mut self) -> Option<Vec<u8>> {
        self.inner.take_attestation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        host::tape::{OracleTape, TapeEntry, TapeHost},
        types::value::{LuaString, LuaValue},
    };
    use alloc::vec;

    /// Canonical bytes for a policy, built by hand so these tests do not need
    /// `std` or `OraclePolicy`.
    fn canonical(domains: &[&str], methods: &[&str], max_calls: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for list in [domains, methods] {
            out.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for s in list {
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
        out.extend_from_slice(&max_calls.to_le_bytes());
        out.extend_from_slice(&65536u64.to_le_bytes());
        out.push(0); // UnattestedPermitted
        out.extend_from_slice(&0u32.to_le_bytes()); // required_output_schema
        out.extend_from_slice(&0u32.to_le_bytes()); // schema_versions
        out
    }

    fn tape(n: usize) -> OracleTape {
        OracleTape {
            entries: (0..n).map(|_| TapeEntry::Ok(b"{}".to_vec())).collect(),
            attestations: vec![Vec::new(); n],
        }
    }

    fn args_with_url(url: &str) -> LuaTable {
        let mut t = LuaTable::new();
        t.rawset(
            crate::types::table::LuaKey::String(LuaString::from_str("url")),
            LuaValue::String(LuaString::from_str(url)),
        )
        .unwrap();
        t
    }

    fn host<'a>(bytes: &'a [u8], entries: usize) -> PolicyEnforcingHost<'a, TapeHost> {
        let view = PolicyView::parse(bytes).unwrap();
        PolicyEnforcingHost::new(TapeHost::new(tape(entries)), view)
    }

    #[test]
    fn allows_a_listed_domain() {
        let b = canonical(&["api.example.com"], &["http_get"], 4);
        let mut h = host(&b, 1);
        assert!(
            h.call_tool("http_get", &args_with_url("https://api.example.com/v1"))
                .is_ok()
        );
    }

    #[test]
    fn rejects_an_unlisted_domain() {
        let b = canonical(&["api.example.com"], &["http_get"], 4);
        let mut h = host(&b, 1);
        let err = h
            .call_tool("http_get", &args_with_url("https://evil.example/steal"))
            .unwrap_err();
        assert!(err.contains("evil.example"), "got: {err}");
        assert!(err.contains("allowed_domains"), "got: {err}");
    }

    #[test]
    fn rejects_a_disallowed_method() {
        let b = canonical(&[], &["http_get"], 4);
        let mut h = host(&b, 1);
        let err = h
            .call_tool("http_post", &args_with_url("https://anywhere.example/"))
            .unwrap_err();
        assert!(err.contains("allowed_http_methods"), "got: {err}");
    }

    /// Omitting `url` must not be a way past the allowlist.
    #[test]
    fn missing_url_is_rejected_when_an_allowlist_is_set() {
        let b = canonical(&["api.example.com"], &[], 4);
        let mut h = host(&b, 1);
        assert!(h.call_tool("http_get", &LuaTable::new()).is_err());
    }

    #[test]
    fn enforces_the_tool_call_cap() {
        let b = canonical(&[], &[], 2);
        let mut h = host(&b, 4);
        let args = args_with_url("https://anywhere.example/");
        assert!(h.call_tool("http_get", &args).is_ok());
        assert!(h.call_tool("http_get", &args).is_ok());
        let err = h.call_tool("http_get", &args).unwrap_err();
        assert!(err.contains("tool call limit 2"), "got: {err}");
    }

    /// A rejected call still consumes budget, so probing is not free.
    #[test]
    fn rejected_calls_count_against_the_cap() {
        let b = canonical(&["api.example.com"], &[], 2);
        let mut h = host(&b, 4);
        assert!(
            h.call_tool("http_get", &args_with_url("https://evil.example/"))
                .is_err()
        );
        assert!(
            h.call_tool("http_get", &args_with_url("https://evil.example/"))
                .is_err()
        );
        let err = h
            .call_tool("http_get", &args_with_url("https://api.example.com/"))
            .unwrap_err();
        assert!(err.contains("tool call limit"), "got: {err}");
    }

    /// Empty lists mean unrestricted, matching OraclePolicy.
    #[test]
    fn empty_lists_permit_everything() {
        let b = canonical(&[], &[], 8);
        let mut h = host(&b, 1);
        assert!(
            h.call_tool("http_post", &args_with_url("https://anywhere.example/"))
                .is_ok()
        );
    }

    /// Non-HTTP tools are outside the domain and method rules but still counted.
    #[test]
    fn non_http_tools_skip_url_checks_but_count() {
        let b = canonical(&["api.example.com"], &["http_get"], 1);
        let mut h = host(&b, 2);
        assert!(h.call_tool("time_now", &LuaTable::new()).is_ok());
        assert!(h.call_tool("time_now", &LuaTable::new()).is_err());
    }
}
