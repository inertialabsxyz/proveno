//! Oracle execution policy.
//!
//! `OraclePolicy` is a first-class artifact that defines what counts as an
//! acceptable oracle execution. Its `policy_hash()` is committed to in
//! `PublicInputs`, making it machine-checkable and on-chain verifiable.
//!
//! See `docs/canonical-serialization.md` for the byte-exact hash format.

pub mod profiles;

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// TLS enforcement requirement for HTTPS tool calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsRequirement {
    /// Every HTTPS response must carry a P-256 ECDSA-verified attestation.
    RequiredAttested,
    /// HTTPS responses should be attested; unattested calls are allowed but flagged.
    PreferredAttested,
    /// TLS attestation is not required.
    UnattestedPermitted,
}

/// Defines admissibility for one oracle execution.
///
/// An execution is *policy-approved* only when every tool call satisfies
/// the constraints below. The `policy_hash()` commits to this document so
/// a verifier can point to a single hash and know exactly what was allowed.
#[derive(Debug, Clone)]
pub struct OraclePolicy {
    /// Domains that `http_get` / `http_post` may contact.
    /// Empty = no domain restriction (any domain is allowed).
    pub allowed_domains: Vec<String>,

    /// HTTP tool names that may be called (`"http_get"`, `"http_post"`, …).
    /// Empty = no method restriction (all HTTP tools are allowed).
    pub allowed_http_methods: Vec<String>,

    /// Maximum number of tool calls per execution.
    pub max_tool_calls: usize,

    /// Maximum serialized byte size of each tool call's response.
    pub max_payload_bytes_per_call: usize,

    /// TLS attestation requirement for HTTPS calls.
    pub tls_requirement: TlsRequirement,

    /// Optional JSON schema that the program's final output must match.
    pub required_output_schema: Option<serde_json::Value>,

    /// Per-domain response schemas. After a successful HTTP tool call, the
    /// response JSON is validated against the schema registered for that domain.
    /// Domains with no entry are not validated.
    ///
    /// `// Phase 4 stub` — populated by template_price_feed_v1 in Phase 4.
    pub schema_versions: HashMap<String, serde_json::Value>,
}

impl OraclePolicy {
    /// Produce the stable canonical byte representation of this policy.
    ///
    /// The format is specified in `docs/canonical-serialization.md`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        // 1. allowed_domains: sorted, each as u32LE(len) || utf8
        let mut domains = self.allowed_domains.clone();
        domains.sort();
        out.extend_from_slice(&(domains.len() as u32).to_le_bytes());
        for d in &domains {
            let b = d.as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }

        // 2. allowed_http_methods: sorted, each as u32LE(len) || utf8
        let mut methods = self.allowed_http_methods.clone();
        methods.sort();
        out.extend_from_slice(&(methods.len() as u32).to_le_bytes());
        for m in &methods {
            let b = m.as_bytes();
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }

        // 3. max_tool_calls: u64LE
        out.extend_from_slice(&(self.max_tool_calls as u64).to_le_bytes());

        // 4. max_payload_bytes_per_call: u64LE
        out.extend_from_slice(&(self.max_payload_bytes_per_call as u64).to_le_bytes());

        // 5. tls_requirement: u8 (0=UnattestedPermitted, 1=PreferredAttested, 2=RequiredAttested)
        out.push(match self.tls_requirement {
            TlsRequirement::UnattestedPermitted => 0u8,
            TlsRequirement::PreferredAttested => 1u8,
            TlsRequirement::RequiredAttested => 2u8,
        });

        // 6. required_output_schema: u32LE(len) || canonical_json_bytes; len=0 if None
        let schema_bytes = self
            .required_output_schema
            .as_ref()
            .map(canonical_json_bytes)
            .unwrap_or_default();
        out.extend_from_slice(&(schema_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&schema_bytes);

        // 7. schema_versions: sorted by domain, each as:
        //    u32LE(domain_len) || domain_bytes || u32LE(schema_len) || schema_bytes
        let mut pairs: Vec<(&String, &serde_json::Value)> = self.schema_versions.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        for (domain, schema) in &pairs {
            let db = domain.as_bytes();
            out.extend_from_slice(&(db.len() as u32).to_le_bytes());
            out.extend_from_slice(db);
            let sb = canonical_json_bytes(schema);
            out.extend_from_slice(&(sb.len() as u32).to_le_bytes());
            out.extend_from_slice(&sb);
        }

        out
    }

    /// SHA-256 of `canonical_bytes()`. Stable across machines and runs.
    pub fn policy_hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Check whether the given HTTP tool call is permitted by this policy.
    ///
    /// Returns `Err(reason)` if the call violates the method or domain restriction.
    pub fn check_http_call(&self, tool_name: &str, url: &str) -> Result<(), String> {
        // Method restriction.
        if !self.allowed_http_methods.is_empty()
            && !self.allowed_http_methods.iter().any(|m| m == tool_name)
        {
            return Err(format!(
                "policy: HTTP method '{}' is not in allowed_http_methods",
                tool_name
            ));
        }

        // Domain restriction.
        if !self.allowed_domains.is_empty() {
            let domain = extract_domain(url).unwrap_or("");
            if !self.allowed_domains.iter().any(|d| d == domain) {
                return Err(format!(
                    "policy: domain '{}' is not in allowed_domains",
                    domain
                ));
            }
        }

        Ok(())
    }

    /// Validate a tool response (as canonical JSON bytes) against the per-domain
    /// schema, if one is registered. Returns `Err(reason)` on mismatch.
    pub fn check_response_schema(&self, url: &str, response_bytes: &[u8]) -> Result<(), String> {
        let domain = extract_domain(url).unwrap_or("");
        let schema = match self.schema_versions.get(domain) {
            Some(s) => s,
            None => return Ok(()),
        };

        let actual: serde_json::Value = serde_json::from_slice(response_bytes)
            .map_err(|e| format!("policy: response is not valid JSON: {}", e))?;

        if !schema_matches(schema, &actual) {
            return Err(format!(
                "policy: response from '{}' does not match registered schema",
                domain
            ));
        }

        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Extract the hostname from a URL string (no port, no path).
///
/// `"https://api.example.com/v1/price"` → `"api.example.com"`
pub fn extract_domain(url: &str) -> Option<&str> {
    let rest = if let Some(idx) = url.find("://") {
        &url[idx + 3..]
    } else {
        url
    };
    let rest = rest.split('/').next().unwrap_or(rest);
    let host = rest.split(':').next().unwrap_or(rest);
    if host.is_empty() { None } else { Some(host) }
}

/// Check whether `actual` satisfies `schema`.
///
/// Each key in a schema object must be present in `actual` with a value of
/// the same JSON type. `null` in the schema accepts any value.
/// Extra keys in `actual` are permitted.
fn schema_matches(schema: &serde_json::Value, actual: &serde_json::Value) -> bool {
    match schema {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(_) => actual.is_boolean(),
        serde_json::Value::Number(_) => actual.is_number(),
        serde_json::Value::String(_) => actual.is_string(),
        serde_json::Value::Array(schema_arr) => {
            if !actual.is_array() {
                return false;
            }
            if let (Some(item_schema), Some(actual_arr)) = (schema_arr.first(), actual.as_array()) {
                actual_arr.iter().all(|v| schema_matches(item_schema, v))
            } else {
                true
            }
        }
        serde_json::Value::Object(schema_map) => {
            let Some(actual_map) = actual.as_object() else {
                return false;
            };
            schema_map.iter().all(|(key, schema_val)| {
                actual_map
                    .get(key)
                    .is_some_and(|v| schema_matches(schema_val, v))
            })
        }
    }
}

/// Serialize a `serde_json::Value` to canonical (sorted-key) JSON bytes.
///
/// Object keys are sorted lexicographically. The output is compact (no whitespace).
/// This produces the same bytes on any machine for the same value.
fn canonical_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    canonical_json_write(v).into_bytes()
}

fn canonical_json_write(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_owned(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json_write).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            let items: Vec<String> = pairs
                .iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()),
                        canonical_json_write(val)
                    )
                })
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_policy() -> OraclePolicy {
        OraclePolicy {
            allowed_domains: vec![],
            allowed_http_methods: vec![],
            max_tool_calls: 16,
            max_payload_bytes_per_call: 64 * 1024,
            tls_requirement: TlsRequirement::UnattestedPermitted,
            required_output_schema: None,
            schema_versions: HashMap::new(),
        }
    }

    #[test]
    fn policy_hash_is_32_bytes() {
        let h = minimal_policy().policy_hash();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn policy_hash_stable_across_calls() {
        let p = minimal_policy();
        assert_eq!(p.policy_hash(), p.policy_hash());
    }

    #[test]
    fn policy_hash_differs_for_different_policies() {
        let p1 = minimal_policy();
        let mut p2 = minimal_policy();
        p2.max_tool_calls = 5;
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn canonical_json_bytes_sorts_keys() {
        let v: serde_json::Value = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let s = String::from_utf8(canonical_json_bytes(&v)).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn extract_domain_strips_scheme_path_port() {
        assert_eq!(
            extract_domain("https://api.example.com/v1"),
            Some("api.example.com")
        );
        assert_eq!(extract_domain("http://foo.bar:8080/path"), Some("foo.bar"));
        assert_eq!(extract_domain("example.com"), Some("example.com"));
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn check_http_call_allows_when_domains_empty() {
        let p = minimal_policy();
        assert!(
            p.check_http_call("http_get", "https://anywhere.com/")
                .is_ok()
        );
    }

    #[test]
    fn check_http_call_rejects_unlisted_domain() {
        let mut p = minimal_policy();
        p.allowed_domains = vec!["approved.com".to_owned()];
        assert!(
            p.check_http_call("http_get", "https://evil.com/price")
                .is_err()
        );
    }

    #[test]
    fn check_http_call_accepts_listed_domain() {
        let mut p = minimal_policy();
        p.allowed_domains = vec!["approved.com".to_owned()];
        assert!(
            p.check_http_call("http_get", "https://approved.com/price")
                .is_ok()
        );
    }

    #[test]
    fn check_http_call_rejects_unlisted_method() {
        let mut p = minimal_policy();
        p.allowed_http_methods = vec!["http_get".to_owned()];
        assert!(
            p.check_http_call("http_post", "https://example.com/")
                .is_err()
        );
    }

    #[test]
    fn check_response_schema_passes_when_no_schema() {
        let p = minimal_policy();
        let resp = b"{\"status\":200,\"body\":\"ok\"}";
        assert!(
            p.check_response_schema("https://example.com/", resp)
                .is_ok()
        );
    }

    #[test]
    fn check_response_schema_passes_matching_schema() {
        let mut p = minimal_policy();
        p.schema_versions.insert(
            "example.com".to_owned(),
            serde_json::json!({"status": 0, "body": ""}),
        );
        let resp = b"{\"status\":200,\"body\":\"hello\"}";
        assert!(
            p.check_response_schema("https://example.com/", resp)
                .is_ok()
        );
    }

    #[test]
    fn check_response_schema_rejects_mismatch() {
        let mut p = minimal_policy();
        p.schema_versions.insert(
            "example.com".to_owned(),
            serde_json::json!({"status": 0, "body": ""}),
        );
        // "body" is an integer, schema expects string
        let resp = b"{\"status\":200,\"body\":42}";
        assert!(
            p.check_response_schema("https://example.com/", resp)
                .is_err()
        );
    }

    #[test]
    fn check_response_schema_rejects_missing_key() {
        let mut p = minimal_policy();
        p.schema_versions.insert(
            "example.com".to_owned(),
            serde_json::json!({"status": 0, "body": ""}),
        );
        // Missing "body"
        let resp = b"{\"status\":200}";
        assert!(
            p.check_response_schema("https://example.com/", resp)
                .is_err()
        );
    }
}
