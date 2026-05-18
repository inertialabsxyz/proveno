//! Named execution profiles.
//!
//! Each profile function returns a ready-to-use `OraclePolicy` with
//! pre-configured constraints. Callers should treat these as canonical
//! starting points; the `policy_hash()` of each profile is stable.

use std::collections::HashMap;

use super::{OraclePolicy, TlsRequirement};

/// Permissive HTTP oracle: `http_get` only, any domain, no schema constraint.
///
/// Use this for ad-hoc oracle tasks that only need GET and do not require
/// TLS attestation or per-domain response validation.
pub fn constrained_http_v1() -> OraclePolicy {
    OraclePolicy {
        allowed_domains: vec![],
        allowed_http_methods: vec!["http_get".to_owned()],
        max_tool_calls: 16,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::UnattestedPermitted,
        required_output_schema: None,
        schema_versions: HashMap::new(),
    }
}

/// Price-feed oracle template: `http_get` only, approved sources TBD, attested.
///
/// This is the Phase 4 template profile. Domain list and response schemas are
/// populated in Phase 4; they are left empty here as stubs.
pub fn template_price_feed_v1() -> OraclePolicy {
    OraclePolicy {
        allowed_domains: vec![], // Phase 4 stub
        allowed_http_methods: vec!["http_get".to_owned()],
        max_tool_calls: 5,
        max_payload_bytes_per_call: 64 * 1024,
        tls_requirement: TlsRequirement::RequiredAttested,
        required_output_schema: None,
        schema_versions: HashMap::new(), // Phase 4 stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_http_v1_hash_is_stable() {
        let h1 = constrained_http_v1().policy_hash();
        let h2 = constrained_http_v1().policy_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn template_price_feed_v1_hash_is_stable() {
        let h1 = template_price_feed_v1().policy_hash();
        let h2 = template_price_feed_v1().policy_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn profiles_have_distinct_hashes() {
        let h1 = constrained_http_v1().policy_hash();
        let h2 = template_price_feed_v1().policy_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn constrained_http_v1_only_allows_get() {
        let p = constrained_http_v1();
        assert!(p.check_http_call("http_get", "https://any.com/").is_ok());
        assert!(p.check_http_call("http_post", "https://any.com/").is_err());
    }

    #[test]
    fn template_price_feed_v1_only_allows_get() {
        let p = template_price_feed_v1();
        assert!(p.check_http_call("http_get", "https://any.com/").is_ok());
        assert!(p.check_http_call("http_post", "https://any.com/").is_err());
    }

    #[test]
    fn template_price_feed_v1_has_max_5_tool_calls() {
        assert_eq!(template_price_feed_v1().max_tool_calls, 5);
    }

    #[test]
    fn template_price_feed_v1_requires_attested_tls() {
        assert_eq!(
            template_price_feed_v1().tls_requirement,
            TlsRequirement::RequiredAttested
        );
    }
}
