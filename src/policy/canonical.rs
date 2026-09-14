//! `no_std` view over `OraclePolicy::canonical_bytes()`.
//!
//! The zkVM guest cannot construct an [`OraclePolicy`](super::OraclePolicy):
//! that type carries `serde_json` schemas and needs `std`. But it already
//! receives the policy's canonical bytes in order to derive `policy_hash`, and
//! that encoding is fully self-describing. This module parses the parts a guest
//! can meaningfully enforce out of those same bytes.
//!
//! Deriving both the hash and the enforcement from one buffer is the point: the
//! policy that gets enforced and the policy that gets committed cannot disagree,
//! because there is only one of them.
//!
//! Sections 6 and 7 of the encoding (`required_output_schema` and
//! `schema_versions`) are parsed for length only, never interpreted — JSON
//! schema validation stays host-side. That part remains bind-only.

use alloc::{format, string::String, vec::Vec};

use crate::types::{
    table::{LuaKey, LuaTable},
    value::{LuaString, LuaValue},
};

/// TLS enforcement requirement for HTTPS tool calls.
///
/// Lives here rather than beside `OraclePolicy` so the guest can name it
/// without pulling in `std`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TlsRequirement {
    /// Every HTTPS response must carry a P-256 ECDSA-verified attestation.
    RequiredAttested,
    /// HTTPS responses should be attested; unattested calls are allowed but flagged.
    PreferredAttested,
    /// TLS attestation is not required.
    UnattestedPermitted,
}

/// Host portion of a URL, with scheme, path and port stripped.
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

/// Whether a tool name is one the HTTP policy rules apply to.
pub fn is_http_tool(name: &str) -> bool {
    matches!(name, "http_get" | "http_post")
}

/// Extract the `url` string from a tool call's argument table.
///
/// Lives here rather than in `host` because only policy enforcement reads it:
/// both `OraclePolicyHost` (host-side) and `guest::PolicyEnforcingHost`
/// (in-guest) must pull the URL out of a call the same way, or the policy
/// enforced during a dry run would not be the policy enforced during replay.
pub fn get_url_from_args(args: &LuaTable) -> Option<String> {
    let key = LuaKey::String(LuaString::from_str("url"));
    match args.get(&key) {
        Some(LuaValue::String(s)) => Some(String::from_utf8_lossy(s.as_bytes()).into_owned()),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyParseError {
    /// Ran off the end of the buffer while reading a field.
    Truncated { at: usize },
    /// A length prefix claims more bytes than remain.
    LengthOverrun { at: usize, len: usize },
    /// A domain or method was not valid UTF-8.
    NotUtf8 { at: usize },
    /// The tls_requirement byte was not 0, 1 or 2.
    BadTlsRequirement(u8),
    /// Bytes remained after the final section.
    TrailingBytes { extra: usize },
}

impl core::fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { at } => write!(f, "policy bytes truncated at offset {at}"),
            Self::LengthOverrun { at, len } => {
                write!(
                    f,
                    "policy length prefix {len} at offset {at} overruns buffer"
                )
            }
            Self::NotUtf8 { at } => write!(f, "policy string at offset {at} is not UTF-8"),
            Self::BadTlsRequirement(b) => write!(f, "policy tls_requirement byte {b} is not 0/1/2"),
            Self::TrailingBytes { extra } => write!(f, "{extra} trailing bytes after policy"),
        }
    }
}

/// The enforceable subset of a policy, borrowed from its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView<'a> {
    /// Empty means *no restriction*, not *deny everything*.
    pub allowed_domains: Vec<&'a str>,
    /// Empty means *no restriction*.
    pub allowed_http_methods: Vec<&'a str>,
    pub max_tool_calls: u64,
    pub max_payload_bytes_per_call: u64,
    pub tls_requirement: TlsRequirement,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PolicyParseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PolicyParseError::LengthOverrun {
                at: self.pos,
                len: n,
            })?;
        if end > self.buf.len() {
            return Err(PolicyParseError::LengthOverrun {
                at: self.pos,
                len: n,
            });
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u32le(&mut self) -> Result<u32, PolicyParseError> {
        let at = self.pos;
        let b = self
            .take(4)
            .map_err(|_| PolicyParseError::Truncated { at })?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64le(&mut self) -> Result<u64, PolicyParseError> {
        let at = self.pos;
        let b = self
            .take(8)
            .map_err(|_| PolicyParseError::Truncated { at })?;
        let mut w = [0u8; 8];
        w.copy_from_slice(b);
        Ok(u64::from_le_bytes(w))
    }

    fn u8(&mut self) -> Result<u8, PolicyParseError> {
        let at = self.pos;
        Ok(self
            .take(1)
            .map_err(|_| PolicyParseError::Truncated { at })?[0])
    }

    /// `u32LE(count)` followed by `count` × (`u32LE(len)` ‖ utf8).
    fn string_list(&mut self) -> Result<Vec<&'a str>, PolicyParseError> {
        let count = self.u32le()? as usize;
        let mut out = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let len = self.u32le()? as usize;
            let at = self.pos;
            let bytes = self.take(len)?;
            out.push(core::str::from_utf8(bytes).map_err(|_| PolicyParseError::NotUtf8 { at })?);
        }
        Ok(out)
    }

    /// A length-prefixed blob we do not interpret.
    fn skip_blob(&mut self) -> Result<(), PolicyParseError> {
        let len = self.u32le()? as usize;
        self.take(len)?;
        Ok(())
    }
}

impl<'a> PolicyView<'a> {
    /// Parse `OraclePolicy::canonical_bytes()`.
    ///
    /// Strict: the whole buffer must be consumed. A policy that does not parse
    /// cleanly is refused rather than partially applied, because a partially
    /// applied policy is indistinguishable from a weaker one.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PolicyParseError> {
        let mut r = Reader { buf: bytes, pos: 0 };

        let allowed_domains = r.string_list()?;
        let allowed_http_methods = r.string_list()?;
        let max_tool_calls = r.u64le()?;
        let max_payload_bytes_per_call = r.u64le()?;
        let tls_requirement = match r.u8()? {
            0 => TlsRequirement::UnattestedPermitted,
            1 => TlsRequirement::PreferredAttested,
            2 => TlsRequirement::RequiredAttested,
            other => return Err(PolicyParseError::BadTlsRequirement(other)),
        };

        // 6. required_output_schema, 7. schema_versions — walked to confirm the
        // buffer is well formed, never interpreted.
        r.skip_blob()?;
        let pairs = r.u32le()? as usize;
        for _ in 0..pairs {
            r.skip_blob()?; // domain
            r.skip_blob()?; // schema
        }

        if r.pos != bytes.len() {
            return Err(PolicyParseError::TrailingBytes {
                extra: bytes.len() - r.pos,
            });
        }

        Ok(PolicyView {
            allowed_domains,
            allowed_http_methods,
            max_tool_calls,
            max_payload_bytes_per_call,
            tls_requirement,
        })
    }

    /// Whether this HTTP tool call is permitted.
    ///
    /// Mirrors `OraclePolicy::check_http_call`, including its messages, so a
    /// rejection reads identically whether it came from the host during the dry
    /// run or from the guest during replay.
    pub fn check_http_call(&self, tool_name: &str, url: &str) -> Result<(), String> {
        if !self.allowed_http_methods.is_empty() && !self.allowed_http_methods.contains(&tool_name)
        {
            return Err(format!(
                "policy: HTTP method '{tool_name}' is not in allowed_http_methods"
            ));
        }

        if !self.allowed_domains.is_empty() {
            let domain = extract_domain(url).unwrap_or("");
            if !self.allowed_domains.contains(&domain) {
                return Err(format!(
                    "policy: domain '{domain}' is not in allowed_domains"
                ));
            }
        }

        Ok(())
    }
}
