use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use luai::{
    host::tls_attestation::TlsAttestation,
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::engine::HostInterface,
};

use crate::llm::LlmClient;
use crate::tls_capture::{TlsCaptureStore, build_capturing_client};

// ── helpers ──────────────────────────────────────────────────────────────────

fn str_key(s: &str) -> LuaKey {
    LuaKey::String(LuaString::from_str(s))
}

fn get_str(args: &LuaTable, key: &str) -> Result<String, String> {
    match args.get(&str_key(key)) {
        Some(LuaValue::String(s)) => Ok(String::from_utf8_lossy(s.as_bytes()).to_string()),
        Some(_) => Err(format!("expected string arg '{key}'")),
        None => Err(format!("missing required arg '{key}'")),
    }
}

fn get_opt_str(args: &LuaTable, key: &str) -> Option<String> {
    match args.get(&str_key(key)) {
        Some(LuaValue::String(s)) => Some(String::from_utf8_lossy(s.as_bytes()).to_string()),
        _ => None,
    }
}

// ── StubHost (kept for testing) ──────────────────────────────────────────────

#[cfg(test)]
#[derive(Debug)]
pub struct StubHost;

#[cfg(test)]
impl HostInterface for StubHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        let mut resp = LuaTable::new();

        match name {
            "echo" => {
                let msg = args
                    .get(&str_key("message"))
                    .cloned()
                    .unwrap_or(LuaValue::Nil);
                resp.rawset(str_key("message"), msg).unwrap();
            }
            "add" => {
                let a = match args.get(&str_key("a")) {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => return Err("add: expected integer arg 'a'".into()),
                };
                let b = match args.get(&str_key("b")) {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => return Err("add: expected integer arg 'b'".into()),
                };
                resp.rawset(str_key("result"), LuaValue::Integer(a + b))
                    .unwrap();
            }
            "upper" => {
                let text = match args.get(&str_key("text")) {
                    Some(LuaValue::String(s)) => {
                        String::from_utf8_lossy(s.as_bytes()).to_uppercase()
                    }
                    _ => return Err("upper: expected string arg 'text'".into()),
                };
                resp.rawset(
                    str_key("result"),
                    LuaValue::String(LuaString::from_str(&text)),
                )
                .unwrap();
            }
            "time_now" => {
                resp.rawset(str_key("timestamp"), LuaValue::Integer(1709654400))
                    .unwrap();
            }
            other => return Err(format!("unknown tool '{other}'")),
        }
        Ok(resp)
    }
}

// ── LiveHost ─────────────────────────────────────────────────────────────────

/// Maximum response body size for HTTP tools (1 MB).
const MAX_HTTP_BODY: usize = 1024 * 1024;
/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 30;

pub struct LiveHost {
    http: reqwest::blocking::Client,
    kv: HashMap<String, String>,
    llm: LlmClient,
    tls_store: TlsCaptureStore,
    tls_attestations: Vec<Option<TlsAttestation>>,
}

impl LiveHost {
    pub fn new(llm: LlmClient) -> Self {
        let tls_store = TlsCaptureStore::new();
        let http = build_capturing_client(tls_store.clone(), HTTP_TIMEOUT_SECS);
        LiveHost {
            http,
            kv: HashMap::new(),
            llm,
            tls_store,
            tls_attestations: Vec::new(),
        }
    }

    /// Consume the host and return captured TLS attestations (one per tool call).
    pub fn into_tls_attestations(self) -> Vec<Option<TlsAttestation>> {
        self.tls_attestations
    }

    fn tool_http_get(&self, args: &LuaTable) -> Result<LuaTable, String> {
        let url = get_str(args, "url")?;
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| format!("http_get failed: {e}"))?;
        let status = resp.status().as_u16() as i64;
        let body = resp
            .text()
            .map_err(|e| format!("http_get: failed to read body: {e}"))?;
        let body = if body.len() > MAX_HTTP_BODY {
            body[..MAX_HTTP_BODY].to_string()
        } else {
            body
        };

        let mut resp_table = LuaTable::new();
        resp_table
            .rawset(str_key("status"), LuaValue::Integer(status))
            .unwrap();
        resp_table
            .rawset(
                str_key("body"),
                LuaValue::String(LuaString::from_str(&body)),
            )
            .unwrap();
        Ok(resp_table)
    }

    fn tool_http_post(&self, args: &LuaTable) -> Result<LuaTable, String> {
        let url = get_str(args, "url")?;
        let body = get_str(args, "body")?;
        let resp = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|e| format!("http_post failed: {e}"))?;
        let status = resp.status().as_u16() as i64;
        let resp_body = resp
            .text()
            .map_err(|e| format!("http_post: failed to read body: {e}"))?;
        let resp_body = if resp_body.len() > MAX_HTTP_BODY {
            resp_body[..MAX_HTTP_BODY].to_string()
        } else {
            resp_body
        };

        let mut resp_table = LuaTable::new();
        resp_table
            .rawset(str_key("status"), LuaValue::Integer(status))
            .unwrap();
        resp_table
            .rawset(
                str_key("body"),
                LuaValue::String(LuaString::from_str(&resp_body)),
            )
            .unwrap();
        Ok(resp_table)
    }

    fn tool_kv_get(&self, args: &LuaTable) -> Result<LuaTable, String> {
        let key = get_str(args, "key")?;
        let mut resp = LuaTable::new();
        match self.kv.get(&key) {
            Some(val) => {
                resp.rawset(
                    str_key("value"),
                    LuaValue::String(LuaString::from_str(val)),
                )
                .unwrap();
            }
            None => {
                resp.rawset(str_key("value"), LuaValue::Nil).unwrap();
            }
        }
        Ok(resp)
    }

    fn tool_kv_set(&mut self, args: &LuaTable) -> Result<LuaTable, String> {
        let key = get_str(args, "key")?;
        let value = get_str(args, "value")?;
        self.kv.insert(key, value);
        Ok(LuaTable::new())
    }

    fn tool_llm_query(&self, args: &LuaTable) -> Result<LuaTable, String> {
        let prompt = get_str(args, "prompt")?;
        let context = get_opt_str(args, "context").unwrap_or_default();

        let user_content = if context.is_empty() {
            prompt
        } else {
            format!("{prompt}\n\nContext:\n{context}")
        };

        let messages = vec![crate::llm::Message {
            role: "user".into(),
            content: user_content,
        }];

        let llm_response = self
            .llm
            .generate("You are a helpful assistant. Be concise.", &messages)
            .map_err(|e| format!("llm_query failed: {e}"))?;

        let mut resp = LuaTable::new();
        resp.rawset(
            str_key("response"),
            LuaValue::String(LuaString::from_str(&llm_response.text)),
        )
        .unwrap();
        Ok(resp)
    }

    fn tool_time_now(&self) -> Result<LuaTable, String> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("time_now: {e}"))?
            .as_secs() as i64;
        let mut resp = LuaTable::new();
        resp.rawset(str_key("timestamp"), LuaValue::Integer(ts))
            .unwrap();
        Ok(resp)
    }
}

impl HostInterface for LiveHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        let is_http = matches!(name, "http_get" | "http_post");

        let result = match name {
            "http_get" => self.tool_http_get(args),
            "http_post" => self.tool_http_post(args),
            "kv_get" => self.tool_kv_get(args),
            "kv_set" => self.tool_kv_set(args),
            "llm_query" => self.tool_llm_query(args),
            "time_now" => self.tool_time_now(),
            other => Err(format!("unknown tool '{other}'")),
        };

        // Capture TLS attestation for HTTP calls, None for everything else
        if is_http {
            self.tls_attestations.push(self.tls_store.take_last());
        } else {
            self.tls_attestations.push(None);
        }

        result
    }
}

/// Tool descriptions for the live host (used in prompt generation).
pub fn live_tool_descriptions() -> Vec<crate::prompt::ToolDescription> {
    use crate::prompt::ToolDescription;
    vec![
        ToolDescription {
            name: "http_get".into(),
            description: "Fetch a URL via HTTP GET. Returns the status code and response body as a string.".into(),
            args: vec![("url".into(), "string — the URL to fetch".into())],
            returns: vec![
                ("status".into(), "integer — HTTP status code (e.g. 200)".into()),
                ("body".into(), "string — the response body".into()),
            ],
        },
        ToolDescription {
            name: "http_post".into(),
            description: "Send a POST request with a JSON body. Returns the status code and response body.".into(),
            args: vec![
                ("url".into(), "string — the URL to post to".into()),
                ("body".into(), "string — the JSON request body".into()),
            ],
            returns: vec![
                ("status".into(), "integer — HTTP status code".into()),
                ("body".into(), "string — the response body".into()),
            ],
        },
        ToolDescription {
            name: "kv_get".into(),
            description: "Read a value from the key-value store. Returns nil if the key does not exist.".into(),
            args: vec![("key".into(), "string — the key to look up".into())],
            returns: vec![("value".into(), "string or nil — the stored value".into())],
        },
        ToolDescription {
            name: "kv_set".into(),
            description: "Write a value to the key-value store.".into(),
            args: vec![
                ("key".into(), "string — the key to set".into()),
                ("value".into(), "string — the value to store".into()),
            ],
            returns: vec![],
        },
        ToolDescription {
            name: "llm_query".into(),
            description: "Ask an LLM a question. Use this for fuzzy reasoning, summarisation, or classification tasks that can't be done with string manipulation.".into(),
            args: vec![
                ("prompt".into(), "string — the question or instruction for the LLM".into()),
                ("context".into(), "string (optional) — additional context to include".into()),
            ],
            returns: vec![("response".into(), "string — the LLM's response".into())],
        },
        ToolDescription {
            name: "time_now".into(),
            description: "Returns the current Unix timestamp in seconds.".into(),
            args: vec![],
            returns: vec![("timestamp".into(), "integer — Unix timestamp in seconds".into())],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(pairs: &[(&str, LuaValue)]) -> LuaTable {
        let mut t = LuaTable::new();
        for (k, v) in pairs {
            t.rawset(str_key(k), v.clone()).unwrap();
        }
        t
    }

    // ── StubHost: echo ───────────────────────────────────────────────

    #[test]
    fn echo_returns_message() {
        let mut host = StubHost;
        let args = make_args(&[("message", LuaValue::String(LuaString::from_str("hello")))]);
        let resp = host.call_tool("echo", &args).unwrap();
        assert_eq!(
            resp.get(&str_key("message")),
            Some(&LuaValue::String(LuaString::from_str("hello")))
        );
    }

    #[test]
    fn echo_missing_message_returns_nil() {
        let mut host = StubHost;
        let args = LuaTable::new();
        let resp = host.call_tool("echo", &args).unwrap();
        // Lua semantics: rawset with Nil is a no-op, so key is absent
        assert_eq!(resp.get(&str_key("message")), None);
    }

    // ── add ──────────────────────────────────────────────────────────

    #[test]
    fn add_returns_sum() {
        let mut host = StubHost;
        let args = make_args(&[
            ("a", LuaValue::Integer(17)),
            ("b", LuaValue::Integer(25)),
        ]);
        let resp = host.call_tool("add", &args).unwrap();
        assert_eq!(resp.get(&str_key("result")), Some(&LuaValue::Integer(42)));
    }

    #[test]
    fn add_negative_numbers() {
        let mut host = StubHost;
        let args = make_args(&[
            ("a", LuaValue::Integer(-10)),
            ("b", LuaValue::Integer(3)),
        ]);
        let resp = host.call_tool("add", &args).unwrap();
        assert_eq!(resp.get(&str_key("result")), Some(&LuaValue::Integer(-7)));
    }

    #[test]
    fn add_missing_arg_a_errors() {
        let mut host = StubHost;
        let args = make_args(&[("b", LuaValue::Integer(1))]);
        let err = host.call_tool("add", &args).unwrap_err();
        assert!(err.contains("expected integer arg 'a'"));
    }

    #[test]
    fn add_missing_arg_b_errors() {
        let mut host = StubHost;
        let args = make_args(&[("a", LuaValue::Integer(1))]);
        let err = host.call_tool("add", &args).unwrap_err();
        assert!(err.contains("expected integer arg 'b'"));
    }

    #[test]
    fn add_wrong_type_errors() {
        let mut host = StubHost;
        let args = make_args(&[
            ("a", LuaValue::String(LuaString::from_str("not a number"))),
            ("b", LuaValue::Integer(1)),
        ]);
        let err = host.call_tool("add", &args).unwrap_err();
        assert!(err.contains("expected integer arg 'a'"));
    }

    // ── upper ────────────────────────────────────────────────────────

    #[test]
    fn upper_converts_text() {
        let mut host = StubHost;
        let args = make_args(&[("text", LuaValue::String(LuaString::from_str("hello world")))]);
        let resp = host.call_tool("upper", &args).unwrap();
        assert_eq!(
            resp.get(&str_key("result")),
            Some(&LuaValue::String(LuaString::from_str("HELLO WORLD")))
        );
    }

    #[test]
    fn upper_already_uppercase() {
        let mut host = StubHost;
        let args = make_args(&[("text", LuaValue::String(LuaString::from_str("ABC")))]);
        let resp = host.call_tool("upper", &args).unwrap();
        assert_eq!(
            resp.get(&str_key("result")),
            Some(&LuaValue::String(LuaString::from_str("ABC")))
        );
    }

    #[test]
    fn upper_missing_text_errors() {
        let mut host = StubHost;
        let args = LuaTable::new();
        let err = host.call_tool("upper", &args).unwrap_err();
        assert!(err.contains("expected string arg 'text'"));
    }

    #[test]
    fn upper_wrong_type_errors() {
        let mut host = StubHost;
        let args = make_args(&[("text", LuaValue::Integer(42))]);
        let err = host.call_tool("upper", &args).unwrap_err();
        assert!(err.contains("expected string arg 'text'"));
    }

    // ── time_now ─────────────────────────────────────────────────────

    #[test]
    fn time_now_returns_fixed_timestamp() {
        let mut host = StubHost;
        let args = LuaTable::new();
        let resp = host.call_tool("time_now", &args).unwrap();
        assert_eq!(
            resp.get(&str_key("timestamp")),
            Some(&LuaValue::Integer(1709654400))
        );
    }

    // ── unknown tool ─────────────────────────────────────────────────

    #[test]
    fn unknown_tool_errors() {
        let mut host = StubHost;
        let args = LuaTable::new();
        let err = host.call_tool("nonexistent", &args).unwrap_err();
        assert!(err.contains("unknown tool 'nonexistent'"));
    }

    // ── tool descriptions ────────────────────────────────────────────

    #[test]
    fn stub_descriptions_match_host_tools() {
        let descs = stub_tool_descriptions();
        let names: Vec<&str> = descs.iter().map(|d| d.name.as_str()).collect();
        // Every described tool should work in the host
        let mut host = StubHost;
        for name in &names {
            // time_now needs no special args
            if *name == "time_now" {
                let _ = host.call_tool(name, &LuaTable::new());
            }
        }
        assert!(names.contains(&"echo"));
        assert!(names.contains(&"add"));
        assert!(names.contains(&"upper"));
        assert!(names.contains(&"time_now"));
    }

    #[test]
    fn stub_descriptions_have_content() {
        let descs = stub_tool_descriptions();
        for desc in &descs {
            assert!(!desc.name.is_empty());
            assert!(!desc.description.is_empty());
        }
    }

    // ── LiveHost: kv_get / kv_set ────────────────────────────────────

    fn make_live_host() -> LiveHost {
        // LlmClient with dummy key — won't be called in KV/time tests
        let llm = LlmClient::new("dummy-key".into(), "dummy-model".into());
        LiveHost::new(llm)
    }

    #[test]
    fn kv_set_then_get() {
        let mut host = make_live_host();
        let set_args = make_args(&[
            ("key", LuaValue::String(LuaString::from_str("name"))),
            ("value", LuaValue::String(LuaString::from_str("alice"))),
        ]);
        host.call_tool("kv_set", &set_args).unwrap();

        let get_args = make_args(&[("key", LuaValue::String(LuaString::from_str("name")))]);
        let resp = host.call_tool("kv_get", &get_args).unwrap();
        assert_eq!(
            resp.get(&str_key("value")),
            Some(&LuaValue::String(LuaString::from_str("alice")))
        );
    }

    #[test]
    fn kv_get_missing_key_returns_nil() {
        let mut host = make_live_host();
        let args = make_args(&[("key", LuaValue::String(LuaString::from_str("nope")))]);
        let resp = host.call_tool("kv_get", &args).unwrap();
        // rawset with Nil is a no-op in LuaTable, so key is absent
        assert_eq!(resp.get(&str_key("value")), None);
    }

    #[test]
    fn kv_set_overwrites() {
        let mut host = make_live_host();
        let set1 = make_args(&[
            ("key", LuaValue::String(LuaString::from_str("x"))),
            ("value", LuaValue::String(LuaString::from_str("old"))),
        ]);
        host.call_tool("kv_set", &set1).unwrap();
        let set2 = make_args(&[
            ("key", LuaValue::String(LuaString::from_str("x"))),
            ("value", LuaValue::String(LuaString::from_str("new"))),
        ]);
        host.call_tool("kv_set", &set2).unwrap();

        let get = make_args(&[("key", LuaValue::String(LuaString::from_str("x")))]);
        let resp = host.call_tool("kv_get", &get).unwrap();
        assert_eq!(
            resp.get(&str_key("value")),
            Some(&LuaValue::String(LuaString::from_str("new")))
        );
    }

    #[test]
    fn kv_get_missing_key_arg_errors() {
        let mut host = make_live_host();
        let err = host.call_tool("kv_get", &LuaTable::new()).unwrap_err();
        assert!(err.contains("missing required arg 'key'"));
    }

    #[test]
    fn kv_set_missing_key_arg_errors() {
        let mut host = make_live_host();
        let args = make_args(&[("value", LuaValue::String(LuaString::from_str("v")))]);
        let err = host.call_tool("kv_set", &args).unwrap_err();
        assert!(err.contains("missing required arg 'key'"));
    }

    #[test]
    fn kv_set_missing_value_arg_errors() {
        let mut host = make_live_host();
        let args = make_args(&[("key", LuaValue::String(LuaString::from_str("k")))]);
        let err = host.call_tool("kv_set", &args).unwrap_err();
        assert!(err.contains("missing required arg 'value'"));
    }

    // ── LiveHost: time_now ───────────────────────────────────────────

    #[test]
    fn live_time_now_returns_recent_timestamp() {
        let mut host = make_live_host();
        let resp = host.call_tool("time_now", &LuaTable::new()).unwrap();
        let ts = match resp.get(&str_key("timestamp")) {
            Some(LuaValue::Integer(n)) => *n,
            other => panic!("expected integer timestamp, got {other:?}"),
        };
        // Should be a reasonable Unix timestamp (after 2024)
        assert!(ts > 1_700_000_000);
    }

    // ── LiveHost: unknown tool ───────────────────────────────────────

    #[test]
    fn live_unknown_tool_errors() {
        let mut host = make_live_host();
        let err = host.call_tool("bogus", &LuaTable::new()).unwrap_err();
        assert!(err.contains("unknown tool 'bogus'"));
    }

    // ── LiveHost: http arg validation ────────────────────────────────

    #[test]
    fn http_get_missing_url_errors() {
        let mut host = make_live_host();
        let err = host.call_tool("http_get", &LuaTable::new()).unwrap_err();
        assert!(err.contains("missing required arg 'url'"));
    }

    #[test]
    fn http_post_missing_url_errors() {
        let mut host = make_live_host();
        let args = make_args(&[("body", LuaValue::String(LuaString::from_str("{}")))]);
        let err = host.call_tool("http_post", &args).unwrap_err();
        assert!(err.contains("missing required arg 'url'"));
    }

    #[test]
    fn http_post_missing_body_errors() {
        let mut host = make_live_host();
        let args = make_args(&[(
            "url",
            LuaValue::String(LuaString::from_str("http://example.com")),
        )]);
        let err = host.call_tool("http_post", &args).unwrap_err();
        assert!(err.contains("missing required arg 'body'"));
    }

    // ── live tool descriptions ───────────────────────────────────────

    #[test]
    fn live_descriptions_have_all_tools() {
        let descs = live_tool_descriptions();
        let names: Vec<&str> = descs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"http_get"));
        assert!(names.contains(&"http_post"));
        assert!(names.contains(&"kv_get"));
        assert!(names.contains(&"kv_set"));
        assert!(names.contains(&"llm_query"));
        assert!(names.contains(&"time_now"));
    }

    #[test]
    fn live_descriptions_have_content() {
        let descs = live_tool_descriptions();
        for desc in &descs {
            assert!(!desc.name.is_empty());
            assert!(!desc.description.is_empty());
        }
    }

    // ── TLS attestation capture ──────────────────────────────────────

    #[test]
    fn tls_attestation_captured_for_https() {
        // Use cloudflare.com which serves P-256 ECDSA certs
        let mut host = make_live_host();
        let args = make_args(&[(
            "url",
            LuaValue::String(LuaString::from_str("https://one.one.one.one/")),
        )]);
        let _result = host.call_tool("http_get", &args).unwrap();

        // Verify TLS attestation was captured
        let attestations = host.into_tls_attestations();
        assert_eq!(attestations.len(), 1);
        let att = attestations[0].as_ref().expect("expected TLS attestation for P-256 HTTPS call");

        assert_eq!(att.hostname, "one.one.one.one");
        assert!(!att.cert_chain.is_empty(), "cert chain should not be empty");
        assert!(!att.signature.is_empty(), "signature should not be empty");
        // signed_message should be at least 98 bytes (64 + 34 prefix) plus the transcript hash
        assert!(att.signed_message.len() >= 98, "signed_message should contain prefix + transcript hash");
    }

    #[test]
    fn tls_attestation_none_for_non_http_tools() {
        let mut host = make_live_host();

        // kv_set is not an HTTP tool
        let args = make_args(&[
            ("key", LuaValue::String(LuaString::from_str("k"))),
            ("value", LuaValue::String(LuaString::from_str("v"))),
        ]);
        host.call_tool("kv_set", &args).unwrap();

        let attestations = host.into_tls_attestations();
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].is_none(), "non-HTTP tools should have no TLS attestation");
    }

    #[test]
    fn tls_attestation_e2e_with_proof_artifacts() {
        use crate::{pipeline, prove};
        use luai::host::tls_attestation::tls_attestations_hash;

        let source = r#"
local resp = tool.call("http_get", {url = "https://one.one.one.one/"})
return resp.status
"#;
        let program = pipeline::compile_and_verify(source).unwrap();
        let host = make_live_host();
        let (output, host) = pipeline::execute(
            &program,
            LuaValue::Nil,
            luai::vm::engine::VmConfig::default(),
            host,
        )
        .unwrap();

        let tls_attestations = host.into_tls_attestations();
        assert_eq!(tls_attestations.len(), 1);
        assert!(tls_attestations[0].is_some());

        // Build proof artifacts and verify TLS attestation hash is non-zero
        let dir = tempfile::tempdir().unwrap();
        let artifacts = prove::build_proof_artifacts(
            &program,
            &LuaValue::Nil,
            output,
            dir.path().to_str().unwrap(),
            tls_attestations.clone(),
        )
        .unwrap();

        let zero_hash = [0u8; 32];
        assert_ne!(
            artifacts.public_inputs.tls_attestation_hash, zero_hash,
            "tls_attestation_hash should be non-zero for HTTPS calls"
        );

        // Verify the hash matches what we'd compute directly
        let expected_hash = tls_attestations_hash(&tls_attestations);
        assert_eq!(artifacts.public_inputs.tls_attestation_hash, expected_hash);
    }

    #[test]
    fn tls_attestation_ecdsa_verifies_with_p256_crate() {
        use luai::zkvm::der_parser;
        use p256::ecdsa::{
            signature::Verifier,
            Signature, VerifyingKey,
        };

        let mut host = make_live_host();
        let args = make_args(&[(
            "url",
            LuaValue::String(LuaString::from_str("https://one.one.one.one/")),
        )]);
        host.call_tool("http_get", &args).unwrap();

        let attestations = host.into_tls_attestations();
        let att = attestations[0].as_ref().expect("expected TLS attestation");

        // Extract pubkey from leaf cert (which is now the signing cert from verify_tls13_signature)
        let pubkey_bytes = der_parser::extract_p256_pubkey(&att.cert_chain[0].0).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("valid P-256 pubkey");

        // Parse the DER-encoded ECDSA signature
        let sig = Signature::from_der(&att.signature).expect("valid DER ECDSA signature");

        // Use the full signed_message directly (captured from TLS handshake).
        // p256 crate's verify() does SHA-256 internally (ecdsa_secp256r1_sha256).
        let result = vk.verify(&att.signed_message, &sig);

        if result.is_err() {
            eprintln!("=== ECDSA VERIFY DEBUG ===");
            eprintln!("cert chain len: {}", att.cert_chain.len());
            eprintln!("leaf cert len: {}", att.cert_chain[0].0.len());
            eprintln!("signed_message ({} bytes)", att.signed_message.len());
            eprintln!("signature len: {}", att.signature.len());
            eprintln!("pubkey: {:02x?}", &pubkey_bytes);
            eprintln!("hostname: {}", att.hostname);
        }

        assert!(result.is_ok(), "ECDSA verification failed: {:?}", result.err());
    }

    /// Test that replicates exactly what the zkVM guest does:
    /// 1. Call verify_tls_attestation to get EcdsaVerifyTask
    /// 2. Verify with prehashed digest using p256 crate
    #[test]
    fn tls_attestation_guest_path_verifies() {
        use luai::zkvm::tls_verify::verify_tls_attestation;
        use p256::ecdsa::{
            signature::hazmat::PrehashVerifier,
            Signature, VerifyingKey,
        };
        use sha2::{Digest, Sha256};

        let mut host = make_live_host();
        let args = make_args(&[(
            "url",
            LuaValue::String(LuaString::from_str("https://one.one.one.one/")),
        )]);
        host.call_tool("http_get", &args).unwrap();

        let attestations = host.into_tls_attestations();
        let att = attestations[0].as_ref().expect("expected TLS attestation");

        // This is exactly what verify_tls_attestation does
        let tasks = verify_tls_attestation(att).expect("TLS attestation verification failed");
        assert_eq!(tasks.len(), 1);
        let task = &tasks[0];

        // Reconstruct what the guest does in main.rs
        let vk = VerifyingKey::from_sec1_bytes(&task.pubkey).expect("valid P-256 pubkey");

        // Reconstruct the 64-byte r||s signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&task.sig_r);
        sig_bytes[32..].copy_from_slice(&task.sig_s);
        let sig = Signature::from_bytes((&sig_bytes).into()).expect("valid signature");

        // task.message_hash is SHA256(signed_message) — this is the prehash
        let result = vk.verify_prehash(&task.message_hash, &sig);

        if result.is_err() {
            // Debug: also verify with the raw signed_message to confirm it's the hash that's wrong
            eprintln!("=== GUEST PATH DEBUG ===");
            eprintln!("message_hash: {:02x?}", &task.message_hash);
            let recomputed: [u8; 32] = Sha256::digest(&att.signed_message).into();
            eprintln!("recomputed hash: {:02x?}", &recomputed);
            eprintln!("hashes match: {}", task.message_hash == recomputed);
            eprintln!("sig_r: {:02x?}", &task.sig_r);
            eprintln!("sig_s: {:02x?}", &task.sig_s);
            eprintln!("pubkey: {:02x?}", &task.pubkey);
        }

        assert!(result.is_ok(), "Guest-path ECDSA prehash verification failed: {:?}", result.err());
    }
}

/// Tool descriptions for the stub host (used in tests).
#[cfg(test)]
pub fn stub_tool_descriptions() -> Vec<crate::prompt::ToolDescription> {
    use crate::prompt::ToolDescription;
    vec![
        ToolDescription {
            name: "echo".into(),
            description: "Echoes the message back. Useful for testing.".into(),
            args: vec![("message".into(), "string — the message to echo".into())],
            returns: vec![("message".into(), "string — the echoed message".into())],
        },
        ToolDescription {
            name: "add".into(),
            description: "Adds two integers.".into(),
            args: vec![
                ("a".into(), "integer — first number".into()),
                ("b".into(), "integer — second number".into()),
            ],
            returns: vec![("result".into(), "integer — the sum".into())],
        },
        ToolDescription {
            name: "upper".into(),
            description: "Converts a string to uppercase.".into(),
            args: vec![("text".into(), "string — text to convert".into())],
            returns: vec![("result".into(), "string — the uppercased text".into())],
        },
        ToolDescription {
            name: "time_now".into(),
            description: "Returns the current Unix timestamp.".into(),
            args: vec![],
            returns: vec![("timestamp".into(), "integer — Unix timestamp in seconds".into())],
        },
    ]
}
