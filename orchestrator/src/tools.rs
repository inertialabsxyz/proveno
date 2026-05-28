use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use luai::{
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
    vm::engine::HostInterface,
};

use crate::llm::LlmClient;

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

/// Format a reqwest error including its full source chain.
///
/// reqwest::Error's Display only shows the top-line message (e.g.
/// "error sending request for url (...)"); the actual cause
/// (TLS / connect / timeout details) lives in `source()` and is lost
/// by a plain `{e}`. This walks the chain and joins each layer with ": ".
pub(crate) fn format_reqwest_error(prefix: &str, e: &reqwest::Error) -> String {
    let mut msg = format!("{prefix}: {e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(cause) = src {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        src = cause.source();
    }
    msg
}

/// Maximum response body size for HTTP tools (1 MB).
const MAX_HTTP_BODY: usize = 1024 * 1024;
/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 30;

pub struct LiveHost {
    http: reqwest::blocking::Client,
    kv: HashMap<String, String>,
    llm: LlmClient,
}

impl LiveHost {
    pub fn new(llm: LlmClient) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .expect("failed to build HTTP client");
        LiveHost {
            http,
            kv: HashMap::new(),
            llm,
        }
    }

    fn tool_http_get(&self, args: &LuaTable) -> Result<LuaTable, String> {
        let url = get_str(args, "url")?;
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| format_reqwest_error("http_get failed", &e))?;
        let status = resp.status().as_u16() as i64;
        let body = resp
            .text()
            .map_err(|e| format_reqwest_error("http_get: failed to read body", &e))?;
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
            .map_err(|e| format_reqwest_error("http_post failed", &e))?;
        let status = resp.status().as_u16() as i64;
        let resp_body = resp
            .text()
            .map_err(|e| format_reqwest_error("http_post: failed to read body", &e))?;
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
                resp.rawset(str_key("value"), LuaValue::String(LuaString::from_str(val)))
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
        match name {
            "http_get" => self.tool_http_get(args),
            "http_post" => self.tool_http_post(args),
            "kv_get" => self.tool_kv_get(args),
            "kv_set" => self.tool_kv_set(args),
            "llm_query" => self.tool_llm_query(args),
            "time_now" => self.tool_time_now(),
            other => Err(format!("unknown tool '{other}'")),
        }
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
        let args = make_args(&[("a", LuaValue::Integer(17)), ("b", LuaValue::Integer(25))]);
        let resp = host.call_tool("add", &args).unwrap();
        assert_eq!(resp.get(&str_key("result")), Some(&LuaValue::Integer(42)));
    }

    #[test]
    fn add_negative_numbers() {
        let mut host = StubHost;
        let args = make_args(&[("a", LuaValue::Integer(-10)), ("b", LuaValue::Integer(3))]);
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
        let llm = LlmClient::new(
            crate::llm::Backend::Anthropic {
                api_key: "dummy-key".into(),
            },
            "dummy-model".into(),
        );
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

    // ── format_reqwest_error: source chain is preserved ──────────────

    #[test]
    fn format_reqwest_error_includes_full_cause_chain() {
        // Drive a real reqwest failure against an unreachable port. The
        // resulting reqwest::Error always has at least one nested cause
        // (the underlying io / connect / hyper error), so the formatted
        // message should contain "<prefix>: <top-line>: <cause...>" —
        // i.e. at least 3 ':'-separated segments.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let err = client
            .get("http://127.0.0.1:1/")
            .send()
            .expect_err("request to 127.0.0.1:1 should fail");

        let msg = format_reqwest_error("http_get failed", &err);
        assert!(
            msg.starts_with("http_get failed: "),
            "missing prefix in {msg:?}"
        );
        let colon_segments = msg.matches(": ").count();
        assert!(
            colon_segments >= 2,
            "expected at least one nested cause (>=2 ': ' separators) in {msg:?}"
        );
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
            returns: vec![(
                "timestamp".into(),
                "integer — Unix timestamp in seconds".into(),
            )],
        },
    ]
}
