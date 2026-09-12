use proveno::{
    HostInterface,
    types::{
        table::{LuaKey, LuaTable},
        value::{LuaString, LuaValue},
    },
};

pub struct ProverHost {
    client: reqwest::blocking::Client,
}

impl ProverHost {
    pub fn new() -> Self {
        ProverHost {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .user_agent("proveno/1.0")
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

fn str_key(s: &str) -> LuaKey {
    LuaKey::String(LuaString::from_str(s))
}

/// Format a reqwest error including its full source chain.
///
/// reqwest::Error's Display only surfaces the top-line message; the
/// actual cause (TLS / connect / timeout details) lives in `source()`
/// and is lost by a plain `{e}`. This walks the chain and joins each
/// layer with ": ".
fn format_reqwest_error(prefix: &str, e: &reqwest::Error) -> String {
    let mut msg = format!("{prefix}: {e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(cause) = src {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        src = cause.source();
    }
    msg
}

impl HostInterface for ProverHost {
    fn call_tool(&mut self, name: &str, args: &LuaTable) -> Result<LuaTable, String> {
        let mut resp = LuaTable::new();
        match name {
            "http_get" => {
                let url = match args.get(&str_key("url")) {
                    Some(LuaValue::String(s)) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
                    _ => return Err("http_get: missing 'url' arg".into()),
                };
                let r = self
                    .client
                    .get(&url)
                    .send()
                    .map_err(|e| format_reqwest_error("http_get failed", &e))?;
                let status = r.status().as_u16() as i64;
                let body = r
                    .text()
                    .map_err(|e| format_reqwest_error("http_get: read error", &e))?;
                resp.rawset(str_key("status"), LuaValue::Integer(status))
                    .unwrap();
                resp.rawset(
                    str_key("body"),
                    LuaValue::String(LuaString::from_str(&body)),
                )
                .unwrap();
            }
            // random: returns a constant integer (deterministic for tests)
            "random" => {
                resp.rawset(str_key("result"), LuaValue::Integer(42))
                    .unwrap();
            }
            // fail: always errors
            "fail" => return Err("this tool always fails".into()),
            // time_now: real clock. Deterministic replay is not at risk — the
            // dry run records the timestamp on the oracle tape, and the guest
            // replays that recorded value rather than reading a clock.
            "time_now" => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| format!("time_now: {e}"))?
                    .as_secs() as i64;
                resp.rawset(str_key("timestamp"), LuaValue::Integer(ts))
                    .unwrap();
            }
            // echo / add / upper mirror the demo tools in src/main.rs and the
            // orchestrator's StubHost, response shapes included, so the example
            // programs run unchanged through the proving pipeline.
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
            other => return Err(format!("unknown tool '{other}'")),
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(pairs: &[(&str, LuaValue)]) -> LuaTable {
        let mut t = LuaTable::new();
        for (k, v) in pairs {
            t.rawset(str_key(k), v.clone()).unwrap();
        }
        t
    }

    fn call(name: &str, args: LuaTable) -> Result<LuaTable, String> {
        ProverHost::new().call_tool(name, &args)
    }

    #[test]
    fn echo_returns_the_message() {
        let r = call(
            "echo",
            args_of(&[("message", LuaValue::String(LuaString::from_str("hi")))]),
        )
        .unwrap();
        assert_eq!(
            r.get(&str_key("message")),
            Some(&LuaValue::String(LuaString::from_str("hi")))
        );
    }

    #[test]
    fn add_sums_integers() {
        let r = call(
            "add",
            args_of(&[("a", LuaValue::Integer(17)), ("b", LuaValue::Integer(25))]),
        )
        .unwrap();
        assert_eq!(r.get(&str_key("result")), Some(&LuaValue::Integer(42)));
    }

    #[test]
    fn add_rejects_non_integer_args() {
        let err = call(
            "add",
            args_of(&[
                ("a", LuaValue::String(LuaString::from_str("x"))),
                ("b", LuaValue::Integer(1)),
            ]),
        )
        .unwrap_err();
        assert!(err.contains("expected integer"), "got: {err}");
    }

    #[test]
    fn upper_uppercases_text() {
        let r = call(
            "upper",
            args_of(&[("text", LuaValue::String(LuaString::from_str("lua")))]),
        )
        .unwrap();
        assert_eq!(
            r.get(&str_key("result")),
            Some(&LuaValue::String(LuaString::from_str("LUA")))
        );
    }

    #[test]
    fn time_now_returns_a_plausible_timestamp() {
        let r = call("time_now", LuaTable::new()).unwrap();
        match r.get(&str_key("timestamp")) {
            // Later than 2024-01-01; pins that it is a real clock reading and
            // not a zero or a stub constant.
            Some(LuaValue::Integer(ts)) => assert!(*ts > 1_704_067_200, "got {ts}"),
            other => panic!("expected integer timestamp, got {other:?}"),
        }
    }

    #[test]
    fn fail_always_errors() {
        assert!(call("fail", LuaTable::new()).is_err());
    }

    #[test]
    fn unknown_tool_is_reported_by_name() {
        let err = call("nope", LuaTable::new()).unwrap_err();
        assert!(err.contains("unknown tool 'nope'"), "got: {err}");
    }
}
