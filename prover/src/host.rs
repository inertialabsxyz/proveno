use luai::{
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
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

fn str_key(s: &str) -> LuaKey {
    LuaKey::String(LuaString::from_str(s))
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
                    .map_err(|e| format!("http_get failed: {e}"))?;
                let status = r.status().as_u16() as i64;
                let body = r.text().map_err(|e| format!("http_get: read error: {e}"))?;
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
            other => return Err(format!("unknown tool '{other}'")),
        }
        Ok(resp)
    }
}
