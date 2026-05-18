use serde::{Deserialize, Serialize};

/// Which LLM provider to talk to.
#[derive(Debug, Clone)]
pub enum Backend {
    Anthropic { api_key: String },
    Ollama { base_url: String },
}

#[derive(Debug, Clone)]
pub struct LlmClient {
    backend: Backend,
    model: String,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicUsage {
    input_tokens: u64,
    output_tokens: u64,
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    stream: bool,
    messages: Vec<Message>,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OllamaMessage {
    content: String,
}

/// Token usage from a single LLM call.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// Response from an LLM generation call.
pub struct LlmResponse {
    pub text: String,
    pub usage: TokenUsage,
}

#[derive(Debug)]
pub enum LlmError {
    Http(reqwest::Error),
    Api(String),
    NoContent,
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Http(e) => write!(f, "HTTP error: {e}"),
            LlmError::Api(msg) => write!(f, "API error: {msg}"),
            LlmError::NoContent => write!(f, "empty response from API"),
        }
    }
}

impl From<reqwest::Error> for LlmError {
    fn from(e: reqwest::Error) -> Self {
        LlmError::Http(e)
    }
}

impl LlmClient {
    pub fn new(backend: Backend, model: String) -> Self {
        // Generous timeout — local Ollama models can take >60s to load on first call.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("failed to build HTTP client");
        LlmClient {
            backend,
            model,
            client,
        }
    }

    /// Generate a Lua program from a system prompt and conversation history.
    /// Returns the raw text response and token usage from the LLM.
    pub fn generate(
        &self,
        system_prompt: &str,
        messages: &[Message],
    ) -> Result<LlmResponse, LlmError> {
        match &self.backend {
            Backend::Anthropic { api_key } => {
                self.generate_anthropic(api_key, system_prompt, messages)
            }
            Backend::Ollama { base_url } => self.generate_ollama(base_url, system_prompt, messages),
        }
    }

    fn generate_anthropic(
        &self,
        api_key: &str,
        system_prompt: &str,
        messages: &[Message],
    ) -> Result<LlmResponse, LlmError> {
        let request = AnthropicRequest {
            model: self.model.clone(),
            max_tokens: 4096,
            system: system_prompt.to_string(),
            messages: messages.to_vec(),
        };

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(LlmError::Api(format!("status {status}: {body}")));
        }

        let api_resp: AnthropicResponse = resp.json()?;
        let usage = match api_resp.usage {
            Some(u) => TokenUsage {
                input_tokens: u.input_tokens,
                output_tokens: u.output_tokens,
            },
            None => TokenUsage::default(),
        };

        let text = api_resp
            .content
            .into_iter()
            .map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");

        if text.is_empty() {
            return Err(LlmError::NoContent);
        }

        Ok(LlmResponse { text, usage })
    }

    fn generate_ollama(
        &self,
        base_url: &str,
        system_prompt: &str,
        messages: &[Message],
    ) -> Result<LlmResponse, LlmError> {
        // Ollama puts the system prompt inside the messages array.
        let mut all_messages = Vec::with_capacity(messages.len() + 1);
        all_messages.push(Message {
            role: "system".into(),
            content: system_prompt.to_string(),
        });
        all_messages.extend_from_slice(messages);

        let request = OllamaRequest {
            model: self.model.clone(),
            stream: false,
            messages: all_messages,
        };

        let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&request)
            .send()?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(LlmError::Api(format!("status {status}: {body}")));
        }

        let api_resp: OllamaResponse = resp.json()?;
        let usage = TokenUsage {
            input_tokens: api_resp.prompt_eval_count.unwrap_or(0),
            output_tokens: api_resp.eval_count.unwrap_or(0),
        };

        let text = api_resp.message.content;
        if text.is_empty() {
            return Err(LlmError::NoContent);
        }

        Ok(LlmResponse { text, usage })
    }
}

/// Strip markdown code fences from LLM output.
/// Handles ```lua ... ```, ``` ... ```, and bare code.
pub fn strip_code_fences(raw: &str) -> String {
    let trimmed = raw.trim();

    // Try ```lua or ```
    if let Some(rest) = trimmed.strip_prefix("```lua") {
        if let Some(code) = rest.strip_suffix("```") {
            return code.trim().to_string();
        }
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        if let Some(code) = rest.strip_suffix("```") {
            return code.trim().to_string();
        }
    }

    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_code_fences ────────────────────────────────────────────

    #[test]
    fn strip_bare_code() {
        let input = "return 42";
        assert_eq!(strip_code_fences(input), "return 42");
    }

    #[test]
    fn strip_lua_fence() {
        let input = "```lua\nreturn 42\n```";
        assert_eq!(strip_code_fences(input), "return 42");
    }

    #[test]
    fn strip_plain_fence() {
        let input = "```\nreturn 42\n```";
        assert_eq!(strip_code_fences(input), "return 42");
    }

    #[test]
    fn strip_with_whitespace() {
        let input = "  ```lua\n  local x = 1\n  return x\n  ```  ";
        assert_eq!(strip_code_fences(input), "local x = 1\n  return x");
    }

    #[test]
    fn strip_multiline_program() {
        let input = "```lua\nlocal a = 1\nlocal b = 2\nreturn a + b\n```";
        assert_eq!(
            strip_code_fences(input),
            "local a = 1\nlocal b = 2\nreturn a + b"
        );
    }

    #[test]
    fn strip_fence_with_trailing_newline() {
        let input = "```lua\nreturn 42\n```\n";
        // After trim, trailing newline is gone, so suffix match works
        assert_eq!(strip_code_fences(input), "return 42");
    }

    #[test]
    fn strip_only_opening_fence_passthrough() {
        // No closing fence — should pass through as-is (trimmed)
        let input = "```lua\nreturn 42";
        assert_eq!(strip_code_fences(input), "```lua\nreturn 42");
    }

    #[test]
    fn strip_empty_fenced_block() {
        let input = "```lua\n```";
        assert_eq!(strip_code_fences(input), "");
    }

    #[test]
    fn strip_empty_string() {
        assert_eq!(strip_code_fences(""), "");
    }

    #[test]
    fn strip_whitespace_only() {
        assert_eq!(strip_code_fences("   \n  \n  "), "");
    }

    #[test]
    fn strip_no_fence_multiline() {
        let input = "local x = 1\nreturn x";
        assert_eq!(strip_code_fences(input), "local x = 1\nreturn x");
    }

    // ── Message serialization ────────────────────────────────────────

    #[test]
    fn message_serialize() {
        let msg = Message {
            role: "user".into(),
            content: "hello".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"hello\""));
    }

    #[test]
    fn message_deserialize() {
        let json = r#"{"role":"assistant","content":"return 42"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.role, "assistant");
        assert_eq!(msg.content, "return 42");
    }

    // ── LlmError display ────────────────────────────────────────────

    #[test]
    fn llm_error_display_api() {
        let err = LlmError::Api("bad request".into());
        assert_eq!(format!("{err}"), "API error: bad request");
    }

    #[test]
    fn llm_error_display_no_content() {
        let err = LlmError::NoContent;
        assert_eq!(format!("{err}"), "empty response from API");
    }
}
