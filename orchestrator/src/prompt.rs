/// Build the system prompt for Lua program generation.
///
/// This tells the LLM what language subset is available, what tools exist,
/// and how to structure its output.
pub fn build_system_prompt(tool_descriptions: &[ToolDescription]) -> String {
    let mut prompt = String::from(SYSTEM_PREAMBLE);

    if !tool_descriptions.is_empty() {
        prompt.push_str("\n## Available tools\n\n");
        prompt.push_str("Call tools with: `tool.call(\"name\", {arg1 = val1, ...})`\n");
        prompt.push_str("Tool calls return a table with the result fields.\n\n");

        for tool in tool_descriptions {
            prompt.push_str(&format!("### `{}`\n", tool.name));
            prompt.push_str(&format!("{}\n", tool.description));
            if !tool.args.is_empty() {
                prompt.push_str("**Args:**\n");
                for (name, desc) in &tool.args {
                    prompt.push_str(&format!("- `{name}` — {desc}\n"));
                }
            }
            if !tool.returns.is_empty() {
                prompt.push_str("**Returns:**\n");
                for (name, desc) in &tool.returns {
                    prompt.push_str(&format!("- `{name}` — {desc}\n"));
                }
            }
            prompt.push('\n');
        }
    }

    prompt.push_str(OUTPUT_INSTRUCTIONS);
    prompt
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolDescription {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub args: Vec<(String, String)>,
    #[serde(default)]
    pub returns: Vec<(String, String)>,
}

/// A named collection of tool descriptions that can be loaded from JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct ToolCatalogue {
    pub tools: Vec<ToolDescription>,
}

#[allow(dead_code)]
impl ToolCatalogue {
    pub fn new(tools: Vec<ToolDescription>) -> Self {
        ToolCatalogue { tools }
    }

    /// Load a catalogue from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the catalogue to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Build a system prompt from this catalogue.
    pub fn build_prompt(&self) -> String {
        build_system_prompt(&self.tools)
    }

    /// List the tool names in this catalogue.
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name.as_str()).collect()
    }
}

const SYSTEM_PREAMBLE: &str = r#"You are a Lua program generator. You write Lua programs that execute in a sandboxed, deterministic VM.

## Language subset
- **Types:** nil, boolean, integer (signed 64-bit), string, table, function
- **No floats** — all arithmetic is integer-only. Division is floor division (`//`).
- **Variables:** `local` declarations, globals
- **Control flow:** `if`/`elseif`/`else`/`end`, `while`/`end`, numeric `for i = start, stop [, step] do`, generic `for k, v in pairs_sorted(t) do` and `for i, v in ipairs(t) do`
- **Functions:** `function(args) ... end`, closures with upvalues, `return`
- **Tables:** `{}` literals, `t.field`, `t[key]`, `#t` for array length
- **Operators:** `+`, `-`, `*`, `//` (floor div), `%` (mod), `==`, `~=`, `<`, `<=`, `>`, `>=`, `not`, `and`, `or`, `..` (concat), `#` (length)
- **Strings:** double-quoted or single-quoted, escape sequences
- **Comments:** `--` single line

## Standard library
- `string.len(s)`, `string.sub(s, i [, j])`, `string.find(s, pattern [, init])`, `string.find_literal(s, needle [, init])`, `string.upper(s)`, `string.lower(s)`, `string.rep(s, n)`, `string.byte(s [, i])`, `string.char(...)`, `string.format(fmt, ...)`
- `math.abs(x)`, `math.min(...)`, `math.max(...)`, `math.scale_div(num, denom, scale)`
- `table.insert(t [, i], v)`, `table.remove(t [, i])`, `table.concat(t [, sep])`, `table.move(src, a, b, t)`, `table.sort(t [, comp])`
- `json.encode(v)` — serialize to JSON string; `json.decode(s)` — parse JSON (integer-only; errors on any fractional number anywhere in the payload); `json.decode_strings(s)` — parse JSON returning every number as its raw source string (use this for API responses containing floats; then split on `.` and scale to an integer per the Numeric gotchas section)
- `type(v)`, `tostring(v)`, `tonumber(s)`, `select(i, ...)`, `unpack(t)`, `pcall(f, ...)`, `error(msg)`, `log(msg)`, `print(msg)`
- `pairs_sorted(t)` — iterate table keys in deterministic order; `ipairs(t)` — iterate array portion

## Tool calls
- Call external tools with: `tool.call("tool_name", {arg1 = val1, arg2 = val2})`
- Tool calls return a result table
- Use `pcall` to handle tool errors: `local ok, err = pcall(function() tool.call(...) end)`

## Important constraints
- No floating-point numbers. Use integers only. For money, use cents. For percentages, use basis points.
- No `require`, `io`, `os`, `debug`, `load`, `dofile`, or `setmetatable`
- No coroutines or metatables
- All programs are single-shot: receive input, do work, return a result
- The input is available as the first parameter to the top-level chunk

## Numeric gotchas (read this!)
- `tonumber("3245.67")` returns **`nil`**, not `3246`. The VM is integer-only, so any string containing a `.` fails to parse.
- If `nil` ends up as a value in a returned table, JSON encoding silently drops the field — your run will look "successful" but be missing data. Always sanity-check:
  `if value == nil then error("failed to parse price from " .. raw) end`
- `string.find` rejects all Lua pattern metacharacters (`.`, `*`, `+`, `?`, `^`, `$`, `(`, `)`, `%`, `[`, `]`, `-`) even when you want them as literals. Use `string.find_literal(s, needle [, init])` whenever you need to search for one of these characters or any substring containing them.
- For decimal API responses (prices, rates, percentages), parse them into integers at a fixed scale:
    1. Get the raw string. If the value lives inside a JSON payload that also contains any other fractional fields (e.g. an open-meteo or coingecko response), parse the whole payload with `json.decode_strings(body)` rather than `json.decode(body)` — the latter errors on the first float it sees anywhere in the document, even fields you don't care about. `json.decode_strings` returns every number as its verbatim source string (e.g. `"3245.67"`, `"-2.5E-3"`).
    2. Find the dot with `local dot = string.find_literal(raw, ".")`.
    3. Take the integer and fractional parts with `string.sub(raw, 1, dot - 1)` and `string.sub(raw, dot + 1)`.
    4. Pad or truncate the fractional part to a fixed scale (e.g. 8 digits for satoshi-style, or 2 for cents).
    5. Concatenate and `tonumber` *that*. Document the scale in your returned value (e.g. `price_scale = 8`).
- Prefer API endpoints that return integer-valued fields when one is available (e.g. a price already quoted in cents, or a Coingecko endpoint with `precision=0` for whole units). When that's not an option, reach for `json.decode_strings` and the split-on-dot recipe above.
"#;

const OUTPUT_INSTRUCTIONS: &str = r#"
## Output format
- Respond with ONLY the Lua program. No markdown fences, no explanation, no commentary.
- The program must end with a `return` statement that returns the result.
- Use `log()` for debug output that should appear in logs.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_includes_tools() {
        let tools = vec![ToolDescription {
            name: "echo".into(),
            description: "Echoes the message back".into(),
            args: vec![("message".into(), "string to echo".into())],
            returns: vec![("message".into(), "the echoed string".into())],
        }];
        let prompt = build_system_prompt(&tools);
        assert!(prompt.contains("### `echo`"));
        assert!(prompt.contains("Echoes the message back"));
        assert!(prompt.contains("- `message` — string to echo"));
        assert!(prompt.contains("- `message` — the echoed string"));
    }

    #[test]
    fn prompt_no_tools() {
        let prompt = build_system_prompt(&[]);
        assert!(!prompt.contains("## Available tools"));
        assert!(prompt.contains("You are a Lua program generator"));
        assert!(prompt.contains("## Output format"));
    }

    #[test]
    fn prompt_multiple_tools() {
        let tools = vec![
            ToolDescription {
                name: "echo".into(),
                description: "Echo".into(),
                args: vec![("msg".into(), "string".into())],
                returns: vec![],
            },
            ToolDescription {
                name: "add".into(),
                description: "Add".into(),
                args: vec![],
                returns: vec![("result".into(), "integer".into())],
            },
        ];
        let prompt = build_system_prompt(&tools);
        assert!(prompt.contains("### `echo`"));
        assert!(prompt.contains("### `add`"));
        // echo has args but no returns section
        assert!(prompt.contains("- `msg` — string"));
        // add has returns but no args section
        assert!(prompt.contains("- `result` — integer"));
    }

    #[test]
    fn prompt_tool_no_args_no_returns() {
        let tools = vec![ToolDescription {
            name: "noop".into(),
            description: "Does nothing".into(),
            args: vec![],
            returns: vec![],
        }];
        let prompt = build_system_prompt(&tools);
        assert!(prompt.contains("### `noop`"));
        assert!(prompt.contains("Does nothing"));
        // No **Args:** or **Returns:** sections
        let noop_section = prompt.split("### `noop`").nth(1).unwrap();
        let section_end = noop_section
            .find("## Output format")
            .unwrap_or(noop_section.len());
        let section = &noop_section[..section_end];
        assert!(!section.contains("**Args:**"));
        assert!(!section.contains("**Returns:**"));
    }

    #[test]
    fn prompt_contains_language_reference() {
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("## Language subset"));
        assert!(prompt.contains("No floats"));
        assert!(prompt.contains("## Standard library"));
        assert!(prompt.contains("string.len"));
        assert!(prompt.contains("json.encode"));
        assert!(prompt.contains("## Tool calls"));
        assert!(prompt.contains("tool.call"));
        assert!(prompt.contains("## Important constraints"));
        assert!(prompt.contains("## Output format"));
        assert!(prompt.contains("Respond with ONLY the Lua program"));
    }

    #[test]
    fn prompt_advertises_string_find_literal_and_numeric_gotchas() {
        // These two are load-bearing for decimal-parsing tasks: without the
        // gotchas section the LLM walks into the silent-nil `tonumber("x.y")`
        // trap, and without `string.find_literal` it cannot recover by
        // splitting on the dot. If either disappears, this test fails loudly.
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("string.find_literal"));
        assert!(prompt.contains("## Numeric gotchas"));
        assert!(prompt.contains("integer-only"));
    }

    #[test]
    fn prompt_advertises_json_decode_strings() {
        // `json.decode_strings` is the load-bearing escape hatch for API
        // responses that contain floats (which `json.decode` rejects outright,
        // even for fields the program doesn't care about). The prompt must
        // both name the function in the stdlib listing and cross-reference it
        // from the Numeric gotchas integerization recipe.
        let prompt = build_system_prompt(&[]);
        assert!(
            prompt.contains("json.decode_strings"),
            "prompt must advertise json.decode_strings"
        );
        // The gotchas section must point at it as the recommended path for
        // payloads with floats — not just list it in the stdlib reference.
        let gotchas = prompt
            .split("## Numeric gotchas")
            .nth(1)
            .expect("Numeric gotchas section must exist");
        assert!(
            gotchas.contains("json.decode_strings"),
            "Numeric gotchas section must cross-reference json.decode_strings"
        );
    }

    // ── ToolCatalogue tests ──────────────────────────────────────────

    #[test]
    fn catalogue_roundtrip_json() {
        let cat = ToolCatalogue::new(vec![
            ToolDescription {
                name: "echo".into(),
                description: "Echo back".into(),
                args: vec![("message".into(), "string".into())],
                returns: vec![("message".into(), "string".into())],
            },
            ToolDescription {
                name: "add".into(),
                description: "Add two integers".into(),
                args: vec![
                    ("a".into(), "integer".into()),
                    ("b".into(), "integer".into()),
                ],
                returns: vec![("result".into(), "integer".into())],
            },
        ]);

        let json = cat.to_json().unwrap();
        let restored = ToolCatalogue::from_json(&json).unwrap();

        assert_eq!(restored.tools.len(), 2);
        assert_eq!(restored.tools[0].name, "echo");
        assert_eq!(restored.tools[1].name, "add");
        assert_eq!(restored.tools[1].args.len(), 2);
    }

    #[test]
    fn catalogue_from_json_minimal() {
        let json = r#"{"tools": [{"name": "ping", "description": "Ping"}]}"#;
        let cat = ToolCatalogue::from_json(json).unwrap();
        assert_eq!(cat.tools.len(), 1);
        assert_eq!(cat.tools[0].name, "ping");
        assert!(cat.tools[0].args.is_empty());
        assert!(cat.tools[0].returns.is_empty());
    }

    #[test]
    fn catalogue_from_json_invalid() {
        let result = ToolCatalogue::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn catalogue_tool_names() {
        let cat = ToolCatalogue::new(vec![
            ToolDescription {
                name: "a".into(),
                description: "".into(),
                args: vec![],
                returns: vec![],
            },
            ToolDescription {
                name: "b".into(),
                description: "".into(),
                args: vec![],
                returns: vec![],
            },
        ]);
        assert_eq!(cat.tool_names(), vec!["a", "b"]);
    }

    #[test]
    fn catalogue_build_prompt() {
        let cat = ToolCatalogue::new(vec![ToolDescription {
            name: "test_tool".into(),
            description: "A test tool".into(),
            args: vec![("x".into(), "integer".into())],
            returns: vec![],
        }]);
        let prompt = cat.build_prompt();
        assert!(prompt.contains("### `test_tool`"));
        assert!(prompt.contains("A test tool"));
    }

    #[test]
    fn catalogue_empty() {
        let cat = ToolCatalogue::new(vec![]);
        assert!(cat.tool_names().is_empty());
        let prompt = cat.build_prompt();
        assert!(!prompt.contains("## Available tools"));
    }
}
