use clap::Parser;
use proveno::{types::value::LuaValue, vm::engine::VmConfig};
use proveno_orchestrator::{llm, pipeline, prompt, prove, tools};

#[derive(Parser)]
#[command(name = "proveno-orchestrator")]
#[command(about = "LLM-driven agentic pipeline for the Proveno VM")]
struct Cli {
    /// The task to accomplish (natural language)
    task: String,

    /// LLM provider: "anthropic" or "ollama"
    #[arg(long, default_value = "anthropic")]
    provider: String,

    /// Model name. Defaults: anthropic→claude-sonnet-4-20250514, ollama→llama3.1
    #[arg(long)]
    model: Option<String>,

    /// Base URL for the Ollama server (only used when --provider=ollama)
    #[arg(long, default_value = "http://localhost:11434")]
    ollama_url: String,

    /// Maximum retry attempts on compile/runtime errors
    #[arg(long, default_value_t = 3)]
    max_retries: usize,

    /// Print output as JSON
    #[arg(long)]
    json: bool,

    /// Show verbose output (generated prompts, raw LLM responses)
    #[arg(long, short)]
    verbose: bool,

    /// VM gas limit (default: 200000)
    #[arg(long)]
    gas_limit: Option<u64>,

    /// VM max tool bytes in (default: 65536)
    #[arg(long)]
    max_tool_bytes_in: Option<usize>,

    /// VM max tool calls (default: 16)
    #[arg(long)]
    max_tool_calls: Option<usize>,

    /// Generate the Lua program and print it to stdout — skip compile, execute, retry
    #[arg(long)]
    generate_only: bool,

    /// Generate + compile + verify, then stop. No execution, no retry. Single
    /// fresh-conversation attempt — designed for measuring raw LLM code-gen
    /// quality without retry feedback contaminating the signal.
    #[arg(long)]
    generate_and_compile: bool,

    /// Repeat the `--generate-and-compile` pass N times with independent
    /// conversations, then print a stage histogram. Requires
    /// `--generate-and-compile`.
    #[arg(long)]
    repeat: Option<usize>,

    /// Generate ZK proof artifacts after successful execution
    #[arg(long)]
    prove: bool,

    /// Output directory for proof artifacts (used with --prove)
    #[arg(long, default_value = "proof-output")]
    prove_output: String,

    /// Directory containing the Noir circuit (Nargo.toml). Defaults to ./noir
    #[arg(long, default_value = "noir")]
    circuit_dir: String,
}

fn main() {
    let cli = Cli::parse();

    // Load .env file if present (silently ignore if missing)
    let _ = dotenvy::dotenv();

    let (backend, model) = match cli.provider.as_str() {
        "anthropic" => {
            let api_key = match std::env::var("ANTHROPIC_API_KEY") {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("error: ANTHROPIC_API_KEY environment variable not set");
                    std::process::exit(1);
                }
            };
            let model = cli
                .model
                .clone()
                .unwrap_or_else(|| "claude-sonnet-4-20250514".into());
            (llm::Backend::Anthropic { api_key }, model)
        }
        "ollama" => {
            let model = cli.model.clone().unwrap_or_else(|| "llama3.1".into());
            (
                llm::Backend::Ollama {
                    base_url: cli.ollama_url.clone(),
                },
                model,
            )
        }
        other => {
            eprintln!("error: unknown --provider '{other}' (expected 'anthropic' or 'ollama')");
            std::process::exit(1);
        }
    };

    let client = llm::LlmClient::new(backend, model.clone());

    // Build tool catalogue and system prompt
    let tool_descs = tools::live_tool_descriptions();
    let system_prompt = prompt::build_system_prompt(&tool_descs);

    if cli.verbose {
        eprintln!("── System prompt ──────────────────────────────");
        eprintln!("{system_prompt}");
        eprintln!("───────────────────────────────────────────────\n");
    }

    // --generate-and-compile path: skip the retry loop entirely. Optionally
    // batch via --repeat to characterize per-stage failure modes of the LLM.
    if cli.generate_and_compile {
        if let Some(0) = cli.repeat {
            eprintln!("error: --repeat must be >= 1");
            std::process::exit(1);
        }
        let n = cli.repeat.unwrap_or(1);
        run_generate_and_compile_batch(&client, &system_prompt, &cli.task, n, cli.json);
        return;
    }
    if cli.repeat.is_some() {
        eprintln!("error: --repeat requires --generate-and-compile");
        std::process::exit(1);
    }

    // Conversation history for multi-turn retry
    let mut messages: Vec<llm::Message> = vec![llm::Message {
        role: "user".into(),
        content: cli.task.clone(),
    }];

    let mut config = VmConfig::default();
    if let Some(gas) = cli.gas_limit {
        config.gas_limit = gas;
    }
    if let Some(bytes_in) = cli.max_tool_bytes_in {
        config.max_tool_bytes_in = bytes_in;
    }
    if let Some(calls) = cli.max_tool_calls {
        config.max_tool_calls = calls;
    }
    let mut total_usage = llm::TokenUsage::default();

    for attempt in 1..=cli.max_retries + 1 {
        // Call LLM
        eprintln!("[attempt {attempt}] generating Lua program...");

        let llm_response = match client.generate(&system_prompt, &messages) {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("error: LLM generation failed: {e}");
                std::process::exit(1);
            }
        };

        let raw_response = llm_response.text;
        total_usage.input_tokens += llm_response.usage.input_tokens;
        total_usage.output_tokens += llm_response.usage.output_tokens;

        if cli.verbose {
            eprintln!(
                "  tokens: {} in + {} out = {} total",
                llm_response.usage.input_tokens,
                llm_response.usage.output_tokens,
                llm_response.usage.total()
            );
        }

        let source = llm::strip_code_fences(&raw_response);

        if cli.generate_only {
            // Print Lua to stdout, usage stats to stderr; skip compile/execute.
            print!("{source}");
            if !source.ends_with('\n') {
                println!();
            }
            eprintln!(
                "[generate-only] tokens: {} in + {} out = {} total",
                total_usage.input_tokens,
                total_usage.output_tokens,
                total_usage.total()
            );
            return;
        }

        if cli.verbose {
            eprintln!("── LLM response (raw) ─────────────────────────");
            eprintln!("{raw_response}");
            eprintln!("── Source (cleaned) ───────────────────────────");
            eprintln!("{source}");
            eprintln!("───────────────────────────────────────────────\n");
        }

        // Compile and verify
        let program = match pipeline::compile_and_verify(&source) {
            Ok(p) => p,
            Err(e) => {
                if matches!(e, pipeline::PipelineError::Parse(_)) {
                    println!("── Parse error: generated program ─────────────");
                    println!("{source}");
                    if !source.ends_with('\n') {
                        println!();
                    }
                    println!("───────────────────────────────────────────────");
                }
                eprintln!("[attempt {attempt}] {e}");
                if attempt <= cli.max_retries {
                    let retry_msg = pipeline::format_error_for_retry(&source, &e);
                    // Add assistant response and error feedback to conversation
                    messages.push(llm::Message {
                        role: "assistant".into(),
                        content: raw_response,
                    });
                    messages.push(llm::Message {
                        role: "user".into(),
                        content: retry_msg,
                    });
                    continue;
                }
                eprintln!("error: all attempts exhausted");
                std::process::exit(1);
            }
        };

        // Execute
        let host = tools::LiveHost::new(client.clone());
        let output = match pipeline::execute(&program, LuaValue::Nil, config.clone(), host) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[attempt {attempt}] {e}");
                if attempt <= cli.max_retries {
                    let retry_msg = pipeline::format_error_for_retry(&source, &e);
                    messages.push(llm::Message {
                        role: "assistant".into(),
                        content: raw_response,
                    });
                    messages.push(llm::Message {
                        role: "user".into(),
                        content: retry_msg,
                    });
                    continue;
                }
                eprintln!("error: all attempts exhausted");
                std::process::exit(1);
            }
        };

        // Success
        let prove_artifacts = if cli.prove {
            let circuit_dir = std::path::PathBuf::from(&cli.circuit_dir);
            let artifacts = prove::build_proof_artifacts_with_noir(
                &program,
                &LuaValue::Nil,
                output.clone(),
                vec![],
                &cli.prove_output,
                &circuit_dir,
            );
            match artifacts {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!("error: proof artifact generation failed: {e}");
                    None
                }
            }
        } else {
            None
        };

        let result = pipeline::PipelineResult {
            task: cli.task.clone(),
            model: model.clone(),
            source,
            output,
            config: config.clone(),
            attempts: attempt,
            token_usage: total_usage.clone(),
        };

        if cli.json {
            print_json(&result, &prove_artifacts);
        } else {
            print!("{}", pipeline::format_output(&result));
            if let Some(ref artifacts) = prove_artifacts {
                print!("\n{}", prove::format_prove_section(artifacts));
            }
        }
        return;
    }

    eprintln!("error: all attempts exhausted");
    std::process::exit(1);
}

fn print_json(result: &pipeline::PipelineResult, prove_artifacts: &Option<prove::ProveArtifacts>) {
    let hashes = pipeline::compute_hashes(result);

    let transcript: Vec<serde_json::Value> = result
        .output
        .transcript
        .iter()
        .map(|r| {
            let args_str = String::from_utf8_lossy(&r.args_canonical).to_string();
            let response_str = String::from_utf8_lossy(&r.response_canonical).to_string();
            serde_json::json!({
                "seq": r.seq,
                "tool": r.tool_name,
                "args": serde_json::from_str::<serde_json::Value>(&args_str).unwrap_or(serde_json::Value::String(args_str)),
                "response": serde_json::from_str::<serde_json::Value>(&response_str).unwrap_or(serde_json::Value::String(response_str)),
                "response_hash": r.response_hash,
                "response_bytes": r.response_bytes,
                "status": format!("{:?}", r.status),
                "gas_charged": r.gas_charged,
            })
        })
        .collect();

    let mut json = serde_json::json!({
        "task": result.task,
        "model": result.model,
        "source": result.source,
        "attempts": result.attempts,
        "return_value": pipeline::format_return_value(&result.output.return_value),
        "logs": result.output.logs,
        "resource_usage": {
            "gas_used": result.output.gas_used,
            "gas_limit": result.config.gas_limit,
            "memory_used": result.output.memory_used,
            "memory_limit": result.config.memory_limit_bytes,
            "tool_calls": result.output.transcript.len(),
            "tool_call_limit": result.config.max_tool_calls,
            "llm_input_tokens": result.token_usage.input_tokens,
            "llm_output_tokens": result.token_usage.output_tokens,
            "llm_total_tokens": result.token_usage.total(),
        },
        "transcript": transcript,
        "verification": {
            "program_hash": hashes.program_hash,
            "tape_hash": hashes.tape_hash,
            "output_hash": hashes.output_hash,
        },
    });

    if let Some(artifacts) = prove_artifacts {
        let pi = &artifacts.public_inputs;
        let hex = |h: &[u8; 32]| -> String { h.iter().map(|b| format!("{b:02x}")).collect() };
        let mut proving = serde_json::json!({
            "program_hash": hex(&pi.program_hash),
            "input_hash": hex(&pi.input_hash),
            "tool_responses_hash": hex(&pi.tool_responses_hash),
            "output_hash": hex(&pi.output_hash),
            "compiled_path": artifacts.compiled_path.to_string_lossy(),
            "dry_result_path": artifacts.dry_result_path.to_string_lossy(),
        });
        if let Some(np) = &artifacts.noir_proof {
            let mut proof_hex = String::with_capacity(2 + np.proof_bytes.len() * 2);
            proof_hex.push_str("0x");
            for b in &np.proof_bytes {
                proof_hex.push_str(&format!("{b:02x}"));
            }
            proving["proof_bytes_hex"] = serde_json::Value::String(proof_hex);
            proving["public_inputs"] = serde_json::Value::Array(
                np.public_inputs_hex
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            );
            proving["prove_duration_ms"] =
                serde_json::Value::Number(serde_json::Number::from(np.prove_duration_ms as u64));
            proving["verified"] = serde_json::Value::Bool(np.verified);
        }
        json["proving"] = proving;
    }

    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

/// Run `pipeline::generate_and_compile` `n` times with fresh conversations
/// and print either a single-run report (n=1) or a histogram + per-run
/// table (n>1). Each run is independent so retry feedback cannot
/// contaminate the per-stage failure measurement.
fn run_generate_and_compile_batch(
    client: &llm::LlmClient,
    system_prompt: &str,
    task: &str,
    n: usize,
    json: bool,
) {
    let mut outcomes: Vec<pipeline::GenerateCompileOutcome> = Vec::with_capacity(n);
    for i in 1..=n {
        eprintln!("[run {i}/{n}] generating + compiling...");
        let outcome = pipeline::generate_and_compile(client, system_prompt, task);
        eprintln!(
            "  → {} ({} ms, {} tok)",
            outcome.stage,
            outcome.latency_ms,
            outcome.usage.total()
        );
        outcomes.push(outcome);
    }
    let hist = pipeline::StageHistogram::from_outcomes(&outcomes);

    if json {
        print_generate_and_compile_json(task, &hist, &outcomes);
    } else if n == 1 {
        let o = &outcomes[0];
        println!("── Generate + compile result ──────────────────");
        println!("Task:    {task:?}");
        println!("Stage:   {} ({} ms)", o.stage, o.latency_ms);
        if let Some(ref err) = o.error {
            println!("Error:   {err}");
        }
        println!(
            "Tokens:  {} in + {} out = {} total",
            o.usage.input_tokens,
            o.usage.output_tokens,
            o.usage.total()
        );
        if let Some(ref src) = o.source {
            println!("── Source ─────────────────────────────────────");
            println!("{src}");
        }
    } else {
        print!("{}", pipeline::format_histogram(&hist, &outcomes));
    }
}

fn print_generate_and_compile_json(
    task: &str,
    hist: &pipeline::StageHistogram,
    outcomes: &[pipeline::GenerateCompileOutcome],
) {
    let runs: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "stage": o.stage.label(),
                "error": o.error,
                "source": o.source,
                "latency_ms": o.latency_ms as u64,
                "input_tokens": o.usage.input_tokens,
                "output_tokens": o.usage.output_tokens,
            })
        })
        .collect();

    let json = serde_json::json!({
        "task": task,
        "runs": runs,
        "histogram": {
            "generate": hist.generate,
            "parse": hist.parse,
            "compile": hist.compile,
            "verify": hist.verify,
            "compiled": hist.compiled,
            "total": hist.total(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
