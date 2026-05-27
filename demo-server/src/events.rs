use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "stage", content = "data", rename_all = "snake_case")]
#[allow(dead_code)] // Error variant is part of the public SSE schema; emitted in Phase 2a+.
pub enum DemoEvent {
    GeneratingLua {
        prompt: String,
    },
    LuaReady {
        lua: String,
    },
    Compiling,
    Executing,
    ToolCall {
        name: String,
        args: String,
        response: String,
    },
    Proving,
    Complete {
        result: serde_json::Value,
        hashes: ProofHashes,
    },
    Error {
        message: String,
        at_stage: String,
    },
}

#[derive(Serialize, Clone, Debug)]
pub struct ProofHashes {
    pub program_hash: String,
    pub input_hash: String,
    pub tool_responses_hash: String,
    pub output_hash: String,
    pub tls_attestation_hash: String,
    pub policy_hash: String,
}
