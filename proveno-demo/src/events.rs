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
    VerifyingOnChain {
        chain_id: u64,
        verifier_addr: String,
        explorer_base: Option<String>,
    },
    VerifiedOnChain {
        accepted: bool,
        reason: Option<String>,
        tx_hash: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifying_on_chain_serializes_with_snake_case_stage() {
        let ev = DemoEvent::VerifyingOnChain {
            chain_id: 31337,
            verifier_addr: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".into(),
            explorer_base: None,
        };
        let json: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["stage"], "verifying_on_chain");
        assert_eq!(json["data"]["chain_id"], 31337);
        assert_eq!(
            json["data"]["verifier_addr"],
            "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
        );
        assert!(json["data"]["explorer_base"].is_null());
    }

    #[test]
    fn verified_on_chain_serializes_with_snake_case_stage() {
        let ev = DemoEvent::VerifiedOnChain {
            accepted: true,
            reason: None,
            tx_hash: None,
        };
        let json: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["stage"], "verified_on_chain");
        assert_eq!(json["data"]["accepted"], true);
        assert!(json["data"]["reason"].is_null());
        assert!(json["data"]["tx_hash"].is_null());
    }

    #[test]
    fn verified_on_chain_rejected_carries_reason() {
        let ev = DemoEvent::VerifiedOnChain {
            accepted: false,
            reason: Some("ProofInvalid".into()),
            tx_hash: None,
        };
        let json: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["data"]["accepted"], false);
        assert_eq!(json["data"]["reason"], "ProofInvalid");
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ProofHashes {
    pub program_hash: String,
    pub input_hash: String,
    pub tool_responses_hash: String,
    pub output_hash: String,
    pub attestation_hash: String,
    pub policy_hash: String,
}
