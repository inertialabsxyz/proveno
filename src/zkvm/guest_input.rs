//! `GuestInput` — the serializable bundle fed into the zkVM guest.
//!
//! The guest reads one `GuestInput`, re-executes the program with a `TapeHost`
//! for tool calls, computes the `PublicInputs`, and commits them to the journal.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{
    compiler::{program_hash::compute_program_hash_sha256, proto::CompiledProgram},
    host::tape::{OracleTape, TapeEntry, TapeHost},
    policy::{canonical::PolicyView, guest::PolicyEnforcingHost},
    types::value::LuaValue,
    vm::{
        engine::{Vm, VmConfig, VmOutput},
        gas::VmError,
    },
    zkvm::commitment::{PublicInputs, compute_public_inputs_sha256_with_policy_hash},
};
use sha2::{Digest, Sha256};

/// Everything the zkVM guest needs to replay an agent execution deterministically.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GuestInput {
    /// The compiled Lua program (bytecode + program_hash).
    pub program: CompiledProgram,
    /// The input value passed to the program's top-level function.
    pub input_value: LuaValue,
    /// Pre-recorded oracle tape of tool responses.
    pub oracle_tape: OracleTape,
    /// VM resource limits (must be identical to the dry-run config).
    pub config: VmConfig,
    /// Tool names registered in the dry run (used to build the ToolRegistry inside the guest).
    pub tool_names: Vec<String>,
    /// `OraclePolicy::canonical_bytes()` of the policy in force, or empty when
    /// no policy was attached.
    ///
    /// The guest hashes these itself rather than being handed a `policy_hash`,
    /// so the committed hash provably corresponds to this document and a
    /// prover cannot assert an unrelated one. The policy is carried as bytes
    /// because `OraclePolicy` needs `serde_json` for its schemas and the guest
    /// is `no_std`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub policy_canonical: Vec<u8>,
}

impl GuestInput {
    /// Replay the program against the oracle tape and compute the public inputs.
    ///
    /// This is the whole of what a zkVM guest proves, and the host driver calls
    /// the identical function to predict what the guest will reveal. Keeping it
    /// in one place is the point: if host and guest computed these separately
    /// they could drift, and a drift shows up only as an unverifiable proof.
    ///
    /// Every commitment is derived from data in `self`, and `program_hash` is
    /// **recomputed from the bytecode** rather than read from
    /// `self.program.program_hash`. That field arrives from `proveno-compiler`,
    /// which builds with `poseidon` and therefore stores the Poseidon2 hash;
    /// using it here would both mix schemes and let a prover assert a program
    /// hash unrelated to what actually ran.
    ///
    /// Replay uses a [`TapeHost`], so no external calls happen and the run is
    /// bit-identical to the host dry run that produced the tape.
    ///
    /// `policy_hash` is SHA-256 of [`Self::policy_canonical`], matching
    /// `OraclePolicy::policy_hash` byte for byte, and is all-zero when no
    /// policy is attached. Unlike `attestation_hash`, this is not bind-only:
    /// the enforceable fields are parsed out of the *same* buffer that gets
    /// hashed (see [`PolicyView::parse`]) and enforced during the replay by
    /// [`PolicyEnforcingHost`], so an execution that violates the policy
    /// cannot be replayed and therefore cannot be proved. Editing the bytes
    /// moves the committed hash and the enforced rules together.
    ///
    /// Enforced in-guest: HTTP method restriction, domain allowlist,
    /// `max_tool_calls` (a rejected call still consumes budget), and
    /// `max_payload_bytes_per_call` via [`Self::check_tape_payload_sizes`]
    /// before replay starts. Still bind-only, because they need `serde_json`:
    /// `required_output_schema` and `schema_versions`, which stay host-side in
    /// `policy::OraclePolicyHost`. `tls_requirement` is parsed but not acted
    /// on, for the same reason `attestation_hash` is bind-only — the guest has
    /// no way to authenticate a provider blob.
    ///
    /// Not bound: [`VmConfig`]. The prover picks the gas and memory limits,
    /// which decide whether execution completes or aborts. Committing to the
    /// config is follow-on work.
    pub fn replay_public_inputs(&self) -> Result<(VmOutput, PublicInputs), VmError> {
        let program_hash = compute_program_hash_sha256(&self.program.prototypes);

        let (output, policy_hash) = if self.policy_canonical.is_empty() {
            let tape = TapeHost::new(self.oracle_tape.clone());
            let mut vm = Vm::new(self.config.clone(), tape);
            (
                vm.execute(&self.program, self.input_value.clone())?,
                [0u8; 32],
            )
        } else {
            // Parsed from the same bytes that get hashed below, so the policy
            // enforced and the policy committed are the same document by
            // construction rather than by convention.
            let view = PolicyView::parse(&self.policy_canonical).map_err(|e| {
                VmError::ToolError(alloc::format!("policy: unparsable canonical bytes: {e}"))
            })?;
            self.check_tape_payload_sizes(&view)?;

            let host = PolicyEnforcingHost::new(TapeHost::new(self.oracle_tape.clone()), view);
            let mut vm = Vm::new(self.config.clone(), host);
            let output = vm.execute(&self.program, self.input_value.clone())?;
            (output, Sha256::digest(&self.policy_canonical).into())
        };
        let public_inputs = compute_public_inputs_sha256_with_policy_hash(
            program_hash,
            &self.input_value,
            &self.oracle_tape,
            &output,
            policy_hash,
        );
        Ok((output, public_inputs))
    }

    pub fn new(
        program: CompiledProgram,
        input_value: LuaValue,
        oracle_tape: OracleTape,
        config: VmConfig,
        tool_names: Vec<String>,
    ) -> Self {
        GuestInput {
            program,
            input_value,
            oracle_tape,
            config,
            tool_names,
            policy_canonical: Vec::new(),
        }
    }

    /// Reject a tape carrying a response larger than the policy allows.
    ///
    /// Checked against the tape rather than inside the enforcing host because
    /// the tape entries already *are* the canonical response bytes: measuring
    /// them here is a length read, whereas doing it per call would mean
    /// re-serializing each response inside the guest for nothing.
    fn check_tape_payload_sizes(&self, policy: &PolicyView<'_>) -> Result<(), VmError> {
        let cap = policy.max_payload_bytes_per_call as usize;
        for (i, entry) in self.oracle_tape.entries.iter().enumerate() {
            let len = match entry {
                TapeEntry::Ok(bytes) => bytes.len(),
                TapeEntry::Err(msg) => msg.len(),
            };
            if len > cap {
                return Err(VmError::ToolError(alloc::format!(
                    "policy: tool call {i} response is {len} bytes, over the \
                     max_payload_bytes_per_call limit of {cap}"
                )));
            }
        }
        Ok(())
    }

    /// Attach the policy whose `canonical_bytes()` these are.
    pub fn with_policy_canonical(mut self, canonical: Vec<u8>) -> Self {
        self.policy_canonical = canonical;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compiler::compile, host::tape::TapeEntry, parser::parse};
    use alloc::vec;

    fn guest_input_for(src: &str) -> GuestInput {
        let program = compile(&parse(src).unwrap()).unwrap();
        GuestInput::new(
            program,
            LuaValue::Nil,
            OracleTape::new(),
            VmConfig::default(),
            Vec::new(),
        )
    }

    #[test]
    fn replay_executes_the_program() {
        let (output, _) = guest_input_for("return 1 + 2")
            .replay_public_inputs()
            .unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(3));
    }

    #[test]
    fn replay_is_deterministic() {
        let input = guest_input_for("local t = 0 for i = 1, 10 do t = t + i end return t");
        let (out_a, pi_a) = input.replay_public_inputs().unwrap();
        let (out_b, pi_b) = input.replay_public_inputs().unwrap();
        assert_eq!(out_a.return_value, LuaValue::Integer(55));
        assert_eq!(out_a.return_value, out_b.return_value);
        assert_eq!(pi_a, pi_b);
    }

    /// The proof must bind the bytecode that ran, not a hash the prover supplied.
    /// `proveno-compiler` stores a Poseidon2 `program_hash` on `CompiledProgram`;
    /// if that field leaked into the public inputs, a prover could assert any
    /// program hash for any execution.
    #[test]
    fn program_hash_is_recomputed_not_read_from_input() {
        let honest = guest_input_for("return 7");
        let (_, honest_pi) = honest.replay_public_inputs().unwrap();

        let mut tampered = guest_input_for("return 7");
        tampered.program.program_hash = [0xAA; 32];
        let (_, tampered_pi) = tampered.replay_public_inputs().unwrap();

        assert_eq!(honest_pi.program_hash, tampered_pi.program_hash);
        assert_ne!(honest_pi.program_hash, [0xAA; 32]);
        assert_eq!(honest_pi.digest_sha256(), tampered_pi.digest_sha256());
    }

    // ── Policy binding ───────────────────────────────────────────────────────

    #[test]
    fn no_policy_gives_a_zero_policy_hash() {
        let (_, pi) = guest_input_for("return 1").replay_public_inputs().unwrap();
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    /// The whole point of shipping canonical bytes rather than a hash: what the
    /// guest commits must equal what `OraclePolicy::policy_hash` produces on
    /// the host, or the two sides disagree about which policy was in force.
    #[cfg(feature = "std")]
    #[test]
    fn guest_policy_hash_matches_oracle_policy_hash() {
        let policy = crate::policy::profiles::constrained_http_v1();
        let input = guest_input_for("return 1").with_policy_canonical(policy.canonical_bytes());

        let (_, pi) = input.replay_public_inputs().unwrap();
        assert_eq!(pi.policy_hash, policy.policy_hash());
        assert_ne!(pi.policy_hash, [0u8; 32]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn different_policies_give_different_digests() {
        let a = crate::policy::profiles::constrained_http_v1();
        let b = crate::policy::profiles::template_price_feed_v1();

        let (_, pa) = guest_input_for("return 1")
            .with_policy_canonical(a.canonical_bytes())
            .replay_public_inputs()
            .unwrap();
        let (_, pb) = guest_input_for("return 1")
            .with_policy_canonical(b.canonical_bytes())
            .replay_public_inputs()
            .unwrap();

        assert_ne!(pa.policy_hash, pb.policy_hash);
        assert_ne!(pa.digest_sha256(), pb.digest_sha256());
    }

    // ── Guest-side policy enforcement ────────────────────────────────────────

    #[cfg(feature = "std")]
    fn policy_for(domains: &[&str], max_calls: usize) -> crate::policy::OraclePolicy {
        crate::policy::OraclePolicy {
            allowed_domains: domains.iter().map(|d| (*d).into()).collect(),
            allowed_http_methods: alloc::vec!["http_get".into()],
            max_tool_calls: max_calls,
            max_payload_bytes_per_call: 65536,
            tls_requirement: crate::policy::TlsRequirement::UnattestedPermitted,
            required_output_schema: None,
            schema_versions: Default::default(),
        }
    }

    #[cfg(feature = "std")]
    fn fetching(url: &str) -> GuestInput {
        let src =
            alloc::format!(r#"local r = tool.call("http_get", {{ url = "{url}" }}) return 0"#);
        let mut gi = guest_input_for(&src);
        gi.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"ok\":1}".to_vec())],
            attestations: vec![Vec::new()],
        };
        gi
    }

    /// The guarantee this buys: a run that violates the policy cannot be
    /// replayed, so no proof of it exists. Previously the guest ignored the
    /// policy entirely and would happily prove this execution while committing
    /// a policy_hash that said the domain was not allowed.
    #[cfg(feature = "std")]
    #[test]
    fn disallowed_domain_cannot_be_replayed() {
        let input = fetching("https://evil.example/steal")
            .with_policy_canonical(policy_for(&["api.example.com"], 4).canonical_bytes());

        let err = input.replay_public_inputs().unwrap_err();
        let msg = alloc::format!("{err:?}");
        assert!(msg.contains("evil.example"), "got: {msg}");
        assert!(msg.contains("allowed_domains"), "got: {msg}");
    }

    /// Same program and tape, allowed domain: proceeds, and still commits the
    /// policy. Without this the test above would pass for the wrong reason.
    #[cfg(feature = "std")]
    #[test]
    fn allowed_domain_replays_and_commits_the_policy() {
        let policy = policy_for(&["api.example.com"], 4);
        let input = fetching("https://api.example.com/v1/price")
            .with_policy_canonical(policy.canonical_bytes());

        let (output, pi) = input.replay_public_inputs().unwrap();
        assert_eq!(output.return_value, LuaValue::Integer(0));
        assert_eq!(pi.policy_hash, policy.policy_hash());
    }

    /// Attaching no policy leaves the old behaviour intact: nothing is checked.
    #[cfg(feature = "std")]
    #[test]
    fn without_a_policy_the_same_call_is_unchecked() {
        let (_, pi) = fetching("https://evil.example/steal")
            .replay_public_inputs()
            .unwrap();
        assert_eq!(pi.policy_hash, [0u8; 32]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn tool_call_cap_is_enforced_during_replay() {
        let src = r#"
            tool.call("http_get", { url = "https://api.example.com/a" })
            tool.call("http_get", { url = "https://api.example.com/b" })
            return 0
        "#;
        let mut gi = guest_input_for(src);
        gi.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{}".to_vec()), TapeEntry::Ok(b"{}".to_vec())],
            attestations: vec![Vec::new(), Vec::new()],
        };
        let input = gi.with_policy_canonical(policy_for(&["api.example.com"], 1).canonical_bytes());

        let err = input.replay_public_inputs().unwrap_err();
        assert!(
            alloc::format!("{err:?}").contains("tool call limit 1"),
            "got: {err:?}"
        );
    }

    /// An oversized recorded response is refused before replay starts.
    #[cfg(feature = "std")]
    #[test]
    fn oversized_tape_entry_is_rejected() {
        let mut policy = policy_for(&["api.example.com"], 4);
        policy.max_payload_bytes_per_call = 4;
        let input =
            fetching("https://api.example.com/v1").with_policy_canonical(policy.canonical_bytes());

        let err = input.replay_public_inputs().unwrap_err();
        assert!(
            alloc::format!("{err:?}").contains("max_payload_bytes_per_call"),
            "got: {err:?}"
        );
    }

    /// Corrupt policy bytes are refused rather than silently applied in part,
    /// since a partially applied policy is indistinguishable from a weaker one.
    #[cfg(feature = "std")]
    #[test]
    fn unparsable_policy_bytes_are_refused() {
        let mut bytes = policy_for(&["api.example.com"], 4).canonical_bytes();
        bytes.truncate(bytes.len() - 3);
        let input = fetching("https://api.example.com/v1").with_policy_canonical(bytes);

        let err = input.replay_public_inputs().unwrap_err();
        assert!(
            alloc::format!("{err:?}").contains("unparsable"),
            "got: {err:?}"
        );
    }

    /// A prover editing the policy bytes gets a proof of the *edited* policy,
    /// not the original: the guest both hashes and enforces the bytes it was
    /// given, so the two move together.
    ///
    /// Here the allowed domain is corrupted from `api.example.com` to
    /// `bpi.example.com`. The committed hash changes, and the call the original
    /// policy permitted is now rejected.
    #[cfg(feature = "std")]
    #[test]
    fn tampering_policy_bytes_changes_both_the_hash_and_what_is_enforced() {
        let policy = policy_for(&["api.example.com"], 4);
        let honest = policy.canonical_bytes();

        let at = honest
            .windows(b"api.example.com".len())
            .position(|w| w == b"api.example.com")
            .expect("domain present in canonical bytes");
        let mut tampered = honest.clone();
        tampered[at] = b'b';

        let url = "https://api.example.com/v1";
        let (_, honest_pi) = fetching(url)
            .with_policy_canonical(honest)
            .replay_public_inputs()
            .unwrap();
        assert_eq!(honest_pi.policy_hash, policy.policy_hash());

        let err = fetching(url)
            .with_policy_canonical(tampered)
            .replay_public_inputs()
            .unwrap_err();
        assert!(
            alloc::format!("{err:?}").contains("api.example.com"),
            "tampered policy should reject the domain it no longer lists: {err:?}"
        );
    }

    #[test]
    fn different_programs_get_different_program_hashes() {
        let (_, a) = guest_input_for("return 1").replay_public_inputs().unwrap();
        let (_, b) = guest_input_for("return 2").replay_public_inputs().unwrap();
        assert_ne!(a.program_hash, b.program_hash);
        assert_ne!(a.digest_sha256(), b.digest_sha256());
    }

    /// Same program, different recorded tool responses, must not collide: the
    /// tape is what the proof attests the program consumed.
    #[test]
    fn tape_contents_reach_the_public_inputs() {
        let src = "local r = tool.call(\"t\", {}) return 0";
        let mut a = guest_input_for(src);
        a.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"v\":1}".to_vec())],
            attestations: vec![Vec::new()],
        };
        let mut b = guest_input_for(src);
        b.oracle_tape = OracleTape {
            entries: vec![TapeEntry::Ok(b"{\"v\":2}".to_vec())],
            attestations: vec![Vec::new()],
        };

        let (_, pi_a) = a.replay_public_inputs().unwrap();
        let (_, pi_b) = b.replay_public_inputs().unwrap();
        assert_ne!(pi_a.tool_responses_hash, pi_b.tool_responses_hash);
        assert_ne!(pi_a.digest_sha256(), pi_b.digest_sha256());
    }

    /// A tape shorter than the program's tool calls must fail rather than
    /// silently produce a proof over a truncated run.
    #[test]
    fn exhausted_tape_fails_replay() {
        let input = guest_input_for("local r = tool.call(\"t\", {}) return 0");
        assert!(input.replay_public_inputs().is_err());
    }
}
