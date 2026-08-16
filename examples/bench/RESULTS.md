# Proveno proving-cost benchmark

Measures **gate count** (the input-independent cost truth, via `bb gates`),
trace length (`num_steps`), gas, and prove time for the window-max-breach task
across data sizes and two parsing strategies.

Toolchain: `nargo 1.0.0-beta.22`, `bb 5.0.0-nightly.20260522`, UltraHonk, on this
machine (14 threads). Circuit: `noir/src/main.nr` (`trace_verifier`).

## Scripts

| script | what it does |
|---|---|
| `gen.py` | generate a window-max-breach program: `--mode harness` (json.decode in host) or `--mode inlua` (byte-parse in the trace) |
| `steps.sh <prog.lua>` | compile + dry-run; report `num_steps`, gas, and whether it fits the current `MAX_STEPS` |
| `set_ceiling.sh <N>` | set `MAX_STEPS=N` in both the circuit and the Rust witness mirror, rebuild, recompile the circuit |
| `gates.sh` | `bb gates` on the current circuit (takes NO program — gates depend only on the circuit) |
| `set_caps.sh <C> <B>` | set `MAX_TOOL_CALLS=C` and `MAX_TAPE_ENTRY_BYTES=B` in both the circuit and the Rust witness mirror, recompile the circuit |
| `prove.sh <prog.lua>` | full compile→dry-run→witness→`bb prove`→`bb verify` with timing, at the current ceiling |

Reproduce the gate sweep: `for N in 256 512 1024 2048 4096 8192; do ./set_ceiling.sh $N >/dev/null; ./gates.sh; done`

## 1. Gate count is a pure function of MAX_STEPS, not the data

`bb gates` reads only the compiled circuit; it never sees a program or witness.
Confirmed empirically: two different programs at the same ceiling give identical
gates and near-identical prove time.

| MAX_STEPS | ACIR opcodes | gates (circuit_size) | prove time |
|---:|---:|---:|---:|
| 256  | 81,110    | 616,680   | — |
| 512  | 119,510   | 657,576   | — |
| 1,024 | 196,310  | 739,368   | — |
| **2,048** (shipping default) | 349,910 | **902,952** | 2.9 s |
| 4,096 | 657,110  | 1,230,120 | 4.0 s |
| 8,192 | 1,271,510 | 1,884,456 | 6.0 s |

Linear fit: **gates ≈ 574,700 + 159.8 × MAX_STEPS**. The ~575k fixed base is the
Poseidon2 bytecode hash (512×2 inputs), the oracle-tape hashing (16×1026 inputs),
and the keccak output binding — none of which depend on the program either.

Input-independence, measured: `p_harness_6.lua` (188 steps) and `h_50.lua`
(1,659 steps) both → **902,952 gates, 2.9 s prove** at MAX_STEPS=2048.

**This is a padded-ceiling design.** The circuit loops `for i in 0..MAX_STEPS`
unconditionally (`noir/src/main.nr:100`); unused steps are masked, not removed.
The cost driver is the ceiling, full stop.

## 2. Trace length per scenario (the input-dependent truth)

`window = n` (the whole series is the window) to stress the loop.

| program | mode | rows | num_steps | steps/row | fits MAX_STEPS=2048? |
|---|---|---:|---:|---:|---|
| `p_harness_6` | harness | 6   | 188     | — | yes |
| `h_50`        | harness | 50  | 1,659   | ~31 | yes |
| `h_100`       | harness | 100 | 3,209   | ~31 | no — needs ≥ 4,096 |
| `h_200`       | harness | 200 | 6,309   | ~31 | no — needs ≥ 8,192 |
| `h_400`       | harness | 400 | 12,514  | ~31 | no |
| `il_100`      | in-lua  | 100 | 86,559  | ~865 | no — needs ≥ 131,072 |

Harness windowing is ~31 steps/observation → the default ceiling is exhausted at
**~62 observations**. In-Lua byte parsing is ~865 steps/row (≈32 steps per input
byte) → the default ceiling is exhausted at **~2 rows**.

## 3. Walls hit as you scale data, in the order they bite

The padded ceiling is not the first wall. A real "5,000 observations" input hits
three earlier:

1. **64 KB single-value cap** (`MAX_STRING_LEN`, `src/vm/builtins.rs:33`). 5,000
   observations as one JSON literal/string is ~133 KB → **does not compile**
   (`StringTooLong`). Max embeddable ≈ 2,400 observations.
2. **200,000 gas cap** (prover's `VmConfig::default`, `src/vm/engine.rs:55` — note
   the CLAUDE.md doc table's "10M gas / 64MB" is stale; real defaults are 200k /
   16 MB). In-Lua parsing costs **1,219 gas/row** (dead linear), so it
   `GasExhausted` at **~164 rows**.
3. **MAX_STEPS=2048 trace cap.** As above: ~62 rows (harness) / ~2 rows (in-lua).
4. **16 tool calls × 1 KB tape** (`MAX_TOOL_CALLS`, `MAX_TAPE_ENTRY_BYTES`). Real
   *attested* oracle data is capped at **16 KB total** across the entire proof.

So "5,000 observations, WINDOW 5,000" does not run: it fails to compile at wall
(1). Extrapolating past it, 5,000 rows ≈ 155k steps → MAX_STEPS≈155k → ~25M gates.

## 4. The honest-worst-case finding (in-Lua parsing)

Moving the JSON parse from the host builtin into Lua (`gen.py --mode inlua`,
byte-scan with `string.byte`) makes it ~28× more steps per row than harness mode
(865 vs 31). But the sharper point is about what those steps buy:

The per-step circuit loop (`noir/src/main.nr:100-159`) constrains only
**control flow** — each step's opcode/operand match the bytecode, `next_pc`
follows the jump rules, step continuity, and the *final* `Ret`'s `stack_top ==
return_value`. It never checks that `ADD` adds or that `string.byte`/`tonumber`
returned the right value. `stack_top` is a free witness used only for branch
decisions and the final return.

Consequently `string.byte`, `string.sub`, `tonumber`, `json.decode` are all
**single opaque trace steps** whose results are trusted, not re-derived in-circuit.
Moving the parse "inside the proven region" lengthens the trace (more padding
pressure on MAX_STEPS, more gates once you raise it) **without making the parse
proven correct**. You pay the gate cost without buying the guarantee. To actually
constrain parsing you would need the circuit to re-execute the byte ops — which
this trace-commitment design does not do.

---

# Tape-cap sweep

Same method, different knob: hold `MAX_STEPS=2048` and vary the oracle-tape
bounds. Motivated by a concrete question, whether real API responses (which run
from 1.4 KB to 57 KB, well past the 1 KB cap) can be proven without losing the
few-seconds prove time. Run with `set_caps.sh` + `gates.sh`, same toolchain and
machine as the tables above.

## 5. Tape bytes cost ~501 gates each, dead linear

Holding `MAX_TOOL_CALLS=16`:

| MAX_TAPE_ENTRY_BYTES | ACIR opcodes | gates (circuit_size) | nargo compile |
|---:|---:|---:|---:|
| **1,024** (shipping default) | 349,910 | **902,952** | 5 s |
| 2,048 | 388,118 | 1,415,868 | 22 s |
| 4,096 | 464,598 | 2,443,048 | 65 s |
| 8,192 | 617,494 | 4,496,060 | 241 s |

Marginal cost across the three intervals: **500.9, 501.6, 501.2** gates per tape
byte. Linear fit **gates ≈ 389,700 + 501.2 × MAX_TAPE_ENTRY_BYTES**, or
**31.33 gates per tape byte per tool-call slot**.

The cause is the unconditional absorb loop at `noir/src/main.nr:180`. The
`Poseidon2::hash(entry_fields, len + 2)` message size narrows the *hash*, but the
circuit is static, so all `MAX_TOOL_CALLS × (MAX_TAPE_ENTRY_BYTES + 2)` field
positions are laid down whether or not any response fills them. You pay for the
declared cap, never for the bytes actually fetched.

**This is where the fixed base goes.** Section 1 fits the step sweep as
`gates ≈ 574,700 + 159.8 × MAX_STEPS`. Of that 574,700, tape hashing is
`501.2 × 1,024 =` **513,229 gates, or 89%**. At the shipping default, tape hashing
alone is **57% of the entire 902,952-gate circuit**. The dominant cost in the
proof is hashing a padded tape, not proving execution.

Combining both sweeps:

```
gates ≈ 61,500  +  159.8 × MAX_STEPS  +  31.33 × (MAX_TOOL_CALLS × MAX_TAPE_ENTRY_BYTES)
```

Checks out at the shipping default: 61,500 + 327,270 + 513,229 = 902,000 against a
measured 902,952, within 0.1%.

## 6. Cost is the product, so the split is free

Three ways to spend the same 65,536-byte tape budget:

| config | product | ACIR opcodes | gates | vs 16×4,096 | nargo compile |
|---|---:|---:|---:|---:|---:|
| 16 × 4,096 | 65,536 | 464,598 | 2,443,048 | baseline | 65 s |
| 8 × 8,192 | 65,536 | 463,764 | 2,445,045 | +0.08% | 117 s |
| 4 × 16,384 | 65,536 | 463,370 | 2,454,659 | +0.48% | 218 s |
| 1 × 65,536 | 65,536 | not measured | n/a | n/a | killed at 20 min |

Gate cost is the **product** `MAX_TOOL_CALLS × MAX_TAPE_ENTRY_BYTES`, flat to
within 0.5% across a 4× redistribution, with a slight penalty for fewer, larger
entries.

Practical consequence: raising `MAX_TAPE_ENTRY_BYTES` is only expensive if the
slot count is held at 16. **Raising the cap while cutting slots is nearly free.**
A task that makes one large fetch and a task that makes sixteen small ones can
have the same proof cost.

**Compile time does not follow the product, it follows entry size.** 65 s, 117 s,
218 s for the same budget at 4 KB, 8 KB, 16 KB entries, roughly 1.85× per doubling
of entry size. The `1 × 65,536` case was still compiling at 20 minutes and 700 MB
RSS when it was killed, so its gate count is unmeasured. The "one big fetch"
profile is free at proving time and expensive at build time, which is an argument
for several medium entries over one large one even though the proof costs the same.

## 7. What fits in a prove-time budget

Extrapolated, not measured. Section 1 gives prove time against gates at two points
(902,952 → 2.9 s, 1,884,456 → 6.0 s), a slope of **~3.16 s per million gates** on
this machine. That fit was measured over 0.9–1.9M gates and is being stretched well
past its range below, so treat these as order-of-magnitude:

| target prove | gate budget | tape budget (calls × bytes) | example profiles |
|---:|---:|---:|---|
| 5 s | 1.58M | ~38,000 B | 16 × 2.3 KB, 4 × 9.5 KB, 1 × 38 KB |
| 10 s | 3.16M | ~88,600 B | 16 × 5.5 KB, 4 × 22 KB, 2 × 44 KB |
| 15 s | 4.75M | ~139,000 B | 16 × 8.6 KB, 4 × 34 KB, 2 × 69 KB |
| 30 s | 9.50M | ~291,000 B | 16 × 18 KB, 4 × 72 KB, 2 × 145 KB |

Measured payload sizes for five real resolution sources: NY Fed rates 1,427 B,
Binance daily klines 18,574 B, ESPN NBA scoreboard 19,398 B, EDGAR full-text
search 57,319 B. Each of those fits individually inside a **10-second, 2 × 44 KB
or 4 × 22 KB** profile. None of them fits the shipping 1 KB cap.

So the bound question is a **profile** question, not a ceiling question. Each
profile is a distinct circuit, a distinct verification key, and a distinct
deployed verifier, which is a versioning and deployment cost rather than a tuning
flag.

## 8. Packing is the highest-leverage optimisation in the codebase

At **31.33 gates per tape byte per slot**, the tape term dominates everything else
in the circuit. The bytes are hash-only: `tape_entry_data` is absorbed into
Poseidon2 and never otherwise interpreted or constrained by the circuit. Nothing
downstream depends on their one-byte-per-Field representation.

Packing 31 bytes per Field (GH#35, Poseidon2 31:1) therefore cuts the absorb count
by up to **31×**, taking the tape term from ~31.3 to ~1.0 gates per byte, with both
sides only needing to agree on the packing. On the model above that turns
`16 × 64 KB` from roughly 33M gates into roughly 1.4M, which is below today's
shipping circuit.

This reclassifies GH#35. It is not deferred performance work. It is the
prerequisite for proving real API responses at all, and the difference between a
1 KB tape cap and a 64 KB one costing nothing.
