# Stack-semantics constraints — opcode reference & analysis

> Design doc for GitHub issue #30 (`feat/noir-stack-semantics`).
> First-draft opcode table derived directly from the VM dispatch loop, with a
> constrainability analysis per opcode. The "Constrainable?" columns are an
> analysis to be reviewed, not yet a committed design decision.

## Why this doc exists

The Noir circuit currently proves execution *shape* (opcodes match bytecode,
control flow is consistent, the final `Ret` returns the claimed value) but does
**not** prove that intermediate stack values are computed correctly. A malicious
prover can fabricate `trace_stack_tops` for non-`Ret` steps. To close that gap
we must add circuit constraints that mirror, per opcode, what the VM actually
does to the stack.

This doc is the spec the circuit constraints must match. The **single source of
truth** for value semantics is `Vm::dispatch` in `src/vm/engine.rs:402+`. Arity
(pops/pushes) is independently specified in `stack_effect()` at
`src/bytecode/verifier.rs:452+`; every row below was cross-checked against it.

## Three load-bearing facts about the trace

Before any per-opcode rule makes sense, three properties of how the trace is
recorded (`src/vm/engine.rs:306-337`) constrain what is even *possible* to
assert.

### Fact 1 — `stack_top[i]` is the **pre-dispatch** top

The trace captures the top of stack *before* instruction `i` executes (the
comment at `engine.rs:306` says "Capture pre-dispatch state"). The `TraceStep`
is pushed after dispatch but still carries that pre-dispatch value
(`engine.rs:356`).

Consequences:
- An opcode's **inputs** are visible at `stack_top[i]` (the top input only).
- An opcode's **result** is visible at `stack_top[i+1]` — the next step's
  pre-dispatch top. **Every "push" constraint is forward-looking** and must
  guard `i+1 < num_steps`.

This means the issue's suggested `trace_stack_tops[i] == operand` for PushK is
off by one step; the correct target is `trace_stack_tops[i+1]`.

### Fact 2 — the trace is lossy: everything collapses to `i64`

`stack_top` is an `i64`. The recorder maps (`engine.rs:312-333`):
`Integer(n) → n`, `Boolean(true) → 1`, `Boolean(false) → 0`, and **everything
else (`Nil`, `String`, `Table`, `Closure`) → 0**.

Consequences:
- Value constraints have teeth **only for integer and boolean** values.
- The trace cannot distinguish `nil`, `false`, `""`, `{}`, or `0` — they are all
  `0`. Any constraint whose soundness depends on telling these apart is **not
  expressible** with the current trace (see Eq/Ne below).
- Arithmetic is safe despite the collapse: the VM errors (no trace produced) if
  an arithmetic operand is a non-integer, so a *valid* trace guarantees
  arithmetic operands really were the integers recorded.

### Fact 3 — only `stack_top` is recorded, not `stack_second`

Binary ops pop two values; the trace records only the top. The second operand
is **not in the trace at all**. Constraining any pop-2 opcode therefore requires
adding a `stack_second` witness column (issue step 2).

Pop order matters: every binary arm pops `b` first (top), then `a` (second) —
e.g. `Sub` computes `a - b` (`engine.rs:531-536`). So in trace terms
`b = stack_top[i]`, `a = stack_second[i]`, `result = a OP b`.

## Opcode table

Opcode IDs are from `src/noir/opcodes.rs` (authoritative). **Note:** the inline
numbers in issue #30's body (`Add (5)`, `Pop (19)`, …) are from an older scheme
and are wrong — use the IDs below.

`Δ` = net stack delta (from `stack_effect`). "result" = value left on top,
observed at `stack_top[i+1]`.

| ID | Opcode | pops | Δ | Value rule (from `dispatch`) | Inputs in trace? |
|----|--------|------|----|------------------------------|------------------|
| 0  | Nop        | 0 | 0  | no stack change | — |
| 1  | PushK      | 0 | +1 | push `constants[operand]` (operand is the **constant index**, not value) | constant **not committed** |
| 2  | PushNil    | 0 | +1 | push `nil` → collapses to `0` | n/a (constant) |
| 3  | PushTrue   | 0 | +1 | push `true` → `1` | n/a |
| 4  | PushFalse  | 0 | +1 | push `false` → `0` | n/a |
| 5  | Pop        | 1 | -1 | discard top; new top = old second | needs `stack_second` |
| 6  | Dup        | 1 | +1 | push copy of top → `result == stack_top[i]` | top only ✓ |
| 7  | LoadLocal  | 0 | +1 | push local slot `operand` (lives deep in stack, **not** on top) | local not in trace |
| 8  | StoreLocal | 1 | -1 | pop top into local slot; new top = old second | needs `stack_second` |
| 9  | LoadUp     | 0 | +1 | push upvalue `operand` | upvalue not in trace |
| 10 | StoreUp    | 1 | -1 | pop top into upvalue | — |
| 11 | NewTable   | 0 | +1 | push fresh table → `0` | — |
| 12 | GetTable   | 2 | -1 | `t[k]` | table/key not scalar |
| 13 | SetTable   | 3 | -3 | `t[k]=v`, pushes nothing | — |
| 14 | GetField   | 1 | 0  | `t[const]` | table not scalar |
| 15 | SetField   | 2 | -2 | `t[const]=v` | — |
| 16 | Add        | 2 | -1 | `a + b` = `stack_second[i] + stack_top[i]` | needs `stack_second` |
| 17 | Sub        | 2 | -1 | `a - b` = `stack_second[i] - stack_top[i]` | needs `stack_second` |
| 18 | Mul        | 2 | -1 | `a * b` | needs `stack_second` |
| 19 | IDiv       | 2 | -1 | `a // b` (floor div; `b==0` errors → no trace) | needs `stack_second` |
| 20 | Mod        | 2 | -1 | `a % b` (`b==0` errors → no trace) | needs `stack_second` |
| 21 | Neg        | 1 | 0  | `-a` = `-stack_top[i]` | top only ✓ |
| 22 | Eq         | 2 | -1 | `a == b` (**any** types) → bool | needs `stack_second` **+ type** |
| 23 | Ne         | 2 | -1 | `a != b` (any types) → bool | needs `stack_second` **+ type** |
| 24 | Lt         | 2 | -1 | `a < b` (ints, also strings) → bool | needs `stack_second` **+ type** |
| 25 | Le         | 2 | -1 | `a <= b` → bool | needs `stack_second` **+ type** |
| 26 | Gt         | 2 | -1 | `a > b` → bool | needs `stack_second` **+ type** |
| 27 | Ge         | 2 | -1 | `a >= b` → bool | needs `stack_second` **+ type** |
| 28 | Not        | 1 | 0  | `!truthy(a)` → bool. **truthiness ≠ i64 value**: `nil`/`false` are falsy, all else truthy; but the trace shows `nil`→0 *and* `0`→0 | top only, but truthiness not recoverable |
| 29 | And        | 0 | 0  | branch-only (short-circuit); leaves top unchanged | control-flow (already handled) |
| 30 | Or         | 0 | 0  | branch-only; leaves top unchanged | control-flow (already handled) |
| 31 | Concat     | n | 1-n | string concat → `0` | strings not scalar |
| 32 | Len        | 1 | 0  | `#a` (string/table length); operand collapses to `0` | length not recoverable |
| 33 | Jmp        | 0 | 0  | control flow (already constrained) | — |
| 34 | JmpIf      | 1 | -1 | pop, branch on truthy | control flow |
| 35 | JmpIfNot   | 1 | -1 | pop, branch on falsy | control flow |
| 36 | Call       | argc+1 | -argc | frame push; result unconstrained (already `is_unconstrained`) | out of scope |
| 37 | Ret        | — | — | collapse frame; final Ret returns top (already constrained, `main.nr`) | — |
| 38 | Closure    | 0 | +1 | push function → `0`; next_pc unconstrained | out of scope |
| 39 | ToolCall   | 2 | -1 | host response; value is non-deterministic input, bound via oracle tape | out of scope (tape) |
| 40 | PCall      | argc+1 | 1-argc | pushes `ok` bool + result | out of scope |
| 41 | Log        | 1 | -1 | pop 1, side effect only | — |
| 42 | Error      | — | — | raises; terminates | — |
| 43 | IterInitSorted | — | — | iterator handle setup; branch-only in `next_pc` logic | out of scope |
| 44 | IterInitArray  | — | — | iterator handle setup | out of scope |
| 45 | IterNext       | — | — | iterator step; pushes handle/values | out of scope |

## Constrainability partition

This is the real output of the analysis — it sorts opcodes into implementation
tiers by what each one needs.

### Tier A — constrainable **today**, `stack_top` only, no new witness
- **Dup (6)**: `stack_top[i+1] == stack_top[i]`.
- **Neg (21)**: `stack_top[i+1] == -stack_top[i]` (operand guaranteed integer).
- **PushNil/PushTrue/PushFalse (2/3/4)**: `stack_top[i+1] ==` `0`/`1`/`0`.

These are pure wins: a few asserts, zero trace/Rust changes. Good first commit
to validate the forward-looking (`i+1`) constraint pattern end-to-end.

### Tier B — needs one new witness column `stack_second`
- **Integer arithmetic Add/Sub/Mul/IDiv/Mod (16–20)**:
  `stack_top[i+1] == stack_second[i] OP stack_top[i]`. Sound — valid traces
  guarantee integer operands (VM errors otherwise). This is the **core
  soundness win** the issue is really after.
- **Pop (5)** and **StoreLocal (8)**: `stack_top[i+1] == stack_second[i]`
  (shape constraint; the stored *value* itself isn't verifiable without local
  tracking, but the stack-collapse is).

`stack_second` = the second-from-top value, captured pre-dispatch with the same
i64 collapse as `stack_top`. Adds one `[i64; MAX_STEPS]` column to the witness.

### Tier C — needs a **committed constant pool**
- **PushK (1)**: the operand is the constant *index*; the value is
  `constants[idx]` which is **not committed** in `program_hash` today (only
  `(opcode, idx)` pairs are). To soundly assert
  `stack_top[i+1] == <pushed value>` we must bring the resolved scalar constant
  into the circuit as a committed witness (folded into `program_hash`), and
  apply the same i64 collapse so only Integer/Boolean constants are constrained.
  This touches the Rust `canonical_hash` encoder — the largest blast radius of
  the three tiers.

### Tier D — **not** soundly constrainable with the current trace
These need a per-slot **type tag** the i64 trace doesn't carry. Listing them so
they are explicitly out of scope, not silently skipped:
- **Eq/Ne (22/23)**: compare values of any type. The collapse makes `nil`,
  `false`, `0`, `""`, `{}` indistinguishable, so a circuit equality check over
  the i64 values would give false positives (e.g. two distinct empty
  strings/tables both read `0` and look "equal"). Unsound without a type tag.
- **Lt/Le/Gt/Ge (24–27)**: same problem for any non-integer operand (e.g. string
  comparison).
- **Not (28)** and **Len (32)**: depend on truthiness / length that the i64
  collapse erases (`nil`→0 is falsy but `0`→0 is truthy; they're identical in
  the trace).
- **LoadLocal/LoadUp (7/9)**: the loaded value lives deep in the stack / in an
  upvalue cell, neither of which is in the trace.
- **Tables, strings, closures, calls, tools, iterators**: opaque scalars (`0`)
  by design; covered by the oracle-tape / transparency-receipt model, not by
  stack constraints.

## Recommended minimal trace extension

Add exactly one column, `stack_second: i64`, to `TraceStep`
(`src/noir/trace.rs`), populated in the recorder (`engine.rs:306-337`) with the
same collapse used for `stack_top`, applied to `self.stack[len-2]`. This unlocks
all of Tier B. Tier A needs nothing. Tier C is a separate, larger change
(constant-pool commitment) and can be a follow-on commit. Tier D is deferred and
documented as such.

## Adjacent unconstrained public inputs (out of scope for #30, recorded as a known gap)

While analysing the circuit for stack semantics, a related soundness gap one
level up became visible and is recorded here so it isn't lost — it is **not**
part of issue #30's scope.

Of the 8 public inputs, only four are actually bound in `noir/src/main.nr`:
`program_hash` (`assert_bytecode`, line 40), `return_value` (final `Ret`, line
128), `tool_responses_hash` (line 163), and `attestation_hash` (line 187). The
remaining three — **`input_hash`, `output_hash`, `policy_hash`** — are declared
`pub` (lines 60–63) but are **never referenced in the circuit body**. They are
free public inputs: the circuit accepts whatever the prover supplies.

The Rust side *does* compute real values (`hash_output(output)` over return
value + logs + transcript, `src/zkvm/commitment.rs:61`,
`proveno-noir/src/witness.rs:151`), so an honest prover fills them in
correctly — but nothing in the circuit forces that. A proof verifies with a
fabricated `output_hash`.

This is the same class of gap as #30, one level up: #30 is "intermediate stack
values aren't constrained"; this is "the output/input/policy commitments aren't
bound to the execution." Note the partial overlap: the circuit binds the scalar
`return_value`, but `output_hash` covers strictly more (return value **+ logs +
transcript**), so even the cross-checkable portion is currently unbound, and the
logs/transcript portion has no in-circuit anchor at all. Arguably a larger gap
than the stack one, since `output_hash` is the public input a consumer contract
keys on.

**Implication for the trace verifier:** mirror the circuit *as-is* (these three
unchecked) and mark them with an explicit `TODO`, so the Rust verifier documents
the gap rather than silently modelling a binding the circuit doesn't enforce.

## Open questions (resolve before circuit code)

1. **Constant-pool commitment shape (Tier C / PushK).** Two routes:
   (a) commit a parallel `[i64; MAX_BYTECODE]` constant-value array aligned to
   bytecode slots and fold it into `program_hash`; or (b) re-encode PushK's
   circuit operand to be the resolved scalar value instead of the index. (a)
   generalises to other value-carrying opcodes; (b) is smaller but PushK-only.
   Needs a read of `compiler/mod.rs::canonical_hash` to size the change.
2. **Gas/`MAX_STEPS` budget (issue step 4).** Tier A+B add a handful of field
   ops per step inside the existing `MAX_STEPS` loop. Measure the per-step gate
   delta with `make test-prove` before deciding whether `MAX_STEPS` must drop.
3. **`stack_second` underflow on shallow stacks.** When the stack has <2 entries
   the recorder must write a defined sentinel (`0`) and the circuit must not
   assert Tier B constraints for opcodes that didn't actually pop two — but
   arity is fixed per opcode, so a valid trace already guarantees depth ≥ pops.
   Confirm the recorder writes `0` rather than panicking on a 1-deep stack.
