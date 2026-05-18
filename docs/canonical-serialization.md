# Canonical Serialization

This document specifies the byte-exact encoding used to produce `policy_hash`
and other hash commitments in luai. An independent implementation that follows
this specification will produce the same SHA-256 hashes for the same inputs.

---

## OraclePolicy canonical bytes

`OraclePolicy::canonical_bytes()` serializes the policy fields in the following
fixed order. All multi-byte integers are **little-endian**. There is no framing
header; the fields are concatenated directly.

### Field order

| # | Field | Encoding |
|---|-------|----------|
| 1 | `allowed_domains` | sorted string list (see §String list) |
| 2 | `allowed_http_methods` | sorted string list |
| 3 | `max_tool_calls` | u64LE (8 bytes) |
| 4 | `max_payload_bytes_per_call` | u64LE (8 bytes) |
| 5 | `tls_requirement` | u8 enum tag (see §TLS enum) |
| 6 | `required_output_schema` | length-prefixed canonical JSON (see §Schema) |
| 7 | `schema_versions` | sorted domain→schema map (see §Schema map) |

### String list encoding

A list of UTF-8 strings is encoded as:

```
u32LE(count)
for each string in sorted order:
    u32LE(byte_length)
    utf8_bytes
```

Strings are sorted lexicographically (Rust `str::cmp` / Unicode code-point order)
before encoding. The same string list in any insertion order produces identical bytes.

### TLS enum tag

| `TlsRequirement` variant | byte value |
|--------------------------|------------|
| `UnattestedPermitted`    | `0x00`     |
| `PreferredAttested`      | `0x01`     |
| `RequiredAttested`       | `0x02`     |

### Schema field encoding

A single optional JSON schema value (`required_output_schema`) is encoded as:

```
u32LE(canonical_json_byte_length)   # 0 when None
canonical_json_bytes                 # omitted when None (length = 0)
```

`canonical_json_bytes` is the output of the canonical JSON serializer described
in §Canonical JSON below.

### Schema map encoding

`schema_versions` (a map from domain string to JSON schema) is encoded as:

```
u32LE(entry_count)
for each (domain, schema) in lexicographic domain order:
    u32LE(domain_byte_length)
    domain_utf8_bytes
    u32LE(schema_byte_length)
    schema_canonical_json_bytes
```

Entries are sorted by domain string (same ordering as §String list).

---

## Canonical JSON

Objects inside `OraclePolicy` (schemas in `required_output_schema` and
`schema_versions`) are serialized to compact JSON with **sorted keys**.

Rules:
- No whitespace (no spaces, no newlines).
- Object keys are sorted lexicographically (Unicode code-point order).
- Numbers are serialized without leading zeros (standard JSON number format).
- Strings are serialized with JSON escaping (`\"`, `\\`, `\n`, `\r`, `\t`,
  `\uXXXX` for non-ASCII control characters).
- Arrays preserve element order.
- `null`, `true`, `false` as literals.
- Encoding is UTF-8.

### Example

The JSON object `{"z": 1, "a": 2, "m": 3}` canonicalizes to:

```
{"a":2,"m":3,"z":1}
```

(bytes: `7b 22 61 22 3a 32 2c 22 6d 22 3a 33 2c 22 7a 22 3a 31 7d`)

---

## policy_hash

```
policy_hash = SHA-256(OraclePolicy::canonical_bytes())
```

The hash is 32 bytes. An all-zero hash (`[0u8; 32]`) indicates that no policy
was in force (no-policy stub); callers should reject all-zero hashes when a
policy is required.

---

## LuaValue canonical JSON (tool responses and inputs)

Tool call arguments, responses, program inputs, and outputs are serialized with
`canonical_serialize(v: &LuaValue)` in `src/host/canonicalize.rs`. This
function produces the same canonical JSON format:

- Tables with consecutive integer keys starting at 1 are arrays: `[v1,v2,v3]`
- All other tables are objects with **sorted string keys**: `{"a":1,"b":2}`
- Integer keys in hash section are serialized as decimal strings in the key.
- Strings are length-checked (max 1 MB).
- Functions are not serializable (returns `CanonError::FunctionNotSerializable`).
- Table nesting depth is limited to 32 (`CanonError::TableDepthExceeded`).

---

## Hash commitments in PublicInputs

| Field | Preimage |
|-------|----------|
| `program_hash` | SHA-256 of the concatenated canonical encoding of all `FunctionProto`s |
| `input_hash` | SHA-256 of `canonical_serialize(input_value)` |
| `tool_responses_hash` | SHA-256 of framed oracle tape entries (see `OracleTape::commitment_hash()`) |
| `output_hash` | SHA-256 of `return_value \|\| length-prefixed logs \|\| transcript entries` |
| `tls_attestation_hash` | SHA-256 of framed P-256-verified cert chains (see `src/tls/mod.rs`) |
| `policy_hash` | SHA-256 of `OraclePolicy::canonical_bytes()` as above |

All SHA-256 computations use the standard FIPS 180-4 algorithm.
