# TLS Attestation

## What the attestation hash proves

When a luai Lua program calls `http_get` or `http_post` over HTTPS, the
prover captures the server's DER-encoded TLS certificate chain. If the chain
satisfies both of the following conditions:

1. **P-256 ECDSA** — the leaf certificate's public key uses the P-256 elliptic
   curve (`secp256r1 / prime256v1`, OID `1.2.840.10045.3.1.7`), and every
   certificate in the chain is signed with P-256 ECDSA.
2. **Mozilla root pinning** — the root certificate's SubjectPublicKeyInfo
   matches an entry in the Mozilla root CA store (embedded as a static constant
   via the `webpki-roots` crate; not fetched at runtime).

...then `tls_attestation_hash` in the resulting `PublicInputs` is non-zero and
equals:

```
SHA-256 over:
  for each verified record (in tool-call order):
    u32_le(number of certs in chain)
    for each cert:
      u32_le(cert DER length)
      cert DER bytes
```

This hash is committed by the zkVM guest (OpenVM) as one of its public outputs.
An on-chain verifier can use it to bind the proof to a specific server identity.

### What the hash does NOT prove

- **No wall-clock time.** The hash does not record when the TLS handshake
  occurred. Certificate validity periods are not checked at proof time.
- **No response freshness.** The proof binds the _certificate_, not the HTTP
  response body. A response could be stale even when the cert attests to a
  known server.
- **No full TLS session transcript.** Only the certificate chain is captured,
  not the TLS session keys, MAC tags, or the encrypted traffic.
- **No hostname pinning.** The hash covers the certificate DER bytes. Callers
  who need hostname binding must inspect the cert's Subject Alternative Names
  separately.

## Supported TLS configurations

| Configuration | `tls_attestation_hash` |
|---|---|
| HTTPS, leaf cert uses P-256, chain roots in Mozilla set | Non-zero |
| HTTPS, leaf cert uses RSA or Ed25519 | Zero (degraded) |
| HTTPS, root cert not in Mozilla set | Zero (degraded) |
| Plain HTTP (no TLS) | Zero (degraded) |
| TLS handshake error / network failure | Zero (degraded) |

## Degradation

When TLS attestation is unavailable — because the server does not use P-256,
the chain does not terminate in a Mozilla root, or the connection is plain
HTTP — the system degrades cleanly:

- Execution completes normally; no panic, no malformed proof.
- `tls_attestation_hash` is set to `[0u8; 32]`.
- A `TlsAttestationRecord::unavailable()` is recorded in the transcript so the
  verifier knows a tool call was made without provable TLS identity.

The degraded state is a valid proof; it simply does not commit to any server
identity. Protocols that require TLS attestation must explicitly reject proofs
where `tls_attestation_hash == [0; 32]`.

## P-256 verification in the zkVM guest

The signature check runs **inside the OpenVM guest** (not just in the prover
host):

1. The prover host captures the raw certificate chain DER bytes during the
   HTTPS connection and stores them in `TlsAttestationRecord.cert_chain_der`.
2. These bytes are passed to the guest as part of `DryRunResult.tls_attestations`
   inside the `OpenVMInput`.
3. The guest calls `reverify_attestations()` which independently runs
   `verify_p256_chain()` against the embedded Mozilla roots.
4. Only records that pass the in-guest check contribute to the
   `tls_attestation_hash` the guest commits.

This means a malicious prover cannot forge a non-zero `tls_attestation_hash` —
the signature check is part of the verifiable computation.

## Crate dependencies

| Crate | Role |
|---|---|
| `rustls` (dev) | TLS transport + cert capture in integration tests |
| `webpki-roots` | Mozilla root CA trust anchors (no_std static data) |
| `p256` | P-256 ECDSA signature verification (no_std, used in zkVM guest) |
| `x509-cert` | DER certificate parsing (no_std + alloc, used in zkVM guest) |
