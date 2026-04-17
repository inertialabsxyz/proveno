# TLS Attestation

## What the attestation hash proves

When a luai Lua program calls `http_get` or `http_post` over HTTPS, the
prover captures the server's DER-encoded TLS certificate chain. If the chain
satisfies all of the following conditions:

1. **P-256 ECDSA** — the leaf certificate's public key uses the P-256 elliptic
   curve (`secp256r1 / prime256v1`, OID `1.2.840.10045.3.1.7`), and every
   certificate in the chain is signed with P-256 ECDSA.
2. **Mozilla root pinning** — the root certificate's SubjectPublicKeyInfo
   matches an entry in the Mozilla root CA store (embedded as a static constant
   via the `webpki-roots` crate; not fetched at runtime).
3. **Hostname binding** — the leaf certificate's Subject Alternative Names
   (SAN extension) include the hostname from the request URL. Wildcard SANs
   (`*.example.com`) are matched against a single label. CN fallback is not
   supported; a SAN extension is required.

...then `tls_attestation_hash` in the resulting `PublicInputs` is non-zero and
equals:

```
SHA-256 over:
  for each verified record (in tool-call order):
    u32_le(hostname length in bytes)
    hostname bytes (UTF-8)
    u64_le(cert_not_after, Unix seconds, from leaf cert validity field)
    u32_le(number of certs in chain)
    for each cert:
      u32_le(cert DER length)
      cert DER bytes
```

This hash is committed by the zkVM guest (OpenVM) as one of its public outputs.
An on-chain verifier can use it to bind the proof to a specific server identity
and inspect when the leaf certificate expires.

### What the hash does NOT prove

- **No wall-clock time at connection.** The hash commits the leaf certificate's
  `not_after` timestamp, so verifiers can check cert expiry as of proof
  verification time. However, it does not record when the TLS handshake
  actually occurred, so there is no proof that the certificate was valid at
  connection time.
- **No response freshness.** The proof binds the _certificate_, not the HTTP
  response body. A response could be stale even when the cert attests to a
  known server.
- **No full TLS session transcript.** Only the certificate chain is captured,
  not the TLS session keys, MAC tags, or the encrypted traffic.

## Supported TLS configurations

| Configuration | `tls_attestation_hash` |
|---|---|
| HTTPS, leaf cert uses P-256, chain roots in Mozilla set, hostname matches SAN | Non-zero |
| HTTPS, leaf cert uses RSA or Ed25519 | Zero (degraded) |
| HTTPS, root cert not in Mozilla set | Zero (degraded) |
| HTTPS, hostname does not match leaf cert SANs | Zero (degraded) |
| HTTPS, leaf cert has no SAN extension | Zero (degraded) |
| Plain HTTP (no TLS) | Zero (degraded) |
| TLS handshake error / network failure | Zero (degraded) |

## Degradation

When TLS attestation is unavailable — because the server does not use P-256,
the chain does not terminate in a Mozilla root, the hostname does not match
the leaf cert's SANs, or the connection is plain HTTP — the system degrades
cleanly:

- Execution completes normally; no panic, no malformed proof.
- `tls_attestation_hash` is set to `[0u8; 32]`.
- A `TlsAttestationRecord::unavailable()` is recorded in the transcript so the
  verifier knows a tool call was made without provable TLS identity.

The degraded state is a valid proof; it simply does not commit to any server
identity. Protocols that require TLS attestation must explicitly reject proofs
where `tls_attestation_hash == [0; 32]`.

## P-256 verification and hostname binding in the zkVM guest

All checks run **inside the OpenVM guest** (not just in the prover host):

1. The prover host captures the raw certificate chain DER bytes and the request
   hostname during the HTTPS connection, storing them in
   `TlsAttestationRecord.cert_chain_der` and `TlsAttestationRecord.hostname`.
2. These are passed to the guest as part of `DryRunResult.tls_attestations`
   inside the `OpenVMInput`.
3. The guest calls `reverify_attestations()` which independently:
   - Runs `verify_p256_chain()` against the embedded Mozilla roots.
   - Checks that the leaf cert's SAN extension covers the supplied hostname.
   - Extracts `cert_not_after` from the leaf cert DER (ignoring the prover's
     value to prevent a malicious prover from forging the timestamp).
4. Only records that pass all in-guest checks contribute to the
   `tls_attestation_hash` the guest commits.

This means a malicious prover cannot forge a non-zero `tls_attestation_hash`
— the signature check, hostname match, and `not_after` extraction are all
part of the verifiable computation.

## Crate dependencies

| Crate | Role |
|---|---|
| `rustls` (dev) | TLS transport + cert capture in integration tests |
| `webpki-roots` | Mozilla root CA trust anchors (no_std static data) |
| `p256` | P-256 ECDSA signature verification (no_std, used in zkVM guest) |
| `x509-cert` | DER certificate parsing — SPKI, SANs, validity (no_std + alloc, used in zkVM guest and dev tests) |
