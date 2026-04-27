# atl-test-vectors

> ⚠️ **EXPERIMENTAL · ACTIVE DEVELOPMENT.** Published in the open as part of building peptideRx in public. The protocol is at V1 but APIs around it are not yet stable. The vectors and their published hashes are frozen — those will not change without a major-version bump.

Three frozen cryptographic test vectors for the Peptide Rx **Peptide Design Attestation (PDA)** protocol.

Any conforming implementation in any language must produce these three documented SHA-256 hashes when run against the corresponding input file. If yours does, you have byte-identical parity with the Python and Rust references. If yours does not, your implementation is non-conforming.

This is the public verification surface. The peptideRx core repository is private. These vectors and the open-source verifier (`@peptiderx/atl-verifier`) are how an outside observer confirms the cryptographic claim.

---

## The three vectors

| Vector | Shape                                | PDA hash (32 bytes, hex)                                                |
|--------|--------------------------------------|-------------------------------------------------------------------------|
| **A**  | 1 candidate · simple shape           | `28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e`     |
| **B**  | 2 candidates · `-9.0` float edge     | `4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594`     |
| **C**  | 3 candidates · odd Merkle duplication| `1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4`     |

Reproduced byte-for-byte by:

- **Python** (private reference: `pydantic v2` + `sha2`)
- **Rust** (private reference: `serde_json` + `sha2`)
- **TypeScript** (public: [`@peptiderx/atl-verifier`](https://github.com/PeptideRX/atl-verifier), Web Crypto SubtleCrypto)

The TypeScript implementation is open source. The Python and Rust implementations are closed (biosecurity-relevant code, patent-pending IP).

---

## Run the verification (30 seconds)

Requires Node 20+. The verifier is live on npm:

```bash
npm install @peptiderx/atl-verifier@experimental
```

Or run the bundled harness:

```bash
git clone https://github.com/PeptideRX/atl-test-vectors.git
cd atl-test-vectors
npm install
node verify.mjs
```

**Live npm package**: [`@peptiderx/atl-verifier`](https://www.npmjs.com/package/@peptiderx/atl-verifier)

Expected output:

```
[PASS] vector-a.json
        expected: 28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e
        actual:   28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e
        chain:    verified
[PASS] vector-b.json
        ...
[PASS] vector-c.json
        ...

Result: 3 passed, 0 failed.
```

Exit code 0 if all three pass, 1 if any fail.

---

## What's in this repo

| Path                                | Purpose                                                                                                |
|-------------------------------------|--------------------------------------------------------------------------------------------------------|
| `vectors/vector-a.json`             | Vector A: PDAOutput JSON, 1 candidate                                                                  |
| `vectors/vector-b.json`             | Vector B: PDAOutput JSON, 2 candidates with the `-9.0` float canonical-JSON edge case                  |
| `vectors/vector-c.json`             | Vector C: PDAOutput JSON, 3 candidates exercising odd-leaf Merkle duplication                          |
| `vectors/vector-{a,b,c}.reveal.json` | Per-candidate reveal bundles for selective-disclosure verification                                     |
| `verify.mjs`                        | Node script that runs `@peptiderx/atl-verifier` against all three vectors and asserts the documented hashes |
| `PDA-HASHES.txt`                    | Plain-text listing of the three hashes for direct human reference                                      |
| `package.json`                      | npm dependency on `@peptiderx/atl-verifier`                                                            |

---

## What this proves and what it does not

**This proves**: the cross-language byte-identical determinism property of the PDA protocol at V1. Any change to the canonical JSON dialect, domain separators, Merkle tag, odd-level duplication rule, or TEE simulator key would flip these three hashes simultaneously.

**This does NOT prove**: that any peptide design referenced by these vectors is safe, effective, or suitable for human use. The PDA is a cryptographic chain of custody for a research artifact, not a regulatory clearance. See LICENSE for the research-use-only addendum.

---

## Why this exists

The peptideRx core repository is private. Anyone evaluating peptideRx's cryptographic claims should not have to take the company's word for them.

Three vectors. Three documented hashes. Two minutes of `npm install` and you have replicated the determinism claim with code you compiled yourself, on hardware you control, against vectors you can read end-to-end.

That is the open-trust posture: **the code that issues a commitment can stay private, but the code and inputs that verify it cannot.**

---

## Implementing your own verifier

If you are building a fourth implementation (Go, Swift, Elixir, anything), the reference open-source TypeScript verifier is at [`@peptiderx/atl-verifier`](https://github.com/PeptideRX/atl-verifier). The protocol is documented in the ATL dissertation appendix at [peptiderx.io/atl.html](https://peptiderx.io/atl.html).

Start by reproducing all three of these vectors. If your implementation matches all three, you have parity. If it diverges on any one, the canonical JSON dialect or one of the domain separators is almost certainly the cause.

---

## Stability commitment

The vectors and their hashes are **frozen** at protocol V1. They will not change without a major version bump that ships new vectors alongside.

The verifier package and this repo are **experimental**. Pin exact versions when depending on either.

---

## License

Apache-2.0 plus a research-use-only addendum on output interpretation.

The vector data itself is dedicated to the public domain (CC0): you may copy, modify, and redistribute the JSON files for any purpose without attribution.

---

## Contact

- Site: [peptiderx.io](https://peptiderx.io)
- White paper: [peptiderx.io/atl.html](https://peptiderx.io/atl.html)
- Verifier: [github.com/PeptideRX/atl-verifier](https://github.com/PeptideRX/atl-verifier)
- Issues: [github.com/PeptideRX/atl-test-vectors/issues](https://github.com/PeptideRX/atl-test-vectors/issues)
- Security: security@peptiderx.io (private disclosures only)
