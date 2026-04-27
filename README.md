# atl-test-vectors

[![verify](https://github.com/PeptideRX/atl-test-vectors/actions/workflows/verify.yml/badge.svg)](https://github.com/PeptideRX/atl-test-vectors/actions/workflows/verify.yml)
[![verifier](https://img.shields.io/npm/v/@peptiderx/atl-verifier/experimental?label=verifier&color=cb3837)](https://www.npmjs.com/package/@peptiderx/atl-verifier)
[![status](https://img.shields.io/badge/status-experimental-orange)](#)

> ⚠️ **EXPERIMENTAL · ACTIVE DEVELOPMENT.** Published in the open as part of building peptideRx in public. The protocol is at V1 but APIs around it are not yet stable. The vectors and their published hashes are frozen — those will not change without a major-version bump.

Three frozen cryptographic test vectors for the Peptide Rx **Peptide Design Attestation (PDA)** protocol.

Any conforming implementation in any language must produce these three documented SHA-256 hashes when run against the corresponding input file. If yours does, you have byte-identical parity with the Python and Rust references. If yours does not, your implementation is non-conforming.

This is the public verification surface. The peptideRx core repository is private. These vectors and the open-source verifier (`@peptiderx/atl-verifier`) are how an outside observer confirms the cryptographic claim.

---

## The three vectors

| Vector | Shape                                                | PDA hash (32 bytes, hex)                                                |
|--------|------------------------------------------------------|-------------------------------------------------------------------------|
| **A**  | 1 candidate · simple shape                           | `28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e`     |
| **B**  | 2 candidates · `-9.0` dialect edge in reveal bundle  | `4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594`     |
| **C**  | 3 candidates · odd-count Merkle duplication          | `1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4`     |

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

Expected output (11 assertions across three groups):

```
GROUP 1 — Frozen PDA hashes reproduce under verifyPDA
  [PASS] vector-a: hash matches + chain verifies -- pda=28dbab77f560665f... chain=verified
  [PASS] vector-b: hash matches + chain verifies -- pda=4c261a1105a45c55... chain=verified
  [PASS] vector-c: hash matches + chain verifies -- pda=1bc8afdfee115252... chain=verified

GROUP 2 — Per-candidate reveal bundles verify under verifyCandidateReveal
  [PASS] vector-a candidate 0: reveal verifies (sequence=GIGAVLKVLT...)
  [PASS] vector-b candidate 0: reveal verifies (sequence=KLAKLAKKLA...)
  [PASS] vector-b candidate 1: reveal verifies (sequence=RGRGRGRGKL...)
  [PASS] vector-c candidate 0: reveal verifies (sequence=ACDEFGHIKL...)
  [PASS] vector-c candidate 1: reveal verifies (sequence=ACDEFGHIKL...)
  [PASS] vector-c candidate 2: reveal verifies (sequence=ACDEFGHIKL...)

GROUP 3 — Negative control: -9.0 preservation matters
  [PASS] vector-b.reveal.json contains a `-9.0` literal -- fixture exercises the dialect
  [PASS] JSON.parse + JSON.stringify of vector-b reveal DROPS the `.0` -- native round-trip breaks dialect; harness must use raw text

Result: 11 passed, 0 failed.
```

Three checks per vector, plus a negative control proving the harness actually exercises the Python-dialect canonical JSON edge case (vector B's `-9.0` float that JS's native `JSON.parse + JSON.stringify` round-trip silently drops to `-9`). Exit code 0 if all 11 pass, 1 if any fail.

---

## What's in this repo

| Path                                | Purpose                                                                                                |
|-------------------------------------|--------------------------------------------------------------------------------------------------------|
| `vectors/vector-a.json`             | Vector A: PDAOutput JSON, 1 candidate                                                                  |
| `vectors/vector-b.json`             | Vector B: PDAOutput JSON, 2 candidates                                                                 |
| `vectors/vector-c.json`             | Vector C: PDAOutput JSON, 3 candidates · exercises odd-count Merkle duplication                        |
| `vectors/vector-b.reveal.json`      | Vector B reveal bundle · candidate metadata containing the `-9.0` Python-dialect canonical-JSON edge   |
| `vectors/vector-{a,c}.reveal.json`  | Vector A and C reveal bundles for selective-disclosure verification                                    |
| `verify.mjs`                        | Node script that runs `@peptiderx/atl-verifier` against all three vectors and asserts the documented hashes |
| `PDA-HASHES.txt`                    | Plain-text listing of the three hashes for direct human reference                                      |
| `package.json`                      | npm dependency on `@peptiderx/atl-verifier`                                                            |

---

## What this proves and what it does not

**This proves**: the cross-language byte-identical determinism property of the PDA protocol at V1. Any change to the canonical JSON dialect, domain separators, Merkle tag, odd-level duplication rule, or TEE simulator key would flip these three hashes simultaneously.

**This does NOT prove**: that any peptide design referenced by these vectors is safe, effective, or suitable for human use. The PDA is a cryptographic chain of custody for a research artifact, not a regulatory clearance. See `NOTICE` for the non-binding research-use-only disclaimer.

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

Apache-2.0 (see `LICENSE`). See `NOTICE` for non-binding, informational
research-scope disclaimers and for the test-vector public-domain
dedication. The `NOTICE` file does not modify the Apache-2.0 terms.

In short:

- Verification scripts (`verify.mjs`, `package.json`) and documentation
  (`README.md`, `PDA-HASHES.txt`, `LICENSE`, `NOTICE`): Apache-2.0.
- Vector data files in `vectors/`: dedicated to the public domain
  under Creative Commons CC0 1.0 Universal — copy, modify, and
  redistribute for any purpose without attribution.

---

## Contact

- Site: [peptiderx.io](https://peptiderx.io)
- White paper: [peptiderx.io/atl.html](https://peptiderx.io/atl.html)
- Verifier: [github.com/PeptideRX/atl-verifier](https://github.com/PeptideRX/atl-verifier)
- Issues: [github.com/PeptideRX/atl-test-vectors/issues](https://github.com/PeptideRX/atl-test-vectors/issues)
- Security: security@peptiderx.io (private disclosures only)
