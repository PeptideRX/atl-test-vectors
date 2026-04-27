#!/usr/bin/env node
/**
 * verify.mjs — exhaustive cross-language reproduction harness for the
 * three frozen Peptide Design Attestation (PDA) test vectors.
 *
 * Runs the published @peptiderx/atl-verifier against:
 *
 *   1. Each vector's PDAOutput JSON, comparing the produced PDA hash
 *      against the documented frozen hash AND running the full
 *      cryptographic chain through verifyPDA.
 *
 *   2. Every per-candidate reveal bundle, calling verifyCandidateReveal
 *      so the Python canonical-JSON dialect (preserved -9.0 floats etc.)
 *      is exercised end-to-end. The reveal flow takes a raw metadata
 *      JSON STRING so Python's whole-number-floats-with-trailing-.0
 *      survive across language boundaries.
 *
 *   3. A negative-control assertion that confirms the JS-native round
 *      trip JSON.parse + JSON.stringify breaks the dialect, proving
 *      the harness IS exercising the edge case.
 *
 * Status: EXPERIMENTAL. Pin exact versions when depending on either
 * this script or the verifier.
 *
 * Exit codes:
 *   0 — all vectors and reveals reproduce
 *   1 — at least one assertion failed
 *   2 — setup or import error
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

let verifyPDA, verifyCandidateReveal;
try {
  ({ verifyPDA } = await import('@peptiderx/atl-verifier'));
  ({ verifyCandidateReveal } = await import('@peptiderx/atl-verifier/pda'));
} catch (err) {
  console.error('ERROR: failed to import @peptiderx/atl-verifier.');
  console.error('Run `npm install` first.');
  console.error('Underlying error:', err.message);
  process.exit(2);
}

// Frozen at PDA protocol V1. These hashes never change.
const EXPECTED_PDA = {
  'a': '28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e',
  'b': '4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594',
  'c': '1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4',
};

let pass = 0, fail = 0;
function assert(label, ok, detail = '') {
  console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${label}${detail ? ' -- ' + detail : ''}`);
  if (ok) pass++; else fail++;
}

function loadJsonRaw(name) {
  return readFileSync(resolve(__dirname, 'vectors', name), 'utf8');
}

/**
 * Extract the raw JSON substring for one candidate's metadata from a
 * reveal-bundle JSON file. We need the RAW text (not a parsed object)
 * so Python's whole-number-floats-with-trailing-.0 survive into the
 * verifyCandidateReveal call. Walks the source text by counting braces
 * starting at the candidate's opening brace.
 */
function extractCandidateMetadataJSON(revealText, candidateIndex) {
  // Find candidates array
  const candidatesIdx = revealText.indexOf('"candidates"');
  if (candidatesIdx === -1) return null;
  let i = revealText.indexOf('[', candidatesIdx);
  if (i === -1) return null;

  // Walk to candidate at candidateIndex
  let depth = 0;
  let inObj = false;
  let candCount = -1;
  let candStart = -1;
  for (; i < revealText.length; i++) {
    const ch = revealText[i];
    if (ch === '"') {
      // skip string
      i++;
      while (i < revealText.length && revealText[i] !== '"') {
        if (revealText[i] === '\\') i++;
        i++;
      }
      continue;
    }
    if (ch === '{') {
      if (depth === 0) {
        candCount++;
        if (candCount === candidateIndex) candStart = i;
      }
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && candCount === candidateIndex) {
        // We have the full candidate JSON. Now find "metadata":
        const candText = revealText.slice(candStart, i + 1);
        const mdLabel = candText.indexOf('"metadata"');
        if (mdLabel === -1) return null;
        let j = candText.indexOf('{', mdLabel);
        if (j === -1) return null;
        const mdStart = j;
        let d = 0;
        for (; j < candText.length; j++) {
          const c = candText[j];
          if (c === '"') {
            j++;
            while (j < candText.length && candText[j] !== '"') {
              if (candText[j] === '\\') j++;
              j++;
            }
            continue;
          }
          if (c === '{') d++;
          else if (c === '}') {
            d--;
            if (d === 0) {
              return candText.slice(mdStart, j + 1);
            }
          }
        }
        return null;
      }
    }
  }
  return null;
}

// =============================================================================
//  GROUP 1 — PDA hash reproduction
// =============================================================================

console.log('GROUP 1 — Frozen PDA hashes reproduce under verifyPDA');

for (const v of ['a', 'b', 'c']) {
  const output = JSON.parse(loadJsonRaw(`vector-${v}.json`));
  const expected = EXPECTED_PDA[v];
  const hashOk = output.pda_hex === expected;
  const report = await verifyPDA(output, { acceptSimulator: true });
  assert(
    `vector-${v}: hash matches + chain verifies`,
    hashOk && report.passed,
    `pda=${output.pda_hex.slice(0, 16)}... chain=${report.passed ? 'verified' : 'rejected (' + report.blocked_reasons.join(',') + ')'}`,
  );
}

// =============================================================================
//  GROUP 2 — Reveal-bundle verification (commit-reveal flow)
// =============================================================================

console.log('\nGROUP 2 — Per-candidate reveal bundles verify under verifyCandidateReveal');

for (const v of ['a', 'b', 'c']) {
  const output = JSON.parse(loadJsonRaw(`vector-${v}.json`));
  const revealText = loadJsonRaw(`vector-${v}.reveal.json`);
  const revealBundle = JSON.parse(revealText);

  const candidates = revealBundle.candidates || [];
  for (let idx = 0; idx < candidates.length; idx++) {
    const c = candidates[idx];

    const commitment = {
      candidate_id: c.candidate_id,
      salt_hex: c.salt_hex,
      canonical_sequence_hash: c.canonical_sequence_hash,
      metadata_hash: c.metadata_hash,
      commitment_hex: c.leaf_hex,
    };

    const inclusionProof = {
      leaf_index: c.leaf_index,
      leaf_hash_hex: c.leaf_hex,
      path: c.inclusion_path || [],
    };

    // Pull the RAW metadata JSON substring (preserves -9.0 etc.)
    const metadataJSON = extractCandidateMetadataJSON(revealText, idx);
    if (!metadataJSON) {
      assert(`vector-${v} candidate ${idx}: extracted raw metadata JSON`, false);
      continue;
    }

    try {
      const ok = await verifyCandidateReveal({
        pdaOutput: output,
        commitment,
        revealedSequence: c.sequence,
        revealedMetadataJSON: metadataJSON,
        inclusionProof,
      });
      assert(
        `vector-${v} candidate ${idx}: reveal verifies (sequence=${c.sequence.slice(0, 10)}...)`,
        ok,
      );
    } catch (e) {
      assert(`vector-${v} candidate ${idx}: reveal verifies`, false, e.message);
    }
  }
}

// =============================================================================
//  GROUP 3 — Negative control: prove the harness exercises the
//             canonical-JSON dialect edge case (-9.0 preservation)
// =============================================================================

console.log('\nGROUP 3 — Negative control: -9.0 preservation matters');

const vectorBRaw = loadJsonRaw('vector-b.reveal.json');
const containsNeg9pt0 = /-9\.0\b/.test(vectorBRaw);
assert(
  'vector-b.reveal.json contains a `-9.0` literal',
  containsNeg9pt0,
  containsNeg9pt0 ? 'fixture exercises the dialect' : 'fixture does not contain -9.0; dialect test is dormant',
);

if (containsNeg9pt0) {
  const naive = JSON.stringify(JSON.parse(vectorBRaw));
  const naiveDropsDot = !/-9\.0\b/.test(naive);
  assert(
    'JSON.parse + JSON.stringify of vector-b reveal DROPS the `.0`',
    naiveDropsDot,
    naiveDropsDot ? 'native round-trip breaks dialect; harness must use raw text' : 'JS happens to preserve here; the edge case may have shifted',
  );
}

// =============================================================================
//  Result
// =============================================================================

console.log(`\nResult: ${pass} passed, ${fail} failed.`);
process.exit(fail === 0 ? 0 : 1);
