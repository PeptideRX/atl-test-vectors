#!/usr/bin/env node
/**
 * produce-and-verify-fresh.mjs
 *
 * Generate a BRAND-NEW PDA run from scratch — different inputs from
 * Vectors A, B, C — using ONLY public exports from
 * `@peptiderx/atl-verifier`. Then verify it end-to-end against the
 * same public verifier anyone can install from npm.
 *
 * Why this exists: anyone evaluating peptideRx's cryptographic claims
 * shouldn't have to take the company's word that "the verifier works
 * for arbitrary inputs, not just the three pinned vectors." This
 * script proves the protocol works for any input by generating a
 * fresh one every time it runs.
 *
 * Run:
 *
 *   npm install @peptiderx/atl-verifier@experimental
 *   node produce-and-verify-fresh.mjs
 *
 * Expected output: every step PASS, fresh PDA hex printed at the end.
 */

import { writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

import {
  // Verifier-side
  verifyPDA,
  verifyCandidateReveal,
  // Producer primitives — all public exports
  computeCandidateCommitLeaf,
  computeCandidateMetadataHash,
  pdaSha256,
  pdaHmacSha256,
  pdaComponentHash,
  pdaU32BE,
  pdaMerkleRoot,
  pdaGenerateInclusionProof,
  canonicalizePythonJSON,
  bytesToHex,
  hexToBytes,
  // Constants
  PDA_SCHEMA_VERSION_V1,
  PDA_DOMAIN_SEPARATOR,
  PDA_DOMAIN_TARGET_SPEC,
  PDA_DOMAIN_PIPELINE_MANIFEST,
  PDA_DOMAIN_BIOSECURITY_POLICY,
  PDA_DOMAIN_TIER_DIST,
  PDA_DOMAIN_TEE_ATTESTATION,
  PDA_SIMULATOR_MEASUREMENT_HEX,
  PDA_SIMULATOR_SIGNING_KEY_HEX,
} from '@peptiderx/atl-verifier';

const NONCLINICAL_SCOPE = 'research use only, nonclinical, no human-use claim';
const utf8 = (s) => new TextEncoder().encode(s);
const randHex = (n) => randomBytes(n).toString('hex');

function uuidv4() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function step(n, total, label) {
  console.log(`[${n}/${total}] ${label}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Define BRAND-NEW inputs (different from Vectors A, B, C)
// ─────────────────────────────────────────────────────────────────────────────

console.log('═'.repeat(72));
console.log('  Producing a fresh PDA run with arbitrary inputs.');
console.log('  None of the inputs below appear in Vectors A, B, or C.');
console.log('═'.repeat(72));
console.log('');

const target_spec = {
  target_pdb_hash: randHex(32),
  pocket_coordinates: [
    { x_nm: 12, y_nm: -8, z_nm: 4 },
    { x_nm: 13, y_nm: -7, z_nm: 5 },
    { x_nm: 11, y_nm: -9, z_nm: 3 },
  ],
  length_min: 10,
  length_max: 20,
  modifications_whitelist: ['acetyl_n_term', 'amide_c_term'],
  scope: NONCLINICAL_SCOPE,
};

const pipeline_manifest = {
  backbone_model: { name: 'rfdiffusion', version: '1.4.2', weights_sha256: randHex(32) },
  sequence_model: { name: 'proteinmpnn', version: '1.0.1', weights_sha256: randHex(32) },
  structure_model: { name: 'boltz2', version: '0.6.0', weights_sha256: randHex(32) },
  sequence_filter: { name: 'sentinel', version: '1.0.0', weights_sha256: '0'.repeat(64) },
};

const biosecurity_policy = {
  pathogen_db_version: '2026-04',
  pathogen_db_hash: randHex(32),
  toxin_db_version: '2026-04',
  toxin_db_hash: randHex(32),
  t_pathogen: 30,
  t_toxin: 25,
  t_motif: 90,
  blacklist_motif_patterns: [],
};

// 4 candidates — different shape from A (1), B (2), C (3)
const candidates = [
  {
    sequence: 'GIGAVLKVLTTGLPALISWIK',
    tier: 'green',
    metadata: { predicted_affinity_kcal_mol: -8.5, structure_confidence: 0.82 },
  },
  {
    sequence: 'KLAKLAKKLAKLAKKL',
    tier: 'amber',
    metadata: { predicted_affinity_kcal_mol: -7.3, structure_confidence: 0.74 },
  },
  {
    sequence: 'CYIQNCPLGGGRPRPRP',
    tier: 'green',
    metadata: { predicted_affinity_kcal_mol: -9.2, structure_confidence: 0.88 },
  },
  {
    sequence: 'RGRGRGRGRGRGRG',
    tier: 'red',
    metadata: { predicted_affinity_kcal_mol: -6.1, structure_confidence: 0.65 },
  },
];

const tier_distribution = {
  green_count: candidates.filter((c) => c.tier === 'green').length,
  amber_count: candidates.filter((c) => c.tier === 'amber').length,
  red_count: candidates.filter((c) => c.tier === 'red').length,
  black_count: 0,
  total_count: candidates.length,
};

console.log(`  Candidates:        ${candidates.length} (vectors A/B/C have 1/2/3)`);
console.log(`  Tier distribution: green=${tier_distribution.green_count}, amber=${tier_distribution.amber_count}, red=${tier_distribution.red_count}, black=${tier_distribution.black_count}`);
console.log('');

// ─────────────────────────────────────────────────────────────────────────────
// 2. Per-candidate commitments: salt + sequence hash + metadata hash + leaf
// ─────────────────────────────────────────────────────────────────────────────

step(1, 7, 'Generating per-candidate commitments + Merkle leaves');

const commitments = [];
const leaves = [];
const reveal_metadata_json = [];

for (const c of candidates) {
  const metaJson = JSON.stringify(c.metadata);
  reveal_metadata_json.push(metaJson);

  const salt_hex = randHex(32);
  const candidate_id = uuidv4();
  const canonical_sequence_hash = bytesToHex(await pdaSha256(utf8(c.sequence)));
  const metadata_hash = await computeCandidateMetadataHash(metaJson);
  const leaf = await computeCandidateCommitLeaf(salt_hex, c.sequence, metaJson);

  commitments.push({
    candidate_id,
    salt_hex,
    canonical_sequence_hash,
    metadata_hash,
    leaf_hex: bytesToHex(leaf),
  });
  leaves.push(leaf);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Merkle root over candidate leaves
// ─────────────────────────────────────────────────────────────────────────────

step(2, 7, 'Building Merkle root over candidate leaves');
const candidate_commit_root = await pdaMerkleRoot(leaves);
const candidate_commit_root_hex = bytesToHex(candidate_commit_root);

// ─────────────────────────────────────────────────────────────────────────────
// 4. Component hashes (5 of them: target, pipeline, biosec, tier, tee)
// ─────────────────────────────────────────────────────────────────────────────

step(3, 7, 'Computing 5 component hashes');

async function hashComponent(domain, payload) {
  const canonical = canonicalizePythonJSON(payload);
  return pdaComponentHash(domain, utf8(canonical));
}

const target_spec_hash = await hashComponent(PDA_DOMAIN_TARGET_SPEC, {
  target_pdb_hash: target_spec.target_pdb_hash,
  pocket_coordinates: target_spec.pocket_coordinates.map((c) => ({
    x_nm: c.x_nm,
    y_nm: c.y_nm,
    z_nm: c.z_nm,
  })),
  length_min: target_spec.length_min,
  length_max: target_spec.length_max,
  modifications_whitelist: [...target_spec.modifications_whitelist],
  scope: target_spec.scope,
});

const pipeline_manifest_hash = await hashComponent(PDA_DOMAIN_PIPELINE_MANIFEST, {
  backbone_model: { ...pipeline_manifest.backbone_model },
  sequence_model: { ...pipeline_manifest.sequence_model },
  structure_model: { ...pipeline_manifest.structure_model },
  sequence_filter: { ...pipeline_manifest.sequence_filter },
});

const biosecurity_policy_hash = await hashComponent(PDA_DOMAIN_BIOSECURITY_POLICY, {
  pathogen_db_version: biosecurity_policy.pathogen_db_version,
  pathogen_db_hash: biosecurity_policy.pathogen_db_hash,
  toxin_db_version: biosecurity_policy.toxin_db_version,
  toxin_db_hash: biosecurity_policy.toxin_db_hash,
  t_pathogen: biosecurity_policy.t_pathogen,
  t_toxin: biosecurity_policy.t_toxin,
  t_motif: biosecurity_policy.t_motif,
  blacklist_motif_patterns: [...biosecurity_policy.blacklist_motif_patterns],
});

const tier_distribution_hash = await hashComponent(PDA_DOMAIN_TIER_DIST, {
  green_count: tier_distribution.green_count,
  amber_count: tier_distribution.amber_count,
  red_count: tier_distribution.red_count,
  black_count: tier_distribution.black_count,
  total_count: tier_distribution.total_count,
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. TEE simulator attestation: build transcript, sign with public key
// ─────────────────────────────────────────────────────────────────────────────

step(4, 7, 'Building TEE simulator attestation (HMAC-SHA256 over transcript)');

const nonce_hex = randHex(32);
const nonce_bytes = hexToBytes(nonce_hex);
const measurement_hex = PDA_SIMULATOR_MEASUREMENT_HEX;
const tee_measurement_bytes = hexToBytes(measurement_hex);

// Transcript = DOMAIN_TEE || u32be(version) || ts_hash || pm_hash || bp_hash || commit_root || td_hash
const transcript_parts = [
  utf8(PDA_DOMAIN_TEE_ATTESTATION),
  pdaU32BE(PDA_SCHEMA_VERSION_V1),
  target_spec_hash,
  pipeline_manifest_hash,
  biosecurity_policy_hash,
  candidate_commit_root,
  tier_distribution_hash,
];
const transcript_total = transcript_parts.reduce((acc, p) => acc + p.length, 0);
const transcript = new Uint8Array(transcript_total);
{
  let off = 0;
  for (const p of transcript_parts) {
    transcript.set(p, off);
    off += p.length;
  }
}
const transcript_with_nonce = new Uint8Array(transcript.length + nonce_bytes.length);
transcript_with_nonce.set(transcript, 0);
transcript_with_nonce.set(nonce_bytes, transcript.length);

const simulator_key = hexToBytes(PDA_SIMULATOR_SIGNING_KEY_HEX);
const signature = await pdaHmacSha256(simulator_key, transcript_with_nonce);

const tee_attestation = {
  tee_type: 'simulator',
  measurement_hex,
  signature_hex: bytesToHex(signature),
  nonce_hex,
};

// ─────────────────────────────────────────────────────────────────────────────
// 6. TEE attestation hash + outer PDA fold
// ─────────────────────────────────────────────────────────────────────────────

step(5, 7, 'Folding the outer 32-byte PDA');

const tee_attestation_hash = await hashComponent(PDA_DOMAIN_TEE_ATTESTATION, {
  tee_type: tee_attestation.tee_type,
  measurement_hex: tee_attestation.measurement_hex,
  signature_hex: tee_attestation.signature_hex,
  nonce_hex: tee_attestation.nonce_hex,
});

const pda_bytes = await pdaSha256(
  PDA_DOMAIN_SEPARATOR,
  pdaU32BE(PDA_SCHEMA_VERSION_V1),
  target_spec_hash,
  pipeline_manifest_hash,
  biosecurity_policy_hash,
  candidate_commit_root,
  tier_distribution_hash,
  tee_measurement_bytes,
  tee_attestation_hash,
);
const pda_hex = bytesToHex(pda_bytes);

// ─────────────────────────────────────────────────────────────────────────────
// 7. Assemble PDAOutput, write to disk, run public verifier
// ─────────────────────────────────────────────────────────────────────────────

const pdaOutput = {
  pda_hex,
  schema_version: PDA_SCHEMA_VERSION_V1,
  tee_attestation,
  pipeline_manifest,
  biosecurity_policy,
  target_spec,
  tier_distribution,
  candidate_commit_root_hex,
  merkle_leaves_hex: commitments.map((c) => c.leaf_hex),
};

writeFileSync('vector-fresh.json', JSON.stringify(pdaOutput, null, 2), 'utf8');

step(6, 7, 'Running verifyPDA against the brand-new PDAOutput');
const report = await verifyPDA(pdaOutput, { acceptSimulator: true });
if (!report.passed) {
  console.error('FAIL — verifyPDA rejected:', report.blocked_reasons);
  process.exit(1);
}
for (const [k, v] of Object.entries(report.verified_fields)) {
  console.log(`        ${v ? '[ok]' : '[!!]'}  ${k}`);
}

step(7, 7, 'Running per-candidate reveal verification');
let revealPass = 0;
for (let i = 0; i < commitments.length; i++) {
  const c = commitments[i];
  const proofPath = await pdaGenerateInclusionProof(leaves, i);
  const proofPathWire = proofPath.map(([sibling, side]) => ({
    sibling_hex: bytesToHex(sibling),
    side,
  }));
  const ok = await verifyCandidateReveal({
    pdaOutput,
    commitment: {
      candidate_id: c.candidate_id,
      salt_hex: c.salt_hex,
      canonical_sequence_hash: c.canonical_sequence_hash,
      metadata_hash: c.metadata_hash,
    },
    revealedSequence: candidates[i].sequence,
    revealedMetadataJSON: reveal_metadata_json[i],
    inclusionProof: {
      leaf_index: i,
      leaf_hash_hex: c.leaf_hex,
      path: proofPathWire,
    },
  });
  if (!ok) {
    console.error(`FAIL — candidate ${i} reveal rejected`);
    process.exit(1);
  }
  revealPass++;
  console.log(`        [PASS] candidate ${i} (sequence=${candidates[i].sequence.slice(0, 12)}...) reveal verifies`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Done.
// ─────────────────────────────────────────────────────────────────────────────

console.log('');
console.log('═'.repeat(72));
console.log('  RESULT: brand-new PDA run, generated and verified end-to-end.');
console.log('═'.repeat(72));
console.log(`  Fresh PDA hex:     ${pda_hex}`);
console.log(`  Candidates:        ${candidates.length}`);
console.log(`  Reveal verifies:   ${revealPass}/${commitments.length}`);
console.log(`  verifyPDA:         PASS (every component re-derives, every check matches)`);
console.log(`  Output written:    ./vector-fresh.json`);
console.log('═'.repeat(72));
console.log('');
console.log('Try this:');
console.log('  - Modify any byte of vector-fresh.json and rerun verifyPDA.');
console.log('  - Pass { acceptSimulator: false } to verifyPDA — it refuses simulator attestations.');
console.log('  - Re-run this script — every run produces a different PDA hash because');
console.log('    salts and database hashes are freshly random.');
