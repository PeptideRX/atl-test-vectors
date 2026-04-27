#!/usr/bin/env node
/**
 * verify.mjs — runs the published @peptiderx/atl-verifier against the
 * three frozen test vectors and confirms each one produces its
 * documented PDA hash.
 *
 * Usage:
 *   npm install
 *   node verify.mjs
 *
 * Exit codes:
 *   0  all three vectors passed
 *   1  one or more vectors failed
 *   2  setup or import error
 *
 * Status: EXPERIMENTAL. The protocol is under active development. Pin
 * exact versions when depending on either this script or the verifier.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Expected PDAs — frozen at protocol V1.
const EXPECTED = {
  'vector-a.json': '28dbab77f560665f9b374b7fb8b5c0dfe8c8ff6582cbd29f773241acfb3a640e',
  'vector-b.json': '4c261a1105a45c55fb0d2eb45d74542b7f70b78b27aa41999cfa444400051594',
  'vector-c.json': '1bc8afdfee1152521fa1d7a2e9e1019b9d199879ab921f7f5c4874e06d1861f4',
};

let verifyPDA;
try {
  ({ verifyPDA } = await import('@peptiderx/atl-verifier'));
} catch (err) {
  console.error('ERROR: failed to import @peptiderx/atl-verifier.');
  console.error('Run `npm install` first.');
  console.error('Underlying error:', err.message);
  process.exit(2);
}

let pass = 0;
let fail = 0;

for (const [filename, expectedPda] of Object.entries(EXPECTED)) {
  const path = resolve(__dirname, 'vectors', filename);
  const raw = await readFile(path, 'utf8');
  const output = JSON.parse(raw);

  const actualPda = output.pda_hex;
  const matches = actualPda === expectedPda;

  // Run the full cryptographic chain for each vector.
  const report = await verifyPDA(output, { acceptSimulator: true });

  const verdict = matches && report.passed ? 'PASS' : 'FAIL';
  if (verdict === 'PASS') pass++; else fail++;

  console.log(`[${verdict}] ${filename}`);
  console.log(`        expected: ${expectedPda}`);
  console.log(`        actual:   ${actualPda}`);
  console.log(`        chain:    ${report.passed ? 'verified' : 'rejected (' + (report.blocked_reasons || []).join(', ') + ')'}`);
}

console.log('');
console.log(`Result: ${pass} passed, ${fail} failed.`);
process.exit(fail === 0 ? 0 : 1);
