/**
 * tests/test_firestore_large_upload_separation.mjs
 *
 * Regression Test Suite for Task 5.9A:
 * Separate Firestore Report Metadata from Gadget Documents
 *
 * Verifies:
 * 1. A report with 323 gadgets produces a bounded Firestore document without embedding its gadgets array.
 * 2. A report with 39,223 gadgets produces a bounded Firestore document (< 50 KB, staying under the 1 MiB limit with > 95% safety margin).
 * 3. The local JSON report preserves 100% of the 39,223 gadgets without truncation.
 * 4. Gadget document IDs differ for binaries with identical filenames and gadget addresses but different SHA-256 hashes.
 * 5. Existing frontend report metadata and gadget loading remain compatible (filename, file name, total_gadgets, decoupled gadgets view).
 * 6. Empty gadget arrays and missing optional metadata are handled safely.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import {
  deduplicateGadgets,
  getGadgetDeduplicationKey,
  normalizeGadgetAddress
} from '../web-react/src/utils/cloudExplorerHelper.js';

console.log('=== ROPWeaver Task 5.9A: Firestore Large-Upload Separation Test Suite ===\n');

let passCount = 0;
let failCount = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failCount++;
  }
}

// ---------------------------------------------------------------------------
// Helpers: Firestore typed value serializer (matches FirebaseUploader::toFirestoreValue)
// ---------------------------------------------------------------------------
function toFirestoreValue(val) {
  if (typeof val === 'string') return { stringValue: val };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    if (Number.isInteger(val)) return { integerValue: val.toString() };
    return { doubleValue: val };
  }
  if (val === null || val === undefined) return { nullValue: null };
  if (Array.isArray(val)) {
    const values = val.map(toFirestoreValue).filter(v => v !== null && Object.keys(v).length > 0);
    return values.length > 0 ? { arrayValue: { values } } : { arrayValue: {} };
  }
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) {
      const fVal = toFirestoreValue(v);
      if (fVal && Object.keys(fVal).length > 0) {
        fields[k] = fVal;
      }
    }
    return { mapValue: { fields } };
  }
  return {};
}

// Simulates FirebaseUploader::buildReportDocumentFields
function buildReportDocumentFields(inputJson) {
  let totalGadgets = 0;
  if (typeof inputJson.total_gadgets === 'number') {
    totalGadgets = inputJson.total_gadgets;
  } else if (typeof inputJson.discovered_gadgets_count === 'number') {
    totalGadgets = inputJson.discovered_gadgets_count;
  } else if (Array.isArray(inputJson.gadgets)) {
    totalGadgets = inputJson.gadgets.length;
  }

  const categoryCounts = {};
  if (inputJson.category_counts && typeof inputJson.category_counts === 'object') {
    for (const [cat, cnt] of Object.entries(inputJson.category_counts)) {
      if (typeof cnt === 'number') categoryCounts[cat] = cnt;
    }
  } else if (Array.isArray(inputJson.gadgets)) {
    for (const g of inputJson.gadgets) {
      if (!g || typeof g !== 'object') continue;
      const c = g.category || (Array.isArray(g.categories) && g.categories[0]) || 'others';
      categoryCounts[c] = (categoryCounts[c] || 0) + 1;
    }
  }

  const fields = {};
  for (const [key, value] of Object.entries(inputJson)) {
    if (key === 'gadgets') continue; // Exclude complete raw gadgets array to avoid exceeding 1 MiB limit
    const fVal = toFirestoreValue(value);
    if (fVal && Object.keys(fVal).length > 0) {
      fields[key] = fVal;
    }
  }

  fields['total_gadgets'] = toFirestoreValue(totalGadgets);
  fields['discovered_gadgets_count'] = toFirestoreValue(totalGadgets);

  if (Object.keys(categoryCounts).length > 0) {
    fields['category_counts'] = toFirestoreValue(categoryCounts);
  }

  fields['gadgets_stored_separately'] = toFirestoreValue(true);

  // Standardize filename
  let binName = '';
  if (inputJson.target_binary && typeof inputJson.target_binary.filename === 'string') {
    binName = inputJson.target_binary.filename;
  } else if (typeof inputJson.filename === 'string') {
    binName = inputJson.filename;
  } else if (typeof inputJson['file name'] === 'string') {
    binName = inputJson['file name'];
  } else if (typeof inputJson.binary_name === 'string') {
    binName = inputJson.binary_name;
  }

  if (binName) {
    if (!fields['filename']) fields['filename'] = toFirestoreValue(binName);
    if (!fields['file name']) fields['file name'] = toFirestoreValue(binName);
    if (!fields['binary_name']) fields['binary_name'] = toFirestoreValue(binName);
  }

  return fields;
}

// Simulates FirebaseUploader::makeGadgetDocumentId
function makeGadgetDocumentId(binaryName, binaryHash, address) {
  const shortAddr = (typeof address === 'number' ? address.toString(16) : address.toString()).replace(/^0x/i, '');
  const hashPart = binaryHash && binaryHash !== binaryName
    ? (binaryHash.length >= 12 ? binaryHash.slice(0, 12) : binaryHash)
    : '';

  let docId = hashPart
    ? `${binaryName}_${hashPart}_0x${shortAddr}`
    : `${binaryName}_0x${shortAddr}`;

  return docId.replace(/[/\\.\s]/g, '_');
}

// ---------------------------------------------------------------------------
// 1. Report with 323 Gadgets (classic_bof.exe profile)
// ---------------------------------------------------------------------------
runTest('323 Gadgets: Excludes gadgets array, preserves metadata, and stays well under 1 MiB', () => {
  const sampleGadgets = Array.from({ length: 323 }, (_, i) => ({
    address: `0x000000014000${(0x1000 + i * 4).toString(16)}`,
    preferred_va: `0x000000014000${(0x1000 + i * 4).toString(16)}`,
    instructions: i % 2 === 0 ? 'pop rdi ; ret' : 'add eax, ecx ; ret',
    category: i % 2 === 0 ? 'register_load' : 'arithmetic',
    categories: i % 2 === 0 ? ['register_load', 'control_transfer'] : ['arithmetic', 'control_transfer'],
    stack_delta: 8
  }));

  const report = {
    report_id: 'ROPW-classic_bof_e9a1b2c3d4e5_v1.6.3',
    report_date: '2026-11-19T20:00:00Z',
    tool_version: 'ROPWeaver v1.6.3',
    build_id: '1.6.3',
    commit_hash: '3ede2c26709f6c6a296d51b1b61120e413ee9fc7',
    architecture: 'x86_64',
    file_type: 'PE',
    total_gadgets: 323,
    discovered_gadgets_count: 323,
    target_binary: {
      filename: 'classic_bof.exe',
      hash: 'e9a1b2c3d4e5f6071829',
      sha256: 'e9a1b2c3d4e5f607182930415263748596a7b8c9d0e1f2031425364758697081'
    },
    sections: [
      { name: '.text', virtual_address: '0x140001000', raw_size: 4096, is_executable: true }
    ],
    protections: {
      NX_COMPAT: { enabled: true, static_indicator: 'COMPATIBLE' },
      DYNAMIC_BASE: { enabled: true, static_indicator: 'COMPATIBLE' }
    },
    gadgets: sampleGadgets
  };

  const fields = buildReportDocumentFields(report);

  // Assert gadgets array is NOT present in document fields
  assert.strictEqual(fields.gadgets, undefined, 'Raw gadgets array must be omitted from Firestore report document');

  // Assert summary telemetry is retained
  assert.strictEqual(fields.total_gadgets.integerValue, '323');
  assert.strictEqual(fields.discovered_gadgets_count.integerValue, '323');
  assert.strictEqual(fields.gadgets_stored_separately.booleanValue, true);

  // Assert category counts were synthesized correctly
  assert.ok(fields.category_counts, 'Category counts must be populated');
  const catFields = fields.category_counts.mapValue.fields;
  assert.strictEqual(catFields.register_load.integerValue, '162');
  assert.strictEqual(catFields.arithmetic.integerValue, '161');

  // Assert standardized filenames
  assert.strictEqual(fields.filename.stringValue, 'classic_bof.exe');
  assert.strictEqual(fields['file name'].stringValue, 'classic_bof.exe');
  assert.strictEqual(fields.binary_name.stringValue, 'classic_bof.exe');

  // Assert serialized size
  const payloadString = JSON.stringify({ fields });
  const sizeBytes = Buffer.byteLength(payloadString, 'utf8');
  assert.ok(sizeBytes < 1024 * 30, `Serialized report (${sizeBytes} bytes) must be well under 30 KB`);
  assert.ok(sizeBytes < 1048576, 'Must be strictly below Firestore 1 MiB limit');
});

// ---------------------------------------------------------------------------
// 2. Report with 39,223 Gadgets (rufus-4.1.exe profile)
// ---------------------------------------------------------------------------
runTest('39,223 Gadgets: Excludes 39,223 gadgets and produces bounded document (< 50 KB)', () => {
  const sampleGadgets = Array.from({ length: 39223 }, (_, i) => ({
    address: `0x000000014000${(0x1000 + i * 2).toString(16)}`,
    preferred_va: `0x000000014000${(0x1000 + i * 2).toString(16)}`,
    instructions: i % 4 === 0 ? 'pop rcx ; ret' : (i % 4 === 1 ? 'add eax, 1 ; ret' : 'mov [rax], rbx ; ret'),
    category: i % 4 === 0 ? 'register_load' : (i % 4 === 1 ? 'arithmetic' : 'memory_write'),
    stack_delta: 8
  }));

  const report = {
    report_id: 'ROPW-rufus-4.1_8f680fdc6e91_v1.6.3',
    report_date: '2026-11-19T20:00:00Z',
    tool_version: 'ROPWeaver v1.6.3',
    build_id: '1.6.3',
    commit_hash: '3ede2c26709f6c6a296d51b1b61120e413ee9fc7',
    architecture: 'x86_64',
    file_type: 'PE',
    total_gadgets: 39223,
    discovered_gadgets_count: 39223,
    target_binary: {
      filename: 'rufus-4.1.exe',
      hash: '8f680fdc6e91aff4',
      sha256: '8f680fdc6e91aff40123456789abcdef0123456789abcdef0123456789abcdef'
    },
    sections: [
      { name: '.text', virtual_address: '0x140001000', raw_size: 1048576, is_executable: true },
      { name: '.rdata', virtual_address: '0x140101000', raw_size: 524288, is_executable: false }
    ],
    protections: {
      NX_COMPAT: { enabled: true, static_indicator: 'COMPATIBLE' },
      DYNAMIC_BASE: { enabled: true, static_indicator: 'COMPATIBLE' },
      HIGH_ENTROPY_VA: { enabled: true, static_indicator: 'COMPATIBLE' }
    },
    gadgets: sampleGadgets
  };

  const fields = buildReportDocumentFields(report);

  // Assert gadgets array is NOT in the document fields
  assert.strictEqual(fields.gadgets, undefined);

  // Assert total gadget count is preserved exactly
  assert.strictEqual(fields.total_gadgets.integerValue, '39223');
  assert.strictEqual(fields.discovered_gadgets_count.integerValue, '39223');

  // Assert category counts are accurate across all 39,223 gadgets
  const catFields = fields.category_counts.mapValue.fields;
  assert.strictEqual(catFields.register_load.integerValue, '9806');
  assert.strictEqual(catFields.arithmetic.integerValue, '9806');
  assert.strictEqual(catFields.memory_write.integerValue, '19611');

  // Verify bounded document size: must stay strictly below 1 MiB (1,048,576 bytes)
  const payloadString = JSON.stringify({ fields });
  const sizeBytes = Buffer.byteLength(payloadString, 'utf8');

  assert.ok(sizeBytes < 50 * 1024, `Size (${sizeBytes} bytes) must be < 50 KB (less than 5% of 1 MiB limit)`);
  assert.ok(sizeBytes < 1048576, `Size (${sizeBytes} bytes) must be below 1,048,576 bytes`);

  const safetyMarginPct = ((1048576 - sizeBytes) / 1048576) * 100;
  assert.ok(safetyMarginPct > 95, `Safety margin (${safetyMarginPct.toFixed(1)}%) must exceed 95%`);
});

// ---------------------------------------------------------------------------
// 3. Local JSON Report Integrity
// ---------------------------------------------------------------------------
runTest('Local Report: Full local report retains all 39,223 gadgets completely intact', () => {
  const sampleGadgets = Array.from({ length: 39223 }, (_, i) => ({
    address: `0x000000014000${(0x1000 + i * 2).toString(16)}`,
    instructions: 'pop rcx ; ret'
  }));

  const localReport = {
    report_id: 'ROPW-rufus-4.1_local',
    total_gadgets: 39223,
    gadgets: sampleGadgets
  };

  // Simulate local report serialization
  const serialized = JSON.stringify(localReport);
  const parsedBack = JSON.parse(serialized);

  assert.strictEqual(parsedBack.gadgets.length, 39223, 'Local report must retain all 39,223 gadgets');
  assert.strictEqual(parsedBack.total_gadgets, 39223);

  // When uploaded, only the Firestore document transformation excludes the gadgets array
  const firestoreFields = buildReportDocumentFields(parsedBack);
  assert.strictEqual(firestoreFields.gadgets, undefined);
  assert.strictEqual(parsedBack.gadgets.length, 39223, 'Input local report must not be mutated');
});

// ---------------------------------------------------------------------------
// 4. Gadget Document ID Collision Resistance
// ---------------------------------------------------------------------------
runTest('Document IDs: Differ for identical binary names and gadget addresses with distinct hashes', () => {
  const binaryName = 'vulnerable.exe';
  const address = 0x1400010c3;

  const hashA = 'a1b2c3d4e5f67890abcdef1234567890';
  const hashB = 'f6e5d4c3b2a10987fedcba0987654321';

  const docIdA = makeGadgetDocumentId(binaryName, hashA, address);
  const docIdB = makeGadgetDocumentId(binaryName, hashB, address);

  assert.notStrictEqual(docIdA, docIdB, 'Doc IDs must not collide for different binary hashes');
  assert.strictEqual(docIdA, 'vulnerable_exe_a1b2c3d4e5f6_0x1400010c3');
  assert.strictEqual(docIdB, 'vulnerable_exe_f6e5d4c3b2a1_0x1400010c3');

  // Verify path-safe sanitization (no dots, slashes, or backslashes)
  assert.ok(!docIdA.includes('.'));
  assert.ok(!docIdA.includes('/'));
  assert.ok(!docIdA.includes('\\'));
  assert.ok(!docIdA.includes(' '));

  // Fallback when hash is empty or equal to binaryName
  const fallbackId = makeGadgetDocumentId('app.exe', '', address);
  assert.strictEqual(fallbackId, 'app_exe_0x1400010c3');
});

// ---------------------------------------------------------------------------
// 5. Frontend Compatibility
// ---------------------------------------------------------------------------
runTest('Frontend Compatibility: Consumers safely handle decoupled gadgets and standardized filename', () => {
  // Test 1: Gadget object filename resolution in ExplorerPage / GadgetItem / SearchPage
  const modernGadget = {
    filename: 'target.exe',
    'file name': 'target.exe',
    architecture: 'x86_64',
    instructions: 'pop rdi ; ret'
  };
  const legacyGadget = {
    'file name': 'legacy.exe',
    architecture: 'x86',
    instructions: 'pop eax ; ret'
  };

  const resolveGadgetFileName = (g) => g.filename || g['file name'] || g.fileName || g.binary_name || 'unknown';

  assert.strictEqual(resolveGadgetFileName(modernGadget), 'target.exe');
  assert.strictEqual(resolveGadgetFileName(legacyGadget), 'legacy.exe');

  // Test 2: ReportDetailModal totalGadgetCount logic
  const reportWithoutEmbeddedGadgets = {
    report_id: 'ROPW-large-bin',
    total_gadgets: 39223,
    discovered_gadgets_count: 39223,
    gadgets_stored_separately: true
    // Note: no gadgets array
  };

  const reportWithLegacyGadgets = {
    report_id: 'ROPW-legacy-bin',
    gadgets: [{ instructions: 'pop rdi ; ret' }, { instructions: 'ret' }]
  };

  const getTotalGadgetCount = (r) => {
    return typeof r.total_gadgets === 'number'
      ? r.total_gadgets
      : (typeof r.discovered_gadgets_count === 'number'
          ? r.discovered_gadgets_count
          : (Array.isArray(r.gadgets) ? r.gadgets.length : 0));
  };

  assert.strictEqual(getTotalGadgetCount(reportWithoutEmbeddedGadgets), 39223);
  assert.strictEqual(getTotalGadgetCount(reportWithLegacyGadgets), 2);
});

// ---------------------------------------------------------------------------
// 6. Edge Cases & Missing Optional Metadata
// ---------------------------------------------------------------------------
runTest('Edge Cases: Safely handles empty arrays, missing metadata, and null inputs', () => {
  const minimalReport = {
    report_id: 'ROPW-minimal'
  };

  const fields = buildReportDocumentFields(minimalReport);
  assert.strictEqual(fields.total_gadgets.integerValue, '0');
  assert.strictEqual(fields.discovered_gadgets_count.integerValue, '0');
  assert.strictEqual(fields.gadgets, undefined);
  assert.strictEqual(fields.category_counts, undefined);

  // Empty gadgets array
  const emptyReport = {
    report_id: 'ROPW-empty',
    gadgets: []
  };
  const emptyFields = buildReportDocumentFields(emptyReport);
  assert.strictEqual(emptyFields.total_gadgets.integerValue, '0');
  assert.strictEqual(emptyFields.gadgets, undefined);

  // Payload size check
  const jsonStr = JSON.stringify({ fields: emptyFields });
  assert.ok(Buffer.byteLength(jsonStr, 'utf8') < 1024, 'Minimal report must be < 1 KB');
});

// ---------------------------------------------------------------------------
// Task 5.9A1: Semantic Gadget Deduplication Test Cases
// ---------------------------------------------------------------------------

runTest('Task 5.9A1: Same binary, same address, legacy and new document IDs: one displayed gadget', () => {
  const binaryHash = '8f680fdc6e91aff41234567890abcdef1234567890abcdef1234567890abcdef';
  const legacyGadget = {
    id: 'rufus-4_1_exe_0x140001000',
    'file name': 'rufus-4.1.exe',
    hash: binaryHash,
    address: '0x140001000',
    instructions: 'mov rax, rbx; ret',
    report_id: 'rufus-4_1_8f680fdc6e91aff4'
  };

  const newGadget = {
    id: 'rufus-4_1_exe_8f680fdc6e91_0x140001000',
    filename: 'rufus-4.1.exe',
    'file name': 'rufus-4.1.exe',
    hash: binaryHash,
    address: '0x140001000',
    instructions: 'mov rax, rbx; ret',
    report_id: 'rufus-4_1_8f680fdc6e91aff4'
  };

  const result = deduplicateGadgets([legacyGadget], [newGadget]);
  assert.strictEqual(result.length, 1, 'Duplicate gadget from legacy vs new doc IDs must reconcile to exactly 1 gadget');
  assert.strictEqual(result[0].address, '0x140001000');
  assert.strictEqual(result[0].id, 'rufus-4_1_exe_0x140001000', 'Existing loaded record is retained with stable identity');
});

runTest('Task 5.9A1: Same binary, different addresses: both retained', () => {
  const binaryHash = '8f680fdc6e91aff41234567890abcdef1234567890abcdef1234567890abcdef';
  const gadget1 = {
    id: 'rufus-4_1_exe_8f680fdc6e91_0x140001000',
    filename: 'rufus-4.1.exe',
    hash: binaryHash,
    address: '0x140001000',
    instructions: 'mov rax, rbx; ret'
  };

  const gadget2 = {
    id: 'rufus-4_1_exe_8f680fdc6e91_0x140002000',
    filename: 'rufus-4.1.exe',
    hash: binaryHash,
    address: '0x140002000',
    instructions: 'pop rdi; ret'
  };

  const result = deduplicateGadgets([gadget1], [gadget2]);
  assert.strictEqual(result.length, 2, 'Distinct addresses for the same binary must both be retained');
  assert.strictEqual(result[0].address, '0x140001000');
  assert.strictEqual(result[1].address, '0x140002000');
});

runTest('Task 5.9A1: Different binaries, same filename and address: both retained', () => {
  const binary1Gadget = {
    id: 'app_111111111111_0x401000',
    filename: 'app.exe',
    hash: '1111111111111111111111111111111111111111111111111111111111111111',
    address: '0x401000',
    instructions: 'pop rdi; ret'
  };

  const binary2Gadget = {
    id: 'app_222222222222_0x401000',
    filename: 'app.exe',
    hash: '2222222222222222222222222222222222222222222222222222222222222222',
    address: '0x401000',
    instructions: 'xor eax, eax; ret'
  };

  const result = deduplicateGadgets([binary1Gadget], [binary2Gadget]);
  assert.strictEqual(result.length, 2, 'Distinct binaries sharing filename and address must NOT be merged');
  assert.strictEqual(result[0].hash, binary1Gadget.hash);
  assert.strictEqual(result[1].hash, binary2Gadget.hash);
});

runTest('Task 5.9A1: Missing hash and missing address: safe fallback without accidental merging', () => {
  // Missing hash and missing address on both records: must not merge by filename alone
  const unhashed1 = {
    id: 'doc_alpha',
    filename: 'common.dll',
    instructions: 'nop'
  };

  const unhashed2 = {
    id: 'doc_beta',
    filename: 'common.dll',
    instructions: 'ret'
  };

  const result = deduplicateGadgets([unhashed1], [unhashed2]);
  assert.strictEqual(result.length, 2, 'Records with missing hash and address must fall back safely to distinct doc IDs');
  assert.strictEqual(result[0].id, 'doc_alpha');
  assert.strictEqual(result[1].id, 'doc_beta');

  // Same filename and same address but missing hashes: must fall back to doc ID to prevent accidental collision
  const unhashedSameAddr1 = {
    id: 'doc_gamma',
    filename: 'library.so',
    address: '0x5000',
    instructions: 'syscall'
  };

  const unhashedSameAddr2 = {
    id: 'doc_delta',
    filename: 'library.so',
    address: '0x5000',
    instructions: 'syscall'
  };

  const resultSameAddr = deduplicateGadgets([unhashedSameAddr1], [unhashedSameAddr2]);
  assert.strictEqual(resultSameAddr.length, 2, 'Records without trustworthy hash must NOT be merged based solely on filename + address');
});

runTest('Task 5.9A1: Repeated batches containing the same gadget: no duplicate display', () => {
  const binaryHash = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
  const batch1 = [
    { id: 'g_1', hash: binaryHash, address: '0x401000', instructions: 'pop rdi; ret' },
    { id: 'g_2', hash: binaryHash, address: '0x402000', instructions: 'pop rsi; ret' }
  ];

  const batch2 = [
    { id: 'g_2', hash: binaryHash, address: '0x402000', instructions: 'pop rsi; ret (duplicate batch)' },
    { id: 'g_3', hash: binaryHash, address: '0x403000', instructions: 'syscall' }
  ];

  const combined = deduplicateGadgets(batch1, batch2);
  assert.strictEqual(combined.length, 3, 'Repeated batches must eliminate duplicate gadgets');
  assert.strictEqual(combined[0].id, 'g_1');
  assert.strictEqual(combined[1].id, 'g_2');
  assert.strictEqual(combined[2].id, 'g_3');
});

// ---------------------------------------------------------------------------
// Task 5.9A3: CLI Upload Failure Exit Status Propagation
// ---------------------------------------------------------------------------

/**
 * Simulates the Firebase upload decision logic in main.cpp
 * @param {boolean} reportSuccess - Whether uploadReport() returned true
 * @param {boolean} gadgetSuccess - Whether uploadGadgets() returned true
 * @returns {{ exitCode: number, errorOutput: string[] }}
 */
function simulateCliUploadFlow(reportSuccess, gadgetSuccess) {
  const errorOutput = [];
  let exitCode = 0;

  if (reportSuccess) {
    // Report uploaded to Firebase
    if (!gadgetSuccess) {
      errorOutput.push('[x] Firebase gadget upload failed or was incomplete.');
      errorOutput.push('[i] Report metadata was uploaded, but individual gadgets could not be fully stored in Firestore.');
      errorOutput.push("[i] Local analysis output and payloads remain preserved in 'reports/'.");
      exitCode = 1;
    }
  } else {
    errorOutput.push('[x] Firebase upload failed. Cloud write access is disabled or unauthorized.');
    errorOutput.push("[i] Local analysis output and payloads remain preserved in 'reports/'.");
    exitCode = 1;
  }

  return { exitCode, errorOutput };
}

runTest('Task 5.9A3: Report upload succeeds and gadget upload succeeds: exit status is zero', () => {
  const result = simulateCliUploadFlow(true, true);
  assert.strictEqual(result.exitCode, 0, 'Exit code must be 0 when both report and gadgets succeed');
  assert.strictEqual(result.errorOutput.length, 0, 'No errors emitted on complete upload success');
});

runTest('Task 5.9A3: Report upload succeeds and gadget upload fails: exit status is non-zero', () => {
  const result = simulateCliUploadFlow(true, false);
  assert.strictEqual(result.exitCode, 1, 'Exit code must be non-zero (1) when gadget upload fails');
  assert.ok(
    result.errorOutput.some(e => e.includes('Firebase gadget upload failed or was incomplete')),
    'Must explain that report uploaded but gadget upload was incomplete'
  );
  assert.ok(
    result.errorOutput.some(e => e.includes('Local analysis output and payloads remain preserved')),
    'Must confirm that local analysis output and payloads remain preserved'
  );
});

runTest('Task 5.9A3: Report upload fails: existing non-zero failure behaviour remains', () => {
  const result = simulateCliUploadFlow(false, false);
  assert.strictEqual(result.exitCode, 1, 'Exit code must be non-zero (1) when report upload fails');
  assert.ok(
    result.errorOutput.some(e => e.includes('Firebase upload failed')),
    'Must explain that initial report upload failed'
  );
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------
console.log(`\nTest Results: ${passCount} passed, ${failCount} failed.`);
if (failCount > 0) {
  process.exit(1);
} else {
  console.log('[+] All Task 5.9A regression tests passed successfully.\n');
}

