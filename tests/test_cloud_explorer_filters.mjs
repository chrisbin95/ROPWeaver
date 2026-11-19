/**
 * Test Suite: Cloud Explorer Helpers, Normalizers, Filters, and Deterministic Sorting
 *
 * Verifies Task 5.1A, 5.1A.1, and 5.1A.2 implementation:
 * - Deterministic timestamp resolution with multi-tier fallback
 * - Newest-first and oldest-first sorting with locale-independent lexical tie-breaking
 * - Strict binary-format normalization with conflict detection (PE, ELF, Mach-O, RAW, UNKNOWN)
 * - Architecture normalization: bare ARM -> unknown, explicit ARMv7 -> armv7, ARM64 -> arm64
 * - Safe Firestore document mapping preserving explicit firestore_id
 * - Distinct Firestore document ID vs payload id vs payload report_id
 * - Multi-dimensional filtering and immutability guarantees
 */

import assert from 'node:assert/strict';
import {
  lexicalCompare,
  mapFirestoreReportDoc,
  getFirestoreDocumentId,
  getPayloadReportId,
  getReportIdentifier,
  getReportUploadTimestamp,
  getReportTimestamp,
  sortReports,
  normalizeArchitecture,
  getReportArchitecture,
  normalizeReportFormat,
  matchesArchitecture,
  matchesFormat,
  filterReports,
  tallyExplorerMetrics
} from '../web-react/src/utils/cloudExplorerHelper.js';

let passed = 0;
let total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`[PASS] ${name}`);
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

console.log('=== ROPWeaver Cloud Explorer Helpers Test Suite ===\n');

// 1. Lexical Comparison & Document Identity Tests
test('Lexical: Code-point comparison is locale-independent and deterministic', () => {
  assert.equal(lexicalCompare('A', 'B'), -1);
  assert.equal(lexicalCompare('B', 'A'), 1);
  assert.equal(lexicalCompare('A', 'A'), 0);
  assert.equal(lexicalCompare('doc-10', 'doc-2'), -1); // '1' < '2' in standard lexical
  assert.equal(lexicalCompare('ROPW_test.exe', 'ROPW_test.so'), -1);
  assert.equal(lexicalCompare('ROPW-Alpha', 'ROPW-alpha'), -1); // 'A' (65) < 'a' (97)
  assert.equal(lexicalCompare('doc_1_1', 'doc_1.1'), 1); // '_' (95) > '.' (46)
});

test('Identity: mapFirestoreReportDoc preserves explicit firestore_id and payload id separately', () => {
  // Case A: Payload contains its own internal 'id' property
  const mockSnapWithId = {
    id: 'firestore_doc_999',
    data: () => ({
      id: 'payload_internal_uuid_456',
      report_id: 'ROPW-1791653080',
      tool_version: 'v1.6.3'
    })
  };

  const mappedA = mapFirestoreReportDoc(mockSnapWithId);
  assert.equal(mappedA.firestore_id, 'firestore_doc_999'); // Firestore document ID preserved!
  assert.equal(mappedA.id, 'payload_internal_uuid_456');     // Payload's own id preserved!
  assert.equal(mappedA.report_id, 'ROPW-1791653080');       // Payload report_id preserved!

  // Case B: Payload does not have its own 'id' property -> falls back to doc.id for UI compatibility
  const mockSnapWithoutId = {
    id: 'firestore_doc_888',
    data: () => ({
      report_id: 'ROPW-1791653080',
      target_binary: 'test.exe'
    })
  };

  const mappedB = mapFirestoreReportDoc(mockSnapWithoutId);
  assert.equal(mappedB.firestore_id, 'firestore_doc_888');
  assert.equal(mappedB.id, 'firestore_doc_888');
  assert.equal(mappedB.report_id, 'ROPW-1791653080');
});

test('Identity: Visible report_id takes priority in getReportIdentifier over internal IDs', () => {
  const report = {
    firestore_id: 'firestore_doc_unique_1',
    id: 'payload_local_id_2',
    report_id: 'ROPW-1791653080'
  };

  assert.equal(getFirestoreDocumentId(report), 'firestore_doc_unique_1');
  assert.equal(getPayloadReportId(report), 'ROPW-1791653080');
  assert.equal(report.id, 'payload_local_id_2');
  assert.equal(getReportIdentifier(report), 'ROPW-1791653080'); // Visible report_id prioritized
});

test('Identity: Missing report_id falls back to report.id, then firestore_id', () => {
  // Only payload id present
  const payloadOnly = { id: 'payload_only_id' };
  assert.equal(getReportIdentifier(payloadOnly), 'payload_only_id');

  // Only firestore_id present
  const firestoreOnly = { firestore_id: 'firestore_only_id' };
  assert.equal(getReportIdentifier(firestoreOnly), 'firestore_only_id');

  // Both present without report_id: id takes precedence
  const bothNoReportId = { id: 'local_id', firestore_id: 'doc_id' };
  assert.equal(getReportIdentifier(bothNoReportId), 'local_id');

  // Empty object
  assert.equal(getReportIdentifier({}), '');
});

test('Identity: Deterministic sorting uses visible report_id for tie-breaking', () => {
  // Equal timestamps: visible report_id 'ROPW-111' vs 'ROPW-999'
  const r1 = {
    firestore_id: 'doc-A',
    id: 'z-payload-id',
    report_id: 'ROPW-999',
    report_date: '2026-10-10T12:00:00Z'
  };
  const r2 = {
    firestore_id: 'doc-B',
    id: 'a-payload-id',
    report_id: 'ROPW-111',
    report_date: '2026-10-10T12:00:00Z'
  };

  // Ascending: ROPW-111 comes before ROPW-999
  const sortedAsc = sortReports([r1, r2], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.report_id), ['ROPW-111', 'ROPW-999']);

  // Descending: ROPW-999 comes before ROPW-111
  const sortedDesc = sortReports([r1, r2], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.report_id), ['ROPW-999', 'ROPW-111']);
});

// 2. Timestamp Resolution & Fallback Tests
test('Timestamp: Prefers valid report_date (ISO 8601 string)', () => {
  const rep = {
    report_date: '2026-10-10T17:24:40Z',
    timestamp: '2025-01-01T00:00:00Z',
    report_id: 'ROPW-1000000000'
  };
  const expected = Date.parse('2026-10-10T17:24:40Z');
  assert.equal(getReportTimestamp(rep), expected);
});

test('Timestamp: Falls back to timestamp when report_date is absent', () => {
  const rep = {
    timestamp: '2026-11-09T16:00:00Z',
    report_id: 'ROPW-1000000000'
  };
  const expected = Date.parse('2026-11-09T16:00:00Z');
  assert.equal(getReportTimestamp(rep), expected);
});

test('Timestamp: Handles Firestore Timestamp object with toMillis()', () => {
  const rep = {
    timestamp: {
      toMillis: () => 1791653080000
    }
  };
  assert.equal(getReportTimestamp(rep), 1791653080000);
});

test('Timestamp: Handles Firestore Timestamp object with toDate()', () => {
  const rep = {
    timestamp: {
      toDate: () => new Date('2026-11-09T12:00:00Z')
    }
  };
  assert.equal(getReportTimestamp(rep), Date.parse('2026-11-09T12:00:00Z'));
});

test('Timestamp: Handles Firestore Timestamp object with seconds / _seconds', () => {
  const rep1 = { timestamp: { seconds: 1791653080 } };
  const rep2 = { timestamp: { _seconds: 1791653080 } };
  assert.equal(getReportTimestamp(rep1), 1791653080000);
  assert.equal(getReportTimestamp(rep2), 1791653080000);
});

test('Timestamp: getReportUploadTimestamp strictly resolves genuine upload fields and returns 0 when absent without substituting report_date or timestamp', () => {
  // 1. Genuine uploaded_at takes precedence over report_date
  const repWithUploaded = { uploaded_at: '2026-10-20T14:30:00Z', report_date: '2026-10-10T12:00:00Z' };
  assert.equal(getReportUploadTimestamp(repWithUploaded), Date.parse('2026-10-20T14:30:00Z'));

  // 2. created_at is accepted as supported upload metadata
  const repWithCreated = { created_at: '2026-10-22T08:00:00Z' };
  assert.equal(getReportUploadTimestamp(repWithCreated), Date.parse('2026-10-22T08:00:00Z'));

  // 2b. upload_date and upload_time are accepted as supported upload metadata
  const repWithUploadDate = { upload_date: '2026-10-23T09:00:00Z' };
  assert.equal(getReportUploadTimestamp(repWithUploadDate), Date.parse('2026-10-23T09:00:00Z'));
  const repWithUploadTime = { upload_time: '2026-10-24T10:00:00Z' };
  assert.equal(getReportUploadTimestamp(repWithUploadTime), Date.parse('2026-10-24T10:00:00Z'));

  // 3. Missing upload metadata never falls back to report_date
  const repReportDateOnly = { report_date: '2026-10-10T12:00:00Z' };
  assert.equal(getReportUploadTimestamp(repReportDateOnly), 0);

  // 4. Missing upload metadata never falls back to timestamp or ROPW-<epoch>
  const repTimestampString = { timestamp: '2025-07-02T13:11:31Z' };
  assert.equal(getReportUploadTimestamp(repTimestampString), 0);
  const repTimestampObj = { timestamp: { seconds: 1751461891 } };
  assert.equal(getReportUploadTimestamp(repTimestampObj), 0);
  const repRopwId = { report_id: 'ROPW-1791653080' };
  assert.equal(getReportUploadTimestamp(repRopwId), 0);

  // Safely handles null, undefined, empty object
  assert.equal(getReportUploadTimestamp({}), 0);
  assert.equal(getReportUploadTimestamp(null), 0);
  assert.equal(getReportUploadTimestamp(undefined), 0);
});

test('Timestamp: getReportTimestamp prioritizes genuine upload timestamp over report_date when both are present', () => {
  const repBoth = {
    uploaded_at: '2026-10-25T16:00:00Z', // Genuine upload timestamp (newer)
    report_date: '2026-10-10T10:00:00Z'  // Execution timestamp (older)
  };
  // Must return uploaded_at, NOT report_date
  assert.equal(getReportTimestamp(repBoth), Date.parse('2026-10-25T16:00:00Z'));
});

test('Timestamp: Falls back to uploaded_at or created_at when date/timestamp absent', () => {
  const repUploaded = {
    uploaded_at: '2026-10-10 17:24:24Z'
  };
  assert.equal(getReportTimestamp(repUploaded), Date.parse('2026-10-10T17:24:24Z'));

  const repCreated = {
    created_at: '2026-10-10T15:00:00Z'
  };
  assert.equal(getReportTimestamp(repCreated), Date.parse('2026-10-10T15:00:00Z'));
});

test('Timestamp: Falls back to ROPW-<epoch> in report_id when date/timestamp absent', () => {
  const rep = {
    report_id: 'ROPW-1791653080'
  };
  assert.equal(getReportTimestamp(rep), 1791653080000);
});

test('Timestamp: Normalizes seconds vs milliseconds representations', () => {
  const repSec = { report_date: 1791653080 };
  const repMs = { report_date: 1791653080000 };
  assert.equal(getReportTimestamp(repSec), 1791653080000);
  assert.equal(getReportTimestamp(repMs), 1791653080000);
});

test('Timestamp: Handles invalid, missing, null, and malformed values safely with 0 fallback', () => {
  assert.equal(getReportTimestamp(null), 0);
  assert.equal(getReportTimestamp(undefined), 0);
  assert.equal(getReportTimestamp({}), 0);
  assert.equal(getReportTimestamp({ report_date: 'invalid_date_string' }), 0);
  assert.equal(getReportTimestamp({ report_date: null, timestamp: undefined }), 0);
  assert.equal(getReportTimestamp({ report_id: 'not_a_valid_id' }), 0);
  assert.equal(getReportTimestamp({ report_date: -500 }), 0);
});

// 3. Deterministic Sorting Tests
test('Sorting: Prioritizes genuine upload timestamp when upload and execution timestamps differ', () => {
  // Record A: older execution time (Oct 10), but newer upload time (Oct 20)
  const repA = {
    id: 'repA',
    report_date: '2026-10-10T12:00:00Z',
    uploaded_at: '2026-10-20T12:00:00Z'
  };
  // Record B: newer execution time (Oct 18), but older upload time (Oct 15)
  const repB = {
    id: 'repB',
    report_date: '2026-10-18T12:00:00Z',
    uploaded_at: '2026-10-15T12:00:00Z'
  };

  // Descending (newest upload first): repA (Oct 20) > repB (Oct 15)
  const sortedDesc = sortReports([repB, repA], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.id), ['repA', 'repB']);

  // Ascending (oldest upload first): repB (Oct 15) < repA (Oct 20)
  const sortedAsc = sortReports([repB, repA], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.id), ['repB', 'repA']);
});

test('Sorting: Newest-first orders descending by genuine upload timestamp', () => {
  const r1 = { id: 'r1', uploaded_at: '2026-10-10T10:00:00Z', report_date: '2026-10-12T12:00:00Z' };
  const r2 = { id: 'r2', uploaded_at: '2026-10-10T12:00:00Z', report_date: '2026-10-09T08:00:00Z' };
  const r3 = { id: 'r3', uploaded_at: '2026-10-10T08:00:00Z', report_date: '2026-10-15T15:00:00Z' };

  const sorted = sortReports([r1, r2, r3], 'desc');
  assert.deepEqual(sorted.map(r => r.id), ['r2', 'r1', 'r3']);
});

test('Sorting: Oldest-first orders ascending by genuine upload timestamp', () => {
  const r1 = { id: 'r1', uploaded_at: '2026-10-10T10:00:00Z', report_date: '2026-10-12T12:00:00Z' };
  const r2 = { id: 'r2', uploaded_at: '2026-10-10T12:00:00Z', report_date: '2026-10-09T08:00:00Z' };
  const r3 = { id: 'r3', uploaded_at: '2026-10-10T08:00:00Z', report_date: '2026-10-15T15:00:00Z' };

  const sorted = sortReports([r1, r2, r3], 'asc');
  assert.deepEqual(sorted.map(r => r.id), ['r3', 'r1', 'r2']);
});

test('Sorting: Equal timestamps break ties deterministically using code-point lexical order', () => {
  const rA = { id: 'doc-Alpha', uploaded_at: '2026-10-10T12:00:00Z' };
  const rB = { id: 'doc-alpha', uploaded_at: '2026-10-10T12:00:00Z' };
  const rC = { id: 'doc-beta_1', uploaded_at: '2026-10-10T12:00:00Z' };
  const rD = { id: 'doc-beta.2', uploaded_at: '2026-10-10T12:00:00Z' };

  // Ascending order: 'A' < 'a', '.' (46) < '_' (95)
  // 'doc-Alpha' < 'doc-alpha' < 'doc-beta.2' < 'doc-beta_1'
  const sortedAsc = sortReports([rC, rB, rD, rA], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.id), ['doc-Alpha', 'doc-alpha', 'doc-beta.2', 'doc-beta_1']);

  // Descending order: reverse tie-breaking
  const sortedDesc = sortReports([rC, rB, rD, rA], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.id), ['doc-beta_1', 'doc-beta.2', 'doc-alpha', 'doc-Alpha']);
});

test('Sorting: Missing timestamps remain last in both directions', () => {
  const rValid = { id: 'valid', uploaded_at: '2026-10-20T12:00:00Z' };
  // Missing upload metadata never falls back to report_date or timestamp
  const rMiss1 = { id: 'miss-b', report_date: '2026-11-01T12:00:00Z' };
  const rMiss2 = { id: 'miss-a', timestamp: '2025-07-02T13:11:31Z' };

  // Descending: valid record first, missing records last (tie-broken in reverse lexical order)
  const sortedDesc = sortReports([rMiss1, rValid, rMiss2], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.id), ['valid', 'miss-b', 'miss-a']);

  // Ascending: valid record first, missing records last (tie-broken in lexical order)
  const sortedAsc = sortReports([rMiss1, rValid, rMiss2], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.id), ['valid', 'miss-a', 'miss-b']);
});

test('Sorting: Samples with all missing upload metadata order deterministically by visible ID in both directions', () => {
  const r1 = { id: 'id-1', report_id: 'ROPW-Alpha', report_date: '2026-10-10T12:00:00Z' };
  const r2 = { id: 'id-2', report_id: 'ROPW-alpha', timestamp: '2025-01-01T00:00:00Z' };
  const r3 = { id: 'id-3', report_id: 'ROPW-beta', report_date: '2026-10-31T22:47:44Z' };

  // Ascending: deterministic lexical ID order ('ROPW-Alpha' < 'ROPW-alpha' < 'ROPW-beta')
  const sortedAsc = sortReports([r3, r1, r2], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.report_id), ['ROPW-Alpha', 'ROPW-alpha', 'ROPW-beta']);

  // Descending: reverse deterministic lexical ID order ('ROPW-beta' > 'ROPW-alpha' > 'ROPW-Alpha')
  const sortedDesc = sortReports([r3, r1, r2], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.report_id), ['ROPW-beta', 'ROPW-alpha', 'ROPW-Alpha']);
});

test('Sorting: Mixed valid and missing upload timestamps - valid first according to direction, missing at end', () => {
  const rValidNew = { id: 'rV1', report_id: 'ROPW-ValidNew', uploaded_at: '2026-10-25T12:00:00Z' };
  const rValidOld = { id: 'rV2', report_id: 'ROPW-ValidOld', uploaded_at: '2026-10-10T12:00:00Z' };
  const rMissA = { id: 'rM1', report_id: 'ROPW-MissA', report_date: '2026-10-31T22:47:44Z' };
  const rMissB = { id: 'rM2', report_id: 'ROPW-MissB', report_date: '2026-10-01T10:00:00Z' };

  // Descending (newest first): ValidNew, then ValidOld, then missing in reverse lexical order (MissB, MissA)
  const sortedDesc = sortReports([rMissB, rValidOld, rMissA, rValidNew], 'desc');
  assert.deepEqual(sortedDesc.map(r => r.report_id), ['ROPW-ValidNew', 'ROPW-ValidOld', 'ROPW-MissB', 'ROPW-MissA']);

  // Ascending (oldest first): ValidOld, then ValidNew, then missing in lexical order (MissA, MissB)
  const sortedAsc = sortReports([rMissB, rValidOld, rMissA, rValidNew], 'asc');
  assert.deepEqual(sortedAsc.map(r => r.report_id), ['ROPW-ValidOld', 'ROPW-ValidNew', 'ROPW-MissA', 'ROPW-MissB']);
});

test('Sorting: Stable deterministic behavior regardless of source records input arrival order', () => {
  const rA = { id: 'doc-A', report_id: 'ROPW-100', report_date: '2026-10-10T12:00:00Z' };
  const rB = { id: 'doc-B', report_id: 'ROPW-200', report_date: '2026-10-10T12:00:00Z' };
  const rC = { id: 'doc-C', report_id: 'ROPW-300', report_date: '2026-10-10T12:00:00Z' };

  // Permutation 1
  const sorted1 = sortReports([rC, rA, rB], 'asc');
  // Permutation 2
  const sorted2 = sortReports([rB, rC, rA], 'asc');
  // Permutation 3
  const sorted3 = sortReports([rA, rB, rC], 'asc');

  assert.deepEqual(sorted1.map(r => r.report_id), ['ROPW-100', 'ROPW-200', 'ROPW-300']);
  assert.deepEqual(sorted2.map(r => r.report_id), ['ROPW-100', 'ROPW-200', 'ROPW-300']);
  assert.deepEqual(sorted3.map(r => r.report_id), ['ROPW-100', 'ROPW-200', 'ROPW-300']);
});

test('Sorting: Filtering and direction toggling preserve deterministic ordering', () => {
  const r1 = { id: '1', report_id: 'ROPW-ELF-1', architecture: 'x86_64', file_type: 'ELF', report_date: '2026-10-10T12:00:00Z' };
  const r2 = { id: '2', report_id: 'ROPW-ELF-2', architecture: 'x86_64', file_type: 'ELF', report_date: '2026-10-31T22:47:44Z' };
  const r3 = { id: '3', report_id: 'ROPW-PE-1', architecture: 'i386', file_type: 'PE', report_date: '2026-10-10T12:00:00Z' };

  const all = [r2, r3, r1];
  const filtered = filterReports(all, { architecture: 'x86_64', format: 'all', searchTerm: '' });
  assert.equal(filtered.length, 2);

  // In descending: ROPW-ELF-2 comes before ROPW-ELF-1 by reverse lexical ID
  const desc = sortReports(filtered, 'desc');
  assert.deepEqual(desc.map(r => r.report_id), ['ROPW-ELF-2', 'ROPW-ELF-1']);

  // In ascending: ROPW-ELF-1 comes before ROPW-ELF-2 by lexical ID
  const asc = sortReports(filtered, 'asc');
  assert.deepEqual(asc.map(r => r.report_id), ['ROPW-ELF-1', 'ROPW-ELF-2']);
});

test('Sorting: Input array is not mutated', () => {
  const original = [{ id: 'b', uploaded_at: '2026-10-10T10:00:00Z' }, { id: 'a', uploaded_at: '2026-10-10T12:00:00Z' }];
  const copy = [...original];
  const sorted = sortReports(original, 'desc');
  assert.deepEqual(original, copy);
  assert.notEqual(sorted, original);
});

// 4. Binary Format Normalization & Conflict Tests
test('Format: Accurately classifies PE, ELF, Mach-O, RAW on unambiguous evidence', () => {
  assert.equal(normalizeReportFormat({ file_type: 'PE' }), 'PE');
  assert.equal(normalizeReportFormat({ format: 'Portable Executable (PE32+)' }), 'PE');
  assert.equal(normalizeReportFormat({ target_binary: { filename: 'exploit.exe' } }), 'PE');
  assert.equal(normalizeReportFormat({ protections: { NX_COMPAT: {} } }), 'PE');

  assert.equal(normalizeReportFormat({ file_type: 'ELF' }), 'ELF');
  assert.equal(normalizeReportFormat({ protections: { RELRO: {} } }), 'ELF');

  assert.equal(normalizeReportFormat({ file_type: 'Mach-O' }), 'Mach-O');
  assert.equal(normalizeReportFormat({ target_binary: { filename: 'libtarget.dylib' } }), 'Mach-O');
  assert.equal(normalizeReportFormat({ protections: { Code_Signature: {} } }), 'Mach-O');

  assert.equal(normalizeReportFormat({ file_type: 'RAW' }), 'RAW');
  assert.equal(normalizeReportFormat({ format: 'raw binary shellcode' }), 'RAW');
  assert.equal(normalizeReportFormat({ target_binary: { filename: 'payload.raw' } }), 'RAW');

  // Verify matchesFormat helper
  assert.equal(matchesFormat({ file_type: 'PE' }, 'PE'), true);
  assert.equal(matchesFormat({ file_type: 'PE' }, 'ELF'), false);
  assert.equal(matchesFormat({ file_type: 'PE' }, 'all'), true);
  assert.equal(matchesFormat({ file_type: 'ELF' }, 'ELF'), true);
  assert.equal(matchesFormat({ file_type: 'Mach-O' }, 'Mach-O'), true);
  assert.equal(matchesFormat({ file_type: 'RAW' }, 'RAW'), true);
});

test('Format: Explicit metadata takes precedence over filename extensions', () => {
  // Explicit PE metadata overrides .dylib or non-standard extension
  const peDylib = { file_type: 'PE', target_binary: { filename: 'binary.dylib' } };
  assert.equal(normalizeReportFormat(peDylib), 'PE');

  // Explicit ELF metadata overrides .exe extension
  const elfExe = { file_type: 'ELF', target_binary: { filename: 'linux_binary.exe' } };
  assert.equal(normalizeReportFormat(elfExe), 'ELF');
});

test('Format: Conflicting explicit metadata produces UNKNOWN', () => {
  // Conflicting explicit fields: file_type says PE, format says ELF
  const conflictingExplicit = {
    file_type: 'PE',
    format: 'ELF'
  };
  assert.equal(normalizeReportFormat(conflictingExplicit), 'UNKNOWN');

  // Conflicting explicit fields: binary_analysis format says Mach-O, file_type says RAW
  const conflictingAnalysis = {
    file_type: 'RAW',
    binary_analysis: { format: 'Mach-O' }
  };
  assert.equal(normalizeReportFormat(conflictingAnalysis), 'UNKNOWN');
});

test('Format: Conflicting indirect evidence produces UNKNOWN', () => {
  // Filename says .exe (PE), but protections schema contains ELF RELRO
  const conflictingIndirect = {
    target_binary: { filename: 'suspicious.exe' },
    protections: { RELRO: {} }
  };
  assert.equal(normalizeReportFormat(conflictingIndirect), 'UNKNOWN');

  // Protections schema has both PE (NX_COMPAT) and Mach-O (Stack_NX)
  const conflictingProts = {
    protections: { NX_COMPAT: {}, Stack_NX: {} }
  };
  assert.equal(normalizeReportFormat(conflictingProts), 'UNKNOWN');
});

test('Format: Insufficient or unsupported metadata produces UNKNOWN', () => {
  assert.equal(normalizeReportFormat({}), 'UNKNOWN');
  assert.equal(normalizeReportFormat(null), 'UNKNOWN');
  assert.equal(normalizeReportFormat({ file_type: 'a.out' }), 'UNKNOWN');
  assert.equal(normalizeReportFormat({ file_type: 'COFF' }), 'UNKNOWN');
  assert.equal(normalizeReportFormat({ target_binary: { filename: 'binary_without_ext' } }), 'UNKNOWN');
  assert.equal(normalizeReportFormat({ target_binary: { filename: 'readme.txt' } }), 'UNKNOWN');
});

// 5. Architecture Normalization & Matching Tests
test('Architecture: Bare ARM maps to unknown unless source explicitly establishes ARMv7', () => {
  // Generic bare ARM without explicit v7/v8 marker -> unknown
  assert.equal(normalizeArchitecture('arm'), 'unknown');
  assert.equal(normalizeArchitecture('ARM'), 'unknown');
  assert.equal(normalizeArchitecture('arm32'), 'unknown');
  assert.equal(normalizeArchitecture('arm-none-eabi'), 'unknown');
  assert.equal(normalizeArchitecture('armv6'), 'unknown');

  // Explicit ARMv7 -> armv7
  assert.equal(normalizeArchitecture('armv7'), 'armv7');
  assert.equal(normalizeArchitecture('ARMv7'), 'armv7');
  assert.equal(normalizeArchitecture('armv7l'), 'armv7');
  assert.equal(normalizeArchitecture('armhf'), 'armv7');
  assert.equal(normalizeArchitecture('armv7-a'), 'armv7');

  // 64-bit ARM -> arm64
  assert.equal(normalizeArchitecture('arm64'), 'arm64');
  assert.equal(normalizeArchitecture('aarch64'), 'arm64');
  assert.equal(normalizeArchitecture('ARM64-v8a'), 'arm64');
  assert.equal(normalizeArchitecture('armv8'), 'arm64');
});

test('Architecture: Normalizes x86_64, i386, and RISC-V consistently', () => {
  assert.equal(normalizeArchitecture('x86_64'), 'x86_64');
  assert.equal(normalizeArchitecture('AMD64'), 'x86_64');
  assert.equal(normalizeArchitecture('x64'), 'x86_64');
  assert.equal(normalizeArchitecture('x86-64'), 'x86_64');

  assert.equal(normalizeArchitecture('i386'), 'i386');
  assert.equal(normalizeArchitecture('i686'), 'i386');
  assert.equal(normalizeArchitecture('x86'), 'i386');
  assert.equal(normalizeArchitecture('ia32'), 'i386');

  assert.equal(normalizeArchitecture('riscv64'), 'riscv64');
  assert.equal(normalizeArchitecture('rv64'), 'riscv64');
  assert.equal(normalizeArchitecture('riscv32'), 'riscv32');
  assert.equal(normalizeArchitecture('unknown'), 'unknown');
  assert.equal(normalizeArchitecture(null), 'unknown');
});

test('Architecture: Strict matching prevents substring false positives (i386 does not match x86_64)', () => {
  const rep64 = { architecture: 'x86_64' };
  const rep32 = { architecture: 'i386' };
  const repBareArm = { architecture: 'arm' };

  assert.equal(matchesArchitecture(rep64, 'x86_64'), true);
  assert.equal(matchesArchitecture(rep64, 'i386'), false);
  assert.equal(matchesArchitecture(rep64, 'x86'), false);

  assert.equal(matchesArchitecture(rep32, 'i386'), true);
  assert.equal(matchesArchitecture(rep32, 'x86'), true);
  assert.equal(matchesArchitecture(rep32, 'x86_64'), false);

  assert.equal(matchesArchitecture(repBareArm, 'armv7'), false);
  assert.equal(matchesArchitecture(repBareArm, 'unknown'), true);

  // Verify getReportArchitecture helper across object structures
  assert.equal(getReportArchitecture(rep64), 'x86_64');
  assert.equal(getReportArchitecture(rep32), 'i386');
  assert.equal(getReportArchitecture(repBareArm), 'unknown');
  assert.equal(getReportArchitecture({ binary_analysis: { architecture: 'AMD64' } }), 'x86_64');
  assert.equal(getReportArchitecture({ target_binary: { architecture: 'armv7l' } }), 'armv7');
  assert.equal(getReportArchitecture(null), 'unknown');
});

test('Architecture: ARMv7 is not confused with AArch64/ARM64', () => {
  const repV7 = { architecture: 'armv7' };
  const rep64 = { architecture: 'arm64' };

  assert.equal(matchesArchitecture(repV7, 'armv7'), true);
  assert.equal(matchesArchitecture(repV7, 'arm64'), false);
  assert.equal(matchesArchitecture(rep64, 'arm64'), true);
  assert.equal(matchesArchitecture(rep64, 'armv7'), false);
});

// 6. Multi-dimensional Filtering & Metrics Tests
test('Filter: Applies architecture, format, and search independently and together', () => {
  const reports = [
    { id: '1', target_binary: 'bin1.exe', architecture: 'x86_64', file_type: 'PE' },
    { id: '2', target_binary: 'bin2', architecture: 'x86_64', file_type: 'ELF' },
    { id: '3', target_binary: 'bin3.exe', architecture: 'i386', file_type: 'PE' },
    { id: '4', target_binary: 'bin4', architecture: 'arm64', file_type: 'ELF' },
    { id: '5', target_binary: 'unknown_bin' }
  ];

  // No filter -> All 5 preserved
  assert.equal(filterReports(reports).length, 5);
  assert.equal(filterReports(reports, { architecture: 'all', format: 'all' }).length, 5);

  // Arch filter: x86_64 -> 2 items
  const x64 = filterReports(reports, { architecture: 'x86_64' });
  assert.deepEqual(x64.map(r => r.id), ['1', '2']);

  // Format filter: PE -> 2 items
  const pe = filterReports(reports, { format: 'PE' });
  assert.deepEqual(pe.map(r => r.id), ['1', '3']);

  // Combined: x86_64 AND PE -> 1 item
  const x64Pe = filterReports(reports, { architecture: 'x86_64', format: 'PE' });
  assert.deepEqual(x64Pe.map(r => r.id), ['1']);

  // Search term: 'bin2'
  const searchResult = filterReports(reports, { searchTerm: 'bin2' });
  assert.deepEqual(searchResult.map(r => r.id), ['2']);

  // Unknown metadata record is visible in unfiltered list
  assert.ok(filterReports(reports).some(r => r.id === '5'));
});

test('Filter: Input array is not mutated and handles empty arrays', () => {
  const empty = [];
  assert.deepEqual(filterReports(empty), []);
  assert.deepEqual(filterReports(null), []);

  const input = [{ id: '1', architecture: 'x86_64' }];
  const copy = [...input];
  filterReports(input, { architecture: 'x86_64' });
  assert.deepEqual(input, copy);
});

test('Metrics: Accurately tallies architecture and binary format counts', () => {
  const reports = [
    { target_binary: 'bin1.exe', architecture: 'x86_64', file_type: 'PE' },
    { target_binary: 'bin2.exe', architecture: 'x86_64', file_type: 'PE' },
    { target_binary: 'bin3', architecture: 'x86_64', file_type: 'ELF' },
    { target_binary: 'bin4', architecture: 'i386', file_type: 'ELF' },
    { target_binary: 'bin5', architecture: 'arm64', file_type: 'ELF' },
    { target_binary: 'shellcode.raw', architecture: 'riscv64', file_type: 'RAW' },
    { target_binary: 'arm_generic', architecture: 'arm', file_type: 'ELF' },
    { target_binary: 'legacy_bin' }
  ];

  const metrics = tallyExplorerMetrics(reports);

  assert.equal(metrics.totalReports, 8);
  assert.equal(metrics.archCounts.x86_64, 3);
  assert.equal(metrics.archCounts.i386, 1);
  assert.equal(metrics.archCounts.arm64, 1);
  assert.equal(metrics.archCounts.riscv64, 1);
  assert.equal(metrics.archCounts.unknown, 2);

  assert.equal(metrics.typeCounts.PE, 2);
  assert.equal(metrics.typeCounts.ELF, 4);
  assert.equal(metrics.typeCounts.RAW, 1);
  assert.equal(metrics.typeCounts.UNKNOWN, 1);
  assert.equal(metrics.typeCounts['Mach-O'], 0);

  assert.equal(metrics.recentBinaries.length, 8);
});

console.log(`\nResults: ${passed} / ${total} tests passed successfully.`);
if (passed !== total) {
  process.exit(1);
}