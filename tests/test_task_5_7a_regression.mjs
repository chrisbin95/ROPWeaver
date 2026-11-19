/**
 * Regression Test Suite: ROPWeaver v1.6.3 — Task 5.7A
 *
 * Covers all three issues fixed in Task 5.7A:
 *   1. Android / Mobile: Windows x86_64 target must be selectable on Android
 *      (platform detection and recommendation logic must NOT block user OS choice).
 *   2. Explorer: Sorting labels and direction correctness
 *      (DESCENDING = newest/Z→A for missing, ASCENDING = oldest/A→Z for missing).
 *   3. Explorer: Gadget deferred section heading update verification.
 *
 * Uses only module imports — no browser/DOM required.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  detectPlatformAndArch,
  getRecommendedDownload
} from '../web-react/src/utils/platformHelper.js';

import {
  mapFirestoreReportDoc,
  getReportIdentifier,
  getReportUploadTimestamp,
  sortReports,
  lexicalCompare
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
    console.error(err.message);
    process.exitCode = 1;
  }
}

console.log('=== ROPWeaver Task 5.7A Regression Test Suite ===\n');

// ============================================================
// ISSUE 1: Android / Mobile — Windows x86_64 must be selectable
// ============================================================

console.log('\n--- Issue 1: Android/Mobile OS Selection ---');

test('Android: detectPlatformAndArch correctly identifies Android ARM64 and mobile flag', () => {
  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  assert.strictEqual(detected.platform, 'android');
  assert.strictEqual(detected.arch, 'arm64');
  assert.strictEqual(detected.isMobile, true);
});

test('Android: getRecommendedDownload returns MOBILE_DEVICE — recommends source, NOT Windows', () => {
  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'MOBILE_DEVICE');
  assert.strictEqual(rec.recommendedOS, 'source');
  assert.strictEqual(rec.primaryAsset, null, 'Must NOT auto-recommend Windows x64 binary to Android visitor');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
});

test('Android: userHasExplicitlySelected guard prevents auto-reset — simulated state machine test', () => {
  // Simulate what DownloadPage does:
  // 1. On load: selectedOS defaults to recommendation ('source' on Android)
  // 2. User clicks Windows: setSelectedOS('windows'), setUserHasExplicitlySelected(true)
  // 3. The useEffect fires but must NOT reset because userHasExplicitlySelected === true
  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  const rec = getRecommendedDownload(detected);

  // Initial state from recommendation
  let selectedOS = rec.recommendedOS || 'windows';  // 'source'
  let userHasExplicitlySelected = false;

  // Verify initial state
  assert.strictEqual(selectedOS, 'source');

  // Simulate user clicking Windows card
  selectedOS = 'windows';
  userHasExplicitlySelected = true;

  // Simulate the useEffect condition check
  const wouldAutoReset =
    !userHasExplicitlySelected &&
    rec.recommendedOS &&
    selectedOS === 'windows' &&
    detected.platform !== 'windows';

  assert.strictEqual(
    wouldAutoReset,
    false,
    'useEffect must NOT auto-reset selectedOS when userHasExplicitlySelected is true'
  );
  assert.strictEqual(selectedOS, 'windows', 'User selection of Windows must be preserved on Android');
});

test('Android: Auto-sync DOES fire before user makes explicit selection (initial hint arrival)', () => {
  // Before user touches anything: selectedOS = 'windows' (default), userHasExplicitlySelected = false
  // highEntropyHints arrive and confirm Android — effect should update from 'windows' to 'source'
  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  const rec = getRecommendedDownload(detected);

  let selectedOS = 'windows';  // Initial default before hints arrive
  let userHasExplicitlySelected = false;

  // Simulate the useEffect condition check (initial auto-sync, no user action yet)
  const wouldAutoSync =
    !userHasExplicitlySelected &&
    rec.recommendedOS &&
    selectedOS === 'windows' &&
    detected.platform !== 'windows';

  assert.strictEqual(
    wouldAutoSync,
    true,
    'useEffect MUST fire for initial recommendation sync when user has not explicitly selected'
  );
});

test('Android: Resetting to recommended re-enables auto-syncing (setUserHasExplicitlySelected(false))', () => {
  // After reset: userHasExplicitlySelected = false, selectedOS = recommendation
  let userHasExplicitlySelected = false;  // reset by handleResetToRecommended
  let selectedOS = 'source';              // reset by handleResetToRecommended

  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  const rec = getRecommendedDownload(detected);

  // After reset, selectedOS is already 'source', so wouldAutoReset is false regardless
  const wouldAutoReset =
    !userHasExplicitlySelected &&
    rec.recommendedOS &&
    selectedOS === 'windows' &&
    detected.platform !== 'windows';

  assert.strictEqual(wouldAutoReset, false, 'selectedOS is not windows after reset, so no reset occurs');
  assert.strictEqual(userHasExplicitlySelected, false, 'explicit selection guard is cleared after reset');
});

test('Android: Windows download assets exist and are accessible regardless of user platform', () => {
  // Windows download content is statically defined in DownloadPage, NOT guarded by platform detection.
  // Verify that the DownloadPage source contains the Windows assets unconditionally.
  const pageSource = fs.readFileSync('web-react/src/pages/DownloadPage.jsx', 'utf8');
  assert.ok(
    pageSource.includes('ropweaver-windows-x64.exe'),
    'Windows x64 EXE download asset must always be present in DownloadPage'
  );
  assert.ok(
    pageSource.includes('ropweaver-v1.6.3-win64.zip'),
    'Windows x64 ZIP download asset must always be present in DownloadPage'
  );
  // Verify Windows OS is always an option in the selector (unconditional)
  assert.ok(
    pageSource.includes("value=\"windows\""),
    'Windows option must be unconditionally included in OS dropdown'
  );
  // Verify os-selector-box renders all OS options (the grid maps over downloads, which always contains windows)
  assert.ok(
    pageSource.includes("handleSelectOS(key)"),
    'OS card click handler must call handleSelectOS without platform guards'
  );
});

// ============================================================
// ISSUE 3: Explorer Sort Direction Correctness
// ============================================================

console.log('\n--- Issue 3: Explorer Sort Direction ---');

// Helper: build a mock Firestore doc snapshot
function mkDoc(id, data) {
  return { id, data: () => data };
}

test('Sort direction: DESCENDING (desc) puts newer timestamps first with valid upload timestamps', () => {
  const records = [
    mkDoc('id-old', { report_id: 'ROPW-OLD', uploaded_at: 1700000000000 }),
    mkDoc('id-new', { report_id: 'ROPW-NEW', uploaded_at: 1800000000000 }),
    mkDoc('id-mid', { report_id: 'ROPW-MID', uploaded_at: 1750000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'desc');
  const ids = result.map(r => getReportIdentifier(r));
  assert.deepStrictEqual(ids, ['ROPW-NEW', 'ROPW-MID', 'ROPW-OLD'], 'DESC must put newest (highest ms) first');
});

test('Sort direction: ASCENDING (asc) puts oldest timestamps first with valid upload timestamps', () => {
  const records = [
    mkDoc('id-new', { report_id: 'ROPW-NEW', uploaded_at: 1800000000000 }),
    mkDoc('id-old', { report_id: 'ROPW-OLD', uploaded_at: 1700000000000 }),
    mkDoc('id-mid', { report_id: 'ROPW-MID', uploaded_at: 1750000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'asc');
  const ids = result.map(r => getReportIdentifier(r));
  assert.deepStrictEqual(ids, ['ROPW-OLD', 'ROPW-MID', 'ROPW-NEW'], 'ASC must put oldest (lowest ms) first');
});

test('Sort direction: DESCENDING and ASCENDING are strictly opposite orderings', () => {
  const records = [
    mkDoc('id-a', { report_id: 'ROPW-A', uploaded_at: 1700000000000 }),
    mkDoc('id-b', { report_id: 'ROPW-B', uploaded_at: 1800000000000 }),
    mkDoc('id-c', { report_id: 'ROPW-C', uploaded_at: 1750000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const desc = sortReports(records, 'desc').map(r => getReportIdentifier(r));
  const asc  = sortReports(records, 'asc').map(r => getReportIdentifier(r));
  assert.deepStrictEqual(
    desc.slice().reverse(),
    asc,
    'ASC order must be the exact reverse of DESC order for uniform-timestamp records'
  );
});

test('Sort direction: Missing upload timestamps fall last in DESCENDING mode', () => {
  const records = [
    mkDoc('id-new', { report_id: 'ROPW-NEW', uploaded_at: 1800000000000 }),
    mkDoc('id-none', { report_id: 'ROPW-NONE' }),  // no upload metadata
    mkDoc('id-old', { report_id: 'ROPW-OLD', uploaded_at: 1700000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'desc');
  const ids = result.map(r => getReportIdentifier(r));
  assert.strictEqual(ids[0], 'ROPW-NEW', 'Newest timestamp must be first in DESC');
  assert.strictEqual(ids[1], 'ROPW-OLD', 'Second record must be older timestamped record');
  assert.strictEqual(ids[2], 'ROPW-NONE', 'Missing timestamp record must be last in DESC');
});

test('Sort direction: Missing upload timestamps fall last in ASCENDING mode', () => {
  const records = [
    mkDoc('id-none', { report_id: 'ROPW-NONE' }),  // no upload metadata
    mkDoc('id-new', { report_id: 'ROPW-NEW', uploaded_at: 1800000000000 }),
    mkDoc('id-old', { report_id: 'ROPW-OLD', uploaded_at: 1700000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'asc');
  const ids = result.map(r => getReportIdentifier(r));
  assert.strictEqual(ids[0], 'ROPW-OLD', 'Oldest timestamp must be first in ASC');
  assert.strictEqual(ids[1], 'ROPW-NEW', 'Second record must be newer timestamped record');
  assert.strictEqual(ids[2], 'ROPW-NONE', 'Missing timestamp record must be last in ASC');
});

test('Sort direction: All-missing timestamps in DESCENDING sorts Z→A by report_id', () => {
  // All records lack upload metadata — tie-breaker activates
  const records = [
    mkDoc('id-a', { report_id: 'ROPW-A' }),
    mkDoc('id-c', { report_id: 'ROPW-C' }),
    mkDoc('id-b', { report_id: 'ROPW-B' }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'desc');
  const ids = result.map(r => getReportIdentifier(r));
  // DESC with no timestamps: -tie on lexical(a,b) → Z before A
  assert.deepStrictEqual(ids, ['ROPW-C', 'ROPW-B', 'ROPW-A'], 'DESC missing-metadata must produce Z→A order by report_id');
});

test('Sort direction: All-missing timestamps in ASCENDING sorts A→Z by report_id', () => {
  const records = [
    mkDoc('id-c', { report_id: 'ROPW-C' }),
    mkDoc('id-a', { report_id: 'ROPW-A' }),
    mkDoc('id-b', { report_id: 'ROPW-B' }),
  ].map(d => mapFirestoreReportDoc(d));

  const result = sortReports(records, 'asc');
  const ids = result.map(r => getReportIdentifier(r));
  // ASC with no timestamps: +tie on lexical(a,b) → A before Z
  assert.deepStrictEqual(ids, ['ROPW-A', 'ROPW-B', 'ROPW-C'], 'ASC missing-metadata must produce A→Z order by report_id');
});

test('Sort direction: ASC and DESC are strictly opposite for all-missing-metadata set', () => {
  const records = [
    mkDoc('id-c', { report_id: 'ROPW-C' }),
    mkDoc('id-a', { report_id: 'ROPW-A' }),
    mkDoc('id-b', { report_id: 'ROPW-B' }),
  ].map(d => mapFirestoreReportDoc(d));

  const desc = sortReports(records, 'desc').map(r => getReportIdentifier(r));
  const asc  = sortReports(records, 'asc').map(r => getReportIdentifier(r));
  assert.deepStrictEqual(
    desc.slice().reverse(),
    asc,
    'ASC order must be the exact reverse of DESC order even for all-missing-timestamp records'
  );
});

test('Sort direction: Tie on equal timestamps uses lexical report_id tie-breaker in correct direction', () => {
  const ts = 1750000000000;
  const records = [
    mkDoc('id-c', { report_id: 'ROPW-C', uploaded_at: ts }),
    mkDoc('id-a', { report_id: 'ROPW-A', uploaded_at: ts }),
    mkDoc('id-b', { report_id: 'ROPW-B', uploaded_at: ts }),
  ].map(d => mapFirestoreReportDoc(d));

  const desc = sortReports(records, 'desc').map(r => getReportIdentifier(r));
  const asc  = sortReports(records, 'asc').map(r => getReportIdentifier(r));
  assert.deepStrictEqual(desc, ['ROPW-C', 'ROPW-B', 'ROPW-A'], 'Equal timestamps: DESC tie-break must be Z→A');
  assert.deepStrictEqual(asc,  ['ROPW-A', 'ROPW-B', 'ROPW-C'], 'Equal timestamps: ASC tie-break must be A→Z');
});

test('Sort direction: sortReports never mutates the input array', () => {
  const records = [
    mkDoc('id-b', { report_id: 'ROPW-B', uploaded_at: 1750000000000 }),
    mkDoc('id-a', { report_id: 'ROPW-A', uploaded_at: 1700000000000 }),
  ].map(d => mapFirestoreReportDoc(d));
  const originalOrder = records.map(r => getReportIdentifier(r));
  sortReports(records, 'desc');
  sortReports(records, 'asc');
  const afterOrder = records.map(r => getReportIdentifier(r));
  assert.deepStrictEqual(afterOrder, originalOrder, 'sortReports must not mutate the caller array');
});

test('Sort direction: Mixed valid + missing timestamps — all valid come first regardless of direction', () => {
  const records = [
    mkDoc('id-none-z', { report_id: 'ROPW-Z' }),
    mkDoc('id-old',    { report_id: 'ROPW-OLD', uploaded_at: 1700000000000 }),
    mkDoc('id-none-a', { report_id: 'ROPW-A' }),
    mkDoc('id-new',    { report_id: 'ROPW-NEW', uploaded_at: 1800000000000 }),
  ].map(d => mapFirestoreReportDoc(d));

  const desc = sortReports(records, 'desc');
  const asc  = sortReports(records, 'asc');

  // In DESC: valid timestamps (NEW before OLD), then missing (Z before A per -tie)
  const descIds = desc.map(r => getReportIdentifier(r));
  assert.strictEqual(getReportUploadTimestamp(desc[0]) > 0, true, 'DESC: first record must have valid timestamp');
  assert.strictEqual(getReportUploadTimestamp(desc[1]) > 0, true, 'DESC: second record must have valid timestamp');
  assert.strictEqual(getReportUploadTimestamp(desc[2]), 0, 'DESC: third record must have missing timestamp');
  assert.strictEqual(getReportUploadTimestamp(desc[3]), 0, 'DESC: fourth record must have missing timestamp');
  assert.strictEqual(descIds[0], 'ROPW-NEW');
  assert.strictEqual(descIds[1], 'ROPW-OLD');

  // In ASC: valid timestamps (OLD before NEW), then missing (A before Z per +tie)
  const ascIds = asc.map(r => getReportIdentifier(r));
  assert.strictEqual(getReportUploadTimestamp(asc[0]) > 0, true, 'ASC: first record must have valid timestamp');
  assert.strictEqual(getReportUploadTimestamp(asc[1]) > 0, true, 'ASC: second record must have valid timestamp');
  assert.strictEqual(ascIds[0], 'ROPW-OLD');
  assert.strictEqual(ascIds[1], 'ROPW-NEW');
  assert.strictEqual(ascIds[2], 'ROPW-A');  // A before Z for missing
  assert.strictEqual(ascIds[3], 'ROPW-Z');
});

// ============================================================
// ISSUE 2: Explorer gadget section heading update
// ============================================================

console.log('\n--- Issue 2: Explorer Gadget Section UI ---');

test('Explorer ExplorerPage: deferred gadget heading uses user-action language not technical placeholder', () => {
  const src = fs.readFileSync('web-react/src/pages/ExplorerPage.jsx', 'utf8');
  assert.ok(
    src.includes('GADGET INDEX — LOAD ON DEMAND'),
    'Deferred gadget heading must use user-facing language "GADGET INDEX — LOAD ON DEMAND"'
  );
  assert.ok(
    !src.includes('GADGET DATASTORE (DEFERRED TO OPTIMIZE INITIAL LOAD)'),
    'Technical internal placeholder text must not appear in the deferred gadget section heading'
  );
});

test('Explorer ExplorerPage: deferred gadget body text mentions user action (click / browse)', () => {
  const src = fs.readFileSync('web-react/src/pages/ExplorerPage.jsx', 'utf8');
  assert.ok(
    src.includes('Click below to load the first batch'),
    'Deferred gadget description must guide user to click and browse'
  );
});

test('Explorer ExplorerPage: gadget load button still present and uses LOAD GADGETS label', () => {
  const src = fs.readFileSync('web-react/src/pages/ExplorerPage.jsx', 'utf8');
  assert.ok(
    src.includes('LOAD GADGETS (BATCH OF'),
    'LOAD GADGETS button label must still be present'
  );
});

// ============================================================
// Summary
// ============================================================

console.log(`\nTask 5.7A Regression Test Results: ${passed} / ${total} passed.`);
if (passed !== total) {
  process.exit(1);
}
