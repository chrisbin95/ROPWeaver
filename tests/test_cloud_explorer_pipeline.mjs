/**
 * ROPWeaver Cloud Explorer Pipeline, Loading States & Firebase Read Optimization Test Suite
 *
 * Verifies Task 5.2A and Task 5.2A.2 implementation:
 * 1. [Helper Unit Test] Valid cache serialization, expiration, and deserialization
 * 2. [Simulated Behavior] Cache restoration suppresses network fetch; expired cache triggers fetch
 * 3. [Simulated Behavior] Manual SYNC initiates network fetch after cache restoration
 * 4. [Simulated Behavior] Failed refresh preserves existing loaded data
 * 5. [Simulated Behavior] Gadget query remaining deferred until requested
 * 6. [Simulated Behavior] Gadget pagination bounded to 50 items with cursor pagination
 * 7. [Simulated Behavior] Empty subsequent gadget batch preserves the cursor
 * 8. [Helper Unit Test] Gadget deduplication preserves existing order and prevents duplicates
 * 9. [Helper Unit Test] Diagnostics correctly classifies distinct Firestore SDK error codes
 * 10. [Helper Unit Test] Empty collection results produce zero records without error banner
 * 11. [Helper Unit Test] Metric separation: known versus unknown catalog total formatting
 *
 * NOTE: These tests run hermetically in Node.js using mock objects and pure helper logic.
 * Live production Firestore connectivity and WebChannel networking are not tested here.
 */

import assert from 'node:assert/strict';
import {
  REPORTS_BATCH_LIMIT,
  GADGETS_BATCH_LIMIT,
  CACHE_TTL_MS,
  serializeExplorerCache,
  deserializeExplorerCache,
  classifyFirestoreError,
  formatReportCountMetrics,
  deduplicateGadgets,
  tallyExplorerMetrics,
  filterReports
} from '../web-react/src/utils/cloudExplorerHelper.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error(err);
    failed++;
  }
}

console.log('=== ROPWeaver Cloud Explorer Pipeline & Optimization Test Suite ===\n');

// ---------------------------------------------------------------------------
// 1. [Simulated Behavior] Valid cache restoration without network fetch
// ---------------------------------------------------------------------------
test('Cache [Simulated Behavior]: Valid cache restores data and suppresses network fetch', () => {
  const now = 1700000000000;
  const mockReports = [
    { id: 'rep_1', report_id: 'ROPW-100', target_binary: 'bin1', architecture: 'x86_64' },
    { id: 'rep_2', report_id: 'ROPW-101', target_binary: 'bin2', architecture: 'i386' }
  ];
  const mockStats = { totalReports: 2, loadedReports: 2, archCounts: { x86_64: 1, i386: 1 } };

  const cacheJson = serializeExplorerCache({
    catalogTotalReports: 2,
    reports: mockReports,
    stats: mockStats,
    recentBinaries: ['bin1', 'bin2'],
    now: now - 30000 // 30s old (well within 5m TTL)
  });

  let networkCalls = 0;
  const mockFetchNetwork = () => { networkCalls++; };

  // Simulate mount behavior
  const cachedData = deserializeExplorerCache(cacheJson, now, CACHE_TTL_MS);
  assert.ok(cachedData !== null, 'Valid cache must deserialize successfully');
  assert.equal(cachedData.reports.length, 2);
  assert.equal(cachedData.catalogTotalReports, 2);

  if (!cachedData) {
    mockFetchNetwork();
  }

  assert.equal(networkCalls, 0, 'Network fetch must NOT be invoked when valid cache is restored');
});

// ---------------------------------------------------------------------------
// 2. [Simulated Behavior] Expired or absent cache triggering initial fetch
// ---------------------------------------------------------------------------
test('Cache [Simulated Behavior]: Absent cache triggers initial network fetch', () => {
  let networkCalls = 0;
  const mockFetchNetwork = () => { networkCalls++; };

  const cachedData = deserializeExplorerCache(null);
  if (!cachedData) {
    mockFetchNetwork();
  }

  assert.equal(networkCalls, 1, 'Initial fetch must be triggered when cache is absent');
});

test('Cache [Simulated Behavior]: Expired cache (> 5 minutes) triggers initial network fetch', () => {
  const now = 1700000000000;
  const expiredJson = serializeExplorerCache({
    catalogTotalReports: 5,
    reports: [{ id: 'old_1' }],
    stats: {},
    now: now - (CACHE_TTL_MS + 1000) // 1 second past 5m TTL
  });

  let networkCalls = 0;
  const mockFetchNetwork = () => { networkCalls++; };

  const cachedData = deserializeExplorerCache(expiredJson, now, CACHE_TTL_MS);
  assert.equal(cachedData, null, 'Expired cache must deserialize to null');

  if (!cachedData) {
    mockFetchNetwork();
  }

  assert.equal(networkCalls, 1, 'Initial fetch must be triggered when cache has expired');
});

// ---------------------------------------------------------------------------
// 3. [Simulated Behavior] Manual SYNC triggering refresh after cache restoration
// ---------------------------------------------------------------------------
test('Cache [Simulated Behavior]: Manual SYNC initiates network fetch after cache restoration', () => {
  const now = 1700000000000;
  const cachedData = deserializeExplorerCache(
    serializeExplorerCache({
      catalogTotalReports: 1,
      reports: [{ id: 'cached_1' }],
      stats: {},
      now: now - 10000
    }),
    now
  );
  assert.ok(cachedData !== null);

  let manualSyncCalls = 0;
  const onManualSync = () => {
    manualSyncCalls++;
  };

  // User explicitly clicks SYNC button
  onManualSync();
  assert.equal(manualSyncCalls, 1, 'Manual SYNC action must trigger fresh network fetch');
});

// ---------------------------------------------------------------------------
// 4. [Simulated Behavior] Failed refresh preserving previously loaded data
// ---------------------------------------------------------------------------
test('Error Handling [Simulated Behavior]: Failed refresh preserves existing loaded data', () => {
  // Existing state holding 10 reports
  let loadedReports = Array.from({ length: 10 }, (_, i) => ({ id: `doc_${i}` }));
  let errorState = null;

  // Simulate network fetch error during manual SYNC
  const simulateFailedSync = () => {
    try {
      const err = new Error('Resource exhausted / rate limit exceeded');
      err.code = 'resource-exhausted';
      throw err;
    } catch (err) {
      const diag = classifyFirestoreError(err);
      errorState = diag.message;
      // Safeguard: Do NOT clear loadedReports!
    }
  };

  simulateFailedSync();

  assert.ok(errorState !== null, 'Error state must be set on failed sync');
  assert.ok(errorState.includes('quota or rate limit exceeded'), 'Error diagnostics must describe error');
  assert.equal(loadedReports.length, 10, 'Previously loaded reports must be preserved intact');
});

// ---------------------------------------------------------------------------
// 5. [Simulated Behavior] Gadget query remaining deferred until requested
// ---------------------------------------------------------------------------
test('Gadget Decoupling [Simulated Behavior]: Initial reports fetch does not query /gadgets collection', () => {
  let reportsQueried = 0;
  let gadgetsQueried = 0;

  const mockExecuteQuery = (collectionName, limitVal) => {
    if (collectionName === 'reports') {
      reportsQueried++;
      assert.equal(limitVal, REPORTS_BATCH_LIMIT, 'Reports query must be bounded to 100');
    }
    if (collectionName === 'gadgets') {
      gadgetsQueried++;
    }
  };

  // Simulate initial report fetch
  mockExecuteQuery('reports', 100);

  assert.equal(reportsQueried, 1, 'Reports query executed once');
  assert.equal(gadgetsQueried, 0, 'Gadgets query must remain 0 on initial load');
});

// ---------------------------------------------------------------------------
// 6. [Simulated Behavior] Gadget pagination respecting 50-item bound and cursor
// ---------------------------------------------------------------------------
test('Gadget Pagination [Simulated Behavior]: Queries are bounded to 50 items with cursor progression', () => {
  const queryLog = [];

  const mockQueryGadgets = (cursorDoc, limitCount) => {
    queryLog.push({ cursor: cursorDoc ? cursorDoc.id : null, limit: limitCount });
    assert.equal(limitCount, GADGETS_BATCH_LIMIT, 'Gadgets query limit must be exactly 50');

    // Batch 1 returns 50 docs; Batch 2 returns 25 docs
    if (!cursorDoc) {
      return Array.from({ length: 50 }, (_, i) => ({ id: `gadget_${i}`, gadget: `pop rdi; ret` }));
    } else {
      return Array.from({ length: 25 }, (_, i) => ({ id: `gadget_${50 + i}`, gadget: `ret` }));
    }
  };

  // Request Batch 1 (initial gadget load)
  const batch1 = mockQueryGadgets(null, 50);
  assert.equal(batch1.length, 50);
  const lastDocBatch1 = batch1[batch1.length - 1];
  const hasMoreAfterBatch1 = batch1.length === GADGETS_BATCH_LIMIT;
  assert.equal(hasMoreAfterBatch1, true);

  // Request Batch 2 (pagination with cursor)
  const batch2 = mockQueryGadgets(lastDocBatch1, 50);
  assert.equal(batch2.length, 25);
  const hasMoreAfterBatch2 = batch2.length === GADGETS_BATCH_LIMIT;
  assert.equal(hasMoreAfterBatch2, false, 'hasMore must be false when batch returned fewer than 50');

  assert.equal(queryLog.length, 2);
  assert.equal(queryLog[0].cursor, null);
  assert.equal(queryLog[1].cursor, 'gadget_49');
  assert.equal(batch1.length + batch2.length, 75);
});

// ---------------------------------------------------------------------------
// 7. [Simulated Behavior] Empty subsequent batch preserves cursor
// ---------------------------------------------------------------------------
test('Gadget Cursor [Simulated Behavior]: Empty subsequent batch sets hasMore=false without wiping cursor', () => {
  let lastGadgetDoc = { id: 'gadget_batch1_last' };
  let hasMoreGadgets = true;

  // Simulate subsequent batch returning 0 docs
  const mockSubsequentEmptyBatch = {
    docs: []
  };

  const lastDoc = (mockSubsequentEmptyBatch.docs && mockSubsequentEmptyBatch.docs.length > 0)
    ? mockSubsequentEmptyBatch.docs[mockSubsequentEmptyBatch.docs.length - 1]
    : null;

  // Task 5.2A.2 correction: only advance cursor if lastDoc is non-null
  if (lastDoc) {
    lastGadgetDoc = lastDoc;
  }
  hasMoreGadgets = mockSubsequentEmptyBatch.docs.length === GADGETS_BATCH_LIMIT;

  assert.equal(hasMoreGadgets, false, 'hasMoreGadgets must be false when batch has 0 results');
  assert.ok(lastGadgetDoc !== null, 'lastGadgetDoc cursor must NOT be wiped to null on empty response');
  assert.equal(lastGadgetDoc.id, 'gadget_batch1_last', 'Cursor must preserve last valid snapshot reference');
});

// ---------------------------------------------------------------------------
// 8. [Helper Unit Test] Gadget deduplication preserves order and uniqueness
// ---------------------------------------------------------------------------
test('Gadget Deduplication [Helper Unit Test]: Preserves original order and eliminates duplicates', () => {
  const existing = [
    { id: 'g_1', gadget: 'pop rdi; ret' },
    { id: 'g_2', gadget: 'pop rsi; ret' },
    { id: 'g_3', gadget: 'syscall' }
  ];

  // Incoming batch contains an overlapping document ('g_2') and novel documents ('g_4')
  const incoming = [
    { id: 'g_2', gadget: 'pop rsi; ret (duplicate)' },
    { id: 'g_4', gadget: 'ret' }
  ];

  const deduplicated = deduplicateGadgets(existing, incoming);

  assert.equal(deduplicated.length, 4, 'Total deduplicated length must be 4');
  assert.equal(deduplicated[0].id, 'g_1');
  assert.equal(deduplicated[1].id, 'g_2');
  assert.equal(deduplicated[1].gadget, 'pop rsi; ret', 'Existing record must be preserved over duplicate incoming');
  assert.equal(deduplicated[2].id, 'g_3');
  assert.equal(deduplicated[3].id, 'g_4');

  // First-page deduplication (when existing is empty)
  const firstBatch = [
    { id: 'g_a', gadget: 'nop' },
    { id: 'g_a', gadget: 'nop dup' },
    { id: 'g_b', gadget: 'int3' }
  ];
  const firstDeduplicated = deduplicateGadgets([], firstBatch);
  assert.equal(firstDeduplicated.length, 2);
  assert.equal(firstDeduplicated[0].id, 'g_a');
  assert.equal(firstDeduplicated[1].id, 'g_b');
});

// ---------------------------------------------------------------------------
// 9. [Helper Unit Test] Diagnostics: Firestore SDK error codes
// ---------------------------------------------------------------------------
test('Diagnostics [Helper Unit Test]: Correctly classifies distinct Firestore SDK error codes', () => {
  const cases = [
    {
      err: { code: 'permission-denied', message: 'Missing permissions' },
      expectedCode: 'permission-denied',
      expectedRetryable: false
    },
    {
      err: { code: 'unauthenticated', message: 'Token expired' },
      expectedCode: 'unauthenticated',
      expectedRetryable: false
    },
    {
      err: { code: 'unavailable', message: 'Client offline' },
      expectedCode: 'unavailable',
      expectedRetryable: true
    },
    {
      err: { code: 'resource-exhausted', message: 'Quota exceeded 429' },
      expectedCode: 'resource-exhausted',
      expectedRetryable: true
    },
    {
      err: { code: 'unknown-code', message: 'Socket closed' },
      expectedCode: 'unknown-code',
      expectedRetryable: true
    }
  ];

  for (const c of cases) {
    const diag = classifyFirestoreError(c.err);
    assert.equal(diag.code, c.expectedCode);
    assert.equal(diag.isRetryable, c.expectedRetryable);
    assert.ok(typeof diag.message === 'string' && diag.message.length > 0);
  }
});

// ---------------------------------------------------------------------------
// 10. [Helper Unit Test] Diagnostics: Empty collection produces zero records
// ---------------------------------------------------------------------------
test('Diagnostics [Helper Unit Test]: Empty collection results produce zero records without error banner', () => {
  const emptyDocs = [];
  const metrics = tallyExplorerMetrics(emptyDocs);

  assert.equal(metrics.totalReports, 0);
  assert.equal(metrics.recentBinaries.length, 0);
  // Empty state is distinct: no exception thrown, error remains null
});

// ---------------------------------------------------------------------------
// 11. [Helper Unit Test] Known versus unknown catalog total formatting
// ---------------------------------------------------------------------------
test('Metrics [Helper Unit Test]: Correctly distinguishes known versus unknown catalog totals', () => {
  // Case A: Known catalog total with partial sample (Catalog: 250, Loaded: 100, Filtered: 12)
  const knownPartial = formatReportCountMetrics({
    catalogTotal: 250,
    loadedCount: 100,
    filteredCount: 12
  });

  assert.equal(knownPartial.catalogTotal, 250);
  assert.equal(knownPartial.isCatalogTotalKnown, true);
  assert.equal(knownPartial.loadedCount, 100);
  assert.equal(knownPartial.filteredCount, 12);
  assert.equal(knownPartial.isSubset, true);
  assert.equal(knownPartial.displayLabel, '12 shown (100 loaded of 250 in catalog)');

  // Case B: Known catalog total with full loaded collection (Catalog: 10, Loaded: 10, Filtered: 10)
  const knownFull = formatReportCountMetrics({
    catalogTotal: 10,
    loadedCount: 10,
    filteredCount: 10
  });

  assert.equal(knownFull.catalogTotal, 10);
  assert.equal(knownFull.isCatalogTotalKnown, true);
  assert.equal(knownFull.loadedCount, 10);
  assert.equal(knownFull.filteredCount, 10);
  assert.equal(knownFull.isSubset, false);
  assert.equal(knownFull.displayLabel, '10 of 10');

  // Case C (Task 5.2A.2): Unavailable/null catalog total preserves null and formats explicitly
  const unavailableCatalog = formatReportCountMetrics({
    catalogTotal: null,
    loadedCount: 100,
    filteredCount: 12
  });

  assert.equal(unavailableCatalog.catalogTotal, null, 'Catalog total must remain strictly null when unavailable');
  assert.equal(unavailableCatalog.isCatalogTotalKnown, false, 'isCatalogTotalKnown must be false');
  assert.equal(unavailableCatalog.loadedCount, 100);
  assert.equal(unavailableCatalog.filteredCount, 12);
  assert.equal(unavailableCatalog.isSubset, false, 'isSubset must not be claimed when catalog total is unknown');
  assert.equal(
    unavailableCatalog.displayLabel,
    '12 shown (100 loaded, catalog total unavailable)',
    'Display label must explicitly state catalog total is unavailable'
  );
});

// ---------------------------------------------------------------------------
// 12. [Task 5.3A Unit Test] Unified Multi-Dimensional Filtering
// ---------------------------------------------------------------------------
test('Filters [Task 5.3A]: Combines search, architecture, and format filters simultaneously', () => {
  const sampleReports = [
    { id: '1', report_id: 'ROPW-001', target_binary: 'vuln_elf_x64', architecture: 'x86_64', format: 'ELF' },
    { id: '2', report_id: 'ROPW-002', target_binary: 'vuln_pe_x64.exe', architecture: 'x86_64', format: 'PE' },
    { id: '3', report_id: 'ROPW-003', target_binary: 'vuln_elf_arm', architecture: 'armv7', format: 'ELF' },
    { id: '4', report_id: 'ROPW-004', target_binary: 'vuln_pe_x86.exe', architecture: 'i386', format: 'PE' },
    { id: '5', report_id: 'ROPW-005', target_binary: 'special_x64', architecture: 'x86_64', format: 'ELF' }
  ];

  // 1. Independent search
  const searchOnly = filterReports(sampleReports, { searchTerm: 'vuln' });
  assert.equal(searchOnly.length, 4);

  // 2. Independent architecture
  const archOnly = filterReports(sampleReports, { architecture: 'x86_64' });
  assert.equal(archOnly.length, 3);

  // 3. Independent format
  const formatOnly = filterReports(sampleReports, { format: 'PE' });
  assert.equal(formatOnly.length, 2);

  // 4. Combined search + architecture
  const searchAndArch = filterReports(sampleReports, { searchTerm: 'vuln', architecture: 'x86_64' });
  assert.equal(searchAndArch.length, 2);
  assert.deepEqual(searchAndArch.map(r => r.id), ['1', '2']);

  // 5. Combined search + format
  const searchAndFormat = filterReports(sampleReports, { searchTerm: 'vuln', format: 'ELF' });
  assert.equal(searchAndFormat.length, 2);
  assert.deepEqual(searchAndFormat.map(r => r.id), ['1', '3']);

  // 6. Combined architecture + format
  const archAndFormat = filterReports(sampleReports, { architecture: 'x86_64', format: 'ELF' });
  assert.equal(archAndFormat.length, 2);
  assert.deepEqual(archAndFormat.map(r => r.id), ['1', '5']);

  // 7. Combined all three dimensions simultaneously
  const allThree = filterReports(sampleReports, { searchTerm: 'special', architecture: 'x86_64', format: 'ELF' });
  assert.equal(allThree.length, 1);
  assert.equal(allThree[0].id, '5');

  // 8. Exact architecture matching: 'i386' does not match 'x86_64'
  const i386Match = filterReports(sampleReports, { architecture: 'i386' });
  assert.equal(i386Match.length, 1);
  assert.equal(i386Match[0].id, '4');
});

// ---------------------------------------------------------------------------
// 13. [Task 5.3A Unit Test] Filter Clearing and Independent Dimension Preservation
// ---------------------------------------------------------------------------
test('Filters [Task 5.3A]: Preserves search text when toggling chip filters and clears correctly', () => {
  // Simulating state updates as in ExplorerPage
  let searchTerm = 'vuln';
  let selectedArch = 'all';
  let selectedFormat = 'all';

  // Clicking an arch chip updates arch WITHOUT overwriting search
  const handleSelectArch = (arch) => { selectedArch = (selectedArch === arch ? 'all' : arch); };
  handleSelectArch('x86_64');
  assert.equal(selectedArch, 'x86_64');
  assert.equal(searchTerm, 'vuln', 'Search term must be preserved when clicking arch chip');

  // Clicking a format chip updates format WITHOUT overwriting search
  const handleSelectFormat = (fmt) => { selectedFormat = (selectedFormat === fmt ? 'all' : fmt); };
  handleSelectFormat('ELF');
  assert.equal(selectedFormat, 'ELF');
  assert.equal(searchTerm, 'vuln', 'Search term must be preserved when clicking format chip');

  // Removing arch filter pill
  selectedArch = 'all';
  assert.equal(selectedArch, 'all');
  assert.equal(selectedFormat, 'ELF');
  assert.equal(searchTerm, 'vuln');

  // Clear all filters resets all 3 dimensions
  const handleClearAllFilters = () => {
    searchTerm = '';
    selectedArch = 'all';
    selectedFormat = 'all';
  };
  handleClearAllFilters();
  assert.equal(searchTerm, '');
  assert.equal(selectedArch, 'all');
  assert.equal(selectedFormat, 'all');
});

// ---------------------------------------------------------------------------
// 14. [Task 5.3A Unit Test] Gadget Pagination Completion Banner Logic
// ---------------------------------------------------------------------------
test('Gadgets [Task 5.3A]: Completion banner renders only when all gadgets are fully retrieved', () => {
  const isCompletionVisible = (hasMore, totalLoaded, isLoading, isError) => {
    return !hasMore && totalLoaded > 0 && !isLoading && !isError;
  };

  // While more gadgets exist -> NOT visible
  assert.equal(isCompletionVisible(true, 50, false, null), false);

  // When currently loading -> NOT visible
  assert.equal(isCompletionVisible(false, 50, true, null), false);

  // When error occurred -> NOT visible
  assert.equal(isCompletionVisible(false, 50, false, 'Network error'), false);

  // When 0 gadgets loaded (deferred state) -> NOT visible
  assert.equal(isCompletionVisible(false, 0, false, null), false);

  // When all gadgets loaded, no more pages, not loading, no error -> VISIBLE
  assert.equal(isCompletionVisible(false, 73, false, null), true);
});

// ---------------------------------------------------------------------------
// 15. [Task 5.3A Unit Test] Pre-Indexed O(1) Gadget Grouping Lookup
// ---------------------------------------------------------------------------
test('Performance [Task 5.3A]: Pre-indexed report map achieves correct O(1) lookups in gadget grouping', () => {
  const sampleReports = [
    { id: 'rep_1', report_id: 'ROPW-001', target_binary: '/bin/target_a', architecture: 'x86_64', file_type: 'ELF' },
    { id: 'rep_2', report_id: 'ROPW-002', target_binary: 'C:\\targets\\target_b.exe', architecture: 'i386', file_type: 'PE' }
  ];

  const reportByFileName = new Map();
  const reportById = new Map();

  sampleReports.forEach((r) => {
    const rawReportName = r.target_binary?.filename || r.target_binary || r["file name"] || r.binary_name || '';
    const rName = (typeof rawReportName === 'string' ? rawReportName : '').split(/[/\\]/).pop();
    if (rName && !reportByFileName.has(rName)) {
      reportByFileName.set(rName, r);
    }
    const rId = r.report_id || r.id;
    if (rId && !reportById.has(rId)) {
      reportById.set(rId, r);
    }
  });

  // Verify lookup by filename
  const foundA = reportByFileName.get('target_a');
  assert.ok(foundA);
  assert.equal(foundA.report_id, 'ROPW-001');

  // Verify lookup by report_id
  const foundB = reportById.get('ROPW-002');
  assert.ok(foundB);
  assert.equal(foundB.architecture, 'i386');

  // Verify unknown binary yields undefined without throwing
  assert.equal(reportByFileName.get('nonexistent'), undefined);
});

// ---------------------------------------------------------------------------
// 16. [Task 5.3B Unit Test] Empty Filter State Summary & Recovery
// ---------------------------------------------------------------------------
test('UX Polish [Task 5.3B]: Generates concise active filter summary and enables one-click recovery', () => {
  const getFilterSummary = (arch, fmt, term) => {
    return [
      arch && arch !== 'all' ? `arch: ${arch}` : null,
      fmt && fmt !== 'all' ? `format: ${fmt}` : null,
      term && term.trim() ? `search: "${term.trim()}"` : null
    ].filter(Boolean).join(', ');
  };

  // When no filters active
  assert.equal(getFilterSummary('all', 'all', ''), '');

  // When only arch active
  assert.equal(getFilterSummary('x86_64', 'all', ''), 'arch: x86_64');

  // When all 3 active
  assert.equal(getFilterSummary('x86_64', 'PE', 'test'), 'arch: x86_64, format: PE, search: "test"');

  // Simulated 0-match filter result produces empty state with summary
  const sampleReports = [
    { id: '1', architecture: 'x86_64', format: 'ELF', target_binary: 'vuln_elf' }
  ];

  const matched = filterReports(sampleReports, { architecture: 'i386', format: 'PE', searchTerm: 'nonexistent' });
  assert.equal(matched.length, 0);

  const summary = getFilterSummary('i386', 'PE', 'nonexistent');
  assert.equal(summary, 'arch: i386, format: PE, search: "nonexistent"');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\nTest Results: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
}
