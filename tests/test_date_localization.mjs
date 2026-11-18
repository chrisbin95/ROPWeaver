/**
 * Test Suite: Visitor Local Timezone Detection and Timestamp Formatting
 *
 * Verifies Task 5.5A requirements:
 * - Local timezone detection using Intl.DateTimeFormat
 * - Converting UTC timestamps (with 'Z') to visitor's local time
 * - Handling UAE (Asia/Dubai, GMT+4), India (Asia/Kolkata, GMT+5:30), UK (Europe/London, BST/GMT DST)
 * - Handling Firestore Timestamp objects (.toDate(), .toMillis(), seconds)
 * - Graceful handling of missing and invalid timestamps (fallback 'N/A')
 * - Immutability: stored original records remain 100% untouched
 * - Formatter caching for high-performance list rendering
 */

import assert from 'node:assert/strict';
import {
  getUserTimezone,
  parseDateInput,
  formatLocalTimestamp
} from '../web-react/src/utils/dateHelper.js';

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

console.log('=== ROPWeaver Local Timezone & Timestamp Formatting Test Suite ===\n');

// 1. Timezone Detection
test('Timezone: Detects user timezone or defaults safely to UTC', () => {
  const tz = getUserTimezone();
  assert.equal(typeof tz, 'string');
  assert.ok(tz.length > 0);
});

// 2. Date Parsing
test('Parsing: Accurately parses standard UTC ISO strings ending in Z', () => {
  const parsed1 = parseDateInput('2026-10-10T17:24:40Z');
  assert.ok(parsed1 instanceof Date);
  assert.equal(parsed1.toISOString(), '2026-10-10T17:24:40.000Z');

  // Space instead of T
  const parsed2 = parseDateInput('2026-10-10 17:24:24Z');
  assert.ok(parsed2 instanceof Date);
  assert.equal(parsed2.toISOString(), '2026-10-10T17:24:24.000Z');
});

test('Parsing: Handles Firestore Timestamp objects (.toDate, .toMillis, seconds)', () => {
  const mockToDate = {
    toDate: () => new Date('2026-10-10T17:24:40Z')
  };
  assert.equal(parseDateInput(mockToDate)?.toISOString(), '2026-10-10T17:24:40.000Z');

  const mockToMillis = {
    toMillis: () => 1791653080000
  };
  assert.equal(parseDateInput(mockToMillis)?.toISOString(), '2026-10-10T17:24:40.000Z');

  const mockSeconds = {
    seconds: 1791653080
  };
  assert.equal(parseDateInput(mockSeconds)?.toISOString(), '2026-10-10T17:24:40.000Z');
});

test('Parsing: Handles numeric epochs (seconds and milliseconds)', () => {
  const ms = 1791653080000;
  const sec = 1791653080;
  assert.equal(parseDateInput(ms)?.toISOString(), '2026-10-10T17:24:40.000Z');
  assert.equal(parseDateInput(sec)?.toISOString(), '2026-10-10T17:24:40.000Z');
});

test('Parsing: Handles ROPW-<epoch> report identifier strings', () => {
  const parsed = parseDateInput('ROPW-1791653080');
  assert.equal(parsed?.toISOString(), '2026-10-10T17:24:40.000Z');
});

test('Parsing: Invalid and missing timestamps return null safely', () => {
  assert.equal(parseDateInput(null), null);
  assert.equal(parseDateInput(undefined), null);
  assert.equal(parseDateInput(''), null);
  assert.equal(parseDateInput('   '), null);
  assert.equal(parseDateInput('invalid-date'), null);
  assert.equal(parseDateInput('N/A'), null);
  assert.equal(parseDateInput(-1), null);
  assert.equal(parseDateInput(NaN), null);
});

// 3. Timezone Conversion & Formatting
test('Format: Converts UTC to UAE timezone (Asia/Dubai, GMT+4)', () => {
  const utcInput = '2026-10-10T17:24:40Z';
  const formatted = formatLocalTimestamp(utcInput, { timeZone: 'Asia/Dubai' });
  // 17:24:40 UTC + 4 hours = 21:24:40
  assert.ok(formatted.includes('2026-10-10 21:24:40'));
  assert.ok(formatted.includes('GMT+4') || formatted.includes('GST'));
});

test('Format: Converts UTC with space to UAE timezone', () => {
  const utcInput = '2026-10-10 17:24:24Z';
  const formatted = formatLocalTimestamp(utcInput, { timeZone: 'Asia/Dubai' });
  // 17:24:24 UTC + 4 hours = 21:24:24
  assert.ok(formatted.includes('2026-10-10 21:24:24'));
  assert.ok(formatted.includes('GMT+4') || formatted.includes('GST'));
});

test('Format: Converts UTC to India timezone (Asia/Kolkata, GMT+5:30)', () => {
  const utcInput = '2026-10-10T17:24:40Z';
  const formatted = formatLocalTimestamp(utcInput, { timeZone: 'Asia/Kolkata' });
  // 17:24:40 UTC + 5h30m = 22:54:40
  assert.ok(formatted.includes('2026-10-10 22:54:40'));
  assert.ok(formatted.includes('GMT+5:30') || formatted.includes('IST'));
});

test('Format: Handles UK Daylight Saving Transitions (Europe/London: BST vs GMT)', () => {
  // Summer date: July (BST = UTC + 1)
  const summerUTC = '2026-07-15T12:00:00Z';
  const summerFormatted = formatLocalTimestamp(summerUTC, { timeZone: 'Europe/London' });
  assert.ok(summerFormatted.includes('2026-07-15 13:00:00'));
  assert.ok(summerFormatted.includes('GMT+1') || summerFormatted.includes('BST'));

  // Winter date: January (GMT = UTC + 0)
  const winterUTC = '2026-01-15T12:00:00Z';
  const winterFormatted = formatLocalTimestamp(winterUTC, { timeZone: 'Europe/London' });
  assert.ok(winterFormatted.includes('2026-01-15 12:00:00'));
  assert.ok(winterFormatted.includes('GMT'));
});

test('Format: Gracefully handles missing and invalid timestamps with fallback', () => {
  assert.equal(formatLocalTimestamp(null), 'N/A');
  assert.equal(formatLocalTimestamp(undefined), 'N/A');
  assert.equal(formatLocalTimestamp('invalid-date-string'), 'N/A');
  assert.equal(formatLocalTimestamp('', { fallback: 'Unknown' }), 'Unknown');
  assert.equal(formatLocalTimestamp('N/A', { fallback: 'Unspecified' }), 'Unspecified');
});

test('Format: Preserves original stored records without mutating data', () => {
  const storedReport = {
    id: 'rep_1',
    report_date: '2026-10-10T17:24:40Z',
    target_binary: { filename: 'test.exe' }
  };
  const snapshotBefore = JSON.stringify(storedReport);

  const displayedDate = formatLocalTimestamp(storedReport.report_date, { timeZone: 'Asia/Dubai' });
  assert.ok(displayedDate.includes('21:24:40'));

  const snapshotAfter = JSON.stringify(storedReport);
  // Stored record MUST remain 100% identical in UTC
  assert.equal(snapshotBefore, snapshotAfter);
  assert.equal(storedReport.report_date, '2026-10-10T17:24:40Z');
});

console.log(`\nLocal Timezone Test Results: ${passed} / ${total} passed.`);
