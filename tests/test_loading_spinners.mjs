/**
 * ROPWeaver Loading Spinners & Indicators Test Suite
 *
 * Verifies Task 5.3C:
 * 1. [Helper Unit Test] LoadingSpinner props resolution and defaults
 * 2. [A11y Unit Test] role="status", aria-live="polite", and .sr-only accessible text
 * 3. [Visual & Theme Unit Test] Cyber sizes (sm, md, lg) and accent color variants
 * 4. [Contextual Label Unit Test] Preserves custom loading labels alongside spinner
 * 5. [Layout & Motion Unit Test] Card wrapping and reduced-motion CSS rules in App.css
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { getLoadingSpinnerProps } from '../web-react/src/utils/spinnerHelper.js';

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

console.log('=== ROPWeaver Loading Spinners & Indicators Test Suite ===\n');

// ---------------------------------------------------------------------------
// 1. [Helper Unit Test] LoadingSpinner default props
// ---------------------------------------------------------------------------
test('Spinner [Unit]: Default props resolve to medium green spinner', () => {
  const config = getLoadingSpinnerProps();
  assert.equal(config.role, 'status');
  assert.equal(config.ariaLive, 'polite');
  assert.ok(config.containerClasses.includes('size-md'));
  assert.ok(config.containerClasses.includes('color-green'));
  assert.ok(config.spinnerClasses.includes('size-md'));
  assert.ok(config.spinnerClasses.includes('color-green'));
  assert.equal(config.accessibleText, 'Loading content...');
});

// ---------------------------------------------------------------------------
// 2. [A11y Unit Test] Accessible announcements & labels
// ---------------------------------------------------------------------------
test('Spinner [A11y]: Features role="status", aria-live="polite", and .sr-only accessible announcement', () => {
  const config = getLoadingSpinnerProps({
    label: 'Querying Firestore...',
    srLabel: 'Fallback label'
  });

  assert.equal(config.role, 'status');
  assert.equal(config.ariaLive, 'polite');
  assert.equal(config.accessibleText, 'Querying Firestore...');
  assert.equal(config.hasLabel, true);
});

// ---------------------------------------------------------------------------
// 3. [Visual Unit Test] Size variants (sm, md, lg) and colors (green, cyan, orange, muted)
// ---------------------------------------------------------------------------
test('Spinner [Visual]: Supports button size (sm), section size (md), and page size (lg)', () => {
  const sm = getLoadingSpinnerProps({ size: 'sm', inline: true });
  assert.ok(sm.containerClasses.includes('size-sm'));
  assert.ok(sm.containerClasses.includes('is-inline'));

  const md = getLoadingSpinnerProps({ size: 'md', color: 'cyan' });
  assert.ok(md.containerClasses.includes('size-md'));
  assert.ok(md.containerClasses.includes('color-cyan'));

  const lg = getLoadingSpinnerProps({ size: 'lg', color: 'orange', center: true });
  assert.ok(lg.containerClasses.includes('size-lg'));
  assert.ok(lg.containerClasses.includes('color-orange'));
  assert.ok(lg.containerClasses.includes('is-centered'));

  const muted = getLoadingSpinnerProps({ color: 'muted' });
  assert.ok(muted.containerClasses.includes('color-muted'));
});

// ---------------------------------------------------------------------------
// 4. [Contextual Unit Test] Preserves custom loading labels alongside spinner
// ---------------------------------------------------------------------------
test('Spinner [Contextual]: Preserves custom labels across different operations', () => {
  const reportLoading = getLoadingSpinnerProps({ label: 'QUERYING CLOUD REPOSITORY (MAX 100 REPORTS)...' });
  assert.equal(reportLoading.accessibleText, 'QUERYING CLOUD REPOSITORY (MAX 100 REPORTS)...');

  const gadgetLoading = getLoadingSpinnerProps({ label: 'RETRIEVING NEXT 50 GADGETS...' });
  assert.equal(gadgetLoading.accessibleText, 'RETRIEVING NEXT 50 GADGETS...');

  const binaryAnalysis = getLoadingSpinnerProps({ label: 'Parsing binary headers & validating instruction sections...' });
  assert.equal(binaryAnalysis.accessibleText, 'Parsing binary headers & validating instruction sections...');
});

// ---------------------------------------------------------------------------
// 5. [CSS Audit] App.css contains cyber-spinner, .sr-only, and prefers-reduced-motion
// ---------------------------------------------------------------------------
test('CSS [Audit]: App.css contains .cyber-spinner definitions and prefers-reduced-motion rules', () => {
  const cssPath = path.resolve('web-react/src/App.css');
  const css = fs.readFileSync(cssPath, 'utf8');

  assert.ok(css.includes('.cyber-spinner'), 'App.css must define .cyber-spinner');
  assert.ok(css.includes('@keyframes cyberSpin'), 'App.css must define @keyframes cyberSpin');
  assert.ok(css.includes('.sr-only'), 'App.css must define .sr-only');
  assert.ok(css.includes('prefers-reduced-motion: reduce'), 'App.css must handle reduced-motion');
  assert.ok(css.includes('.loading-state-card'), 'App.css must define .loading-state-card with min-height');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\nTest Results: ${passed} passed, ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
}
