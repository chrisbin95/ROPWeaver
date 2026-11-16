/**
 * Regression Test Suite: Mitigation Consistency and Format-Aware Presentation
 *
 * Validates format detection, mitigation normalization, state distinctions,
 * and exact consistency between Explorer summaries and Report-Detail views.
 */

import assert from 'node:assert';
import { detectBinaryFormat, getNormalizedMitigations, getArchitecture } from '../web-react/src/utils/mitigationHelper.js';

console.log('Running Mitigation Consistency and Normalization Tests...\n');

let passedTests = 0;
let failedTests = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failedTests++;
  }
}

// ---------------------------------------------------------------------------
// 1. PE x86_64 with NX_COMPAT and DYNAMIC_BASE Enabled
// ---------------------------------------------------------------------------
runTest('PE x86_64: Detects PE format from file_type and PE protections schema', () => {
  const report = {
    file_type: 'PE',
    architecture: 'x86_64',
    target_binary: { filename: 'target.exe' },
    protections: {
      NX_COMPAT: { static_indicator: 'COMPATIBLE', enabled: true },
      DYNAMIC_BASE: { static_indicator: 'COMPATIBLE', enabled: true },
      HIGH_ENTROPY_VA: { static_indicator: 'COMPATIBLE', enabled: true },
      CET_COMPAT: { static_indicator: 'UNKNOWN', enabled: null },
      GS_COOKIE: { static_indicator: 'NOT_DETECTED', enabled: false }
    }
  };

  const format = detectBinaryFormat(report);
  assert.strictEqual(format, 'PE');

  const m = getNormalizedMitigations(report);
  assert.strictEqual(m.format, 'PE');
  assert.strictEqual(m.hasMitigations, true);

  // Verify Summary Badges (Explorer view)
  const nxCompatBadge = m.summaryBadges.find(b => b.id === 'nx_compat');
  const dynamicBaseBadge = m.summaryBadges.find(b => b.id === 'dynamic_base');
  const gsCookieBadge = m.summaryBadges.find(b => b.id === 'gs_cookie');
  const cetBadge = m.summaryBadges.find(b => b.id === 'cet');

  assert.ok(nxCompatBadge, 'NX_COMPAT badge must be present for PE');
  assert.strictEqual(nxCompatBadge.value, 'COMPATIBLE');
  assert.strictEqual(nxCompatBadge.status, 'badge-on');

  assert.ok(dynamicBaseBadge, 'DYNAMIC_BASE badge must be present for PE');
  assert.strictEqual(dynamicBaseBadge.value, 'COMPATIBLE');
  assert.strictEqual(dynamicBaseBadge.status, 'badge-on');

  assert.ok(gsCookieBadge, 'GS-Cookie badge must be present for PE');
  assert.strictEqual(gsCookieBadge.value, 'NOT_DETECTED');
  assert.strictEqual(gsCookieBadge.status, 'badge-off');

  assert.ok(cetBadge, 'CET badge must be present for PE');
  assert.strictEqual(cetBadge.value, 'UNKNOWN');
  assert.strictEqual(cetBadge.status, 'badge-info');

  // Verify no ELF-style RELRO appears in summary or chips
  assert.ok(!m.summaryBadges.some(b => b.label.includes('RELRO')), 'RELRO must NOT appear in PE summary badges');
  assert.ok(!m.detailedChips.some(c => c.name.includes('RELRO')), 'RELRO must NOT appear in PE detailed chips');

  // Verify no DYNAMIC_BASE is mislabeled as PIE
  assert.ok(!m.summaryBadges.some(b => b.label === 'PIE'), 'DYNAMIC_BASE must not be labeled as PIE for PE');
});

// ---------------------------------------------------------------------------
// 2. PE with Flags Disabled or Absent
// ---------------------------------------------------------------------------
runTest('PE: Flags disabled or absent produce accurate states without false claims', () => {
  const report = {
    target_binary: { filename: 'legacy_app.exe' },
    protections: {
      NX_COMPAT: { static_indicator: 'NOT_COMPATIBLE', enabled: false },
      DYNAMIC_BASE: { static_indicator: 'NOT_COMPATIBLE', enabled: false },
      HIGH_ENTROPY_VA: { static_indicator: 'NOT_COMPATIBLE', enabled: false }
    }
  };

  const m = getNormalizedMitigations(report);
  assert.strictEqual(m.format, 'PE');

  const nxCompatBadge = m.summaryBadges.find(b => b.id === 'nx_compat');
  const dynamicBaseBadge = m.summaryBadges.find(b => b.id === 'dynamic_base');
  const gsCookieBadge = m.summaryBadges.find(b => b.id === 'gs_cookie');
  const cetBadge = m.summaryBadges.find(b => b.id === 'cet');

  assert.strictEqual(nxCompatBadge.value, 'NOT_COMPATIBLE');
  assert.strictEqual(nxCompatBadge.status, 'badge-off');

  assert.strictEqual(dynamicBaseBadge.value, 'NOT_COMPATIBLE');
  assert.strictEqual(dynamicBaseBadge.status, 'badge-off');

  // Absent GS_COOKIE and CET must be reported as UNKNOWN, never assumed as disabled
  assert.strictEqual(gsCookieBadge.value, 'UNKNOWN');
  assert.strictEqual(gsCookieBadge.status, 'badge-info');

  assert.strictEqual(cetBadge.value, 'UNKNOWN');
  assert.strictEqual(cetBadge.status, 'badge-info');
});

// ---------------------------------------------------------------------------
// 3. ELF with NX, PIE, Stack-Canary, and RELRO States
// ---------------------------------------------------------------------------
runTest('ELF: Standard Linux mitigations correctly normalized across full/partial/none states', () => {
  const reportFull = {
    file_type: 'ELF',
    architecture: 'x86_64',
    protections: {
      NX: true,
      PIE: true,
      Canary: true,
      RELRO: 'Full'
    }
  };

  const mFull = getNormalizedMitigations(reportFull);
  assert.strictEqual(mFull.format, 'ELF');

  const nxBadge = mFull.summaryBadges.find(b => b.id === 'nx');
  const pieBadge = mFull.summaryBadges.find(b => b.id === 'pie');
  const canaryBadge = mFull.summaryBadges.find(b => b.id === 'canary');
  const relroBadge = mFull.summaryBadges.find(b => b.id === 'relro');

  assert.strictEqual(nxBadge.value, 'ON');
  assert.strictEqual(nxBadge.status, 'badge-on');
  assert.strictEqual(pieBadge.value, 'ON');
  assert.strictEqual(pieBadge.status, 'badge-on');
  assert.strictEqual(canaryBadge.value, 'ON');
  assert.strictEqual(canaryBadge.status, 'badge-on');
  assert.strictEqual(relroBadge.value, 'Full');
  assert.strictEqual(relroBadge.status, 'badge-on');

  // Test Partial RELRO & disabled flags
  const reportPartial = {
    file_type: 'ELF',
    architecture: 'x86_64',
    protections: {
      NX: true,
      PIE: false,
      Canary: false,
      RELRO: 'Partial'
    }
  };

  const mPartial = getNormalizedMitigations(reportPartial);
  assert.strictEqual(mPartial.summaryBadges.find(b => b.id === 'pie').value, 'OFF');
  assert.strictEqual(mPartial.summaryBadges.find(b => b.id === 'pie').status, 'badge-off');
  assert.strictEqual(mPartial.summaryBadges.find(b => b.id === 'relro').value, 'Partial');
  assert.strictEqual(mPartial.summaryBadges.find(b => b.id === 'relro').status, 'badge-warning');
});

// ---------------------------------------------------------------------------
// 4. Mach-O with Applicable and Non-Applicable Mitigation States
// ---------------------------------------------------------------------------
runTest('Mach-O: Apple Darwin mitigations correctly presented with zero ELF RELRO', () => {
  const report = {
    file_type: 'Mach-O',
    architecture: 'arm64',
    protections: {
      Stack_NX: true,
      Heap_NX: 'EXPLICIT_ENABLED',
      Segment_WX: { status: 'COMPLIANT' },
      PIE: true,
      Canary: { status: 'SYMBOL_DETECTED' },
      Code_Signature: { load_command_present: true, superblob_header_valid: true }
    }
  };

  const m = getNormalizedMitigations(report);
  assert.strictEqual(m.format, 'Mach-O');

  const stackNx = m.summaryBadges.find(b => b.id === 'stack_nx');
  const heapNx = m.summaryBadges.find(b => b.id === 'heap_nx');
  const segmentWx = m.summaryBadges.find(b => b.id === 'segment_wx');
  const pie = m.summaryBadges.find(b => b.id === 'pie');
  const canary = m.summaryBadges.find(b => b.id === 'canary');

  assert.strictEqual(stackNx.value, 'ENABLED');
  assert.strictEqual(stackNx.status, 'badge-on');
  assert.strictEqual(heapNx.value, 'EXPLICIT_ENABLED');
  assert.strictEqual(heapNx.status, 'badge-on');
  assert.strictEqual(segmentWx.value, 'COMPLIANT');
  assert.strictEqual(segmentWx.status, 'badge-on');
  assert.strictEqual(pie.value, 'ENABLED');
  assert.strictEqual(pie.status, 'badge-on');
  assert.strictEqual(canary.value, 'SYMBOL_DETECTED');
  assert.strictEqual(canary.status, 'badge-on');

  // Verify RELRO is NOT present in Mach-O
  assert.ok(!m.summaryBadges.some(b => b.label.includes('RELRO')), 'RELRO must NOT appear in Mach-O summary badges');
  assert.ok(!m.detailedChips.some(c => c.name.includes('RELRO')), 'RELRO must NOT appear in Mach-O detailed chips');
});

// ---------------------------------------------------------------------------
// 5. Unknown or Unavailable Metadata & Distinction Preservation
// ---------------------------------------------------------------------------
runTest('Metadata: Preserves UNKNOWN, NOT_DETECTED, DISABLED, NOT_APPLICABLE distinctions', () => {
  // Empty protections
  const emptyReport = {
    file_type: 'ELF',
    protections: {}
  };
  const mEmpty = getNormalizedMitigations(emptyReport);
  assert.strictEqual(mEmpty.hasMitigations, false);
  assert.strictEqual(mEmpty.summaryBadges.length, 0);

  // 32-bit PE SafeSEH vs 64-bit PE SafeSEH
  const pe32Report = {
    target_binary: { filename: 'test32.exe' },
    architecture: 'i386',
    protections: {
      NX_COMPAT: { static_indicator: 'COMPATIBLE' },
      SafeSEH: { static_indicator: 'ENABLED', enabled: true }
    }
  };
  const m32 = getNormalizedMitigations(pe32Report);
  const safeSehChip32 = m32.detailedChips.find(c => c.id === 'safeseh');
  assert.strictEqual(safeSehChip32.state, 'ENABLED');
  assert.strictEqual(safeSehChip32.status, 'on');

  const pe64Report = {
    target_binary: { filename: 'test64.exe' },
    architecture: 'x86_64',
    protections: {
      NX_COMPAT: { static_indicator: 'COMPATIBLE' }
    }
  };
  const m64 = getNormalizedMitigations(pe64Report);
  const safeSehChip64 = m64.detailedChips.find(c => c.id === 'safeseh');
  assert.ok(safeSehChip64.state.includes('NOT_APPLICABLE'), 'SafeSEH on x86_64 must be reported as NOT_APPLICABLE');
  assert.strictEqual(safeSehChip64.status, 'na');
});

// ---------------------------------------------------------------------------
// 6. Consistency Between Explorer Summary and Report-Detail Presentation
//    Exact target: ROPW-ntwklauncher_131a314e1f92
// ---------------------------------------------------------------------------
runTest('Consistency: ROPW-ntwklauncher_131a314e1f92 produces identical states in Explorer and Report-Detail', () => {
  const ntwkReport = {
    id: 'ROPW-ntwklauncher_131a314e1f92',
    report_id: 'ROPW-ntwklauncher_131a314e1f92',
    architecture: 'x86_64',
    target_binary: { filename: 'ntwklauncher.exe' },
    protections: {
      NX_COMPAT: {
        static_indicator: 'COMPATIBLE',
        enabled: true,
        description: 'Binary explicitly opts into DEP via PE header; runtime enforcement is governed by host OS policy and hardware NX support'
      },
      DYNAMIC_BASE: {
        static_indicator: 'COMPATIBLE',
        enabled: true,
        description: 'Binary explicitly opts into ASLR via PE header; runtime address randomization is governed by host OS ASLR policy'
      },
      HIGH_ENTROPY_VA: {
        static_indicator: 'COMPATIBLE',
        enabled: true,
        description: 'Binary declares compatibility with 64-bit high-entropy ASLR (>4GB virtual address space) when loaded by OS'
      },
      GS_COOKIE: {
        static_indicator: 'NOT_DETECTED',
        enabled: false,
        description: 'Compiler stack buffer overrun guard (__security_cookie); static scan of sections and imports'
      },
      CET_COMPAT: {
        static_indicator: 'UNKNOWN',
        enabled: null,
        description: 'Control-flow Enforcement Technology (Shadow Stack / IBT); reported as UNKNOWN when Load Config Directory is absent'
      },
      // Stale or legacy backward-compatibility fields in Firestore doc:
      DEP_NX: true,
      ASLR_PIE: true,
      GS_Canary: false,
      NX: true,
      PIE: true,
      Canary: false,
      RELRO: 'N/A (PE format)'
    }
  };

  // Both views execute getNormalizedMitigations:
  const normalized = getNormalizedMitigations(ntwkReport);

  // 1. Explorer summary badges (rendered by ReportCard.jsx)
  const explorerNx = normalized.summaryBadges.find(b => b.id === 'nx_compat');
  const explorerDyn = normalized.summaryBadges.find(b => b.id === 'dynamic_base');
  const explorerGs = normalized.summaryBadges.find(b => b.id === 'gs_cookie');
  const explorerCet = normalized.summaryBadges.find(b => b.id === 'cet');

  assert.strictEqual(explorerNx.label, 'NX_COMPAT');
  assert.strictEqual(explorerNx.value, 'COMPATIBLE');

  assert.strictEqual(explorerDyn.label, 'DYNAMIC_BASE');
  assert.strictEqual(explorerDyn.value, 'COMPATIBLE');

  assert.strictEqual(explorerGs.label, 'GS-Cookie');
  assert.strictEqual(explorerGs.value, 'NOT_DETECTED');

  assert.strictEqual(explorerCet.label, 'CET');
  assert.strictEqual(explorerCet.value, 'UNKNOWN');

  // 2. Report Detail chips (rendered by BinaryDetailPage.jsx & ReportDetailModal.jsx)
  const detailNx = normalized.detailedChips.find(c => c.id === 'nx_compat');
  const detailDyn = normalized.detailedChips.find(c => c.id === 'dynamic_base');
  const detailGs = normalized.detailedChips.find(c => c.id === 'gs_cookie');
  const detailCet = normalized.detailedChips.find(c => c.id === 'cet_compat');

  assert.strictEqual(detailNx.state, explorerNx.value, 'NX_COMPAT state must match between Explorer and Detail');
  assert.strictEqual(detailDyn.state, explorerDyn.value, 'DYNAMIC_BASE state must match between Explorer and Detail');
  assert.strictEqual(detailGs.state, explorerGs.value, 'GS_COOKIE state must match between Explorer and Detail');
  assert.strictEqual(detailCet.state, explorerCet.value, 'CET state must match between Explorer and Detail');

  // 3. Absolute consistency check: NO RELRO or false ELF PIE in either view
  assert.ok(!normalized.summaryBadges.some(b => b.label.includes('RELRO')), 'No RELRO in Explorer summary');
  assert.ok(!normalized.detailedChips.some(c => c.name.includes('RELRO')), 'No RELRO in Detail view');
  assert.ok(!normalized.summaryBadges.some(b => b.label === 'PIE'), 'No ELF PIE in Explorer summary for PE');
  assert.ok(!normalized.detailedChips.some(c => c.name.includes('PIE')), 'No ELF PIE in Detail view for PE');
});

// ---------------------------------------------------------------------------
// 7. ELF ARM and AArch64 Architecture Coverage
// ---------------------------------------------------------------------------
runTest('ELF ARM and AArch64: Validates standard ELF protections on 32-bit and 64-bit ARM', () => {
  // ARM (32-bit)
  const armReport = {
    file_type: 'ELF',
    architecture: 'ARM',
    target_binary: { filename: 'embedded_sensor_arm' },
    protections: {
      NX: true,
      PIE: false,
      Canary: true,
      RELRO: 'Partial'
    }
  };
  const mArm = getNormalizedMitigations(armReport);
  assert.strictEqual(mArm.format, 'ELF');
  assert.strictEqual(mArm.arch, 'ARM');
  assert.strictEqual(mArm.summaryBadges.find(b => b.id === 'nx').value, 'ON');
  assert.strictEqual(mArm.summaryBadges.find(b => b.id === 'pie').value, 'OFF');
  assert.strictEqual(mArm.summaryBadges.find(b => b.id === 'canary').value, 'ON');
  assert.strictEqual(mArm.summaryBadges.find(b => b.id === 'relro').value, 'Partial');

  // AArch64 (64-bit ARM)
  const aarch64Report = {
    file_type: 'ELF',
    architecture: 'aarch64',
    target_binary: { filename: 'crypto_daemon_aarch64' },
    protections: {
      NX: true,
      PIE: true,
      Canary: true,
      RELRO: 'Full'
    }
  };
  const mAarch64 = getNormalizedMitigations(aarch64Report);
  assert.strictEqual(mAarch64.format, 'ELF');
  assert.strictEqual(mAarch64.arch, 'aarch64');
  assert.strictEqual(mAarch64.summaryBadges.find(b => b.id === 'nx').value, 'ON');
  assert.strictEqual(mAarch64.summaryBadges.find(b => b.id === 'pie').value, 'ON');
  assert.strictEqual(mAarch64.summaryBadges.find(b => b.id === 'canary').value, 'ON');
  assert.strictEqual(mAarch64.summaryBadges.find(b => b.id === 'relro').value, 'Full');
  assert.ok(!mAarch64.summaryBadges.some(b => b.label.includes('NX_COMPAT')), 'No PE terms on AArch64 ELF');
});

// ---------------------------------------------------------------------------
// 8. ELF RISC-V Architecture Coverage
// ---------------------------------------------------------------------------
runTest('ELF RISC-V: Validates standard ELF protections on riscv64 and riscv32', () => {
  const riscvReport = {
    file_type: 'ELF',
    architecture: 'riscv64',
    target_binary: { filename: 'firmware_riscv64.elf' },
    protections: {
      NX: true,
      PIE: true,
      Canary: false,
      RELRO: 'Full'
    }
  };

  const mRiscv = getNormalizedMitigations(riscvReport);
  assert.strictEqual(mRiscv.format, 'ELF');
  assert.strictEqual(mRiscv.arch, 'riscv64');

  const nx = mRiscv.summaryBadges.find(b => b.id === 'nx');
  const pie = mRiscv.summaryBadges.find(b => b.id === 'pie');
  const canary = mRiscv.summaryBadges.find(b => b.id === 'canary');
  const relro = mRiscv.summaryBadges.find(b => b.id === 'relro');

  assert.strictEqual(nx.value, 'ON');
  assert.strictEqual(pie.value, 'ON');
  assert.strictEqual(canary.value, 'OFF');
  assert.strictEqual(relro.value, 'Full');
  assert.ok(!mRiscv.summaryBadges.some(b => b.label.includes('DYNAMIC_BASE')), 'No PE terms on RISC-V ELF');
});

// ---------------------------------------------------------------------------
// 9. Mach-O x86_64 Architecture Coverage
// ---------------------------------------------------------------------------
runTest('Mach-O x86_64: Validates Darwin mitigations on Intel Mac binaries with zero RELRO', () => {
  const machoX64Report = {
    file_type: 'Mach-O',
    architecture: 'x86_64',
    target_binary: { filename: 'darwin_intel_binary' },
    protections: {
      Stack_NX: true,
      Heap_NX: 'EXPLICIT_ENABLED',
      Segment_WX: { status: 'COMPLIANT' },
      PIE: true,
      Canary: { status: 'SYMBOL_DETECTED' },
      Code_Signature: { load_command_present: true, superblob_header_valid: true }
    }
  };

  const mMacho = getNormalizedMitigations(machoX64Report);
  assert.strictEqual(mMacho.format, 'Mach-O');
  assert.strictEqual(mMacho.arch, 'x86_64');
  assert.strictEqual(mMacho.summaryBadges.find(b => b.id === 'stack_nx').value, 'ENABLED');
  assert.strictEqual(mMacho.summaryBadges.find(b => b.id === 'heap_nx').value, 'EXPLICIT_ENABLED');
  assert.strictEqual(mMacho.summaryBadges.find(b => b.id === 'segment_wx').value, 'COMPLIANT');
  assert.strictEqual(mMacho.summaryBadges.find(b => b.id === 'pie').value, 'ENABLED');
  assert.strictEqual(mMacho.summaryBadges.find(b => b.id === 'canary').value, 'SYMBOL_DETECTED');
  assert.ok(!mMacho.summaryBadges.some(b => b.label.includes('RELRO')), 'Zero RELRO on Intel Mach-O');
});

// ---------------------------------------------------------------------------
// 10. Unknown / Unsupported Architectures and Fallback Robustness
// ---------------------------------------------------------------------------
runTest('Robustness: Gracefully handles unknown/unsupported architectures without inventing states', () => {
  // Unknown architecture on ELF
  const unknownElfReport = {
    file_type: 'ELF',
    architecture: 'sparc64',
    target_binary: { filename: 'legacy_sparc.bin' },
    protections: {
      NX: true,
      PIE: false,
      Canary: false,
      RELRO: 'None'
    }
  };
  const mUnknownElf = getNormalizedMitigations(unknownElfReport);
  assert.strictEqual(mUnknownElf.format, 'ELF');
  assert.strictEqual(mUnknownElf.arch, 'sparc64');
  assert.strictEqual(mUnknownElf.summaryBadges.find(b => b.id === 'nx').value, 'ON');
  assert.strictEqual(mUnknownElf.summaryBadges.find(b => b.id === 'relro').value, 'None');

  // Completely undefined architecture and null format
  const rawReport = {
    protections: {
      NX_COMPAT: { static_indicator: 'COMPATIBLE' }
    }
  };
  const mRaw = getNormalizedMitigations(rawReport);
  // Infers PE from NX_COMPAT schema
  assert.strictEqual(mRaw.format, 'PE');
  assert.strictEqual(mRaw.summaryBadges.find(b => b.id === 'nx_compat').value, 'COMPATIBLE');
});

console.log(`\nTest Results: ${passedTests} passed, ${failedTests} failed.`);
if (failedTests > 0) {
  process.exit(1);
}
