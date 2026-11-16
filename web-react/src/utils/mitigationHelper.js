/**
 * Mitigation Normalization and Format-Aware Presentation Utility
 *
 * Provides a single shared source of truth for security mitigation interpretation
 * across Explorer summaries (ReportCard), Report Detail views (BinaryDetailPage),
 * and Detailed Audit modals (ReportDetailModal).
 */

/**
 * Accurately determines the binary format ('PE', 'Mach-O', or 'ELF')
 * by inspecting explicit metadata fields, file extensions, and protection schemas.
 *
 * @param {Object} report - Raw analysis report object
 * @returns {'PE' | 'Mach-O' | 'ELF'} Normalized binary format
 */
export function detectBinaryFormat(report) {
  if (!report) return 'ELF';

  // 1. Check explicit format and file_type fields
  const candidates = [
    report.file_type,
    report.format,
    report.binary_analysis?.format,
    report.binary_analysis?.file_type,
    report.target_binary?.format,
    report.target_binary?.file_type
  ].filter(Boolean);

  for (const c of candidates) {
    const s = String(c).toUpperCase();
    if (s.includes('PE') || s.includes('PORTABLE EXECUTABLE')) return 'PE';
    if (s.includes('MACH-O') || s.includes('MACHO') || s.includes('DARWIN')) return 'Mach-O';
    if (s.includes('ELF')) return 'ELF';
  }

  // 2. Check filename extension
  const filename = (
    report.target_binary?.filename ||
    report.binary_name ||
    report.filename ||
    report['file name'] ||
    report.id ||
    ''
  ).toLowerCase();

  if (filename.endsWith('.exe') || filename.endsWith('.dll') || filename.endsWith('.sys')) {
    return 'PE';
  }
  if (filename.endsWith('.dylib') || filename.endsWith('.macho')) {
    return 'Mach-O';
  }

  // 3. Inspect protections schema keys
  const prots = report.protections || (report.binary_analysis && report.binary_analysis.hardening_features);
  if (prots && typeof prots === 'object') {
    // PE-specific mitigation keys
    if (
      'NX_COMPAT' in prots ||
      'DYNAMIC_BASE' in prots ||
      'HIGH_ENTROPY_VA' in prots ||
      'GUARD_CF' in prots ||
      'CET_COMPAT' in prots ||
      'SafeSEH' in prots ||
      'DEP_NX' in prots ||
      'ASLR_PIE' in prots ||
      'GS_COOKIE' in prots ||
      'GS_Canary' in prots ||
      'SafeSEH_NoSEH' in prots
    ) {
      return 'PE';
    }

    // Mach-O-specific mitigation keys
    if (
      'Stack_NX' in prots ||
      'Heap_NX' in prots ||
      'Segment_WX' in prots ||
      'Code_Signature' in prots
    ) {
      return 'Mach-O';
    }
  }

  // Default to ELF
  return 'ELF';
}

/**
 * Extracts normalized CPU architecture string.
 *
 * @param {Object} report - Analysis report object
 * @returns {string} Architecture string (e.g. 'x86_64', 'i386', 'arm64')
 */
export function getArchitecture(report) {
  if (!report) return 'x86_64';
  return (
    report.architecture ||
    report.binary_analysis?.architecture ||
    report.target_binary?.architecture ||
    'x86_64'
  );
}

/**
 * Parses and normalizes binary protections into format-aware summary badges,
 * detailed chips, and text-export lines.
 *
 * @param {Object} report - Raw analysis report object
 * @returns {Object} Normalized mitigations object
 */
export function getNormalizedMitigations(report) {
  const format = detectBinaryFormat(report);
  const arch = getArchitecture(report);
  const rawProts = (report && (report.protections || (report.binary_analysis && report.binary_analysis.hardening_features))) || {};
  const hasMitigations = Boolean(rawProts && typeof rawProts === 'object' && Object.keys(rawProts).length > 0);

  if (!hasMitigations) {
    return {
      format,
      arch,
      hasMitigations: false,
      summaryBadges: [],
      detailedChips: [],
      textReportLines: ['Mitigations: None (All Protections Disabled / RAW)']
    };
  }

  if (format === 'PE') {
    return normalizePEMitigations(rawProts, arch);
  } else if (format === 'Mach-O') {
    return normalizeMachOMitigations(rawProts, arch);
  } else {
    return normalizeELFMitigations(rawProts, arch);
  }
}

/**
 * Normalizes Windows PE mitigations.
 * Terminology: NX_COMPAT, DYNAMIC_BASE, HIGH_ENTROPY_VA, CET_COMPAT, GS_COOKIE, SafeSEH.
 * Strictly NEVER labels DYNAMIC_BASE as PIE or includes ELF RELRO.
 */
function normalizePEMitigations(prots, arch) {
  const is64Bit = arch.includes('64');

  // 1. NX_COMPAT (DEP Opt-In)
  let nxCompatVal = 'UNKNOWN';
  if (prots.NX_COMPAT?.static_indicator) {
    nxCompatVal = prots.NX_COMPAT.static_indicator;
  } else if (prots.NX_COMPAT?.enabled !== undefined) {
    nxCompatVal = prots.NX_COMPAT.enabled ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (prots.DEP_NX !== undefined) {
    nxCompatVal = prots.DEP_NX ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (prots.NX !== undefined && typeof prots.NX === 'boolean') {
    nxCompatVal = prots.NX ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  }
  const nxCompatStatus = nxCompatVal === 'COMPATIBLE' ? 'badge-on' : (nxCompatVal === 'NOT_COMPATIBLE' ? 'badge-off' : 'badge-info');

  // 2. DYNAMIC_BASE (ASLR Opt-In)
  let dynamicBaseVal = 'UNKNOWN';
  if (prots.DYNAMIC_BASE?.static_indicator) {
    dynamicBaseVal = prots.DYNAMIC_BASE.static_indicator;
  } else if (prots.DYNAMIC_BASE?.enabled !== undefined) {
    dynamicBaseVal = prots.DYNAMIC_BASE.enabled ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (prots.ASLR_PIE !== undefined) {
    dynamicBaseVal = prots.ASLR_PIE ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (prots.PIE !== undefined && typeof prots.PIE === 'boolean') {
    dynamicBaseVal = prots.PIE ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  }
  const dynamicBaseStatus = dynamicBaseVal === 'COMPATIBLE' ? 'badge-on' : (dynamicBaseVal === 'NOT_COMPATIBLE' ? 'badge-off' : 'badge-info');

  // 3. GS Security Cookie (__security_cookie)
  let gsCookieVal = 'UNKNOWN';
  if (prots.GS_COOKIE?.static_indicator) {
    gsCookieVal = prots.GS_COOKIE.static_indicator;
  } else if (prots.GS_Canary !== undefined) {
    gsCookieVal = prots.GS_Canary ? 'PRESENT' : 'NOT_DETECTED';
  } else if (prots.Canary !== undefined && typeof prots.Canary === 'boolean') {
    gsCookieVal = prots.Canary ? 'PRESENT' : 'NOT_DETECTED';
  }
  const gsCookieStatus = gsCookieVal.includes('PRESENT') ? 'badge-on' : (gsCookieVal === 'UNKNOWN' ? 'badge-info' : 'badge-off');

  // 4. CET_COMPAT (Shadow Stack / IBT)
  let cetVal = 'UNKNOWN';
  if (prots.CET_COMPAT?.static_indicator) {
    cetVal = prots.CET_COMPAT.static_indicator;
  } else if (prots.CET_COMPAT?.enabled !== undefined && prots.CET_COMPAT?.enabled !== null) {
    cetVal = prots.CET_COMPAT.enabled ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  }
  const cetStatus = cetVal === 'COMPATIBLE' ? 'badge-on' : (cetVal === 'UNKNOWN' ? 'badge-info' : 'badge-off');

  // 5. HIGH_ENTROPY_VA (64-bit ASLR)
  let highEntropyVal = 'UNKNOWN';
  if (prots.HIGH_ENTROPY_VA?.static_indicator) {
    highEntropyVal = prots.HIGH_ENTROPY_VA.static_indicator;
  } else if (prots.HIGH_ENTROPY_VA?.enabled !== undefined) {
    highEntropyVal = prots.HIGH_ENTROPY_VA.enabled ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (prots.HighEntropyVA !== undefined) {
    highEntropyVal = prots.HighEntropyVA ? 'COMPATIBLE' : 'NOT_COMPATIBLE';
  } else if (!is64Bit) {
    highEntropyVal = 'NOT_APPLICABLE (32-bit PE)';
  }

  // 6. SafeSEH (x86 only; x86_64 uses .pdata/.xdata table unwinding)
  let safeSehVal = is64Bit ? 'NOT_APPLICABLE (x86_64 uses .pdata/.xdata table unwinding)' : 'UNKNOWN';
  if (prots.SafeSEH?.static_indicator) {
    safeSehVal = prots.SafeSEH.static_indicator;
  } else if (prots.SafeSEH?.enabled !== undefined) {
    safeSehVal = prots.SafeSEH.enabled ? 'ENABLED' : 'DISABLED';
  } else if (prots.SafeSEH_NoSEH !== undefined && !is64Bit) {
    safeSehVal = prots.SafeSEH_NoSEH ? 'DISABLED' : 'ENABLED';
  }

  // Explorer Summary Badges (Top 4 critical indicators matching Explorer standard)
  const summaryBadges = [
    { id: 'nx_compat', label: 'NX_COMPAT', value: nxCompatVal, status: nxCompatStatus, title: 'DEP Compatibility Opt-in via PE Header' },
    { id: 'dynamic_base', label: 'DYNAMIC_BASE', value: dynamicBaseVal, status: dynamicBaseStatus, title: 'ASLR Compatibility Opt-in via PE Header' },
    { id: 'gs_cookie', label: 'GS-Cookie', value: gsCookieVal, status: gsCookieStatus, title: 'Compiler Stack Buffer Overrun Guard (__security_cookie)' },
    { id: 'cet', label: 'CET', value: cetVal, status: cetStatus, title: 'Control-flow Enforcement Technology (Shadow Stack)' }
  ];

  // Comprehensive Detailed Chips (Auditing & Modal inspections)
  const detailedChips = [
    {
      id: 'nx_compat',
      name: 'NX_COMPAT (DEP Opt-In)',
      state: nxCompatVal,
      status: nxCompatVal === 'COMPATIBLE' ? 'on' : (nxCompatVal === 'NOT_COMPATIBLE' ? 'off' : 'info'),
      description: prots.NX_COMPAT?.description || 'Binary explicitly opts into DEP via PE header; runtime enforcement is governed by host OS policy and hardware NX support.'
    },
    {
      id: 'dynamic_base',
      name: 'DYNAMIC_BASE (ASLR Opt-In)',
      state: dynamicBaseVal,
      status: dynamicBaseVal === 'COMPATIBLE' ? 'on' : (dynamicBaseVal === 'NOT_COMPATIBLE' ? 'off' : 'info'),
      description: prots.DYNAMIC_BASE?.description || 'Binary explicitly opts into ASLR via PE header; runtime address randomization is governed by host OS ASLR policy.'
    },
    {
      id: 'high_entropy_va',
      name: 'HIGH_ENTROPY_VA (64-bit ASLR)',
      state: highEntropyVal,
      status: highEntropyVal === 'COMPATIBLE' ? 'on' : (highEntropyVal.startsWith('NOT_APPLICABLE') ? 'na' : (highEntropyVal === 'NOT_COMPATIBLE' ? 'off' : 'info')),
      description: prots.HIGH_ENTROPY_VA?.description || 'Binary declares compatibility with 64-bit high-entropy ASLR (>4GB virtual address space) when loaded by OS.'
    },
    {
      id: 'cet_compat',
      name: 'CET_COMPAT (Shadow Stack)',
      state: cetVal,
      status: cetVal === 'COMPATIBLE' ? 'on' : (cetVal === 'UNKNOWN' ? 'info' : 'off'),
      description: prots.CET_COMPAT?.description || 'Control-flow Enforcement Technology (Shadow Stack / IBT); reported as UNKNOWN when Load Config Directory is absent.'
    },
    {
      id: 'gs_cookie',
      name: 'GS Security Cookie',
      state: gsCookieVal,
      status: gsCookieVal.includes('PRESENT') ? 'on' : (gsCookieVal === 'UNKNOWN' ? 'info' : 'off'),
      description: prots.GS_COOKIE?.description || 'Compiler stack buffer overrun guard (__security_cookie); static scan of sections and imports.'
    },
    {
      id: 'safeseh',
      name: 'SafeSEH (Structured Exception)',
      state: safeSehVal,
      status: safeSehVal === 'ENABLED' ? 'on' : (safeSehVal.startsWith('NOT_APPLICABLE') ? 'na' : (safeSehVal === 'DISABLED' ? 'off' : 'info')),
      description: prots.SafeSEH?.description || 'Structured Exception Handler table verification (x86 only; x86_64 PE targets use table-based unwind in .pdata/.xdata).'
    }
  ];

  const textReportLines = [
    `NX_COMPAT (DEP Opt-In):        ${nxCompatVal}`,
    `DYNAMIC_BASE (ASLR Opt-In):    ${dynamicBaseVal}`,
    `HIGH_ENTROPY_VA (64-bit ASLR): ${highEntropyVal}`,
    `CET_COMPAT (Shadow Stack):     ${cetVal}`,
    `GS Security Cookie:            ${gsCookieVal}`,
    `SafeSEH (Structured Exception): ${safeSehVal}`
  ];

  return {
    format: 'PE',
    arch,
    hasMitigations: true,
    summaryBadges,
    detailedChips,
    textReportLines
  };
}

/**
 * Normalizes Apple Darwin Mach-O mitigations.
 * Terminology: Stack-NX, Heap-NX, Segment W^X, PIE, Canary, Code Signature.
 * Strictly NEVER displays ELF RELRO.
 */
function normalizeMachOMitigations(prots, arch) {
  // 1. Stack-NX
  let stackNxVal = 'UNKNOWN';
  if (prots.Stack_NX !== undefined) {
    stackNxVal = prots.Stack_NX ? 'ENABLED' : 'DISABLED';
  } else if (prots.NX !== undefined) {
    stackNxVal = prots.NX ? 'ENABLED' : 'DISABLED';
  }
  const stackNxStatus = stackNxVal === 'ENABLED' ? 'badge-on' : (stackNxVal === 'DISABLED' ? 'badge-off' : 'badge-info');

  // 2. Heap-NX
  const heapNxVal = prots.Heap_NX || 'UNKNOWN';
  const heapNxStatus = heapNxVal === 'EXPLICIT_ENABLED' ? 'badge-on' : 'badge-info';

  // 3. Segment W^X
  const wxVal = prots.Segment_WX?.status || 'UNKNOWN';
  const wxStatus = wxVal === 'COMPLIANT' ? 'badge-on' : (wxVal === 'INIT_VIOLATION' ? 'badge-off' : 'badge-warning');

  // 4. PIE
  let pieVal = 'UNKNOWN';
  if (prots.PIE !== undefined) {
    pieVal = prots.PIE ? 'ENABLED' : 'DISABLED';
  }
  const pieStatus = pieVal === 'ENABLED' ? 'badge-on' : (pieVal === 'DISABLED' ? 'badge-off' : 'badge-info');

  // 5. Stack Canary
  let canaryVal = 'UNKNOWN';
  if (prots.Canary?.status) {
    canaryVal = prots.Canary.status;
  } else if (prots.Canary !== undefined) {
    canaryVal = prots.Canary ? 'SYMBOL_DETECTED' : 'NOT_DETECTED';
  }
  const canaryStatus = canaryVal === 'SYMBOL_DETECTED' ? 'badge-on' : (canaryVal === 'NOT_DETECTED' ? 'badge-off' : 'badge-info');

  // 6. Code Signature
  let csVal = 'NOT_PRESENT';
  if (prots.Code_Signature?.load_command_present) {
    if (prots.Code_Signature.superblob_header_valid) {
      csVal = 'PRESENT (SuperBlob Valid)';
    } else if (prots.Code_Signature.data_range_valid) {
      csVal = 'PRESENT (Data Valid)';
    } else {
      csVal = 'PRESENT (Unverified)';
    }
  }

  const summaryBadges = [
    { id: 'stack_nx', label: 'Stack-NX', value: stackNxVal, status: stackNxStatus, title: 'Non-Executable Stack via Mach-O Sub-Framework' },
    { id: 'heap_nx', label: 'Heap-NX', value: heapNxVal, status: heapNxStatus, title: 'Explicit Heap Non-Executable Enforcement' },
    { id: 'segment_wx', label: 'Segment W^X', value: wxVal, status: wxStatus, title: 'Segment Protection: Write XOR Execute Enforcement' },
    { id: 'pie', label: 'PIE', value: pieVal, status: pieStatus, title: 'Position Independent Executable (MH_PIE Flag)' },
    { id: 'canary', label: 'Canary', value: canaryVal, status: canaryStatus, title: 'Stack Guard Symbol in Symbol Table' }
  ];

  const detailedChips = [
    {
      id: 'stack_nx',
      name: 'Stack NX (Non-Executable Stack)',
      state: stackNxVal,
      status: stackNxVal === 'ENABLED' ? 'on' : (stackNxVal === 'DISABLED' ? 'off' : 'info'),
      description: 'Disallows execution of shellcode placed on the stack.'
    },
    {
      id: 'heap_nx',
      name: 'Heap NX (Non-Executable Heap)',
      state: heapNxVal,
      status: heapNxVal === 'EXPLICIT_ENABLED' ? 'on' : 'info',
      description: 'Enforces non-executable pages on allocated heap regions.'
    },
    {
      id: 'segment_wx',
      name: 'Segment W^X (Write XOR Execute)',
      state: wxVal,
      status: wxVal === 'COMPLIANT' ? 'on' : (wxVal === 'INIT_VIOLATION' ? 'off' : 'info'),
      description: 'Ensures no memory segment is simultaneously writable and executable.'
    },
    {
      id: 'pie',
      name: 'PIE (Position Independent Executable)',
      state: pieVal,
      status: pieVal === 'ENABLED' ? 'on' : (pieVal === 'DISABLED' ? 'off' : 'info'),
      description: 'Randomizes program base address on each execution under ASLR.'
    },
    {
      id: 'canary',
      name: 'Stack Canary (SSP Guard)',
      state: canaryVal,
      status: canaryVal === 'SYMBOL_DETECTED' ? 'on' : (canaryVal === 'NOT_DETECTED' ? 'off' : 'info'),
      description: 'Static detection of stack guard symbols (__stack_chk_guard / __stack_chk_fail).'
    },
    {
      id: 'code_signature',
      name: 'Code Signature',
      state: csVal,
      status: csVal.startsWith('PRESENT') ? 'on' : 'off',
      description: 'Presence and structural integrity of Mach-O LC_CODE_SIGNATURE load command.'
    }
  ];

  const textReportLines = [
    `Stack NX (Non-Executable Stack):  ${stackNxVal}`,
    `Heap NX (Non-Executable Heap):   ${heapNxVal}`,
    `Segment W^X (Write XOR Execute): ${wxVal}`,
    `PIE (Position Independent):      ${pieVal}`,
    `Stack Canary (SSP Guard):        ${canaryVal}`,
    `Code Signature:                  ${csVal}`
  ];

  return {
    format: 'Mach-O',
    arch,
    hasMitigations: true,
    summaryBadges,
    detailedChips,
    textReportLines
  };
}

/**
 * Normalizes Linux ELF mitigations.
 * Terminology: NX, PIE, Canary, RELRO.
 */
function normalizeELFMitigations(prots, arch) {
  // 1. NX
  let nxVal = 'OFF';
  if (prots.NX !== undefined && typeof prots.NX === 'boolean') {
    nxVal = prots.NX ? 'ON' : 'OFF';
  } else if (prots.nx_enabled !== undefined) {
    nxVal = prots.nx_enabled ? 'ON' : 'OFF';
  }
  const nxStatus = nxVal === 'ON' ? 'badge-on' : 'badge-off';

  // 2. PIE
  let pieVal = 'OFF';
  if (prots.PIE !== undefined && typeof prots.PIE === 'boolean') {
    pieVal = prots.PIE ? 'ON' : 'OFF';
  } else if (prots.pie_enabled !== undefined) {
    pieVal = prots.pie_enabled ? 'ON' : 'OFF';
  }
  const pieStatus = pieVal === 'ON' ? 'badge-on' : 'badge-off';

  // 3. Canary
  let canaryVal = 'OFF';
  if (prots.Canary !== undefined && typeof prots.Canary === 'boolean') {
    canaryVal = prots.Canary ? 'ON' : 'OFF';
  } else if (prots.canary_enabled !== undefined) {
    canaryVal = prots.canary_enabled ? 'ON' : 'OFF';
  }
  const canaryStatus = canaryVal === 'ON' ? 'badge-on' : 'badge-off';

  // 4. RELRO
  let relroVal = 'None';
  if (prots.RELRO && typeof prots.RELRO === 'string' && prots.RELRO !== 'NOT_APPLICABLE' && !prots.RELRO.includes('PE')) {
    relroVal = prots.RELRO;
  } else if (prots.relro_full) {
    relroVal = 'Full';
  } else if (prots.relro_partial) {
    relroVal = 'Partial';
  }
  const relroStatus = relroVal === 'Full' ? 'badge-on' : (relroVal === 'Partial' ? 'badge-warning' : 'badge-off');

  const summaryBadges = [
    { id: 'nx', label: 'NX', value: nxVal, status: nxStatus, title: 'No-Execute Stack Protection (PT_GNU_STACK)' },
    { id: 'pie', label: 'PIE', value: pieVal, status: pieStatus, title: 'Position Independent Executable (ET_DYN)' },
    { id: 'canary', label: 'Canary', value: canaryVal, status: canaryStatus, title: 'Stack Smashing Protection (__stack_chk_fail)' },
    { id: 'relro', label: 'RELRO', value: relroVal, status: relroStatus, title: 'Relocation Read-Only (PT_GNU_RELRO + BIND_NOW)' }
  ];

  const detailedChips = [
    {
      id: 'nx',
      name: 'NX / DEP (No-Execute Stack)',
      state: nxVal === 'ON' ? 'ENABLED' : 'DISABLED',
      status: nxVal === 'ON' ? 'on' : 'off',
      description: 'Enforces memory pages in the stack region as non-executable via PT_GNU_STACK.'
    },
    {
      id: 'pie',
      name: 'PIE (Position Independent Executable)',
      state: pieVal === 'ON' ? 'ENABLED' : 'DISABLED',
      status: pieVal === 'ON' ? 'on' : 'off',
      description: 'Generates position-independent code permitting full base address randomization via ASLR.'
    },
    {
      id: 'canary',
      name: 'Stack Canary (SSP Guard)',
      state: canaryVal === 'ON' ? 'ENABLED' : 'DISABLED',
      status: canaryVal === 'ON' ? 'on' : 'off',
      description: 'Inserts integrity guard values before return addresses to detect stack-based buffer overflows.'
    },
    {
      id: 'relro',
      name: 'RELRO (Relocation Read-Only)',
      state: relroVal,
      status: relroVal === 'Full' ? 'on' : (relroVal === 'Partial' ? 'info' : 'off'),
      description: 'Hardens Global Offset Table (GOT) and dynamic linker data structures against runtime overwrite.'
    }
  ];

  const textReportLines = [
    `NX (No-Execute Stack):        ${nxVal === 'ON' ? 'ENABLED (ON)' : 'DISABLED (OFF)'}`,
    `PIE (Position-Independent):   ${pieVal === 'ON' ? 'ENABLED (ON)' : 'DISABLED (OFF)'}`,
    `Stack Canary (SSP Guard):     ${canaryVal === 'ON' ? 'ENABLED (ON)' : 'DISABLED (OFF)'}`,
    `RELRO (Read-Only GOT):        ${relroVal}`
  ];

  return {
    format: 'ELF',
    arch,
    hasMitigations: true,
    summaryBadges,
    detailedChips,
    textReportLines
  };
}
