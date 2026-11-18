/**
 * Cloud Explorer Helper Utilities
 *
 * Pure JavaScript helpers for ROPWeaver Cloud Explorer:
 * - Deterministic timestamp resolution with multi-tier fallback
 * - Stable, deterministic sorting (newest/oldest) with code-point lexical tie-breaking
 * - Strict binary-format normalization (PE, ELF, Mach-O, RAW, UNKNOWN) with conflict detection
 * - Architecture normalization without substring collisions (i386 vs x86_64, generic arm vs armv7 vs arm64)
 * - Safe Firestore document mapping preserving explicit firestore_id
 * - Multi-dimensional report filtering without array mutation
 * - Explorer metrics aggregation
 */

/**
 * Standard code-point binary lexical comparison (locale-independent).
 *
 * Guarantees identical deterministic ordering across all host operating systems,
 * locales, and Node.js/browser environments.
 *
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} -1 if a < b, 1 if a > b, 0 if equal
 */
export function lexicalCompare(a, b) {
  const strA = typeof a === 'string' ? a : String(a ?? '');
  const strB = typeof b === 'string' ? b : String(b ?? '');
  if (strA < strB) return -1;
  if (strA > strB) return 1;
  return 0;
}

/**
 * Maps a Firestore DocumentSnapshot into an application report object,
 * ensuring that the Firestore document ID is safely preserved under `firestore_id`
 * and cannot be clobbered by any payload `id` or `report_id` properties.
 *
 * If the payload data does not define its own `id`, preserves `docSnapshot.id` under `id`
 * to maintain backwards compatibility with existing UI components.
 *
 * @param {Object} docSnapshot - Firestore DocumentSnapshot or mock { id, data() }
 * @returns {Object} Mapped report document object
 */
export function mapFirestoreReportDoc(docSnapshot) {
  if (!docSnapshot || typeof docSnapshot !== 'object') return {};
  const docId = typeof docSnapshot.id === 'string' ? docSnapshot.id : '';
  const data = typeof docSnapshot.data === 'function' ? (docSnapshot.data() || {}) : {};

  return {
    ...data,
    firestore_id: docId,
    // If payload does not provide an explicit id, retain docId as fallback for UI compatibility
    id: data.id !== undefined ? data.id : docId
  };
}

/**
 * Extracts the explicit Firestore document ID (`firestore_id`, fallback to `id`).
 *
 * @param {Object} report - Analysis report document object
 * @returns {string} Firestore document ID, or empty string if not present
 */
export function getFirestoreDocumentId(report) {
  if (!report || typeof report !== 'object') return '';
  if (typeof report.firestore_id === 'string' && report.firestore_id.trim()) {
    return report.firestore_id.trim();
  }
  if (typeof report.id === 'string' && report.id.trim()) {
    return report.id.trim();
  }
  return '';
}

/**
 * Extracts the payload report ID (stored in doc.data().report_id).
 *
 * @param {Object} report - Analysis report document object
 * @returns {string} Payload report ID (e.g. "ROPW-1791653080"), or empty string
 */
export function getPayloadReportId(report) {
  if (!report || typeof report !== 'object') return '';
  return typeof report.report_id === 'string' ? report.report_id.trim() : '';
}

/**
 * Returns the primary unique identifier for a report for deterministic tie-breaking.
 * Priority:
 * 1. Explicit Firestore document ID (`firestore_id`)
 * 2. Fallback to `report.id` (when firestore_id is absent)
 * 3. Fallback to payload `report_id`
 * 4. Empty string (never invents synthetic IDs)
 *
 * @param {Object} report - Analysis report object
 * @returns {string} Primary identifier string
 */
export function getReportIdentifier(report) {
  if (!report || typeof report !== 'object') return '';
  const firestoreId = getFirestoreDocumentId(report);
  if (firestoreId) return firestoreId;

  const payloadId = getPayloadReportId(report);
  if (payloadId) return payloadId;

  return '';
}

/**
 * Resolves an authoritative Unix epoch millisecond timestamp from report metadata.
 *
 * Fallback precedence:
 * 1. Valid report.report_date (ISO 8601 string or numeric timestamp)
 * 2. Valid report.timestamp (Firestore Timestamp object, ISO string, or numeric)
 * 3. Unix epoch seconds encoded in payload report_id or document id (e.g. "ROPW-1791653080")
 * 4. Fallback: 0
 *
 * Safely handles invalid dates, null, undefined, and malformed structures.
 * Normalizes seconds vs milliseconds consistently.
 *
 * @param {Object} report - Analysis report object
 * @returns {number} Unix epoch timestamp in milliseconds (>= 0)
 */
export function getReportTimestamp(report) {
  if (!report || typeof report !== 'object') return 0;

  // Helper: Normalize numeric seconds/milliseconds
  const normalizeNumeric = (val) => {
    if (typeof val !== 'number' || isNaN(val) || !isFinite(val) || val <= 0) return 0;
    // If value is in seconds range (1e8 to 1e11, approx 1973 to 2286), convert to ms
    if (val >= 1e8 && val < 1e11) {
      return Math.floor(val * 1000);
    }
    // If already in milliseconds range (>= 1e11)
    if (val >= 1e11) {
      return Math.floor(val);
    }
    return 0;
  };

  // 1. Prefer report_date
  if (report.report_date !== undefined && report.report_date !== null) {
    if (typeof report.report_date === 'string') {
      const parsed = Date.parse(report.report_date);
      if (!isNaN(parsed) && parsed > 0) return parsed;
    } else if (typeof report.report_date === 'number') {
      const norm = normalizeNumeric(report.report_date);
      if (norm > 0) return norm;
    }
  }

  // 2. Fall back to timestamp
  if (report.timestamp !== undefined && report.timestamp !== null) {
    // Firestore Timestamp with toMillis()
    if (typeof report.timestamp.toMillis === 'function') {
      try {
        const ms = report.timestamp.toMillis();
        if (typeof ms === 'number' && !isNaN(ms) && ms > 0) return ms;
      } catch {
        // ignore
      }
    }
    // Firestore Timestamp with toDate()
    if (typeof report.timestamp.toDate === 'function') {
      try {
        const d = report.timestamp.toDate();
        if (d instanceof Date && !isNaN(d.getTime()) && d.getTime() > 0) {
          return d.getTime();
        }
      } catch {
        // ignore
      }
    }
    // Timestamp with seconds / _seconds property
    const rawSeconds = report.timestamp.seconds ?? report.timestamp._seconds;
    if (typeof rawSeconds === 'number') {
      const norm = normalizeNumeric(rawSeconds);
      if (norm > 0) return norm;
    }
    // String timestamp
    if (typeof report.timestamp === 'string') {
      const parsed = Date.parse(report.timestamp);
      if (!isNaN(parsed) && parsed > 0) return parsed;
    }
    // Numeric timestamp
    if (typeof report.timestamp === 'number') {
      const norm = normalizeNumeric(report.timestamp);
      if (norm > 0) return norm;
    }
  }

  // 3. Fall back to ROPW-<epoch> encoded in payload report_id, id, or firestore_id
  const repId = report.report_id || report.id || report.firestore_id;
  if (typeof repId === 'string' && repId.startsWith('ROPW-')) {
    const epochStr = repId.slice(5).trim();
    const rawEpoch = parseInt(epochStr, 10);
    const norm = normalizeNumeric(rawEpoch);
    if (norm > 0) return norm;
  }

  // 4. Fallback: 0
  return 0;
}

/**
 * Deterministically sorts an array of reports by analysis generation timestamp.
 *
 * - direction: 'desc' (newest first, default) or 'asc' (oldest first).
 * - Equal timestamps break ties deterministically using locale-independent code-point lexical comparison.
 * - Prioritizes Firestore document identity (`firestore_id`) over payload identifiers.
 * - Documents with missing or zero timestamps are stably sorted to the end (desc) or start (asc).
 * - Never mutates the caller's array.
 *
 * @param {Array<Object>} reports - Array of report objects
 * @param {'desc' | 'asc'} [direction='desc'] - Sort direction
 * @returns {Array<Object>} New sorted array of reports
 */
export function sortReports(reports, direction = 'desc') {
  if (!Array.isArray(reports)) return [];
  const isAsc = direction === 'asc';

  return [...reports].sort((a, b) => {
    const timeA = getReportTimestamp(a);
    const timeB = getReportTimestamp(b);

    if (timeA !== timeB) {
      return isAsc ? timeA - timeB : timeB - timeA;
    }

    // Deterministic tie-breaker using locale-independent code-point lexical comparison
    const idA = getReportIdentifier(a);
    const idB = getReportIdentifier(b);

    const tie = lexicalCompare(idA, idB);
    return isAsc ? tie : -tie;
  });
}

/**
 * Normalizes raw architecture string to a canonical identifier.
 *
 * Rules:
 * - Strictly keeps 32-bit x86/i386 distinct from 64-bit x86_64.
 * - Keeps ARMv7 distinct from AArch64/ARM64.
 * - Generic 'arm' or 'arm32' without explicit v7 indicator maps to 'unknown'.
 *
 * @param {string|null|undefined} rawArch - Input architecture string
 * @returns {string} Normalized canonical architecture ('x86_64', 'i386', 'armv7', 'arm64', 'riscv64', 'riscv32', 'unknown')
 */
export function normalizeArchitecture(rawArch) {
  if (!rawArch || typeof rawArch !== 'string') return 'unknown';
  const s = rawArch.trim().toLowerCase();

  // 64-bit x86 / AMD64
  if (s === 'x86_64' || s === 'x86-64' || s === 'amd64' || s === 'x64') {
    return 'x86_64';
  }

  // 32-bit x86 / Intel
  if (s === 'i386' || s === 'i686' || s === 'x86' || s === 'ia32' || s === 'x86_32') {
    return 'i386';
  }

  // 64-bit ARM / AArch64
  if (s === 'arm64' || s === 'aarch64' || s === 'arm64-v8a' || s === 'armv8' || s === 'armv8-a') {
    return 'arm64';
  }

  // 32-bit ARMv7: Requires explicit v7 / armhf indicator
  if (s === 'armv7' || s === 'armv7l' || s === 'armhf' || s === 'armv7-a' || s === 'armv7a') {
    return 'armv7';
  }

  // Generic ARM (e.g. 'arm', 'arm32', 'arm-none-eabi') without explicit v7 indicator maps to 'unknown'
  if (s === 'arm' || s === 'arm32' || s.startsWith('arm-') || s === 'armv6') {
    return 'unknown';
  }

  // 64-bit RISC-V
  if (s === 'riscv64' || s === 'rv64' || s === 'rv64gc' || s === 'riscv' || s === 'risc-v') {
    return 'riscv64';
  }

  // 32-bit RISC-V
  if (s === 'riscv32' || s === 'rv32') {
    return 'riscv32';
  }

  return 'unknown';
}

/**
 * Extracts and normalizes the CPU architecture of a report.
 *
 * @param {Object} report - Analysis report object
 * @returns {string} Canonical architecture string
 */
export function getReportArchitecture(report) {
  if (!report || typeof report !== 'object') return 'unknown';

  const raw = report.architecture ||
    report.binary_analysis?.architecture ||
    report.target_binary?.architecture ||
    '';

  return normalizeArchitecture(raw);
}

/**
 * Accurately determines the binary format of a report ('PE', 'ELF', 'Mach-O', 'RAW', 'UNKNOWN').
 *
 * Evidence Hierarchy:
 * 1. Explicit format metadata fields take absolute priority.
 * 2. Conflicting explicit metadata produces 'UNKNOWN'.
 * 3. In the absence of explicit format metadata, evaluates protection schemas and extensions.
 * 4. Conflicting or insufficient evidence produces 'UNKNOWN'.
 * 5. Does NOT classify unknown or missing metadata as RAW.
 *
 * @param {Object} report - Analysis report object
 * @returns {'PE' | 'ELF' | 'Mach-O' | 'RAW' | 'UNKNOWN'} Normalized format
 */
export function normalizeReportFormat(report) {
  if (!report || typeof report !== 'object') return 'UNKNOWN';

  // 1. Gather all explicit format candidate fields
  const explicitCandidates = [
    report.file_type,
    report.format,
    report.binary_analysis?.format,
    report.binary_analysis?.file_type,
    report.target_binary?.format,
    report.target_binary?.file_type
  ].filter(Boolean);

  const detectedExplicit = new Set();
  for (const c of explicitCandidates) {
    const s = String(c).trim().toUpperCase();
    if (s === 'RAW' || s.includes('SHELLCODE') || s.includes('RAW BINARY')) {
      detectedExplicit.add('RAW');
    } else if (s === 'PE' || s.includes('PORTABLE EXECUTABLE') || s.includes('PE32')) {
      detectedExplicit.add('PE');
    } else if (s === 'MACH-O' || s === 'MACHO' || s.includes('DARWIN')) {
      detectedExplicit.add('Mach-O');
    } else if (s === 'ELF') {
      detectedExplicit.add('ELF');
    } else {
      // Unrecognized explicit format string
      detectedExplicit.add('UNSUPPORTED');
    }
  }

  // Conflict in explicit fields -> Ambiguous -> UNKNOWN
  if (detectedExplicit.size > 1) {
    return 'UNKNOWN';
  }
  if (detectedExplicit.size === 1) {
    const single = Array.from(detectedExplicit)[0];
    return single === 'UNSUPPORTED' ? 'UNKNOWN' : single;
  }

  // 2. Secondary: Evaluate protections schema indicators
  const detectedByProtections = new Set();
  const prots = report.protections || report.binary_analysis?.hardening_features;
  if (prots && typeof prots === 'object') {
    if (
      'NX_COMPAT' in prots ||
      'DYNAMIC_BASE' in prots ||
      'HIGH_ENTROPY_VA' in prots ||
      'GUARD_CF' in prots ||
      'CET_COMPAT' in prots ||
      'SafeSEH' in prots ||
      'GS_COOKIE' in prots ||
      'SafeSEH_NoSEH' in prots
    ) {
      detectedByProtections.add('PE');
    }

    if (
      'Stack_NX' in prots ||
      'Heap_NX' in prots ||
      'Segment_WX' in prots ||
      'Code_Signature' in prots
    ) {
      detectedByProtections.add('Mach-O');
    }

    if (
      'RELRO' in prots ||
      'BIND_NOW' in prots
    ) {
      detectedByProtections.add('ELF');
    }
  }

  // 3. Fallback: Evaluate filename extension
  const detectedByExtension = new Set();
  const filename = (
    report.target_binary?.filename ||
    report.binary_name ||
    report.filename ||
    report['file name'] ||
    ''
  ).toLowerCase().trim();

  if (filename) {
    if (filename.endsWith('.exe') || filename.endsWith('.dll') || filename.endsWith('.sys')) {
      detectedByExtension.add('PE');
    } else if (filename.endsWith('.dylib') || filename.endsWith('.macho')) {
      detectedByExtension.add('Mach-O');
    } else if (filename.endsWith('.raw') || filename.endsWith('.shellcode')) {
      detectedByExtension.add('RAW');
    }
  }

  // Check for conflicts between protections and extension
  const indirectEvidence = new Set([...detectedByProtections, ...detectedByExtension]);
  if (indirectEvidence.size > 1) {
    // Conflicting indirect evidence (e.g. .exe extension with ELF RELRO) -> UNKNOWN
    return 'UNKNOWN';
  }
  if (indirectEvidence.size === 1) {
    return Array.from(indirectEvidence)[0];
  }

  // Insufficient metadata -> UNKNOWN
  return 'UNKNOWN';
}

/**
 * Checks whether a report matches a target architecture filter.
 *
 * Uses strict equality on normalized architecture strings (no substring matching).
 * If targetArch is 'all', undefined, null, or empty, matches everything.
 *
 * @param {Object} report - Analysis report object
 * @param {string} [targetArch] - Target architecture filter
 * @returns {boolean} Whether report matches
 */
export function matchesArchitecture(report, targetArch) {
  if (!targetArch || targetArch === 'all') return true;
  const normalizedTarget = normalizeArchitecture(targetArch);
  const reportArch = getReportArchitecture(report);
  return reportArch === normalizedTarget;
}

/**
 * Checks whether a report matches a target binary format filter.
 *
 * If targetFormat is 'all', undefined, null, or empty, matches everything.
 *
 * @param {Object} report - Analysis report object
 * @param {string} [targetFormat] - Target format ('PE', 'ELF', 'Mach-O', 'RAW', 'all')
 * @returns {boolean} Whether report matches
 */
export function matchesFormat(report, targetFormat) {
  if (!targetFormat || targetFormat === 'all') return true;
  const normTarget = targetFormat.trim().toUpperCase();
  const reportFormat = normalizeReportFormat(report).toUpperCase();
  return reportFormat === normTarget;
}

/**
 * Filters a list of reports by architecture, binary format, and search term.
 *
 * - Does NOT mutate the source reports array.
 * - Applies architecture and format filters independently or together.
 * - Unknown metadata records remain visible under an unfiltered view.
 * - Search term matches target binary name, report_id, architecture, or format.
 *
 * @param {Array<Object>} reports - Input reports array
 * @param {Object} [filters={}] - Filter criteria
 * @param {string} [filters.architecture] - Architecture filter ('x86_64', 'i386', etc. or 'all')
 * @param {string} [filters.format] - Binary format filter ('PE', 'ELF', etc. or 'all')
 * @param {string} [filters.searchTerm] - Free text search term
 * @returns {Array<Object>} Filtered reports array
 */
export function filterReports(reports, { architecture, format, searchTerm } = {}) {
  if (!Array.isArray(reports)) return [];

  const term = typeof searchTerm === 'string' ? searchTerm.trim().toLowerCase() : '';
  const isSearchAll = !term || term === 'all';

  return reports.filter((r) => {
    // 1. Architecture filter
    if (!matchesArchitecture(r, architecture)) return false;

    // 2. Binary format filter
    if (!matchesFormat(r, format)) return false;

    // 3. Search term filter
    if (!isSearchAll) {
      const binName = (
        r.target_binary?.filename ||
        r.target_binary ||
        r['file name'] ||
        r.binary_name ||
        ''
      ).toLowerCase();
      const repId = String(r.report_id || r.id || '').toLowerCase();
      const arch = getReportArchitecture(r).toLowerCase();
      const fmt = normalizeReportFormat(r).toLowerCase();

      const matched =
        binName.includes(term) ||
        repId.includes(term) ||
        arch === term ||
        fmt === term ||
        binName.split(/[/\\]/).pop().includes(term);

      if (!matched) return false;
    }

    return true;
  });
}

/**
 * Aggregates summary telemetry metrics across an array of report documents.
 *
 * @param {Array<Object>} reports - Reports list
 * @returns {Object} Metric counts object
 */
export function tallyExplorerMetrics(reports) {
  const result = {
    totalReports: Array.isArray(reports) ? reports.length : 0,
    archCounts: {
      x86_64: 0,
      i386: 0,
      armv7: 0,
      arm64: 0,
      riscv64: 0,
      riscv32: 0,
      unknown: 0
    },
    typeCounts: {
      PE: 0,
      ELF: 0,
      'Mach-O': 0,
      RAW: 0,
      UNKNOWN: 0
    },
    recentBinaries: []
  };

  if (!Array.isArray(reports)) return result;

  const binarySet = new Set();

  reports.forEach((r) => {
    // Arch tally
    const arch = getReportArchitecture(r);
    if (Object.prototype.hasOwnProperty.call(result.archCounts, arch)) {
      result.archCounts[arch]++;
    } else {
      result.archCounts.unknown++;
    }

    // Type tally
    const fmt = normalizeReportFormat(r);
    if (Object.prototype.hasOwnProperty.call(result.typeCounts, fmt)) {
      result.typeCounts[fmt]++;
    } else {
      result.typeCounts.UNKNOWN++;
    }

    // Binary name
    const rawName = r.target_binary?.filename || r.target_binary || r['file name'] || r.binary_name;
    if (typeof rawName === 'string' && rawName.trim()) {
      const cleanName = rawName.split(/[/\\]/).pop().trim();
      if (cleanName) binarySet.add(cleanName);
    }
  });

  result.recentBinaries = Array.from(binarySet);
  return result;
}
/**
 * Cloud Explorer Pipeline & Cache Constants
 *
 * Query Bounds:
 * - REPORTS_BATCH_LIMIT (100): Caps maximum report documents retrieved per initial query,
 *   preventing unbounded collection download while maintaining representative sampling.
 * - GADGETS_BATCH_LIMIT (50): Caps maximum gadget documents retrieved per paginated query batch,
 *   decoupling gadget loading from initial view and preventing UI freeze.
 *
 * Cache Strategy:
 * - CACHE_TTL_MS (300,000 ms = 5 minutes): Time-to-live for sessionStorage explorer cache.
 *   Valid cache restores immediately without silent background revalidation, saving Firestore reads.
 * - CACHE_STORAGE_KEY: Key used in window.sessionStorage.
 */
export const REPORTS_BATCH_LIMIT = 100;
export const GADGETS_BATCH_LIMIT = 50;
export const CACHE_TTL_MS = 5 * 60 * 1000;
export const CACHE_STORAGE_KEY = 'ropweaver_explorer_cache_v1';

/**
 * Classifies a Firestore error into a standardized diagnostics object.
 *
 * Distinguishes:
 * - permission-denied (security rules reject read)
 * - unauthenticated (missing or expired authentication token)
 * - unavailable (backend unavailable, client offline, network dropped)
 * - resource-exhausted (Firestore rate limit, quota exceeded, HTTP 429)
 * - generic / network errors
 *
 * @param {Error|Object} err - Error object thrown by Firestore SDK
 * @returns {{ code: string, message: string, isRetryable: boolean }}
 */
export function classifyFirestoreError(err) {
  if (!err) {
    return {
      code: 'unknown',
      message: 'An unknown error occurred during Firestore retrieval.',
      isRetryable: true
    };
  }

  const code = (typeof err.code === 'string' ? err.code.toLowerCase() : '');
  const rawMsg = (typeof err.message === 'string' ? err.message.toLowerCase() : '');

  if (code.includes('permission-denied') || rawMsg.includes('permission-denied') || rawMsg.includes('missing or insufficient permissions')) {
    return {
      code: 'permission-denied',
      message: 'Access denied by Firestore security rules. Verify read permissions for "reports" and "gadgets" collections.',
      isRetryable: false
    };
  }

  if (code.includes('unauthenticated') || rawMsg.includes('unauthenticated')) {
    return {
      code: 'unauthenticated',
      message: 'Unauthenticated Firestore request. User credentials or anonymous token required.',
      isRetryable: false
    };
  }

  if (code.includes('unavailable') || rawMsg.includes('unavailable') || rawMsg.includes('failed to get document because the client is offline')) {
    return {
      code: 'unavailable',
      message: 'Firestore service is temporarily unavailable or client is offline. Verify network connectivity.',
      isRetryable: true
    };
  }

  if (code.includes('resource-exhausted') || rawMsg.includes('resource-exhausted') || rawMsg.includes('quota') || rawMsg.includes('429')) {
    return {
      code: 'resource-exhausted',
      message: 'Firestore query quota or rate limit exceeded. Please wait a moment before retrying.',
      isRetryable: true
    };
  }

  return {
    code: code || 'network-error',
    message: `Firestore request failed: ${err.message || 'Network error or unreachable backend.'}`,
    isRetryable: true
  };
}

/**
 * Validates whether a cache entry object is structurally sound and within its TTL.
 *
 * @param {Object} entry - Deserialized cache entry
 * @param {number} [now=Date.now()] - Current epoch millisecond timestamp
 * @param {number} [ttl=CACHE_TTL_MS] - Time to live in milliseconds
 * @returns {boolean} True if valid and not expired
 */
export function isCacheValid(entry, now = Date.now(), ttl = CACHE_TTL_MS) {
  if (!entry || typeof entry !== 'object') return false;
  if (entry.version !== 1) return false;
  if (typeof entry.timestamp !== 'number' || entry.timestamp <= 0) return false;
  if (!Array.isArray(entry.reports)) return false;

  const age = now - entry.timestamp;
  if (age < 0 || age >= ttl) return false;
  return true;
}

/**
 * Serializes Explorer state data for sessionStorage persistence.
 *
 * @param {Object} params
 * @param {number|null} params.catalogTotalReports
 * @param {Array<Object>} params.reports
 * @param {Object} params.stats
 * @param {Array<string>} [params.recentBinaries]
 * @param {number} [params.now=Date.now()]
 * @returns {string} JSON-serialized payload
 */
export function serializeExplorerCache({ catalogTotalReports, reports, stats, recentBinaries = [], now = Date.now() }) {
  const payload = {
    version: 1,
    timestamp: now,
    catalogTotalReports: typeof catalogTotalReports === 'number' ? catalogTotalReports : null,
    reports: Array.isArray(reports) ? reports : [],
    stats: stats && typeof stats === 'object' ? stats : {},
    recentBinaries: Array.isArray(recentBinaries) ? recentBinaries : []
  };
  return JSON.stringify(payload);
}

/**
 * Safely parses and validates a serialized cache JSON string from sessionStorage.
 *
 * @param {string|null} jsonString - Serialized cache JSON
 * @param {number} [now=Date.now()] - Current epoch millisecond timestamp
 * @param {number} [ttl=CACHE_TTL_MS] - Time to live in milliseconds
 * @returns {Object|null} Validated cached data or null if invalid/expired
 */
export function deserializeExplorerCache(jsonString, now = Date.now(), ttl = CACHE_TTL_MS) {
  if (!jsonString || typeof jsonString !== 'string') return null;
  try {
    const parsed = JSON.parse(jsonString);
    if (isCacheValid(parsed, now, ttl)) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Formats count metrics distinguishing catalog total, loaded count, and filtered count.
 *
 * When catalog total is unavailable (e.g. aggregation query fails or offline),
 * catalogTotal is strictly preserved as null and isCatalogTotalKnown is false.
 * Loaded count is never substituted as a verified catalog total.
 *
 * @param {Object} params
 * @param {number|null} params.catalogTotal - Total documents in Firestore reports collection (from getCountFromServer)
 * @param {number} params.loadedCount - Number of reports currently retrieved in client memory
 * @param {number} params.filteredCount - Number of reports matching active search/filter criteria
 * @returns {Object} Metric counts object with explicit separation
 */
export function formatReportCountMetrics({ catalogTotal, loadedCount, filteredCount }) {
  const isCatalogTotalKnown = typeof catalogTotal === 'number' && catalogTotal >= 0;
  const safeLoaded = Math.max(0, loadedCount || 0);
  const safeFiltered = Math.max(0, filteredCount || 0);

  if (!isCatalogTotalKnown) {
    return {
      catalogTotal: null,
      isCatalogTotalKnown: false,
      loadedCount: safeLoaded,
      filteredCount: safeFiltered,
      isSubset: false,
      displayLabel: `${safeFiltered} shown (${safeLoaded} loaded, catalog total unavailable)`
    };
  }

  const isSubset = catalogTotal > safeLoaded;
  return {
    catalogTotal,
    isCatalogTotalKnown: true,
    loadedCount: safeLoaded,
    filteredCount: safeFiltered,
    isSubset,
    displayLabel: isSubset
      ? `${safeFiltered} shown (${safeLoaded} loaded of ${catalogTotal} in catalog)`
      : `${safeFiltered} of ${catalogTotal}`
  };
}

/**
 * Deduplicates incoming gadget records against existing records using stable document ID,
 * preserving original array order and without replacing existing items.
 *
 * @param {Array<Object>} existingGadgets - Currently loaded gadgets
 * @param {Array<Object>} incomingGadgets - Newly fetched gadget records
 * @returns {Array<Object>} Deduplicated combined gadgets array
 */
export function deduplicateGadgets(existingGadgets = [], incomingGadgets = []) {
  const existing = Array.isArray(existingGadgets) ? existingGadgets : [];
  const incoming = Array.isArray(incomingGadgets) ? incomingGadgets : [];

  const seenIds = new Set();
  const result = [];

  for (const g of existing) {
    if (!g || typeof g !== 'object') continue;
    const key = g.id || g.hash;
    if (key) {
      if (!seenIds.has(key)) {
        seenIds.add(key);
        result.push(g);
      }
    } else {
      result.push(g);
    }
  }

  for (const g of incoming) {
    if (!g || typeof g !== 'object') continue;
    const key = g.id || g.hash;
    if (key) {
      if (!seenIds.has(key)) {
        seenIds.add(key);
        result.push(g);
      }
    } else {
      result.push(g);
    }
  }

  return result;
}
