/**
 * Utility: Visitor Local Timezone Detection and Timestamp Formatting
 *
 * Provides presentation-layer conversion of UTC timestamps into the
 * visitor's detected local timezone, while strictly preserving original
 * UTC timestamps in internal datastores and APIs.
 */

// Memory cache for Intl.DateTimeFormat instances by timezone key to avoid expensive repeated re-allocations
const formatterCache = new Map();

/**
 * Detects the visitor's local timezone using standard browser Intl API.
 * Falls back to 'UTC' if unavailable.
 *
 * @returns {string} IANA timezone identifier (e.g. 'Asia/Dubai', 'Europe/London')
 */
export function getUserTimezone() {
  try {
    if (typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat === 'function') {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz && typeof tz === 'string' && tz.trim()) {
        return tz.trim();
      }
    }
  } catch {
    // Fallback on error
  }
  return 'UTC';
}

/**
 * Retrieves or initializes a cached Intl.DateTimeFormat instance for a timezone.
 *
 * @param {string} timeZone - IANA timezone identifier
 * @returns {Intl.DateTimeFormat} Cached formatter instance
 */
function getCachedFormatter(timeZone) {
  const key = timeZone || 'UTC';
  let formatter = formatterCache.get(key);
  if (!formatter) {
    try {
      formatter = new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZone: key,
        timeZoneName: 'short'
      });
    } catch {
      // If specified timezone is unrecognized, fallback to UTC formatter
      formatter = new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZone: 'UTC',
        timeZoneName: 'short'
      });
    }
    formatterCache.set(key, formatter);
  }
  return formatter;
}

/**
 * Parses raw timestamp inputs safely into a valid Date object.
 *
 * Rules:
 * - Timestamps ending with 'Z' are strictly parsed as UTC.
 * - Firestore Timestamp objects (.toDate(), .toMillis(), or seconds) are handled.
 * - Millisecond and second epoch numbers are handled.
 * - 'ROPW-<epoch>' encoded strings are handled.
 * - Invalid, null, undefined, or missing values return null (never throws, never invents dates).
 *
 * @param {any} input - Raw timestamp input
 * @returns {Date|null} Valid Date object or null if invalid/missing
 */
export function parseDateInput(input) {
  if (input === null || input === undefined || input === '') return null;

  if (input instanceof Date) {
    return isNaN(input.getTime()) ? null : input;
  }

  // Firestore Timestamp or custom object
  if (typeof input === 'object') {
    if (typeof input.toDate === 'function') {
      try {
        const d = input.toDate();
        return (d instanceof Date && !isNaN(d.getTime())) ? d : null;
      } catch {
        return null;
      }
    }
    if (typeof input.toMillis === 'function') {
      try {
        const ms = input.toMillis();
        return (typeof ms === 'number' && !isNaN(ms) && ms > 0) ? new Date(ms) : null;
      } catch {
        return null;
      }
    }
    const sec = input.seconds ?? input._seconds;
    if (typeof sec === 'number' && !isNaN(sec) && sec > 0) {
      return new Date(sec * 1000);
    }
  }

  // Numeric epoch
  if (typeof input === 'number') {
    if (isNaN(input) || !isFinite(input) || input <= 0) return null;
    const ms = input < 1e11 ? input * 1000 : input;
    return new Date(ms);
  }

  // String timestamp
  if (typeof input === 'string') {
    let str = input.trim();
    if (!str || str.toLowerCase() === 'n/a' || str.toLowerCase() === 'unknown') return null;

    // ROPW-<epoch> ID
    if (str.startsWith('ROPW-')) {
      const epoch = parseInt(str.slice(5).trim(), 10);
      if (!isNaN(epoch) && epoch > 0) {
        const ms = epoch < 1e11 ? epoch * 1000 : epoch;
        return new Date(ms);
      }
    }

    // Normalize space between date and time to 'T' for reliable cross-engine parsing
    // E.g. '2026-10-10 17:24:24Z' -> '2026-10-10T17:24:24Z'
    if (str.includes(' ') && !str.includes('T')) {
      str = str.replace(' ', 'T');
    }

    // If string has date and time without offset or Z, treat as UTC by appending 'Z'
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/i.test(str)) {
      str += 'Z';
    }

    const parsed = Date.parse(str);
    return (!isNaN(parsed) && parsed > 0) ? new Date(parsed) : null;
  }

  return null;
}

/**
 * Formats a UTC timestamp into the visitor's local timezone for human presentation.
 *
 * Format: YYYY-MM-DD HH:mm:ss (TZ)
 * Example: 2026-10-10 21:24:40 (GMT+4)
 *
 * @param {any} input - Raw timestamp input
 * @param {Object} [options]
 * @param {string} [options.timeZone] - Override target timezone (defaults to visitor's detected timezone)
 * @param {string} [options.fallback='N/A'] - Fallback string if input is missing or invalid
 * @returns {string} Formatted localized date-time string
 */
export function formatLocalTimestamp(input, options = {}) {
  const d = parseDateInput(input);
  const fallback = options.fallback !== undefined ? options.fallback : 'N/A';
  if (!d) return fallback;

  const targetTz = options.timeZone || getUserTimezone();

  try {
    const formatter = getCachedFormatter(targetTz);
    const parts = Object.fromEntries(formatter.formatToParts(d).map((p) => [p.type, p.value]));
    const tzName = parts.timeZoneName || targetTz;
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} (${tzName})`;
  } catch {
    return d.toISOString();
  }
}
