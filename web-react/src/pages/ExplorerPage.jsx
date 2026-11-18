import React, { useState, useEffect, useMemo } from 'react';
import { Search, RotateCcw, AlertTriangle, Layers, Filter, Terminal, RefreshCw, Database, Check, X } from 'lucide-react';
import { db, collection, getDocs, query, limit, startAfter, getCountFromServer } from '../firebase/config';
import {
  mapFirestoreReportDoc,
  filterReports,
  tallyExplorerMetrics,
  classifyFirestoreError,
  serializeExplorerCache,
  deserializeExplorerCache,
  formatReportCountMetrics,
  deduplicateGadgets,
  REPORTS_BATCH_LIMIT,
  GADGETS_BATCH_LIMIT,
  CACHE_STORAGE_KEY
} from '../utils/cloudExplorerHelper';
import StatsPanel from '../components/StatsPanel';
import ReportCard from '../components/ReportCard';
import GadgetItem from '../components/GadgetItem';
import BinaryGadgetGroup from '../components/BinaryGadgetGroup';
import LazyList from '../components/LazyList';
import ReportDetailModal from '../components/ReportDetailModal';
import LoadingSpinner from '../components/LoadingSpinner';

export default function ExplorerPage({ onNavigateToBinary, onInspectReport }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedArch, setSelectedArch] = useState('all');
  const [selectedFormat, setSelectedFormat] = useState('all');
  const [activeFilter, setActiveFilter] = useState('all'); // 'all', 'reports', 'gadgets'
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState(null);
  const [selectedReportForModal, setSelectedReportForModal] = useState(null);
  const [selectedReportIndex, setSelectedReportIndex] = useState(1);

  const [rawReports, setRawReports] = useState([]);
  const [rawGadgets, setRawGadgets] = useState([]);
  const [catalogTotalReports, setCatalogTotalReports] = useState(null);

  const [gadgetsLoaded, setGadgetsLoaded] = useState(false);
  const [loadingGadgets, setLoadingGadgets] = useState(false);
  const [lastGadgetDoc, setLastGadgetDoc] = useState(null);
  const [hasMoreGadgets, setHasMoreGadgets] = useState(false);

  const [stats, setStats] = useState({
    totalReports: null,
    catalogTotal: null,
    isCatalogTotalKnown: false,
    loadedReports: 0,
    isPartial: false,
    totalGadgets: 0,
    gadgetsLoaded: false,
    archCounts: { "x86_64": 0, "i386": 0, "x86": 0, "arm": 0, "armv7": 0, "riscv": 0 },
    typeCounts: { "RAW": 0, "MACHO": 0, "ELF": 0, "PE": 0 }
  });

  const [recentBinaries, setRecentBinaries] = useState([]);

  // Fetch Firestore documents (bounded reports pipeline + decoupled gadgets)
  const fetchData = async (isManualSync = false) => {
    if (isManualSync) {
      setSyncing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      // 1. Retrieve catalog count using Firestore getCountFromServer aggregation query.
      // Firestore aggregation billing details:
      // - Aggregation billing is based on index entries scanned rather than downloading full document payloads.
      // - One document read is charged per batch of up to 1,000 index entries scanned.
      // - A minimum of one document read is charged per aggregation query (even if 0 or <1,000 index entries match).
      // - Total cost scales with catalog size: e.g. 1-1,000 docs = 1 read; 1,001-2,000 docs = 2 reads, etc.
      let catalogTotal = null;
      try {
        const countSnap = await getCountFromServer(collection(db, "reports"));
        if (countSnap && typeof countSnap.data === 'function') {
          const c = countSnap.data().count;
          if (typeof c === 'number' && !isNaN(c) && c >= 0) {
            catalogTotal = c;
          }
        }
      } catch (countErr) {
        console.warn("Firestore getCountFromServer aggregation failed; catalog total remains unverified:", countErr);
      }

      // 2. Bounded report retrieval (maximum of 100 reports for this phase)
      // Read-cost safeguard: Query is bounded by limit(100) to prevent full-collection download.
      // Documents are mapped with mapFirestoreReportDoc to preserve authentic firestore_id.
      const reportsQuery = query(collection(db, "reports"), limit(REPORTS_BATCH_LIMIT));
      const reportsSnap = await getDocs(reportsQuery);

      const reportsList = [];
      reportsSnap.forEach((doc) => {
        reportsList.push(mapFirestoreReportDoc(doc));
      });

      // 3. Compute telemetry metrics over the loaded batch
      // Clarification: archCounts and typeCounts represent the loaded sample (up to 100 docs),
      // distinct from the catalog total.
      const metrics = tallyExplorerMetrics(reportsList);
      const isCatalogTotalKnown = typeof catalogTotal === 'number' && catalogTotal >= 0;

      const newStats = {
        totalReports: isCatalogTotalKnown ? catalogTotal : null,
        catalogTotal: isCatalogTotalKnown ? catalogTotal : null,
        isCatalogTotalKnown,
        loadedReports: reportsList.length,
        isPartial: isCatalogTotalKnown && catalogTotal > reportsList.length,
        totalGadgets: 0,
        gadgetsLoaded: false,
        archCounts: metrics.archCounts,
        typeCounts: metrics.typeCounts
      };

      setCatalogTotalReports(isCatalogTotalKnown ? catalogTotal : null);
      setRawReports(reportsList);
      setStats(newStats);
      setRecentBinaries(metrics.recentBinaries);

      // 4. Save to session cache
      // Valid cache restores on reload without silent background revalidation, saving Firestore reads.
      try {
        const cachePayload = serializeExplorerCache({
          catalogTotalReports: isCatalogTotalKnown ? catalogTotal : null,
          reports: reportsList,
          stats: newStats,
          recentBinaries: metrics.recentBinaries
        });
        sessionStorage.setItem(CACHE_STORAGE_KEY, cachePayload);
      } catch (cacheErr) {
        console.warn("Session cache write failed:", cacheErr);
      }
    } catch (err) {
      console.error("Firestore fetch error:", err);
      const classified = classifyFirestoreError(err);
      setError(classified.message);
      // Preservation safeguard: Do not replace valid cached data with an empty result after a failed refresh!
    } finally {
      setLoading(false);
      setSyncing(false);
    }
  };

  // On-demand bounded gadget pagination (maximum 50 gadgets per request)
  const loadGadgetsBatch = async (isNextPage = false) => {
    if (loadingGadgets) return;
    setLoadingGadgets(true);
    setError(null);

    try {
      let gadgetsQuery;
      if (isNextPage && lastGadgetDoc) {
        gadgetsQuery = query(collection(db, "gadgets"), startAfter(lastGadgetDoc), limit(GADGETS_BATCH_LIMIT));
      } else {
        gadgetsQuery = query(collection(db, "gadgets"), limit(GADGETS_BATCH_LIMIT));
      }

      const gadgetsSnap = await getDocs(gadgetsQuery);
      const newGadgets = [];
      gadgetsSnap.forEach((doc) => {
        newGadgets.push({ id: doc.id, ...doc.data() });
      });

      const lastDoc = (gadgetsSnap.docs && gadgetsSnap.docs.length > 0)
        ? gadgetsSnap.docs[gadgetsSnap.docs.length - 1]
        : null;

      // Cursor preservation:
      // Only advance cursor when a non-null last document snapshot is returned.
      // An empty subsequent batch sets hasMoreGadgets to false without clearing the previous cursor.
      if (lastDoc) {
        setLastGadgetDoc(lastDoc);
      }

      // Deduplicate incoming records against existing records using stable document ID while preserving order
      const combined = deduplicateGadgets(isNextPage ? rawGadgets : [], newGadgets);

      setRawGadgets(combined);
      setHasMoreGadgets(newGadgets.length === GADGETS_BATCH_LIMIT);
      setGadgetsLoaded(true);

      // Update gadget telemetry count
      setStats((prev) => ({
        ...prev,
        totalGadgets: combined.length,
        gadgetsLoaded: true
      }));
    } catch (err) {
      console.error("Gadget pagination error:", err);
      const classified = classifyFirestoreError(err);
      setError(classified.message);
    } finally {
      setLoadingGadgets(false);
    }
  };

  useEffect(() => {
    // 1. Session cache restoration
    try {
      const cachedJson = sessionStorage.getItem(CACHE_STORAGE_KEY);
      const cachedData = deserializeExplorerCache(cachedJson);
      if (cachedData && Array.isArray(cachedData.reports) && cachedData.reports.length > 0) {
        const isKnown = typeof cachedData.catalogTotalReports === 'number' && cachedData.catalogTotalReports >= 0;
        setRawReports(cachedData.reports);
        setCatalogTotalReports(isKnown ? cachedData.catalogTotalReports : null);
        setStats({
          ...cachedData.stats,
          totalReports: isKnown ? cachedData.catalogTotalReports : null,
          catalogTotal: isKnown ? cachedData.catalogTotalReports : null,
          isCatalogTotalKnown: isKnown,
          gadgetsLoaded: false
        });
        setRecentBinaries(cachedData.recentBinaries || []);
        setLoading(false);
        // Do NOT trigger silent background revalidation; cache restoration is complete
        return;
      }
    } catch (cacheErr) {
      console.warn("Session cache check failed:", cacheErr);
    }

    // 2. Initial fetch if cache is absent or expired
    fetchData();
  }, []);

  // Multi-dimensional filter logic (reports)
  const filteredReports = useMemo(() => {
    return filterReports(rawReports, {
      architecture: selectedArch,
      format: selectedFormat,
      searchTerm: searchTerm
    });
  }, [rawReports, selectedArch, selectedFormat, searchTerm]);

  // Multi-dimensional filter logic (gadgets)
  const filteredGadgets = useMemo(() => {
    let list = rawGadgets;
    if (selectedArch && selectedArch !== 'all') {
      const targetArch = selectedArch.toLowerCase();
      list = list.filter((g) => (g.architecture || '').toLowerCase() === targetArch);
    }
    if (selectedFormat && selectedFormat !== 'all') {
      const targetFmt = selectedFormat.toUpperCase();
      list = list.filter((g) => {
        const cat = (g.category || g.format || '').toUpperCase();
        return cat === targetFmt;
      });
    }

    const term = searchTerm.trim().toLowerCase();
    if (!term || term === 'all') {
      return list;
    }

    return list.filter((g) => {
      const fileName = (g["file name"] || g.fileName || '').toLowerCase();
      const hash = (g.hash || '').toLowerCase();
      const instr = (g.instructions || g.gadget || '').toLowerCase();
      const cat = (g.category || '').toLowerCase();
      const repId = (g.report_id || '').toLowerCase();
      const addr = (g.address || '').toLowerCase();
      return (
        fileName.includes(term) ||
        hash.includes(term) ||
        instr.includes(term) ||
        cat.includes(term) ||
        repId.includes(term) ||
        addr.includes(term)
      );
    });
  }, [rawGadgets, selectedArch, selectedFormat, searchTerm]);

  // Combined active filter summary for informative empty states
  const activeFilterSummary = [
    selectedArch !== 'all' ? `arch: ${selectedArch}` : null,
    selectedFormat !== 'all' ? `format: ${selectedFormat}` : null,
    searchTerm.trim() ? `search: "${searchTerm.trim()}"` : null
  ].filter(Boolean).join(', ');
  const hasActiveFilters = Boolean(activeFilterSummary);

  const onSearchSubmit = (e) => {
    e.preventDefault();
  };

  const handleFilterChange = (filterName) => {
    setActiveFilter(filterName);
    if (filterName === 'gadgets' && !gadgetsLoaded && !loadingGadgets) {
      loadGadgetsBatch(false);
    }
  };

  const handleSelectBinary = (binaryName) => {
    setSearchTerm(binaryName);
  };

  const handleSelectArch = (arch) => {
    setSelectedArch(arch);
  };

  const handleSelectFormat = (fmt) => {
    setSelectedFormat(fmt);
  };

  const handleSelectReportId = (reportId) => {
    setSearchTerm(reportId);
  };

  const handleReset = () => {
    setSearchTerm('');
  };

  const handleClearAllFilters = () => {
    setSearchTerm('');
    setSelectedArch('all');
    setSelectedFormat('all');
  };

  // Group filtered gadgets by binary file for structured, professional presentation.
  // Pre-index rawReports into Maps for O(1) matching, eliminating O(G x R) scan bottlenecks.
  const groupedGadgetsByFile = useMemo(() => {
    const reportByFileName = new Map();
    const reportById = new Map();

    rawReports.forEach((r) => {
      const rawReportName = r.target_binary?.filename || r.target_binary || r["file name"] || r.binary_name || '';
      const rName = (typeof rawReportName === 'string' ? rawReportName : '').split(/[/\\]/).pop();
      if (rName && !reportByFileName.has(rName)) {
        reportByFileName.set(rName, r);
      }
      const rId = r.report_id || r.id;
      if (rId && !reportById.has(rId)) {
        reportById.set(rId, r);
      }
      if (r.firestore_id && !reportById.has(r.firestore_id)) {
        reportById.set(r.firestore_id, r);
      }
    });

    const map = new Map();

    filteredGadgets.forEach((g) => {
      const rawName = g["file name"] || g.fileName || g.binary_name || 'unknown_binary';
      const cleanName = (typeof rawName === 'string' ? rawName : 'binary').split(/[/\\]/).pop() || 'binary';

      if (!map.has(cleanName)) {
        const gRepId = g.report_id || g.reportId;
        const matchingReport = (gRepId ? reportById.get(gRepId) : null) || reportByFileName.get(cleanName) || null;

        map.set(cleanName, {
          cleanName,
          rawName,
          arch: g.architecture || (matchingReport?.architecture) || 'x86_64',
          category: g.category || (matchingReport?.file_type) || 'ELF',
          hash: g.hash || matchingReport?.target_binary?.hash || '',
          reportId: g.report_id || matchingReport?.report_id || matchingReport?.id || cleanName,
          rawReport: matchingReport,
          gadgets: []
        });
      }

      map.get(cleanName).gadgets.push(g);
    });

    return Array.from(map.values());
  }, [filteredGadgets, rawReports]);

  return (
    <div className="explorer-page fade-in">
      {/* Intro Header */}
      <div className="explorer-hero">
        <div className="hero-terminal-tag mono">
          <Terminal size={14} className="text-accent-green" />
          <span>ROPWEAVER CLOUD GADGET & EXPLOIT REPOSITORY</span>
        </div>
        <h1 className="hero-title">Live Binary Exploit & Gadget Explorer</h1>
        <p className="hero-subtitle">
          Real-time query engine for published ROP chains, binary hardening mitigations, and indexed Capstone disassembly gadgets.
        </p>
      </div>

      {/* Telemetry Stats Panel */}
      <StatsPanel
        stats={stats}
        recentBinaries={recentBinaries}
        loading={loading}
        syncing={syncing}
        onRefresh={() => {
          if (!loading && !syncing) {
            fetchData(true);
          }
        }}
        onSelectBinary={handleSelectBinary}
        onSelectArch={handleSelectArch}
        selectedArch={selectedArch}
        selectedFormat={selectedFormat}
        onSelectFormat={handleSelectFormat}
      />

      {/* Search Input Bar */}
      <div className="search-section-card">
        <form onSubmit={onSearchSubmit} className="search-form-row">
          <div className="search-input-wrap">
            <Search size={18} className="search-icon text-muted" />
            <input
              id="explorer-search-input"
              name="search"
              type="text"
              className="search-input mono"
              placeholder="Enter binary name (e.g. binsh_test, p3), hash, address, or 'all'..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search cloud exploit reports and indexed disassembly gadgets"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={handleReset}
                className="clear-search-btn text-muted"
                title="Clear input"
                aria-label="Clear search input"
              >
                &times;
              </button>
            )}
          </div>

          <div className="search-actions-group">
            <button type="submit" className="btn btn-primary" disabled={loading || syncing}>
              <Search size={15} />
              <span>SEARCH</span>
            </button>
            <button
              type="button"
              onClick={handleClearAllFilters}
              className="btn btn-secondary"
              disabled={loading || syncing}
              title="Reset search, architecture, and format filters"
              aria-label="Show all reports and reset active filters"
            >
              SHOW ALL
            </button>
          </div>
        </form>

        {/* View Filters: All, Reports Only, Gadgets Only */}
        <div className="view-filter-bar">
          <div className="filter-label-wrap">
            <Filter size={14} className="text-accent-cyan" />
            <span className="mono text-xs filter-label-text">VIEW:</span>
          </div>
          <div className="filter-buttons-group">
            <button
              type="button"
              onClick={() => handleFilterChange('all')}
              className={`filter-btn ${activeFilter === 'all' ? 'filter-btn-active' : ''}`}
              aria-pressed={activeFilter === 'all'}
              aria-label="View all results"
            >
              <span className="filter-btn-text">All Results</span>
              <span className="filter-btn-badge mono">
                {filteredReports.length + (gadgetsLoaded ? filteredGadgets.length : 0)}
              </span>
            </button>
            <button
              type="button"
              onClick={() => handleFilterChange('reports')}
              className={`filter-btn ${activeFilter === 'reports' ? 'filter-btn-active' : ''}`}
              aria-pressed={activeFilter === 'reports'}
              aria-label="View reports only"
            >
              <span className="filter-btn-text">Reports</span>
              <span className="filter-btn-badge mono">
                {filteredReports.length}
              </span>
            </button>
            <button
              type="button"
              onClick={() => handleFilterChange('gadgets')}
              className={`filter-btn ${activeFilter === 'gadgets' ? 'filter-btn-active' : ''}`}
              aria-pressed={activeFilter === 'gadgets'}
              aria-label="View gadgets only"
            >
              <span className="filter-btn-text">Gadgets</span>
              <span className="filter-btn-badge mono">
                {gadgetsLoaded ? filteredGadgets.length : (loadingGadgets ? '...' : 'on-demand')}
              </span>
            </button>
          </div>
        </div>

        {/* Active Multi-Dimensional Filters Bar */}
        {(searchTerm.trim() !== '' || selectedArch !== 'all' || selectedFormat !== 'all') && (
          <div className="active-filters-bar mono text-xs">
            <span className="active-filters-label text-dim">ACTIVE FILTERS:</span>
            <div className="active-filter-pills">
              {selectedArch !== 'all' && (
                <span className="active-filter-pill">
                  <span className="pill-key">arch:</span>
                  <span className="pill-val">{selectedArch}</span>
                  <button
                    type="button"
                    onClick={() => setSelectedArch('all')}
                    className="pill-remove-btn"
                    title="Remove architecture filter"
                    aria-label={`Remove ${selectedArch} architecture filter`}
                  >
                    <X size={11} />
                  </button>
                </span>
              )}
              {selectedFormat !== 'all' && (
                <span className="active-filter-pill">
                  <span className="pill-key">format:</span>
                  <span className="pill-val">{selectedFormat}</span>
                  <button
                    type="button"
                    onClick={() => setSelectedFormat('all')}
                    className="pill-remove-btn"
                    title="Remove format filter"
                    aria-label={`Remove ${selectedFormat} format filter`}
                  >
                    <X size={11} />
                  </button>
                </span>
              )}
              {searchTerm.trim() !== '' && (
                <span className="active-filter-pill">
                  <span className="pill-key">search:</span>
                  <span className="pill-val">"{searchTerm.trim()}"</span>
                  <button
                    type="button"
                    onClick={() => setSearchTerm('')}
                    className="pill-remove-btn"
                    title="Clear search term"
                    aria-label="Clear search term"
                  >
                    <X size={11} />
                  </button>
                </span>
              )}
              <button
                type="button"
                onClick={handleClearAllFilters}
                className="btn btn-secondary btn-xs mono clear-all-filters-btn"
                title="Clear all active filters"
              >
                CLEAR ALL
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Syncing Progress Banner (displayed while preserving active UI) */}
      {syncing && (
        <div
          className="sync-progress-banner mono text-xs"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 16px',
            background: 'rgba(0, 255, 157, 0.08)',
            border: '1px solid rgba(0, 255, 157, 0.3)',
            borderRadius: '6px',
            marginBottom: '1.5rem',
            color: 'var(--text-accent)'
          }}
        >
          <LoadingSpinner inline size="sm" color="green" label="Synchronizing cloud datastore metrics... Currently loaded dataset remains interactive." />
        </div>
      )}

      {/* Error Notice with Retry Path */}
      {error && (
        <div className="error-banner" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
            <AlertTriangle size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Firestore Query Diagnostics:</strong> {error}
              {rawReports.length > 0 && (
                <p className="text-xs text-muted" style={{ marginTop: '4px' }}>
                  Preserving previously loaded dataset ({rawReports.length} reports).
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              if (!loading && !syncing && !loadingGadgets) {
                if (activeFilter === 'gadgets' && !gadgetsLoaded) {
                  loadGadgetsBatch(false);
                } else if (activeFilter === 'gadgets' && hasMoreGadgets) {
                  loadGadgetsBatch(true);
                } else {
                  fetchData(true);
                }
              }
            }}
            disabled={loading || syncing || loadingGadgets}
            className="btn btn-secondary mono text-xs"
            style={{ flexShrink: 0, marginLeft: '16px' }}
            aria-label="Retry failed query operation"
          >
            RETRY
          </button>
        </div>
      )}

      {/* Initial Loading State Card */}
      {loading && (
        <LoadingSpinner
          asCard
          size="lg"
          color="green"
          label={`QUERYING CLOUD REPOSITORY (MAX ${REPORTS_BATCH_LIMIT} REPORTS)...`}
        />
      )}

      {/* Search Results Display */}
      {!loading && (
        <div className="results-container">
          {/* Section: Exploit Chain Reports */}
          {(activeFilter === 'all' || activeFilter === 'reports') && (
            <div className="results-section">
              <div className="results-section-header">
                <h2 className="section-header-title mono">
                  ==«✪»== Exploit Chain Reports ({formatReportCountMetrics({
                    catalogTotal: catalogTotalReports,
                    loadedCount: rawReports.length,
                    filteredCount: filteredReports.length
                  }).displayLabel}) ==«✪»==
                </h2>
              </div>

              <LazyList
                items={filteredReports}
                initialCount={3}
                step={3}
                emptyMessage={
                  hasActiveFilters ? (
                    <div className="empty-filter-state">
                      <p className="mono text-muted" style={{ marginBottom: '0.75rem' }}>
                        No exploit chain reports match active filters ({activeFilterSummary}).
                      </p>
                      <button
                        type="button"
                        onClick={handleClearAllFilters}
                        className="btn btn-secondary btn-xs mono"
                        aria-label="Reset all active filters"
                      >
                        RESET ALL FILTERS
                      </button>
                    </div>
                  ) : (
                    "No matching exploit chain reports found."
                  )
                }
                renderItem={(report, index) => (
                  <ReportCard
                    key={report.id || index}
                    report={report}
                    index={index + 1}
                    onSelectReportId={handleSelectReportId}
                    onOpenDetail={(r) => {
                      if (onInspectReport) {
                        onInspectReport(r);
                      } else if (onNavigateToBinary) {
                        onNavigateToBinary(r);
                      } else {
                        setSelectedReportForModal(r);
                        setSelectedReportIndex(index + 1);
                      }
                    }}
                  />
                )}
              />
            </div>
          )}

          {/* Section: Discovered Gadgets Grouped by Binary File */}
          {(activeFilter === 'all' || activeFilter === 'gadgets') && (
            <div className="results-section" style={{ marginTop: '2.5rem' }}>
              <div className="results-section-header">
                <h2 className="section-header-title mono">
                  ==«✪»== Discovered Gadgets ({gadgetsLoaded ? `${groupedGadgetsByFile.length} ${groupedGadgetsByFile.length === 1 ? 'Binary' : 'Binaries'} • ${filteredGadgets.length} Gadgets loaded` : 'Deferred / On-Demand'}) ==«✪»==
                </h2>
              </div>

              {!gadgetsLoaded ? (
                <div className="empty-state-card" style={{ padding: '2.5rem 1.5rem', textAlign: 'center' }}>
                  <Database size={28} className="text-accent-cyan" style={{ marginBottom: '0.75rem', opacity: 0.8 }} />
                  <h3 className="mono text-sm" style={{ marginBottom: '0.5rem', color: 'var(--text-main)' }}>
                    GADGET DATASTORE (DEFERRED TO OPTIMIZE INITIAL LOAD)
                  </h3>
                  <p className="mono text-dim text-xs" style={{ maxWidth: '540px', margin: '0 auto 1.25rem' }}>
                    Indexed disassembly gadgets are loaded on demand in bounded batches of {GADGETS_BATCH_LIMIT} documents to reduce bandwidth and Firestore read consumption.
                  </p>
                  <button
                    type="button"
                    onClick={() => loadGadgetsBatch(false)}
                    disabled={loadingGadgets}
                    className="btn btn-secondary mono text-xs"
                  >
                    {loadingGadgets ? (
                      <LoadingSpinner inline size="sm" color="cyan" label={`RETRIEVING GADGETS (BATCH OF ${GADGETS_BATCH_LIMIT})...`} />
                    ) : (
                      <>
                        <Database size={14} />
                        <span>LOAD GADGETS (BATCH OF {GADGETS_BATCH_LIMIT})</span>
                      </>
                    )}
                  </button>
                </div>
              ) : groupedGadgetsByFile.length === 0 ? (
                <div className="empty-state-card" style={{ padding: '2rem', textAlign: 'center' }}>
                  <span className="mono text-dim text-xs" style={{ display: 'block', marginBottom: hasActiveFilters ? '0.75rem' : 0 }}>
                    {hasActiveFilters
                      ? `No gadgets match active filters (${activeFilterSummary}).`
                      : 'No matching gadgets found for the selected query.'}
                  </span>
                  {hasActiveFilters && (
                    <button
                      type="button"
                      onClick={handleClearAllFilters}
                      className="btn btn-secondary btn-xs mono"
                      aria-label="Reset all active filters"
                    >
                      RESET ALL FILTERS
                    </button>
                  )}
                </div>
              ) : (
                <>
                  <LazyList
                    items={groupedGadgetsByFile}
                    initialCount={3}
                    step={3}
                    containerClassName="grouped-gadgets-lazy"
                    emptyMessage="No matching binary gadget groups found."
                    renderItem={(group, idx) => (
                      <BinaryGadgetGroup
                        key={group.cleanName || idx}
                        group={group}
                        index={idx + 1}
                        defaultExpanded={idx === 0}
                        onInspect={(r) => {
                          if (onInspectReport) {
                            onInspectReport(r);
                          } else if (onNavigateToBinary) {
                            onNavigateToBinary(r);
                          } else {
                            const repId = r.report_id || r.id;
                            window.location.hash = `#/report/${encodeURIComponent(repId)}`;
                          }
                        }}
                        onSelectBinary={handleSelectBinary}
                      />
                    )}
                  />

                  {/* Cursor-Based Gadget Pagination Button */}
                  {hasMoreGadgets && (
                    <div style={{ textAlign: 'center', marginTop: '1.5rem', marginBottom: '1.5rem' }}>
                      <button
                        type="button"
                        onClick={() => loadGadgetsBatch(true)}
                        disabled={loadingGadgets}
                        className="btn btn-secondary mono text-xs"
                      >
                        {loadingGadgets ? (
                          <LoadingSpinner inline size="sm" color="cyan" label={`RETRIEVING NEXT ${GADGETS_BATCH_LIMIT} GADGETS...`} />
                        ) : (
                          <>
                            <RefreshCw size={14} />
                            <span>LOAD NEXT {GADGETS_BATCH_LIMIT} GADGETS ({rawGadgets.length} LOADED)</span>
                          </>
                        )}
                      </button>
                    </div>
                  )}

                  {/* Gadget pagination completion banner */}
                  {!hasMoreGadgets && rawGadgets.length > 0 && !loadingGadgets && !error && (
                    <div className="gadget-completion-banner mono text-xs">
                      <Check size={14} className="text-accent-green" />
                      <span>All {rawGadgets.length} indexed gadgets loaded from cloud repository.</span>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* Comprehensive Report Detail Modal */}
      {selectedReportForModal && (
        <ReportDetailModal
          report={selectedReportForModal}
          index={selectedReportIndex}
          onClose={() => setSelectedReportForModal(null)}
        />
      )}
    </div>
  );
}
