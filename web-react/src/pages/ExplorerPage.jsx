import React, { useState, useEffect, useMemo } from 'react';
import { Search, RotateCcw, AlertTriangle, Layers, Filter, Terminal } from 'lucide-react';
import { db, collection, getDocs } from '../firebase/config';
import StatsPanel from '../components/StatsPanel';
import ReportCard from '../components/ReportCard';
import GadgetItem from '../components/GadgetItem';
import BinaryGadgetGroup from '../components/BinaryGadgetGroup';
import LazyList from '../components/LazyList';
import ReportDetailModal from '../components/ReportDetailModal';

export default function ExplorerPage({ onNavigateToBinary, onInspectReport }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeFilter, setActiveFilter] = useState('all'); // 'all', 'reports', 'gadgets'
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedReportForModal, setSelectedReportForModal] = useState(null);
  const [selectedReportIndex, setSelectedReportIndex] = useState(1);

  const [rawReports, setRawReports] = useState([]);
  const [rawGadgets, setRawGadgets] = useState([]);

  const [filteredReports, setFilteredReports] = useState([]);
  const [filteredGadgets, setFilteredGadgets] = useState([]);

  const [stats, setStats] = useState({
    totalReports: 0,
    totalGadgets: 0,
    archCounts: { "x86_64": 0, "i386": 0, "x86": 0, "arm": 0, "armv7": 0, "riscv": 0 },
    typeCounts: { "RAW": 0, "MACHO": 0, "ELF": 0, "PE": 0 }
  });

  const [recentBinaries, setRecentBinaries] = useState([]);

  // Fetch Firestore documents
  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [reportsSnap, gadgetsSnap] = await Promise.all([
        getDocs(collection(db, "reports")),
        getDocs(collection(db, "gadgets"))
      ]);

      const reportsList = [];
      const gadgetsList = [];
      const archCounts = { "x86_64": 0, "i386": 0, "x86": 0, "arm": 0, "armv7": 0, "riscv": 0 };
      const typeCounts = { "RAW": 0, "MACHO": 0, "ELF": 0, "PE": 0 };
      const binarySet = new Set();

      reportsSnap.forEach((doc) => {
        const d = { id: doc.id, ...doc.data() };
        reportsList.push(d);

        // Arch count
        const arch = (d.architecture || (d.binary_analysis && d.binary_analysis.architecture) || '').toLowerCase();
        if (archCounts.hasOwnProperty(arch)) archCounts[arch]++;

        // Binary name
        const binName = d.target_binary?.filename || d.target_binary || d["file name"] || d.binary_name;
        if (binName && typeof binName === 'string') {
          const cleanName = binName.split(/[/\\]/).pop();
          if (cleanName) binarySet.add(cleanName);
        }
      });

      gadgetsSnap.forEach((doc) => {
        const g = { id: doc.id, ...doc.data() };
        gadgetsList.push(g);

        const arch = (g.architecture || '').toLowerCase();
        if (archCounts.hasOwnProperty(arch)) archCounts[arch]++;

        const cat = (g.category || '').toUpperCase();
        if (typeCounts.hasOwnProperty(cat)) typeCounts[cat]++;

        const fileName = g["file name"] || g.fileName || g.binary_name;
        if (fileName && typeof fileName === 'string') {
          const cleanName = fileName.split(/[/\\]/).pop();
          if (cleanName) binarySet.add(cleanName);
        }
      });

      setRawReports(reportsList);
      setRawGadgets(gadgetsList);
      setFilteredReports(reportsList);
      setFilteredGadgets(gadgetsList);

      setStats({
        totalReports: reportsList.length,
        totalGadgets: gadgetsList.length,
        archCounts,
        typeCounts
      });

      setRecentBinaries(Array.from(binarySet));
    } catch (err) {
      console.error("Firestore fetch error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Filter logic
  const handleSearch = (termToSearch = searchTerm) => {
    const term = termToSearch.trim().toLowerCase();

    if (!term || term === 'all') {
      setFilteredReports(rawReports);
      setFilteredGadgets(rawGadgets);
      return;
    }

    const matchedReports = rawReports.filter((r) => {
      const bin = (r.target_binary?.filename || r.target_binary || r["file name"] || r.binary_name || '').toLowerCase();
      const repId = (r.report_id || r.id || '').toLowerCase();
      const arch = (r.architecture || (r.binary_analysis && r.binary_analysis.architecture) || '').toLowerCase();
      return bin.includes(term) || repId.includes(term) || arch.includes(term);
    });

    const matchedGadgets = rawGadgets.filter((g) => {
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

    setFilteredReports(matchedReports);
    setFilteredGadgets(matchedGadgets);
  };

  const onSearchSubmit = (e) => {
    e.preventDefault();
    handleSearch();
  };

  const handleSelectBinary = (binaryName) => {
    setSearchTerm(binaryName);
    handleSearch(binaryName);
  };

  const handleSelectArch = (arch) => {
    setSearchTerm(arch);
    handleSearch(arch);
  };

  const handleSelectReportId = (reportId) => {
    setSearchTerm(reportId);
    handleSearch(reportId);
  };

  const handleReset = () => {
    setSearchTerm('');
    setFilteredReports(rawReports);
    setFilteredGadgets(rawGadgets);
  };

  // Group filtered gadgets by binary file for structured, professional presentation
  const groupedGadgetsByFile = useMemo(() => {
    const map = new Map();

    filteredGadgets.forEach((g) => {
      const rawName = g["file name"] || g.fileName || g.binary_name || 'unknown_binary';
      const cleanName = (typeof rawName === 'string' ? rawName : 'binary').split(/[/\\]/).pop() || 'binary';

      if (!map.has(cleanName)) {
        // Find matching report in rawReports if exists
        const matchingReport = rawReports.find((r) => {
          const rName = (r.target_binary?.filename || r.target_binary || r["file name"] || r.binary_name || '').split(/[/\\]/).pop();
          const rId = r.report_id || r.id;
          const gRepId = g.report_id || g.reportId;
          return (gRepId && (rId === gRepId || r.id === gRepId)) || (rName && rName === cleanName);
        }) || null;

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
        onRefresh={fetchData}
        onSelectBinary={handleSelectBinary}
        onSelectArch={handleSelectArch}
      />

      {/* Search Input Bar */}
      <div className="search-section-card">
        <form onSubmit={onSearchSubmit} className="search-form-row">
          <div className="search-input-wrap">
            <Search size={18} className="search-icon text-muted" />
            <input
              type="text"
              className="search-input mono"
              placeholder="Enter binary name (e.g. binsh_test, p3), hash, address, or 'all'..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            {searchTerm && (
              <button
                type="button"
                onClick={handleReset}
                className="clear-search-btn text-muted"
                title="Clear input"
              >
                &times;
              </button>
            )}
          </div>

          <div className="search-actions-group">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Search size={15} />
              <span>SEARCH</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setSearchTerm('all');
                handleSearch('all');
              }}
              className="btn btn-secondary"
              disabled={loading}
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
              onClick={() => setActiveFilter('all')}
              className={`filter-btn ${activeFilter === 'all' ? 'filter-btn-active' : ''}`}
            >
              <span className="filter-btn-text">All Results</span>
              <span className="filter-btn-badge mono">
                {filteredReports.length + filteredGadgets.length}
              </span>
            </button>
            <button
              type="button"
              onClick={() => setActiveFilter('reports')}
              className={`filter-btn ${activeFilter === 'reports' ? 'filter-btn-active' : ''}`}
            >
              <span className="filter-btn-text">Reports</span>
              <span className="filter-btn-badge mono">
                {filteredReports.length}
              </span>
            </button>
            <button
              type="button"
              onClick={() => setActiveFilter('gadgets')}
              className={`filter-btn ${activeFilter === 'gadgets' ? 'filter-btn-active' : ''}`}
            >
              <span className="filter-btn-text">Gadgets</span>
              <span className="filter-btn-badge mono">
                {filteredGadgets.length}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Error Notice */}
      {error && (
        <div className="error-banner">
          <AlertTriangle size={20} />
          <div>
            <strong>Firestore Query Error:</strong> {error}
            <p className="text-xs text-muted" style={{ marginTop: '4px' }}>
              Verify that Firestore Rules in Firebase Console allow read access to `reports` and `gadgets`.
            </p>
          </div>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && (
        <div className="loading-state-card">
          <div className="cyber-spinner"></div>
          <span className="mono text-accent-green">SYNCING CLOUD DATASTORE...</span>
        </div>
      )}

      {/* Search Results Display */}
      {!loading && (
        <div className="results-container">
          {/* Section: Exploit Chain Reports */}
          {(activeFilter === 'all' || activeFilter === 'reports') && (
            <div className="results-section">
              <div className="results-section-header">
                <span className="section-header-title mono">
                  ==«✪»== Exploit Chain Reports ({filteredReports.length}) ==«✪»==
                </span>
              </div>

              <LazyList
                items={filteredReports}
                initialCount={3}
                step={3}
                emptyMessage="No matching exploit chain reports found."
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
                <span className="section-header-title mono">
                  ==«✪»== Discovered Gadgets Grouped by Binary ({groupedGadgetsByFile.length} {groupedGadgetsByFile.length === 1 ? 'Binary' : 'Binaries'} &bull; {filteredGadgets.length} Gadgets) ==«✪»==
                </span>
              </div>

              {groupedGadgetsByFile.length === 0 ? (
                <div className="empty-state-card" style={{ padding: '2rem', textAlign: 'center' }}>
                  <span className="mono text-dim text-xs">No matching gadgets found for the selected query.</span>
                </div>
              ) : (
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
