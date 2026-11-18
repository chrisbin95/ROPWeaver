import React from 'react';
import { Cpu, FileCode2, Database, RefreshCw, Radio } from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';

export default function StatsPanel({
  stats,
  recentBinaries,
  loading,
  syncing = false,
  onRefresh,
  onSelectBinary,
  onSelectArch,
  selectedArch = 'all',
  selectedFormat = 'all',
  onSelectFormat
}) {
  return (
    <div className="stats-panel-card">
      <div className="stats-panel-header">
        <div className="stats-header-left">
          <Radio size={16} className="text-accent-green pulse-glow" />
          <h2 className="mono stats-title">ropweaver &gt; cloud_telemetry</h2>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading || syncing}
          className="btn btn-secondary btn-icon-only refresh-btn"
          title={syncing ? "Syncing Firestore..." : "Refresh Firestore Metrics"}
          aria-label={syncing ? "Syncing Firestore..." : "Refresh Firestore Metrics"}
        >
          {syncing ? (
            <LoadingSpinner inline size="sm" color="cyan" srLabel="Syncing Firestore..." />
          ) : (
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
          )}
          <span className="mono text-xs">{syncing ? 'SYNCING...' : 'SYNC'}</span>
        </button>
      </div>

      {/* Main KPI Counters */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-icon-wrap green">
            <FileCode2 size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">
              {loading ? (
                <LoadingSpinner inline size="sm" color="muted" srLabel="Loading exploit reports metric..." />
              ) : stats.isCatalogTotalKnown === false || stats.totalReports === null ? (
                `${stats.loadedReports ?? 0}`
              ) : stats.isPartial ? (
                `${stats.loadedReports} / ${stats.totalReports}`
              ) : (
                stats.totalReports
              )}
            </span>
            <span className="kpi-label">
              {stats.isCatalogTotalKnown === false || stats.totalReports === null
                ? 'Exploit Reports (Loaded Sample)'
                : stats.isPartial
                ? 'Reports (Loaded / Catalog)'
                : 'Exploit Reports'}
            </span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap cyan">
            <Database size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">
              {loading ? (
                <LoadingSpinner inline size="sm" color="muted" srLabel="Loading gadgets metric..." />
              ) : stats.gadgetsLoaded === false ? (
                'Deferred'
              ) : (
                stats.totalGadgets
              )}
            </span>
            <span className="kpi-label">
              {stats.gadgetsLoaded === false ? 'Gadgets (On-Demand)' : 'Indexed Gadgets (Loaded)'}
            </span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap orange">
            <Cpu size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">
              {loading ? (
                <LoadingSpinner inline size="sm" color="muted" srLabel="Loading target binaries metric..." />
              ) : (
                recentBinaries.length
              )}
            </span>
            <span className="kpi-label">Target Binaries</span>
          </div>
        </div>
      </div>

      {/* Sub-breakdowns: Architectures & Formats */}
      <div className="breakdown-grid">
        {/* Architectures */}
        <div className="breakdown-col">
          <span className="breakdown-header mono">&gt; by_architecture (loaded sample)</span>
          <div className="chips-row">
            {Object.entries(stats.archCounts).map(([arch, count]) => {
              const isSelected = selectedArch === arch;
              return (
                <button
                  key={arch}
                  type="button"
                  onClick={() => onSelectArch && onSelectArch(isSelected ? 'all' : arch)}
                  className={`stat-chip ${count > 0 ? 'stat-chip-active' : ''} ${isSelected ? 'stat-chip-selected' : ''}`}
                  title={isSelected ? `Clear ${arch} filter` : `Filter by ${arch}`}
                  aria-pressed={isSelected}
                  aria-label={`Filter by ${arch} architecture (${count} reports)`}
                >
                  <span className="stat-chip-name">{arch}</span>
                  <span className="stat-chip-badge mono">{count}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Binary Formats */}
        <div className="breakdown-col">
          <span className="breakdown-header mono">&gt; by_binary_type (loaded sample)</span>
          <div className="chips-row">
            {Object.entries(stats.typeCounts).map(([type, count]) => {
              const isSelected = selectedFormat === type;
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => onSelectFormat && onSelectFormat(isSelected ? 'all' : type)}
                  className={`stat-chip ${count > 0 ? 'stat-chip-active' : ''} ${isSelected ? 'stat-chip-selected' : ''}`}
                  title={isSelected ? `Clear ${type} filter` : `Filter by ${type}`}
                  aria-pressed={isSelected}
                  aria-label={`Filter by ${type} binary format (${count} reports)`}
                >
                  <span className="stat-chip-name">{type}</span>
                  <span className="stat-chip-badge mono">{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Quick Binary Chips */}
      {recentBinaries.length > 0 && (
        <div className="recent-binaries-bar">
          <span className="mono text-muted text-xs">&gt; available_in_cloud:</span>
          <div className="binary-chips-list">
            {recentBinaries.map((bin, idx) => (
              <button
                key={`${bin}-${idx}`}
                type="button"
                onClick={() => onSelectBinary(bin)}
                className="binary-chip mono"
                title={`Filter by target binary ${bin}`}
                aria-label={`Filter by target binary ${bin}`}
              >
                {bin}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
