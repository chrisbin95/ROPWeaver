import React from 'react';
import { Cpu, FileCode2, Database, RefreshCw, Radio } from 'lucide-react';

export default function StatsPanel({
  stats,
  recentBinaries,
  loading,
  onRefresh,
  onSelectBinary,
  onSelectArch
}) {
  return (
    <div className="stats-panel-card">
      <div className="stats-panel-header">
        <div className="stats-header-left">
          <Radio size={16} className="text-accent-green pulse-glow" />
          <span className="mono stats-title">ropweaver &gt; cloud_telemetry</span>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="btn btn-secondary btn-icon-only refresh-btn"
          title="Refresh Firestore Metrics"
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span className="mono text-xs">SYNC</span>
        </button>
      </div>

      {/* Main KPI Counters */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-icon-wrap green">
            <FileCode2 size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">{stats.totalReports}</span>
            <span className="kpi-label">Exploit Reports</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap cyan">
            <Database size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">{stats.totalGadgets}</span>
            <span className="kpi-label">Indexed Gadgets</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon-wrap orange">
            <Cpu size={20} />
          </div>
          <div className="kpi-info">
            <span className="kpi-value mono">{recentBinaries.length}</span>
            <span className="kpi-label">Target Binaries</span>
          </div>
        </div>
      </div>

      {/* Sub-breakdowns: Architectures & Formats */}
      <div className="breakdown-grid">
        {/* Architectures */}
        <div className="breakdown-col">
          <span className="breakdown-header mono">&gt; by_architecture</span>
          <div className="chips-row">
            {Object.entries(stats.archCounts).map(([arch, count]) => (
              <button
                key={arch}
                onClick={() => onSelectArch(arch)}
                className={`stat-chip ${count > 0 ? 'stat-chip-active' : ''}`}
                title={`Filter by ${arch}`}
              >
                <span className="stat-chip-name">{arch}</span>
                <span className="stat-chip-badge mono">{count}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Binary Formats */}
        <div className="breakdown-col">
          <span className="breakdown-header mono">&gt; by_binary_type</span>
          <div className="chips-row">
            {Object.entries(stats.typeCounts).map(([type, count]) => (
              <span key={type} className={`stat-chip ${count > 0 ? 'stat-chip-active' : ''}`}>
                <span className="stat-chip-name">{type}</span>
                <span className="stat-chip-badge mono">{count}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Binary Chips */}
      {recentBinaries.length > 0 && (
        <div className="recent-binaries-bar">
          <span className="mono text-muted text-xs">&gt; available_in_cloud:</span>
          <div className="binary-chips-list">
            {recentBinaries.map((bin) => (
              <button
                key={bin}
                onClick={() => onSelectBinary(bin)}
                className="binary-chip mono"
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
