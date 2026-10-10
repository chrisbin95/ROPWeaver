import React, { useState } from 'react';
import { 
  Shield, ChevronDown, ChevronUp, Copy, Check, Terminal, 
  ExternalLink, Code2, Cpu, Eye, FileCode
} from 'lucide-react';

export default function ReportCard({ report, index, onSelectReportId, onOpenDetail }) {
  const [showGadgets, setShowGadgets] = useState(false);
  const [showPayload, setShowPayload] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [gadgetFilter, setGadgetFilter] = useState('');

  // Extract fields cleanly
  const getBinaryName = () => {
    if (!report) return 'N/A';
    if (typeof report.target_binary === 'string') return report.target_binary;
    if (report.target_binary && typeof report.target_binary.filename === 'string') return report.target_binary.filename;
    if (report["file name"]) return report["file name"];
    if (report.binary_name) return report.binary_name;
    return 'N/A';
  };

  const getArch = () => {
    return report.architecture || (report.binary_analysis && report.binary_analysis.architecture) || 'x86_64';
  };

  const getFormat = () => {
    if (report.format) return report.format;
    if (report.binary_analysis && report.binary_analysis.format) return report.binary_analysis.format;
    const path = getBinaryName().toLowerCase();
    if (path.endsWith('.exe')) return 'PE';
    if (path.endsWith('.dylib')) return 'Mach-O';
    return 'ELF';
  };

  const binPath = getBinaryName();
  const binName = binPath.split(/[/\\]/).pop();
  const arch = getArch();
  const format = getFormat();
  const reportId = report.report_id || report.id || 'ROPW-N/A';
  const date = report.report_date || (report.timestamp && report.timestamp.toDate ? report.timestamp.toDate().toLocaleString() : 'N/A');

  const summary = report.summary || (report.rop_chain_generation ? {
    chain_type: report.rop_chain_generation.target_syscall || 'execve',
    success: (report.rop_chain_generation.status || "").toLowerCase().includes("success"),
    notes: report.rop_chain_generation.chain_notes || 'Attempted ROP chain generation.'
  } : null);

  const rawProts = report.protections || (report.binary_analysis && report.binary_analysis.hardening_features);
  const hasMitigations = rawProts && Object.keys(rawProts).length > 0;

  const chainSteps = report.rop_chain || (report.rop_chain_details && report.rop_chain_details.chain_steps) || [];
  const gadgetsList = report.gadgets || [];
  const rawPayload = report.raw_payload;

  const handleCopyId = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(reportId);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleCopyPayload = () => {
    if (rawPayload && rawPayload.data) {
      navigator.clipboard.writeText(rawPayload.data);
      setCopiedPayload(true);
      setTimeout(() => setCopiedPayload(false), 2000);
    }
  };

  // Filter gadgets inside report
  const filteredGadgets = gadgetsList.filter(g => {
    if (!gadgetFilter) return true;
    const term = gadgetFilter.toLowerCase();
    const instr = (g.gadget || g.instructions || '').toLowerCase();
    const addr = (g.address || '').toLowerCase();
    return instr.includes(term) || addr.includes(term);
  });

  const handleInspect = (e) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    const repId = report.report_id || report.id || binName;
    window.location.hash = `#/report/${encodeURIComponent(repId)}`;
    if (onOpenDetail) {
      onOpenDetail(report);
    }
  };

  return (
    <div className="report-card">
      {/* Top Banner */}
      <div className="report-card-top">
        <div className="report-title-group">
          {index && <span className="report-card-index mono">#{index}</span>}
          <Terminal size={18} className="text-accent-green" />
          <span 
            className="report-binary-name mono clickable-title"
            onClick={handleInspect}
            title="Click to view detailed report"
          >
            {binName}
          </span>
          <span className="badge badge-info mono">{arch}</span>
          <span className="badge badge-warning mono">{format}</span>
        </div>

        <div className="report-top-actions">
          <div className="report-id-badge" onClick={handleCopyId} title="Click to copy Report ID">
            <span className="mono text-xs">{reportId}</span>
            {copiedId ? <Check size={13} className="text-accent-green" /> : <Copy size={13} className="text-dim" />}
          </div>

          <button
            type="button"
            onClick={handleInspect}
            className="btn btn-outline-green btn-xs mono report-inspect-btn"
            title="View full comprehensive report"
          >
            <Eye size={13} />
            <span>INSPECT REPORT</span>
          </button>
        </div>
      </div>

      {/* Date & Subtitle */}
      <div className="report-date-line mono text-dim text-xs">
        <span>Path: <strong className="text-muted">{binPath}</strong></span>
        {date !== 'N/A' && <span> &bull; Executed: {date}</span>}
      </div>

      {/* Security Hardening Protections — ALWAYS VISIBLE */}
      <div className="protections-bar">
        <span className="mono text-muted text-xs protec-label">
          <Shield size={13} className="text-accent-green" /> MITIGATIONS:
        </span>
        <div className="badges-group">
          {hasMitigations ? (
            <>
              <span className={`badge ${rawProts.NX || rawProts.nx_enabled ? 'badge-on' : 'badge-off'}`}>
                NX: {rawProts.NX || rawProts.nx_enabled ? 'ON' : 'OFF'}
              </span>
              <span className={`badge ${rawProts.PIE || rawProts.pie_enabled ? 'badge-on' : 'badge-off'}`}>
                PIE: {rawProts.PIE || rawProts.pie_enabled ? 'ON' : 'OFF'}
              </span>
              <span className={`badge ${rawProts.Canary || rawProts.canary_enabled ? 'badge-on' : 'badge-off'}`}>
                Canary: {rawProts.Canary || rawProts.canary_enabled ? 'ON' : 'OFF'}
              </span>
              <span className="badge badge-warning">
                RELRO: {rawProts.RELRO || (rawProts.relro_full ? 'Full' : rawProts.relro_partial ? 'Partial' : 'None')}
              </span>
            </>
          ) : (
            <span className="badge badge-none mono">
              None (All Protections Disabled / RAW)
            </span>
          )}
        </div>
      </div>

      {/* Chain Status Summary */}
      {summary && (
        <div className={`summary-box ${summary.success ? 'summary-success' : 'summary-failed'}`}>
          <div className="summary-status-line">
            <span className="mono font-bold">
              STATUS: <span className={summary.success ? 'text-accent-green' : 'text-accent-red'}>
                {summary.success ? 'SUCCESS (Execve Chain Verified)' : 'PARTIAL / FAILED'}
              </span>
            </span>
            {summary.chain_type && (
              <span className="badge badge-info mono">{summary.chain_type}</span>
            )}
          </div>
          {summary.notes && (
            <p className="summary-notes mono text-muted text-xs">{summary.notes}</p>
          )}
        </div>
      )}

      {/* ROP Chain Steps (Overflow container) */}
      {Array.isArray(chainSteps) && chainSteps.length > 0 && (
        <div className="chain-container">
          <div className="chain-header">
            <Code2 size={15} className="text-accent-orange" />
            <span className="mono font-semibold text-xs text-accent-orange">
              ROP CHAIN DISPATCH ({chainSteps.length} STEPS)
            </span>
          </div>
          <div className="chain-steps-scroll overflow-container">
            {chainSteps.map((step, idx) => {
              const stepNum = step.step || step.index || (idx + 1);
              const addr = step.address || step.gadget_address || 'N/A';
              const desc = step.description || step.comment || step.assembly || '';
              return (
                <div key={idx} className="chain-step-row mono">
                  <span className="step-tag">[Step {stepNum}]</span>
                  <span className="step-addr">{addr}</span>
                  <span className="step-arrow">&rarr;</span>
                  <span className="step-desc text-accent-green">{desc}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Discovered Gadgets Accordion (Overflow container) */}
      {Array.isArray(gadgetsList) && gadgetsList.length > 0 && (
        <div className="collapsible-section">
          <button
            onClick={() => setShowGadgets(!showGadgets)}
            className="collapsible-toggle"
          >
            <span className="mono text-accent-cyan font-semibold text-xs">
              &gt; Discovered Gadgets ({gadgetsList.length})
            </span>
            {showGadgets ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showGadgets && (
            <div className="collapsible-body fade-in">
              <div className="gadgets-search-mini">
                <input
                  type="text"
                  placeholder="Filter within gadgets..."
                  value={gadgetFilter}
                  onChange={(e) => setGadgetFilter(e.target.value)}
                  className="mini-input mono text-xs"
                />
                <span className="mono text-dim text-xs">
                  {filteredGadgets.length} / {gadgetsList.length}
                </span>
              </div>
              <div className="gadgets-pre-scroll overflow-container">
                <table className="gadgets-mini-table mono text-xs">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Instructions</th>
                      <th>Category</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGadgets.map((g, idx) => (
                      <tr key={idx}>
                        <td className="addr-cell">{g.address || 'N/A'}</td>
                        <td className="instr-cell text-accent-green">
                          {g.gadget || g.instructions || ''}
                        </td>
                        <td className="cat-cell text-dim">
                          {g.category || 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Raw Payload Section (Overflow container) */}
      {rawPayload && rawPayload.data && (
        <div className="collapsible-section">
          <button
            onClick={() => setShowPayload(!showPayload)}
            className="collapsible-toggle"
          >
            <span className="mono text-accent-orange font-semibold text-xs">
              &gt; Exploit Raw Payload ({rawPayload.format || 'python_hex_string'})
            </span>
            {showPayload ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showPayload && (
            <div className="collapsible-body fade-in">
              <div className="payload-action-bar">
                <span className="mono text-dim text-xs">
                  Padding: {rawPayload.padding_size || 104} bytes
                </span>
                <button
                  onClick={handleCopyPayload}
                  className="btn btn-secondary btn-xs mono"
                >
                  {copiedPayload ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
                  <span>{copiedPayload ? 'COPIED!' : 'COPY PAYLOAD'}</span>
                </button>
              </div>
              <div className="payload-box overflow-container">
                <pre className="payload-code mono text-xs text-accent-green">
                  {rawPayload.data}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
