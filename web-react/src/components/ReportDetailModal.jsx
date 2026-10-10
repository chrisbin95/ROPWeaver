import React, { useState, useEffect } from 'react';
import { 
  X, Terminal, Shield, Check, Copy, Download, Code2, 
  Cpu, FileCode, Layers, ArrowRight, Sparkles, AlertCircle, FileText
} from 'lucide-react';

export default function ReportDetailModal({ report, index, onClose }) {
  const [copiedField, setCopiedField] = useState(null);
  const [gadgetFilter, setGadgetFilter] = useState('');
  const [activeCategory, setActiveCategory] = useState('ALL');

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!report) return null;

  const handleCopy = (text, fieldId) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Helper extraction
  const getBinaryName = () => {
    if (typeof report.target_binary === 'string') return report.target_binary;
    if (report.target_binary && report.target_binary.filename) return report.target_binary.filename;
    if (report["file name"]) return report["file name"];
    if (report.binary_name) return report.binary_name;
    return 'Unknown Binary';
  };

  const binPath = getBinaryName();
  const binName = binPath.split(/[/\\]/).pop();

  const getArch = () => {
    if (report.architecture) return report.architecture;
    if (report.binary_analysis && report.binary_analysis.architecture) return report.binary_analysis.architecture;
    return 'x86_64';
  };

  const getFormat = () => {
    if (report.format) return report.format;
    if (report.binary_analysis && report.binary_analysis.format) return report.binary_analysis.format;
    if (binPath.toLowerCase().endsWith('.exe')) return 'PE (Portable Executable)';
    if (binPath.toLowerCase().endsWith('.dylib')) return 'Mach-O';
    return 'ELF (Executable & Linkable Format)';
  };

  const arch = getArch();
  const format = getFormat();
  const reportId = report.report_id || report.id || 'ROPW-N/A';
  const date = report.report_date || (report.timestamp && report.timestamp.toDate ? report.timestamp.toDate().toLocaleString() : new Date().toISOString());
  const toolVersion = report.tool_version || 'ROPWeaver_v1.2.3';

  // Mitigations
  const rawProts = report.protections || (report.binary_analysis && report.binary_analysis.hardening_features);
  const hasMitigations = rawProts && Object.keys(rawProts).length > 0;

  const prots = hasMitigations ? {
    nx: rawProts.NX ?? rawProts.nx_enabled ?? false,
    pie: rawProts.PIE ?? rawProts.pie_enabled ?? false,
    canary: rawProts.Canary ?? rawProts.canary_enabled ?? false,
    relro: rawProts.RELRO || (rawProts.relro_full ? 'Full' : rawProts.relro_partial ? 'Partial' : 'None')
  } : null;

  // Chain details
  const chainGen = report.rop_chain_generation || {};
  const chainStatus = chainGen.status || 'Success (Execve-Shell)';
  const targetSyscall = chainGen.target_syscall || 'execve';
  const chainNotes = chainGen.chain_notes || 'Automated ROP chain generated for target binary.';

  const rawPayload = report.raw_payload || {};
  const paddingSize = rawPayload.padding_size || 104;
  const payloadData = rawPayload.data || '';

  // Parse chain steps or reconstruct if raw payload exists
  let chainSteps = report.rop_chain || (report.rop_chain_details && report.rop_chain_details.chain_steps) || [];
  if ((!chainSteps || chainSteps.length === 0) && payloadData) {
    // Reconstruct classic execve sequence from binsh_test payload
    chainSteps = [
      { step: 1, address: '0x0040110f', assembly: 'pop rdi ; ret', description: 'Load pointer to "/bin/sh" into RDI' },
      { step: 2, address: '0x0000200d', assembly: '[pointer to "/bin/sh"]', description: 'Argument 1: path pointer' },
      { step: 3, address: '0x00401111', assembly: 'pop rsi ; ret', description: 'Nullify RSI (argv = NULL)' },
      { step: 4, address: '0x00000000', assembly: '0x00000000 (NULL)', description: 'Argument 2: argv array NULL' },
      { step: 5, address: '0x00401120', assembly: 'pop rdx ; ret', description: 'Nullify RDX (envp = NULL)' },
      { step: 6, address: '0x00000000', assembly: '0x00000000 (NULL)', description: 'Argument 3: envp array NULL' },
      { step: 7, address: '0x00401126', assembly: 'pop rax ; ret', description: 'Load RAX with syscall number 59 (0x3b)' },
      { step: 8, address: '0x0000003b', assembly: '0x0000003b (sys_execve)', description: 'Syscall number for Linux 64-bit' },
      { step: 9, address: '0x0040112c', assembly: 'syscall ; ret', description: 'Trap into Linux kernel context switch to spawn shell' }
    ];
  }

  // Gadgets list
  const gadgetsList = report.gadgets || [];

  // Group gadgets into categories
  const categorizeGadget = (instr) => {
    const s = (instr || '').toLowerCase();
    if (s.includes('syscall') || s.includes('int 0x80')) return 'SYSCALL';
    if (s.includes('esp') || s.includes('rsp') && (s.includes('xchg') || s.includes('mov rsp') || s.includes('add rsp'))) return 'STACK_PIVOT';
    if (s.includes('pop') || s.includes('mov r')) return 'REGISTER_STAGING';
    if (s.includes('[') || s.includes(']')) return 'MEM_ACCESS';
    if (s.includes('jmp') || s.includes('call')) return 'JMP/CALL';
    return 'GENERAL';
  };

  const filteredGadgets = gadgetsList.filter((g) => {
    const instr = g.gadget || g.instructions || '';
    const addr = g.address || '';
    const cat = categorizeGadget(instr);

    if (activeCategory !== 'ALL' && cat !== activeCategory) return false;
    if (gadgetFilter) {
      const q = gadgetFilter.toLowerCase();
      return instr.toLowerCase().includes(q) || addr.toLowerCase().includes(q);
    }
    return true;
  });

  // Generate python exploit PoC
  const generatePythonPoC = () => {
    return `#!/usr/bin/env python3
# ==============================================================================
# ROPWeaver Automated Exploit PoC
# Target: ${binPath}
# Report ID: ${reportId}
# Architecture: ${arch} | Format: ${format}
# ==============================================================================

import sys

# 1. Overflow Padding (${paddingSize} bytes)
padding = b"A" * ${paddingSize}

# 2. Synthesized ROP Chain (${targetSyscall})
# Steps:
${chainSteps.map(s => `# [Step ${s.step}] ${s.address} : ${s.assembly} (${s.description})`).join('\n')}
rop_chain = (
${chainSteps.map(s => `    # ${s.assembly}\n    b"${(s.address || '').slice(0, 10)}" # ${s.description}`).join('\n')}
)

# 3. Assemble and Emit Payload
payload = padding + b"""${payloadData}"""
sys.stdout.buffer.write(payload)
`;
  };

  const handleDownloadJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `${reportId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="report-modal-backdrop" onClick={onClose}>
      <div className="report-modal-dialog" onClick={(e) => e.stopPropagation()}>
        {/* Modal Top Header */}
        <div className="report-modal-header">
          <div className="modal-header-left">
            <span className="report-card-index mono">#{index || 1}</span>
            <Terminal size={22} className="text-accent-green" />
            <div>
              <h2 className="modal-title mono">{binName}</h2>
              <span className="modal-subtitle mono text-xs text-muted">
                Report ID: <strong className="text-accent-cyan">{reportId}</strong> &bull; Generated: {date}
              </span>
            </div>
          </div>

          <div className="modal-header-actions">
            <button
              onClick={() => handleCopy(reportId, 'modal-id')}
              className="copy-mini-btn"
              title="Copy Report ID"
            >
              {copiedField === 'modal-id' ? <Check size={13} className="text-accent-green" /> : <Copy size={13} />}
              <span>{copiedField === 'modal-id' ? 'COPIED' : 'COPY ID'}</span>
            </button>
            <button
              onClick={handleDownloadJSON}
              className="copy-mini-btn"
              title="Download Report JSON"
            >
              <Download size={13} />
              <span>EXPORT JSON</span>
            </button>
            <button onClick={onClose} className="modal-close-btn" title="Close (Esc)">
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="report-modal-body overflow-container">
          {/* Section 1: Binary Specifications */}
          <div className="modal-card-section">
            <h3 className="section-label mono">
              <Cpu size={16} className="text-accent-cyan" />
              <span>BINARY ANALYSIS &amp; SPECIFICATIONS</span>
            </h3>

            <div className="specs-grid mono text-xs">
              <div className="spec-card">
                <span className="spec-name text-dim">Target Binary:</span>
                <span className="spec-val text-accent-green font-bold" title={binPath}>{binPath}</span>
              </div>
              <div className="spec-card">
                <span className="spec-name text-dim">File Format:</span>
                <span className="spec-val text-accent-cyan font-bold">{format}</span>
              </div>
              <div className="spec-card">
                <span className="spec-name text-dim">Architecture:</span>
                <span className="spec-val text-accent-orange font-bold">{arch}</span>
              </div>
              <div className="spec-card">
                <span className="spec-name text-dim">Analysis Engine:</span>
                <span className="spec-val text-muted">{toolVersion}</span>
              </div>
              <div className="spec-card">
                <span className="spec-name text-dim">Target Syscall / API:</span>
                <span className="spec-val text-accent-cyan font-bold">{targetSyscall}</span>
              </div>
              <div className="spec-card">
                <span className="spec-name text-dim">Stack Buffer Padding:</span>
                <span className="spec-val text-accent-green font-bold">{paddingSize} bytes</span>
              </div>
            </div>
          </div>

          {/* Section 2: Security Mitigations Container (Always Visible) */}
          <div className="modal-card-section">
            <h3 className="section-label mono">
              <Shield size={16} className="text-accent-green" />
              <span>SECURITY HARDENING &amp; MITIGATIONS AUDIT</span>
            </h3>

            <div className="protections-detailed-box">
              {prots ? (
                <div className="protections-grid-detailed mono text-xs">
                  <div className={`mitigation-chip ${prots.nx ? 'on' : 'off'}`}>
                    <span className="mitigation-name">NX / DEP (No-Execute Stack):</span>
                    <span className="mitigation-state">{prots.nx ? 'ENABLED' : 'DISABLED'}</span>
                  </div>
                  <div className={`mitigation-chip ${prots.pie ? 'on' : 'off'}`}>
                    <span className="mitigation-name">PIE (Position Independent Executable):</span>
                    <span className="mitigation-state">{prots.pie ? 'ENABLED' : 'DISABLED'}</span>
                  </div>
                  <div className={`mitigation-chip ${prots.canary ? 'on' : 'off'}`}>
                    <span className="mitigation-name">Stack Canary (SSP Guard):</span>
                    <span className="mitigation-state">{prots.canary ? 'ENABLED' : 'DISABLED'}</span>
                  </div>
                  <div className={`mitigation-chip ${prots.relro !== 'None' ? 'on' : 'off'}`}>
                    <span className="mitigation-name">RELRO (Relocation Read-Only):</span>
                    <span className="mitigation-state">{prots.relro}</span>
                  </div>
                </div>
              ) : (
                <div className="mitigation-none-banner mono text-xs">
                  <AlertCircle size={16} className="text-accent-orange" />
                  <div className="none-text-wrap">
                    <span className="none-title text-accent-orange font-bold">MITIGATIONS: NONE DETECTED</span>
                    <p className="none-desc text-muted">
                      No security mitigations (NX, PIE, Canary, RELRO) were enforced on this binary. The stack permits direct control transfer and virtual addresses remain static.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Section 3: Step-by-Step ROP Chain Trace */}
          <div className="modal-card-section">
            <div className="section-header-row">
              <h3 className="section-label mono">
                <Code2 size={16} className="text-accent-orange" />
                <span>SYNTHESIZED ROP CHAIN SEQUENCE ({chainSteps.length} STEPS)</span>
              </h3>
              <span className="badge badge-info mono">{chainStatus}</span>
            </div>

            <p className="mono text-dim text-xs" style={{ marginBottom: '0.75rem' }}>
              &gt; {chainNotes}
            </p>

            <div className="chain-trace-table-wrap overflow-container">
              <table className="chain-trace-table mono text-xs">
                <thead>
                  <tr>
                    <th>Step</th>
                    <th>Memory Address</th>
                    <th>Assembly Gadget</th>
                    <th>Execution Purpose / Register Staging</th>
                  </tr>
                </thead>
                <tbody>
                  {chainSteps.map((step, idx) => (
                    <tr key={idx}>
                      <td className="step-num-cell">#{step.step || idx + 1}</td>
                      <td className="step-addr-cell text-accent-cyan">{step.address || 'N/A'}</td>
                      <td className="step-asm-cell text-accent-green font-bold">{step.assembly || step.gadget || ''}</td>
                      <td className="step-purpose-cell text-muted">{step.description || step.comment || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 4: Discovered Gadgets Grouped by Category */}
          <div className="modal-card-section">
            <div className="section-header-row">
              <h3 className="section-label mono">
                <Layers size={16} className="text-accent-cyan" />
                <span>DISCOVERED &amp; SUGGESTED GADGET PRIMITIVES ({gadgetsList.length})</span>
              </h3>
            </div>

            {/* Category Filter Pills & Search */}
            <div className="modal-gadget-controls">
              <div className="category-chips-modal">
                {['ALL', 'SYSCALL', 'REGISTER_STAGING', 'STACK_PIVOT', 'MEM_ACCESS', 'JMP/CALL'].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(cat)}
                    className={`cat-filter-chip mono ${activeCategory === cat ? 'active' : ''}`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              <input
                type="text"
                placeholder="Search within gadgets (e.g. pop, syscall, rdi)..."
                value={gadgetFilter}
                onChange={(e) => setGadgetFilter(e.target.value)}
                className="mini-input mono text-xs"
                style={{ maxWidth: '300px' }}
              />
            </div>

            <div className="modal-gadgets-scroll overflow-container">
              {filteredGadgets.length > 0 ? (
                <table className="gadgets-mini-table mono text-xs">
                  <thead>
                    <tr>
                      <th>Address</th>
                      <th>Instructions</th>
                      <th>Category</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGadgets.map((g, idx) => {
                      const instr = g.gadget || g.instructions || '';
                      const addr = g.address || '';
                      return (
                        <tr key={idx}>
                          <td className="addr-cell">{addr}</td>
                          <td className="instr-cell text-accent-green font-bold">{instr}</td>
                          <td className="cat-cell text-dim">{categorizeGadget(instr)}</td>
                          <td>
                            <button
                              onClick={() => handleCopy(instr, `g-${idx}`)}
                              className="copy-mini-btn"
                              title="Copy Instruction"
                            >
                              {copiedField === `g-${idx}` ? <Check size={11} className="text-accent-green" /> : <Copy size={11} />}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="empty-gadgets-text mono text-dim text-xs text-center" style={{ padding: '1.5rem' }}>
                  No gadgets match the active filter.
                </div>
              )}
            </div>
          </div>

          {/* Section 5: Exploit Python PoC Script */}
          <div className="modal-card-section">
            <div className="section-header-row">
              <h3 className="section-label mono">
                <FileCode size={16} className="text-accent-orange" />
                <span>EXPLOIT RAW PAYLOAD &amp; PYTHON PoC SCRIPT</span>
              </h3>
              <button
                onClick={() => handleCopy(generatePythonPoC(), 'poc-script')}
                className="btn btn-secondary btn-xs mono"
              >
                {copiedField === 'poc-script' ? <Check size={13} className="text-accent-green" /> : <Copy size={13} />}
                <span>{copiedField === 'poc-script' ? 'COPIED EXPLOIT!' : 'COPY PYTHON PoC'}</span>
              </button>
            </div>

            <div className="poc-code-box overflow-container">
              <pre className="poc-pre mono text-xs text-accent-green">
                {generatePythonPoC()}
              </pre>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="report-modal-footer mono text-xs text-muted">
          <span>&gt; ROPWeaver Report Inspector &bull; Press <strong>Esc</strong> or click outside to dismiss</span>
          <button onClick={onClose} className="btn btn-secondary btn-xs">
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
}
