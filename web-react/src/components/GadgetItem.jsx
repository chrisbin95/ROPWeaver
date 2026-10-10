import React, { useState } from 'react';
import { Copy, Check, Terminal, Cpu, Hash } from 'lucide-react';

export default function GadgetItem({ gadget, index, onSelectReportId, onSelectBinary }) {
  const [copiedAddr, setCopiedAddr] = useState(false);
  const [copiedInstr, setCopiedInstr] = useState(false);

  const fileName = gadget["file name"] || gadget.fileName || gadget.binary_name || 'N/A';
  const hash = gadget.hash || 'N/A';
  const arch = gadget.architecture || 'N/A';
  const instr = gadget.instructions || gadget.gadget || '[no instruction]';
  const offset = gadget.offset || '0';
  const address = gadget.address || 'N/A';
  const category = gadget.category || 'ELF';
  const reportId = gadget.report_id || gadget.reportId || '';

  const handleCopyAddr = () => {
    navigator.clipboard.writeText(address);
    setCopiedAddr(true);
    setTimeout(() => setCopiedAddr(false), 2000);
  };

  const handleCopyInstr = () => {
    navigator.clipboard.writeText(instr);
    setCopiedInstr(true);
    setTimeout(() => setCopiedInstr(false), 2000);
  };

  return (
    <div className="gadget-item-card">
      <div className="gadget-item-header">
        <div className="gadget-target-meta">
          {index && <span className="report-card-index mono">#{index}</span>}
          <button
            onClick={() => onSelectBinary(fileName)}
            className="gadget-bin-link mono font-semibold"
            title={`Filter by ${fileName}`}
          >
            <Terminal size={14} className="text-accent-green" />
            <span>{fileName}</span>
          </button>
          <span className="badge badge-info">{arch}</span>
          <span className="badge badge-warning">{category}</span>
        </div>

        <div className="gadget-addr-group">
          <button
            onClick={handleCopyAddr}
            className="addr-pill mono"
            title="Click to copy memory address"
          >
            <span>{address}</span>
            {copiedAddr ? <Check size={12} className="text-accent-green" /> : <Copy size={12} className="text-dim" />}
          </button>
          {offset && offset !== '0' && (
            <span className="offset-pill mono text-dim text-xs">+{offset}</span>
          )}
        </div>
      </div>

      {/* Assembly Instruction Line */}
      <div className="gadget-instr-bar">
        <div className="gadget-instr-text mono text-accent-green font-bold">
          {instr}
        </div>
        <button
          onClick={handleCopyInstr}
          className="copy-mini-btn gadget-copy-asm-btn"
          title="Copy ASM instructions"
        >
          {copiedInstr ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
          <span>{copiedInstr ? 'COPIED' : 'COPY ASM'}</span>
        </button>
      </div>

      {/* Bottom Metadata: Hash & Report ID */}
      <div className="gadget-item-footer mono text-xs text-dim">
        {hash !== 'N/A' && (
          <div className="gadget-footer-item">
            <Hash size={12} />
            <span className="hash-val" title={hash}>{hash.slice(0, 16)}...</span>
          </div>
        )}

        {reportId && (
          <div className="gadget-footer-item">
            <span>REPORT:</span>
            <button
              onClick={() => onSelectReportId(reportId)}
              className="report-id-link text-accent-cyan"
            >
              {reportId}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
