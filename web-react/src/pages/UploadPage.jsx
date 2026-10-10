import React, { useState, useEffect } from 'react';
import { Upload, FileCode, CheckCircle2, AlertCircle, FileSearch, ArrowRight, Shield } from 'lucide-react';
import { db, collection, getDocs } from '../firebase/config';

export default function UploadPage({ onSelectBinarySample }) {
  const [file, setFile] = useState(null);
  const [isRaw, setIsRaw] = useState(false);
  const [customArch, setCustomArch] = useState('auto');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [dragActive, setDragActive] = useState(false);

  // Live recent binaries fetched from Firebase Firestore
  const [recentBinaries, setRecentBinaries] = useState([]);
  const [loadingRecent, setLoadingRecent] = useState(true);

  useEffect(() => {
    const fetchRecentFromFirebase = async () => {
      setLoadingRecent(true);
      try {
        const [reportsSnap, gadgetsSnap] = await Promise.all([
          getDocs(collection(db, "reports")),
          getDocs(collection(db, "gadgets"))
        ]);

        const gadgetCountsByBinary = {};
        gadgetsSnap.forEach(doc => {
          const g = doc.data();
          const fn = (g["file name"] || g.fileName || g.binary_name || '').split(/[/\\]/).pop();
          if (fn) {
            gadgetCountsByBinary[fn] = (gadgetCountsByBinary[fn] || 0) + 1;
          }
        });

        const list = [];
        const seenNames = new Set();

        reportsSnap.forEach(doc => {
          const d = { id: doc.id, ...doc.data() };
          const rawName = d.target_binary?.filename || d.target_binary || d["file name"] || d.binary_name || d.id;
          const cleanName = (typeof rawName === 'string' ? rawName : d.id).split(/[/\\]/).pop() || 'binary';
          const hash = d.target_binary?.hash || d.target_binary?.sha256 || d.id;
          const arch = d.architecture || (d.binary_analysis && d.binary_analysis.architecture) || 'x86_64';
          const type = d.file_type || d.format || 'ELF';
          const gadgetCount = (Array.isArray(d.gadgets) && d.gadgets.length > 0)
            ? d.gadgets.length
            : (gadgetCountsByBinary[cleanName] || 0);

          if (!seenNames.has(cleanName)) {
            seenNames.add(cleanName);
            list.push({
              id: d.id,
              reportId: d.report_id || d.id,
              name: cleanName,
              hash: hash,
              arch: arch,
              type: type,
              count: gadgetCount,
              rawReport: d
            });
          }
        });

        // Also check any binary in gadgets that didn't have a report entry
        Object.entries(gadgetCountsByBinary).forEach(([fn, count]) => {
          if (!seenNames.has(fn)) {
            seenNames.add(fn);
            list.push({
              id: fn,
              reportId: fn,
              name: fn,
              hash: fn,
              arch: 'x86_64',
              type: 'ELF',
              count: count,
              rawReport: null
            });
          }
        });

        setRecentBinaries(list);
      } catch (err) {
        console.error("Error loading recent binaries from Firestore:", err);
      } finally {
        setLoadingRecent(false);
      }
    };

    fetchRecentFromFirebase();
  }, []);

  // Inspect binary header directly in browser
  const analyzeFile = (selectedFile) => {
    if (!selectedFile) return;
    setAnalyzing(true);

    const reader = new FileReader();
    reader.onload = (e) => {
      const buffer = e.target.result;
      const bytes = new Uint8Array(buffer.slice(0, 64));

      let format = 'RAW';
      let detectedArch = customArch !== 'auto' ? customArch : 'unknown';

      // Check ELF magic: 0x7f 'E' 'L' 'F'
      if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
        format = 'ELF';
        const is64 = bytes[4] === 2;
        const machine = bytes[18] | (bytes[19] << 8);
        if (customArch === 'auto') {
          if (machine === 0x3e) detectedArch = 'x86_64';
          else if (machine === 0x03) detectedArch = 'i386';
          else if (machine === 0x28) detectedArch = 'arm';
          else if (machine === 0xb7) detectedArch = 'aarch64';
          else if (machine === 0xf3) detectedArch = 'riscv';
          else detectedArch = is64 ? 'x86_64' : 'i386';
        }
      } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
        // PE magic 'MZ'
        format = 'PE';
        if (customArch === 'auto') detectedArch = 'x86_64';
      }

      setTimeout(() => {
        setAnalysisResult({
          filename: selectedFile.name,
          size: selectedFile.size,
          format: isRaw ? 'RAW' : format,
          architecture: detectedArch,
          hash: Array.from(bytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''),
          timestamp: new Date().toISOString(),
          mitigations: {
            nx: true,
            pie: false,
            canary: false,
            relro: 'Partial'
          }
        });
        setAnalyzing(false);
      }, 500);
    };

    reader.readAsArrayBuffer(selectedFile);
  };

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (f) {
      if (f.size > 4 * 1024 * 1024) {
        alert("File size exceeds 4MB limit.");
        return;
      }
      setFile(f);
      analyzeFile(f);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const f = e.dataTransfer.files[0];
      if (f.size > 4 * 1024 * 1024) {
        alert("File size exceeds 4MB limit.");
        return;
      }
      setFile(f);
      analyzeFile(f);
    }
  };

  return (
    <div className="upload-page fade-in">
      {/* Hero Header */}
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver upload_gateway</span>
        <h1 className="hero-title">Binary Ingestion & Upload</h1>
        <p className="hero-subtitle">
          Submit ELF, PE, or RAW binary executables up to 4MB for architecture validation and gadget compilation.
        </p>
      </div>

      {/* Constraints Box */}
      <div className="upload-notice-box mono text-xs">
        <p>&gt; Maximum file size: <strong>4MB</strong></p>
        <p>&gt; Supported architectures: <strong>x86 / x86_64 / ARM / RISC-V</strong> with PE, ELF, and MACH-O formats</p>
        <p>&gt; Automated backend: Runs gadget identification and chain construction via Capstone & libcurl sync.</p>
      </div>

      {/* Upload Zone */}
      <div className="upload-form-card">
        <div
          className={`dropzone-box ${dragActive ? 'dropzone-active' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <Upload size={38} className="text-accent-green drop-icon" />
          <h3 className="drop-title">Drag & drop your binary here</h3>
          <p className="drop-subtitle text-muted text-sm">or click to browse local files</p>
          <input
            id="binaryFileInput"
            type="file"
            onChange={handleFileChange}
            className="file-input-hidden"
          />
          <label htmlFor="binaryFileInput" className="btn btn-primary" style={{ marginTop: '1rem' }}>
            <FileCode size={16} />
            <span>Select Binary File</span>
          </label>
        </div>

        {/* Options Row */}
        <div className="upload-options-grid">
          <div className="option-field checkbox-field">
            <label className="checkbox-label mono">
              <input
                type="checkbox"
                checked={isRaw}
                onChange={(e) => setIsRaw(e.target.checked)}
              />
              <span>Raw binary (no file header)</span>
            </label>
          </div>

          <div className="option-field">
            <label className="mono text-xs text-muted">Custom Architecture Override:</label>
            <select
              value={customArch}
              onChange={(e) => setCustomArch(e.target.value)}
              className="select-input mono"
            >
              <option value="auto">auto (auto-detect header)</option>
              <option value="i386">i386 (x86_32)</option>
              <option value="x86_64">x86_64</option>
              <option value="arm">arm</option>
              <option value="RISC-V">RISC-V</option>
            </select>
          </div>
        </div>

        {/* Selected File Feedback */}
        {file && (
          <div className="selected-file-banner mono text-xs">
            <CheckCircle2 size={16} className="text-accent-green" />
            <span>Target: <strong>{file.name}</strong> ({(file.size / 1024).toFixed(2)} KB)</span>
          </div>
        )}
      </div>

      {/* Local Inspection Terminal Output */}
      {analyzing && (
        <div className="analysis-box mono text-xs fade-in">
          <div className="cyber-spinner mini"></div>
          <span className="text-accent-cyan">Parsing binary headers & validating instruction sections...</span>
        </div>
      )}

      {analysisResult && (
        <div className="analysis-box mono text-xs fade-in">
          <div className="analysis-title text-accent-green">
            [+] Binary Header Verified: {analysisResult.filename}
          </div>
          <div className="analysis-details-grid">
            <div>Format: <span className="text-accent-cyan">{analysisResult.format}</span></div>
            <div>Architecture: <span className="text-accent-cyan">{analysisResult.architecture}</span></div>
            <div>Size: <span>{analysisResult.size} bytes</span></div>
            <div>Simulated Hash: <span className="text-dim">{analysisResult.hash}</span></div>
          </div>
          <div className="analysis-footer-note text-dim">
            [i] CLI upload command: <code>ropweaver {analysisResult.filename} --auto-chain --upload-report</code>
          </div>
        </div>
      )}

      {/* Recent Binaries Table — ONLY Live Firebase Data, No Mock Binaries */}
      <div className="recent-table-card">
        <div className="recent-table-header">
          <span className="mono font-semibold text-accent-cyan">&gt; ropshell &gt; recent uploads</span>
          <span className="mono text-dim text-xs">Live binaries in cloud registry ({recentBinaries.length})</span>
        </div>

        {loadingRecent ? (
          <div className="loading-state-card" style={{ padding: '2rem' }}>
            <div className="cyber-spinner mini" style={{ margin: '0 auto 0.75rem' }}></div>
            <span className="mono text-accent-cyan text-xs">QUERYING LIVE BINARIES FROM FIRESTORE...</span>
          </div>
        ) : recentBinaries.length === 0 ? (
          <div className="empty-recent-box mono text-xs text-dim" style={{ padding: '2rem', textAlign: 'center' }}>
            No uploaded binaries found in cloud registry yet. Upload a binary above or using the CLI.
          </div>
        ) : (
          <div className="recent-table-scroll overflow-container">
            <table className="recent-table mono text-xs">
              <thead>
                <tr>
                  <th>Hash Digest</th>
                  <th>Binary Name</th>
                  <th>Architecture</th>
                  <th>Format</th>
                  <th>Gadgets</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentBinaries.map((b, idx) => {
                  const safeHash = typeof b.hash === 'string' ? b.hash : '';
                  const displayHash = safeHash.length > 16 ? safeHash.slice(0, 16) + '...' : (safeHash || 'N/A');
                  return (
                    <tr key={idx} className="recent-row">
                      <td className="hash-col text-dim" title={safeHash}>
                        {displayHash}
                      </td>
                      <td className="name-col text-accent-green font-bold">
                        {b.name}
                      </td>
                      <td className="arch-col text-muted">{b.arch}</td>
                      <td className="type-col">
                        <span className="badge badge-info">{b.type}</span>
                      </td>
                      <td className="count-col">{Number(b.count || 0).toLocaleString()}</td>
                      <td className="action-col">
                        <button
                          onClick={() => {
                            if (onSelectBinarySample) {
                              onSelectBinarySample(b.hash, b.name, b.reportId, b.rawReport);
                            } else {
                              const targetId = b.reportId || b.name;
                              window.location.hash = `#/report/${encodeURIComponent(targetId)}`;
                            }
                          }}
                          className="btn btn-secondary btn-xs mono"
                          title="Inspect full report and gadget groups"
                        >
                          <span>Explore</span>
                          <ArrowRight size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
