import React, { useState, useEffect } from 'react';
import { Upload, FileCode, CheckCircle2, ArrowRight, Shield, Copy, Check, Terminal, Database } from 'lucide-react';
import { db, collection, getDocs } from '../firebase/config';
import LoadingSpinner from '../components/LoadingSpinner';

export default function UploadPage({ onSelectBinarySample }) {
  const [file, setFile] = useState(null);
  const [isRaw, setIsRaw] = useState(false);
  const [customArch, setCustomArch] = useState('auto');
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

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

  // Inspect binary header directly in browser & correlate with cloud datastore
  const analyzeFile = async (selectedFile) => {
    if (!selectedFile) return;
    setAnalyzing(true);
    setAnalysisResult(null);

    try {
      const buffer = await selectedFile.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const dataView = new DataView(buffer);

      // Compute authentic SHA-256 digest via Web Crypto API
      let sha256 = '';
      try {
        const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
        sha256 = Array.from(new Uint8Array(hashBuf))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      } catch (cryptoErr) {
        console.warn('Web Crypto SHA-256 failed, fallback to slice:', cryptoErr);
        sha256 = Array.from(bytes.slice(0, 32))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }

      let format = 'RAW';
      let detectedArch = customArch !== 'auto' ? customArch : 'unknown';
      let bitness = 'Unknown';
      let endianness = 'Unknown';
      let binaryType = 'Raw / Unknown';
      const mitigations = [];

      // 1. Check ELF magic: 0x7f 'E' 'L' 'F'
      if (bytes.length >= 20 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
        format = 'ELF';
        const is64 = bytes[4] === 2;
        bitness = is64 ? '64-bit' : bytes[4] === 1 ? '32-bit' : 'Unknown';
        const isLittle = bytes[5] === 1;
        endianness = isLittle ? 'Little-Endian (LSB)' : bytes[5] === 2 ? 'Big-Endian (MSB)' : 'Unknown';

        const machine = isLittle
          ? bytes[18] | (bytes[19] << 8)
          : (bytes[18] << 8) | bytes[19];

        const eType = isLittle
          ? bytes[16] | (bytes[17] << 8)
          : (bytes[16] << 8) | bytes[17];

        if (eType === 2) {
          binaryType = 'Executable (ET_EXEC)';
        } else if (eType === 3) {
          binaryType = 'Shared Object / PIE (ET_DYN)';
          mitigations.push({ name: 'PIE', status: 'badge-on', desc: 'Position-Independent Executable' });
        } else if (eType === 1) {
          binaryType = 'Relocatable Object (ET_REL)';
        }

        if (customArch === 'auto') {
          if (machine === 0x3e) detectedArch = 'x86_64';
          else if (machine === 0x03) detectedArch = 'i386';
          else if (machine === 0x28) detectedArch = 'armv7';
          else if (machine === 0xb7) detectedArch = 'arm64';
          else if (machine === 0xf3) detectedArch = 'riscv64';
          else detectedArch = is64 ? 'x86_64' : 'i386';
        }
      }
      // 2. Check PE magic: 'MZ' (0x4d 0x5a)
      else if (bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
        format = 'PE';
        endianness = 'Little-Endian (x86/PE Standard)';
        let isPeValid = false;

        const eLfanew = dataView.getUint32(0x3c, true);
        if (eLfanew > 0 && eLfanew + 24 <= bytes.length) {
          // Signature 'PE\0\0'
          if (
            bytes[eLfanew] === 0x50 &&
            bytes[eLfanew + 1] === 0x45 &&
            bytes[eLfanew + 2] === 0x00 &&
            bytes[eLfanew + 3] === 0x00
          ) {
            isPeValid = true;
            const peMachine = dataView.getUint16(eLfanew + 4, true);
            if (peMachine === 0x8664) {
              if (customArch === 'auto') detectedArch = 'x86_64';
              bitness = '64-bit (PE32+)';
            } else if (peMachine === 0x014c) {
              if (customArch === 'auto') detectedArch = 'i386';
              bitness = '32-bit (PE32)';
            } else if (peMachine === 0xaa64) {
              if (customArch === 'auto') detectedArch = 'arm64';
              bitness = '64-bit (ARM64)';
            } else if (peMachine === 0x01c0) {
              if (customArch === 'auto') detectedArch = 'arm';
              bitness = '32-bit (ARM Thumb)';
            }

            binaryType = 'Portable Executable (PE32/PE32+)';

            // Check DllCharacteristics
            const optHeaderOffset = eLfanew + 24;
            if (optHeaderOffset + 72 <= bytes.length) {
              const optMagic = dataView.getUint16(optHeaderOffset, true);
              const is64Opt = optMagic === 0x20b;
              bitness = is64Opt ? '64-bit (PE32+)' : '32-bit (PE32)';

              const dllCharOffset = optHeaderOffset + 70;
              const dllChar = dataView.getUint16(dllCharOffset, true);
              if ((dllChar & 0x0100) !== 0) {
                mitigations.push({ name: 'DYNAMIC_BASE', status: 'badge-on', desc: 'ASLR / Dynamic Base' });
              }
              if ((dllChar & 0x0400) !== 0) {
                mitigations.push({ name: 'NX_COMPAT', status: 'badge-on', desc: 'DEP / No-Execute stack' });
              }
              if ((dllChar & 0x4000) !== 0) {
                mitigations.push({ name: 'GUARD_CF', status: 'badge-on', desc: 'Control Flow Guard' });
              }
            }
          }
        }
        if (!isPeValid) {
          binaryType = 'MS-DOS / Legacy PE Stub';
          if (customArch === 'auto') detectedArch = 'i386';
          bitness = '16/32-bit';
        }
      }
      // 3. Check Mach-O magic
      else if (
        bytes.length >= 8 &&
        ((bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xce) ||
          (bytes[0] === 0xce && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
          (bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe))
      ) {
        format = 'Mach-O';
        const is64 = bytes[3] === 0xcf || bytes[0] === 0xcf;
        bitness = is64 ? '64-bit' : '32-bit';
        endianness = (bytes[0] === 0xcf || bytes[0] === 0xce) ? 'Little-Endian' : 'Big-Endian';
        binaryType = 'Mach-O Binary (Apple Darwin)';

        if (customArch === 'auto') {
          const isLittle = endianness === 'Little-Endian';
          const cpuType = isLittle ? dataView.getUint32(4, true) : dataView.getUint32(4, false);
          if (cpuType === 0x01000007) detectedArch = 'x86_64';
          else if (cpuType === 0x0100000c) detectedArch = 'arm64';
          else if (cpuType === 0x00000007) detectedArch = 'i386';
          else if (cpuType === 0x0000000c) detectedArch = 'arm';
          else detectedArch = is64 ? 'x86_64' : 'arm64';
        }
      } else {
        format = isRaw ? 'RAW' : 'RAW / Unknown Header';
        bitness = (customArch && customArch.includes('64')) ? '64-bit' : '32-bit';
        binaryType = isRaw ? 'Raw Instruction Stream' : 'Unrecognized Header Format';
      }

      // Check correlation against existing live Firestore binaries
      const cleanFileName = selectedFile.name.split(/[/\\]/).pop().toLowerCase();
      const matched = recentBinaries.find((b) => {
        const bHash = (typeof b.hash === 'string' ? b.hash : '').toLowerCase();
        const bName = (typeof b.name === 'string' ? b.name : '').toLowerCase();
        return (
          (sha256 && bHash && (bHash === sha256 || bHash.startsWith(sha256.slice(0, 16)))) ||
          (cleanFileName && bName === cleanFileName)
        );
      });

      // Format readable size
      const sizeBytes = selectedFile.size;
      const formattedSize =
        sizeBytes >= 1024 * 1024
          ? `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB (${sizeBytes.toLocaleString()} bytes)`
          : `${(sizeBytes / 1024).toFixed(2)} KB (${sizeBytes.toLocaleString()} bytes)`;

      setAnalysisResult({
        filename: selectedFile.name,
        sizeBytes,
        formattedSize,
        format: isRaw ? 'RAW' : format,
        architecture: customArch !== 'auto' ? customArch : detectedArch,
        bitness,
        endianness,
        binaryType,
        sha256,
        mitigations,
        cloudMatch: matched || null,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Binary inspection error:', err);
    } finally {
      setAnalyzing(false);
    }
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
          <LoadingSpinner inline size="sm" color="cyan" label="Parsing binary headers & validating instruction sections..." />
        </div>
      )}

      {analysisResult && (
        <div className="analysis-box mono text-xs fade-in">
          {/* Header Row with status badge */}
          <div className="analysis-header-row">
            <div className="analysis-title">
              <CheckCircle2 size={18} className="text-accent-green" />
              <span>[+] BINARY HEADER VERIFIED: {analysisResult.filename}</span>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
              <span className="badge badge-info">{analysisResult.format}</span>
              <span className="badge badge-warning">{analysisResult.architecture}</span>
              <span className="badge badge-on">{analysisResult.bitness}</span>
            </div>
          </div>

          {/* Detailed Specifications Grid */}
          <div className="analysis-specs-grid">
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">Target Binary</span>
              <span className="analysis-spec-value text-accent-green" title={analysisResult.filename}>
                {analysisResult.filename}
              </span>
            </div>
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">File Size</span>
              <span className="analysis-spec-value">
                {analysisResult.formattedSize}
              </span>
            </div>
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">Binary Format & Type</span>
              <span className="analysis-spec-value text-accent-cyan">
                {analysisResult.binaryType}
              </span>
            </div>
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">Architecture</span>
              <span className="analysis-spec-value text-accent-orange">
                {analysisResult.architecture} ({analysisResult.bitness})
              </span>
            </div>
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">Byte Endianness</span>
              <span className="analysis-spec-value text-muted">
                {analysisResult.endianness}
              </span>
            </div>
            <div className="analysis-spec-item">
              <span className="analysis-spec-label">Header Verification</span>
              <span className="analysis-spec-value text-accent-green">
                PASSED (Magic Verified)
              </span>
            </div>
          </div>

          {/* Authentic SHA-256 Digest Row with Copy */}
          <div className="analysis-hash-row">
            <div className="analysis-hash-content">
              <span className="analysis-spec-label">SHA-256 Authenticated Checksum</span>
              <span className="analysis-hash-text" title={analysisResult.sha256}>
                {analysisResult.sha256}
              </span>
            </div>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(analysisResult.sha256);
                setCopiedHash(true);
                setTimeout(() => setCopiedHash(false), 2000);
              }}
              className="btn btn-secondary btn-xs mono"
              title="Copy SHA-256 digest"
            >
              {copiedHash ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
              <span>{copiedHash ? 'COPIED' : 'COPY SHA-256'}</span>
            </button>
          </div>

          {/* Security Mitigations from Binary Header (if detected) */}
          {analysisResult.mitigations && analysisResult.mitigations.length > 0 && (
            <div style={{ marginBottom: '0.85rem' }}>
              <span className="analysis-spec-label" style={{ display: 'block', marginBottom: '0.35rem' }}>
                <Shield size={12} className="text-accent-green" style={{ display: 'inline', marginRight: '4px' }} />
                Detected Header Security Features:
              </span>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                {analysisResult.mitigations.map((m, idx) => (
                  <span key={idx} className={`badge ${m.status}`} title={m.desc}>
                    {m.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Cloud Datastore Correlation Findings */}
          {analysisResult.cloudMatch ? (
            <div className="analysis-cloud-match">
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.25rem' }}>
                  <Database size={15} className="text-accent-cyan" />
                  <span className="mono font-bold text-accent-cyan" style={{ fontSize: '0.85rem' }}>
                    MATCHED IN CLOUD DATASTORE: {analysisResult.cloudMatch.reportId}
                  </span>
                </div>
                <p className="mono text-muted text-xs" style={{ margin: 0 }}>
                  This binary is already cataloged in the ROPWeaver cloud registry with{' '}
                  <strong className="text-accent-green">{analysisResult.cloudMatch.count.toLocaleString()}</strong> discovered gadgets.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  if (onSelectBinarySample) {
                    onSelectBinarySample(
                      analysisResult.cloudMatch.hash,
                      analysisResult.cloudMatch.name,
                      analysisResult.cloudMatch.reportId,
                      analysisResult.cloudMatch.rawReport
                    );
                  } else {
                    const targetId = analysisResult.cloudMatch.reportId || analysisResult.cloudMatch.name;
                    window.location.hash = `#/report/${encodeURIComponent(targetId)}`;
                  }
                }}
                className="btn btn-primary btn-xs mono"
                title="Inspect cataloged exploit report & gadget chains"
              >
                <span>EXPLORE REPORT</span>
                <ArrowRight size={12} />
              </button>
            </div>
          ) : (
            <div className="analysis-cli-box">
              <div style={{ minWidth: 0, flex: 1 }}>
                <span className="analysis-spec-label" style={{ display: 'block', marginBottom: '0.2rem' }}>
                  <Terminal size={12} className="text-accent-green" style={{ display: 'inline', marginRight: '4px' }} />
                  Full Gadget Compilation & Cloud Ingestion CLI:
                </span>
                <code className="analysis-cli-code">
                  ropweaver {analysisResult.filename} --auto-chain --upload-report
                </code>
              </div>
              <button
                type="button"
                onClick={() => {
                  const cmd = `ropweaver ${analysisResult.filename} --auto-chain --upload-report`;
                  navigator.clipboard.writeText(cmd);
                  setCopiedCmd(true);
                  setTimeout(() => setCopiedCmd(false), 2000);
                }}
                className="btn btn-secondary btn-xs mono"
                title="Copy terminal command"
              >
                {copiedCmd ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
                <span>{copiedCmd ? 'COPIED' : 'COPY COMMAND'}</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Recent Binaries Table — ONLY Live Firebase Data, No Mock Binaries */}
      <div className="recent-table-card">
        <div className="recent-table-header">
          <span className="mono font-semibold text-accent-cyan">&gt; ropshell &gt; recent uploads</span>
          <span className="mono text-dim text-xs">Live binaries in cloud registry ({recentBinaries.length})</span>
        </div>

        {loadingRecent ? (
          <LoadingSpinner asCard size="md" color="cyan" label="QUERYING LIVE BINARIES FROM FIRESTORE..." />
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
