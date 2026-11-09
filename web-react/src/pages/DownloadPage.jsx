import React, { useState, useEffect } from 'react';
import { Download, Check, Copy, Terminal, ShieldCheck, Laptop, Apple, Sparkles, Package, FileDown, ExternalLink, RefreshCw, BookOpen } from 'lucide-react';

export default function DownloadPage({ onNavigateTab }) {
  // Reliable hardware/OS detection directly from browser environment (never cookies)
  const detectClientPlatform = () => {
    // 1. High-Entropy Client Hints API (Chromium / Chrome / Edge)
    try {
      const hint = (navigator.userAgentData?.platform || '').toLowerCase();
      if (hint.includes('win')) return 'windows';
      if (hint.includes('mac')) return 'macos';
      if (hint.includes('linux') || hint.includes('android')) return 'linux';
    } catch (e) {}

    // 2. Navigator platform & userAgent strings
    const platform = (navigator.platform || '').toLowerCase();
    const ua = (navigator.userAgent || '').toLowerCase();

    if (platform.includes('win') || ua.includes('win')) {
      return 'windows';
    }
    if (platform.includes('mac') || platform.includes('darwin') || ua.includes('mac') || ua.includes('darwin')) {
      return 'macos';
    }
    if (platform.includes('linux') || platform.includes('x11') || ua.includes('linux')) {
      return 'linux';
    }
    return 'windows';
  };

  const clientOS = detectClientPlatform();
  const [selectedOS, setSelectedOS] = useState(clientOS);
  const [copiedItem, setCopiedItem] = useState(null);

  // Clean up any stale ropweaver_preferred_os cookie so it cannot contaminate client state
  useEffect(() => {
    try {
      document.cookie = 'ropweaver_preferred_os=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax';
    } catch (e) {}
  }, []);

  const handleSelectOS = (osKey) => {
    setSelectedOS(osKey);
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(id);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  // Download Catalog Data with actual packaged distribution artifacts
  const downloads = {
    windows: {
      name: 'Windows',
      fullName: 'Windows 10 / 11 / Server (x64)',
      version: 'v1.2.4',
      arch: 'x86_64 / AMD64',
      releaseDate: 'November 2026',
      icon: Laptop,
      primaryDownload: {
        filename: 'ropweaver-windows-x64.exe',
        url: '/ropweaver-windows-x64.exe',
        size: '9.4 MB',
        label: 'Download Standalone Executable (.exe)'
      },
      secondaryDownload: {
        filename: 'ropweaver-v1.2.4-win64.zip',
        url: '/ropweaver-v1.2.4-win64.zip',
        size: '9.3 MB',
        label: 'Download Complete Portable Bundle (.zip with DLLs & Samples)'
      },
      sha256: '5746CFE87826C3E26FBA9D9E54260C1FDE487BE848F5A34B2204FCEF810CF1D3',
      quickInstallCmd: 'irm https://ropweaver.io/install.ps1 | iex',
      packageManager: 'winget install ROPWeaver.ROPWeaver',
      requirements: 'Windows 10 build 19041+ or Windows 11, x64 architecture (Zero external dependencies)',
      verifyCmd: '.\\ropweaver-windows-x64.exe --version'
    },
    linux: {
      name: 'Linux',
      fullName: 'Linux (Ubuntu, Debian, Kali, Arch, Fedora)',
      version: 'v1.2.4',
      arch: 'x86_64 / AArch64 (ARM64)',
      releaseDate: 'November 2026',
      icon: Terminal,
      primaryDownload: {
        filename: 'ropweaver-v1.2.4-linux-x86_64.tar.gz',
        url: '/ropweaver-v1.2.4-linux-x86_64.tar.gz',
        size: '285 KB',
        label: 'Download Binary Archive (.tar.gz with ELF executable)'
      },
      secondaryDownload: {
        filename: 'ropweaver_1.2.4_amd64.deb',
        url: '/ropweaver_1.2.4_amd64.deb',
        size: '282 KB',
        label: 'Download Debian / Ubuntu Package (.deb)'
      },
      sha256: '15B259F6E104C4D02E4D5AC78D0F45D80788F50B4867F5935BF875C2336FC661',
      quickInstallCmd: 'curl -fsSL https://ropweaver.io/install.sh | bash',
      packageManager: 'yay -S ropweaver-bin   # Arch Linux AUR',
      requirements: 'GLIBC 2.31+, Capstone Engine, Linux Kernel 5.4+ (x86_64 or ARM64)',
      verifyCmd: 'ropweaver --version'
    },
    macos: {
      name: 'macOS',
      fullName: 'macOS Sonoma, Ventura & Monterey',
      version: 'v1.2.4',
      arch: 'Apple Silicon (arm64) & Intel (x86_64)',
      releaseDate: 'November 2026',
      icon: Apple,
      primaryDownload: {
        filename: 'ropweaver-v1.2.4-darwin-arm64.tar.gz',
        url: '/ropweaver-v1.2.4-darwin-arm64.tar.gz',
        size: '235 KB',
        label: 'Download Apple Silicon Archive (arm64)'
      },
      secondaryDownload: {
        filename: 'ropweaver-v1.2.4-darwin-x86_64.tar.gz',
        url: '/ropweaver-v1.2.4-darwin-x86_64.tar.gz',
        size: '249 KB',
        label: 'Download Intel x86_64 Archive'
      },
      sha256: '7BF02144D115F436E8127083135913E1EE8971AD1CC800EFEA885634F96428CF',
      quickInstallCmd: 'brew install ropweaver/tap/ropweaver',
      packageManager: 'brew tap ropweaver/tap && brew install ropweaver',
      requirements: 'macOS 12.0 Monterey or later, Terminal with zsh/bash',
      verifyCmd: 'ropweaver --version'
    }
  };

  const active = downloads[selectedOS] || downloads.windows;
  const ActiveIcon = active.icon;

  return (
    <div className="download-page fade-in">
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver official_releases</span>
        <h1 className="hero-title">Download ROPWeaver</h1>
        <p className="hero-subtitle">
          Get the high-performance binary gadget analyzer and automated ROP synthesizer for your native system.
        </p>
      </div>

      {/* Auto-Detection Banner */}
      <div className="detection-banner mono text-xs">
        <div className="detection-left">
          <Sparkles size={16} className="text-accent-green" />
          <span>
            DEVICE PLATFORM: <strong className="text-accent-cyan">{clientOS.toUpperCase()}</strong>
            <span className="text-muted"> (auto-detected from browser environment)</span>
          </span>
        </div>
        {selectedOS !== clientOS ? (
          <button
            type="button"
            onClick={() => setSelectedOS(clientOS)}
            className="refresh-detect-btn"
            title={`Switch view back to your auto-detected device (${clientOS.toUpperCase()})`}
          >
            <RefreshCw size={12} />
            <span>Show My Device ({clientOS.toUpperCase()})</span>
          </button>
        ) : (
          <div className="text-accent-green mono" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Check size={14} />
            <span>Viewing Recommended</span>
          </div>
        )}
      </div>

      {/* OS Picker Tabs / Dropdown */}
      <div className="os-picker-card">
        <div className="os-picker-header">
          <span className="mono font-semibold text-xs text-muted">SELECT TARGET OPERATING SYSTEM:</span>
          <select
            value={selectedOS}
            onChange={(e) => handleSelectOS(e.target.value)}
            className="os-select-dropdown mono"
          >
            <option value="windows">🪟 Windows (10 / 11 / Server)</option>
            <option value="linux">🐧 Linux (Ubuntu, Debian, Arch, Kali)</option>
            <option value="macos">🍎 macOS (Apple Silicon & Intel)</option>
          </select>
        </div>

        <div className="os-cards-grid">
          {Object.entries(downloads).map(([key, item]) => {
            const ItemIcon = item.icon;
            const isSelected = selectedOS === key;
            return (
              <div
                key={key}
                onClick={() => handleSelectOS(key)}
                className={`os-selector-box ${isSelected ? 'selected' : ''}`}
              >
                <div className="os-box-top">
                  <ItemIcon size={24} className={isSelected ? 'text-accent-green' : 'text-dim'} />
                  {key === clientOS && (
                    <span className="recommended-badge mono">RECOMMENDED</span>
                  )}
                </div>
                <h4 className="os-box-title mono">{item.name}</h4>
                <p className="os-box-arch text-xs text-dim mono">{item.arch}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Download Spotlight Card for Selected OS */}
      <div className="download-spotlight-card">
        <div className="spotlight-header">
          <div className="spotlight-title-row">
            <ActiveIcon size={28} className="text-accent-green" style={{ flexShrink: 0 }} />
            <div style={{ minWidth: 0, flex: 1 }}>
              <h2 className="spotlight-os-name mono">{active.fullName}</h2>
              <span className="spotlight-meta mono text-xs text-muted">
                Version: <strong className="text-accent-cyan">{active.version}</strong> &bull; Architecture: {active.arch} &bull; Released: {active.releaseDate}
              </span>
            </div>
          </div>
          <span className="badge badge-info mono">{active.arch}</span>
        </div>

        {/* Primary & Secondary Download CTAs */}
        <div className="download-buttons-group">
          <a
            href={active.primaryDownload.url}
            download={active.primaryDownload.filename}
            className="btn btn-primary btn-large mono"
          >
            <Download size={20} />
            <div className="btn-large-text">
              <span className="btn-large-main">{active.primaryDownload.label}</span>
              <span className="btn-large-sub text-xs">Filename: {active.primaryDownload.filename} ({active.primaryDownload.size})</span>
            </div>
          </a>

          {active.secondaryDownload && (
            <a
              href={active.secondaryDownload.url}
              download={active.secondaryDownload.filename}
              className="btn btn-secondary btn-large mono"
            >
              <Package size={20} />
              <div className="btn-large-text">
                <span className="btn-large-main">{active.secondaryDownload.label}</span>
                <span className="btn-large-sub text-xs">Archive: {active.secondaryDownload.filename} ({active.secondaryDownload.size})</span>
              </div>
            </a>
          )}
        </div>

        {/* Quick Command Line Install */}
        <div className="command-install-box">
          <div className="cmd-header">
            <Terminal size={14} className="text-accent-cyan" />
            <span className="mono text-xs font-bold text-accent-cyan">AUTOMATED TERMINAL ONE-LINER:</span>
          </div>
          <div className="cmd-input-row mono text-xs">
            <code>{active.quickInstallCmd}</code>
            <button
              onClick={() => handleCopy(active.quickInstallCmd, 'install-cmd')}
              className="copy-mini-btn"
              title="Copy terminal command"
            >
              {copiedItem === 'install-cmd' ? <Check size={14} className="text-accent-green" /> : <Copy size={14} />}
              <span>{copiedItem === 'install-cmd' ? 'COPIED' : 'COPY'}</span>
            </button>
          </div>
        </div>

        {/* Package Manager Command */}
        <div className="command-install-box" style={{ marginTop: '0.75rem' }}>
          <div className="cmd-header">
            <Package size={14} className="text-accent-orange" />
            <span className="mono text-xs font-bold text-accent-orange">PACKAGE MANAGER:</span>
          </div>
          <div className="cmd-input-row mono text-xs">
            <code>{active.packageManager}</code>
            <button
              onClick={() => handleCopy(active.packageManager, 'pkg-cmd')}
              className="copy-mini-btn"
              title="Copy package command"
            >
              {copiedItem === 'pkg-cmd' ? <Check size={14} className="text-accent-green" /> : <Copy size={14} />}
              <span>{copiedItem === 'pkg-cmd' ? 'COPIED' : 'COPY'}</span>
            </button>
          </div>
        </div>

        {/* SHA-256 Checksum */}
        <div className="checksum-row mono text-xs">
          <div className="checksum-left">
            <div className="checksum-label-row">
              <ShieldCheck size={14} className="text-accent-green" style={{ flexShrink: 0 }} />
              <span className="text-dim">SHA-256 DIGEST:</span>
            </div>
            <span className="checksum-hash text-muted" title={active.sha256}>
              {active.sha256}
            </span>
          </div>
          <button
            onClick={() => handleCopy(active.sha256, 'checksum')}
            className="copy-mini-btn"
            title="Copy SHA-256 hash"
          >
            {copiedItem === 'checksum' ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
            <span>{copiedItem === 'checksum' ? 'COPIED' : 'COPY'}</span>
          </button>
        </div>

        {/* Verification Note */}
        <div className="verification-box mono text-xs text-muted">
          <p>&gt; System Requirements: {active.requirements}</p>
          <p>&gt; Test Installation: <code>{active.verifyCmd}</code></p>
        </div>
      </div>

      {/* Instructions & Links */}
      <div className="download-footer-grid">
        <div className="download-info-card">
          <h4 className="mono font-bold text-accent-cyan text-sm">Offline Air-Gapped Mode</h4>
          <p className="text-muted text-xs" style={{ marginTop: '0.5rem', lineHeight: '1.6' }}>
            ROPWeaver operates completely offline by default. Disassembly, gadget discovery, and ROP chain synthesis occur strictly in memory. 
            Firestore cloud publishing is opt-in via the <code>--upload-report</code> flag.
          </p>
        </div>

        <div className="download-info-card">
          <h4 className="mono font-bold text-accent-green text-sm">Need Help Setting Up?</h4>
          <p className="text-muted text-xs" style={{ marginTop: '0.5rem', lineHeight: '1.6' }}>
            Visit the interactive{' '}
            <strong
              className="text-accent-cyan clickable-title"
              style={{ cursor: 'pointer', textDecoration: 'underline' }}
              onClick={() => {
                if (onNavigateTab) onNavigateTab('guide');
                else window.location.hash = '#/guide';
              }}
            >
              Developer &amp; Researcher Guide
            </strong>{' '}
            for native compiler flags, vulnerable test binaries, and debugging tutorials.
          </p>
          <button
            onClick={() => {
              if (onNavigateTab) onNavigateTab('guide');
              else window.location.hash = '#/guide';
            }}
            className="btn btn-outline-cyan btn-xs mono"
            style={{ marginTop: '0.75rem', width: '100%', justifyContent: 'center' }}
          >
            <BookOpen size={13} />
            <span>Open Developer &amp; Researcher Guide &rarr;</span>
          </button>
        </div>
      </div>
    </div>
  );
}
