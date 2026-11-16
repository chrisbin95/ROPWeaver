import React, { useState, useEffect } from 'react';
import { Download, Check, Copy, Terminal, ShieldCheck, Laptop, Apple, Sparkles, Package, ExternalLink, RefreshCw, BookOpen } from 'lucide-react';

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

  const RELEASE_PAGE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.3';
  const DOWNLOAD_BASE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.3';

  // Download Catalog Data with actual published v1.6.3 distribution artifacts
  const downloads = {
    windows: {
      name: 'Windows',
      fullName: 'Windows 10 / 11 / Server (x64)',
      version: 'v1.6.3',
      arch: 'x86_64 / AMD64',
      releaseDate: 'November 2026',
      icon: Laptop,
      primaryDownload: {
        filename: 'ropweaver-v1.6.3-win64.zip',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-win64.zip`,
        size: '9.5 MB',
        label: 'Download Complete Portable Bundle (.zip with DLLs & Samples)'
      },
      secondaryDownload: null,
      packages: [
        {
          name: 'Windows x86_64 ZIP Archive',
          filename: 'ropweaver-v1.6.3-win64.zip',
          url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-win64.zip`,
          size: '9.5 MB',
          sha256: 'd9acde6bfee97cd71630ad4d97f1e709a78131c98ddb2b397578ed9286941fd4'
        }
      ],
      requirements: 'Windows 10 build 19041+ or Windows 11, x64 architecture (Complete portable bundle with runtime DLLs & samples)',
      verifyCmd: '.\\ropweaver.exe --version'
    },
    linux: {
      name: 'Linux',
      fullName: 'Linux (Ubuntu, Debian, Kali, Arch, Fedora)',
      version: 'v1.6.3',
      arch: 'x86_64 / AMD64',
      releaseDate: 'November 2026',
      icon: Terminal,
      primaryDownload: {
        filename: 'ropweaver_1.6.3_amd64.deb',
        url: `${DOWNLOAD_BASE_URL}/ropweaver_1.6.3_amd64.deb`,
        size: '385 KB',
        label: 'Download Debian / Ubuntu Package (.deb)'
      },
      secondaryDownload: {
        filename: 'ropweaver-v1.6.3-linux-x86_64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-linux-x86_64.tar.gz`,
        size: '508 KB',
        label: 'Download Standalone Binary Archive (.tar.gz with ELF executable)'
      },
      packages: [
        {
          name: 'Debian / Ubuntu Package (.deb)',
          filename: 'ropweaver_1.6.3_amd64.deb',
          url: `${DOWNLOAD_BASE_URL}/ropweaver_1.6.3_amd64.deb`,
          size: '385 KB',
          sha256: 'c2f21c8367ac0ccdac45e9edc33d0d2ebca460323a8628d09d3a38d6613024e8'
        },
        {
          name: 'Standalone Linux x86_64 (.tar.gz)',
          filename: 'ropweaver-v1.6.3-linux-x86_64.tar.gz',
          url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-linux-x86_64.tar.gz`,
          size: '508 KB',
          sha256: 'e2ec7e636c2051343c7ff14f1aef0ef0e735226c635b4a120c9aadc6764acb10'
        }
      ],
      requirements: 'GLIBC 2.31+, Capstone Engine, Linux Kernel 5.4+ (Ubuntu 20.04+, Debian 11+, Kali Linux x86_64)',
      verifyCmd: 'ropweaver --version'
    },
    macos: {
      name: 'macOS',
      fullName: 'macOS (Apple Silicon & Intel)',
      version: 'v1.6.3',
      arch: 'Apple Silicon (arm64) & Intel (x86_64)',
      releaseDate: 'November 2026',
      icon: Apple,
      primaryDownload: {
        filename: 'ropweaver-v1.6.3-darwin-arm64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-arm64.tar.gz`,
        size: '371 KB',
        label: 'Download Apple Silicon Archive (arm64 .tar.gz)'
      },
      secondaryDownload: {
        filename: 'ropweaver-v1.6.3-darwin-x86_64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-x86_64.tar.gz`,
        size: '391 KB',
        label: 'Download Intel x86_64 Archive (.tar.gz)'
      },
      packages: [
        {
          name: 'macOS Apple Silicon (arm64 .tar.gz)',
          filename: 'ropweaver-v1.6.3-darwin-arm64.tar.gz',
          url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-arm64.tar.gz`,
          size: '371 KB',
          sha256: '9e554516e393dc009daa0abfaebb6e79a322432d9c192800f65aedf4e7d596ae'
        },
        {
          name: 'macOS Intel (x86_64 .tar.gz)',
          filename: 'ropweaver-v1.6.3-darwin-x86_64.tar.gz',
          url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-x86_64.tar.gz`,
          size: '391 KB',
          sha256: 'cbdee9879c5cb15274f8b6aeb768e193a8832ed7de0e14d02357282f9ae7e5a4'
        }
      ],
      requirements: 'macOS 12.0 Monterey or later, Terminal with zsh/bash. Note: Core gadget discovery and chain synthesis engines validated on regression test beds; native macOS runtime testing has not been performed on live Apple hardware.',
      verifyCmd: './ropweaver --version'
    }
  };

  const active = downloads[selectedOS] || downloads.windows;
  const ActiveIcon = active.icon;

  return (
    <div className="download-page fade-in">
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver official_releases // product_v1.6.3</span>
        <h1 className="hero-title">Download ROPWeaver</h1>
        <p className="hero-subtitle">
          Official release: <strong className="text-accent-cyan">v1.6.3</strong>.
          Download verified cross-platform release archives for Windows, Linux, and macOS below.
          View complete release notes, changelogs, and corresponding source archives on the official{' '}
          <a
            href={RELEASE_PAGE_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent-green"
            style={{ textDecoration: 'underline', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
          >
            <span>GitHub Release v1.6.3</span>
            <ExternalLink size={12} />
          </a>.
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
                Version: <strong className="text-accent-cyan">{active.version}</strong> &bull; Architecture: <strong className="text-accent-green">{active.arch}</strong> &bull; Released: {active.releaseDate}
              </span>
            </div>
          </div>
          <span className="badge badge-info mono">{active.arch}</span>
        </div>

        {/* Primary & Secondary Download CTAs */}
        <div className="download-buttons-group">
          <a
            href={active.primaryDownload.url}
            className="btn btn-primary btn-large mono"
            target="_blank"
            rel="noopener noreferrer"
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
              className="btn btn-secondary btn-large mono"
              target="_blank"
              rel="noopener noreferrer"
            >
              <Package size={20} />
              <div className="btn-large-text">
                <span className="btn-large-main">{active.secondaryDownload.label}</span>
                <span className="btn-large-sub text-xs">Archive: {active.secondaryDownload.filename} ({active.secondaryDownload.size})</span>
              </div>
            </a>
          )}
        </div>

        {/* Package Manager & Automated Install Notice */}
        <div className="command-install-box">
          <div className="cmd-header">
            <Terminal size={14} className="text-accent-cyan" />
            <span className="mono text-xs font-bold text-accent-cyan">PACKAGE MANAGERS &amp; AUTOMATED SCRIPTS:</span>
          </div>
          <p className="mono text-xs text-muted" style={{ margin: '0.4rem 0 0', lineHeight: '1.5' }}>
            Automated terminal installers and package manager packages (winget, Homebrew, AUR) are <strong className="text-accent-orange">unavailable / coming soon</strong> in a future release. Please download the verified official v1.6.3 release archives above or compile from source.
          </p>
        </div>

        {/* SHA-256 Checksums */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '1rem' }}>
          {active.packages.map((pkg) => (
            <div key={pkg.filename} className="checksum-row mono text-xs" style={{ marginTop: 0 }}>
              <div className="checksum-left">
                <div className="checksum-label-row">
                  <ShieldCheck size={14} className="text-accent-green" style={{ flexShrink: 0 }} />
                  <span className="text-dim">{pkg.filename}:</span>
                </div>
                <span className="checksum-hash text-muted" title={pkg.sha256}>
                  {pkg.sha256}
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(pkg.sha256, pkg.filename)}
                className="copy-mini-btn"
                title={`Copy SHA-256 hash for ${pkg.filename}`}
              >
                {copiedItem === pkg.filename ? <Check size={12} className="text-accent-green" /> : <Copy size={12} />}
                <span>{copiedItem === pkg.filename ? 'COPIED' : 'COPY'}</span>
              </button>
            </div>
          ))}
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
          <h4 className="mono font-bold text-accent-cyan text-sm">Official GitHub Release &amp; Sources</h4>
          <p className="text-muted text-xs" style={{ marginTop: '0.5rem', lineHeight: '1.6' }}>
            All binary packages, SHA-256 digests, and exact corresponding source archives for bundled LGPL/GPL components (libiconv, libidn2, gettext, libunistring, GCC runtime) are published on GitHub.
          </p>
          <a
            href={RELEASE_PAGE_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-outline-cyan btn-xs mono"
            style={{ marginTop: '0.75rem', width: '100%', justifyContent: 'center' }}
          >
            <ExternalLink size={13} />
            <span>View GitHub Release v1.6.3 &rarr;</span>
          </a>
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
