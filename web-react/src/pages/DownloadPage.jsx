import React, { useState, useEffect, useMemo } from 'react';
import {
  Download, Check, Copy, Terminal, ShieldCheck, Laptop, Apple, Sparkles,
  Package, ExternalLink, RefreshCw, BookOpen, Code2, AlertTriangle, Cpu
} from 'lucide-react';
import {
  detectPlatformAndArch,
  getRecommendedDownload
} from '../utils/platformHelper';

const RELEASE_PAGE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.3';
const DOWNLOAD_BASE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.3';
const SOURCE_CODE_ZIP_URL = 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.3.zip';
const SOURCE_CODE_TAR_URL = 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.3.tar.gz';
const GIT_REPO_URL = 'https://github.com/chrisbin95/ROPWeaver.git';

export default function DownloadPage({ onNavigateTab }) {
  const [highEntropyHints, setHighEntropyHints] = useState(null);
  const [copiedItem, setCopiedItem] = useState(null);

  // 1. Asynchronously retrieve High-Entropy Client Hints if supported
  useEffect(() => {
    if (typeof navigator !== 'undefined' && navigator.userAgentData?.getHighEntropyValues) {
      navigator.userAgentData.getHighEntropyValues(['architecture', 'bitness', 'platform', 'model'])
        .then((hints) => {
          setHighEntropyHints(hints);
        })
        .catch(() => {});
    }
  }, []);

  // 2. Clean up any stale ropweaver_preferred_os cookie
  useEffect(() => {
    try {
      document.cookie = 'ropweaver_preferred_os=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax';
    } catch {}
  }, []);

  // 3. Compute client detection & recommendation
  const clientDetection = useMemo(() => {
    return detectPlatformAndArch(
      typeof navigator !== 'undefined' ? navigator : {},
      highEntropyHints
    );
  }, [highEntropyHints]);

  const recommendation = useMemo(() => {
    return getRecommendedDownload(clientDetection);
  }, [clientDetection]);

  // 4. Manual selection state (defaults to recommendation, can be changed by user)
  const [selectedOS, setSelectedOS] = useState(recommendation.recommendedOS || 'windows');
  const [selectedArch, setSelectedArch] = useState(
    recommendation.recommendedArch || (recommendation.recommendedOS === 'macos' ? null : 'x86_64')
  );
  // Track whether the user has explicitly changed the OS selection from the initial default.
  // Once the user manually picks an OS, automatic recommendation syncing must NOT override their choice.
  const [userHasExplicitlySelected, setUserHasExplicitlySelected] = useState(false);

  // Sync selection only when the initial asynchronous highEntropyHints arrive AND the user has
  // not yet made an explicit manual selection. This allows the initial auto-detection to update
  // from a UA-based guess (e.g., 'windows' default) to the more accurate high-entropy result,
  // but once the user clicks any OS card or dropdown option, their choice is permanently locked.
  useEffect(() => {
    if (
      !userHasExplicitlySelected &&
      recommendation.recommendedOS &&
      selectedOS === 'windows' &&
      clientDetection.platform !== 'windows'
    ) {
      setSelectedOS(recommendation.recommendedOS);
      setSelectedArch(
        recommendation.recommendedArch || (recommendation.recommendedOS === 'macos' ? null : 'x86_64')
      );
    }
  }, [recommendation, clientDetection.platform, selectedOS, userHasExplicitlySelected]);

  const handleSelectOS = (osKey) => {
    setSelectedOS(osKey);
    setUserHasExplicitlySelected(true);
    // Pick sensible default arch for the newly chosen OS
    if (osKey === 'windows') {
      setSelectedArch('x86_64');
    } else if (osKey === 'linux') {
      setSelectedArch('x86_64');
    } else if (osKey === 'macos') {
      if (clientDetection.arch === 'x86_64') setSelectedArch('x86_64');
      else if (clientDetection.arch === 'arm64') setSelectedArch('arm64');
      else setSelectedArch(null); // Unknown architecture requires explicit user selection
    } else if (osKey === 'source') {
      setSelectedArch('source');
    }
  };

  const handleSelectArch = (archKey) => {
    setSelectedArch(archKey);
  };

  const handleResetToRecommended = () => {
    setSelectedOS(recommendation.recommendedOS || 'windows');
    setSelectedArch(
      recommendation.recommendedArch || (recommendation.recommendedOS === 'macos' ? null : 'x86_64')
    );
    // Resetting to recommendation re-enables future auto-syncing
    setUserHasExplicitlySelected(false);
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(id);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  // Supported architecture tabs per OS
  const osArchMap = {
    windows: [
      { id: 'x86_64', label: 'x86_64 / AMD64', available: true },
      { id: 'arm64', label: 'ARM64 (Unavailable)', available: false }
    ],
    linux: [
      { id: 'x86_64', label: 'x86_64 / AMD64', available: true },
      { id: 'arm64', label: 'ARM64 / AArch64 (Unavailable)', available: false },
      { id: 'riscv64', label: 'RISC-V 64-bit (Unavailable)', available: false }
    ],
    macos: [
      { id: 'arm64', label: 'Apple Silicon (arm64)', available: true },
      { id: 'x86_64', label: 'Intel (x86_64)', available: true }
    ],
    source: [
      { id: 'source', label: 'Source Archives & Git', available: true }
    ]
  };

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
        filename: 'ropweaver-windows-x64.exe',
        url: '/ropweaver-windows-x64.exe',
        size: '9.5 MB',
        label: 'Download Standalone Executable (.exe with embedded runtime)'
      },
      secondaryDownload: {
        filename: 'ropweaver-v1.6.3-win64.zip',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-win64.zip`,
        size: '9.5 MB',
        label: 'Download Portable Bundle (.zip with DLLs & Samples)'
      },
      packages: [
        {
          name: 'Standalone Windows x64 Executable',
          filename: 'ropweaver-windows-x64.exe',
          url: '/ropweaver-windows-x64.exe',
          size: '9.5 MB',
          sha256: '53baa53a2c1c3c22e6d49a21bbbf89ba1838a19fe465666a61aa978ee6ffd02f'
        },
        {
          name: 'Windows x86_64 ZIP Archive',
          filename: 'ropweaver-v1.6.3-win64.zip',
          url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-win64.zip`,
          size: '9.5 MB',
          sha256: 'd9acde6bfee97cd71630ad4d97f1e709a78131c98ddb2b397578ed9286941fd4'
        }
      ],
      requirements: 'Windows 10 build 19041+ or Windows 11, x64 architecture (Zero external dependencies; auto-extracts portable runtime)',
      verifyCmd: '.\\ropweaver-windows-x64.exe --version'
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
      arch: selectedArch === 'x86_64' ? 'Intel (x86_64)' : (selectedArch === 'arm64' ? 'Apple Silicon (arm64)' : 'Choose Architecture'),
      releaseDate: 'November 2026',
      icon: Apple,
      primaryDownload: selectedArch === 'x86_64' ? {
        filename: 'ropweaver-v1.6.3-darwin-x86_64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-x86_64.tar.gz`,
        size: '391 KB',
        label: 'Download Intel x86_64 Archive (.tar.gz)'
      } : {
        filename: 'ropweaver-v1.6.3-darwin-arm64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-arm64.tar.gz`,
        size: '371 KB',
        label: 'Download Apple Silicon Archive (arm64 .tar.gz)'
      },
      secondaryDownload: selectedArch === 'x86_64' ? {
        filename: 'ropweaver-v1.6.3-darwin-arm64.tar.gz',
        url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.3-darwin-arm64.tar.gz`,
        size: '371 KB',
        label: 'Download Apple Silicon Archive (arm64 .tar.gz)'
      } : {
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
    },
    source: {
      name: 'Source Code',
      fullName: 'Source Code & Native Compilation',
      version: 'v1.6.3',
      arch: 'All Supported Platforms (C99 / C++17)',
      releaseDate: 'November 2026',
      icon: Code2,
      primaryDownload: {
        filename: 'v1.6.3.tar.gz',
        url: SOURCE_CODE_TAR_URL,
        size: '1.2 MB',
        label: 'Download Source Archive (.tar.gz)'
      },
      secondaryDownload: {
        filename: 'v1.6.3.zip',
        url: SOURCE_CODE_ZIP_URL,
        size: '1.4 MB',
        label: 'Download Source Archive (.zip)'
      },
      packages: [
        {
          name: 'Official v1.6.3 Source Code (tar.gz)',
          filename: 'ROPWeaver-1.6.3.tar.gz',
          url: SOURCE_CODE_TAR_URL,
          size: '1.2 MB',
          sha256: 'Verified GitHub Release Source Archive'
        },
        {
          name: 'Official v1.6.3 Source Code (zip)',
          filename: 'ROPWeaver-1.6.3.zip',
          url: SOURCE_CODE_ZIP_URL,
          size: '1.4 MB',
          sha256: 'Verified GitHub Release Source Archive'
        }
      ],
      requirements: 'CMake 3.16+, C99/C++17 compiler (GCC, Clang, or MSVC), Capstone 5.0+ development headers, libcurl dev libraries',
      verifyCmd: 'cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build'
    }
  };

  const active = downloads[selectedOS] || downloads.windows;
  const ActiveIcon = active.icon;

  // Determine whether the currently selected arch for the selected OS is published/available
  const isSelectedArchAvailable = useMemo(() => {
    if (selectedOS === 'source') return true;
    if (selectedOS === 'windows') return selectedArch === 'x86_64';
    if (selectedOS === 'linux') return selectedArch === 'x86_64';
    if (selectedOS === 'macos') return selectedArch === 'arm64' || selectedArch === 'x86_64';
    return false;
  }, [selectedOS, selectedArch]);

  const isCurrentViewingRecommended =
    selectedOS === recommendation.recommendedOS &&
    (selectedArch === recommendation.recommendedArch || (!recommendation.recommendedArch && !selectedArch));

  return (
    <div className="download-page fade-in">
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver official_releases // product_v1.6.3</span>
        <h1 className="hero-title">Download ROPWeaver</h1>
        <p className="hero-subtitle">
          Official release: <strong className="text-accent-cyan">v1.6.3</strong>.
          Download verified cross-platform release archives for Windows, Linux, and macOS below, or build directly from source.
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

      {/* Architecture & Client Detection Banner */}
      <div className="detection-banner mono text-xs">
        <div className="detection-left">
          <Sparkles size={16} className="text-accent-green" />
          <span>
            DEVICE ENVIRONMENT: <strong className="text-accent-cyan">{clientDetection.displayLabel}</strong>
            <span className="text-muted"> (detected via browser signals)</span>
          </span>
        </div>
        {!isCurrentViewingRecommended ? (
          <button
            type="button"
            onClick={handleResetToRecommended}
            className="refresh-detect-btn"
            title={`Switch view back to recommended (${recommendation.title})`}
          >
            <RefreshCw size={12} />
            <span>Show Recommended ({recommendation.title})</span>
          </button>
        ) : (
          <div className="text-accent-green mono" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Check size={14} />
            <span>Viewing Recommended</span>
          </div>
        )}
      </div>

      {/* Mobile Visitor Warning if on mobile device */}
      {clientDetection.isMobile && (
        <div className="detection-banner mono text-xs" style={{ background: 'rgba(255, 170, 0, 0.1)', borderColor: 'rgba(255, 170, 0, 0.4)', marginTop: '-0.75rem', marginBottom: '1.25rem' }}>
          <div className="detection-left" style={{ alignItems: 'flex-start' }}>
            <AlertTriangle size={16} className="text-accent-orange" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong className="text-accent-orange">MOBILE DEVICE DETECTED ({clientDetection.platform.toUpperCase()}):</strong>
              <div className="text-muted" style={{ marginTop: '0.25rem' }}>
                Pre-compiled ROPWeaver packages are built for desktop and server operating systems. Desktop CLI binaries are not directly runnable on mobile environments. Please access this page from your Windows, Linux, or macOS workstation, or inspect source code below.
              </div>
            </div>
          </div>
        </div>
      )}

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
            <option value="source">📦 Source Code & Git Repository</option>
          </select>
        </div>

        <div className="os-cards-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
          {Object.entries(downloads).map(([key, item]) => {
            const ItemIcon = item.icon;
            const isSelected = selectedOS === key;
            const isRec = key === recommendation.recommendedOS;
            return (
              <div
                key={key}
                onClick={() => handleSelectOS(key)}
                className={`os-selector-box ${isSelected ? 'selected' : ''}`}
              >
                <div className="os-box-top">
                  <ItemIcon size={24} className={isSelected ? 'text-accent-green' : 'text-dim'} />
                  {isRec && (
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
                Version: <strong className="text-accent-cyan">{active.version}</strong> &bull; Released: {active.releaseDate}
              </span>
            </div>
          </div>
          <span className="badge badge-info mono">{selectedArch ? selectedArch.toUpperCase() : 'SELECT ARCHITECTURE'}</span>
        </div>

        {/* Architecture Selector for Selected OS */}
        {osArchMap[selectedOS] && osArchMap[selectedOS].length > 1 && (
          <div style={{ marginBottom: '1.25rem', paddingBottom: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>
            <span className="mono text-xs text-muted" style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 600 }}>
              SELECT TARGET ARCHITECTURE:
            </span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {osArchMap[selectedOS].map((archOption) => {
                const isCurrentArch = selectedArch === archOption.id;
                return (
                  <button
                    key={archOption.id}
                    type="button"
                    onClick={() => handleSelectArch(archOption.id)}
                    className={`btn btn-xs mono ${isCurrentArch ? 'btn-primary' : 'btn-outline-cyan'}`}
                    style={{
                      borderColor: isCurrentArch ? 'var(--accent-green)' : undefined,
                      background: isCurrentArch ? 'rgba(0, 255, 136, 0.15)' : undefined,
                      color: isCurrentArch ? 'var(--accent-green)' : undefined
                    }}
                  >
                    <Cpu size={12} />
                    <span>{archOption.label}</span>
                    {!archOption.available && (
                      <span style={{ fontSize: '0.65rem', opacity: 0.8, marginLeft: '4px' }}>[UNAVAILABLE]</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* macOS Architecture Prompt when arch is unselected */}
        {selectedOS === 'macos' && !selectedArch ? (
          <div className="command-install-box" style={{ background: 'rgba(0, 210, 255, 0.05)', borderColor: 'rgba(0, 210, 255, 0.3)', padding: '1.25rem' }}>
            <div className="cmd-header" style={{ alignItems: 'flex-start' }}>
              <Cpu size={18} className="text-accent-cyan" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <span className="mono text-sm font-bold text-accent-cyan">
                  CHOOSE YOUR MAC ARCHITECTURE
                </span>
                <p className="mono text-xs text-muted" style={{ margin: '0.5rem 0 0', lineHeight: '1.6' }}>
                  ROPWeaver provides native v1.6.3 packages for both Apple Silicon (M1/M2/M3/M4) and Intel (x86_64) Macs.
                  Browser privacy protections do not expose your Mac's CPU architecture. Please select your architecture below to view download options:
                </p>
              </div>
            </div>

            <div style={{ marginTop: '1.25rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
              <button
                type="button"
                onClick={() => handleSelectArch('arm64')}
                className="btn btn-primary btn-large mono"
                style={{ justifyContent: 'flex-start', textAlign: 'left' }}
              >
                <Apple size={22} />
                <div className="btn-large-text">
                  <span className="btn-large-main">Apple Silicon (arm64)</span>
                  <span className="btn-large-sub text-xs">M1 / M2 / M3 / M4 Macs (371 KB)</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => handleSelectArch('x86_64')}
                className="btn btn-secondary btn-large mono"
                style={{ justifyContent: 'flex-start', textAlign: 'left' }}
              >
                <Laptop size={22} />
                <div className="btn-large-text">
                  <span className="btn-large-main">Intel Mac (x86_64)</span>
                  <span className="btn-large-sub text-xs">Core i5 / i7 / i9 / Xeon Macs (391 KB)</span>
                </div>
              </button>
            </div>
          </div>
        ) : isSelectedArchAvailable ? (
          <>
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
          </>
        ) : (
          /* Architecture Unavailable Notice (e.g. RISC-V 64-bit, Linux ARM64, Windows ARM64) */
          <div className="command-install-box" style={{ background: 'rgba(255, 170, 0, 0.05)', borderColor: 'rgba(255, 170, 0, 0.3)', padding: '1.25rem' }}>
            <div className="cmd-header" style={{ alignItems: 'flex-start' }}>
              <AlertTriangle size={18} className="text-accent-orange" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <span className="mono text-sm font-bold text-accent-orange">
                  PRE-COMPILED BINARY UNAVAILABLE FOR {active.name.toUpperCase()} ({selectedArch.toUpperCase()})
                </span>
                <p className="mono text-xs text-muted" style={{ margin: '0.5rem 0 0', lineHeight: '1.6' }}>
                  An official pre-compiled v1.6.3 binary package is not published for {active.name} on {selectedArch}.
                  ROPWeaver's engine fully supports {selectedArch} target analysis and compilation, and can be built directly from source using CMake on this architecture.
                </p>
              </div>
            </div>

            <div style={{ marginTop: '1.25rem', display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => handleSelectOS('source')}
                className="btn btn-primary btn-sm mono"
              >
                <Code2 size={14} />
                <span>View Source Code &amp; Build Instructions</span>
              </button>
              <a
                href={SOURCE_CODE_TAR_URL}
                className="btn btn-secondary btn-sm mono"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Download size={14} />
                <span>Download Source Archive (v1.6.3.tar.gz)</span>
              </a>
            </div>
          </div>
        )}

        {/* Source Code Special Section */}
        {selectedOS === 'source' && (
          <div className="verification-box mono text-xs text-muted" style={{ marginTop: '1rem' }}>
            <p className="text-accent-cyan font-bold">&gt; Quick Source Build:</p>
            <pre style={{ margin: '0.5rem 0', padding: '0.75rem', background: 'rgba(0,0,0,0.4)', borderRadius: '4px', overflowX: 'auto' }}>
{`git clone ${GIT_REPO_URL}
cd ROPWeaver
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
./build/ropweaver --version`}
            </pre>
            <p>&gt; Cross-Platform Python Launcher: <code>python tools/universal_launcher/ropweaver_universal.py &lt;binary&gt; --list-gadgets</code></p>
          </div>
        )}
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
