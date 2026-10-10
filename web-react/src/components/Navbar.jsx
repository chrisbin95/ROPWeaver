import React, { useState } from 'react';
import { Terminal, Upload, Search, BookOpen, Info, Menu, X, Download } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'explorer', label: 'Explorer', icon: Terminal },
    { id: 'upload', label: 'Upload', icon: Upload },
    { id: 'search', label: 'Search', icon: Search },
    { id: 'howto', label: 'Developer Guide', icon: BookOpen },
    { id: 'about', label: 'About', icon: Info },
  ];

  const handleNavClick = (id) => {
    setActiveTab(id);
    setMobileMenuOpen(false);
  };

  return (
    <header className="navbar-container">
      <div className="navbar-content">
        <div className="navbar-brand" onClick={() => handleNavClick('explorer')}>
          <div className="brand-logo">
            <Terminal size={20} className="brand-icon" />
          </div>
          <div className="brand-text">
            <span className="brand-title">ROPWeaver</span>
            <span className="brand-badge hide-mobile-sm">CLOUD EXPLORER</span>
          </div>
        </div>

        {/* Desktop Nav */}
        <nav className="desktop-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`nav-link ${isActive ? 'nav-link-active' : ''}`}
              >
                <Icon size={16} />
                <span>{item.label}</span>
                {isActive && <div className="nav-link-indicator" />}
              </button>
            );
          })}
        </nav>

        {/* Right Section: Download Button + Mobile Hamburger Toggle */}
        <div className="navbar-right-group">
          <div className="navbar-actions hide-mobile-sm">
            <button
              onClick={() => handleNavClick('download')}
              className={`nav-download-btn ${activeTab === 'download' ? 'nav-download-btn-active' : ''}`}
              title="Download ROPWeaver for your OS"
            >
              <Download size={14} />
              <span>DOWNLOAD</span>
              <span className="download-pill mono">v1.2.3</span>
            </button>
          </div>

          {/* Mobile Hamburger Toggle Button */}
          <button
            className="mobile-toggle"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="mobile-menu fade-in">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`mobile-nav-link ${isActive ? 'mobile-nav-link-active' : ''}`}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
          <div className="mobile-menu-divider" />
          <button
            onClick={() => handleNavClick('download')}
            className={`mobile-nav-link mobile-nav-download ${activeTab === 'download' ? 'mobile-nav-link-active' : ''}`}
          >
            <Download size={18} />
            <span>Download ROPWeaver (v1.2.3)</span>
          </button>
        </div>
      )}
    </header>
  );
}
