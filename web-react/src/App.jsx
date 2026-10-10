import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import ExplorerPage from './pages/ExplorerPage';
import UploadPage from './pages/UploadPage';
import SearchPage from './pages/SearchPage';
import BinaryDetailPage from './pages/BinaryDetailPage';
import HowtoPage from './pages/HowtoPage';
import AboutPage from './pages/AboutPage';
import DownloadPage from './pages/DownloadPage';
import './App.css';

// Helper to parse current window.location.hash into route state
function parseHashRoute() {
  const hash = window.location.hash || '';
  if (!hash || hash === '#' || hash === '#/' || hash === '#/explorer') {
    return { tab: 'explorer', param: null };
  }
  if (hash.startsWith('#/report/')) {
    const reportId = decodeURIComponent(hash.slice('#/report/'.length));
    return { tab: 'report-detail', param: reportId };
  }
  if (hash.startsWith('#/binary/')) {
    const binaryName = decodeURIComponent(hash.slice('#/binary/'.length));
    return { tab: 'binary-detail', param: binaryName };
  }
  if (hash === '#/upload') return { tab: 'upload', param: null };
  if (hash === '#/search') return { tab: 'search', param: null };
  if (hash === '#/howto' || hash === '#/guide') return { tab: 'howto', param: null };
  if (hash === '#/about') return { tab: 'about', param: null };
  if (hash === '#/download') return { tab: 'download', param: null };

  return { tab: 'explorer', param: null };
}

export default function App() {
  const [route, setRoute] = useState(parseHashRoute);
  const [selectedReportData, setSelectedReportData] = useState(null);
  const [selectedBinary, setSelectedBinary] = useState({
    hash: 'fd635dde8a2c5df766008b4cc7a113ec',
    name: 'p3'
  });

  // Listen to browser hash changes (Back/Forward, address bar navigation)
  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHashRoute();
      setRoute(parsed);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Update hash when navbar tabs are clicked
  const handleNavigateTab = (tabId) => {
    setRoute({ tab: tabId, param: null });
    if (tabId === 'explorer') {
      window.location.hash = '#/explorer';
    } else if (tabId === 'upload') {
      window.location.hash = '#/upload';
    } else if (tabId === 'search') {
      window.location.hash = '#/search';
    } else if (tabId === 'howto' || tabId === 'guide') {
      window.location.hash = '#/guide';
    } else if (tabId === 'about') {
      window.location.hash = '#/about';
    } else if (tabId === 'download') {
      window.location.hash = '#/download';
    } else {
      window.location.hash = `#/${tabId}`;
    }
  };

  // Inspect report action with unique URL redirect: #/report/:id
  const handleInspectReport = (report) => {
    const repId = report.report_id || report.id;
    const cleanName = (report.target_binary?.filename || report["file name"] || report.binary_name || report.id || 'binary').split(/[/\\]/).pop();
    const hash = report.target_binary?.hash || report.target_binary?.sha256 || report.id;

    setSelectedReportData(report);
    setSelectedBinary({
      hash: hash,
      name: cleanName
    });

    setRoute({ tab: 'report-detail', param: repId });
    window.location.hash = `#/report/${encodeURIComponent(repId)}`;
  };

  // Select binary from upload page or search page
  const handleSelectBinarySample = (hash, name, reportId, rawReport) => {
    setSelectedBinary({ hash, name });
    if (rawReport) {
      setSelectedReportData(rawReport);
    }
    if (reportId) {
      setRoute({ tab: 'report-detail', param: reportId });
      window.location.hash = `#/report/${encodeURIComponent(reportId)}`;
    } else {
      setRoute({ tab: 'binary-detail', param: name || hash });
      window.location.hash = `#/binary/${encodeURIComponent(name || hash)}`;
    }
  };

  const handleNavigateToBinary = (bin) => {
    if (typeof bin === 'object' && bin !== null) {
      const repId = bin.report_id || bin.id;
      const bName = (bin.name || bin.filename || bin.target_binary?.filename || 'p1').split(/[/\\]/).pop();
      const bHash = bin.hash || bin.target_binary?.hash || bin.target_binary?.sha256 || 'fd635dde8a2c5df766008b4cc7a113ec';
      setSelectedBinary({ hash: bHash, name: bName });
      setSelectedReportData(bin);

      if (repId) {
        setRoute({ tab: 'report-detail', param: repId });
        window.location.hash = `#/report/${encodeURIComponent(repId)}`;
      } else {
        setRoute({ tab: 'binary-detail', param: bName });
        window.location.hash = `#/binary/${encodeURIComponent(bName)}`;
      }
    } else if (typeof bin === 'string') {
      setSelectedBinary({
        hash: 'fd635dde8a2c5df766008b4cc7a113ec',
        name: bin
      });
      setRoute({ tab: 'binary-detail', param: bin });
      window.location.hash = `#/binary/${encodeURIComponent(bin)}`;
    }
  };

  // Determine active navbar tab highlight
  const currentNavTab = (route.tab === 'report-detail' || route.tab === 'binary-detail')
    ? 'explorer'
    : route.tab;

  return (
    <div className="app-container">
      <Navbar activeTab={currentNavTab} setActiveTab={handleNavigateTab} />

      <main className="main-content">
        {route.tab === 'explorer' && (
          <ExplorerPage 
            onNavigateToBinary={handleNavigateToBinary} 
            onInspectReport={handleInspectReport}
          />
        )}

        {route.tab === 'upload' && (
          <UploadPage onSelectBinarySample={handleSelectBinarySample} />
        )}

        {route.tab === 'search' && (
          <SearchPage
            onSelectBinarySample={handleSelectBinarySample}
            onSelectReportId={(id) => { window.location.hash = `#/report/${encodeURIComponent(id)}`; }}
            onSelectBinary={(name) => { window.location.hash = `#/binary/${encodeURIComponent(name)}`; }}
          />
        )}

        {(route.tab === 'report-detail' || route.tab === 'binary-detail') && (
          <BinaryDetailPage
            reportId={route.tab === 'report-detail' ? route.param : null}
            binaryName={route.tab === 'binary-detail' ? route.param : (selectedBinary.name || route.param)}
            binaryHash={selectedBinary.hash}
            reportData={selectedReportData}
            onBack={() => {
              window.location.hash = '#/explorer';
            }}
          />
        )}

        {route.tab === 'howto' && (
          <HowtoPage onNavigateTab={handleNavigateTab} />
        )}

        {route.tab === 'about' && (
          <AboutPage />
        )}

        {route.tab === 'download' && (
          <DownloadPage onNavigateTab={handleNavigateTab} />
        )}
      </main>

      <Footer onNavigate={handleNavigateTab} />
    </div>
  );
}

