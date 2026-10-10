import React, { useState, useEffect } from 'react';
import { Search, Database, ArrowRight, Code, Filter, Sparkles, Terminal } from 'lucide-react';
import { db, collection, getDocs } from '../firebase/config';
import GadgetItem from '../components/GadgetItem';
import LazyList from '../components/LazyList';

export default function SearchPage({ onSelectBinarySample, onSelectReportId, onSelectBinary }) {
  const [pattern, setPattern] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [gadgets, setGadgets] = useState([]);
  const [filteredResults, setFilteredResults] = useState([]);
  const [loading, setLoading] = useState(false);

  // Live registered databases fetched directly from Firebase Firestore
  const [registeredDatabases, setRegisteredDatabases] = useState([]);
  const [loadingDatabases, setLoadingDatabases] = useState(true);

  const categories = ['ALL', 'SYSCALL', 'REGISTER_MOVE', 'STACK_PIVOT', 'MEM_WRITE', 'MEM_LOAD', 'JMP/CALL'];

  const quickPatterns = [
    { label: 'pop rdi', query: 'pop rdi' },
    { label: 'syscall', query: 'syscall' },
    { label: 'xchg esp', query: 'xchg esp' },
    { label: 'pop pop ret', query: 'pop' },
    { label: 'int 0x80', query: 'int 0x80' },
    { label: 'jmp rax', query: 'jmp rax' }
  ];

  useEffect(() => {
    // Load live gadgets and registered binaries from Firestore
    const fetchData = async () => {
      setLoading(true);
      setLoadingDatabases(true);
      try {
        const [reportsSnap, gadgetsSnap] = await Promise.all([
          getDocs(collection(db, "reports")),
          getDocs(collection(db, "gadgets"))
        ]);

        const gadgetCountsByBinary = {};
        const gadgetsList = [];

        gadgetsSnap.forEach((doc) => {
          const g = { id: doc.id, ...doc.data() };
          gadgetsList.push(g);
          const rawFn = g["file name"] || g.fileName || g.binary_name || '';
          const cleanFn = (typeof rawFn === 'string' ? rawFn : '').split(/[/\\]/).pop();
          if (cleanFn) {
            gadgetCountsByBinary[cleanFn] = (gadgetCountsByBinary[cleanFn] || 0) + 1;
          }
        });

        setGadgets(gadgetsList);
        setFilteredResults(gadgetsList);

        // Aggregate unique registered databases from reports + gadgets
        const dbList = [];
        const seenNames = new Set();

        reportsSnap.forEach((doc) => {
          const d = { id: doc.id, ...doc.data() };
          const rawName = d.target_binary?.filename || d.target_binary || d["file name"] || d.binary_name || d.id;
          const cleanName = (typeof rawName === 'string' ? rawName : d.id).split(/[/\\]/).pop() || 'binary';
          const hash = d.target_binary?.hash || d.target_binary?.sha256 || d.hash || d.id;
          const arch = d.architecture || (d.binary_analysis && d.binary_analysis.architecture) || 'x86_64';
          const type = d.file_type || d.format || (d.binary_analysis && d.binary_analysis.format) || 'ELF';
          const embeddedCount = Array.isArray(d.gadgets) ? d.gadgets.length : 0;
          const count = embeddedCount > 0 ? embeddedCount : (gadgetCountsByBinary[cleanName] || 0);

          if (!seenNames.has(cleanName)) {
            seenNames.add(cleanName);
            dbList.push({
              id: d.id,
              reportId: d.report_id || d.id,
              name: cleanName,
              rawPath: typeof rawName === 'string' ? rawName : cleanName,
              hash: hash,
              arch: arch,
              type: type,
              count: count,
              rawReport: d
            });
          }
        });

        // Also check any binary in gadgets that didn't have an explicit report entry
        Object.entries(gadgetCountsByBinary).forEach(([fn, count]) => {
          if (!seenNames.has(fn)) {
            seenNames.add(fn);
            dbList.push({
              id: fn,
              reportId: fn,
              name: fn,
              rawPath: fn,
              hash: fn,
              arch: 'x86_64',
              type: 'ELF',
              count: count,
              rawReport: null
            });
          }
        });

        setRegisteredDatabases(dbList);
      } catch (err) {
        console.warn("Could not load data from Firestore:", err);
      } finally {
        setLoading(false);
        setLoadingDatabases(false);
      }
    };

    fetchData();
  }, []);

  const handleSearch = (queryPattern = pattern, category = selectedCategory) => {
    let results = gadgets;
    const q = queryPattern.trim().toLowerCase();

    if (q) {
      results = results.filter(g => {
        const instr = (g.instructions || g.gadget || '').toLowerCase();
        const bin = (g["file name"] || g.fileName || '').toLowerCase();
        const hash = (g.hash || '').toLowerCase();
        const addr = (g.address || '').toLowerCase();
        return instr.includes(q) || bin.includes(q) || hash.includes(q) || addr.includes(q);
      });
    }

    if (category !== 'ALL') {
      const catLower = category.toLowerCase();
      results = results.filter(g => {
        const instr = (g.instructions || g.gadget || '').toLowerCase();
        const cat = (g.category || '').toLowerCase();
        if (catLower === 'syscall') return instr.includes('syscall') || instr.includes('int 0x80');
        if (catLower === 'stack_pivot') return instr.includes('esp') || instr.includes('rsp') || instr.includes('xchg');
        if (catLower === 'mem_write') return instr.includes('[') && (instr.includes('mov') || instr.includes('add'));
        if (catLower === 'jmp/call') return instr.includes('jmp') || instr.includes('call');
        return cat.includes(catLower) || instr.includes(catLower);
      });
    }

    setFilteredResults(results);
  };

  const onFormSubmit = (e) => {
    e.preventDefault();
    handleSearch(pattern, selectedCategory);
  };

  const handleCategoryClick = (cat) => {
    setSelectedCategory(cat);
    handleSearch(pattern, cat);
  };

  const handleQuickPattern = (p) => {
    setPattern(p);
    handleSearch(p, selectedCategory);
  };

  // Filter registered databases dynamically by search term
  const displayedDatabases = registeredDatabases.filter(b => {
    if (!pattern.trim()) return true;
    const q = pattern.trim().toLowerCase();
    return (
      b.name.toLowerCase().includes(q) ||
      b.hash.toLowerCase().includes(q) ||
      b.arch.toLowerCase().includes(q) ||
      b.type.toLowerCase().includes(q)
    );
  });

  return (
    <div className="search-page fade-in">
      {/* Hero Header */}
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver query_interface</span>
        <h1 className="hero-title">Gadget Pattern & Database Search</h1>
        <p className="hero-subtitle">
          Search indexed gadget databases by assembly mnemonic, register constraints, or binary hash.
        </p>
      </div>

      {/* Search Input Box */}
      <div className="search-section-card">
        <form onSubmit={onFormSubmit} className="search-form-row">
          <div className="search-input-wrap">
            <Search size={18} className="search-icon text-muted" />
            <input
              type="text"
              className="search-input mono"
              placeholder="binary name, md5 hash, or instruction pattern (e.g. pop rdi, syscall)..."
              value={pattern}
              onChange={(e) => {
                setPattern(e.target.value);
                handleSearch(e.target.value, selectedCategory);
              }}
            />
          </div>
          <button type="submit" className="btn btn-primary">
            <Search size={15} />
            <span>Search</span>
          </button>
        </form>

        {/* Quick Pattern Suggestions */}
        <div className="quick-patterns-row">
          <span className="mono text-xs text-muted">
            <Sparkles size={12} className="text-accent-orange" /> QUICK PATTERNS:
          </span>
          {quickPatterns.map((qp, idx) => (
            <button
              key={idx}
              onClick={() => handleQuickPattern(qp.query)}
              className="pattern-pill mono"
            >
              {qp.label}
            </button>
          ))}
        </div>

        {/* Category Pills */}
        <div className="category-filter-row">
          <span className="mono text-xs text-muted">
            <Filter size={12} /> CATEGORY:
          </span>
          <div className="category-chips">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => handleCategoryClick(cat)}
                className={`category-chip mono ${selectedCategory === cat ? 'active' : ''}`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Search Results */}
      <div className="search-results-section">
        <div className="results-section-header">
          <span className="section-header-title mono">
            ==«✪»== Matching Discovered Gadgets ({filteredResults.length}) ==«✪»==
          </span>
        </div>

        <LazyList
          items={filteredResults}
          initialCount={25}
          step={25}
          emptyMessage="No gadgets found matching the query criteria."
          renderItem={(gadget, index) => (
            <GadgetItem
              key={gadget.id || index}
              gadget={gadget}
              index={index + 1}
              onSelectReportId={onSelectReportId}
              onSelectBinary={onSelectBinary}
            />
          )}
        />
      </div>

      {/* Available Gadget Databases Reference Table — Live Firebase Firestore Data Only */}
      <div className="recent-table-card" style={{ marginTop: '2.5rem' }}>
        <div className="recent-table-header">
          <span className="mono font-semibold text-accent-cyan">&gt; ropshell &gt; registered gadget databases</span>
          <span className="mono text-dim text-xs">Indexed cloud binaries in datastore ({displayedDatabases.length})</span>
        </div>

        {loadingDatabases ? (
          <div className="loading-state-card" style={{ padding: '2rem' }}>
            <div className="cyber-spinner mini" style={{ margin: '0 auto 0.75rem' }}></div>
            <span className="mono text-accent-cyan text-xs">QUERYING REGISTERED DATABASES FROM FIRESTORE...</span>
          </div>
        ) : displayedDatabases.length === 0 ? (
          <div className="empty-recent-box mono text-xs text-dim" style={{ padding: '2rem', textAlign: 'center' }}>
            {pattern ? `No registered gadget databases found matching "${pattern}".` : 'No registered gadget databases found in cloud registry.'}
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
                {displayedDatabases.map((b, idx) => {
                  const safeHash = typeof b.hash === 'string' ? b.hash : '';
                  const displayHash = safeHash.length > 16 ? safeHash.slice(0, 16) + '...' : (safeHash || 'N/A');
                  return (
                    <tr key={idx} className="recent-row">
                      <td className="hash-col text-dim mono" title={safeHash}>
                        {displayHash}
                      </td>
                      <td className="name-col text-accent-green font-bold">
                        <button
                          onClick={() => {
                            if (onSelectBinarySample) {
                              onSelectBinarySample(b.hash, b.name, b.reportId, b.rawReport);
                            } else {
                              window.location.hash = `#/report/${encodeURIComponent(b.reportId || b.id || b.name)}`;
                            }
                          }}
                          className="clickable-title"
                          style={{ background: 'none', border: 'none', padding: 0, textAlign: 'left', cursor: 'pointer' }}
                          title="Open registered database"
                        >
                          &gt;_ {b.name}
                        </button>
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
                              const targetId = b.reportId || b.id || b.name;
                              window.location.hash = `#/report/${encodeURIComponent(targetId)}`;
                            }
                          }}
                          className="btn btn-secondary btn-xs mono"
                          title="Open and inspect this binary database"
                        >
                          <span>Open DB</span>
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
