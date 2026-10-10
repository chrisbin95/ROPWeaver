import React from 'react';
import { Info, Mail, Shield, Cpu, Code2, ExternalLink, BookOpen, GraduationCap, Award, GitBranch } from 'lucide-react';

const GithubIcon = ({ size = 16, className = "" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path>
  </svg>
);

export default function AboutPage() {
  const libraries = [
    { name: 'Capstone Engine', desc: 'Multi-platform disassembly framework for x86/x64, ARMv7, AArch64, and RISC-V', link: 'https://www.capstone-engine.org/' },
    { name: 'nlohmann/json', desc: 'Modern JSON library for C++ serialization, telemetry export, and REST payloads', link: 'https://github.com/nlohmann/json' },
    { name: 'libcurl', desc: 'High-performance HTTP/REST client for native Firebase Firestore report uploading', link: 'https://curl.se/libcurl/' },
    { name: 'Google Firebase Firestore', desc: 'Cloud NoSQL document database providing real-time team collaboration and gadget catalog indexing', link: 'https://firebase.google.com/' },
    { name: 'CMake & MinGW GCC / Clang', desc: 'Cross-platform native C++ build automation system across Linux, Windows, and macOS', link: 'https://cmake.org/' },
    { name: 'React & Vite', desc: 'Ultra-fast reactive frontend with asynchronous Firestore querying and interactive shell styling', link: 'https://vitejs.dev/' },
    { name: 'GDB & Pwntools', desc: 'GNU debugger simulation stub and Python exploit development framework for payload validation', link: 'https://github.com/Gallopsled/pwntools' }
  ];

  return (
    <div className="about-page fade-in">
      {/* Hero Header */}
      <div className="explorer-hero">
        <span className="hero-terminal-tag mono">&gt; ropweaver academic_research_and_architecture</span>
        <h1 className="hero-title">About ROPWeaver</h1>
        <p className="hero-subtitle">
          Constructing an advanced, architecture-neutral platform for automated Return-Oriented Programming (ROP) exploit development, multi-ISA gadget analysis, and collaborative cloud reporting.
        </p>
      </div>

      {/* Academic Research Dissertation Banner */}
      <div className="research-citation-card mono text-xs" style={{ marginBottom: '2rem' }}>
        <div className="citation-header">
          <GraduationCap size={18} className="text-accent-green" />
          <span className="citation-title font-bold text-accent-green">
            OXFORD BROOKES UNIVERSITY &bull; MASTER OF SCIENCE DISSERTATION
          </span>
        </div>
        <p className="citation-text text-muted" style={{ margin: '0.6rem 0', lineHeight: '1.7' }}>
          <strong>Dissertation Title:</strong> <em>"Constructing a tool for building Return Oriented Programming exploits"</em><br />
          <strong>Module:</strong> Dissertation Proposal (Course: COMP7039) &bull; Faculty of Technology, Design and Environment<br />
          <strong>Author:</strong> Chrisbin Thomas (Student ID: 19274867) &bull; <strong>Supervisor:</strong> Ian Bayley &bull; <strong>Date Submitted:</strong> 31/05/2025
        </p>
        <div className="citation-badges">
          <span className="badge badge-info">x86 / x86_64</span>
          <span className="badge badge-info">ARMv7 & AArch64</span>
          <span className="badge badge-info">RISC-V (RV64GC)</span>
          <span className="badge badge-warning">ELF &bull; PE &bull; Mach-O &bull; RAW</span>
          <span className="badge badge-on">Firebase Cloud Storage</span>
        </div>
      </div>

      <div className="about-grid">
        {/* Project Rationale & Problem Formulation */}
        <div className="about-card">
          <div className="about-card-title">
            <Shield size={20} className="text-accent-green" />
            <span className="mono font-bold text-accent-green">PROJECT RATIONALE &amp; MOTIVATION</span>
          </div>
          <p className="text-muted text-sm" style={{ marginTop: '0.8rem', lineHeight: '1.7' }}>
            Return-Oriented Programming (ROP) is an essential class of code-reuse attacks that circumvents modern memory mitigations like 
            Address Space Layout Randomization (ASLR) and Non-Executable (NX) stacks. As reduced instruction set computing (RISC) architectures 
            (such as ARM and RISC-V) surge in embedded and cloud systems, manual gadget discovery and chain formulation become increasingly impractical.
          </p>
          <p className="text-muted text-sm" style={{ marginTop: '0.6rem', lineHeight: '1.7' }}>
            While existing tools like <em>ROPgadget</em> provide basic extraction and <em>Angr</em> performs heavy symbolic execution, no unified system existed that combined lightweight native C++ performance, automated multi-architecture gadget classification, runtime debugger simulation (GDB/Pwntools), and real-time cloud collaboration. ROPWeaver bridges this gap.
          </p>
        </div>

        {/* Core Capabilities */}
        <div className="about-card">
          <div className="about-card-title">
            <Cpu size={20} className="text-accent-cyan" />
            <span className="mono font-bold text-accent-cyan">CORE SYSTEM CAPABILITIES</span>
          </div>
          <ul className="about-features-list mono text-xs text-muted" style={{ marginTop: '0.8rem' }}>
            <li>&gt; <strong>Cross-ISA Disassembly:</strong> High-speed parsing of x86, x86_64, ARMv7, AArch64, and RISC-V binaries using Capstone.</li>
            <li>&gt; <strong>Universal Binary Formats:</strong> Native parsers for Linux ELF, Windows PE (.exe/.dll), macOS Mach-O, and RAW firmware blobs.</li>
            <li>&gt; <strong>Automated Semantic Categorization:</strong> Classifies gadgets into system calls, register manipulators, stack pivots, and memory operations.</li>
            <li>&gt; <strong>Automated ROP Chain Synthesis:</strong> Automatically arranges register staging and stack alignment for sys_execve and VirtualProtect payloads.</li>
            <li>&gt; <strong>Defense Mitigations Inspector:</strong> Programmatically checks for Stack Canaries, Non-Executable Stacks (NX/DEP), PIE/ASLR, and RELRO.</li>
            <li>&gt; <strong>Cloud Collaborative Hub:</strong> Native C++ libcurl syncs exploit artifacts directly to Google Firebase Firestore for remote team inspection.</li>
          </ul>
        </div>
      </div>

      {/* Open Source Dependencies */}
      <div className="about-card" style={{ marginTop: '1.5rem' }}>
        <div className="about-card-title">
          <Code2 size={20} className="text-accent-orange" />
          <span className="mono font-bold text-accent-orange">OPEN SOURCE CREDITS &amp; TOOLCHAIN</span>
        </div>
        <p className="text-muted text-xs mono" style={{ marginTop: '0.4rem', marginBottom: '0.8rem' }}>
          ROPWeaver leverages verified open-source libraries to ensure high performance, security, and sustainability:
        </p>
        <div className="credits-grid">
          {libraries.map((lib, idx) => (
            <a
              key={idx}
              href={lib.link}
              target="_blank"
              rel="noopener noreferrer"
              className="credit-item-card"
            >
              <div className="credit-item-header">
                <span className="mono font-bold text-accent-cyan text-sm">{lib.name}</span>
                <ExternalLink size={14} className="text-dim" />
              </div>
              <p className="credit-item-desc text-muted text-xs">{lib.desc}</p>
            </a>
          ))}
        </div>
      </div>

      {/* Maintainer & Research Contact */}
      <div className="about-card" style={{ marginTop: '1.5rem' }}>
        <div className="about-card-title">
          <Info size={20} className="text-accent-purple" />
          <span className="mono font-bold text-accent-purple">RESEARCHER &amp; CONTACT</span>
        </div>
        <p className="text-muted text-sm" style={{ marginTop: '0.8rem', lineHeight: '1.7' }}>
          Developed and maintained by <strong>Chrisbin Thomas</strong> (MSc Computer Science, Oxford Brookes University). 
          For questions regarding the dissertation, tool benchmarks, bug reports, or collaborative security research, feel free to reach out.
        </p>

        <div className="contact-buttons-row" style={{ marginTop: '1.2rem' }}>
          <a
            href="https://github.com/chrisbin95/ROPWeaver.git"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary mono"
          >
            <GithubIcon size={16} />
            <span>GitHub Repository</span>
          </a>
          <a
            href="mailto:chrisbin95@gmail.com"
            className="btn btn-secondary mono"
          >
            <Mail size={16} />
            <span>chrisbin95@gmail.com</span>
          </a>
        </div>
      </div>
    </div>
  );
}
