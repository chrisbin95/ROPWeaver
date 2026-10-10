# ROPWeaver Web — Cloud ROP Exploit & Gadget Explorer (React)

[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.0-646cff.svg)](https://vitejs.dev/)
[![Firebase](https://img.shields.io/badge/Firebase-Firestore-ffca28.svg)](https://firebase.google.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A modern, high-performance, responsive React web interface for **ROPWeaver** (Automated Return-Oriented Programming Exploit Synthesizer & Binary Gadget Analysis Framework).

This frontend connects directly to **Google Cloud Firestore** to query real-time exploit execution reports, disassemble and index thousands of ROP gadgets, and visualize chained payloads with responsive controls, lazy loading, and overflow-protected code containers.

---

## 🌟 Key Features

1. **⚡ Responsive Data Explorer & Search**:
   - Real-time Firestore sync querying the `reports` and `gadgets` collections.
   - Unified search across target binary filenames, MD5 hashes, report IDs, architectures (`x86_64`, `i386`, `ARM`, `RISC-V`), and instruction mnemonics.
   - Quick pattern pills (`pop rdi`, `syscall`, `xchg esp`, `int 0x80`, etc.).
   - Interactive category filtering (`SYSCALL`, `STACK_PIVOT`, `MEM_WRITE`, `LOAD_REG`, etc.).

2. **🚀 Progressive Lazy Loading**:
   - Implemented via `LazyList.jsx` to render large gadget collections in batched slices (25 items per batch).
   - Prevents DOM lockup and keeps scrolling fluid even when dealing with thousands of indexed gadgets.

3. **📜 Overflow-Protected Code & Chain Containers**:
   - Slim custom cyber-scrollbars for assembly instruction listings, raw exploit payloads, and step-by-step ROP chain sequences.
   - 1-click clipboard copy for memory addresses, disassembly mnemonics, and raw hex payloads.

4. **🛡️ Binary Ingestion & Local Header Inspector**:
   - Drag-and-drop file ingestion portal (up to 4MB).
   - In-browser magic byte validation for ELF (`\x7fELF`) and PE (`MZ`) binaries with architecture identification.
   - Reference binary database table matching CTF and system binaries (`vdso`, `p3`, `libc.so.6`, `ROPiah`, etc.).

5. **🔍 Detailed Binary Analysis View**:
   - Interactive breakdown of binaries (matching legacy `p3` / `fd635dde8a2c5df766008b4cc7a113ec.html`) across 9 categorized gadget groups (`call`, `jmp`, `load mem`, `load reg`, `pop pop ret`, `sp lifting`, `stack pivoting`, `syscall`, `write mem`).

6. **📖 Documentation & About Guides**:
   - Interactive CLI command terminal reference with 1-click command copying.
   - Open source dependencies and project architecture guide.

---

## 📁 Repository Folder Structure

This directory is completely self-contained and ready to be pushed to its own GitHub repository:

```text
web-react/
├── .gitignore              # Ignores node_modules, build outputs, and logs
├── index.html              # HTML shell with Google Fonts (Fira Code & Inter) and SEO meta tags
├── package.json            # NPM dependencies (React, Vite, Firebase, Lucide Icons)
├── package-lock.json       # Exact dependency lockfile
├── vite.config.js          # Vite build and dev server configuration
├── README.md               # Repository documentation and setup instructions
├── public/
│   └── favicon.svg         # Custom cyberpunk SVG favicon
└── src/
    ├── main.jsx            # Application root entry point
    ├── App.jsx             # Top-level view router and state coordinator
    ├── App.css             # Responsive styling, cards, tables, and mobile breakpoints
    ├── index.css           # Design tokens, color system, and animations
    ├── firebase/
    │   └── config.js       # Firebase & Firestore initialization with ropweaver credentials
    ├── components/
    │   ├── Navbar.jsx      # Sticky responsive navigation with live Firestore connection dot
    │   ├── Footer.jsx      # Terminal footer with documentation and contact links
    │   ├── StatsPanel.jsx  # Cloud telemetry KPI counters, architecture chips, and quick binary pills
    │   ├── ReportCard.jsx  # Security mitigation badges, ROP chain steps, and payload viewer
    │   ├── GadgetItem.jsx  # Disassembly card with 1-click copy buttons and report links
    │   └── LazyList.jsx    # Progressive batch loader for smooth scrolling of large collections
    └── pages/
        ├── ExplorerPage.jsx     # Main real-time Firestore explorer
        ├── UploadPage.jsx       # Binary dropzone & client-side header inspector
        ├── SearchPage.jsx       # Gadget pattern & database query interface
        ├── BinaryDetailPage.jsx # Categorized gadget breakdown for sample binaries
        ├── HowtoPage.jsx        # Interactive CLI commands & tutorial manual
        └── AboutPage.jsx        # Architecture overview & open source credits
```

---

## 🛠️ Quick Start & Local Development

### 1. Prerequisites
- **Node.js**: v18.0.0 or higher
- **NPM**: v9.0.0 or higher

### 2. Install Dependencies
```bash
npm install
```

### 3. Run Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:5173` to explore the application with Hot Module Replacement (HMR).

### 4. Build for Production
```bash
npm run build
```
The optimized static build will be generated in the `dist/` directory.

### 5. Preview Production Build
```bash
npm run preview
```

---

## 🚀 How to Upload to a New GitHub Repository

You can initialize a new repository directly from this folder:

```bash
# 1. Navigate to the web-react folder
cd web-react

# 2. Initialize git
git init

# 3. Add all files
git add .

# 4. Commit changes
git commit -m "Initial commit: ROPWeaver React Cloud Explorer"

# 5. Rename branch to main
git branch -M main

# 6. Add your new GitHub remote URL
git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_NEW_REPO_NAME>.git

# 7. Push to GitHub
git push -u origin main
```

---

## 🔐 Firebase Firestore Configuration

Firebase is pre-configured in `src/firebase/config.js` to connect to project `ropweaver`. If you want to connect to a different Firebase instance, update the configuration parameters in that file:

```javascript
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_AUTH_DOMAIN",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_STORAGE_BUCKET",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
};
```

---

## 📄 License

This project is licensed under the MIT License.
