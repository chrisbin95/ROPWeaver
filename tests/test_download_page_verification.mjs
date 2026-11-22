/**
 * Automated Verification Script for DownloadPage.jsx Release Assets
 */
import fs from 'node:fs';
import assert from 'node:assert';

console.log('Verifying DownloadPage.jsx Release Asset Integrity...\n');

const content = fs.readFileSync('web-react/src/pages/DownloadPage.jsx', 'utf-8');

// 1. Verify published release base URL & tag
const expectedBaseUrl = 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.3';
const expectedReleaseUrl = 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.3';

assert.ok(content.includes(expectedBaseUrl), 'Must contain exact v1.6.3 download base URL');
assert.ok(content.includes(expectedReleaseUrl), 'Must contain exact v1.6.3 release page URL');

// 2. Verify all six distribution options and SHA-256 digests
const expectedAssets = [
  {
    name: 'Windows Standalone Executable',
    file: 'ropweaver-windows-x64.exe',
    sha256: '552b82173df0f09528a793368ed168b1c70204e4549b05ab1a682809ed38df98'
  },
  {
    name: 'Windows x86_64 ZIP',
    file: 'ropweaver-v1.6.3-win64.zip',
    sha256: '80a99faf4c81fde7d963978f03ecc7ad00a9c17ec208ac6dae49dfb4d8c154d5'
  },
  {
    name: 'Linux Debian/Ubuntu AMD64 DEB',
    file: 'ropweaver_1.6.3_amd64.deb',
    sha256: 'c2f21c8367ac0ccdac45e9edc33d0d2ebca460323a8628d09d3a38d6613024e8'
  },
  {
    name: 'Linux x86_64 Standalone TAR.GZ',
    file: 'ropweaver-v1.6.3-linux-x86_64.tar.gz',
    sha256: 'e2ec7e636c2051343c7ff14f1aef0ef0e735226c635b4a120c9aadc6764acb10'
  },
  {
    name: 'macOS Apple Silicon ARM64 TAR.GZ',
    file: 'ropweaver-v1.6.3-darwin-arm64.tar.gz',
    sha256: '9e554516e393dc009daa0abfaebb6e79a322432d9c192800f65aedf4e7d596ae'
  },
  {
    name: 'macOS Intel x86_64 TAR.GZ',
    file: 'ropweaver-v1.6.3-darwin-x86_64.tar.gz',
    sha256: 'cbdee9879c5cb15274f8b6aeb768e193a8832ed7de0e14d02357282f9ae7e5a4'
  }
];

expectedAssets.forEach(asset => {
  assert.ok(content.includes(asset.file), `Missing expected file ${asset.file}`);
  assert.ok(content.includes(asset.sha256), `Missing expected SHA-256 hash for ${asset.file}`);
  console.log(`  [OK] ${asset.name} (${asset.file}) -> ${asset.sha256}`);
});

// 3. Verify absence of obsolete legacy download URLs
assert.ok(!content.includes('/ropweaver-v1.2.3'), 'Obsolete v1.2.3 archive URL must not be present');
assert.ok(!content.includes('/ropweaver-v1.2.4'), 'Obsolete v1.2.4 archive URL must not be present');
console.log('  [OK] No obsolete v1.2.3 or v1.2.4 archive download URLs present.');

// 4. Verify macOS testing limitation wording
assert.ok(content.includes('native macOS runtime testing has not been performed on live Apple hardware'), 'macOS testing limitation must be accurately stated');
console.log('  [OK] macOS testing limitation accurately stated without claims of live hardware testing.');

console.log('\nAll DownloadPage.jsx verification checks passed successfully.');
