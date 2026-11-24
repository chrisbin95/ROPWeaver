/**
 * Automated Verification Script for DownloadPage.jsx Release Assets
 */
import fs from 'node:fs';
import assert from 'node:assert';

console.log('Verifying DownloadPage.jsx Release Asset Integrity...\n');

const content = fs.readFileSync('web-react/src/pages/DownloadPage.jsx', 'utf-8');

// 1. Verify published release base URL & tag
const expectedBaseUrl = 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.4';
const expectedReleaseUrl = 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.4';

assert.ok(content.includes(expectedBaseUrl), 'Must contain exact v1.6.4 download base URL');
assert.ok(content.includes(expectedReleaseUrl), 'Must contain exact v1.6.4 release page URL');

// 2. Verify all six distribution options and SHA-256 digests
const expectedAssets = [
  {
    name: 'Windows Standalone Executable',
    file: 'ropweaver-windows-x64.exe',
    sha256: '7ca7aa1c57711c019b40c8957c93601f728bf4278507e621e4055c6b284150c3'
  },
  {
    name: 'Windows x86_64 ZIP',
    file: 'ropweaver-v1.6.4-win64.zip',
    sha256: 'feb756ce1679067c4f11faf91cd1146a40e59a45215deddc1411262737fc6a95'
  },
  {
    name: 'Linux Debian/Ubuntu AMD64 DEB',
    file: 'ropweaver_1.6.4_amd64.deb',
    sha256: 'c2b430e1861c678e7982b5aae9a4a5777d53a685a20f7eff9fbca10f6c90b50b'
  },
  {
    name: 'Linux x86_64 Standalone TAR.GZ',
    file: 'ropweaver-v1.6.4-linux-x86_64.tar.gz',
    sha256: '742c1a2e74de8562a1e7beaf74c3b697155ec464968d6bf4fc3fcd130f0da495'
  },
  {
    name: 'macOS Apple Silicon ARM64 TAR.GZ',
    file: 'ropweaver-v1.6.4-darwin-arm64.tar.gz',
    sha256: 'cabf01d3bd06cdf7f4a9c41144579a96fc5911dbc9962bafd19f1d8e73da066d'
  },
  {
    name: 'macOS Intel x86_64 TAR.GZ',
    file: 'ropweaver-v1.6.4-darwin-x86_64.tar.gz',
    sha256: 'f1714cb999d3892c0fa061f2e4ecc010dfd798fee82e5c01f639dca4a6c4ad03'
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
