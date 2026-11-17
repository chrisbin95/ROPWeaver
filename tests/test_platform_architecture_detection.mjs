/**
 * Focused Test Suite for Architecture-Aware Downloads and Platform Detection
 * ROPWeaver v1.6.3 — Task 4.17 Continuation & Final Architecture Detection Correction
 */

import assert from 'node:assert';
import {
  detectPlatformAndArch,
  getRecommendedDownload,
  OFFICIAL_ASSETS,
  RELEASE_PAGE_URL,
  DOWNLOAD_BASE_URL,
  SOURCE_CODE_ZIP_URL,
  SOURCE_CODE_TAR_URL,
  GIT_REPO_URL
} from '../web-react/src/utils/platformHelper.js';

console.log('Running Architecture-Aware Downloads & Platform Detection Tests...\n');

let passCount = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(err);
    process.exit(1);
  }
}

// 1. Android ARM64 Detection & Mobile Safety
test('Android ARM64: Detects mobile environment and prevents desktop recommendations', () => {
  const mockNav = {
    userAgentData: { platform: 'Android', mobile: true },
    platform: 'Linux armv8l',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  assert.strictEqual(detected.platform, 'android');
  assert.strictEqual(detected.arch, 'arm64');
  assert.strictEqual(detected.isMobile, true);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'MOBILE_DEVICE');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.strictEqual(rec.recommendedOS, 'source');
  assert.strictEqual(rec.primaryAsset, null, 'Must NOT recommend Windows x64 executable to mobile visitor');
  assert.strictEqual(rec.secondaryAsset, null, 'Must NOT recommend Windows x64 zip to mobile visitor');
  assert.ok(rec.message.includes('desktop and server operating systems'));
});

// 2. Safari on Apple Silicon when architecture is not exposed
test('Safari on Apple Silicon (Unexposed Architecture): Returns unknown architecture without assuming arm64', () => {
  const mockNav = {
    userAgentData: null,
    platform: 'MacIntel',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
  };
  const detected = detectPlatformAndArch(mockNav, null);
  assert.strictEqual(detected.platform, 'macos');
  assert.strictEqual(detected.arch, 'unknown', 'Must NOT assume Apple Silicon or Intel when unexposed in Safari');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'MACOS_UNKNOWN_ARCH');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.strictEqual(rec.recommendedOS, 'macos');
  assert.strictEqual(rec.recommendedArch, null, 'Must NOT automatically recommend either macOS binary when arch is unknown');
  assert.strictEqual(rec.primaryAsset, null);
  assert.strictEqual(rec.secondaryAsset, null);
  assert.ok(rec.message.includes('Please select your Mac architecture below'));
});

// 3. Safari on Intel when architecture is not exposed
test('Safari on Intel (Unexposed Architecture): Returns unknown architecture without guessing Intel', () => {
  const mockNav = {
    userAgentData: null,
    platform: 'MacIntel',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15'
  };
  const detected = detectPlatformAndArch(mockNav, null);
  assert.strictEqual(detected.platform, 'macos');
  assert.strictEqual(detected.arch, 'unknown', 'Safari frozen MacIntel user agent must result in unknown architecture');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'MACOS_UNKNOWN_ARCH');
  assert.strictEqual(rec.recommendedArch, null);
  assert.strictEqual(rec.primaryAsset, null);
});

// 4. Explicitly detected macOS ARM64 (e.g. Chromium High-Entropy Hints or explicit UA)
test('Explicitly detected macOS ARM64: Recommends verified Apple Silicon archive', () => {
  const mockNav = {
    userAgentData: { platform: 'macOS', mobile: false },
    platform: 'MacIntel',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  assert.strictEqual(detected.platform, 'macos');
  assert.strictEqual(detected.arch, 'arm64');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'AVAILABLE');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, true);
  assert.strictEqual(rec.recommendedOS, 'macos');
  assert.strictEqual(rec.recommendedArch, 'arm64');
  assert.strictEqual(rec.primaryAsset.filename, 'ropweaver-v1.6.3-darwin-arm64.tar.gz');
  assert.strictEqual(rec.primaryAsset.sha256, '9e554516e393dc009daa0abfaebb6e79a322432d9c192800f65aedf4e7d596ae');
  assert.strictEqual(rec.secondaryAsset.filename, 'ropweaver-v1.6.3-darwin-x86_64.tar.gz');
});

// 5. Explicitly detected macOS x86_64
test('Explicitly detected macOS x86_64: Recommends verified Intel archive', () => {
  const mockNav = {
    userAgentData: { platform: 'macOS', mobile: false },
    platform: 'MacIntel',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'x86', bitness: '64' });
  assert.strictEqual(detected.platform, 'macos');
  assert.strictEqual(detected.arch, 'x86_64');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'AVAILABLE');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, true);
  assert.strictEqual(rec.recommendedOS, 'macos');
  assert.strictEqual(rec.recommendedArch, 'x86_64');
  assert.strictEqual(rec.primaryAsset.filename, 'ropweaver-v1.6.3-darwin-x86_64.tar.gz');
  assert.strictEqual(rec.primaryAsset.sha256, 'cbdee9879c5cb15274f8b6aeb768e193a8832ed7de0e14d02357282f9ae7e5a4');
  assert.strictEqual(rec.secondaryAsset.filename, 'ropweaver-v1.6.3-darwin-arm64.tar.gz');
});

// 6. Unknown Architecture Fallback Requiring Manual Selection
test('Unknown Architecture Fallback: Requires manual selection without automatically recommending binaries', () => {
  const mockNav = {
    userAgentData: null,
    platform: 'CustomUnix',
    userAgent: 'CustomBrowser/1.0'
  };
  const detected = detectPlatformAndArch(mockNav, null);
  assert.strictEqual(detected.platform, 'unknown');
  assert.strictEqual(detected.arch, 'unknown');

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'UNKNOWN_PLATFORM');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.strictEqual(rec.recommendedArch, null, 'Must not force a recommended architecture when unknown');
  assert.strictEqual(rec.primaryAsset, null);
  assert.strictEqual(rec.secondaryAsset, null);
  assert.ok(rec.message.includes('Please select your target environment manually'));
});

// 7. Desktop ARM64 Detection: Linux ARM64 / AArch64
test('Desktop ARM64 (Linux): Detects AArch64 and accurately reports unavailable pre-compiled binary', () => {
  const mockNav = {
    userAgentData: { platform: 'Linux', mobile: false },
    platform: 'Linux aarch64',
    userAgent: 'Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  assert.strictEqual(detected.platform, 'linux');
  assert.strictEqual(detected.arch, 'arm64');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'UNAVAILABLE_ARCH');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.strictEqual(rec.recommendedOS, 'linux');
  assert.strictEqual(rec.recommendedArch, 'arm64');
  assert.strictEqual(rec.primaryAsset, null);
  assert.ok(rec.message.includes('A pre-compiled Linux ARM64 package is unavailable'));
});

// 8. x86_64 Detection: Windows x64
test('x86_64 Detection (Windows): Recommends standalone executable and portable ZIP', () => {
  const mockNav = {
    userAgentData: { platform: 'Windows', mobile: false },
    platform: 'Win32',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'x86', bitness: '64' });
  assert.strictEqual(detected.platform, 'windows');
  assert.strictEqual(detected.arch, 'x86_64');
  assert.strictEqual(detected.isMobile, false);

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'AVAILABLE');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, true);
  assert.strictEqual(rec.recommendedOS, 'windows');
  assert.strictEqual(rec.recommendedArch, 'x86_64');
  assert.strictEqual(rec.primaryAsset.filename, 'ropweaver-windows-x64.exe');
  assert.strictEqual(rec.primaryAsset.sha256, '53baa53a2c1c3c22e6d49a21bbbf89ba1838a19fe465666a61aa978ee6ffd02f');
  assert.strictEqual(rec.secondaryAsset.filename, 'ropweaver-v1.6.3-win64.zip');
  assert.strictEqual(rec.secondaryAsset.sha256, 'd9acde6bfee97cd71630ad4d97f1e709a78131c98ddb2b397578ed9286941fd4');
});

// 9. x86_64 Detection: Linux x86_64
test('x86_64 Detection (Linux): Recommends Debian package and Linux tar.gz', () => {
  const mockNav = {
    userAgentData: { platform: 'Linux', mobile: false },
    platform: 'Linux x86_64',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0'
  };
  const detected = detectPlatformAndArch(mockNav);
  assert.strictEqual(detected.platform, 'linux');
  assert.strictEqual(detected.arch, 'x86_64');

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'AVAILABLE');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, true);
  assert.strictEqual(rec.primaryAsset.filename, 'ropweaver_1.6.3_amd64.deb');
  assert.strictEqual(rec.primaryAsset.sha256, 'c2f21c8367ac0ccdac45e9edc33d0d2ebca460323a8628d09d3a38d6613024e8');
  assert.strictEqual(rec.secondaryAsset.filename, 'ropweaver-v1.6.3-linux-x86_64.tar.gz');
  assert.strictEqual(rec.secondaryAsset.sha256, 'e2ec7e636c2051343c7ff14f1aef0ef0e735226c635b4a120c9aadc6764acb10');
});

// 10. RISC-V 64-bit Detection
test('RISC-V Detection: Accurately reports unavailable pre-compiled binary without inventing packages', () => {
  const mockNav = {
    userAgentData: { platform: 'Linux', mobile: false },
    platform: 'Linux riscv64',
    userAgent: 'Mozilla/5.0 (X11; Linux riscv64) AppleWebKit/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'riscv', bitness: '64' });
  assert.strictEqual(detected.platform, 'linux');
  assert.strictEqual(detected.arch, 'riscv64');

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'UNAVAILABLE_ARCH');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.strictEqual(rec.primaryAsset, null);
  assert.ok(rec.message.includes('RISC-V 64-bit pre-compiled package is unavailable for v1.6.3'));
});

// 11. Windows ARM64 Detection
test('Windows ARM64: Identifies Windows on ARM and reports native binary unavailability', () => {
  const mockNav = {
    userAgentData: { platform: 'Windows', mobile: false },
    platform: 'Win32',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36'
  };
  const detected = detectPlatformAndArch(mockNav, { architecture: 'arm', bitness: '64' });
  assert.strictEqual(detected.platform, 'windows');
  assert.strictEqual(detected.arch, 'arm64');

  const rec = getRecommendedDownload(detected);
  assert.strictEqual(rec.status, 'UNAVAILABLE_ARCH');
  assert.strictEqual(rec.isCompatibleBinaryAvailable, false);
  assert.ok(rec.message.includes('native Windows ARM64 build is not published'));
});

// 12. Source Code URLs and Git Repository Verification
test('Source Code Selection: Validates verified source archives and git repository', () => {
  assert.strictEqual(RELEASE_PAGE_URL, 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.3');
  assert.strictEqual(DOWNLOAD_BASE_URL, 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.3');
  assert.strictEqual(SOURCE_CODE_ZIP_URL, 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.3.zip');
  assert.strictEqual(SOURCE_CODE_TAR_URL, 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.3.tar.gz');
  assert.strictEqual(GIT_REPO_URL, 'https://github.com/chrisbin95/ROPWeaver.git');
});

// 13. Official Release Asset Catalog Completeness and Integrity
test('Preservation of All 6 Verified v1.6.3 Release Assets and Digests', () => {
  const assets = Object.values(OFFICIAL_ASSETS);
  assert.strictEqual(assets.length, 6, 'Must contain exactly 6 verified official release assets');

  const digests = {
    'ropweaver-windows-x64.exe': '53baa53a2c1c3c22e6d49a21bbbf89ba1838a19fe465666a61aa978ee6ffd02f',
    'ropweaver-v1.6.3-win64.zip': 'd9acde6bfee97cd71630ad4d97f1e709a78131c98ddb2b397578ed9286941fd4',
    'ropweaver_1.6.3_amd64.deb': 'c2f21c8367ac0ccdac45e9edc33d0d2ebca460323a8628d09d3a38d6613024e8',
    'ropweaver-v1.6.3-linux-x86_64.tar.gz': 'e2ec7e636c2051343c7ff14f1aef0ef0e735226c635b4a120c9aadc6764acb10',
    'ropweaver-v1.6.3-darwin-arm64.tar.gz': '9e554516e393dc009daa0abfaebb6e79a322432d9c192800f65aedf4e7d596ae',
    'ropweaver-v1.6.3-darwin-x86_64.tar.gz': 'cbdee9879c5cb15274f8b6aeb768e193a8832ed7de0e14d02357282f9ae7e5a4'
  };

  assets.forEach(asset => {
    assert.strictEqual(asset.sha256, digests[asset.filename], `Digest mismatch for ${asset.filename}`);
  });
});

console.log(`\nPlatform Architecture Detection Test Results: ${passCount} passed, 0 failed.`);
