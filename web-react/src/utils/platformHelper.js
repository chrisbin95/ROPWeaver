/**
 * ROPWeaver v1.6.4 - Platform and Architecture Detection Helper
 *
 * Provides robust client-side OS, architecture, and environment detection
 * using Chromium High-Entropy Client Hints API (navigator.userAgentData)
 * and standards-compliant fallback heuristics (navigator.platform / userAgent).
 *
 * Distinguishes:
 * - Desktop architectures: x86_64, arm64, riscv64, unknown
 * - Operating systems: windows, linux, macos, android, ios, unknown
 * - Mobile vs Desktop visitor environments
 */

export const RELEASE_PAGE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/tag/v1.6.4';
export const DOWNLOAD_BASE_URL = 'https://github.com/chrisbin95/ROPWeaver/releases/download/v1.6.4';
export const SOURCE_CODE_ZIP_URL = 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.4.zip';
export const SOURCE_CODE_TAR_URL = 'https://github.com/chrisbin95/ROPWeaver/archive/refs/tags/v1.6.4.tar.gz';
export const GIT_REPO_URL = 'https://github.com/chrisbin95/ROPWeaver.git';

/**
 * Official verified v1.6.4 release assets and SHA-256 digests
 */
export const OFFICIAL_ASSETS = {
  windows_x64_exe: {
    name: 'Standalone Windows x64 Executable',
    filename: 'ropweaver-windows-x64.exe',
    url: `${DOWNLOAD_BASE_URL}/ropweaver-windows-x64.exe`,
    size: '9.5 MB',
    sha256: '7ca7aa1c57711c019b40c8957c93601f728bf4278507e621e4055c6b284150c3',
    platform: 'windows',
    arch: 'x86_64',
    isStaticAsset: false
  },
  windows_x64_zip: {
    name: 'Windows x86_64 ZIP Archive',
    filename: 'ropweaver-v1.6.4-win64.zip',
    url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.4-win64.zip`,
    size: '9.5 MB',
    sha256: 'feb756ce1679067c4f11faf91cd1146a40e59a45215deddc1411262737fc6a95',
    platform: 'windows',
    arch: 'x86_64',
    isStaticAsset: false
  },
  linux_amd64_deb: {
    name: 'Debian / Ubuntu Package (.deb)',
    filename: 'ropweaver_1.6.4_amd64.deb',
    url: `${DOWNLOAD_BASE_URL}/ropweaver_1.6.4_amd64.deb`,
    size: '385 KB',
    sha256: 'Pending release build verification',
    platform: 'linux',
    arch: 'x86_64',
    isStaticAsset: false
  },
  linux_x64_tar: {
    name: 'Standalone Linux x86_64 (.tar.gz)',
    filename: 'ropweaver-v1.6.4-linux-x86_64.tar.gz',
    url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.4-linux-x86_64.tar.gz`,
    size: '508 KB',
    sha256: 'Pending release build verification',
    platform: 'linux',
    arch: 'x86_64',
    isStaticAsset: false
  },
  macos_arm64_tar: {
    name: 'macOS Apple Silicon (arm64 .tar.gz)',
    filename: 'ropweaver-v1.6.4-darwin-arm64.tar.gz',
    url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.4-darwin-arm64.tar.gz`,
    size: '371 KB',
    sha256: 'Pending release build verification',
    platform: 'macos',
    arch: 'arm64',
    isStaticAsset: false
  },
  macos_x64_tar: {
    name: 'macOS Intel (x86_64 .tar.gz)',
    filename: 'ropweaver-v1.6.4-darwin-x86_64.tar.gz',
    url: `${DOWNLOAD_BASE_URL}/ropweaver-v1.6.4-darwin-x86_64.tar.gz`,
    size: '391 KB',
    sha256: 'Pending release build verification',
    platform: 'macos',
    arch: 'x86_64',
    isStaticAsset: false
  }
};

/**
 * Detect client platform, architecture, and mobility signals.
 * Accepts optional navigator and highEntropyHints for deterministic unit testing.
 */
export function detectPlatformAndArch(nav = (typeof navigator !== 'undefined' ? navigator : {}), highEntropyHints = null) {
  const uad = nav.userAgentData || null;
  const platformStr = String(nav.platform || '').toLowerCase();
  const ua = String(nav.userAgent || '').toLowerCase();

  // 1. Detect Mobile status
  let isMobile = false;
  if (uad && typeof uad.mobile === 'boolean') {
    isMobile = uad.mobile;
  }
  if (!isMobile) {
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) {
      isMobile = true;
    }
  }

  // 2. Detect Operating System / Platform
  let platform = 'unknown';
  const uadPlatform = String(uad?.platform || '').toLowerCase();

  if (uadPlatform.includes('android') || ua.includes('android') || platformStr.includes('android')) {
    platform = 'android';
    isMobile = true;
  } else if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod') || platformStr.includes('iphone') || platformStr.includes('ipad')) {
    platform = 'ios';
    isMobile = true;
  } else if (uadPlatform.includes('win') || platformStr.includes('win') || ua.includes('windows')) {
    platform = 'windows';
  } else if (uadPlatform.includes('mac') || platformStr.includes('mac') || ua.includes('mac os') || platformStr.includes('darwin')) {
    platform = 'macos';
  } else if (uadPlatform.includes('linux') || platformStr.includes('linux') || ua.includes('linux') || platformStr.includes('x11')) {
    platform = 'linux';
  }

  // 3. Detect Architecture
  let arch = 'unknown';

  // Check High Entropy Hints first if provided
  if (highEntropyHints && highEntropyHints.architecture) {
    const rawArch = String(highEntropyHints.architecture).toLowerCase();
    const bitness = String(highEntropyHints.bitness || '64');
    if (rawArch.includes('arm')) {
      arch = bitness === '64' ? 'arm64' : 'arm';
    } else if (rawArch.includes('x86') || rawArch.includes('intel') || rawArch.includes('amd')) {
      arch = bitness === '64' ? 'x86_64' : 'x86';
    } else if (rawArch.includes('riscv')) {
      arch = bitness === '64' ? 'riscv64' : 'riscv32';
    }
  }

  // Fallback to standard UA / platform string parsing if arch is still unknown
  if (arch === 'unknown') {
    if (ua.includes('riscv64') || platformStr.includes('riscv64') || ua.includes('riscv') || platformStr.includes('riscv')) {
      arch = 'riscv64';
    } else if (ua.includes('aarch64') || ua.includes('arm64') || platformStr.includes('aarch64') || platformStr.includes('arm64')) {
      arch = 'arm64';
    } else if (ua.includes('x86_64') || ua.includes('win64') || ua.includes('x64') || ua.includes('wow64') || ua.includes('amd64') || platformStr.includes('x86_64') || platformStr.includes('win64')) {
      arch = 'x86_64';
    } else if (platform === 'windows') {
      // Standard Windows desktop default (Win32/Win64)
      arch = 'x86_64';
    } else if (platform === 'android') {
      // Overwhelming majority of modern Android devices are ARM64
      arch = 'arm64';
    }
    // Note: On macOS, Safari and WebKit mask both Intel and Apple Silicon as 'MacIntel' / 'Intel Mac OS X'.
    // If high-entropy hints or explicit arm64/x86_64 tokens are not present, arch intentionally remains 'unknown'.
  }

  // Human-readable summary label
  let displayLabel = `${platform.toUpperCase()} (${arch === 'unknown' ? 'UNKNOWN ARCHITECTURE' : arch.toUpperCase()})`;
  if (isMobile) {
    displayLabel += ' [MOBILE]';
  }

  return {
    platform,
    arch,
    isMobile,
    displayLabel,
    hasHighEntropySupport: typeof nav.userAgentData?.getHighEntropyValues === 'function'
  };
}

/**
 * Determine recommendation rules and available packages based on detected platform and architecture.
 */
export function getRecommendedDownload(detected) {
  const { platform, arch, isMobile } = detected;

  // Rule 1: Mobile visitors (Android / iOS)
  // NEVER recommend Windows x64 or desktop binaries automatically to mobile visitors
  if (isMobile || platform === 'android' || platform === 'ios') {
    return {
      status: 'MOBILE_DEVICE',
      isCompatibleBinaryAvailable: false,
      recommendedOS: 'source',
      recommendedArch: null,
      title: 'Mobile Environment Detected',
      message: 'Pre-compiled ROPWeaver binaries are designed for desktop and server operating systems (Windows x64, Linux x86_64, macOS). To analyze binaries with ROPWeaver, download from a desktop system or inspect the source repository.',
      primaryAsset: null,
      secondaryAsset: null
    };
  }

  // Rule 2: macOS
  if (platform === 'macos') {
    if (arch === 'arm64') {
      return {
        status: 'AVAILABLE',
        isCompatibleBinaryAvailable: true,
        recommendedOS: 'macos',
        recommendedArch: 'arm64',
        title: 'macOS Apple Silicon (ARM64)',
        message: 'Verified v1.6.4 release archive for Apple Silicon (M1/M2/M3/M4) Macs.',
        primaryAsset: OFFICIAL_ASSETS.macos_arm64_tar,
        secondaryAsset: OFFICIAL_ASSETS.macos_x64_tar
      };
    }
    if (arch === 'x86_64') {
      return {
        status: 'AVAILABLE',
        isCompatibleBinaryAvailable: true,
        recommendedOS: 'macos',
        recommendedArch: 'x86_64',
        title: 'macOS Intel (x86_64)',
        message: 'Verified v1.6.4 release archive for Intel x86_64 Macs.',
        primaryAsset: OFFICIAL_ASSETS.macos_x64_tar,
        secondaryAsset: OFFICIAL_ASSETS.macos_arm64_tar
      };
    }
    // Safari / WebKit when architecture is not exposed
    return {
      status: 'MACOS_UNKNOWN_ARCH',
      isCompatibleBinaryAvailable: false,
      recommendedOS: 'macos',
      recommendedArch: null,
      title: 'macOS (Select Architecture)',
      message: 'Browser privacy controls mask whether your Mac is Apple Silicon (arm64) or Intel (x86_64). Please select your Mac architecture below to download the compatible package.',
      primaryAsset: null,
      secondaryAsset: null
    };
  }

  // Rule 3: Windows
  if (platform === 'windows') {
    if (arch === 'arm64') {
      return {
        status: 'UNAVAILABLE_ARCH',
        isCompatibleBinaryAvailable: false,
        recommendedOS: 'windows',
        recommendedArch: 'arm64',
        title: 'Windows ARM64',
        message: 'A native Windows ARM64 build is not published for v1.6.4. Windows 11 ARM64 can execute the x64 binary via emulation, or you can build ROPWeaver from source.',
        primaryAsset: null,
        secondaryAsset: null
      };
    }
    // Standard Windows x86_64
    return {
      status: 'AVAILABLE',
      isCompatibleBinaryAvailable: true,
      recommendedOS: 'windows',
      recommendedArch: 'x86_64',
      title: 'Windows x86_64',
      message: 'Verified v1.6.4 standalone launcher and portable ZIP bundle for Windows 10/11 x64.',
      primaryAsset: OFFICIAL_ASSETS.windows_x64_exe,
      secondaryAsset: OFFICIAL_ASSETS.windows_x64_zip
    };
  }

  // Rule 4: Linux
  if (platform === 'linux') {
    if (arch === 'riscv64') {
      return {
        status: 'UNAVAILABLE_ARCH',
        isCompatibleBinaryAvailable: false,
        recommendedOS: 'linux',
        recommendedArch: 'riscv64',
        title: 'Linux RISC-V 64-bit',
        message: 'A compatible RISC-V 64-bit pre-compiled package is unavailable for v1.6.4. You can compile ROPWeaver natively from source using CMake.',
        primaryAsset: null,
        secondaryAsset: null
      };
    }
    if (arch === 'arm64') {
      return {
        status: 'UNAVAILABLE_ARCH',
        isCompatibleBinaryAvailable: false,
        recommendedOS: 'linux',
        recommendedArch: 'arm64',
        title: 'Linux ARM64 / AArch64',
        message: 'A pre-compiled Linux ARM64 package is unavailable for v1.6.4. You can build from source using CMake or use the universal Python launcher.',
        primaryAsset: null,
        secondaryAsset: null
      };
    }
    // Standard Linux x86_64
    return {
      status: 'AVAILABLE',
      isCompatibleBinaryAvailable: true,
      recommendedOS: 'linux',
      recommendedArch: 'x86_64',
      title: 'Linux x86_64 (Debian, Ubuntu, Kali, Arch)',
      message: 'Verified v1.6.4 Debian system package and standalone Linux x86_64 archive.',
      primaryAsset: OFFICIAL_ASSETS.linux_amd64_deb,
      secondaryAsset: OFFICIAL_ASSETS.linux_x64_tar
    };
  }

  // Rule 5: Unknown platform / architecture fallback
  return {
    status: 'UNKNOWN_PLATFORM',
    isCompatibleBinaryAvailable: false,
    recommendedOS: 'windows',
    recommendedArch: null,
    title: 'Unknown Environment',
    message: 'Could not automatically identify your operating system or architecture. Please select your target environment manually from the options below or build from source.',
    primaryAsset: null,
    secondaryAsset: null
  };
}
