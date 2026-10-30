# ROPWeaver Release Packager

This directory contains automated packaging utilities to build, bundle, and generate distributions for Windows, Linux, and macOS:

- `package_release.bat`: Windows release generator (compiles `build-win`, packages `zip`, builds `ropweaver-windows-x64.exe`, packages `tar.gz` for Linux and macOS, computes SHA-256).
- `package_release.sh`: POSIX release generator for Linux and macOS.

## Usage

```cmd
:: On Windows:
tools\packager\package_release.bat
```

```bash
# On Linux / macOS:
chmod +x tools/packager/package_release.sh
./tools/packager/package_release.sh
```

All distribution artifacts are placed directly into `web-react/public/` for download.
