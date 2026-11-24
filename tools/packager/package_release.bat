@echo off
setlocal EnableDelayedExpansion

echo ================================================================================
echo               ROPWeaver Multi-Platform Release Packager (v1.6.4)
echo ================================================================================

set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..\..
set PUBLIC_DIR=%ROOT_DIR%\web-react\public
set MINGW_BIN=C:\msys64\mingw64\bin
if exist "%MINGW_BIN%\gcc.exe" (
    set PATH=%MINGW_BIN%;%PATH%
)

echo [*] Root directory: %ROOT_DIR%
echo [*] Public release directory: %PUBLIC_DIR%

:: 1. Compile Windows native binary if needed
echo.
echo [*] Step 1: Compiling latest Windows binary (build-win)...
cd /d "%ROOT_DIR%\build-win"
mingw32-make -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo [!] FATAL: Windows compilation failed. Aborting packaging.
    exit /b 1
)

:: Verify compiled binary version reports v1.6.4
"%ROOT_DIR%\build-win\ropweaver.exe" --version | findstr /c:"v1.6.4" >nul
if errorlevel 1 (
    echo [!] FATAL: Compiled executable does not report v1.6.4. Aborting.
    exit /b 1
)
echo [*] Verified compiled executable reports v1.6.4.

:: Synchronize launchers across build directories
echo.
echo [*] Synchronizing platform launchers across build directories...
call "%ROOT_DIR%\tools\linux_launcher\build_launcher.bat"
call "%ROOT_DIR%\tools\macos_launcher\build_launcher.bat"

:: 2. Package Windows ZIP Distribution (v1.6.4)
echo.
echo [*] Step 2: Packaging ropweaver-v1.6.4-win64.zip...
set WIN_STAGE=%TEMP%\rop_win_stage_%RANDOM%
set WIN_PKG=%WIN_STAGE%\ropweaver-v1.6.4-win64
if exist "%WIN_STAGE%" rd /s /q "%WIN_STAGE%"
mkdir "%WIN_PKG%\config" 2>nul
mkdir "%WIN_PKG%\samples" 2>nul

copy /y "%ROOT_DIR%\build-win\ropweaver.exe" "%WIN_PKG%\" >nul
copy /y "%ROOT_DIR%\build-win\*.dll" "%WIN_PKG%\" >nul
copy /y "%ROOT_DIR%\build-win\curl-ca-bundle.crt" "%WIN_PKG%\" >nul 2>nul
copy /y "%ROOT_DIR%\LICENSE" "%WIN_PKG%\" >nul 2>nul
copy /y "%ROOT_DIR%\THIRD_PARTY_NOTICES.txt" "%WIN_PKG%\" >nul 2>nul
if exist "%ROOT_DIR%\config\firebase_config.json" (
    copy /y "%ROOT_DIR%\config\firebase_config.json" "%WIN_PKG%\" >nul
    copy /y "%ROOT_DIR%\config\firebase_config.json" "%WIN_PKG%\config\" >nul
)
if exist "%ROOT_DIR%\test_binaries\classic_bof.exe" (
    copy /y "%ROOT_DIR%\test_binaries\classic_bof.exe" "%WIN_PKG%\samples\" >nul
)

> "%WIN_PKG%\README.txt" echo ================================================================================
>> "%WIN_PKG%\README.txt" echo                     ROPWeaver v1.6.4 for Windows (x86_64)
>> "%WIN_PKG%\README.txt" echo             Academic Research Tool - Oxford Brookes University
>> "%WIN_PKG%\README.txt" echo                        Build Identifier: 1.6.4
>> "%WIN_PKG%\README.txt" echo ================================================================================
>> "%WIN_PKG%\README.txt" echo.
>> "%WIN_PKG%\README.txt" echo Quick Start:
>> "%WIN_PKG%\README.txt" echo   1. Open PowerShell or Command Prompt in this folder.
>> "%WIN_PKG%\README.txt" echo   2. Run ropweaver on a target binary:
>> "%WIN_PKG%\README.txt" echo      .\ropweaver.exe samples\classic_bof.exe --list-gadgets
>> "%WIN_PKG%\README.txt" echo      .\ropweaver.exe samples\classic_bof.exe --suggest-gadgets
>> "%WIN_PKG%\README.txt" echo      .\ropweaver.exe samples\classic_bof.exe --auto-chain
>> "%WIN_PKG%\README.txt" echo.
>> "%WIN_PKG%\README.txt" echo Documentation ^& Online Explorer:
>> "%WIN_PKG%\README.txt" echo   Visit: https://ropweaver.io/ or local web explorer interface.
>> "%WIN_PKG%\README.txt" echo.
>> "%WIN_PKG%\README.txt" echo License ^& Third-Party Notices:
>> "%WIN_PKG%\README.txt" echo   ROPWeaver is licensed under the MIT License (see LICENSE).
>> "%WIN_PKG%\README.txt" echo   This distribution bundles required third-party components (including
>> "%WIN_PKG%\README.txt" echo   Capstone, libcurl, OpenSSL, zlib, and MinGW/GCC runtimes).
>> "%WIN_PKG%\README.txt" echo   See THIRD_PARTY_NOTICES.txt for complete upstream notices and licenses.

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference = 'SilentlyContinue'; Compress-Archive -Path '%WIN_PKG%' -DestinationPath '%PUBLIC_DIR%\ropweaver-v1.6.4-win64.zip' -Force"
rd /s /q "%WIN_STAGE%" 2>nul
echo [+] Updated: %PUBLIC_DIR%\ropweaver-v1.6.4-win64.zip

:: 3. Rebuild Windows Standalone Launcher with embedded zip
echo.
echo [*] Step 3: Compiling Standalone Windows Launcher (ropweaver-windows-x64.exe)...
cd /d "%ROOT_DIR%\tools\windows_launcher"
call build_launcher.bat
if errorlevel 1 (
    echo [!] Failed to compile windows launcher.
    exit /b 1
)

if "%1"=="--win-only" (
    echo [*] --win-only specified. Windows packaging complete.
    exit /b 0
)

:: 4. Package Linux Distribution (tar.gz)
echo.
echo [*] Step 4: Packaging ropweaver-v1.6.4-linux-x86_64.tar.gz...
set LINUX_STAGE=%TEMP%\rop_linux_stage_%RANDOM%
set LINUX_PKG=%LINUX_STAGE%\ropweaver-v1.6.4-linux-x86_64
if exist "%LINUX_STAGE%" rd /s /q "%LINUX_STAGE%"
mkdir "%LINUX_PKG%\bin" 2>nul
mkdir "%LINUX_PKG%\samples" 2>nul

if exist "%ROOT_DIR%\build-linux\ropweaver" (
    copy /y "%ROOT_DIR%\build-linux\ropweaver" "%LINUX_PKG%\bin\" >nul
) else if exist "%ROOT_DIR%\build\ropweaver" (
    copy /y "%ROOT_DIR%\build\ropweaver" "%LINUX_PKG%\bin\" >nul
)
if exist "%ROOT_DIR%\build-linux\binsh_test" (
    copy /y "%ROOT_DIR%\build-linux\binsh_test" "%LINUX_PKG%\samples\" >nul
)
copy /y "%ROOT_DIR%\tools\linux_launcher\launcher.sh" "%LINUX_PKG%\install.sh" >nul
if exist "%ROOT_DIR%\config\firebase_config.json" (
    mkdir "%LINUX_PKG%\config" 2>nul
    copy /y "%ROOT_DIR%\config\firebase_config.json" "%LINUX_PKG%\config\" >nul
)
copy /y "%ROOT_DIR%\LICENSE" "%LINUX_PKG%\" >nul 2>nul
copy /y "%ROOT_DIR%\THIRD_PARTY_NOTICES.txt" "%LINUX_PKG%\" >nul 2>nul

(
echo ================================================================================
echo                     ROPWeaver v1.6.4 for Linux (x86_64)
echo             Academic Research Tool - Oxford Brookes University
echo                        Build Identifier: 1.6.4
echo ================================================================================
echo.
echo Requirements:
echo   GLIBC 2.31+, Capstone Disassembly Engine, libcurl
echo   Install on Ubuntu/Debian/Kali:
echo     sudo apt-get install libcapstone-dev libcurl4-openssl-dev
echo.
echo Usage:
echo   ./bin/ropweaver samples/binsh_test --list-gadgets
echo   ./bin/ropweaver samples/binsh_test --auto-chain
) > "%LINUX_PKG%\README.txt"

tar -czf "%PUBLIC_DIR%\ropweaver-v1.6.4-linux-x86_64.tar.gz" -C "%LINUX_STAGE%" ropweaver-v1.6.4-linux-x86_64
rd /s /q "%LINUX_STAGE%" 2>nul
echo [+] Updated: %PUBLIC_DIR%\ropweaver-v1.6.4-linux-x86_64.tar.gz

:: 5. Package Debian Package (ropweaver_1.6.4_amd64.deb)
echo.
echo [*] Step 5: Packaging ropweaver_1.6.4_amd64.deb...
set DEB_STAGE=%TEMP%\rop_deb_stage_%RANDOM%
if exist "%DEB_STAGE%" rd /s /q "%DEB_STAGE%"
mkdir "%DEB_STAGE%\usr\local\bin" 2>nul
mkdir "%DEB_STAGE%\usr\share\doc\ropweaver" 2>nul
cd /d "%DEB_STAGE%"
<nul set /p="2.0" > debian-binary
echo.>> debian-binary
(
    echo Package: ropweaver
    echo Version: 1.6.4
    echo Section: utils
    echo Priority: optional
    echo Architecture: amd64
    echo Maintainer: ROPWeaver Security Team ^<team@ropweaver.io^>
    echo Description: Advanced Binary ROP Gadget Finder ^& Automated Chain Synthesizer
    echo  High-performance ROP gadget discovery, register tracking, and automated
    echo  execve chain generation for binary exploitation analysis.
) > control
tar -czf control.tar.gz control

if exist "%ROOT_DIR%\build-linux\ropweaver" (
    copy /y "%ROOT_DIR%\build-linux\ropweaver" "%DEB_STAGE%\usr\local\bin\ropweaver" >nul
) else if exist "%ROOT_DIR%\build\ropweaver" (
    copy /y "%ROOT_DIR%\build\ropweaver" "%DEB_STAGE%\usr\local\bin\ropweaver" >nul
)
if exist "%ROOT_DIR%\debian\copyright" (
    copy /y "%ROOT_DIR%\debian\copyright" "%DEB_STAGE%\usr\share\doc\ropweaver\copyright" >nul
)

tar -czf data.tar.gz usr
ar rcs "%PUBLIC_DIR%\ropweaver_1.6.4_amd64.deb" debian-binary control.tar.gz data.tar.gz
cd /d "%ROOT_DIR%"
rd /s /q "%DEB_STAGE%" 2>nul
echo [+] Updated: %PUBLIC_DIR%\ropweaver_1.6.4_amd64.deb

:: 6. Package macOS Distributions (Apple Silicon & Intel)
echo.
echo [*] Step 6: Packaging macOS Distributions (darwin-arm64 and darwin-x86_64)...
set MAC_STAGE=%TEMP%\rop_mac_stage_%RANDOM%
set MAC_ARM=%MAC_STAGE%\ropweaver-v1.6.4-darwin-arm64
set MAC_X64=%MAC_STAGE%\ropweaver-v1.6.4-darwin-x86_64
if exist "%MAC_STAGE%" rd /s /q "%MAC_STAGE%"
mkdir "%MAC_ARM%\bin" 2>nul
mkdir "%MAC_ARM%\build-mac" 2>nul
mkdir "%MAC_X64%\bin" 2>nul
mkdir "%MAC_X64%\build-mac" 2>nul

copy /y "%ROOT_DIR%\tools\macos_launcher\launcher.sh" "%MAC_ARM%\bin\ropweaver" >nul
copy /y "%ROOT_DIR%\tools\macos_launcher\launcher.sh" "%MAC_ARM%\install.sh" >nul
copy /y "%ROOT_DIR%\build-mac\*" "%MAC_ARM%\build-mac\" >nul 2>nul
copy /y "%ROOT_DIR%\LICENSE" "%MAC_ARM%\" >nul 2>nul
copy /y "%ROOT_DIR%\THIRD_PARTY_NOTICES.txt" "%MAC_ARM%\" >nul 2>nul

copy /y "%ROOT_DIR%\tools\macos_launcher\launcher.sh" "%MAC_X64%\bin\ropweaver" >nul
copy /y "%ROOT_DIR%\tools\macos_launcher\launcher.sh" "%MAC_X64%\install.sh" >nul
copy /y "%ROOT_DIR%\build-mac\*" "%MAC_X64%\build-mac\" >nul 2>nul
copy /y "%ROOT_DIR%\LICENSE" "%MAC_X64%\" >nul 2>nul
copy /y "%ROOT_DIR%\THIRD_PARTY_NOTICES.txt" "%MAC_X64%\" >nul 2>nul

(
echo ================================================================================
echo                     ROPWeaver v1.6.4 for macOS (arm64 / Apple Silicon)
echo             Academic Research Tool - Oxford Brookes University
echo                        Build Identifier: 1.6.4
echo ================================================================================
echo.
echo Requirements:
echo   macOS 11.0+ (Sonoma, Ventura, Monterey, Big Sur)
echo   Homebrew packages: brew install capstone curl cmake
echo.
echo Quick Start:
echo   1. Automated installation and compilation on macOS:
echo      ./install.sh
echo      or:
echo      cd build-mac ^&^& ./build.sh
echo.
echo   2. Run ropweaver:
echo      ./bin/ropweaver ^<target_binary^> --list-gadgets
echo      ./bin/ropweaver ^<target_binary^> --suggest-gadgets
echo      ./bin/ropweaver ^<target_binary^> --auto-chain
echo.
echo Continuous Integration:
echo   Native Mach-O binaries for Apple Silicon and Intel are continuously built
echo   and released via GitHub Actions: .github/workflows/build-macos.yml
) > "%MAC_ARM%\README.txt"

(
echo ================================================================================
echo                     ROPWeaver v1.6.4 for macOS (x86_64 / Intel)
echo             Academic Research Tool - Oxford Brookes University
echo                        Build Identifier: 1.6.4
echo ================================================================================
echo.
echo Requirements:
echo   macOS 11.0+ (Sonoma, Ventura, Monterey, Big Sur)
echo   Homebrew packages: brew install capstone curl cmake
echo.
echo Quick Start:
echo   1. Automated installation and compilation on macOS:
echo      ./install.sh
echo      or:
echo      cd build-mac ^&^& ./build.sh
echo.
echo   2. Run ropweaver:
echo      ./bin/ropweaver ^<target_binary^> --list-gadgets
echo      ./bin/ropweaver ^<target_binary^> --suggest-gadgets
echo      ./bin/ropweaver ^<target_binary^> --auto-chain
echo.
echo Continuous Integration:
echo   Native Mach-O binaries for Apple Silicon and Intel are continuously built
echo   and released via GitHub Actions: .github/workflows/build-macos.yml
) > "%MAC_X64%\README.txt"

tar -czf "%PUBLIC_DIR%\ropweaver-v1.6.4-darwin-arm64.tar.gz" -C "%MAC_STAGE%" ropweaver-v1.6.4-darwin-arm64
tar -czf "%PUBLIC_DIR%\ropweaver-v1.6.4-darwin-x86_64.tar.gz" -C "%MAC_STAGE%" ropweaver-v1.6.4-darwin-x86_64

rd /s /q "%MAC_STAGE%" 2>nul
echo [+] Updated: %PUBLIC_DIR%\ropweaver-v1.6.4-darwin-arm64.tar.gz
echo [+] Updated: %PUBLIC_DIR%\ropweaver-v1.6.4-darwin-x86_64.tar.gz

:: 7. Compute SHA-256 Checksums
echo.
echo ================================================================================
echo                  RELEASE PACKAGES AND SHA-256 CHECKSUMS
echo ================================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem '%PUBLIC_DIR%\ropweaver*' | ForEach-Object { $h = Get-FileHash -Path $_.FullName -Algorithm SHA256; [PSCustomObject]@{ Filename = $_.Name; Size = ('{0:N2} MB' -f ($_.Length / 1MB)); SHA256 = $h.Hash.ToLower() } } | Format-Table -AutoSize"

echo.
echo [+] All release artifacts successfully built and synchronized!
endlocal
