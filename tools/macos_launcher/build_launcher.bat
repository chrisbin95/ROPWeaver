@echo off
setlocal
set SCRIPT_DIR=%~dp0
echo [*] Packaging macOS Launcher bundle...
copy /y "%SCRIPT_DIR%launcher.sh" "%SCRIPT_DIR%..\..\build-mac\launcher.sh" >nul 2>nul
echo [+] Copied launcher.sh to build-mac/
endlocal
