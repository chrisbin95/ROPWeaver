@echo off
setlocal
set SCRIPT_DIR=%~dp0
echo [*] Packaging Linux Launcher bundle...
copy /y "%SCRIPT_DIR%launcher.sh" "%SCRIPT_DIR%..\..\build-linux\launcher.sh" >nul 2>nul
copy /y "%SCRIPT_DIR%launcher.sh" "%SCRIPT_DIR%..\..\build\launcher.sh" >nul 2>nul
echo [+] Copied launcher.sh to build-linux/ and build/
endlocal
