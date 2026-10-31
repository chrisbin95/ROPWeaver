@echo off
setlocal
echo [*] Compiling ROPWeaver Windows Standalone Launcher...
set MINGW_BIN=C:\msys64\mingw64\bin
if exist "%MINGW_BIN%\windres.exe" (
    set PATH=%MINGW_BIN%;%PATH%
)

windres launcher.rc -O coff -o launcher.res
if errorlevel 1 (
    echo [!] windres compilation failed.
    exit /b 1
)

gcc -O2 -s -mconsole -municode launcher.c launcher.res -o ropweaver-windows-x64.exe
if errorlevel 1 (
    echo [!] gcc linking failed.
    exit /b 1
)

echo [+] Successfully generated standalone ropweaver-windows-x64.exe
copy /y ropweaver-windows-x64.exe ..\..\web-react\public\ropweaver-windows-x64.exe
copy /y ropweaver-windows-x64.exe ..\..\build-win\ropweaver-windows-x64.exe
copy /y ropweaver-windows-x64.exe ..\..\build-win\launcher\ropweaver-standalone.exe 2>nul
echo [+] Updated web-react\public\ropweaver-windows-x64.exe and build-win distributions
endlocal
