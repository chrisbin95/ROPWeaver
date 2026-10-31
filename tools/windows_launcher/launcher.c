#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <conio.h>

#define IDR_BUNDLE 101

static void ensure_directory(const wchar_t* path) {
    wchar_t temp[MAX_PATH * 2];
    wcsncpy(temp, path, MAX_PATH * 2 - 1);
    temp[MAX_PATH * 2 - 1] = L'\0';

    for (wchar_t* p = temp; *p; p++) {
        if (*p == L'\\' || *p == L'/') {
            wchar_t orig = *p;
            *p = L'\0';
            if (wcslen(temp) > 2 && temp[wcslen(temp) - 1] != L':') {
                CreateDirectoryW(temp, NULL);
            }
            *p = orig;
        }
    }
    CreateDirectoryW(temp, NULL);
}

static BOOL run_command_hidden(const wchar_t* cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    wchar_t cmd_copy[MAX_PATH * 4];
    wcsncpy(cmd_copy, cmd, (MAX_PATH * 4) - 1);
    cmd_copy[(MAX_PATH * 4) - 1] = L'\0';

    if (!CreateProcessW(NULL, cmd_copy, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 120000); // 2 minute timeout
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (exitCode == 0);
}

int wmain(int argc, wchar_t* argv[]) {
    // 1. Determine Local AppData Directory
    wchar_t localAppData[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            GetTempPathW(MAX_PATH, localAppData);
        }
    }

    wchar_t appDir[MAX_PATH * 2];
    swprintf(appDir, MAX_PATH * 2, L"%ls\\ROPWeaver\\app-v1.2.3-r6", localAppData);

    wchar_t stampFile[MAX_PATH * 2];
    swprintf(stampFile, MAX_PATH * 2, L"%ls\\.installed", appDir);

    wchar_t exePath[MAX_PATH * 2];
    swprintf(exePath, MAX_PATH * 2, L"%ls\\ropweaver.exe", appDir);

    // 2. Check if runtime environment is already unpacked
    BOOL needExtract = FALSE;
    if (GetFileAttributesW(stampFile) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
        needExtract = TRUE;
    }

    if (needExtract) {
        wprintf(L"[*] ROPWeaver v1.2.3: Initializing standalone environment...\n");

        ensure_directory(appDir);

        // Load embedded zip bundle from resource
        HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_BUNDLE), RT_RCDATA);
        if (!hRes) {
            fwprintf(stderr, L"[!] Fatal: Embedded bundle resource not found.\n");
            return 1;
        }

        HGLOBAL hMem = LoadResource(NULL, hRes);
        DWORD resSize = SizeofResource(NULL, hRes);
        const void* pData = LockResource(hMem);
        if (!pData || resSize == 0) {
            fwprintf(stderr, L"[!] Fatal: Embedded bundle resource is empty.\n");
            return 1;
        }

        wchar_t tempDir[MAX_PATH];
        GetTempPathW(MAX_PATH, tempDir);

        wchar_t tempZip[MAX_PATH * 2];
        swprintf(tempZip, MAX_PATH * 2, L"%lsropweaver_bundle_%lu.zip", tempDir, (unsigned long)GetCurrentProcessId());

        HANDLE hFile = CreateFileW(tempZip, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            fwprintf(stderr, L"[!] Fatal: Could not write temporary bundle.\n");
            return 1;
        }

        DWORD written = 0;
        WriteFile(hFile, pData, resSize, &written, NULL);
        CloseHandle(hFile);

        // Extract with tar.exe (built-in in Windows 10/11)
        wchar_t cmd[MAX_PATH * 4];
        swprintf(cmd, MAX_PATH * 4, L"tar.exe -xf \"%ls\" -C \"%ls\" --strip-components 1", tempZip, appDir);

        BOOL success = run_command_hidden(cmd);

        // Check if ropweaver.exe exists after tar extraction
        if (!success || GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
            // Fallback to PowerShell Expand-Archive
            swprintf(cmd, MAX_PATH * 4,
                L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
                L"\"$tmp = Join-Path $env:TEMP ('rop_unzip_' + [Guid]::NewGuid().ToString('N')); "
                L"Expand-Archive -LiteralPath '%ls' -DestinationPath $tmp -Force; "
                L"Copy-Item (Join-Path $tmp 'ropweaver-v1.2.3-win64\\*') '%ls' -Recurse -Force; "
                L"Remove-Item $tmp -Recurse -Force\"",
                tempZip, appDir);
            success = run_command_hidden(cmd);
        }

        // Clean up temp zip file
        DeleteFileW(tempZip);

        if (GetFileAttributesW(exePath) == INVALID_FILE_ATTRIBUTES) {
            fwprintf(stderr, L"[!] Fatal: Failed to extract runtime libraries to %ls\n", appDir);
            return 1;
        }

        // Write stamp file
        HANDLE hStamp = CreateFileW(stampFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStamp != INVALID_HANDLE_VALUE) {
            const char stampContent[] = "v1.2.3-r6-standalone\n";
            DWORD stampWritten = 0;
            WriteFile(hStamp, stampContent, (DWORD)strlen(stampContent), &stampWritten, NULL);
            CloseHandle(hStamp);
        }

        wprintf(L"[+] Standalone environment ready.\n\n");
        fflush(stdout);
    }

    // 3. Launch ropweaver.exe with arguments passed through
    const wchar_t* fullCmd = GetCommandLineW();
    const wchar_t* p = fullCmd;

    // Skip argv[0] (which may be quoted or unquoted)
    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') p++;
        if (*p == L'"') p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t') p++;
    }
    while (*p == L' ' || *p == L'\t') p++;

    // Construct command line for child process
    size_t fullLen = wcslen(exePath) + wcslen(p) + 16;
    wchar_t* childCmd = (wchar_t*)malloc(fullLen * sizeof(wchar_t));
    if (!childCmd) return 1;

    if (*p) {
        swprintf(childCmd, fullLen, L"\"%ls\" %ls", exePath, p);
    } else {
        swprintf(childCmd, fullLen, L"\"%ls\"", exePath);
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Inherit stdio handles and current working directory
    if (!CreateProcessW(exePath, childCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"[!] Fatal: Failed to start ropweaver.exe (Error %lu)\n", GetLastError());
        free(childCmd);
        return 1;
    }

    free(childCmd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD childExit = 0;
    GetExitCodeProcess(pi.hProcess, &childExit);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // If double-clicked in Explorer with no args, prompt user before closing console
    if (argc <= 1) {
        DWORD procList[2];
        if (GetConsoleProcessList(procList, 2) <= 1) {
            wprintf(L"\n[Press Enter to exit...]\n");
            _getwch();
        }
    }

    return (int)childExit;
}
