#!/usr/bin/env python3
"""
ROPWeaver Universal Multi-Platform Launcher
Auto-detects host OS (Windows, Linux, macOS), resolves library dependencies,
and forwards all CLI arguments to the native ROPWeaver engine.
"""

import sys
import os
import platform
import subprocess

VERSION = "v1.2.4"

def find_binary(script_dir, root_dir):
    system = platform.system().lower()
    machine = platform.machine().lower()

    candidates = []

    if system == "windows":
        candidates.extend([
            os.path.join(script_dir, "ropweaver.exe"),
            os.path.join(root_dir, "build-win", "ropweaver.exe"),
            os.path.join(root_dir, "tools", "windows_launcher", "ropweaver-windows-x64.exe"),
            os.path.join(root_dir, "build-win", "launcher", "ropweaver-standalone.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "ROPWeaver", "app-v1.2.4", "ropweaver.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "ROPWeaver", "app-v1.2.3-r6", "ropweaver.exe"),
        ])
    elif system == "darwin":
        candidates.extend([
            os.path.join(script_dir, "ropweaver"),
            os.path.join(root_dir, "build-mac", "ropweaver"),
            os.path.join(root_dir, "build-mac", "bin", "ropweaver"),
            os.path.join(os.path.expanduser("~"), ".local", "share", "ropweaver", "ropweaver"),
        ])
    else: # Linux / BSD / POSIX
        candidates.extend([
            os.path.join(script_dir, "ropweaver"),
            os.path.join(root_dir, "build-linux", "ropweaver"),
            os.path.join(root_dir, "build", "ropweaver"),
            os.path.join(os.path.expanduser("~"), ".local", "share", "ropweaver", f"app-{VERSION}", "ropweaver"),
        ])

    for path in candidates:
        if os.path.isfile(path) and (os.access(path, os.X_OK) or system == "windows"):
            return path

    return "ropweaver"

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(script_dir, "..", ".."))

    target_bin = find_binary(script_dir, root_dir)
    env = os.environ.copy()
    system = platform.system().lower()

    if system == "windows":
        # Ensure build-win dll directory is in PATH
        win_dir = os.path.join(root_dir, "build-win")
        if os.path.isdir(win_dir):
            env["PATH"] = win_dir + os.pathsep + env.get("PATH", "")
    elif system == "darwin":
        # Add Homebrew lib directories
        brew_libs = ["/opt/homebrew/lib", "/usr/local/lib"]
        current_dyld = env.get("DYLD_LIBRARY_PATH", "")
        valid_brew = [b for b in brew_libs if os.path.isdir(b)]
        if valid_brew:
            env["DYLD_LIBRARY_PATH"] = os.pathsep.join(valid_brew) + (os.pathsep + current_dyld if current_dyld else "")
    else: # Linux
        linux_lib = os.path.join(root_dir, "build-linux", "lib")
        current_ld = env.get("LD_LIBRARY_PATH", "")
        if os.path.isdir(linux_lib):
            env["LD_LIBRARY_PATH"] = linux_lib + (os.pathsep + current_ld if current_ld else "")

    cmd = [target_bin] + sys.argv[1:]
    try:
        res = subprocess.run(cmd, env=env)
        sys.exit(res.returncode)
    except FileNotFoundError:
        print(f"==«✪»== ROPWeaver Universal Launcher {VERSION} ==«✪»==", file=sys.stderr)
        print(f"[!] Error: Native engine '{target_bin}' could not be located.", file=sys.stderr)
        print(f"[i] Host: {platform.system()} {platform.machine()}", file=sys.stderr)
        print(f"[i] To build native binary for your platform:", file=sys.stderr)
        print(f"    - Windows: cd build-win && build.bat", file=sys.stderr)
        print(f"    - Linux:   cd build-linux && ./build.sh", file=sys.stderr)
        print(f"    - macOS:   cd build-mac && ./build.sh", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
