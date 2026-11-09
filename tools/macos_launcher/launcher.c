#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <errno.h>

#define VERSION "v1.2.4"

static int file_exists(const char* path) {
    return (access(path, X_OK) == 0);
}

int main(int argc, char* argv[]) {
    char exe_dir[PATH_MAX] = {0};
    char target_binary[PATH_MAX] = {0};

    // 1. Get current executable location on macOS
    uint32_t size = sizeof(exe_dir);
    if (_NSGetExecutablePath(exe_dir, &size) == 0) {
        char* last_slash = strrchr(exe_dir, '/');
        if (last_slash) *last_slash = '\0';

        snprintf(target_binary, sizeof(target_binary), "%s/ropweaver", exe_dir);
        if (!file_exists(target_binary)) {
            snprintf(target_binary, sizeof(target_binary), "%s/bin/ropweaver", exe_dir);
        }
    }

    // 2. Check Homebrew or user application directories
    if (!file_exists(target_binary)) {
        const char* home = getenv("HOME");
        if (home) {
            snprintf(target_binary, sizeof(target_binary), "%s/.local/share/ropweaver/ropweaver", home);
        }
    }

    // 3. Fallback to build-mac directory
    if (!file_exists(target_binary)) {
        if (file_exists("./build-mac/ropweaver")) {
            strncpy(target_binary, "./build-mac/ropweaver", sizeof(target_binary) - 1);
        } else if (file_exists("./build/ropweaver")) {
            strncpy(target_binary, "./build/ropweaver", sizeof(target_binary) - 1);
        }
    }

    if (!file_exists(target_binary)) {
        if (system("which ropweaver >/dev/null 2>&1") == 0) {
            strncpy(target_binary, "ropweaver", sizeof(target_binary) - 1);
        }
    }

    if (!file_exists(target_binary) && strcmp(target_binary, "ropweaver") != 0) {
        fprintf(stderr, "==«✪»== ROPWeaver macOS Launcher %s ==«✪»==\n", VERSION);
        fprintf(stderr, "[!] Error: ropweaver binary not found in application bundle or PATH.\n");
        fprintf(stderr, "[i] To build on macOS, run: cd build-mac && ./build.sh\n");
        return 1;
    }

    // 4. Configure DYLD_LIBRARY_PATH for Apple Silicon & Intel Homebrew
    const char* current_dyld = getenv("DYLD_LIBRARY_PATH");
    char new_dyld[PATH_MAX * 2] = {0};
    const char* brew_lib = access("/opt/homebrew/lib", F_OK) == 0 ? "/opt/homebrew/lib" : "/usr/local/lib";

    if (current_dyld && strlen(current_dyld) > 0) {
        snprintf(new_dyld, sizeof(new_dyld), "%s/lib:%s:%s", exe_dir, brew_lib, current_dyld);
    } else {
        snprintf(new_dyld, sizeof(new_dyld), "%s/lib:%s", exe_dir, brew_lib);
    }
    setenv("DYLD_LIBRARY_PATH", new_dyld, 1);

    // 5. Execute ropweaver
    argv[0] = target_binary;
    execvp(target_binary, argv);

    fprintf(stderr, "[!] Fatal: Failed to execute %s: %s\n", target_binary, strerror(errno));
    return 1;
}
