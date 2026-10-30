#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <errno.h>

#define VERSION "v1.2.3"
#define APP_DIR_NAME ".local/share/ropweaver/app-v1.2.3"

static int file_exists(const char* path) {
    return (access(path, X_OK) == 0);
}

static void ensure_dir(const char* path) {
    char temp[PATH_MAX];
    strncpy(temp, path, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    for (char* p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(temp, 0755);
            *p = '/';
        }
    }
    mkdir(temp, 0755);
}

int main(int argc, char* argv[]) {
    char exe_dir[PATH_MAX] = {0};
    char target_binary[PATH_MAX] = {0};

    // 1. Check if ropweaver is adjacent to this launcher
    ssize_t len = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);
    if (len > 0) {
        exe_dir[len] = '\0';
        char* last_slash = strrchr(exe_dir, '/');
        if (last_slash) *last_slash = '\0';

        snprintf(target_binary, sizeof(target_binary), "%s/ropweaver", exe_dir);
        if (!file_exists(target_binary)) {
            snprintf(target_binary, sizeof(target_binary), "%s/bin/ropweaver", exe_dir);
        }
    }

    // 2. If not adjacent, check user appdata directory
    if (!file_exists(target_binary)) {
        const char* home = getenv("HOME");
        if (home) {
            snprintf(target_binary, sizeof(target_binary), "%s/%s/ropweaver", home, APP_DIR_NAME);
        }
    }

    // 3. Fallback to system PATH
    if (!file_exists(target_binary)) {
        if (system("which ropweaver >/dev/null 2>&1") == 0) {
            strncpy(target_binary, "ropweaver", sizeof(target_binary) - 1);
        }
    }

    // If still not found, check build-linux or build directory
    if (!file_exists(target_binary) && strcmp(target_binary, "ropweaver") != 0) {
        if (file_exists("./build-linux/ropweaver")) {
            strncpy(target_binary, "./build-linux/ropweaver", sizeof(target_binary) - 1);
        } else if (file_exists("./build/ropweaver")) {
            strncpy(target_binary, "./build/ropweaver", sizeof(target_binary) - 1);
        }
    }

    if (!file_exists(target_binary) && strcmp(target_binary, "ropweaver") != 0) {
        fprintf(stderr, "==«✪»== ROPWeaver Linux Launcher %s ==«✪»==\n", VERSION);
        fprintf(stderr, "[!] Error: ropweaver binary not found in adjacent path, ~/.local/share, or PATH.\n");
        fprintf(stderr, "[i] Please ensure ROPWeaver is installed or build with: cd build-linux && ./build.sh\n");
        return 1;
    }

    // 4. Ensure LD_LIBRARY_PATH includes local lib directories if present
    const char* current_ld = getenv("LD_LIBRARY_PATH");
    char new_ld[PATH_MAX * 2] = {0};
    if (len > 0) {
        if (current_ld && strlen(current_ld) > 0) {
            snprintf(new_ld, sizeof(new_ld), "%s/lib:%s", exe_dir, current_ld);
        } else {
            snprintf(new_ld, sizeof(new_ld), "%s/lib:/usr/local/lib:/usr/lib", exe_dir);
        }
        setenv("LD_LIBRARY_PATH", new_ld, 1);
    }

    // 5. Execute ropweaver with all forwarded arguments
    argv[0] = target_binary;
    execvp(target_binary, argv);

    // If execvp fails
    fprintf(stderr, "[!] Fatal: Failed to execute %s: %s\n", target_binary, strerror(errno));
    return 1;
}
