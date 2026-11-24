#!/usr/bin/env bash
# ==============================================================================
# ROPWeaver Linux Standalone Shell Launcher & Installer
# Wraps dependency verification, runtime paths, and forwards all arguments
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="v1.6.4"

# 1. Locate ropweaver binary
BIN=""
if [ -x "$DIR/bin/ropweaver" ]; then
    BIN="$DIR/bin/ropweaver"
elif [ -x "$DIR/ropweaver" ]; then
    BIN="$DIR/ropweaver"
elif [ -x "$HOME/.local/share/ropweaver/app-$VERSION/bin/ropweaver" ]; then
    BIN="$HOME/.local/share/ropweaver/app-$VERSION/bin/ropweaver"
elif [ -x "$HOME/.local/share/ropweaver/app-$VERSION/ropweaver" ]; then
    BIN="$HOME/.local/share/ropweaver/app-$VERSION/ropweaver"
elif [ -x "$DIR/../../build-linux/ropweaver" ]; then
    BIN="$DIR/../../build-linux/ropweaver"
elif [ -x "$DIR/../../build/ropweaver" ]; then
    BIN="$DIR/../../build/ropweaver"
elif command -v ropweaver >/dev/null 2>&1; then
    BIN="$(command -v ropweaver)"
fi

# Function: Install ROPWeaver into user or system directories
do_install() {
    echo "==«✪»== ROPWeaver Linux Installer $VERSION ==«✪»=="

    if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
        echo "[!] Error: ropweaver binary not found in $DIR/bin or adjacent directories." >&2
        exit 1
    fi

    # Determine installation prefix based on privileges
    if [ "$(id -u)" -eq 0 ]; then
        INSTALL_BIN_DIR="/usr/local/bin"
        INSTALL_SHARE_DIR="/usr/local/share/ropweaver/app-$VERSION"
    else
        INSTALL_BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
        INSTALL_SHARE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/ropweaver/app-$VERSION"
    fi

    # 1. Existing installation directory detection and symlink protection
    if [ -L "$INSTALL_SHARE_DIR" ]; then
        echo "[!] Security Conflict: Installation directory $INSTALL_SHARE_DIR is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$INSTALL_SHARE_DIR" 2>/dev/null || true)" >&2
        echo "[!] Refusing installation to prevent writing into or following unexpected symlink directory." >&2
        echo "    Please resolve or remove $INSTALL_SHARE_DIR manually." >&2
        exit 1
    elif [ -d "$INSTALL_SHARE_DIR" ]; then
        echo "[i] Existing ROPWeaver installation directory detected at: $INSTALL_SHARE_DIR"
    else
        echo "[*] Installing to: $INSTALL_SHARE_DIR"
    fi

    # Protect bin subdirectory against unexpected symlinks before creating or writing
    if [ -L "$INSTALL_SHARE_DIR/bin" ]; then
        echo "[!] Security Conflict: Binary directory $INSTALL_SHARE_DIR/bin is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$INSTALL_SHARE_DIR/bin" 2>/dev/null || true)" >&2
        echo "[!] Refusing installation to prevent writing into or following unexpected symlink directory." >&2
        echo "    Please resolve or remove $INSTALL_SHARE_DIR/bin manually." >&2
        exit 1
    fi

    # Protect config subdirectory against unexpected symlinks
    if [ -L "$INSTALL_SHARE_DIR/config" ]; then
        echo "[!] Security Conflict: Configuration directory $INSTALL_SHARE_DIR/config is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$INSTALL_SHARE_DIR/config" 2>/dev/null || true)" >&2
        echo "[!] Refusing installation to prevent writing into or following unexpected symlink directory." >&2
        echo "    Please resolve or remove $INSTALL_SHARE_DIR/config manually." >&2
        exit 1
    fi

    mkdir -p "$INSTALL_SHARE_DIR/bin" "$INSTALL_SHARE_DIR/config" "$INSTALL_BIN_DIR"

    # 2. Install executable (idempotent and symlink collision check)
    TARGET_BIN="$INSTALL_SHARE_DIR/bin/ropweaver"
    if [ -L "$TARGET_BIN" ]; then
        echo "[!] Security Warning: Destination binary path $TARGET_BIN is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$TARGET_BIN" 2>/dev/null || true)" >&2
        echo "[!] Refusing to install into or follow symlink target. Please resolve or remove $TARGET_BIN manually." >&2
        exit 1
    elif [ -f "$TARGET_BIN" ]; then
        if cmp -s "$BIN" "$TARGET_BIN"; then
            echo "[i] Executable at $TARGET_BIN is already up to date."
        else
            echo "[*] Updating existing executable at $TARGET_BIN..."
            cp -p "$BIN" "$TARGET_BIN"
            chmod 0755 "$TARGET_BIN"
        fi
    elif [ -e "$TARGET_BIN" ]; then
        echo "[!] Error: Destination $TARGET_BIN exists but is not a regular file." >&2
        exit 1
    else
        echo "[*] Installing ropweaver binary to $TARGET_BIN..."
        cp -p "$BIN" "$TARGET_BIN"
        chmod 0755 "$TARGET_BIN"
    fi

    # App root convenience link for launcher compatibility
    APP_ROOT_LINK="$INSTALL_SHARE_DIR/ropweaver"
    if [ -L "$APP_ROOT_LINK" ]; then
        CURRENT_APP_LINK="$(readlink "$APP_ROOT_LINK" 2>/dev/null || true)"
        if [ "$CURRENT_APP_LINK" = "bin/ropweaver" ] || [ "$CURRENT_APP_LINK" = "$TARGET_BIN" ] || [ "$CURRENT_APP_LINK" = "$INSTALL_SHARE_DIR/bin/ropweaver" ]; then
            : # Verified ROPWeaver compatibility link already in place
        else
            echo "[!] Security Conflict: Existing symlink at $APP_ROOT_LINK points to an unverified target: $CURRENT_APP_LINK" >&2
            echo "[!] Refusing installation to prevent overwriting or following unexpected symlink target." >&2
            echo "    Please resolve or remove $APP_ROOT_LINK manually." >&2
            exit 1
        fi
    elif [ -e "$APP_ROOT_LINK" ]; then
        echo "[!] Warning: An existing file or directory exists at $APP_ROOT_LINK (not a symlink)." >&2
        echo "[!] Preserving existing path and skipping app-root compatibility link." >&2
    else
        ln -sf "bin/ropweaver" "$APP_ROOT_LINK"
    fi

    # 3. Locate source Firebase configuration in release package
    CONFIG_SRC=""
    if [ -f "$DIR/config/firebase_config.json" ]; then
        CONFIG_SRC="$DIR/config/firebase_config.json"
    elif [ -f "$DIR/firebase_config.json" ]; then
        CONFIG_SRC="$DIR/firebase_config.json"
    elif [ -f "$DIR/../../config/firebase_config.json" ]; then
        CONFIG_SRC="$DIR/../../config/firebase_config.json"
    fi

    # 4. Install / Preserve Firebase configuration
    TARGET_CONFIG="$INSTALL_SHARE_DIR/config/firebase_config.json"
    TARGET_BIN_CONFIG="$INSTALL_SHARE_DIR/bin/firebase_config.json"
    TARGET_DIST_CONFIG="$INSTALL_SHARE_DIR/config/firebase_config.json.dist"

    # Pre-check symlinks on configuration file destinations
    if [ -L "$TARGET_CONFIG" ]; then
        echo "[!] Security Warning: Configuration path $TARGET_CONFIG is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$TARGET_CONFIG" 2>/dev/null || true)" >&2
        echo "[!] Refusing to install into or follow symlink target. Please resolve or remove $TARGET_CONFIG manually." >&2
        exit 1
    fi
    if [ -L "$TARGET_BIN_CONFIG" ]; then
        echo "[!] Security Warning: Binary configuration path $TARGET_BIN_CONFIG is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$TARGET_BIN_CONFIG" 2>/dev/null || true)" >&2
        echo "[!] Refusing to install into or follow symlink target. Please resolve or remove $TARGET_BIN_CONFIG manually." >&2
        exit 1
    fi
    if [ -L "$TARGET_DIST_CONFIG" ]; then
        echo "[!] Security Warning: Template configuration path $TARGET_DIST_CONFIG is an unexpected symlink." >&2
        echo "    Points to: $(readlink "$TARGET_DIST_CONFIG" 2>/dev/null || true)" >&2
        echo "[!] Refusing to overwrite or follow symlink template. Please resolve or remove $TARGET_DIST_CONFIG manually." >&2
        exit 1
    fi

    if [ -f "$TARGET_CONFIG" ]; then
        if [ -n "$CONFIG_SRC" ] && cmp -s "$CONFIG_SRC" "$TARGET_CONFIG"; then
            echo "[i] Firebase configuration at $TARGET_CONFIG is identical to packaged configuration."
        else
            echo "[i] Preserving existing customized Firebase configuration at $TARGET_CONFIG."
            if [ -n "$CONFIG_SRC" ]; then
                cp "$CONFIG_SRC" "$TARGET_DIST_CONFIG"
                chmod 0644 "$TARGET_DIST_CONFIG"
                echo "    (Packaged template saved as $TARGET_DIST_CONFIG for reference)"
            fi
        fi
    elif [ -n "$CONFIG_SRC" ]; then
        echo "[*] Installing Firebase configuration to $TARGET_CONFIG..."
        cp "$CONFIG_SRC" "$TARGET_CONFIG"
        chmod 0644 "$TARGET_CONFIG"
    else
        echo "[!] Notice: No source firebase_config.json found in package; binary will use embedded defaults."
    fi

    # Ensure adjacent bin/ config matches config/
    if [ -f "$TARGET_CONFIG" ] && [ ! -f "$TARGET_BIN_CONFIG" ]; then
        cp "$TARGET_CONFIG" "$TARGET_BIN_CONFIG"
        chmod 0644 "$TARGET_BIN_CONFIG"
    elif [ -f "$TARGET_CONFIG" ] && [ -f "$TARGET_BIN_CONFIG" ]; then
        if ! cmp -s "$TARGET_CONFIG" "$TARGET_BIN_CONFIG"; then
            cp "$TARGET_CONFIG" "$TARGET_BIN_CONFIG"
            chmod 0644 "$TARGET_BIN_CONFIG"
        fi
    fi

    # 5. Safe symlink creation in PATH directory
    TARGET_LINK="$INSTALL_BIN_DIR/ropweaver"
    LINK_CREATED=false

    if [ -L "$TARGET_LINK" ]; then
        CURRENT_LINK_TARGET="$(readlink "$TARGET_LINK" 2>/dev/null || true)"
        if [ "$CURRENT_LINK_TARGET" = "$TARGET_BIN" ] || [ "$CURRENT_LINK_TARGET" = "$INSTALL_SHARE_DIR/ropweaver" ]; then
            echo "[i] Symlink at $TARGET_LINK already points to this ROPWeaver installation."
            LINK_CREATED=true
        else
            echo "[!] Warning: Existing symlink at $TARGET_LINK points to an unverified or unrelated target: $CURRENT_LINK_TARGET" >&2
            echo "[!] Refusing to overwrite unverified symlink. You can manually link ROPWeaver using:" >&2
            echo "    ln -sf \"$TARGET_BIN\" \"$TARGET_LINK\"" >&2
        fi
    elif [ -e "$TARGET_LINK" ]; then
        if cmp -s "$TARGET_BIN" "$TARGET_LINK"; then
            echo "[i] Executable or symlink at $TARGET_LINK already matches this ROPWeaver installation."
            LINK_CREATED=true
        else
            echo "[!] Warning: A regular file or binary already exists at $TARGET_LINK (not a symlink)." >&2
            echo "[!] Refusing to overwrite existing file. To enable PATH execution, backup or remove:" >&2
            echo "    $TARGET_LINK" >&2
            echo "    Then link manually: ln -sf \"$TARGET_BIN\" \"$TARGET_LINK\"" >&2
        fi
    else
        echo "[*] Creating launcher symlink at $TARGET_LINK..."
        ln -sf "$TARGET_BIN" "$TARGET_LINK"
        LINK_CREATED=true
    fi

    # 6. Verification of installation and configuration accessibility
    echo "[*] Verifying installation..."
    if [ ! -x "$TARGET_BIN" ]; then
        echo "[!] Verification Error: Installed binary $TARGET_BIN is not executable." >&2
        exit 1
    fi

    CONFIG_STATUS="embedded"
    if [ -f "$TARGET_CONFIG" ]; then
        if grep -q "rop-weaver" "$TARGET_CONFIG" 2>/dev/null; then
            CONFIG_STATUS="active (project: rop-weaver)"
        else
            CONFIG_STATUS="active (custom)"
        fi
        echo "[+] Verified: Executable has valid configuration at $TARGET_CONFIG [$CONFIG_STATUS]."
    else
        echo "[+] Verified: Executable ready using embedded default configuration [project: rop-weaver]."
    fi

    echo "[+] ROPWeaver $VERSION installation complete!"
    if [ "$LINK_CREATED" = true ]; then
        echo "    Binary symlink: $TARGET_LINK"
    fi
    echo "    Application:    $TARGET_BIN"
    if [ -f "$TARGET_CONFIG" ]; then
        echo "    Configuration:  $TARGET_CONFIG"
    fi

    # PATH hint for non-root users if needed
    if [ "$(id -u)" -ne 0 ] && [ "$LINK_CREATED" = true ]; then
        case ":$PATH:" in
            *:"$INSTALL_BIN_DIR":*) ;;
            *)
                echo ""
                echo "[i] Notice: $INSTALL_BIN_DIR is not currently in your PATH."
                echo "    To run 'ropweaver' from any directory, add it to your shell configuration:"
                echo "    export PATH=\"$INSTALL_BIN_DIR:\$PATH\""
                ;;
        esac
    fi
    exit 0
}

# Determine invocation mode:
SCRIPT_NAME="$(basename "$0")"

# 1. Explicit installation requested
if [ "$1" = "--install" ] || [ "$1" = "install" ]; then
    do_install
fi

# 2. Invoked as install.sh with no execution arguments
if [ "$SCRIPT_NAME" = "install.sh" ] && [ "$#" -eq 0 ]; then
    do_install
fi

# 3. Help display
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    if [ "$SCRIPT_NAME" = "install.sh" ]; then
        echo "==«✪»== ROPWeaver Linux Launcher / Installer $VERSION ==«✪»=="
        echo "Usage:"
        echo "  ./install.sh                     Install ROPWeaver to ~/.local/share and ~/.local/bin"
        echo "  ./install.sh --install           Force installation"
        echo "  ./install.sh <binary> [options]  Run ROPWeaver directly with specified arguments"
        exit 0
    fi
fi

# 4. Standard execution mode: verify binary exists
if [ -z "$BIN" ]; then
    echo "==«✪»== ROPWeaver Linux Launcher $VERSION ==«✪»==" >&2
    echo "[!] Error: ropweaver binary not found." >&2
    echo "[i] To build from source, run: cd build-linux && ./build.sh" >&2
    exit 1
fi

# 5. Check essential dynamic libraries
if [ -d "$DIR/lib" ]; then
    export LD_LIBRARY_PATH="$DIR/lib:${LD_LIBRARY_PATH:-/usr/local/lib:/usr/lib}"
fi

# 6. Forward execution to ropweaver
exec "$BIN" "$@"
