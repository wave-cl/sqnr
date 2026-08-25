#!/bin/sh
set -e

REPO="wave-cl/sqnr"
INSTALL_DIR="${SQNR_INSTALL_DIR:-}"

info() { printf "  \033[1m%s\033[0m\n" "$1"; }
warn() { printf "  \033[33mwarning:\033[0m %s\n" "$1" >&2; }
err()  { printf "  \033[31merror:\033[0m %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="darwin" ;;
    *)      err "unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  TARGET="x86_64-linux-gnu" ;;
    aarch64|arm64) TARGET="aarch64-linux-gnu" ;;
    *)             err "unsupported architecture: $ARCH" ;;
esac

if [ "$OS_NAME" = "darwin" ]; then
    case "$ARCH" in
        x86_64|amd64)  TARGET="x86_64-apple-darwin" ;;
        aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
    esac
fi

# sqnr links libpcsclite for the YubiKey, which is awkward to cross-build for
# Linux/aarch64; releases cover Linux x86_64 and both macOS arches. On other
# Linux arches, build from source: cargo install --git https://github.com/wave-cl/sqnr sqnr
if [ "$OS_NAME" = "linux" ] && [ "$TARGET" = "aarch64-linux-gnu" ]; then
    err "no prebuilt sqnr for aarch64 Linux — build from source: cargo install --git https://github.com/$REPO sqnr"
fi

# Determine install directory
if [ -n "$INSTALL_DIR" ]; then
    BIN_DIR="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    err "curl or wget required"
fi

info "Fetching latest release..."
LATEST=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -z "$LATEST" ] && err "could not determine latest version"
info "Latest version: $LATEST"

URL="https://github.com/$REPO/releases/download/$LATEST/sqnr-${LATEST}-${TARGET}.tar.gz"
info "Downloading sqnr $LATEST for $TARGET..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch "$URL" > "$TMPDIR/sqnr.tar.gz" || err "download failed — no release for $TARGET?"

info "Installing to $BIN_DIR..."
mkdir -p "$BIN_DIR"
tar -xzf "$TMPDIR/sqnr.tar.gz" -C "$BIN_DIR"

if ! "$BIN_DIR/sqnr" --version >/dev/null 2>&1; then
    err "installation failed — sqnr not executable"
fi

VERSION=$("$BIN_DIR/sqnr" --version 2>&1 || echo "unknown")
info "Installed: $VERSION"

# The YubiKey path needs libpcsclite at runtime on Linux.
if [ "$OS_NAME" = "linux" ] && ! ldconfig -p 2>/dev/null | grep -q libpcsclite; then
    warn "the --yubikey path needs libpcsclite (e.g. apt install libpcsclite1)"
fi

# PATH setup for non-root installs
if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            SHELL_NAME=$(basename "$SHELL" 2>/dev/null || echo "unknown")
            case "$SHELL_NAME" in
                bash) RC="$HOME/.bashrc"; echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                zsh)  RC="$HOME/.zshrc";  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                fish) RC="$HOME/.config/fish/config.fish"; mkdir -p "$(dirname "$RC")"; echo 'fish_add_path ~/.local/bin' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                *)    info "Add $BIN_DIR to your PATH" ;;
            esac
            info "Restart your shell or run: export PATH=\"$BIN_DIR:\$PATH\""
            ;;
    esac
fi

printf "\n"
info "Getting started:"
printf "  1. sqnr keygen                # create ~/.sqnr/identity (encrypted)\n"
printf "     sqnr keygen --plaintext    # or unencrypted, for unattended signing\n"
printf "  2. sqnr pubkey                # print the key to authorize on a server\n"
printf "     sqnr --yubikey pubkey      # or your YubiKey's Authentication key\n\n"
info "sqnr signs; a service's own tool submits. For sqex, install and use sqex:"
printf "  curl -fsSL https://raw.githubusercontent.com/wave-cl/sqex/main/install.sh | sh\n"
printf "\n"
