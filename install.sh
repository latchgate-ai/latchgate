#!/usr/bin/env bash
# LatchGate installer — downloads and installs the latchgate binary.
#
# Usage (recommended — verify before running):
#
#   curl -fsSL https://raw.githubusercontent.com/latchgate-ai/latchgate/main/install.sh -o install.sh
#   sha256sum install.sh            # compare against install.sh.sha256 from the GitHub Release
#   bash install.sh
#
# Usage (convenience one-liner — not recommended for production):
#
#   curl -fsSL https://raw.githubusercontent.com/latchgate-ai/latchgate/main/install.sh | bash
#
# Options (via environment):
#   LATCHGATE_VERSION          Pin to a specific version (default: latest)
#   LATCHGATE_INSTALL          Install directory (default: /usr/local/bin or ~/.local/bin)
#   LATCHGATE_TARGET           Override target triple (e.g. aarch64-unknown-linux-gnu)
#   LATCHGATE_SKIP_COMPLETIONS Set to 1 to skip shell completion installation
#   LATCHGATE_SKIP_SIGNATURE_CHECK  Set to 1 to skip minisign signature verification (NOT recommended)
#
# This script:
#   1. Detects OS and architecture (or uses LATCHGATE_TARGET).
#   2. Downloads the release tarball from GitHub Releases.
#   3. Verifies the SHA-256 checksum.
#   4. Verifies the minisign signature (requires minisign unless LATCHGATE_SKIP_SIGNATURE_CHECK=1).
#   5. Verifies build provenance (if gh CLI is available).
#   6. Extracts binaries to the install directory.
#   7. Installs shell completions (unless LATCHGATE_SKIP_COMPLETIONS=1).
#   8. Verifies the installed binary runs.
#
# Does NOT start any services. Use `latchgate up` after installation.
#
# Requirements: curl (or wget), sha256sum (or shasum), tar, uname, jq
set -euo pipefail

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()  { printf "${BOLD}%s${RESET}\n" "$*"; }
ok()    { printf "  ${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "  ${DIM}! %s${RESET}\n" "$*"; }
fail()  { printf "  ${RED}✗ %s${RESET}\n" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# OS / arch detection
# ---------------------------------------------------------------------------

detect_target() {
    # Allow explicit override via environment.
    if [ -n "${LATCHGATE_TARGET:-}" ]; then
        case "$LATCHGATE_TARGET" in
            x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu \
            |x86_64-apple-darwin|aarch64-apple-darwin)
                echo "$LATCHGATE_TARGET"
                return ;;
            *) fail "Unknown LATCHGATE_TARGET: $LATCHGATE_TARGET" ;;
        esac
    fi

    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="unknown-linux-gnu"  ;;
        Darwin) os="apple-darwin"       ;;
        *)      fail "Unsupported operating system: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="x86_64"  ;;
        aarch64|arm64)  arch="aarch64" ;;
        *)              fail "Unsupported architecture: $arch" ;;
    esac

    echo "${arch}-${os}"
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

resolve_version() {
    local version="${LATCHGATE_VERSION:-latest}"

    if [ "$version" = "latest" ]; then
        command -v jq >/dev/null 2>&1 \
            || fail "jq is required to resolve the latest version. Install jq or set LATCHGATE_VERSION explicitly."

        version=$(curl -fsSL "https://api.github.com/repos/latchgate-ai/latchgate/releases/latest" \
            | jq -r '.tag_name // empty' \
            | sed 's/^v//')

        if [ -z "$version" ]; then
            fail "Could not determine latest version. Set LATCHGATE_VERSION explicitly."
        fi
    fi

    # Strip leading 'v' if present.
    version="${version#v}"
    echo "$version"
}

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

download() {
    local url="$1" dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        fail "Neither curl nor wget found. Install one and try again."
    fi
}

# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------

verify_checksum() {
    local file="$1" expected="$2"

    local actual
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file" | awk '{print $1}')"
    else
        fail "Neither sha256sum nor shasum found. Cannot verify download integrity."
    fi

    if [ "$actual" != "$expected" ]; then
        fail "Checksum mismatch!\n  Expected: $expected\n  Got:      $actual\n  The download may be corrupted or tampered with."
    fi
}

# ---------------------------------------------------------------------------
# Build provenance verification
# ---------------------------------------------------------------------------

verify_attestation() {
    local file="$1"

    if ! command -v gh >/dev/null 2>&1; then
        warn "gh (GitHub CLI) not found — skipping build provenance verification."
        warn "Install gh to verify artifacts were built by the official CI pipeline."
        return 0
    fi

    info "  Verifying build provenance..."
    if gh attestation verify "$file" --repo "latchgate-ai/latchgate" 2>&1; then
        ok "Build provenance verified"
    else
        fail "Build provenance verification failed. The artifact may have been tampered with."
    fi
}

# ---------------------------------------------------------------------------
# Minisign signature verification
# ---------------------------------------------------------------------------

# Embedded public key — must match keys/release.minisign.pub in the repo.
LATCHGATE_MINISIGN_PUBKEY="RWSH3qH2JE7pX4jsdD0ACXmT5laClRpAy5v6u2heBaXvTynRDzIUYvHx"

verify_signature() {
    local file="$1" sig_url="$2"

    if [ "${LATCHGATE_SKIP_SIGNATURE_CHECK:-0}" = "1" ]; then
        warn "LATCHGATE_SKIP_SIGNATURE_CHECK is set — skipping signature verification."
        warn "This is NOT recommended. Signatures prove the artifact was signed by the LatchGate release key."
        return 0
    fi

    if ! command -v minisign >/dev/null 2>&1; then
        echo ""
        fail "minisign is not installed. Signature verification is required.

  Install minisign:
    macOS:  brew install minisign
    Ubuntu: apt install minisign
    Arch:   pacman -S minisign
    Other:  https://jedisct1.github.io/minisign/

  Or (NOT recommended) bypass with:
    LATCHGATE_SKIP_SIGNATURE_CHECK=1"
    fi

    local sig_file="${file}.minisig"
    info "  Downloading signature..."
    download "$sig_url" "$sig_file" \
        || fail "Signature download failed."

    info "  Verifying minisign signature..."
    if minisign -V -P "$LATCHGATE_MINISIGN_PUBKEY" -m "$file" 2>&1; then
        ok "Minisign signature verified"
    else
        fail "Signature verification failed. The artifact may have been tampered with."
    fi
}

# ---------------------------------------------------------------------------
# Install directory
# ---------------------------------------------------------------------------

resolve_install_dir() {
    local dir="${LATCHGATE_INSTALL:-}"

    if [ -n "$dir" ]; then
        echo "$dir"
        return
    fi

    # Prefer /usr/local/bin if writable (or if we can sudo).
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    elif [ "$(id -u)" = "0" ]; then
        echo "/usr/local/bin"
    else
        # Fallback to user-local directory.
        local user_bin="${HOME}/.local/bin"
        mkdir -p "$user_bin"
        echo "$user_bin"
    fi
}

# ---------------------------------------------------------------------------
# Shell completion installation
# ---------------------------------------------------------------------------

install_completions() {
    local latchgate_bin="$1"

    if [ "${LATCHGATE_SKIP_COMPLETIONS:-0}" = "1" ]; then
        return 0
    fi

    # Verify the binary can generate completions.
    if ! "$latchgate_bin" completions bash >/dev/null 2>&1; then
        warn "Cannot generate completions — skipping."
        return 0
    fi

    local shell_name
    shell_name="$(basename "${SHELL:-}")"

    case "$shell_name" in
        bash)
            local bash_dir="${BASH_COMPLETION_USER_DIR:-${HOME}/.local/share/bash-completion/completions}"
            mkdir -p "$bash_dir" 2>/dev/null || { warn "Cannot create $bash_dir — skipping bash completions."; return 0; }
            "$latchgate_bin" completions bash > "${bash_dir}/latchgate" 2>/dev/null \
                && ok "Bash completions installed" \
                || warn "Failed to install bash completions."
            ;;
        zsh)
            local zsh_dir="${ZSH_COMPLETION_DIR:-${HOME}/.zfunc}"
            mkdir -p "$zsh_dir" 2>/dev/null || { warn "Cannot create $zsh_dir — skipping zsh completions."; return 0; }
            "$latchgate_bin" completions zsh > "${zsh_dir}/_latchgate" 2>/dev/null \
                && ok "Zsh completions installed (run 'compinit' to activate)" \
                || warn "Failed to install zsh completions."
            ;;
        fish)
            local fish_dir="${XDG_CONFIG_HOME:-${HOME}/.config}/fish/completions"
            mkdir -p "$fish_dir" 2>/dev/null || { warn "Cannot create $fish_dir — skipping fish completions."; return 0; }
            "$latchgate_bin" completions fish > "${fish_dir}/latchgate.fish" 2>/dev/null \
                && ok "Fish completions installed" \
                || warn "Failed to install fish completions."
            ;;
        *)
            warn "Shell '$shell_name' not recognized — generate completions manually:"
            warn "  latchgate completions <bash|zsh|fish>"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    info ""
    info "  LatchGate Installer"
    info ""

    local target version install_dir
    target="$(detect_target)"
    version="$(resolve_version)"
    install_dir="$(resolve_install_dir)"

    local base_url="https://github.com/latchgate-ai/latchgate/releases/download/v${version}"
    local tarball="latchgate-v${version}-${target}.tar.gz"
    local checksum_file="latchgate-v${version}-checksums.sha256"

    ok "OS/arch: ${target}"
    ok "Version: ${version}"
    ok "Install: ${install_dir}"
    echo ""

    # --- Download ---

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    info "  Downloading ${tarball}..."
    download "${base_url}/${tarball}" "${tmpdir}/${tarball}" \
        || fail "Download failed. Check https://github.com/latchgate-ai/latchgate/releases"

    info "  Downloading checksums..."
    download "${base_url}/${checksum_file}" "${tmpdir}/${checksum_file}" \
        || fail "Checksum file download failed."

    # --- Verify ---

    local expected_checksum
    expected_checksum="$(grep "${tarball}" "${tmpdir}/${checksum_file}" | awk '{print $1}')"

    if [ -z "$expected_checksum" ]; then
        fail "Tarball not found in checksum file. Release may be incomplete."
    fi

    verify_checksum "${tmpdir}/${tarball}" "$expected_checksum"
    ok "Checksum verified (SHA-256)"

    verify_signature "${tmpdir}/${tarball}" "${base_url}/${tarball}.minisig"

    verify_attestation "${tmpdir}/${tarball}"

    # --- Extract ---

    tar xzf "${tmpdir}/${tarball}" -C "${tmpdir}"

    # The tarball contains a top-level directory with binaries and share/.
    local extracted_dir="${tmpdir}/latchgate-v${version}-${target}"
    if [ ! -d "$extracted_dir" ]; then
        fail "Expected directory ${extracted_dir} not found in tarball. Release may be malformed."
    fi

    # Copy binaries.
    for bin in latchgate latchgate-mcp; do
        if [ -f "${extracted_dir}/${bin}" ]; then
            install -m 0755 "${extracted_dir}/${bin}" "${install_dir}/${bin}"
        fi
    done

    # Copy share/ resources (manifests, providers, policies) if present.
    if [ -d "${extracted_dir}/share" ]; then
        local share_dest
        share_dest="$(dirname "$install_dir")/share/latchgate"
        mkdir -p "$share_dest"
        cp -r "${extracted_dir}/share/latchgate/." "$share_dest/"
    fi

    ok "Installed to ${install_dir}"

    # --- Verify ---

    if ! command -v latchgate >/dev/null 2>&1; then
        # Binary installed but not on PATH.
        echo ""
        printf "  ${DIM}Add to your PATH:${RESET}\n"
        echo "    export PATH=\"${install_dir}:\$PATH\""
        echo ""
    fi

    if command -v latchgate >/dev/null 2>&1; then
        local installed_version
        installed_version="$(latchgate --version 2>/dev/null || echo 'unknown')"
        ok "${installed_version}"
    fi

    # --- Shell completions ---

    install_completions "${install_dir}/latchgate"

    # --- Done ---

    echo ""
    info "  Next step:"
    echo ""
    echo "    latchgate up"
    echo ""
}

main "$@"
