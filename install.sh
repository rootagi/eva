#!/usr/bin/env bash
# Eva CLI installer

set -euo pipefail

# Note: "eva-cli[fast]" can be used instead once eva-fastwalk
# is published for your platform.
PACKAGE="eva-cli"
BIN="eva"

# --------------------------

bold() {
    printf '\033[1m%s\033[0m\n' "$1"
}

info() {
    printf '\033[34m==>\033[0m %s\n' "$1"
}

warn() {
    printf '\033[33m==>\033[0m %s\n' "$1"
}

ask() {
    printf '\033[36m==>\033[0m %s [y/N] ' "$1"
}

confirm() {
    local prompt="$1"
    local default_answer="${2:-n}"
    local answer=""

    ask "$prompt"
    
    # Try to read from /dev/tty (terminal), fall back to stdin if not available
    if read -r answer </dev/tty 2>/dev/null; then
        :
    else
        # Non-interactive; use default
        warn "stdin is not a TTY; defaulting to '$default_answer' in non-interactive mode."
        answer="$default_answer"
    fi

    if [[ -z "$answer" ]]; then
        answer="$default_answer"
    fi

    [[ "$answer" =~ ^[Yy]$ ]]
}

bold "Installing Eva..."

install_with_uv() {
    info "Installing '$PACKAGE' with uv..."
    info "uv may also install Eva's declared Python dependencies."
    uv tool install "$PACKAGE" --force
}

install_with_pipx() {
    info "Installing '$PACKAGE' with pipx..."
    info "pipx may also install Eva's declared Python dependencies."
    pipx install "$PACKAGE" --force
}

install_with_pip() {
    info "Installing '$PACKAGE' with pip --user..."
    info "pip may also install Eva's declared Python dependencies."
    python3 -m pip install --user --upgrade "$PACKAGE"
}

if command -v uv >/dev/null 2>&1; then
    info "Found uv."
    install_with_uv

elif command -v pipx >/dev/null 2>&1; then
    info "Found pipx."
    install_with_pipx

else
    warn "Neither uv nor pipx is installed."

    if confirm "uv is required to continue with the isolated installation. Install uv from astral.sh?"; then
        info "Downloading and installing uv from https://astral.sh..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    else
        warn "uv installation cancelled."

        if confirm "Fall back to installing Eva with pip --user?"; then
            install_with_pip
        else
            warn "Installation cancelled."
            exit 1
        fi
    fi

    if command -v uv >/dev/null 2>&1; then
        install_with_uv
    elif ! command -v "$BIN" >/dev/null 2>&1; then
        warn "uv could not be installed."
        exit 1
    fi
fi

echo

if command -v "$BIN" >/dev/null 2>&1; then
    bold "Eva installed successfully."
    echo "Run '$BIN --help' to get started."
else
    warn "Eva was installed, but '$BIN' isn't on your PATH yet."
    echo "Open a new terminal, or add this to your shell profile:"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
fi
