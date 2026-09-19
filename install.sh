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

    ask "uv is required to continue with the isolated installation. Install uv from astral.sh?"
    read -r answer

    if [[ "$answer" =~ ^[Yy]$ ]]; then
        info "Downloading and installing uv from https://astral.sh..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    else
        warn "uv installation cancelled."

        ask "Fall back to installing Eva with pip --user?"
        read -r answer

        if [[ "$answer" =~ ^[Yy]$ ]]; then
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
