#!/usr/bin/env bash
# Eva CLI installer
# Usage:
#   curl -fsSL https://<your-domain>/install.sh | sh
set -euo pipefail

# ---- CONFIGURE THESE ----
PACKAGE="eva-cli"   # <-- the name you actually publish to PyPI (must be available; "eva" is taken)
BIN="eva"
# --------------------------

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
info() { printf '\033[34m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m==>\033[0m %s\n' "$1"; }

bold "Installing Eva..."

install_with_uv() {
    info "Installing with uv..."
    uv tool install "$PACKAGE" --force
}

install_with_pipx() {
    info "Installing with pipx..."
    pipx install "$PACKAGE" --force
}

install_with_pip() {
    info "Installing with pip --user..."
    python3 -m pip install --user --upgrade "$PACKAGE"
}

if command -v uv >/dev/null 2>&1; then
    install_with_uv
elif command -v pipx >/dev/null 2>&1; then
    install_with_pipx
else
    info "No uv or pipx found. Installing uv (fast, isolated, doesn't touch system Python)..."
    if curl -LsSf https://astral.sh/uv/install.sh | sh; then
        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    fi

    if command -v uv >/dev/null 2>&1; then
        install_with_uv
    else
        warn "Could not set up uv — falling back to pip --user."
        install_with_pip
    fi
fi

echo
if command -v "$BIN" >/dev/null 2>&1; then
    bold "Eva installed."
    echo "Run '$BIN --help' to get started."
else
    warn "Installed, but '$BIN' isn't on your PATH yet."
    echo "Open a new terminal, or add this to your shell profile:"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
fi
