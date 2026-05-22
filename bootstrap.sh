#!/usr/bin/env bash
# claude-guard bootstrap (POSIX).
#
# One-line install, idempotent. Detects git; clones (or pulls) into
# ~/.claude/guard, or downloads a tarball from GitHub if git is missing.
# Stops any running dashboard, then runs install.py --global --yes.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Gabriel-Dalton/claude-guard/main/bootstrap.sh | bash

set -euo pipefail

REPO_URL="https://github.com/Gabriel-Dalton/claude-guard"
TARBALL_URL="https://github.com/Gabriel-Dalton/claude-guard/archive/refs/heads/main.tar.gz"
INSTALL_DIR="$HOME/.claude/guard"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

need() {
    command -v "$1" >/dev/null 2>&1
}

if ! need python3 && ! need python; then
    red "python3 (or python) is required and was not found on PATH."
    exit 1
fi
PYTHON="$(command -v python3 || command -v python)"

mkdir -p "$(dirname "$INSTALL_DIR")"

# Stop a running dashboard so files in the install dir aren't held open.
if [ -f "$INSTALL_DIR/dashboard.py" ]; then
    "$PYTHON" "$INSTALL_DIR/dashboard.py" --stop >/dev/null 2>&1 || true
fi

if need git; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "updating $INSTALL_DIR via git pull..."
        git -C "$INSTALL_DIR" pull --ff-only
    elif [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]; then
        info "existing non-git install at $INSTALL_DIR; leaving files in place."
    else
        info "cloning $REPO_URL into $INSTALL_DIR..."
        git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    fi
else
    # No git: pull a tarball.
    if [ -d "$INSTALL_DIR/.git" ]; then
        red "git is missing but $INSTALL_DIR is a git checkout; install git or remove that directory first."
        exit 1
    fi
    info "git not found; downloading tarball..."
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    if need curl; then
        curl -fsSL "$TARBALL_URL" -o "$tmp/cg.tar.gz"
    elif need wget; then
        wget -q "$TARBALL_URL" -O "$tmp/cg.tar.gz"
    else
        red "neither curl nor wget is available; cannot download tarball."
        exit 1
    fi
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$tmp/cg.tar.gz" -C "$tmp"
    extracted="$(find "$tmp" -maxdepth 1 -type d -name 'claude-guard-*' | head -n 1)"
    if [ -z "$extracted" ]; then
        red "could not find extracted directory in tarball."
        exit 1
    fi
    cp -R "$extracted"/. "$INSTALL_DIR/"
fi

info "running installer..."
"$PYTHON" "$INSTALL_DIR/install.py" --global --yes

green "claude-guard installed. Open a new Claude Code session."
