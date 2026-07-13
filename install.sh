#!/bin/sh
# Sabba installer. Creates an isolated environment and a global `sabba` command.
#
# From a checkout:   ./install.sh
# Remote (once the repo is public):
#   curl -fsSL https://raw.githubusercontent.com/8NobleTruths/sabba/main/install.sh | sh
set -e

SABBA_HOME="${SABBA_HOME:-$HOME/.sabba}"
REPO="${SABBA_REPO:-https://github.com/8NobleTruths/sabba.git}"
BIN="${SABBA_BIN:-$HOME/.local/bin}"
PY="${PYTHON:-python3}"

say() { printf "%s\n" "$*"; }

if [ -f "./pyproject.toml" ] && grep -q 'name = "sabba"' ./pyproject.toml 2>/dev/null; then
    SRC="$(pwd)"
    say "installing from $SRC"
else
    SRC="$SABBA_HOME/src"
    if [ -d "$SRC/.git" ]; then
        say "updating $SRC"
        git -C "$SRC" pull --ff-only
    else
        say "cloning $REPO"
        mkdir -p "$SABBA_HOME"
        git clone --depth 1 "$REPO" "$SRC"
    fi
fi

say "building environment"
"$PY" -m venv "$SABBA_HOME/venv"
"$SABBA_HOME/venv/bin/pip" install -q --upgrade pip
"$SABBA_HOME/venv/bin/pip" install -q -e "$SRC"

mkdir -p "$BIN"
ln -sf "$SABBA_HOME/venv/bin/sabba" "$BIN/sabba"

say ""
say "sabba installed."
case ":$PATH:" in
    *":$BIN:"*) say "run:  sabba" ;;
    *)
        say "add this line to your shell profile, then open a new shell:"
        say "  export PATH=\"$BIN:\$PATH\""
        say "or run it now:  export PATH=\"$BIN:\$PATH\" && sabba"
        ;;
esac
