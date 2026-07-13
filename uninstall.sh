#!/bin/sh
# Remove Sabba: the global command and the isolated environment. Your cloned repo, if any,
# is left in place.
set -e

SABBA_HOME="${SABBA_HOME:-$HOME/.sabba}"
BIN="${SABBA_BIN:-$HOME/.local/bin}"

rm -f "$BIN/sabba"
rm -rf "$SABBA_HOME"

echo "sabba removed ($SABBA_HOME and $BIN/sabba)."
