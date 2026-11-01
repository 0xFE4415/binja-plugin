#!/usr/bin/env bash
# Build the native plugin (real-core link mode) and install it flat into the
# Binary Ninja user plugins directory.
#
# Layout matters: BNInitPlugins scans ~/.binaryninja/plugins for flat *.so
# files (native plugins) and for subdirectories containing __init__.py (Python
# plugins). A subdirectory holding lib<parsed_name>.so is only loaded via the
# Plugin Manager repository path (plugin_status.json), so the .so MUST be
# installed flat, like BN's own bundled lib*.so plugins. No plugin.json is
# needed: the native loader never opens one (verified against the core binary
# — the string "plugin.json" occurs nowhere in it — and no bundled native
# plugin ships one).
#
# After installing, restart Binary Ninja once; plugins (native and Python) are
# loaded at startup and register their MCP tools from CorePluginInit.
set -euo pipefail

NATIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGINS_DIR="${HOME}/.binaryninja/plugins"
INSTALLED_SO="${PLUGINS_DIR}/libbinja_plugin_native.so"

cd "${NATIVE_DIR}"
# Prefer the rustup toolchain when present (it reads rust-toolchain.toml for
# the pinned channel); a distro system cargo of a different build would poison
# target/ with incompatible artifacts (E0514).
if [ -d "${HOME}/.cargo/bin" ]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi
# Real-core mode (default features): links against the BN install discovered
# via BINARYNINJADIR or ~/.binaryninja/lastrun. Requires clang (bindgen).
cargo build --release

install -m 0755 target/release/libbinja_plugin_native.so "${INSTALLED_SO}"

echo "Installed:"
ls -l "${INSTALLED_SO}"
echo
echo "Restart Binary Ninja, then verify with:"
echo "  python3 ${NATIVE_DIR}/bench_mcp.py --check-only"
