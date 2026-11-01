# binja_plugin_native — native Rust MCP tools

Rust half of the plugin: MCP tools whose cost is dominated by byte scanning,
where native code is measurably faster than Python. Registered alongside the
Python `rex_*` tools by the same bundled MCP server:

- `rx_data_find` — hex byte-pattern search, same contract as the Python
  `rex_data_find`, with the scan running in native Rust (SIMD `memchr`
  prefilter + wildcard verification). Measured **7.5x** faster on the
  promotion benchmark (`BENCH.md`).
- `rx_multi_find` — many hex patterns in **one pass** via an `aho-corasick`
  automaton, a capability the per-pattern Python tool structurally cannot
  offer. Measured **12.6x** against 8 sequential Python calls.

Everything else stays in Python deliberately: the other tools wrap single core
calls (analysis, HLIL rendering, constant search) whose cost is inside
Binary Ninja itself, so a rewrite would change nothing but the language.

## Build modes

- **Real-core mode** (default features): links against `libbinaryninjacore`
  from the BN install discovered via `BINARYNINJADIR` or `~/.binaryninja/lastrun`.
  This is what `scripts/install.sh` builds. Requires clang (the sys crate runs
  bindgen).
- **Stub-core mode** (`--no-default-features`): compiles a stub core via cmake
  (needs clang, cmake, ninja). Tests are pure logic and never call the core, so
  this mode is what the `native` nox session and CI run — no Binary Ninja
  install required.

## Integration lessons (each one cost a debugging session — do not re-learn them)

1. **Flat install layout.** The core's user-plugin loader keeps only regular
   `*.so` files directly in `~/.binaryninja/plugins`; subdirectories are
   silently skipped with no error. The subdirectory layout is reachable only
   through the Plugin Manager restore path (`plugin_status.json`), which a
   manually installed plugin does not use.
2. **`binary` is a reserved schema property.** `BNRegisterMcpTool` rejects the
   registration of any **BinaryView-scoped** tool whose input schema declares a
   property named `binary` (the server injects that argument itself and strips
   it before invoking the handler — verified live). Never declare it in tool
   argument structs; resolve the view with `require_binary_view()`.
3. **Pin the API revision.** Both `binaryninja` and `binaryninjacore-sys` must
   be git-pinned to the same `binaryninja-api` revision, ideally the commit the
   target core was built from (`api_REVISION.txt`). The sys crate is a direct
   dependency because the `DEP_BINARYNINJACORE_PATH` linker handshake only
   propagates to direct dependents of the `links = "binaryninjacore"` crate.
4. **Panic policy.** `panic = "unwind"` is deliberate: a panicking tool becomes
   an `internal_error` MCP result instead of killing the GUI (per
   `mcp-tools.html`; bundled plugins use abort, which is wrong for us).

No `plugin.json` is shipped: the native loader never opens one, and no bundled
native plugin has one. The file the PoC carried was inert documentation and was
dropped.

## Development

The native gates are opt-in locally and always run in CI's `native` job:

```sh
uvx nox -s native          # fmt, clippy (-D warnings), tests — stub-core mode
native/scripts/install.sh  # real-core release build + flat install
```

`native/BENCH.md` is the live benchmark protocol; run it after any engine
change. The differential tests (both scanners against a naive reference matcher
on 500 seeded random cases each) run in both build modes.
