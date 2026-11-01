# BENCH — live benchmark protocol for the native tools

This protocol compares the Rust plugin's tools (`rx_data_find`, `rx_multi_find`)
against the Python plugin's `rex_data_find` on the **live** Binary Ninja MCP
server. Run it after every engine change; the field-for-field verification is
the cross-language contract test.

## Prerequisites

1. The plugin is installed flat at `~/.binaryninja/plugins/libbinja_plugin_native.so`.
   Rebuild/reinstall any time with:

   ```sh
   native/scripts/install.sh   # from the repository root
   ```

2. **Restart Binary Ninja.** Native plugins are dlopened at startup and register
   their MCP tools from `CorePluginInit`; they cannot load into the running
   process. Do not remove or modify `~/.binaryninja/plugins/binja_plugin` (the
   Python plugin); both load together and are benchmarked against each other.
3. Open the benchmark database in the GUI and leave it open. The MCP server runs
   at `http://127.0.0.1:24642/mcp`.

## Step 1 — verify the plugin loaded

```sh
python3 native/bench_mcp.py --check-only   # from the repository root
```

Expected output on success:

```
handshake ok; 90 tools registered; rx_* and rex_* both present
```

If it reports `rx_data_find, rx_multi_find missing`, the .so did not load:

- verify the install layout: the core scans `~/.binaryninja/plugins` for **flat
  `*.so` files only** — subdirectories are silently skipped (this bit us once;
  see the layout note in `native/README.md`);
- verify the export and linkage:

  ```sh
  nm -D --defined-only ~/.binaryninja/plugins/libbinja_plugin_native.so | grep CorePluginInit
  ldd ~/.binaryninja/plugins/libbinja_plugin_native.so | grep binaryninjacore
  ```

- the .so must resolve `libbinaryninjacore.so.1` (RUNPATH points at the BN
  install directory recorded by `~/.binaryninja/lastrun`).

## Step 2 — run the benchmark

```sh
python3 native/bench_mcp.py --binary <handle> --repeat 5   # from the repository root
```

Take the handle from `bn_binary_list` — it changes on every restart, and the
script's built-in default is only a last resort. What it measures, on the same
database, interleaved `--repeat` times:

1. **Single pattern, head-to-head.** `rex_data_find("48 8b 05")` vs
   `rx_data_find("48 8b 05")`, all mapped segments, `limit=50`, `offset=0`.
   Reports min/median/max ms and the min-based speedup.
2. **Multi-pattern headliner.** `rx_multi_find` with 8 code patterns in one
   call vs 8 sequential `rex_data_find` calls (summed), same pagination.
   Reports both timings and the speedup.
3. **Correctness verification (always runs).** Every `rx_*` payload is compared
   field-for-field against the corresponding `rex_data_find` payload
   (`total`, `truncated`, `matches`). Both tools must return **identical**
   results on the same database — the Rust tool mirrors the Python contract
   exactly, including overlapping-match counting and the early-stop
   `total`/`truncated` semantics. The final line prints
   `RESULT: all verifications passed` or `VERIFICATION MISMATCH`.

Useful variations:

```sh
# A longer pattern (the Python side pays per-chunk read inflation for length):
python3 native/bench_mcp.py --binary <handle> --pattern "48 8b ?? 05 ?? ?? ?? ?? 48 8b ?? 05"

# Restrict to a section (smaller scan; pass a section name that exists):
python3 native/bench_mcp.py --binary <handle> --section .text

# A bigger signature-set slice for the headliner:
python3 native/bench_mcp.py --binary <handle> --patterns "48 8b 05" "e8 ?? ?? ?? ??" \
    "0f 1f 44 00 00" "48 89 ?? 24 ??" "4c 8b ?? ??" "cc cc cc cc" "48 83 ?? ??" "48 8d ?? ??"
```

## Safety constraints (already encoded in the script)

- The server runs tool handlers **serially** and **cannot cancel** them. Do not
  run other MCP clients or commands against the same server while the benchmark
  is in progress.
- Every call is bounded client-side at 30 s (`CALL_TIMEOUT` in
  `bench_mcp.py`); a hung call raises instead of stalling forever.

## Measured results (2026-11-01, promotion benchmark)

Database: libclang-cpp.so.22.1 (62 MB bndb, ~111k functions, fresh full
reanalysis), all mapped segments (~17 MB), `--repeat 5`.

| Measurement | min | median | max |
| --- | --- | --- | --- |
| `rex_data_find` "48 8b 05" | 110.1 ms | 114.9 ms | 122.5 ms |
| `rx_data_find` "48 8b 05" | 14.6 ms | 15.5 ms | 17.0 ms |
| **single-pattern speedup (min)** | **7.5x** | | |
| 8× sequential `rex_data_find` | 919.1 ms | 938.6 ms | 969.9 ms |
| `rx_multi_find`, 8 patterns, one pass | 72.8 ms | 78.0 ms | 95.3 ms |
| **multi-pattern speedup (min)** | **12.6x** | | |

Verification: all 9 payload comparisons identical (`RESULT: all verifications
passed`), including the all-wildcard and `cc cc cc cc` patterns.

Honest margins: these are short patterns — the fast members of any set. The
advantage shrinks as patterns lengthen, since Python's regex engine also
prefilters on the literal prefix and both sides then approach the cost of
reading the bytes. The multi-pattern gap grows with pattern count: the Python
cost is per-pattern while the Rust cost is one automaton pass.
