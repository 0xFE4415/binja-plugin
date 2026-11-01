# binja-plugin

Extra MCP tools for Binary Ninja's built-in MCP server. The stock server exposes its `bn_*`
tools; this plugin registers additional `rex_*` tools alongside them for the workflows an AI
agent drives most: search, code/data transitions, triage annotations, and scratch state.

## Requirements

- Binary Ninja (GUI or headless) with the built-in MCP server enabled (`ui.mcp.enabled`)
- Python 3.13+ (only for development and testing)

## Install

Clone the repository and symlink the package into Binary Ninja's plugin directory:

```bash
git clone git@github.com:0xFE4415/binja-plugin.git
ln -s "$(pwd)/binja-plugin/src/binja_plugin" ~/.binaryninja/plugins/binja_plugin
```

Restart Binary Ninja and start the MCP server with `Plugins > MCP > Start Server`. MCP
clients that already connected must reconnect to see the registered `rex_*` tools.

## Tools

| Tool | Notes |
| --- | --- |
| `rex_string_search` | Substring/regex search over strings, with section and type filters. |
| `rex_data_find` | Hex byte pattern search (`??` wildcards) over mapped segments. |
| `rex_constant_find` | Finds constant references via the core's linear-view constant search. |
| `rex_hlil_grep` | Regular expression search across rendered HLIL text, with a resumable cursor. |
| `rex_call_paths` | Bounded breadth-first call-path search between two functions. |
| `rex_function_containing` | List the functions containing an address. |
| `rex_function_define` | Turn the bytes at an address into a function. |
| `rex_function_undefine` | Remove the function covering an address (destructive). |
| `rex_string_read_at` | Read the detected string at an address. |
| `rex_memory_write` | Patch bytes in the binary view (destructive). |
| `rex_tag_set` | Attach a GUI-visible tag at an address, creating the tag type on demand. |
| `rex_tag_list` | List the tags set on the binary view. |
| `rex_kv_set` / `rex_kv_get` / `rex_kv_delete` | Persistent scratch key-value store. |
| `rex_eval_python` | Arbitrary `binaryninja` Python scripting (destructive escape hatch). |

Search tools return `total`, `truncated`, and paginated results via `limit`/`offset` so
agents never need to page through unbounded listings. Size parameters (`limit`, `offset`,
`max_depth`, `max_paths`, `max_functions`, `max_chars`) are range-checked, not silently
normalized: a value outside its documented range — including above the resource cap — is
rejected with the MCP layer's `invalid_params` argument error. Echoed strings (names, tag
data, key values, `rex_eval_python` output) are additionally capped in length, with a
`... [N chars truncated]` suffix and a companion `*_truncated` flag whenever a cap bites.

## Bounds on database-wide scans

On a six-figure-function database the two whole-database searches are bounded per
invocation:

- `rex_constant_find` runs the core's linear-view constant search (the engine behind
  Search > For Constant) instead of generating IL for every function. It matches values
  displayed as constant or pointer tokens in rendered instructions — the same reference a
  reader sees in the disassembly — and stops as soon as the requested `limit`/`offset`
  window is known to be complete. Only a value that never occurs in the view pays for a
  full sweep, which is a bounded, core-side pass.
- `rex_hlil_grep` renders HLIL for at most `max_functions` functions per invocation. The
  first render of a function's HLIL costs tens of milliseconds, so large databases are
  paged: each result carries `next_offset`, and callers pass it back as `offset` until
  `truncated` is false.

## Known limits

- `rex_string_search` and `rex_hlil_grep` compile model-supplied regular expressions with
  Python's `re`, which has no match timeout. A pattern prone to catastrophic backtracking
  (e.g. nested quantifiers like `(a+)+$`) can stall the tool invocation indefinitely; the
  MCP server processes invocations serially while it runs. Prefer substring mode
  (`regex=false`) when the input is not trusted, and keep regexes simple.

## Development

The project uses [nox](https://nox.thea.codes/) with `uv` as the default venv backend:

```bash
uvx nox -s check   # format, ruff, ty, and pytest with a 100% line-coverage gate
uvx nox -s test    # tests only
```

Markdown is linted only in CI (`markdownlint-cli2`, config in `.markdownlint.yaml`): the
default rules plus MD013 at 100 characters per line — headings and code blocks included.
Keep Markdown lines at or under 100 columns; the local `check` session will not catch it.

Tests run against a fake `binaryninja` package installed by `tests/conftest.py`, so no
Binary Ninja installation or license is needed for the test suite.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
