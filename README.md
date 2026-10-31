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
| `rex_constant_find` | Find functions whose MLIL references an immediate constant. |
| `rex_hlil_grep` | Regular expression search across rendered HLIL text. |
| `rex_call_paths` | Bounded breadth-first call-path search between two functions. |
| `rex_function_containing` | List the functions containing an address. |
| `rex_function_define` | Turn the bytes at an address into a function. |
| `rex_function_undefine` | Remove the user function covering an address (destructive). |
| `rex_string_read_at` | Read the detected string at an address. |
| `rex_memory_write` | Patch bytes in the binary view (destructive). |
| `rex_tag_set` | Attach a GUI-visible tag at an address, creating the tag type on demand. |
| `rex_tag_list` | List the tags set on the binary view. |
| `rex_kv_set` / `rex_kv_get` / `rex_kv_delete` | Persistent scratch key-value store. |
| `rex_eval_python` | Arbitrary `binaryninja` Python scripting (destructive escape hatch). |

Search tools return `total`, `truncated`, and paginated results via `limit`/`offset` so
agents never need to page through unbounded listings.

## Development

The project uses [nox](https://nox.thea.codes/) with `uv` as the default venv backend:

```bash
uvx nox -s check   # format, ruff, ty, and pytest with a 100% line-coverage gate
uvx nox -s test    # tests only
```

Tests run against a fake `binaryninja` package installed by `tests/conftest.py`, so no
Binary Ninja installation or license is needed for the test suite.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
