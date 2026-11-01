"""MCP tools extending Binary Ninja's built-in MCP server.

Every tool is prefixed ``rex_`` because the ``bn_`` prefix belongs to the built-in tools.
Handlers run on the MCP server thread, so none of them touch the UI thread directly.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import re
from collections import deque
from collections.abc import Callable
from itertools import islice
from pathlib import Path
from typing import Annotated, Any, Literal

import binaryninja
from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern

_READ_CHUNK = 4 * 1024 * 1024
_MAX_CHARS = 512
# Hard caps for list sizes and echoed strings: user-supplied size parameters are
# range-checked against these in the tool bodies — matching the schema-side
# Minimum/Maximum annotations — so out-of-range values are rejected even when handlers
# are invoked directly.
_MAX_LIMIT = 500
_MAX_HLIL_GREP_LIMIT = 200
_MAX_HLIL_GREP_FUNCTIONS = 5000
# rex_constant_find matches displayed constants, which are at most 64-bit values.
_MAX_CONSTANT_VALUE = 2**64 - 1
_MAX_CALL_PATH_DEPTH = 16
_MAX_CALL_PATHS = 50
_MAX_FUNCTION_ENTRIES = 50
_MAX_EVAL_STDOUT_CHARS = 65536
_MAX_EVAL_RESULT_CHARS = 16384
_MAX_KV_VALUE_CHARS = 65536
_MAX_KV_KEY_CHARS = 128
_MAX_TAG_DATA_CHARS = 65536
_MAX_TAG_TYPE_CHARS = 64
_MAX_STRING_READ_CHARS = 4096
# Raw pattern-string cap for rex_data_find: bounds the regex compile and the per-chunk
# read inflation (read_size grows with the pattern length) before any of that happens.
_MAX_PATTERN_CHARS = 8192
# rex_disasm_at window sizes: bounded so one call can never request an unbounded
# instruction render, whatever the containing function's size.
_MAX_DISASM_CONTEXT = 64
# rex_hlil_grep per-match context: bounded so the three-matches-per-function cap keeps
# the echoed lines per function a few dozen at most.
_MAX_HLIL_GREP_CONTEXT = 8
# rex_decompile_many caps: 16 address expressions bound one call's decompilation cost,
# and 400 lines bound the echoed text per function.
_MAX_DECOMPILE_BATCH = 16
_MAX_DECOMPILE_LINES = 400
# rex_find_functions_by_pattern example matches per function: triage wants a handful of
# hit addresses; rex_data_find already returns full match lists.
_MAX_FIND_FUNCTIONS_EXAMPLES = 5
# rex_export_* tools: sweeps write to one fixed directory and echo only a summary, so a
# large export can never flood the MCP response. The byte cap bounds each file; the
# window caps bound how much a single call selects before serialization.
_EXPORT_ROOT = Path.home() / ".binaryninja" / "exports"
_MAX_EXPORT_COMPONENT_BYTES = 255
_MAX_EXPORT_FILE_BYTES = 4 * 1024 * 1024
_MAX_EXPORT_DISASM_LINES = 400
_MAX_EXPORT_SYMBOLS = 2000
_METADATA_PREFIX = "rex/"
_TAG_ICON = "\u25c6"
_STRING_TYPES = Literal["AsciiString", "Utf16String", "Utf32String", "Utf8String"]
_EXPORT_FORMATS = Literal["csv", "json"]


def _validate_range(name: str, value: int, minimum: int, maximum: int | None = None) -> int:
    """Reject an out-of-range integer argument instead of silently normalizing it.

    The code and message follow the bundled mcp layer's own argument-error convention, and
    the schema-side ``Minimum``/``Maximum`` annotations reject the same values on the real
    server; this body-side check keeps direct handler invocation identical.
    """
    if value < minimum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at least {minimum}"
        )
    if maximum is not None and value > maximum:
        raise mcp.ToolError(
            "invalid_params", f"Invalid integer parameter '{name}': Must be at most {maximum}"
        )
    return value


def _truncate_with_flag(value: str, limit: int = _MAX_CHARS) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    return value[:limit] + f"... [{len(value) - limit} chars truncated]", True


def _truncate(value: str, limit: int = _MAX_CHARS) -> str:
    return _truncate_with_flag(value, limit)[0]


def _compile_user_regex(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise mcp.ToolError("invalid_regex", f"bad regular expression: {exc}") from None


def _name_filter(function_filter: str) -> re.Pattern[str] | None:
    if not function_filter:
        return None
    return _compile_user_regex(function_filter, ignore_case=True)


def _resolve_section(bv: BinaryView, name: str) -> tuple[int, int]:
    section = bv.get_section_by_name(name)
    if section is None:
        raise mcp.ToolError("section_not_found", f"no section named '{_truncate(name)}'")
    return section.start, section.end


def _require_function(bv: BinaryView, address: int) -> Function:
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError("no_function", f"no function contains {address:#x}")
    return functions[0]


def _function_entry(function: Function) -> dict[str, object]:
    return {"start": hex(function.start), "name": _truncate(function.name)}


def _render_function_disassembly(function: Any) -> list[tuple[int, str]]:
    """Render a function's addressed disassembly lines, sorted by address.

    Shared by rex_disasm_at and rex_export_disasm so both tools see exactly the same
    render. The parameter is Any-typed: the function comes back from the Any-typed
    binary view handle, and the stubbed Function type does not model basic_blocks.
    """
    lines: list[tuple[int, str]] = []
    for block in function.basic_blocks:
        for line in block.get_disassembly_text():
            # Unaddressed continuation lines cannot anchor or be reported by address.
            if line.address is None:
                continue
            lines.append((line.address, "".join(str(token) for token in line.tokens)))
    lines.sort(key=lambda entry: entry[0])
    return lines


def _disasm_window(
    lines: list[tuple[int, str]], address: int, before: int, after: int
) -> tuple[int, int]:
    """Return the [start, end) slice of ``lines`` for the before/after window at ``address``."""
    # The anchor is the last line at or before the address: at a shared address that is
    # the labeled instruction rather than the label, and past the last instruction it is
    # the final rendered line.
    anchor = 0
    for index, (line_address, _) in enumerate(lines):
        if line_address > address:
            break
        anchor = index
    start = max(0, anchor - before)
    end = min(len(lines), anchor + 1 + after)
    return start, end


def _validate_export_path(filename: str) -> None:
    """Reject filenames that could escape or abuse the export root.

    Pure lexical validation: no filesystem access, just the checks a plain file name must
    pass before it is joined with the export root.
    """
    if not filename:
        raise mcp.ToolError("invalid_params", "filename must not be empty")
    if filename.startswith("/"):
        raise mcp.ToolError(
            "invalid_params", "filename must be a plain file name, not an absolute path"
        )
    if "\\" in filename:
        raise mcp.ToolError("invalid_params", "filename must not contain backslashes")
    if "\x00" in filename:
        raise mcp.ToolError("invalid_params", "filename must not contain NUL bytes")
    parts = filename.split("/")
    if ".." in parts:
        raise mcp.ToolError("invalid_params", "filename must not contain '..' path components")
    for part in parts:
        if len(part.encode("utf-8")) > _MAX_EXPORT_COMPONENT_BYTES:
            # NAME_MAX applies per component, not to the joined path.
            raise mcp.ToolError(
                "invalid_params",
                f"filename component exceeds {_MAX_EXPORT_COMPONENT_BYTES} bytes",
            )


def _resolve_export_path(filename: str) -> Path:
    """Join an already-validated filename with the export root and resolve it."""
    try:
        _EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
        return (_EXPORT_ROOT / filename).resolve()
    except (OSError, ValueError) as error:
        raise mcp.ToolError("export_failed", f"could not prepare export path: {error}") from None


def _write_export_file(path: Path, text: str) -> int:
    """Write UTF-8 text to an export file, returning the encoded byte count."""
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except (OSError, ValueError) as error:
        raise mcp.ToolError("export_failed", f"could not write export file: {error}") from None
    return len(text.encode("utf-8"))


def _fit_to_export_cap[ExportRow](
    serialize: Callable[[list[ExportRow]], str], window: list[ExportRow]
) -> tuple[str, bool]:
    """Serialize a result window, dropping trailing entries until it fits the byte cap.

    Returns the text and whether entries were dropped for size. Dropping always
    terminates at a fitting window because a window holding only its first entry is
    checked up front: when even that overflows the cap, no export is possible and the
    call is rejected instead of silently writing a near-empty file.
    """
    if window and len(serialize(window[:1]).encode("utf-8")) > _MAX_EXPORT_FILE_BYTES:
        raise mcp.ToolError("export_failed", "first entry exceeds the export byte cap")
    dropped = False
    while True:
        text = serialize(window)
        if len(text.encode("utf-8")) <= _MAX_EXPORT_FILE_BYTES:
            return text, dropped
        del window[-1]
        dropped = True


@mcp.tool(read_only=True)
def rex_call_paths(
    call: mcp.ToolCall,
    from_addr: mcp.Address,
    to_addr: mcp.Address,
    direction: Literal["callers", "callees"] = "callers",
    max_depth: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_CALL_PATH_DEPTH)] = 8,
    max_paths: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_CALL_PATHS)] = 5,
) -> dict[str, object]:
    """Bounded breadth-first search for call paths between two functions.

    :param from_addr: Address inside the starting function.
    :param to_addr: Address inside the target function.
    :param direction: Walk "callers" edges (what reaches the target) or "callees" edges.
    :param max_depth: Maximum number of edges to walk from the starting function (1 to 16).
    :param max_paths: Maximum number of paths to return (1 to 50).
    """
    bv = call.binary_view
    max_depth = _validate_range("max_depth", max_depth, 1, _MAX_CALL_PATH_DEPTH)
    max_paths = _validate_range("max_paths", max_paths, 1, _MAX_CALL_PATHS)
    source = _require_function(bv, from_addr)
    target = _require_function(bv, to_addr)
    paths: list[list[dict[str, object]]] = []
    if source.start == target.start:
        return {
            "reachable": True,
            "paths": [[_function_entry(source)]],
            "truncated": False,
            "explored": 1,
        }
    queue: deque[tuple[Function, list[Function]]] = deque([(source, [source])])
    visited = {source.start}
    explored = 0
    hit_path_cap = False
    while queue and len(paths) < max_paths:
        function, path = queue.popleft()
        if len(path) > max_depth:
            continue
        explored += 1
        if direction == "callers":
            neighbors = sorted(function.callers, key=lambda item: item.start)
        else:
            neighbors = sorted(function.callees, key=lambda item: item.start)
        for neighbor in neighbors:
            if neighbor.start == target.start:
                paths.append([_function_entry(item) for item in [*path, neighbor]])
                if len(paths) >= max_paths:
                    # One function's call sites can list the target several times; stop
                    # appending so the result never exceeds max_paths.
                    hit_path_cap = True
                    break
            elif neighbor.start not in visited:
                visited.add(neighbor.start)
                queue.append((neighbor, [*path, neighbor]))
    # hit_path_cap is the only truncation signal: paths can never exceed max_paths (the inner
    # loop breaks first), and reaching max_paths only happens through that same append.
    return {
        "reachable": bool(paths),
        "paths": paths,
        "truncated": hit_path_cap,
        "explored": explored,
    }


@mcp.tool(read_only=True)
def rex_constant_find(
    call: mcp.ToolCall,
    value: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_CONSTANT_VALUE)],
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Find functions whose rendered instructions reference an immediate constant value.

    Uses the core's linear-view constant search (the engine behind Search > For
    Constant), so the core renders each function's instruction text once instead of
    this tool generating IL for every function. A constant counts as referenced when
    an instruction line of the function displays it as a constant or pointer token;
    lines outside any function are ignored. The scan stops as soon as the requested
    result window is known to be complete, and a full view sweep — the worst case,
    reached only when ``value`` never appears — stays a bounded, core-side pass.
    Each function reports at most the first 6 matching addresses.

    :param value: Immediate value to search for, e.g. 31337 or 65534; compared
        against displayed (unsigned) constants, so 0 to 2**64 - 1.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 500).
    :param offset: Number of matching functions to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    value = _validate_range("value", value, 0, _MAX_CONSTANT_VALUE)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    name_matcher = _name_filter(function_filter)
    functions: list[dict[str, object]] = []
    truncated = False
    abort = False

    def keep_scanning(current: int, total: int) -> bool:
        return not abort

    matched = 0
    current_start: int | None = None
    current_addresses: list[str] = []
    for address, line in bv.find_all_constant(bv.start, bv.end, value, progress_func=keep_scanning):
        function = line.function
        if function is None:
            continue
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        if function.start != current_start:
            matched += 1
            if matched > offset + limit:
                # One match past the requested window proves more functions exist.
                truncated = True
                abort = True
                break
            current_start = int(function.start)
            current_addresses = []
            entry: dict[str, object] = {
                "start": hex(function.start),
                "name": _truncate(function.name),
                "addresses": current_addresses,
            }
            if matched > offset:
                functions.append(entry)
        if len(current_addresses) < 6:
            current_addresses.append(hex(address))
    return {"truncated": truncated, "functions": functions}


@mcp.tool(read_only=True)
def rex_data_find(
    call: mcp.ToolCall,
    pattern: str,
    section: str | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Find all occurrences of a hex byte pattern in mapped memory.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
    :param section: Only search within this section.
    :param limit: Maximum number of matches to return (0 to 500).
    :param offset: Number of matches to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    if len(pattern) > _MAX_PATTERN_CHARS:
        raise mcp.ToolError("pattern_too_large", f"pattern exceeds {_MAX_PATTERN_CHARS} characters")
    try:
        matcher, pattern_length = compile_hex_pattern(pattern)
    except HexPatternError as exc:
        raise mcp.ToolError("invalid_pattern", str(exc)) from None
    bounds = _resolve_section(bv, section) if section is not None else None
    matches: list[str] = []
    total = 0
    truncated = False
    for segment in bv.segments:
        if bounds is None:
            seg_start, seg_end = segment.start, segment.start + segment.length
        else:
            seg_start = max(segment.start, bounds[0])
            seg_end = min(segment.start + segment.length, bounds[1])
        if seg_start >= seg_end:
            continue
        position = seg_start
        while position < seg_end:
            read_size = min(_READ_CHUNK + pattern_length - 1, seg_end - position)
            chunk = bv.read(position, read_size)
            if chunk:
                for match in matcher.finditer(chunk):
                    absolute = position + match.start()
                    total += 1
                    if offset < total <= offset + limit:
                        matches.append(hex(absolute))
                    elif total > offset + limit:
                        truncated = True
                        break
                if truncated:
                    break
            position += _READ_CHUNK
        if truncated:
            break
    return {"total": total, "truncated": truncated, "matches": matches}


@mcp.tool(read_only=True)
def rex_decompile_many(
    call: mcp.ToolCall,
    functions: list[str],
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> dict[str, object]:
    """Batch decompilation for triage.

    Renders the HLIL of up to 16 functions in one call. Every address expression is
    resolved and checked against the analyzed functions before anything is rendered, so
    one invalid or unanalyzed entry rejects the whole call: a result is always complete
    or absent, never partial. HLIL rendering costs tens of milliseconds per function the
    first time, which is what the batch cap bounds.

    :param functions: Address expressions of the functions to render, in output order;
        1 to 16 entries.
    :param max_lines: HLIL lines to render per function (1 to 400).
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    if not isinstance(functions, list):
        raise mcp.ToolError("invalid_params", "functions must be a list of address expressions")
    if not 1 <= len(functions) <= _MAX_DECOMPILE_BATCH:
        raise mcp.ToolError(
            "invalid_params",
            f"functions must contain between 1 and {_MAX_DECOMPILE_BATCH} address expressions",
        )
    # Resolve and check every entry before rendering anything, so a bad entry anywhere
    # in the batch cannot leave a partial result behind.
    resolved: list[Function] = []
    for index, entry in enumerate(functions):
        if not isinstance(entry, str):
            raise mcp.ToolError(
                "invalid_params", f"functions[{index}] must be a string address expression"
            )
        try:
            address = call.parse_address(entry)
        except Exception as error:
            raise mcp.ToolError(
                "invalid_params", f"bad address expression '{_truncate(entry)}': {error}"
            ) from None
        found = bv.get_functions_containing(address)
        if not found:
            raise mcp.ToolError("invalid_params", f"no analyzed function contains {address:#x}")
        resolved.append(found[0])
    rendered: list[dict[str, object]] = []
    for function in resolved:
        hlil = function.hlil
        source_lines = str(hlil).splitlines() if hlil is not None else []
        rendered.append(
            {
                **_function_entry(function),
                "lines": [_truncate(line) for line in source_lines[:max_lines]],
                "truncated": len(source_lines) > max_lines,
            }
        )
    return {"functions": rendered}


@mcp.tool(read_only=True)
def rex_disasm_at(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
) -> dict[str, object]:
    """Address-anchored disassembly window.

    The window is anchored at the instruction containing ``address`` and clipped at the
    edges of the containing function: fewer instructions coming back means the function
    ends there, not an error. An address outside every analyzed function is rejected
    rather than snapped to the nearest one. The call renders the containing function's
    disassembly once, so the cost scales with that function.

    :param address: Address expression inside the target function; accepts hex like
        0x401000, symbols, and Binary Ninja expressions.
    :param before: Instructions to include before the anchor (0 to 64).
    :param after: Instructions to include after the anchor (0 to 64).
    """
    bv = call.binary_view
    before = _validate_range("before", before, 0, _MAX_DISASM_CONTEXT)
    after = _validate_range("after", after, 0, _MAX_DISASM_CONTEXT)
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError("invalid_params", f"no analyzed function contains {address:#x}")
    function = functions[0]
    lines = _render_function_disassembly(function)
    start, end = _disasm_window(lines, address, before, after)
    return {
        "function": _function_entry(function),
        "instructions": [
            {"address": hex(line_address), "text": _truncate(text)}
            for line_address, text in lines[start:end]
        ],
        "truncated": start > 0 or end < len(lines),
    }


@mcp.tool(destructive=True)
def rex_eval_python(call: mcp.ToolCall, code: str) -> dict[str, object]:
    """Run trusted Python against the Binary Ninja API with the active view exposed as bv.

    This is the escape hatch for everything the other tools do not cover. It runs arbitrary
    code with full access to the Binary Ninja API, so it is marked destructive.

    :param code: Python source to execute; assign to ``result`` to return a value.
    """
    namespace: dict[str, object] = {
        "bv": call.binary_view,
        "call": call,
        "binaryninja": binaryninja,
        "bn": binaryninja,
    }
    buffer = io.StringIO()
    has_result = False
    raw_result: str | None = None
    try:
        with contextlib.redirect_stdout(buffer):
            exec(code, namespace)
        has_result = "result" in namespace
        if has_result:
            # repr() inside the try: a raising __repr__ must take the error path below, not
            # escape the handler and drop the captured stdout.
            raw_result = repr(namespace["result"])
    except Exception as error:
        # Keep failures out of the mcp layer's uncapped str(error) ToolError path.
        stdout, stdout_truncated = _truncate_with_flag(buffer.getvalue(), _MAX_EVAL_STDOUT_CHARS)
        message, error_truncated = _truncate_with_flag(str(error))
        return {
            "stdout": stdout,
            "stdout_truncated": stdout_truncated,
            "result": None,
            "result_truncated": False,
            "error": message,
            "error_truncated": error_truncated,
        }
    stdout, stdout_truncated = _truncate_with_flag(buffer.getvalue(), _MAX_EVAL_STDOUT_CHARS)
    if has_result and raw_result is not None:
        result, result_truncated = _truncate_with_flag(raw_result, _MAX_EVAL_RESULT_CHARS)
    else:
        result, result_truncated = None, False
    return {
        "stdout": stdout,
        "stdout_truncated": stdout_truncated,
        "result": result,
        "result_truncated": result_truncated,
        "error": None,
        "error_truncated": False,
    }


@mcp.tool()
def rex_export_disasm(
    call: mcp.ToolCall,
    address: mcp.Address,
    before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 4,
    after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_DISASM_CONTEXT)] = 8,
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_EXPORT_DISASM_LINES)] = 200,
    filename: str = "",
) -> dict[str, object]:
    """Export one analyzed function's disassembly window to a file.

    Anti-flood export: the rendered lines are written to disk and the response echoes
    only ``path``, ``bytes_written``, ``lines`` and ``truncated`` — never the
    disassembly text itself, so a large sweep cannot flood the MCP response. Address
    handling matches rex_disasm_at exactly: the window is anchored at the instruction
    containing ``address``, clipped at the containing function's edges, and an address
    outside every analyzed function is rejected rather than snapped to the nearest one.

    Accepted cost: the render materializes the whole function's disassembly lines in
    memory before the ``max_lines`` cap and the export byte cap apply — the same cost
    class as the existing echo tools. Each file line is the rendered instruction text
    (the ``text`` field rex_disasm_at echoes), one instruction per line, LF endings.
    ``truncated`` is true unless the file holds every rendered addressed line of the
    containing function: lines were left out by the before/after window, ``max_lines``,
    or the byte cap.

    :param address: Address expression inside the target function; accepts hex like
        0x401000, symbols, and Binary Ninja expressions.
    :param before: Instructions to include before the anchor (0 to 64).
    :param after: Instructions to include after the anchor (0 to 64).
    :param max_lines: Maximum number of lines to export (1 to 400).
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    before = _validate_range("before", before, 0, _MAX_DISASM_CONTEXT)
    after = _validate_range("after", after, 0, _MAX_DISASM_CONTEXT)
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_EXPORT_DISASM_LINES)
    _validate_export_path(filename)
    functions = bv.get_functions_containing(address)
    if not functions:
        raise mcp.ToolError("invalid_params", f"no analyzed function contains {address:#x}")
    lines = _render_function_disassembly(functions[0])
    start, end = _disasm_window(lines, address, before, after)
    window = lines[start:end][:max_lines]

    def serialize(selected: list[tuple[int, str]]) -> str:
        return "".join(f"{text}\n" for _, text in selected)

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "lines": len(window),
        "truncated": len(window) < len(lines) or dropped,
    }


@mcp.tool()
def rex_export_symbols(
    call: mcp.ToolCall,
    start: Annotated[int, mcp.Minimum(0)],
    end: int,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_EXPORT_SYMBOLS)] = 500,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    format: _EXPORT_FORMATS = "csv",
    filename: str = "",
) -> dict[str, object]:
    """Export the symbols in an address range to a file.

    Anti-flood export: symbols are written to disk and the response echoes only
    ``path``, ``bytes_written``, ``rows``, ``total`` and ``truncated`` — never the
    symbol table itself. Symbols come from the core's range query
    (``bv.get_symbols(start, length)``), are sorted by address ascending, and ``total``
    is the exact count in ``[start, end)``; the window is ``offset`` to
    ``offset + limit`` of that sorted list.

    The sort-then-slice here is a deliberate divergence from the early-stop pagination
    of the string search tools: an export file must contain the true window of the
    sorted listing, not an unsorted first-fit subset, and the range query already bounds
    the enumeration cost.

    CSV rows are ``symbol_address,symbol_type,name`` with commas in names quoted by the
    csv module; JSON is an indented array of the window's rows. Both are written UTF-8
    with LF endings. ``truncated`` is true when the window was clipped by
    ``offset``/``limit`` or when rows were dropped from its end to fit the export byte
    cap.

    :param start: Start of the address range (inclusive, >= 0).
    :param end: End of the address range (exclusive); must be greater than ``start``.
    :param limit: Maximum number of symbols to export (0 to 2000).
    :param offset: Number of sorted symbols to skip before the window starts (>= 0).
    :param format: Output format, "csv" or "json".
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_EXPORT_SYMBOLS)
    offset = _validate_range("offset", offset, 0)
    start = _validate_range("start", start, 0)
    if start >= end:
        raise mcp.ToolError("invalid_params", "end must be greater than start")
    _validate_export_path(filename)
    # The schema-side Literal and the body-side check below must agree; widening to str
    # keeps the body check statically reachable for direct handler invocation.
    requested: str = format
    if requested not in ("csv", "json"):
        raise mcp.ToolError("invalid_params", f"format must be 'csv' or 'json', not '{requested}'")
    symbols = bv.get_symbols(start, end - start)
    # Core symbol order is not guaranteed sorted; sort before slicing so the file holds
    # a true window of the address-ordered listing (see the docstring above).
    ordered = sorted(symbols, key=lambda symbol: symbol.address)
    total = len(ordered)
    window = [
        (symbol.address, symbol.type.name, symbol.name)
        for symbol in ordered[offset : offset + limit]
    ]

    def serialize(rows: list[tuple[int, str, str]]) -> str:
        if requested == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerow(["symbol_address", "symbol_type", "name"])
            for address, symbol_type, name in rows:
                writer.writerow([hex(address), symbol_type, name])
            return buffer.getvalue()
        return json.dumps(
            [
                {"symbol_address": hex(address), "symbol_type": symbol_type, "name": name}
                for address, symbol_type, name in rows
            ],
            indent=2,
        )

    text, dropped = _fit_to_export_cap(serialize, window)
    resolved = _resolve_export_path(filename)
    return {
        "path": str(resolved),
        "bytes_written": _write_export_file(resolved, text),
        "rows": len(window),
        "truncated": offset + limit < total or dropped,
        "total": total,
    }


@mcp.tool(read_only=True)
def rex_find_functions_by_pattern(
    call: mcp.ToolCall,
    pattern: str,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Which functions contain a byte pattern.

    Scans mapped memory rex_data_find-style (chunked reads overlapping by
    pattern_length - 1, so straddling matches are found exactly once) and maps every
    match to the analyzed function containing it. Matches in data or in gaps between
    functions are ignored. Functions are reported in first-match order with a true
    match count and up to 5 example addresses; an empty result is a valid empty list,
    not an error. Like rex_data_find, the scan stops at the first function past the
    requested window, so when ``truncated`` is true the counts near the end of the
    result can be incomplete.

    :param pattern: Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
    :param limit: Maximum number of matching functions to return (0 to 500).
    :param offset: Number of matching functions to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    if len(pattern) > _MAX_PATTERN_CHARS:
        raise mcp.ToolError("pattern_too_large", f"pattern exceeds {_MAX_PATTERN_CHARS} characters")
    try:
        matcher, pattern_length = compile_hex_pattern(pattern)
    except HexPatternError as exc:
        raise mcp.ToolError("invalid_pattern", str(exc)) from None
    # Per-function state lives in plain typed dicts rather than in mutable dict entries:
    # counts are accumulated per match and the entries are assembled once at the end.
    starts: list[int] = []
    names: dict[int, str] = {}
    match_counts: dict[int, int] = {}
    examples: dict[int, list[str]] = {}
    matched_functions = 0
    truncated = False
    for segment in bv.segments:
        position = segment.start
        segment_end = segment.start + segment.length
        while position < segment_end:
            read_size = min(_READ_CHUNK + pattern_length - 1, segment_end - position)
            chunk = bv.read(position, read_size)
            if chunk:
                for match in matcher.finditer(chunk):
                    address = position + match.start()
                    containing = bv.get_functions_containing(address)
                    if not containing:
                        continue
                    function = containing[0]
                    if function.start not in match_counts:
                        matched_functions += 1
                        if matched_functions > offset + limit:
                            # The first matching function past the window proves more
                            # exist; stop the scan there instead of counting the rest.
                            truncated = True
                            break
                        starts.append(function.start)
                        names[function.start] = _truncate(function.name)
                        match_counts[function.start] = 0
                        examples[function.start] = []
                    match_counts[function.start] += 1
                    shown = examples[function.start]
                    if len(shown) < _MAX_FIND_FUNCTIONS_EXAMPLES:
                        shown.append(hex(address))
                if truncated:
                    break
            position += _READ_CHUNK
        if truncated:
            break
    functions = [
        {
            "start": hex(start),
            "name": names[start],
            "match_count": match_counts[start],
            "addresses": examples[start],
        }
        for start in starts[offset:]
    ]
    return {"truncated": truncated, "functions": functions}


@mcp.tool(read_only=True)
def rex_function_containing(call: mcp.ToolCall, addr: mcp.Address) -> dict[str, object]:
    """List the functions that contain an address.

    :param addr: Address to look up.
    """
    functions = call.binary_view.get_functions_containing(addr)
    if not functions:
        raise mcp.ToolError("no_function", f"no function contains {addr:#x}")
    return {
        "functions": [_function_entry(function) for function in functions[:_MAX_FUNCTION_ENTRIES]],
        "truncated": len(functions) > _MAX_FUNCTION_ENTRIES,
    }


@mcp.tool()
def rex_function_define(call: mcp.ToolCall, start: mcp.Address) -> dict[str, object]:
    """Turn the bytes at an address into a function.

    :param start: Address of the new function's entry point.
    """
    function = call.binary_view.create_user_function(start)
    if function is None:
        raise mcp.ToolError("define_failed", f"could not create a function at {start:#x}")
    return _function_entry(function)


@mcp.tool(destructive=True)
def rex_function_undefine(call: mcp.ToolCall, start: mcp.Address) -> dict[str, object]:
    """Remove the user function covering an address.

    :param start: Any address inside the function to remove.
    """
    function = _require_function(call.binary_view, start)
    call.binary_view.remove_user_function(function)
    return _function_entry(function)


@mcp.tool(read_only=True)
def rex_hlil_grep(
    call: mcp.ToolCall,
    regex: str,
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_LIMIT)] = 20,
    max_functions: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_FUNCTIONS)] = 2000,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    context_before: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_CONTEXT)] = 0,
    context_after: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_HLIL_GREP_CONTEXT)] = 0,
) -> dict[str, object]:
    """Search rendered HLIL text across functions with a regular expression.

    Regular expressions run on Python's ``re`` with no timeout, so a pattern with
    catastrophic backtracking can stall the scan. Each function reports at most the
    first 3 matching HLIL lines.

    With ``context_before``/``context_after`` each match comes back wrapped in that
    many surrounding HLIL lines: the matched line is prefixed with ``"> "`` and the
    context lines with two spaces, and consecutive windows are separated by ``"--"`` so
    overlapping context ranges stay unambiguous. Function edges truncate the window;
    the caps on matches per function and on echoed line length are unchanged.

    Rendering HLIL is the dominant cost: tens of milliseconds per function the first
    time a function's HLIL is generated. A single invocation never renders more than
    ``max_functions`` functions; page through a larger database by passing the
    ``next_offset`` of the previous result as ``offset`` until ``truncated`` is false.

    :param regex: Regular expression applied to every rendered HLIL line.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 200).
    :param max_functions: Maximum number of functions to scan before stopping (0 to 5000).
    :param offset: Number of functions to skip before scanning starts (>= 0).
    :param context_before: HLIL lines to include before each match (0 to 8).
    :param context_after: HLIL lines to include after each match (0 to 8).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_HLIL_GREP_LIMIT)
    max_functions = _validate_range("max_functions", max_functions, 0, _MAX_HLIL_GREP_FUNCTIONS)
    offset = _validate_range("offset", offset, 0)
    context_before = _validate_range("context_before", context_before, 0, _MAX_HLIL_GREP_CONTEXT)
    context_after = _validate_range("context_after", context_after, 0, _MAX_HLIL_GREP_CONTEXT)
    matcher = _compile_user_regex(regex)
    name_matcher = _name_filter(function_filter)
    matches: list[dict[str, object]] = []
    scanned = 0
    truncated = False
    next_offset: int | None = None
    for index, function in enumerate(islice(bv.functions, offset, None), offset):
        if len(matches) >= limit or scanned >= max_functions:
            truncated = True
            next_offset = index
            break
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        hlil = function.hlil
        if hlil is None:
            continue
        scanned += 1
        source_lines = str(hlil).splitlines()
        matched = [
            line_index for line_index, line in enumerate(source_lines) if matcher.search(line)
        ]
        if matched:
            if context_before == 0 and context_after == 0:
                lines = [_truncate(source_lines[match_index]) for match_index in matched[:3]]
            else:
                lines = []
                for match_index in matched[:3]:
                    if lines:
                        # Keep windows apart even when their context ranges overlap, so
                        # each match's own before/after group stays identifiable.
                        lines.append("--")
                    start = max(0, match_index - context_before)
                    lines.extend("  " + _truncate(line) for line in source_lines[start:match_index])
                    lines.append("> " + _truncate(source_lines[match_index]))
                    end = match_index + 1 + context_after
                    lines.extend(
                        "  " + _truncate(line) for line in source_lines[match_index + 1 : end]
                    )
            matches.append(
                {
                    "start": hex(function.start),
                    "name": _truncate(function.name),
                    "lines": lines,
                }
            )
    return {
        "scanned": scanned,
        "truncated": truncated,
        "functions": matches,
        "next_offset": next_offset,
    }


@mcp.tool(destructive=True)
def rex_kv_delete(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Delete a value previously stored with rex_kv_set.

    :param key: Key to delete.
    """
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")
    call.binary_view.remove_metadata(_METADATA_PREFIX + key)
    return {"key": _truncate(key)}


@mcp.tool(read_only=True)
def rex_kv_get(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Read a string previously stored with rex_kv_set.

    :param key: Key to read.
    """
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")
    try:
        value = call.binary_view.query_metadata(_METADATA_PREFIX + key)
    except Exception:
        raise mcp.ToolError("not_found", f"no value stored under '{_truncate(key)}'") from None
    text, truncated = _truncate_with_flag(str(value), _MAX_KV_VALUE_CHARS)
    return {"key": _truncate(key), "value": text, "truncated": truncated}


@mcp.tool()
def rex_kv_set(call: mcp.ToolCall, key: str, value: str) -> dict[str, object]:
    """Store a string in the binary view database as persistent scratch data.

    Values are stored under the "rex/" metadata namespace and survive across sessions.

    :param key: Key to store under.
    :param value: String value to store.
    """
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")
    if len(key) > _MAX_KV_KEY_CHARS:
        # The key becomes part of the persistent metadata path with no core-side length bound.
        raise mcp.ToolError("key_too_large", f"key exceeds {_MAX_KV_KEY_CHARS} characters")
    if len(value) > _MAX_KV_VALUE_CHARS:
        raise mcp.ToolError("value_too_large", f"value exceeds {_MAX_KV_VALUE_CHARS} characters")
    call.binary_view.store_metadata(_METADATA_PREFIX + key, value)
    preview, truncated = _truncate_with_flag(value)
    return {"key": _truncate(key), "length": len(value), "value": preview, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_memory_write(call: mcp.ToolCall, addr: mcp.Address, hex_data: str) -> dict[str, object]:
    """Overwrite bytes in the binary view with a hex byte string.

    :param addr: Address to write to.
    :param hex_data: Hex byte string to write, e.g. "90 90" or "9090".
    """
    compact = "".join(hex_data.split())
    if not compact:
        raise mcp.ToolError("invalid_hex", "hex_data is empty")
    try:
        data = bytes.fromhex(compact)
    except ValueError:
        raise mcp.ToolError("invalid_hex", "hex_data must contain hex byte pairs") from None
    written = call.binary_view.write(addr, data)
    return {"address": hex(addr), "bytes_written": written}


@mcp.tool(read_only=True)
def rex_string_read_at(
    call: mcp.ToolCall,
    addr: mcp.Address,
    max_chars: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_STRING_READ_CHARS)] = _MAX_CHARS,
) -> dict[str, object]:
    """Read the detected string at an address.

    :param addr: Address of the string.
    :param max_chars: Truncate long string values to this many characters (1 to 4096).
    """
    max_chars = _validate_range("max_chars", max_chars, 1, _MAX_STRING_READ_CHARS)
    string = call.binary_view.get_string_at(addr)
    if string is None:
        raise mcp.ToolError("no_string", f"no detected string at {addr:#x}")
    value, truncated = _truncate_with_flag(string.value, max_chars)
    return {
        "address": hex(string.start),
        "length": len(string),
        "type": string.type.name,
        "value": value,
        "truncated": truncated,
    }


@mcp.tool(read_only=True)
def rex_string_search(
    call: mcp.ToolCall,
    pattern: str = "",
    regex: bool = False,
    ignore_case: bool = False,
    section: str | None = None,
    string_type: _STRING_TYPES | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Search the binary's detected strings by substring or regular expression.

    Regular expressions run on Python's ``re`` with no timeout, so a pattern with
    catastrophic backtracking can stall the search; prefer substring mode for untrusted input.

    :param pattern: Substring or regular expression to match; empty matches every string.
    :param regex: Treat pattern as a regular expression instead of a substring.
    :param ignore_case: Match case-insensitively.
    :param section: Only include strings within this section.
    :param string_type: Only include strings of this type.
    :param limit: Maximum number of strings to return (0 to 500).
    :param offset: Number of matching strings to skip before collecting results (>= 0).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matcher = _compile_user_regex(pattern, ignore_case=ignore_case) if regex else None
    bounds = _resolve_section(bv, section) if section is not None else None
    total = 0
    truncated = False
    found: list[dict[str, object]] = []
    for string in bv.strings:
        if string_type is not None and string.type.name != string_type:
            continue
        if bounds is not None and not bounds[0] <= string.start < bounds[1]:
            continue
        value = string.value
        if matcher is not None:
            hit = matcher.search(value) is not None
        elif ignore_case:
            hit = pattern.lower() in value.lower()
        else:
            hit = pattern in value
        if not hit:
            continue
        total += 1
        if offset < total <= offset + limit:
            found.append(
                {
                    "address": hex(string.start),
                    "length": len(string),
                    "type": string.type.name,
                    "value": _truncate(value),
                }
            )
        elif total > offset + limit:
            truncated = True
            break
    return {"total": total, "truncated": truncated, "strings": found}


@mcp.tool(read_only=True)
def rex_tag_list(
    call: mcp.ToolCall, limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100
) -> dict[str, object]:
    """List the tags set on the binary view.

    :param limit: Maximum number of tags to return (0 to 500).
    """
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    tags = []
    for address, tag in call.binary_view.get_tags():
        data, data_truncated = _truncate_with_flag(tag.data)
        tags.append(
            {
                "address": hex(address),
                "tag_type": tag.type.name,
                "data": data,
                "data_truncated": data_truncated,
            }
        )
    return {"total": len(tags), "truncated": len(tags) > limit, "tags": tags[:limit]}


@mcp.tool()
def rex_tag_set(
    call: mcp.ToolCall, addr: mcp.Address, tag_type: str, data: str, create_missing: bool = True
) -> dict[str, object]:
    """Attach a Binary Ninja tag at an address, visible in the GUI.

    :param addr: Address to tag; accepts expressions like "main" or ".text + 0x10".
    :param tag_type: Tag type name, e.g. "Crashes" or "Finding".
    :param data: Tag text.
    :param create_missing: Create tag_type when it does not exist yet.
    """
    bv = call.binary_view
    if len(data) > _MAX_TAG_DATA_CHARS:
        raise mcp.ToolError("data_too_large", f"tag data exceeds {_MAX_TAG_DATA_CHARS} characters")
    if tag_type not in bv.tag_types:
        if not create_missing:
            raise mcp.ToolError("tag_type_not_found", f"no tag type named '{_truncate(tag_type)}'")
        if len(tag_type) > _MAX_TAG_TYPE_CHARS:
            # create_tag_type persists the name in the database with no core-side length bound.
            raise mcp.ToolError(
                "tag_type_too_large", f"tag type name exceeds {_MAX_TAG_TYPE_CHARS} characters"
            )
        bv.create_tag_type(tag_type, _TAG_ICON)
    bv.add_tag(addr, tag_type, data)
    data_preview, data_truncated = _truncate_with_flag(data)
    return {
        "address": hex(addr),
        "tag_type": _truncate(tag_type),
        "data": data_preview,
        "data_truncated": data_truncated,
        "length": len(data),
    }
