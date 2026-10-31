"""MCP tools extending Binary Ninja's built-in MCP server.

Every tool is prefixed ``rex_`` because the ``bn_`` prefix belongs to the built-in tools.
Handlers run on the MCP server thread, so none of them touch the UI thread directly.
"""

from __future__ import annotations

import contextlib
import io
import re
from collections import deque
from collections.abc import Iterator
from typing import Annotated, Literal

import binaryninja
from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import MediumLevelILOperation
from binaryninja.function import Function
from binaryninja.mediumlevelil import MediumLevelILInstruction

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
_METADATA_PREFIX = "rex/"
_TAG_ICON = "\u25c6"
_STRING_TYPES = Literal["AsciiString", "Utf16String", "Utf32String", "Utf8String"]


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


def _iter_mlil_constants(
    instruction: MediumLevelILInstruction,
) -> Iterator[MediumLevelILInstruction]:
    if instruction.operation in (
        MediumLevelILOperation.MLIL_CONST,
        MediumLevelILOperation.MLIL_CONST_PTR,
    ):
        yield instruction
        return
    for operand in instruction.operands:
        if isinstance(operand, MediumLevelILInstruction):
            yield from _iter_mlil_constants(operand)
        elif isinstance(operand, list):
            for item in operand:
                if isinstance(item, MediumLevelILInstruction):
                    yield from _iter_mlil_constants(item)


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
    value: int,
    function_filter: str = "",
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
) -> dict[str, object]:
    """Find functions whose MLIL references an immediate constant value.

    Each function reports at most the first 6 matching instruction addresses.

    :param value: Immediate value to search for, e.g. 31337 or 65534.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 500).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    name_matcher = _name_filter(function_filter)
    functions: list[dict[str, object]] = []
    truncated = False
    for function in bv.functions:
        if len(functions) >= limit:
            truncated = True
            break
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        mlil = function.mlil
        if mlil is None:
            continue
        addresses = []
        for instruction in mlil.instructions:
            for constant in _iter_mlil_constants(instruction):
                if int(constant.constant) == value:
                    addresses.append(hex(instruction.address))
                    break
        if addresses:
            functions.append(
                {
                    "start": hex(function.start),
                    "name": _truncate(function.name),
                    "addresses": addresses[:6],
                }
            )
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
) -> dict[str, object]:
    """Search rendered HLIL text across functions with a regular expression.

    Regular expressions run on Python's ``re`` with no timeout, so a pattern with
    catastrophic backtracking can stall the scan. Each function reports at most the
    first 3 matching HLIL lines.

    :param regex: Regular expression applied to every rendered HLIL line.
    :param function_filter: Case-insensitive regular expression matched against function names.
    :param limit: Maximum number of matching functions to return (0 to 200).
    :param max_functions: Maximum number of functions to scan before stopping (0 to 5000).
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_HLIL_GREP_LIMIT)
    max_functions = _validate_range("max_functions", max_functions, 0, _MAX_HLIL_GREP_FUNCTIONS)
    matcher = _compile_user_regex(regex)
    name_matcher = _name_filter(function_filter)
    matches: list[dict[str, object]] = []
    scanned = 0
    truncated = False
    for function in bv.functions:
        if len(matches) >= limit or scanned >= max_functions:
            truncated = True
            break
        if name_matcher is not None and name_matcher.search(function.name) is None:
            continue
        hlil = function.hlil
        if hlil is None:
            continue
        scanned += 1
        lines = [line for line in str(hlil).splitlines() if matcher.search(line)]
        if lines:
            matches.append(
                {
                    "start": hex(function.start),
                    "name": _truncate(function.name),
                    "lines": [_truncate(line) for line in lines[:3]],
                }
            )
    return {"scanned": scanned, "truncated": truncated, "functions": matches}


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
