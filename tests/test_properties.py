from __future__ import annotations

import re
from typing import Any

import pytest
from helpers import (
    FakeBinaryView,
    FakeFunction,
    FakeSegment,
    FakeStringReference,
    FakeToolCall,
    FakeToolError,
    get_tool,
)
from hypothesis import assume, given
from hypothesis import strategies as st

from binja_plugin import tools
from binja_plugin.hexpattern import compile_hex_pattern

_TOKENS = ["00", "7f", "80", "ff", "a5", "??"]
# Bias the blob alphabet toward bytes that appear in the tokens plus the newline byte:
# a wildcard compiled without re.DOTALL misses matches on b"\n", and uniform random
# blobs almost never place one under a wildcard.
_BLOB_BYTES = [0x00, 0x0A, 0x41, 0xA5, 0xFF]


@given(st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=16))
def test_compiled_pattern_matches_its_own_bytes(tokens: list[str]) -> None:
    matcher, length = compile_hex_pattern(" ".join(tokens))
    blob = bytes(0x00 if token == "??" else int(token, 16) for token in tokens)
    assert [match.start() for match in matcher.finditer(blob)] == [0]
    assert length == len(tokens)


@given(
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=8),
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
)
def test_matches_agree_with_naive_search(tokens: list[str], blob: bytes) -> None:
    matcher, length = compile_hex_pattern(" ".join(tokens))
    expected = [
        index
        for index in range(len(blob) - length + 1)
        if all(
            token == "??" or blob[index + offset] == int(token, 16)
            for offset, token in enumerate(tokens)
        )
    ]
    assert [match.start() for match in matcher.finditer(blob)] == expected


# --- rex_string_search pagination -------------------------------------------------
#
# The full match list (one unbounded scan) is the reference; every page must be the
# exact slice of it. The scan stops at the first match past the window, so a page's
# "total" is min(true_total, offset+limit+1) and "truncated" is exactly "the window
# ended before the matches did". Nothing here recomputes matching logic: it only pins
# window arithmetic against the tool's own untruncated scan. Out-of-range pagination
# input is covered by the rejection properties below.


def _string_view(strings: list[str]) -> tuple[FakeToolCall, Any]:
    view = FakeBinaryView(
        strings=[
            FakeStringReference(value, 0x1000 + 16 * index) for index, value in enumerate(strings)
        ]
    )
    _, search = get_tool("rex_string_search")
    call = FakeToolCall(view)
    return call, search


def _check_page(
    page: dict[str, Any],
    everything: list[dict[str, object]],
    true_total: int,
    offset: int,
    limit: int,
    items_key: str = "strings",
) -> None:
    # Callers pass only in-range values: rejection of anything else is its own contract.
    assert offset >= 0
    assert 0 <= limit <= tools._MAX_LIMIT
    assert page[items_key] == everything[offset : offset + limit]
    assert len(page[items_key]) <= tools._MAX_LIMIT
    assert page["total"] == min(true_total, offset + limit + 1)
    assert page["truncated"] is (true_total > offset + limit)


@given(
    strings=st.lists(st.text(max_size=8), max_size=10),
    pattern=st.text(min_size=1, max_size=3),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_string_search_pages_tile_the_full_result(
    strings: list[str], pattern: str, limit: int, offset: int
) -> None:
    call, search = _string_view(strings)
    full = search(call, pattern=pattern, limit=tools._MAX_LIMIT)
    assert full["truncated"] is False
    everything = full["strings"]
    true_total = full["total"]

    # Tiling: consecutive pages of 2 reproduce the full result with no gaps or duplicates.
    tiled = [
        found
        for page_offset in range(0, true_total + 1, 2)
        for found in search(call, pattern=pattern, limit=2, offset=page_offset)["strings"]
    ]
    assert tiled == everything

    # Every page boundary in range is the exact expected slice with exact flags.
    for page_offset in range(0, true_total + 2):
        _check_page(
            search(call, pattern=pattern, limit=2, offset=page_offset),
            everything,
            true_total,
            page_offset,
            2,
        )

    # An arbitrary adversarial (but valid) offset pages the exact expected slice.
    _check_page(
        search(call, pattern=pattern, limit=limit, offset=offset),
        everything,
        true_total,
        offset,
        limit,
    )


# --- out-of-range pagination input is rejected, never normalized --------------------
#
# Adversarial integers: any limit outside [0, _MAX_LIMIT] or any negative offset must
# raise the mcp layer's argument-error convention with the exact per-parameter message,
# regardless of the other parameter's validity.


@given(
    strings=st.lists(st.text(max_size=8), max_size=5),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
    offset=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_string_search_rejects_out_of_range_pagination(
    strings: list[str], limit: int, offset: int
) -> None:
    assume(not (0 <= limit <= tools._MAX_LIMIT and offset >= 0))
    call, search = _string_view(strings)
    with pytest.raises(FakeToolError) as exc:
        search(call, pattern="a", limit=limit, offset=offset)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    elif limit > tools._MAX_LIMIT:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )
    else:
        assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


# --- rex_data_find pagination -------------------------------------------------------


@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=3),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_data_find_pages_tile_the_full_result(
    blob: bytes, tokens: list[str], limit: int, offset: int
) -> None:
    pattern = " ".join(tokens)
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, max(len(blob), 1))],
        memory={0x2000: blob} if blob else {},
    )
    _, find = get_tool("rex_data_find")
    call = FakeToolCall(view)
    full = find(call, pattern=pattern, limit=tools._MAX_LIMIT)
    assert full["truncated"] is False
    everything = full["matches"]
    true_total = full["total"]

    tiled = [
        found
        for page_offset in range(0, true_total + 1, 2)
        for found in find(call, pattern=pattern, limit=2, offset=page_offset)["matches"]
    ]
    assert tiled == everything

    for page_offset in range(0, true_total + 2):
        _check_page(
            find(call, pattern=pattern, limit=2, offset=page_offset),
            everything,
            true_total,
            page_offset,
            2,
            items_key="matches",
        )
    _check_page(
        find(call, pattern=pattern, limit=limit, offset=offset),
        everything,
        true_total,
        offset,
        limit,
        items_key="matches",
    )


@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=8).map(bytes),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
    offset=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_data_find_rejects_out_of_range_pagination(blob: bytes, limit: int, offset: int) -> None:
    assume(not (0 <= limit <= tools._MAX_LIMIT and offset >= 0))
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, max(len(blob), 1))],
        memory={0x2000: blob} if blob else {},
    )
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(FakeToolCall(view), pattern="00", limit=limit, offset=offset)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    elif limit > tools._MAX_LIMIT:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )
    else:
        assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


# --- rex_tag_list paging -------------------------------------------------------------
#
# tag_list reports the true total (it builds the whole list before slicing), slices
# tags[:limit], and flags truncated exactly when tags exist past the page.


@given(
    tags=st.lists(st.tuples(st.integers(0, 2**63), st.text(max_size=600)), max_size=10),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
)
def test_tag_list_pages_arbitrary_limits(tags: list[tuple[int, str]], limit: int) -> None:
    view = FakeBinaryView()
    for address, data in tags:
        view.add_tag(address, "Finding", data)
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(FakeToolCall(view), limit=limit)
    expected = [
        {
            "address": hex(address),
            "tag_type": "Finding",
            "data": data
            if len(data) <= tools._MAX_CHARS
            else data[: tools._MAX_CHARS] + f"... [{len(data) - tools._MAX_CHARS} chars truncated]",
            "data_truncated": len(data) > tools._MAX_CHARS,
        }
        for address, data in tags
    ]
    assert result["total"] == len(tags)
    assert result["truncated"] is (len(tags) > limit)
    assert result["tags"] == expected[:limit]


@given(
    tags=st.lists(st.tuples(st.integers(0, 2**63), st.text(max_size=8)), max_size=5),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_tag_list_rejects_out_of_range_limits(tags: list[tuple[int, str]], limit: int) -> None:
    assume(not 0 <= limit <= tools._MAX_LIMIT)
    view = FakeBinaryView()
    for address, data in tags:
        view.add_tag(address, "Finding", data)
    _, tag_list = get_tool("rex_tag_list")
    with pytest.raises(FakeToolError) as exc:
        tag_list(FakeToolCall(view), limit=limit)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    else:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )


# --- rex_call_paths on random call graphs -------------------------------------------
#
# Invariants over generated graphs: paths are real edges of the graph, start at the
# from-function, end at the to-function, never exceed the requested depth, are unique
# and loop-free, reachable is exactly "target within the requested depth" (verified by
# an independent Floyd-Warshall oracle), and truncated is exactly "the path cap was hit".


_NODES = 6
_STARTS = [0x1000 + 0x10 * index for index in range(_NODES)]


def _graph(edges: list[tuple[int, int]]) -> tuple[list[FakeFunction], list[set[int]]]:
    functions = [FakeFunction(f"f{index}", start, start + 8) for index, start in enumerate(_STARTS)]
    adjacency: list[set[int]] = [set() for _ in range(_NODES)]
    for caller, callee in edges:
        functions[caller].callees.append(functions[callee])
        functions[callee].callers.append(functions[caller])
        adjacency[caller].add(callee)
    return functions, adjacency


def _min_distances(adjacency: list[set[int]], direction: str) -> list[list[int]]:
    """Floyd-Warshall over the traversal edges: callers walk call edges backwards."""
    huge = 10**9
    dist = [[huge] * _NODES for _ in range(_NODES)]
    for node in range(_NODES):
        dist[node][node] = 0
    for caller in range(_NODES):
        for callee in adjacency[caller]:
            if direction == "callees":
                dist[caller][callee] = 1
            else:
                dist[callee][caller] = 1
    for middle in range(_NODES):
        for start in range(_NODES):
            for end in range(_NODES):
                if dist[start][middle] + dist[middle][end] < dist[start][end]:
                    dist[start][end] = dist[start][middle] + dist[middle][end]
    return dist


@given(
    edges=st.lists(st.tuples(st.integers(0, _NODES - 1), st.integers(0, _NODES - 1)), max_size=14),
    from_index=st.integers(0, _NODES - 1),
    to_index=st.integers(0, _NODES - 1),
    direction=st.sampled_from(["callers", "callees"]),
    max_depth=st.integers(min_value=1, max_value=tools._MAX_CALL_PATH_DEPTH),
    max_paths=st.integers(min_value=1, max_value=tools._MAX_CALL_PATHS),
)
def test_call_paths_reports_real_edges_within_the_depth_cap(
    edges: list[tuple[int, int]],
    from_index: int,
    to_index: int,
    direction: str,
    max_depth: int,
    max_paths: int,
) -> None:
    functions, adjacency = _graph(edges)
    _, paths_tool = get_tool("rex_call_paths")
    result = paths_tool(
        FakeToolCall(FakeBinaryView(functions=functions)),
        _STARTS[from_index] + 4,
        _STARTS[to_index] + 4,
        direction=direction,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    depth_cap = max_depth
    path_cap = max_paths

    if from_index == to_index:
        assert result == {
            "reachable": True,
            "paths": [[{"start": hex(_STARTS[from_index]), "name": f"f{from_index}"}]],
            "truncated": False,
            "explored": 1,
        }
        return

    paths = result["paths"]
    assert len(paths) <= path_cap
    assert result["reachable"] is bool(paths)
    assert result["truncated"] is (len(paths) == path_cap)
    for path in paths:
        nodes = [int(entry["start"], 16) for entry in path]
        assert path[0] == {"start": hex(_STARTS[from_index]), "name": f"f{from_index}"}
        assert path[-1] == {"start": hex(_STARTS[to_index]), "name": f"f{to_index}"}
        assert len(path) <= depth_cap + 1
        # Tree paths never revisit a node (target is never enqueued, source never
        # re-enqueued). Duplicate identical paths are legitimate: one call site per
        # entry means the target can appear several times in one neighbor list.
        assert len(set(nodes)) == len(nodes)
        for step, following in zip(nodes, nodes[1:]):
            step_index = _STARTS.index(step)
            following_index = _STARTS.index(following)
            if direction == "callees":
                assert following_index in adjacency[step_index]
            else:
                assert step_index in adjacency[following_index]

    oracle = _min_distances(adjacency, direction)
    assert result["reachable"] is (oracle[from_index][to_index] <= depth_cap)


@given(
    max_depth=st.integers(min_value=-(2**63), max_value=2**63),
    max_paths=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_call_paths_rejects_out_of_range_bounds(max_depth: int, max_paths: int) -> None:
    assume(
        not (
            1 <= max_depth <= tools._MAX_CALL_PATH_DEPTH and 1 <= max_paths <= tools._MAX_CALL_PATHS
        )
    )
    functions, _ = _graph([])
    _, paths_tool = get_tool("rex_call_paths")
    with pytest.raises(FakeToolError) as exc:
        paths_tool(
            FakeToolCall(FakeBinaryView(functions=functions)),
            _STARTS[0] + 4,
            _STARTS[0] + 4,
            max_depth=max_depth,
            max_paths=max_paths,
        )
    assert exc.value.code == "invalid_params"
    if max_depth < 1:
        assert exc.value.message == "Invalid integer parameter 'max_depth': Must be at least 1"
    elif max_depth > tools._MAX_CALL_PATH_DEPTH:
        assert exc.value.message == (
            f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}"
        )
    elif max_paths < 1:
        assert exc.value.message == "Invalid integer parameter 'max_paths': Must be at least 1"
    else:
        assert exc.value.message == (
            f"Invalid integer parameter 'max_paths': Must be at most {tools._MAX_CALL_PATHS}"
        )


# --- rex_string_search regex/ignore_case composition --------------------------------
#
# Regex mode with re.escape must agree with substring mode, and ignore_case must be a
# superset of case-sensitive matching, in the same order. ASCII-only alphabets keep
# both claims exact: str.lower() is length-preserving on ASCII, so the substring path's
# lower()-based comparison and re.IGNORECASE coincide there. (Exotic unicode case
# pairs are out of scope; the docstring already steers untrusted input to substring
# mode.)


@given(
    strings=st.lists(st.text(alphabet="aAbBcC ", max_size=10), max_size=10),
    pattern=st.text(alphabet="aAcC", min_size=1, max_size=3),
)
def test_regex_ignore_case_agrees_with_substring_ignore_case(
    strings: list[str], pattern: str
) -> None:
    call, search = _string_view(strings)
    caseless = search(call, pattern=pattern, ignore_case=True, limit=500)
    as_regex = search(call, pattern=re.escape(pattern), regex=True, ignore_case=True, limit=500)
    assert as_regex == caseless

    sensitive = search(call, pattern=pattern, limit=500)
    caseless_addresses = [entry["address"] for entry in caseless["strings"]]
    sensitive_addresses = {entry["address"] for entry in sensitive["strings"]}
    assert [entry["address"] for entry in sensitive["strings"]] == [
        address for address in caseless_addresses if address in sensitive_addresses
    ]
