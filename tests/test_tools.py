from __future__ import annotations

import binaryninja
import pytest
from helpers import (
    FakeBinaryView,
    FakeFunction,
    FakeMLIL,
    FakeSegment,
    FakeStringReference,
    FakeToolCall,
    FakeToolError,
    RenderableText,
    get_tool,
    make_mlil_instruction,
)

from binja_plugin import tools


def _call(view: FakeBinaryView) -> FakeToolCall:
    return FakeToolCall(view)


def _view_with_functions() -> FakeBinaryView:
    operation = binaryninja.MediumLevelILOperation
    main_mlil = FakeMLIL(
        [
            make_mlil_instruction(
                operation.MLIL_SET_VAR,
                operands=[
                    make_mlil_instruction(operation.MLIL_CONST, constant=0x31337, address=0x1140)
                ],
                address=0x1140,
            ),
            make_mlil_instruction(
                operation.MLIL_SET_VAR,
                operands=[
                    make_mlil_instruction(
                        operation.MLIL_CONST_PTR, constant=0x2000, address=0x1150
                    ),
                    [make_mlil_instruction(operation.MLIL_CONST, constant=0x1234, address=0x1151)],
                    7,
                ],
                address=0x1150,
            ),
        ]
    )
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("void main() {\n    if (recv(fd, buf, n) <= 0)\n        return 1;\n}"),
        mlil=main_mlil,
    )
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    handler.callers = [sink]
    sink.callees = [handler]
    handler.callees = [main]
    return FakeBinaryView(functions=[main, handler, sink])


def test_string_search_matches_substring() -> None:
    view = FakeBinaryView(
        strings=[
            FakeStringReference("hello world", 0x1100),
            FakeStringReference("HELLO again", 0x1120, type_name="Utf8String"),
        ]
    )
    _, search = get_tool("rex_string_search")
    assert search(_call(view), pattern="hello")["total"] == 1
    assert search(_call(view), pattern="hello", ignore_case=True)["total"] == 2
    assert search(_call(view))["total"] == 2


def test_string_search_filters_and_pagination() -> None:
    strings = [
        FakeStringReference("alpha", 0x100),
        FakeStringReference("beta", 0x110),
        FakeStringReference("alphabeta", 0x120, type_name="Utf8String"),
    ]
    view = FakeBinaryView(strings=strings, sections={"s": (0x100, 0x118)})
    _, search = get_tool("rex_string_search")
    # "[ab]" is only matchable in regex mode: dropping the regex path yields 0 here.
    assert search(_call(view), pattern="alph[ab]", regex=True)["total"] == 2
    by_type = search(_call(view), pattern="alpha", string_type="Utf8String")
    assert by_type["total"] == 1
    assert by_type["strings"][0]["value"] == "alphabeta"
    assert search(_call(view), section="s")["total"] == 2
    paged = search(_call(view), limit=1, offset=1)
    assert paged["total"] == 3
    assert paged["strings"][0]["value"] == "beta"
    assert paged["truncated"] is True


def test_string_search_caps_limit() -> None:
    strings = [FakeStringReference(f"s{index}", 0x1000 + index) for index in range(600)]
    view = FakeBinaryView(strings=strings)
    _, search = get_tool("rex_string_search")
    # Exactly at the cap the limit is honored; the scan stops one match past the window.
    result = search(_call(view), limit=tools._MAX_LIMIT)
    assert result["total"] == tools._MAX_LIMIT + 1
    assert len(result["strings"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    # Past the cap the request is rejected, not silently normalized.
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_string_search_truncates_long_values() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("a" * 600, 0x1000)])
    _, search = get_tool("rex_string_search")
    result = search(_call(view), pattern="a")
    assert result["total"] == 1
    assert result["strings"][0]["value"] == "a" * tools._MAX_CHARS + "... [88 chars truncated]"


def test_string_search_pagination_beyond_the_result_set() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("ab", 0x100), FakeStringReference("ab", 0x110)]
    )
    _, search = get_tool("rex_string_search")
    # offset == total and offset > total: empty page, nothing skipped, nothing truncated.
    at_end = search(_call(view), pattern="ab", limit=10, offset=2)
    assert at_end == {"total": 2, "truncated": False, "strings": []}
    past_end = search(_call(view), pattern="ab", limit=10, offset=10**9)
    assert past_end == {"total": 2, "truncated": False, "strings": []}
    # limit=0 pages nothing out; the scan stops at the first match past the empty window,
    # so "total" caps at offset+limit+1 and truncated says a further match existed.
    zero = search(_call(view), pattern="ab", limit=0)
    assert zero == {"total": 1, "truncated": True, "strings": []}


def test_string_search_errors() -> None:
    view = FakeBinaryView()
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), section="nope")
    assert exc.value.code == "section_not_found"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), pattern="(", regex=True)
    assert exc.value.code == "invalid_regex"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), section="s" * 1000)
    assert exc.value.code == "section_not_found"
    assert "chars truncated]" in exc.value.message
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_data_find_finds_pattern_and_wildcards() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x10)],
        memory={0x1000: b"\x90\x48\x8b\x05\x48\x8b\x05"},
    )
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="48 8b 05")
    assert result["matches"] == ["0x1001", "0x1004"]
    assert result["total"] == 2
    assert find(_call(view), pattern="48 ?? 05")["matches"] == ["0x1001", "0x1004"]


def test_data_find_reports_overlapping_matches() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\x90\x90\x90\x90"})
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="9090")
    assert result["matches"] == ["0x1000", "0x1001", "0x1002"]
    assert result["total"] == 3


def test_data_find_finds_matches_across_chunk_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x33\xeb\x00\x00\x33\xeb"},
    )
    _, find = get_tool("rex_data_find")
    result = find(_call(view), pattern="33 eb")
    assert result["total"] == 2
    assert result["matches"] == ["0x1002", "0x1006"]


def test_data_find_matches_straddling_chunk_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    _, find = get_tool("rex_data_find")
    # A match straddling the chunk edge is only visible because each read extends
    # pattern_length - 1 bytes past the chunk; dropping that overlap must fail this test.
    straddle = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x33\xeb\x00\x00\x00"},
    )
    assert find(_call(straddle), pattern="33 eb") == {
        "total": 1,
        "truncated": False,
        "matches": ["0x1003"],
    }
    # A match starting exactly at the chunk edge is reported once: the reads overlap, but
    # every match start belongs to exactly one read.
    boundary = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\x33\xeb\x00\x00"},
    )
    assert find(_call(boundary), pattern="33 eb") == {
        "total": 1,
        "truncated": False,
        "matches": ["0x1004"],
    }


def test_data_find_finds_matches_after_chunk_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, 8)],
        memory={0x2000: b"\x00\x00\x00\x00\x00\x33\xeb\x00"},
    )
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="33 eb")["matches"] == ["0x2005"]


def test_data_find_section_limit_and_errors() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x100), FakeSegment(0x9000, 0x10)],
        memory={0x1000: b"\xeb\x0e" * 4, 0x9000: b"\xeb\x0e"},
        sections={"text": (0x1002, 0x1006)},
    )
    _, find = get_tool("rex_data_find")
    # The section starts and ends inside the first segment, so both bounds are clamped:
    # matches at 0x1000 (before the section) and 0x1006 (past it) must be excluded.
    sectioned = find(_call(view), pattern="eb0e", section="text")
    assert sectioned["matches"] == ["0x1002", "0x1004"]
    assert sectioned["total"] == 2
    paged = find(_call(view), pattern="eb0e", limit=1, offset=1)
    # The scan stops at the first match past the window, so "total" caps at
    # offset+limit+1 == 3 even though 5 matches exist.
    assert paged["total"] == 3
    assert paged["matches"] == ["0x1002"]
    assert paged["truncated"] is True
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="zz")
    assert exc.value.code == "invalid_pattern"


def test_data_find_pagination_beyond_the_result_set() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\x90" * 8})
    _, find = get_tool("rex_data_find")
    at_end = find(_call(view), pattern="90", limit=10, offset=8)
    assert at_end == {"total": 8, "truncated": False, "matches": []}
    past_end = find(_call(view), pattern="90", limit=10, offset=10**9)
    assert past_end == {"total": 8, "truncated": False, "matches": []}
    # limit=0: the scan stops at the first match past the empty window, so "total"
    # caps at offset+limit+1 while truncated reports that a further match existed.
    zero = find(_call(view), pattern="90", limit=0)
    assert zero == {"total": 1, "truncated": True, "matches": []}


def test_data_find_caps_limit() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 600)],
        memory={0x1000: b"\x90" * 600},
    )
    _, find = get_tool("rex_data_find")
    # Exactly at the cap the limit is honored; the scan stops one match past the window.
    result = find(_call(view), pattern="90", limit=tools._MAX_LIMIT)
    assert len(result["matches"]) == tools._MAX_LIMIT
    assert result["total"] == tools._MAX_LIMIT + 1
    assert result["truncated"] is True
    # Past the cap the request is rejected, not silently normalized.
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_data_find_skips_unreadable_segments() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x9000, 0x10)])
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="ff")["total"] == 0


def _constant_view() -> FakeBinaryView:
    functions = [
        FakeFunction("main", 0x1100, 0x1200),
        FakeFunction("handler", 0x2000, 0x2100),
        FakeFunction("sink", 0x3000, 0x3100),
    ]
    return FakeBinaryView(
        functions=functions,
        constant_references=[
            (0x31337, 0x1140, functions[0]),
            (0x31337, 0x1150, functions[0]),
            (0x31337, 0x2050, functions[1]),
            (0x1234, 0x3010, functions[2]),
        ],
    )


def test_constant_find_reports_functions_from_the_constant_search() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=0x31337)
    assert result == {
        "truncated": False,
        "functions": [
            {"start": "0x1100", "name": "main", "addresses": ["0x1140", "0x1150"]},
            {"start": "0x2000", "name": "handler", "addresses": ["0x2050"]},
        ],
    }
    assert find(_call(view), value=0x1234)["functions"][0]["addresses"] == ["0x3010"]


def test_constant_find_skips_lines_outside_functions() -> None:
    view = _constant_view()
    view.constant_references.append((7, 0x9000, None))
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=7) == {"truncated": False, "functions": []}


def test_constant_find_caps_matches_per_function() -> None:
    function = FakeFunction("sink", 0x3000, 0x3100)
    view = FakeBinaryView(
        functions=[function],
        constant_references=[(7, 0x3000 + index, function) for index in range(7)],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=7)
    assert result == {
        "truncated": False,
        "functions": [
            {
                "start": "0x3000",
                "name": "sink",
                "addresses": [hex(0x3000 + index) for index in range(6)],
            }
        ],
    }


def test_constant_find_zero_limit_returns_nothing() -> None:
    function = FakeFunction("f", 0x1000, 0x1010)
    view = FakeBinaryView(functions=[function], constant_references=[(1, 0x1008, function)])
    _, find = get_tool("rex_constant_find")
    assert find(_call(view), value=1, limit=0) == {"truncated": True, "functions": []}


def test_constant_find_offset_and_limit() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    limited = find(_call(view), value=0x31337, limit=1)
    assert limited["truncated"] is True
    assert [entry["name"] for entry in limited["functions"]] == ["main"]
    paged = find(_call(view), value=0x31337, limit=1, offset=1)
    assert paged["truncated"] is False
    assert [entry["name"] for entry in paged["functions"]] == ["handler"]
    assert find(_call(view), value=0x31337, function_filter="nomatch")["functions"] == []
    filtered = find(_call(view), value=0x31337, function_filter="^main$")
    assert [entry["name"] for entry in filtered["functions"]] == ["main"]
    assert find(_call(view), value=0x31337, limit=5, offset=5) == {
        "truncated": False,
        "functions": [],
    }


def test_constant_find_stops_the_scan_at_the_limit() -> None:
    functions = [
        FakeFunction(f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10)
        for index in range(5)
    ]
    view = FakeBinaryView(
        functions=functions,
        constant_references=[(1, function.start + 8, function) for function in functions],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=1, limit=2)
    assert result["truncated"] is True
    assert len(result["functions"]) == 2
    # The window holds 2 functions and the next match proves more exist; the scan
    # must have stopped there instead of running to the end of the view.
    assert view.constant_scan_yields == 3
    # The decline must reach the search as an abort, not just stop the local loop.
    assert view.constant_scan_aborted is True


def test_constant_find_rejects_out_of_range_value() -> None:
    view = _constant_view()
    _, find = get_tool("rex_constant_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'value': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=2**64)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'value': Must be at most {tools._MAX_CONSTANT_VALUE}"
    )


def test_constant_find_rejects_out_of_range_limit() -> None:
    view = _view_with_functions()
    _, find = get_tool("rex_constant_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=1, limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), value=1, limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_constant_find_caps_limit_and_truncates_names() -> None:
    functions = [
        FakeFunction(
            "f" * 1000 if index == 0 else f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10
        )
        for index in range(tools._MAX_LIMIT + 100)
    ]
    view = FakeBinaryView(
        functions=functions,
        constant_references=[(1, function.start + 8, function) for function in functions],
    )
    _, find = get_tool("rex_constant_find")
    result = find(_call(view), value=1, limit=tools._MAX_LIMIT)
    assert len(result["functions"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    assert result["functions"][0]["name"].endswith("chars truncated]")


def test_function_define_and_undefine() -> None:
    view = FakeBinaryView()
    _, define = get_tool("rex_function_define")
    assert define(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.created_functions) == 1

    _, undefine = get_tool("rex_function_undefine")
    assert undefine(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.removed_functions) == 1

    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x9999)
    assert exc.value.code == "no_function"


def test_function_define_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    view = FakeBinaryView()
    monkeypatch.setattr(view, "create_user_function", lambda address: None)
    _, define = get_tool("rex_function_define")
    with pytest.raises(FakeToolError) as exc:
        define(_call(view), 0x4000)
    assert exc.value.code == "define_failed"


def test_hlil_grep_matches_lines() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "recv")
    assert result["scanned"] == 1
    assert result["functions"] == [
        {"start": "0x1100", "name": "main", "lines": ["    if (recv(fd, buf, n) <= 0)"]}
    ]
    assert grep(_call(view), "RECV")["functions"] == []


def test_hlil_grep_caps_lines_per_function() -> None:
    lines = "\n".join(f"call rax_{index}" for index in range(4))
    view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText(lines + "\n"))]
    )
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "call rax")
    assert result == {
        "scanned": 1,
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "lines": [f"call rax_{index}" for index in range(3)],
            }
        ],
        "next_offset": None,
    }


def test_hlil_grep_limits_and_errors() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    skipped = grep(_call(view), ".", function_filter="handler|sink")
    assert skipped["scanned"] == 0
    assert skipped["functions"] == []
    assert skipped["truncated"] is False
    limited = grep(_call(view), ".", limit=0)
    assert limited["truncated"] is True
    assert limited["functions"] == []
    zero_scan = grep(_call(view), ".", max_functions=0)
    assert zero_scan == {"scanned": 0, "truncated": True, "functions": [], "next_offset": 0}
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "(")
    assert exc.value.code == "invalid_regex"
    # Out-of-range sizes are rejected with the mcp layer's argument-error convention.
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_HLIL_GREP_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_HLIL_GREP_LIMIT}",
        ),
        ({"max_functions": -1}, "Invalid integer parameter 'max_functions': Must be at least 0"),
        (
            {"max_functions": tools._MAX_HLIL_GREP_FUNCTIONS + 1},
            "Invalid integer parameter 'max_functions': Must be at most "
            f"{tools._MAX_HLIL_GREP_FUNCTIONS}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            grep(_call(view), ".", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_hlil_grep_caps_limit_and_max_functions() -> None:
    matching = [
        FakeFunction(
            "m" * 1000 if index == 0 else f"m{index}",
            0x1000 + index * 0x10,
            0x1010 + index * 0x10,
            hlil=RenderableText("call ax\n"),
        )
        for index in range(tools._MAX_HLIL_GREP_LIMIT + 50)
    ]
    view = FakeBinaryView(functions=matching)
    _, grep = get_tool("rex_hlil_grep")
    # Exactly at both caps the values are honored, not normalized.
    result = grep(
        _call(view),
        ".",
        limit=tools._MAX_HLIL_GREP_LIMIT,
        max_functions=tools._MAX_HLIL_GREP_FUNCTIONS,
    )
    assert len(result["functions"]) == tools._MAX_HLIL_GREP_LIMIT
    assert result["truncated"] is True
    assert result["functions"][0]["name"].endswith("chars truncated]")

    inert = [
        FakeFunction(
            f"n{index}",
            0x5000 + index * 0x10,
            0x5010 + index * 0x10,
            hlil=RenderableText("nop\n"),
        )
        for index in range(tools._MAX_HLIL_GREP_FUNCTIONS + 1)
    ]
    inert_view = FakeBinaryView(functions=inert)
    scanned_result = grep(
        _call(inert_view),
        "zzz",
        limit=tools._MAX_HLIL_GREP_LIMIT,
        max_functions=tools._MAX_HLIL_GREP_FUNCTIONS,
    )
    assert scanned_result["scanned"] == tools._MAX_HLIL_GREP_FUNCTIONS
    assert scanned_result["truncated"] is True


def test_hlil_grep_offset_and_next_offset() -> None:
    functions = [
        FakeFunction(
            f"a{index}",
            0x1000 + index * 0x10,
            0x1010 + index * 0x10,
            hlil=RenderableText("call ax\n"),
        )
        for index in range(4)
    ]
    view = FakeBinaryView(functions=functions)
    _, grep = get_tool("rex_hlil_grep")
    paged = grep(_call(view), "call", limit=2, offset=1)
    assert paged == {
        "scanned": 2,
        "truncated": True,
        "functions": [
            {"start": hex(0x1000 + index * 0x10), "name": f"a{index}", "lines": ["call ax"]}
            for index in (1, 2)
        ],
        "next_offset": 3,
    }
    resumed = grep(_call(view), "call", limit=2, offset=3)
    assert resumed == {
        "scanned": 1,
        "truncated": False,
        "functions": [{"start": "0x1030", "name": "a3", "lines": ["call ax"]}],
        "next_offset": None,
    }
    beyond = grep(_call(view), "call", offset=10)
    assert beyond == {"scanned": 0, "truncated": False, "functions": [], "next_offset": None}
    with pytest.raises(FakeToolError) as exc:
        grep(_call(view), "call", offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


def test_memory_write_validates_and_writes() -> None:
    view = FakeBinaryView()
    _, write = get_tool("rex_memory_write")
    result = write(_call(view), 0x1000, "90 90")
    assert result == {"address": "0x1000", "bytes_written": 2}
    assert view.written == [(0x1000, b"\x90\x90")]
    # Whitespace of any kind separates bytes before validation; whitespace-only input
    # collapses to the empty pattern and is rejected as empty, not passed to fromhex.
    assert write(_call(view), 0x1000, "90\t90\n") == {"address": "0x1000", "bytes_written": 2}
    assert view.written[-1] == (0x1000, b"\x90\x90")
    for bad in ("", " ", "9", "zz", "9z"):
        with pytest.raises(FakeToolError) as exc:
            write(_call(view), 0x1000, bad)
        assert exc.value.code == "invalid_hex"


def test_string_read_at_truncates_and_caps_max_chars() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("a" * 5000, 0x1100, type_name="Utf16String")]
    )
    _, read = get_tool("rex_string_read_at")
    result = read(_call(view), 0x1100)
    assert result["length"] == 5000
    assert result["type"] == "Utf16String"
    assert result["truncated"] is True
    assert len(result["value"]) == 512 + len("... [4488 chars truncated]")
    # Exactly at the cap the value is honored, never raised past _MAX_STRING_READ_CHARS.
    capped = read(_call(view), 0x1100, max_chars=tools._MAX_STRING_READ_CHARS)
    assert capped["truncated"] is True
    assert len(capped["value"]) == tools._MAX_STRING_READ_CHARS + len("... [904 chars truncated]")
    short = FakeBinaryView(strings=[FakeStringReference("hi", 0x1100)])
    assert read(_call(short), 0x1100)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x2000)
    assert exc.value.code == "no_string"


def test_function_containing_caps_entries_and_truncates_names() -> None:
    inner = FakeFunction("inner", 0x1150, 0x1160)
    outer = FakeFunction("outer", 0x1100, 0x1200)
    layers = [
        FakeFunction("layer" + "x" * 600 if index == 0 else f"layer{index}", 0x1000, 0x2000)
        for index in range(tools._MAX_FUNCTION_ENTRIES + 10)
    ]
    view = FakeBinaryView(functions=[inner, outer, *layers])
    _, containing = get_tool("rex_function_containing")
    result = containing(_call(view), 0x1155)
    assert len(result["functions"]) == tools._MAX_FUNCTION_ENTRIES
    assert result["truncated"] is True
    assert result["functions"][2]["name"].endswith("chars truncated]")
    small = FakeBinaryView(functions=[inner, outer])
    assert containing(_call(small), 0x1155)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        containing(_call(small), 0x2000)
    assert exc.value.code == "no_function"


def test_kv_set_get_delete_roundtrip() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    _, kv_delete = get_tool("rex_kv_delete")
    assert kv_set(_call(view), "notes", "C2 at 0x401000") == {
        "key": "notes",
        "length": 14,
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_get(_call(view), "notes") == {
        "key": "notes",
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_delete(_call(view), "notes") == {"key": "notes"}
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "notes")
    assert exc.value.code == "not_found"
    for name in ("rex_kv_set", "rex_kv_get", "rex_kv_delete"):
        _, function = get_tool(name)
        with pytest.raises(FakeToolError) as exc:
            if name == "rex_kv_set":
                function(_call(view), "", "")
            else:
                function(_call(view), "")
        assert exc.value.code == "invalid_key"


def test_kv_set_truncates_echo_and_rejects_oversized_value() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "notes", "a" * (tools._MAX_KV_VALUE_CHARS + 1))
    assert exc.value.code == "value_too_large"
    assert "aaaa" not in exc.value.message
    echoed = kv_set(_call(view), "notes", "a" * 600)
    assert echoed["length"] == 600
    assert echoed["truncated"] is True
    assert len(echoed["value"]) == 512 + len("... [88 chars truncated]")
    # The stored value is untouched; only the response echo is truncated.
    assert kv_get(_call(view), "notes")["value"] == "a" * 600
    # At exactly the echo cap the value comes back whole; one past it is truncated.
    exact = kv_set(_call(view), "exact", "c" * tools._MAX_CHARS)
    assert exact["value"] == "c" * tools._MAX_CHARS
    assert exact["truncated"] is False
    one_past = kv_set(_call(view), "exact", "c" * (tools._MAX_CHARS + 1))
    assert one_past["truncated"] is True
    assert one_past["value"] == "c" * tools._MAX_CHARS + "... [1 chars truncated]"


def test_kv_get_truncates_oversized_stored_value() -> None:
    view = FakeBinaryView()
    view.store_metadata("rex/legacy", "b" * (tools._MAX_KV_VALUE_CHARS + 10))
    _, kv_get = get_tool("rex_kv_get")
    result = kv_get(_call(view), "legacy")
    assert result["truncated"] is True
    assert len(result["value"]) == tools._MAX_KV_VALUE_CHARS + len("... [10 chars truncated]")


def test_kv_error_messages_truncate_key() -> None:
    view = FakeBinaryView()
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * 1000)
    assert exc.value.code == "not_found"
    assert "chars truncated]" in exc.value.message


def test_call_paths_finds_caller_and_callee_paths() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000)
    assert result["reachable"] is True
    assert result["truncated"] is False
    assert result["paths"] == [
        [
            {"start": "0x1100", "name": "main"},
            {"start": "0x2000", "name": "handler"},
            {"start": "0x3000", "name": "sink"},
        ]
    ]
    result = paths(_call(view), 0x3000, 0x1100, direction="callees")
    assert [step["name"] for step in result["paths"][0]] == ["sink", "handler", "main"]


def test_call_paths_depth_shortcut_and_errors() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    assert paths(_call(view), 0x1100, 0x3000, max_depth=1)["reachable"] is False
    assert paths(_call(view), 0x1100, 0x1100) == {
        "reachable": True,
        "paths": [[{"start": "0x1100", "name": "main"}]],
        "truncated": False,
        "explored": 1,
    }
    with pytest.raises(FakeToolError) as exc:
        paths(_call(view), 0x7777, 0x3000)
    assert exc.value.code == "no_function"


def test_call_paths_reports_truncation_and_caps_depth() -> None:
    view = _view_with_functions()
    extra = FakeFunction("extra", 0x5000, 0x5100)
    view.functions[0].callers.append(extra)
    _, paths = get_tool("rex_call_paths")
    # The search stops with one path in hand and "extra" still queued.
    result = paths(_call(view), 0x1100, 0x3000, max_paths=1)
    assert result["reachable"] is True
    assert result["truncated"] is True
    assert len(result["paths"]) == 1

    chain = [
        FakeFunction(f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10)
        for index in range(20)
    ]
    for index in range(19):
        chain[index].callers = [chain[index + 1]]
    chain_view = FakeBinaryView(functions=chain)
    chain_start, chain_end = 0x1000, 0x1000 + 19 * 0x10
    # max_depth exactly at the cap is accepted, and the cap keeps the 20-deep target
    # unreachable; one past the cap is rejected instead of clamped down.
    deep = paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert deep["reachable"] is False
    with pytest.raises(FakeToolError) as exc:
        paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}"
    )


def test_eval_python_executes_code() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('hi')\nresult = len(bv.functions)")
    assert result["stdout"] == "hi\n"
    assert result["stdout_truncated"] is False
    assert result["result"] == "3"
    assert result["result_truncated"] is False
    assert result["error"] is None
    assert result["error_truncated"] is False
    assert evaluate(_call(view), "1 + 1")["result"] is None
    # The exec namespace exposes the view as bv, the call itself, and the bn module alias.
    probe = evaluate(_call(view), "result = (bn is binaryninja) and (call.binary_view is bv)")
    assert probe["result"] == "True"
    assert probe["error"] is None


def test_eval_python_truncates_stdout_and_result() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(
        _call(view),
        f"print('x' * {tools._MAX_EVAL_STDOUT_CHARS + 10})\n"
        f"result = 'y' * {tools._MAX_EVAL_RESULT_CHARS + 10}",
    )
    assert result["stdout_truncated"] is True
    assert result["stdout"].startswith("x" * 10)
    assert len(result["stdout"]) == tools._MAX_EVAL_STDOUT_CHARS + len("... [11 chars truncated]")
    assert result["result_truncated"] is True
    # repr() wraps the string in quotes, so the truncated result starts with one.
    assert result["result"].startswith("'" + "y" * 10)
    assert len(result["result"]) == tools._MAX_EVAL_RESULT_CHARS + len("... [12 chars truncated]")
    assert result["error"] is None


def test_eval_python_survives_result_repr_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    # An object whose repr() raises must land in the structured error path, not escape the
    # handler; the stdout captured before the failure is still returned.
    result = evaluate(
        _call(view),
        "print('before')\n"
        "class Exploding:\n"
        "    def __repr__(self):\n"
        "        raise RuntimeError('no repr')\n"
        "result = Exploding()",
    )
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert "no repr" in result["error"]
    assert result["error_truncated"] is False


def test_eval_python_returns_truncated_error_instead_of_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('before')\nraise ValueError('z' * 1000)")
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert result["error"].startswith("zzz")
    assert result["error_truncated"] is True
    assert len(result["error"]) == 512 + len("... [488 chars truncated]")


def test_tag_set_creates_missing_type() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    result = tag_set(_call(view), 0x4010, "Finding", "C2 config")
    assert result == {
        "address": "0x4010",
        "tag_type": "Finding",
        "data": "C2 config",
        "data_truncated": False,
        "length": 9,
    }
    assert "Finding" in view.tag_types
    tag_set(_call(view), 0x4020, "Finding", "second")
    assert [tag.data for _, tag in view.get_tags()] == ["C2 config", "second"]


def test_tag_set_caps_data_and_truncates_echo() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Finding", "d" * (tools._MAX_TAG_DATA_CHARS + 1))
    assert exc.value.code == "data_too_large"
    assert "dddd" not in exc.value.message
    # A rejected call must have no side effects: no tag type created, no tag added, even
    # though the tag type check would have passed before the data check raised.
    assert view.tag_types == {}
    assert view.get_tags() == []
    # The data cap is checked before the tag type lookup regardless of create_missing.
    with pytest.raises(FakeToolError) as exc:
        tag_set(
            _call(view),
            0x4010,
            "Missing",
            "d" * (tools._MAX_TAG_DATA_CHARS + 1),
            create_missing=False,
        )
    assert exc.value.code == "data_too_large"
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * 1000, "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    assert "chars truncated]" in exc.value.message
    # A name past the creation cap can only be echoed if the tag type already exists.
    view.create_tag_type("F" * 1000, "\u25c6")
    result = tag_set(_call(view), 0x4010, "F" * 1000, "d" * 600)
    assert result["tag_type"].endswith("chars truncated]")
    assert result["data_truncated"] is True
    assert len(result["data"]) == 512 + len("... [88 chars truncated]")
    assert result["length"] == 600
    # The stored tag data is untouched; only the response echo is truncated.
    assert [tag.data for _, tag in view.get_tags()] == ["d" * 600]


def test_tag_set_without_create_and_listing() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Missing", "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    view.add_tag(0x4010, "Finding", "a")
    view.add_tag(0x4020, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=1)
    assert result["total"] == 2
    assert result["truncated"] is True
    assert result["tags"][0]["data"] == "a"
    assert result["tags"][0]["data_truncated"] is False


def test_tag_list_caps_limit_and_truncates_data() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a" * 600)
    for index in range(600):
        view.add_tag(0x2000 + index, "Finding", f"n{index}")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=tools._MAX_LIMIT)
    assert result["total"] == 601
    assert len(result["tags"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    assert result["tags"][0]["data_truncated"] is True
    assert result["tags"][0]["data"].endswith("chars truncated]")
    assert result["tags"][1]["data_truncated"] is False


def test_tag_list_rejects_out_of_range_limit() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a")
    view.add_tag(0x1100, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    # A negative limit is invalid on its face: rejected, never normalized to 0.
    for limit in (-1, -100):
        with pytest.raises(FakeToolError) as exc:
            tag_list(_call(view), limit=limit)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        tag_list(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )
    # limit=0 pages nothing out; unlike the scan tools, "total" stays the true total.
    assert tag_list(_call(view), limit=0) == {"total": 2, "truncated": True, "tags": []}


def test_string_search_rejects_negative_offset() -> None:
    view = FakeBinaryView(
        strings=[FakeStringReference("alpha", 0x100), FakeStringReference("alphabeta", 0x120)]
    )
    _, search = get_tool("rex_string_search")
    with pytest.raises(FakeToolError) as exc:
        search(_call(view), pattern="alpha", limit=1, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"
    # Nothing ran: the rejection happens before the scan.
    assert search(_call(view), pattern="alpha", limit=1, offset=0)["total"] == 2


def test_data_find_rejects_negative_offset() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\xeb\x0e\xeb\x0e\xff\xff\xff\xff"}
    )
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="eb0e", limit=1, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"
    # Nothing ran: the rejection happens before any segment is read.
    assert find(_call(view), pattern="eb0e", limit=1, offset=0)["total"] == 2


def test_data_find_rejects_out_of_range_limit() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 8)], memory={0x1000: b"\x90" * 8})
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern="90", limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )


def test_data_find_rejects_oversized_pattern() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\x90\x90\x90\x90"})
    _, find = get_tool("rex_data_find")
    oversized = "90" * (tools._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), pattern=oversized)
    assert exc.value.code == "pattern_too_large"
    # A pattern of exactly the cap is still accepted (it just cannot match 4 bytes).
    boundary = "90" * (tools._MAX_PATTERN_CHARS // 2)
    assert find(_call(view), pattern=boundary)["total"] == 0


def test_string_read_at_rejects_out_of_range_max_chars() -> None:
    view = FakeBinaryView(strings=[FakeStringReference("hello", 0x1100)])
    _, read = get_tool("rex_string_read_at")
    # max_chars below 1 is invalid on its face: rejected, never clamped to 1.
    for max_chars in (-5, 0):
        with pytest.raises(FakeToolError) as exc:
            read(_call(view), 0x1100, max_chars=max_chars)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'max_chars': Must be at least 1"
    with pytest.raises(FakeToolError) as exc:
        read(_call(view), 0x1100, max_chars=tools._MAX_STRING_READ_CHARS + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_chars': Must be at most {tools._MAX_STRING_READ_CHARS}"
    )
    # Both bounds are inclusive: exactly 1 and exactly the cap are accepted.
    at_minimum = read(_call(view), 0x1100, max_chars=1)
    assert at_minimum["value"] == "h... [4 chars truncated]"
    assert at_minimum["truncated"] is True


def test_call_paths_reports_one_path_per_intermediate_and_sorts_neighbors() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    x1 = FakeFunction("x1", 0x2000, 0x2010)
    x2 = FakeFunction("x2", 0x2100, 0x2110)
    middle = FakeFunction("middle", 0x3000, 0x3010)
    sink = FakeFunction("sink", 0x4000, 0x4010)
    # "middle" is reachable through two parents; enqueueing it once (the visited set) must
    # keep it to one expansion, so exactly one path exists despite the diamond.
    main.callers = [x1, x2]
    x1.callers = [middle]
    x2.callers = [middle]
    middle.callers = [sink]
    view = FakeBinaryView(functions=[main, x1, x2, middle, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x4000)
    assert result == {
        "reachable": True,
        "paths": [
            [
                {"start": "0x1100", "name": "main"},
                {"start": "0x2000", "name": "x1"},
                {"start": "0x3000", "name": "middle"},
                {"start": "0x4000", "name": "sink"},
            ]
        ],
        "truncated": False,
        "explored": 4,
    }
    # Neighbors are ordered by start address, not insertion order, in both directions.
    late = FakeFunction("late", 0x9000, 0x9010)
    early = FakeFunction("early", 0x5000, 0x5010)
    target = FakeFunction("target", 0x7000, 0x7010)
    root = FakeFunction("root", 0x1100, 0x1200)
    root.callers = [late, early]
    late.callers = [target]
    early.callers = [target]
    caller_view = FakeBinaryView(functions=[root, late, early, target])
    caller_result = paths(_call(caller_view), 0x1100, 0x7000, max_paths=5)
    assert [[step["name"] for step in path] for path in caller_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]
    root.callees = [late, early]
    late.callees = [target]
    early.callees = [target]
    callee_result = paths(_call(caller_view), 0x1100, 0x7000, direction="callees", max_paths=5)
    assert [[step["name"] for step in path] for path in callee_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]


def test_call_paths_caps_paths_per_node() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    # Real BinaryView call-graph properties list one entry per call site, so the target can
    # appear several times in one neighbors list.
    handler.callers = [sink, sink, sink]
    view = FakeBinaryView(functions=[main, handler, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, max_paths=2)
    assert len(result["paths"]) == 2
    assert result["truncated"] is True


def test_call_paths_rejects_out_of_range_bounds() -> None:
    # max_paths/max_depth below 1 or above their caps are rejected, not normalized:
    # each bound is invalid on its face and both bounds are inclusive.
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    for kwargs, message in (
        ({"max_paths": 0}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        ({"max_paths": -1}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        (
            {"max_paths": tools._MAX_CALL_PATHS + 1},
            f"Invalid integer parameter 'max_paths': Must be at most {tools._MAX_CALL_PATHS}",
        ),
        ({"max_depth": 0}, "Invalid integer parameter 'max_depth': Must be at least 1"),
        (
            {"max_depth": tools._MAX_CALL_PATH_DEPTH + 1},
            f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            paths(_call(view), 0x1100, 0x1100, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at both caps (and at the minimum of 1) the search still runs.
    at_cap_paths = paths(_call(view), 0x1100, 0x1100, max_paths=tools._MAX_CALL_PATHS)
    assert at_cap_paths["reachable"] is True
    at_cap_depth = paths(_call(view), 0x1100, 0x1100, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert at_cap_depth["reachable"] is True


def test_tag_set_caps_new_tag_type_name() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * (tools._MAX_TAG_TYPE_CHARS + 1), "x")
    assert exc.value.code == "tag_type_too_large"
    assert view.tag_types == {}
    # A long name that already exists is still usable; only creation is capped.
    view.create_tag_type("L" * 100, "\u25c6")
    result = tag_set(_call(view), 0x4010, "L" * 100, "x")
    assert result["tag_type"] == "L" * 100


def test_kv_set_caps_key_length() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "k" * (tools._MAX_KV_KEY_CHARS + 1), "value")
    assert exc.value.code == "key_too_large"
    # Nothing was stored under the rejected key.
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * (tools._MAX_KV_KEY_CHARS + 1))
    assert exc.value.code == "not_found"
    # A key of exactly the cap is still accepted.
    boundary_key = "k" * tools._MAX_KV_KEY_CHARS
    assert kv_set(_call(view), boundary_key, "value")["key"] == boundary_key
    assert view.query_metadata("rex/" + boundary_key) == "value"


def test_search_tools_report_empty_results_on_an_empty_view() -> None:
    view = FakeBinaryView()
    _, search = get_tool("rex_string_search")
    assert search(_call(view), pattern="x") == {"total": 0, "truncated": False, "strings": []}
    _, find = get_tool("rex_data_find")
    assert find(_call(view), pattern="90") == {"total": 0, "truncated": False, "matches": []}
    _, constant_find = get_tool("rex_constant_find")
    assert constant_find(_call(view), value=1) == {"truncated": False, "functions": []}
    _, tag_list = get_tool("rex_tag_list")
    assert tag_list(_call(view)) == {"total": 0, "truncated": False, "tags": []}
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1000)
    assert exc.value.code == "no_function"
