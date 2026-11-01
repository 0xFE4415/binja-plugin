from __future__ import annotations

from pathlib import Path

import pytest
from helpers import (
    FakeBinaryView,
    FakeFunction,
    FakeSegment,
    FakeStringReference,
    FakeSymbol,
    FakeToolCall,
    FakeToolError,
    RenderableText,
    get_tool,
)

from binja_plugin import tools


def _call(view: FakeBinaryView) -> FakeToolCall:
    return FakeToolCall(view)


def _view_with_functions() -> FakeBinaryView:
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("void main() {\n    if (recv(fd, buf, n) <= 0)\n        return 1;\n}"),
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


class FakeDisassemblyLine:
    """Mirrors the DisassemblyTextLine fields rex_disasm_at reads."""

    def __init__(self, address: int | None, text: str) -> None:
        self.address = address
        self.tokens = [text]


class FakeBasicBlock:
    def __init__(self, lines: list[tuple[int | None, str]]) -> None:
        self._lines = lines

    def get_disassembly_text(self) -> list[FakeDisassemblyLine]:
        return [FakeDisassemblyLine(address, text) for address, text in self._lines]


class FakeDisasmFunction(FakeFunction):
    """FakeFunction with the basic_blocks attribute rex_disasm_at reads."""

    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        blocks: list[FakeBasicBlock],
        hlil: object = None,
    ) -> None:
        super().__init__(name, start, end, hlil=hlil)
        self.basic_blocks = blocks


def _disasm_view() -> FakeBinaryView:
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[
            FakeBasicBlock(
                [
                    (0x1100, "push rbp"),
                    (0x1101, "mov rbp, rsp"),
                    (0x1104, "sub rsp, 0x20"),
                    (0x1108, "mov eax, 1"),
                    (0x110D, "leave"),
                    (0x110E, "ret"),
                ]
            )
        ],
    )
    handler = FakeDisasmFunction(
        "handler", 0x2000, 0x2100, blocks=[FakeBasicBlock([(0x2000, "push rbp"), (0x2001, "ret")])]
    )
    return FakeBinaryView(functions=[main, handler])


def test_disasm_at_returns_function_and_window() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1104)
    assert result == {
        "function": {"start": "0x1100", "name": "main"},
        "instructions": [
            {"address": "0x1100", "text": "push rbp"},
            {"address": "0x1101", "text": "mov rbp, rsp"},
            {"address": "0x1104", "text": "sub rsp, 0x20"},
            {"address": "0x1108", "text": "mov eax, 1"},
            {"address": "0x110d", "text": "leave"},
            {"address": "0x110e", "text": "ret"},
        ],
        "truncated": False,
    }


def test_disasm_at_truncates_at_function_edges() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # "before" reaching past the first line just starts the window at the function start,
    # and the truncation flag says the head was clipped, not that anything failed.
    head = disasm(_call(view), 0x1101, before=4, after=1)
    assert [entry["address"] for entry in head["instructions"]] == ["0x1100", "0x1101", "0x1104"]
    assert head["truncated"] is True
    tail = disasm(_call(view), 0x110D, before=1, after=8)
    assert [entry["address"] for entry in tail["instructions"]] == ["0x1108", "0x110d", "0x110e"]
    assert tail["truncated"] is True


def test_disasm_at_anchors_inside_the_containing_instruction() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # 0x1105 falls inside "sub rsp, 0x20" (0x1104): the anchor moves down to its start.
    inside = disasm(_call(view), 0x1105, before=0, after=0)
    assert inside["instructions"] == [{"address": "0x1104", "text": "sub rsp, 0x20"}]
    assert inside["truncated"] is True
    # An address in the function's range but past the last rendered line anchors at the
    # last line instead of failing.
    past = disasm(_call(view), 0x1150, before=1, after=0)
    assert [entry["address"] for entry in past["instructions"]] == ["0x110d", "0x110e"]


def test_disasm_at_anchors_past_label_lines() -> None:
    # A label line shares the anchor's address with the instruction it names; the
    # instruction wins the anchor, and the label only shows up inside the window.
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[FakeBasicBlock([(0x1100, "loc_1100:"), (0x1100, "push rbp"), (0x1101, "ret")])],
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=1)
    assert result["instructions"] == [
        {"address": "0x1100", "text": "push rbp"},
        {"address": "0x1101", "text": "ret"},
    ]
    assert result["truncated"] is True


def test_disasm_at_skips_unaddressed_lines() -> None:
    # Renderings can emit unaddressed continuation lines (a None address): they can
    # neither anchor nor be reported, so only addressed lines reach the window.
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[FakeBasicBlock([(0x1100, "push rbp"), (None, "..."), (0x1101, "ret")])],
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=1)
    assert result["instructions"] == [
        {"address": "0x1100", "text": "push rbp"},
        {"address": "0x1101", "text": "ret"},
    ]
    assert result["truncated"] is False


def test_disasm_at_rejects_addresses_outside_functions() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # The gap between the two functions, an address before the first one, and one past
    # the last are all rejected outright, never snapped to a neighboring function.
    for address in (0x1800, 0x150, 0x9000):
        with pytest.raises(FakeToolError) as exc:
            disasm(_call(view), address)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"no analyzed function contains {address:#x}"


def test_disasm_at_rejects_out_of_range_window() -> None:
    view = _disasm_view()
    _, disasm = get_tool("rex_disasm_at")
    # Zero and the cap are inclusive; one past the cap is rejected, not clamped down.
    capped = disasm(_call(view), 0x1104, before=0, after=tools._MAX_DISASM_CONTEXT)
    assert [entry["address"] for entry in capped["instructions"]] == [
        "0x1104",
        "0x1108",
        "0x110d",
        "0x110e",
    ]
    assert capped["truncated"] is True
    for kwargs, message in (
        ({"before": -1}, "Invalid integer parameter 'before': Must be at least 0"),
        ({"after": -1}, "Invalid integer parameter 'after': Must be at least 0"),
        (
            {"before": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'before': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        (
            {"after": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'after': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            disasm(_call(view), 0x1104, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Window sizes are validated before the address is even looked up: on a view with no
    # functions the range error wins over the no-function error.
    with pytest.raises(FakeToolError) as exc:
        disasm(_call(FakeBinaryView()), 0x1104, before=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'before': Must be at least 0"


def test_disasm_at_truncates_names_and_text() -> None:
    main = FakeDisasmFunction(
        "m" * 600, 0x1100, 0x1200, blocks=[FakeBasicBlock([(0x1100, "x" * 600)])]
    )
    view = FakeBinaryView(functions=[main])
    _, disasm = get_tool("rex_disasm_at")
    result = disasm(_call(view), 0x1100, before=0, after=0)
    assert result["function"]["name"].endswith("chars truncated]")
    assert result["instructions"][0]["text"].endswith("chars truncated]")


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
    # The docstring promises a case-insensitive name match; pin it with a
    # case-mismatched positive, not just a same-case one.
    caseless = find(_call(view), value=0x31337, function_filter="^HANDLER$")
    assert [entry["name"] for entry in caseless["functions"]] == ["handler"]
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


def test_hlil_grep_context_wraps_matches() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    # Context lines are prefixed with two spaces and the matched line with "> ", so the
    # match stays delimited inside its window.
    result = grep(_call(view), "recv", context_before=1, context_after=1)
    assert result["functions"] == [
        {
            "start": "0x1100",
            "name": "main",
            "lines": [
                "  void main() {",
                ">     if (recv(fd, buf, n) <= 0)",
                "          return 1;",
            ],
        }
    ]
    # Function edges truncate: the first HLIL line has no predecessor, so a larger
    # before-context returns fewer lines rather than padding.
    clipped = grep(_call(view), "recv", context_before=8, context_after=8)
    assert clipped["functions"][0]["lines"] == [
        "  void main() {",
        ">     if (recv(fd, buf, n) <= 0)",
        "          return 1;",
        "  }",
    ]
    # Explicit zero on both sides must stay byte-identical to the undecorated form.
    assert grep(_call(view), "recv", context_before=0, context_after=0) == grep(_call(view), "recv")


def test_hlil_grep_context_separates_and_caps_matches() -> None:
    lines = "\n".join(f"call rax_{index}" for index in range(4))
    view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText(lines + "\n"))]
    )
    _, grep = get_tool("rex_hlil_grep")
    result = grep(_call(view), "call rax", context_before=1)
    # Three matches is still the per-function cap; each match keeps its own window, and
    # "--" separates consecutive groups even where their context ranges overlap.
    assert result["functions"][0]["lines"] == [
        "> call rax_0",
        "--",
        "  call rax_0",
        "> call rax_1",
        "--",
        "  call rax_1",
        "> call rax_2",
    ]


def test_hlil_grep_context_truncates_long_lines() -> None:
    hlil = RenderableText("before\n" + "a" * 600 + "\nrecv()\nafter")
    view = FakeBinaryView(functions=[FakeFunction("f", 0x1000, 0x1010, hlil=hlil)])
    _, grep = get_tool("rex_hlil_grep")
    # Context lines go through the same per-line echo cap as matched lines.
    result = grep(_call(view), "recv", context_before=2)
    assert result["functions"][0]["lines"] == [
        "  before",
        "  " + "a" * tools._MAX_CHARS + "... [88 chars truncated]",
        "> recv()",
    ]


def test_hlil_grep_rejects_out_of_range_context() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    for kwargs, message in (
        ({"context_before": -1}, "Invalid integer parameter 'context_before': Must be at least 0"),
        ({"context_after": -1}, "Invalid integer parameter 'context_after': Must be at least 0"),
        (
            {"context_before": tools._MAX_HLIL_GREP_CONTEXT + 1},
            "Invalid integer parameter 'context_before': Must be at most "
            f"{tools._MAX_HLIL_GREP_CONTEXT}",
        ),
        (
            {"context_after": tools._MAX_HLIL_GREP_CONTEXT + 1},
            "Invalid integer parameter 'context_after': Must be at most "
            f"{tools._MAX_HLIL_GREP_CONTEXT}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            grep(_call(view), "recv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_hlil_grep_limits_and_errors() -> None:
    view = _view_with_functions()
    _, grep = get_tool("rex_hlil_grep")
    skipped = grep(_call(view), ".", function_filter="handler|sink")
    assert skipped["scanned"] == 0
    assert skipped["functions"] == []
    assert skipped["truncated"] is False
    # The docstring promises a case-insensitive name match; pin it with a
    # case-mismatched positive (uppercase filter, lowercase function name).
    caseless = grep(_call(view), "recv", function_filter="MAIN")
    assert [entry["name"] for entry in caseless["functions"]] == ["main"]
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


class FakeParsingToolCall(FakeToolCall):
    """FakeToolCall with the parse_address surface rex_decompile_many reads.

    Deliberately raises a plain ValueError for unparsable input instead of a ToolError:
    the handler owns the conversion of expression-parse failures to invalid_params, so
    the fake must not hand it an error to pass through.
    """

    def parse_address(self, value: object, here: int = 0) -> int:
        text = value if isinstance(value, str) else str(value)
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            raise ValueError(f"unparsable address expression '{text}'") from None


def _decompile_view() -> FakeBinaryView:
    main = FakeFunction(
        "main", 0x1100, 0x1200, hlil=RenderableText("void main() {\n    return 0;\n}")
    )
    handler = FakeFunction(
        "handler",
        0x2000,
        0x2100,
        hlil=RenderableText("void handler() {\n    recv(fd, buf, n);\n    return 1;\n}"),
    )
    # "sink" models a function that was never lifted: it contains addresses but has no HLIL.
    sink = FakeFunction("sink", 0x3000, 0x3100)
    return FakeBinaryView(functions=[main, handler, sink])


def test_decompile_many_renders_each_requested_function() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    result = decompile(FakeParsingToolCall(view), ["0x1100", "0x2000"], max_lines=400)
    assert result == {
        "functions": [
            {
                "start": "0x1100",
                "name": "main",
                "lines": ["void main() {", "    return 0;", "}"],
                "truncated": False,
            },
            {
                "start": "0x2000",
                "name": "handler",
                "lines": ["void handler() {", "    recv(fd, buf, n);", "    return 1;", "}"],
                "truncated": False,
            },
        ]
    }
    # Output order follows the request, not address order.
    flipped = decompile(FakeParsingToolCall(view), ["0x2000", "0x1100"])
    assert [entry["name"] for entry in flipped["functions"]] == ["handler", "main"]


def test_decompile_many_truncates_lines_and_echoes() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    clipped = decompile(FakeParsingToolCall(view), ["0x2000"], max_lines=2)
    assert clipped == {
        "functions": [
            {
                "start": "0x2000",
                "name": "handler",
                "lines": ["void handler() {", "    recv(fd, buf, n);"],
                "truncated": True,
            }
        ]
    }
    # Exactly at max_lines nothing is reported as truncated.
    exact = decompile(FakeParsingToolCall(view), ["0x2000"], max_lines=4)
    assert exact["functions"][0]["truncated"] is False
    # Rendered lines go through the same per-line echo cap as the other tools.
    long_view = FakeBinaryView(
        functions=[FakeFunction("f", 0x1000, 0x1010, hlil=RenderableText("a" * 600))]
    )
    echoed = decompile(FakeParsingToolCall(long_view), ["0x1000"])
    assert echoed["functions"][0]["lines"] == ["a" * tools._MAX_CHARS + "... [88 chars truncated]"]


def test_decompile_many_renders_unlifted_functions_as_empty() -> None:
    # A function can contain addresses without having lifted HLIL; that is an empty
    # render, not an error and not a truncation.
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    assert decompile(FakeParsingToolCall(view), ["0x3000"]) == {
        "functions": [{"start": "0x3000", "name": "sink", "lines": [], "truncated": False}]
    }


def test_decompile_many_rejects_the_whole_call_on_any_bad_entry() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    # An unanalyzed address anywhere in the batch rejects the call: no partial results,
    # no snapping to a neighboring function.
    for batch in (["0x1100", "0x1800"], ["0x1800", "0x1100"]):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "no analyzed function contains 0x1800"
    # An unparsable expression rejects the call the same way.
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), ["0x1100", "garbage"])
    assert exc.value.code == "invalid_params"
    assert "bad address expression" in exc.value.message


def test_decompile_many_rejects_bad_batch_and_max_lines() -> None:
    view = _decompile_view()
    _, decompile = get_tool("rex_decompile_many")
    for batch in ([], ["0x1100"] * (tools._MAX_DECOMPILE_BATCH + 1)):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == (
            f"functions must contain between 1 and {tools._MAX_DECOMPILE_BATCH} address expressions"
        )
    # Exactly the batch cap is accepted.
    at_cap = decompile(FakeParsingToolCall(view), ["0x1100"] * tools._MAX_DECOMPILE_BATCH)
    assert len(at_cap["functions"]) == tools._MAX_DECOMPILE_BATCH
    # The argument must be a list of strings, not a bare value or non-string entries.
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), "0x1100")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "functions must be a list of address expressions"
    with pytest.raises(FakeToolError) as exc:
        decompile(FakeParsingToolCall(view), [0x1100])
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "functions[0] must be a string address expression"
    # Range errors win over address resolution, and both bounds are inclusive.
    for kwargs, message in (
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": tools._MAX_DECOMPILE_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most {tools._MAX_DECOMPILE_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            decompile(FakeParsingToolCall(view), ["garbage"], **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def _find_functions_view() -> FakeBinaryView:
    return FakeBinaryView(
        segments=[
            FakeSegment(0x1000, 0x10),
            FakeSegment(0x2000, 0x10),
            FakeSegment(0x9000, 0x10),
        ],
        memory={
            0x1000: b"\xeb\x0e\x90\x90" * 4,
            0x2000: b"\xeb\x0e" + b"\x90" * 14,
            # This match belongs to no analyzed function and must be skipped.
            0x9000: b"\xeb\x0e" + b"\x90" * 14,
        },
        functions=[FakeFunction("main", 0x1000, 0x1100), FakeFunction("handler", 0x2000, 0x2100)],
    )


def test_find_functions_by_pattern_reports_containing_functions() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    result = find(_call(view), "eb 0e")
    # Functions come back in first-match order; the 0x9000 match is inside no function
    # and shows up in no entry.
    assert result == {
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "main",
                "match_count": 4,
                "addresses": ["0x1000", "0x1004", "0x1008", "0x100c"],
            },
            {"start": "0x2000", "name": "handler", "match_count": 1, "addresses": ["0x2000"]},
        ],
    }


def test_find_functions_by_pattern_caps_examples_at_five() -> None:
    view = FakeBinaryView(
        segments=[FakeSegment(0x1000, 0x10)],
        memory={0x1000: b"\xeb\x0e" * 8},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    result = find(_call(view), "eb0e")
    # The count stays true while the example list is capped at the first 5 addresses.
    assert result == {
        "truncated": False,
        "functions": [
            {
                "start": "0x1000",
                "name": "f",
                "match_count": 8,
                "addresses": [hex(0x1000 + 2 * index) for index in range(5)],
            }
        ],
    }


def test_find_functions_by_pattern_limits_offsets_and_truncates() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    limited = find(_call(view), "eb0e", limit=1)
    assert limited["truncated"] is True
    assert [entry["name"] for entry in limited["functions"]] == ["main"]
    paged = find(_call(view), "eb0e", limit=1, offset=1)
    assert paged["truncated"] is False
    assert [entry["name"] for entry in paged["functions"]] == ["handler"]
    assert paged["functions"][0]["match_count"] == 1
    # limit=0 pages nothing out; the scan stops at the first matching function past the
    # empty window, so truncated says a further one existed.
    assert find(_call(view), "eb0e", limit=0) == {"truncated": True, "functions": []}
    assert find(_call(view), "eb0e", offset=5) == {"truncated": False, "functions": []}
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_LIMIT + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            find(_call(view), "eb0e", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message


def test_find_functions_by_pattern_maps_matches_across_chunk_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "_READ_CHUNK", 4)
    _, find = get_tool("rex_find_functions_by_pattern")
    # A match straddling the chunk edge is only visible because each read extends
    # pattern_length - 1 bytes past the chunk; it must land in the containing function.
    straddle = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x33\xeb\x00\x00\x00"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(straddle), "33 eb") == {
        "truncated": False,
        "functions": [{"start": "0x1000", "name": "f", "match_count": 1, "addresses": ["0x1003"]}],
    }
    # A match starting exactly at the chunk edge is reported once: the reads overlap,
    # but every match start belongs to exactly one read.
    boundary = FakeBinaryView(
        segments=[FakeSegment(0x1000, 8)],
        memory={0x1000: b"\x00\x00\x00\x00\x33\xeb\x00\x00"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(boundary), "33 eb") == {
        "truncated": False,
        "functions": [{"start": "0x1000", "name": "f", "match_count": 1, "addresses": ["0x1004"]}],
    }


def test_find_functions_by_pattern_rejects_invalid_patterns() -> None:
    view = _find_functions_view()
    _, find = get_tool("rex_find_functions_by_pattern")
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), "zz")
    assert exc.value.code == "invalid_pattern"
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), "")
    assert exc.value.code == "invalid_pattern"
    oversized = "90" * (tools._MAX_PATTERN_CHARS // 2 + 1)
    with pytest.raises(FakeToolError) as exc:
        find(_call(view), oversized)
    assert exc.value.code == "pattern_too_large"


def test_find_functions_by_pattern_reports_empty_results_on_empty_views() -> None:
    _, find = get_tool("rex_find_functions_by_pattern")
    # No segments at all: an empty result is valid, not an error.
    assert find(_call(FakeBinaryView()), "eb0e") == {"truncated": False, "functions": []}
    # Pattern bytes exist but no analyzed function covers them: matches are skipped.
    uncovered = FakeBinaryView(
        segments=[FakeSegment(0x1000, 4)], memory={0x1000: b"\xeb\x0e\x90\x90"}
    )
    assert find(_call(uncovered), "eb0e") == {"truncated": False, "functions": []}
    # An unreadable segment contributes nothing.
    unreadable = FakeBinaryView(
        segments=[FakeSegment(0x9000, 4)],
        memory={0x1000: b"\xeb\x0e"},
        functions=[FakeFunction("f", 0x1000, 0x1100)],
    )
    assert find(_call(unreadable), "eb0e") == {"truncated": False, "functions": []}


# --- rex_export_disasm / rex_export_symbols -------------------------------------------------


def _use_export_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the export tools at a per-test root so nothing lands in the real home."""
    root = tmp_path / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    return root


def test_export_disasm_writes_the_window_to_a_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="main.txt")
    expected = "push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov eax, 1\nleave\nret\n"
    assert result == {
        "path": str((root / "main.txt").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "lines": 6,
        "truncated": False,
    }
    # Byte-exact read: read_bytes also proves the LF endings (no \r\n translation).
    assert (root / "main.txt").read_bytes() == expected.encode("utf-8")


def test_export_disasm_caps_the_window_at_max_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Window of 3 lines (anchor 0x1101, before=2, after=1) clipped to 2 by max_lines.
    clipped = export(_call(view), 0x1101, before=2, after=1, max_lines=2, filename="clip.txt")
    assert clipped["lines"] == 2
    assert clipped["truncated"] is True
    assert (root / "clip.txt").read_bytes() == b"push rbp\nmov rbp, rsp\n"
    # Exactly at max_lines nothing is reported as truncated.
    exact = export(_call(view), 0x1104, max_lines=6, filename="full.txt")
    assert exact["lines"] == 6
    assert exact["truncated"] is False
    # A window clipped at a function edge also leaves rendered lines out of the file,
    # so the truncation flag fires even though no cap was hit.
    edge = export(_call(view), 0x110E, before=1, after=8, filename="edge.txt")
    assert edge["lines"] == 2
    assert edge["truncated"] is True


def test_export_disasm_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # 36 bytes hold exactly the first three lines; the fourth ("mov eax, 1\n") would
    # push the file to 47 bytes, so it and everything after it are dropped.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 36)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="shrink.txt")
    expected = b"push rbp\nmov rbp, rsp\nsub rsp, 0x20\n"
    assert result["lines"] == 3
    assert result["truncated"] is True
    assert result["bytes_written"] == len(expected)
    assert (root / "shrink.txt").read_bytes() == expected


def test_export_disasm_rejects_a_single_line_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # Even the first line ("push rbp\n" is 9 bytes) cannot fit under an 8-byte cap, so
    # shrinking from the end could never produce a file: reject instead of writing one.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 8)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="tiny.txt")
    assert exc.value.code == "export_failed"
    assert "first entry" in exc.value.message
    # The rejection happens before any filesystem work: not even the root was created.
    assert not root.exists()


def test_export_disasm_rejects_out_of_function_addresses_and_ranges() -> None:
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Same rejection as rex_disasm_at: never snapped to a neighboring function.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1800, filename="gap.txt")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x1800"
    for kwargs, message in (
        ({"before": -1}, "Invalid integer parameter 'before': Must be at least 0"),
        ({"after": -1}, "Invalid integer parameter 'after': Must be at least 0"),
        (
            {"before": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'before': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        (
            {"after": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'after': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": tools._MAX_EXPORT_DISASM_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most "
            f"{tools._MAX_EXPORT_DISASM_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1104, filename="x.txt", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Both bounds are inclusive on every size parameter.
    at_caps = export(
        _call(view),
        0x1104,
        before=tools._MAX_DISASM_CONTEXT,
        after=tools._MAX_DISASM_CONTEXT,
        max_lines=tools._MAX_EXPORT_DISASM_LINES,
        filename="caps.txt",
    )
    assert at_caps["lines"] == 6
    # Range errors are checked before the address lookup, like rex_disasm_at.
    with pytest.raises(FakeToolError) as exc:
        export(_call(FakeBinaryView()), 0x1104, before=-1, filename="x.txt")
    assert exc.value.message == "Invalid integer parameter 'before': Must be at least 0"


def test_export_disasm_reports_export_failed_when_the_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "exports"
    root.mkdir()
    # A directory sitting where the file would go makes open() raise IsADirectoryError;
    # the handler must turn that into export_failed, not leak the OSError.
    (root / "occupied.txt").mkdir()
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="occupied.txt")
    assert exc.value.code == "export_failed"


def test_export_symbols_reports_export_failed_when_the_root_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A regular file where the export root would go makes mkdir() raise
    # NotADirectoryError; the handler must turn that into export_failed, not leak it.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(tools, "_EXPORT_ROOT", blocker / "exports")
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    assert exc.value.code == "export_failed"
    assert "could not prepare export path" in exc.value.message


def test_export_disasm_fails_nested_filenames_at_the_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Lexical validation allows a nested relative name, but only the fixed root itself is
    # ever created on demand, so the write fails into export_failed instead of silently
    # growing a tree under the root.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="sub/out.txt")
    assert exc.value.code == "export_failed"
    assert not (root / "sub").exists()


def test_export_disasm_accepts_a_component_at_the_name_max_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    filename = "y" * 251 + ".txt"  # exactly 255 bytes, the NAME_MAX bound
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename=filename)
    assert result["path"] == str((root / filename).resolve())
    assert (root / filename).exists()


@pytest.mark.parametrize(
    "filename",
    [
        "/abs/path.txt",
        "up/../down.txt",
        "back\\slash.txt",
        "nul\x00byte.txt",
        "x" * 256,
        "",
    ],
)
def test_export_tools_reject_unsafe_filenames(
    filename: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    _, export_disasm = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export_disasm(_call(_disasm_view()), 0x1104, filename=filename)
    assert exc.value.code == "invalid_params"
    _, export_symbols = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export_symbols(_call(_symbol_view()), 0x1000, 0x4000, filename=filename)
    assert exc.value.code == "invalid_params"


def test_validate_export_path_rejects_each_violation_with_a_clear_message() -> None:
    cases = [
        ("", "filename must not be empty"),
        ("/etc/passwd", "filename must be a plain file name, not an absolute path"),
        ("back\\slash.txt", "filename must not contain backslashes"),
        ("nul\x00byte.txt", "filename must not contain NUL bytes"),
        ("up/../down.txt", "filename must not contain '..' path components"),
        ("x" * 256, f"filename component exceeds {tools._MAX_EXPORT_COMPONENT_BYTES} bytes"),
    ]
    for filename, message in cases:
        with pytest.raises(FakeToolError) as exc:
            tools._validate_export_path(filename)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Plain names and a component exactly at the NAME_MAX bound pass the pure validator.
    tools._validate_export_path("plain.txt")
    tools._validate_export_path("y" * 251 + ".txt")
    tools._validate_export_path("sub/plain.txt")


def _symbol_view() -> FakeBinaryView:
    # Deliberately unsorted, with symbols below and above the queried range and a name
    # containing a comma to pin the CSV quoting.
    return FakeBinaryView(
        symbols=[
            FakeSymbol(0x3000, "FunctionSymbol", "late"),
            FakeSymbol(0x5000, "DataSymbol", "outside"),
            FakeSymbol(0x1000, "FunctionSymbol", "main"),
            FakeSymbol(0x0500, "DataSymbol", "early"),
            FakeSymbol(0x2000, "DataSymbol", "msg, with comma"),
        ]
    )


def test_export_symbols_writes_a_sorted_csv_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    expected = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
        "0x3000,FunctionSymbol,late\n"
    )
    assert result == {
        "path": str((root / "syms.csv").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "rows": 3,
        "truncated": False,
        "total": 3,
    }
    assert (root / "syms.csv").read_bytes() == expected.encode("utf-8")


def test_export_symbols_offset_limit_and_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    view = _symbol_view()
    header = b"symbol_address,symbol_type,name\n"
    # The window is a slice of the address-sorted list, and pagination past the end
    # reports the true total with an empty window.
    limited = export(_call(view), 0x1000, 0x4000, limit=2, filename="page1.csv")
    assert limited["rows"] == 2
    assert limited["total"] == 3
    assert limited["truncated"] is True
    paged = export(_call(view), 0x1000, 0x4000, limit=2, offset=1, filename="page2.csv")
    assert paged["rows"] == 2
    assert paged["truncated"] is False
    assert (root / "page2.csv").read_bytes() == (
        header + b'0x2000,DataSymbol,"msg, with comma"\n' + b"0x3000,FunctionSymbol,late\n"
    )
    at_end = export(_call(view), 0x1000, 0x4000, offset=3, filename="tail.csv")
    assert at_end["rows"] == 0
    assert at_end["total"] == 3
    assert at_end["truncated"] is False
    assert (root / "tail.csv").read_bytes() == header
    # limit=0 pages nothing out but still reports that more symbols existed.
    zero = export(_call(view), 0x1000, 0x4000, limit=0, filename="empty.csv")
    assert zero["rows"] == 0
    assert zero["total"] == 3
    assert zero["truncated"] is True


def test_export_symbols_writes_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, format="json", filename="syms.json")
    expected = """[
  {
    "symbol_address": "0x1000",
    "symbol_type": "FunctionSymbol",
    "name": "main"
  },
  {
    "symbol_address": "0x2000",
    "symbol_type": "DataSymbol",
    "name": "msg, with comma"
  },
  {
    "symbol_address": "0x3000",
    "symbol_type": "FunctionSymbol",
    "name": "late"
  }
]"""
    assert result["bytes_written"] == len(expected.encode("utf-8"))
    assert result["rows"] == 3
    assert result["total"] == 3
    assert result["truncated"] is False
    # Byte-exact: indented JSON, closing bracket included, no trailing newline.
    assert (root / "syms.json").read_bytes() == expected.encode("utf-8")


def test_export_symbols_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    two_rows = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
    )
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", len(two_rows.encode("utf-8")))
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="capped.csv")
    # No pagination happened (the window held all three symbols), so the truncated flag
    # must come from the size drop alone.
    assert result["rows"] == 2
    assert result["total"] == 3
    assert result["truncated"] is True
    assert (root / "capped.csv").read_bytes() == two_rows.encode("utf-8")


def test_export_symbols_rejects_a_single_row_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # The 32-byte header plus the first row can never fit under a 16-byte cap.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 16)
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="tiny.csv")
    assert exc.value.code == "export_failed"
    assert "first entry" in exc.value.message
    assert not root.exists()


def test_export_symbols_writes_a_header_only_file_for_an_empty_range(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x8000, 0x9000, filename="none.csv")
    assert result == {
        "path": str((root / "none.csv").resolve()),
        "bytes_written": 32,
        "rows": 0,
        "truncated": False,
        "total": 0,
    }
    assert (root / "none.csv").read_bytes() == b"symbol_address,symbol_type,name\n"


def test_export_symbols_rejects_invalid_ranges_limits_and_format() -> None:
    view = _symbol_view()
    _, export = get_tool("rex_export_symbols")
    for kwargs, message in (
        ({"start": 0x1000, "end": 0x1000}, "end must be greater than start"),
        ({"start": 0x4000, "end": 0x1000}, "end must be greater than start"),
        ({"start": -1, "end": 0x4000}, "Invalid integer parameter 'start': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_EXPORT_SYMBOLS + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_EXPORT_SYMBOLS}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
        ({"format": "xml"}, "format must be 'csv' or 'json', not 'xml'"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1000, 0x4000, filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at the limit cap the export still runs.
    at_cap = export(
        _call(view), 0x1000, 0x4000, limit=tools._MAX_EXPORT_SYMBOLS, filename="cap.csv"
    )
    assert at_cap["rows"] == 3
