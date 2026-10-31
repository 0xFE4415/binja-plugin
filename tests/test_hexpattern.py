from __future__ import annotations

import pytest

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern, parse_hex_pattern


@pytest.mark.parametrize("pattern", ["", "   ", "4", "48 8", "zz", "48 8z"])
def test_parse_rejects_invalid_patterns(pattern: str) -> None:
    with pytest.raises(HexPatternError):
        parse_hex_pattern(pattern)


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("488b", [0x48, 0x8B]),
        ("48 8b", [0x48, 0x8B]),
        ("48 8B", [0x48, 0x8B]),
        ("??", [None]),
        ("a5 ?? 05", [0xA5, None, 0x05]),
    ],
)
def test_parse_accepts_valid_patterns(pattern: str, expected: list[int | None]) -> None:
    assert parse_hex_pattern(pattern) == expected


def test_compile_matches_literal_and_wildcards() -> None:
    matcher, length = compile_hex_pattern("48 ?? 05")
    assert length == 3
    blob = b"H\x00\x05H\x99\x05"
    assert [match.start() for match in matcher.finditer(blob)] == [0, 3]


def test_compile_reports_overlapping_matches() -> None:
    matcher, length = compile_hex_pattern("90 90")
    assert length == 2
    assert [match.start() for match in matcher.finditer(b"\x90\x90\x90")] == [0, 1]
