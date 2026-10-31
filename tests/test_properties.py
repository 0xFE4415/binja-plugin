from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from binja_plugin.hexpattern import compile_hex_pattern

_TOKENS = ["00", "7f", "80", "ff", "a5", "??"]


@given(st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=16))
def test_compiled_pattern_matches_its_own_bytes(tokens: list[str]) -> None:
    matcher, length = compile_hex_pattern(" ".join(tokens))
    blob = bytes(0x00 if token == "??" else int(token, 16) for token in tokens)
    assert [match.start() for match in matcher.finditer(blob)] == [0]
    assert length == len(tokens)


@given(
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=8),
    blob=st.binary(max_size=64),
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
