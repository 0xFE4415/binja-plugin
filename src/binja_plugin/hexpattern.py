"""Compile hex byte patterns with wildcards into binary regular expressions."""

from __future__ import annotations

import re


class HexPatternError(ValueError):
    """Raised when a hex pattern cannot be parsed."""


def parse_hex_pattern(pattern: str) -> list[int | None]:
    """Parse a hex byte pattern into byte values, using None for wildcards.

    Accepts optional whitespace between byte tokens and "AS ?? 05" style wildcards.

    :param pattern: Hex pattern string, e.g. "48 8b ?? 05".
    :returns: One entry per byte; None marks a wildcard byte.
    :raises HexPatternError: The pattern is empty, truncated, or has non-hex tokens.
    """
    cleaned = pattern.replace(" ", "").replace("\t", "")
    if not cleaned:
        raise HexPatternError("empty hex pattern")
    if len(cleaned) % 2 != 0:
        raise HexPatternError("hex pattern must contain whole bytes")
    values: list[int | None] = []
    for index in range(0, len(cleaned), 2):
        token = cleaned[index : index + 2]
        if token == "??":
            values.append(None)
            continue
        try:
            values.append(int(token, 16))
        except ValueError:
            raise HexPatternError(f"invalid hex byte token '{token}'") from None
    return values


def compile_hex_pattern(pattern: str) -> tuple[re.Pattern[bytes], int]:
    """Compile a hex byte pattern into a binary regex plus its byte length.

    The regex uses a lookahead so overlapping matches are all reported.

    :param pattern: Hex pattern string, e.g. "48 8b ?? 05".
    :returns: Tuple of the compiled pattern and its length in bytes.
    :raises HexPatternError: The pattern cannot be parsed.
    """
    values = parse_hex_pattern(pattern)
    body = b"".join(b"." if value is None else re.escape(bytes([value])) for value in values)
    return re.compile(b"(?=(" + body + b"))", re.DOTALL), len(values)
