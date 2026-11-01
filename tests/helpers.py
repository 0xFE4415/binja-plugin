"""Fakes for exercising binja_plugin without a Binary Ninja installation."""

from __future__ import annotations

import enum
import sys
import types
from collections.abc import Callable, Iterator
from typing import Any, override

REGISTERED_TOOLS: list[tuple[str, dict[str, object], Any]] = []


class FakeToolError(Exception):
    def __init__(self, code: str, message: str, details: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _fake_tool(name: str | None = None, **options: object):
    def decorate(function: Any) -> Any:
        REGISTERED_TOOLS.append((name or function.__name__, options, function))
        return function

    return decorate


class FakeAddress(int):
    pass


class FakeIntegerExpression(int):
    pass


class FakeMinimum:
    """Mirrors binaryninja.mcp.Minimum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeMaximum:
    """Mirrors binaryninja.mcp.Maximum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeToolCallBase:
    pass


def install_fake_binaryninja() -> None:
    """Create the fake binaryninja package in sys.modules when it is absent."""
    if "binaryninja" in sys.modules:
        return
    mcp_module = types.ModuleType("binaryninja.mcp")
    setattr(mcp_module, "tool", _fake_tool)
    setattr(mcp_module, "Address", FakeAddress)
    setattr(mcp_module, "IntegerExpression", FakeIntegerExpression)
    setattr(mcp_module, "ToolCall", FakeToolCallBase)
    setattr(mcp_module, "ToolError", FakeToolError)
    setattr(mcp_module, "Minimum", FakeMinimum)
    setattr(mcp_module, "Maximum", FakeMaximum)
    setattr(
        mcp_module,
        "McpToolScope",
        enum.IntEnum("McpToolScope", {"GlobalScope": 0, "BinaryViewScope": 1}),
    )
    setattr(
        mcp_module,
        "McpToolAnnotation",
        enum.IntFlag(
            "McpToolAnnotation",
            {"ReadOnlyHint": 1, "DestructiveHint": 2, "IdempotentHint": 4, "OpenWorldHint": 8},
        ),
    )

    bv_module = types.ModuleType("binaryninja.binaryview")

    class FakeBinaryViewBase:
        pass

    setattr(bv_module, "BinaryView", FakeBinaryViewBase)

    fn_module = types.ModuleType("binaryninja.function")

    class FakeFunctionBase:
        pass

    setattr(fn_module, "Function", FakeFunctionBase)

    package = types.ModuleType("binaryninja")
    setattr(package, "mcp", mcp_module)
    setattr(package, "binaryview", bv_module)
    setattr(package, "function", fn_module)

    for name, module in (
        ("binaryninja", package),
        ("binaryninja.mcp", mcp_module),
        ("binaryninja.binaryview", bv_module),
        ("binaryninja.function", fn_module),
    ):
        sys.modules[name] = module
    REGISTERED_TOOLS.clear()


class FakeSegment:
    def __init__(self, start: int, length: int) -> None:
        self.start = start
        self.length = length


class FakeStringReference:
    def __init__(self, value: str, start: int, type_name: str = "AsciiString") -> None:
        self._value = value
        self.start = start
        self._type_name = type_name

    def __len__(self) -> int:
        return len(self._value)

    @property
    def value(self) -> str:
        return self._value

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class FakeTag:
    def __init__(self, type_name: str, data: str) -> None:
        self.data = data
        self._type_name = type_name

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class RenderableText:
    def __init__(self, text: str) -> None:
        self._text = text

    @override
    def __str__(self) -> str:
        return self._text


class FakeLinearDisassemblyLine:
    """Mirrors the LinearDisassemblyLine yielded by BinaryView.find_all_constant."""

    def __init__(self, function: FakeFunction | None) -> None:
        self.function = function


class FakeFunction:
    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        *,
        hlil: object = None,
        callers: list[FakeFunction] | None = None,
        callees: list[FakeFunction] | None = None,
    ) -> None:
        self.name = name
        self.start = start
        self.end = end
        self.hlil = hlil
        self.callers = callers if callers is not None else []
        self.callees = callees if callees is not None else []


class FakeBinaryView:
    def __init__(
        self,
        *,
        strings: list[FakeStringReference] | None = None,
        segments: list[FakeSegment] | None = None,
        functions: list[FakeFunction] | None = None,
        sections: dict[str, tuple[int, int]] | None = None,
        memory: dict[int, bytes] | None = None,
        start: int = 0,
        end: int = 0x10000,
        constant_references: list[tuple[int, int, FakeFunction | None]] | None = None,
    ) -> None:
        self.strings = strings if strings is not None else []
        self.segments = segments if segments is not None else []
        self.functions = functions if functions is not None else []
        self._sections: dict[str, tuple[int, int]] = sections or {}
        self._memory: dict[int, bytes] = memory or {}
        self._metadata: dict[str, object] = {}
        self._tags: list[tuple[int, FakeTag]] = []
        self._tag_types: dict[str, object] = {}
        self.written: list[tuple[int, bytes]] = []
        self.created_functions: list[FakeFunction] = []
        self.removed_functions: list[FakeFunction] = []
        self.start = start
        self.end = end
        # (value, address, function) triples answered by find_all_constant; a None
        # function models a match on a line that belongs to no function (data text).
        self.constant_references = constant_references or []
        self.constant_scan_yields = 0
        # Set once progress_func declines, modeling the core honoring the abort.
        self.constant_scan_aborted: bool | None = None

    def get_section_by_name(self, name: str) -> object:
        if name not in self._sections:
            return None
        start, end = self._sections[name]
        return types.SimpleNamespace(start=start, end=end)

    def find_all_constant(
        self,
        start: int,
        end: int,
        value: int,
        progress_func: Callable[[int, int], bool] | None = None,
    ) -> Iterator[tuple[int, FakeLinearDisassemblyLine]]:
        """Yield (address, line) matches in address order, aborting when progress declines."""
        matches = sorted(
            (
                (address, function)
                for matched_value, address, function in self.constant_references
                if matched_value == value and start <= address < end
            ),
            key=lambda match: match[0],
        )
        try:
            for address, function in matches:
                self.constant_scan_yields += 1
                yield address, FakeLinearDisassemblyLine(function)
        finally:
            # The core keeps scanning — and polling progress — after the caller stops
            # consuming matches, so model the shutdown poll even on an early break.
            if progress_func is not None and progress_func(self.end, self.end) is False:
                self.constant_scan_aborted = True

    def read(self, address: int, length: int) -> bytes | None:
        for base, blob in self._memory.items():
            offset = address - base
            if 0 <= offset < len(blob):
                return blob[offset : offset + length]
        return None

    def write(self, address: int, data: bytes) -> int:
        self.written.append((address, bytes(data)))
        return len(data)

    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        return [f for f in self.functions if f.start <= address < f.end]

    def get_string_at(self, address: int) -> object:
        for string in self.strings:
            if string.start == address:
                return string
        return None

    def create_user_function(self, address: int) -> FakeFunction:
        function = FakeFunction(f"sub_{address:x}", address, address + 1)
        self.created_functions.append(function)
        self.functions.append(function)
        return function

    def remove_user_function(self, function: FakeFunction) -> None:
        self.removed_functions.append(function)

    @property
    def tag_types(self) -> dict[str, object]:
        return self._tag_types

    def create_tag_type(self, name: str, icon: str) -> None:
        self._tag_types[name] = types.SimpleNamespace(name=name, icon=icon)

    def add_tag(self, address: int, tag_type_name: str, data: str) -> None:
        self._tags.append((address, FakeTag(tag_type_name, data)))

    def get_tags(self) -> list[tuple[int, FakeTag]]:
        return list(self._tags)

    def store_metadata(self, key: str, value: object) -> None:
        self._metadata[key] = value

    def query_metadata(self, key: str) -> object:
        if key not in self._metadata:
            raise KeyError(key)
        return self._metadata[key]

    def remove_metadata(self, key: str) -> None:
        self._metadata.pop(key, None)


class FakeToolCall:
    def __init__(self, binary_view: FakeBinaryView) -> None:
        self.binary_view = binary_view


def get_tool(name: str) -> tuple[dict[str, object], Any]:
    for tool_name, options, function in REGISTERED_TOOLS:
        if tool_name == name:
            return options, function
    raise KeyError(name)
