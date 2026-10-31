from collections.abc import Callable
from enum import IntEnum, IntFlag
from typing import Any, TypeVar

_ToolFunction = TypeVar("_ToolFunction", bound=Callable[..., Any])


class McpToolScope(IntEnum):
    GlobalScope = 0
    BinaryViewScope = 1


class McpToolAnnotation(IntFlag):
    ReadOnlyHint = 1
    DestructiveHint = 2
    IdempotentHint = 4
    OpenWorldHint = 8


class Address(int): ...


class Minimum:
    def __init__(self, value: int) -> None: ...


class Maximum:
    def __init__(self, value: int) -> None: ...


class ClampTo:
    minimum: int
    maximum: int

    def __init__(self, minimum: int, maximum: int) -> None: ...


class IntegerExpression(int): ...


class ToolError(Exception):
    def __init__(self, code: str, message: str, details: Any = None) -> None: ...


class ToolCall:
    @property
    def binary_view(self) -> Any: ...
    def parse_address(self, value: Any, here: int = 0) -> int: ...
    def parse_integer(self, value: Any, here: int = 0) -> int: ...


def tool(
    name: str | None = None,
    *,
    title: str = "",
    scope: McpToolScope = McpToolScope.BinaryViewScope,
    read_only: bool = False,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
    output_schema: dict[str, Any] | None = None,
) -> Callable[[_ToolFunction], _ToolFunction]: ...
