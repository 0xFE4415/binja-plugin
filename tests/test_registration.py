from __future__ import annotations

import inspect

from helpers import REGISTERED_TOOLS

EXPECTED_NAMES = sorted(
    [
        "rex_call_paths",
        "rex_constant_find",
        "rex_data_find",
        "rex_decompile_many",
        "rex_disasm_at",
        "rex_eval_python",
        "rex_export_disasm",
        "rex_export_symbols",
        "rex_find_functions_by_pattern",
        "rex_function_containing",
        "rex_function_define",
        "rex_function_undefine",
        "rex_hlil_grep",
        "rex_kv_delete",
        "rex_kv_get",
        "rex_kv_set",
        "rex_memory_write",
        "rex_string_read_at",
        "rex_string_search",
        "rex_tag_list",
        "rex_tag_set",
    ]
)

ALLOWED_OPTIONS = {
    "title",
    "scope",
    "read_only",
    "destructive",
    "idempotent",
    "open_world",
    "output_schema",
}


def test_all_tools_are_registered_once() -> None:
    names = [name for name, _, _ in REGISTERED_TOOLS]
    assert sorted(names) == EXPECTED_NAMES
    assert len(names) == len(set(names))


def test_tool_names_are_namespaced() -> None:
    for name, _, _ in REGISTERED_TOOLS:
        assert name.startswith("rex_")
        assert not name.startswith("bn_")


def test_every_tool_documents_its_parameters() -> None:
    for name, _, function in REGISTERED_TOOLS:
        docstring = function.__doc__ or ""
        lines = [line for line in docstring.splitlines() if line.strip()]
        assert lines, f"{name} is missing a description"
        parameters = list(inspect.signature(function).parameters)
        assert parameters[0] == "call"
        for parameter in parameters[1:]:
            assert f":param {parameter}:" in docstring, f"{name} does not document '{parameter}'"


def test_tool_options_are_supported_by_the_decorator() -> None:
    for name, options, _ in REGISTERED_TOOLS:
        assert set(options) <= ALLOWED_OPTIONS, f"{name} passes unknown options {set(options)}"
