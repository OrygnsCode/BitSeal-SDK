"""Smoke tests for the shared CLI UI primitives. Full visual regression is
out of scope; these tests confirm the helpers return the expected rich
types and do not raise on representative inputs.
"""

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from _cli_ui import header_panel, kv_table, render_panel, short_hex


def test_short_hex_passes_short_values_unchanged():
    assert short_hex("abc") == "abc"
    assert short_hex("") == ""
    assert short_hex(None) is None
    assert short_hex(12345) == 12345  # non-string passthrough


def test_short_hex_truncates_long_values():
    long_hex = "a" * 64
    out = short_hex(long_hex, head=10, tail=10)
    assert out.startswith("a" * 10)
    assert out.endswith("a" * 10)
    assert "..." in out
    assert len(out) == 10 + 3 + 10


def test_short_hex_threshold_boundary():
    # head=8, tail=4, so threshold is 8+4+3 = 15 chars
    assert short_hex("a" * 15, head=8, tail=4) == "a" * 15
    assert "..." in short_hex("a" * 16, head=8, tail=4)


def test_header_panel_returns_panel():
    assert isinstance(header_panel("1.2.3", "https://example.com"), Panel)


def test_kv_table_returns_table():
    table = kv_table([("Key", "value"), ("Another", 42)])
    assert isinstance(table, Table)


def test_kv_table_handles_none_values():
    table = kv_table([("nullable", None), ("present", "x")])
    assert isinstance(table, Table)


def _silent_console():
    return Console(file=io.StringIO(), force_terminal=False, width=80)


def test_render_panel_all_kinds():
    console = _silent_console()
    for kind in ("success", "error", "warning", "info", "pending"):
        render_panel(console, "Test", "body", kind=kind)


def test_render_panel_falls_back_on_unknown_kind():
    render_panel(_silent_console(), "Test", "body", kind="nonsense")


def test_render_panel_accepts_renderable_as_body():
    render_panel(_silent_console(), "Test", kv_table([("a", "b")]), kind="success")
