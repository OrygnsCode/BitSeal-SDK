"""Shared Rich-based visual primitives used by the SDK's CLI entry points
(BitSealCore.py for sealing, verify.py for verification).

Private-by-convention (leading underscore). Third-party integrators should
import from BitSealCore, not this module — the surface here is tuned for
CLI output and may change when the UI is retuned.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


_STATUS_STYLES = {
    "success": ("bold green", "green"),
    "error": ("bold red", "red"),
    "warning": ("bold yellow", "yellow"),
    "info": ("bold cyan", "cyan"),
    "pending": ("bold yellow", "yellow"),
}


def header_panel(sdk_version, api_base):
    body = Text.assemble(
        ("BitSeal SDK\n", "bold white"),
        (f"v{sdk_version}  ", "dim"),
        ("- ", "dim"),
        (f"{api_base}", "cyan"),
    )
    return Panel(body, border_style="cyan", padding=(0, 2))


def kv_table(rows):
    """Two-column grid: cyan right-aligned keys, white folding values."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", justify="right", no_wrap=True)
    table.add_column(style="white", overflow="fold")
    for key, value in rows:
        table.add_row(str(key), "" if value is None else str(value))
    return table


def render_panel(console: Console, title: str, renderable, kind: str = "info"):
    """Draws a titled Panel with semantic border colors. Kind is one of:
    success, error, warning, info, pending."""
    title_style, border_style = _STATUS_STYLES.get(kind, _STATUS_STYLES["info"])
    console.print()
    console.print(
        Panel(
            renderable,
            title=f"[{title_style}]{title}[/{title_style}]",
            border_style=border_style,
            padding=(1, 2),
        )
    )


def short_hex(value, head: int = 16, tail: int = 8):
    """Truncate long hex for display while keeping both ends. Returns the
    original value unchanged if already short enough or not a string."""
    if not value or not isinstance(value, str):
        return value
    if len(value) <= head + tail + 3:
        return value
    return f"{value[:head]}...{value[-tail:]}"
