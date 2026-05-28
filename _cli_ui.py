# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Back-compat shim. The real implementation lives in
``bitseal._cli_ui`` as of v0.3.0. This file exists so that code which
predates the package refactor (notably the test suite and any direct
clones running from the repo root without ``pip install``) can still
do ``from _cli_ui import header_panel, kv_table, ...``.

Private-by-convention (leading underscore). Third-party integrators
should not depend on this surface; the CLI UI primitives are tuned
for the SDK's own CLI output and may change between releases.
"""

from bitseal._cli_ui import *  # noqa: F401, F403
from bitseal._cli_ui import (  # noqa: F401
    header_panel,
    kv_table,
    render_panel,
    short_hex,
)

__all__ = [
    "header_panel",
    "kv_table",
    "render_panel",
    "short_hex",
]
