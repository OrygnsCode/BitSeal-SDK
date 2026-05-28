#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Back-compat shim. The real implementation lives in ``bitseal.verify``
as of v0.3.0. This file keeps ``python verify.py [args]`` working from
a fresh clone of the repo so the install instructions documented at
``/legal/key-ceremony`` Section 6 do not break before the package is
installed.

After ``pip install bitseal``, the preferred invocation is::

    python -m bitseal.verify --root <hex>
    python -m bitseal.verify --manifest <path>
    python -m bitseal.verify --fingerprint
"""

from bitseal.verify import main


if __name__ == "__main__":
    main()
