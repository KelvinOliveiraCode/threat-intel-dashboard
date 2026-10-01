"""Permite executar como ``python -m intelhub``.

Enables running as ``python -m intelhub``.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())