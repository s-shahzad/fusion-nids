"""Dispatch ``python -m nids`` to the real CLI in ``src/nids/cli.py``."""

from src.nids.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
