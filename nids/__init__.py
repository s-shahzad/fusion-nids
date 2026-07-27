"""CLI entry-point shim for ``python -m nids``.

This package exists only so the documented command line works from a checkout.
The implementation lives in ``src/nids/``; nothing here should grow beyond
dispatching to it.

Why a shim rather than a single package: the project runs from a checkout rather
than being installed (there is no ``pyproject.toml`` or ``setup.py``), so
``src/`` is not on ``sys.path`` as a package root. Every documented command, the
Dockerfile ``CMD``, the CI workflows, and the lab scripts invoke
``python -m nids``, and this two-file shim is what makes that resolve. Folding it
into ``src/nids/`` would require either adding packaging configuration or
rewriting every documented command, neither of which is in scope for a naming
cleanup.

See ``src/nids/cli.py`` for the actual argument parsing and subcommands.
"""
