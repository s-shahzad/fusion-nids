# Contributing to Fusion NIDS

Thanks for your interest in improving Fusion NIDS, a hybrid ML network intrusion-detection system.
Contributions of all sizes are welcome.

## Ways to contribute

- Report bugs or unexpected behavior via an issue
- Propose features or detection improvements
- Improve documentation
- Submit code via a pull request

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
pip install -r requirements.txt
```

Run the test suite the same way CI does (excludes lab/environment/live suites
that require external infrastructure):

```bash
pytest -m "not lab and not environment and not live"
```

## Pull request process

1. Fork the repo and create a feature branch from `main`.
2. Keep changes focused; one logical change per PR.
3. Add or update tests for any behavior you change.
4. Make sure `pytest` and the CI checks pass locally.
5. Write a clear PR description (what, why, how tested). Fill in the template.

## Code style

- Python: PEP 8, type hints on public functions, no unused imports.
- Prefer small, readable functions over cleverness.
- Match the style of the surrounding code.

## Licensing of contributions

This project is dual-licensed:

- The core engine and API (`src/NIDS/`, excluding `adversary_lab/`) are under the
  **MIT License**.
- `src/NIDS/adversary_lab/` depends on Scapy (GPL-2.0-only) and is licensed
  **GPL-2.0-or-later**.

By submitting a contribution, you agree that your contribution is licensed under
the same license as the file(s) you modify.

## Security issues

Do **not** open a public issue for a suspected vulnerability. Follow the process
in [SECURITY.md](SECURITY.md).