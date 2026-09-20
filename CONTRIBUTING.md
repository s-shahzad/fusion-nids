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

CI also measures coverage with branch tracking on every pull request and push
to `main`, on Python 3.11 and 3.12. The unchanged 72% floor in `.coveragerc`
applies to the combined statement/branch percentage, not branch-only coverage:

```bash
python -m pytest -q -m "not lab and not environment and not live" --cov=src/nids --cov-config=.coveragerc --cov-report=term:skip-covered
```

Each CI run retains JSON/XML coverage and JUnit results in the
`ci-validation-python-<version>` artifact. Quote coverage with its run URL,
commit, measurement date and Python version. Coverage measures exercised code,
not detection accuracy, and excludes the lab/environment/live test suites.
Extended Validation remains an optional deeper run; it is no longer the only
workflow that enforces coverage.

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

## Naming and layout conventions

The repository previously mixed several conventions. These are now the rules;
please follow them so it does not drift back.

| Thing | Convention | Example |
|---|---|---|
| Directories | lowercase, hyphen-separated | `docs/architecture/`, `lab/` |
| Python modules and packages | lowercase with underscores | `src/nids/detect/ml_supervised.py` |
| Shell and PowerShell scripts | lowercase, hyphen-separated | `lab/run-offline-test.ps1` |
| Documentation files | lowercase with underscores or hyphens | `docs/validation/soak-claim-audit.md` |
| Root-level community files | conventional uppercase | `README.md`, `LICENSE`, `SECURITY.md` |

Additional rules:

- **No spaces in filenames.** They break shell pipelines and CI globs.
- **No absolute local paths in tracked files.** Never commit `C:\Users\<you>\...`
  or an equivalent — it leaks your username and machine layout into a public
  repository. Use repo-relative paths in documentation, and a `<workspace>`
  placeholder in recorded evidence where an absolute path must be represented.
- **One package spelling.** The importable package is `src/nids/`. The root
  `nids/` directory is a documented CLI shim for `python -m nids` and should not
  grow beyond dispatching.
- **Generated output is not tracked.** See `reports/README.md`. Evidence is
  tracked; renders are not.

## What does not belong in this repository

- Unpublished manuscripts, thesis source, or presentation decks. `paper/`,
  `thesis/`, and `docs/paper_*.md` are gitignored deliberately.
- Any capture or scan data describing a network you do not own. The synthetic
  bundles under `pcaps/` are lab-generated against mock targets; real captures
  stay in the gitignored `lab/pcaps/`.

Note that removing such a file in a later commit does **not** remove it from
GitHub — orphaned objects stay fetchable by SHA until GitHub garbage-collects
them. Keep it out in the first place.

## Licensing of contributions

This project is dual-licensed:

- The core engine and API (`src/nids/`, excluding `adversary_lab/`) are under the
  **MIT License**.
- `src/nids/adversary_lab/` depends on Scapy (GPL-2.0-only) and is licensed
  **GPL-2.0-or-later**.

By submitting a contribution, you agree that your contribution is licensed under
the same license as the file(s) you modify.

## Dependency review order

Review dependency updates in this order:

1. Confirmed security advisories affecting the installed dependency graph.
2. Security-sensitive libraries and scanners (`cryptography`, `paramiko`, Scapy,
   and CodeQL), even when an update is routine rather than an advisory fix.
3. Other libraries and GitHub Actions, with major versions reviewed separately.
4. Python/container runtime changes, after library compatibility is established.

Patch/minor Dependabot updates may use the existing auto-merge workflow only
after required checks pass against an up-to-date branch. Repository auto-merge
and strict required checks must remain enabled; never bypass a failed check.
Major updates require individual review, relevant runtime tests and an explicit
merge action. A human-authored PR or major update skipping auto-merge is expected.

For each major update, read the upstream migration notes, inspect actual imports
and exercised functionality, refresh the branch against main, and validate the
resulting diff as well as CI. Security-library changes need their functional
tests (for example encryption round trips or SSH host-key rejection); package
installation alone is insufficient. Test dependency consistency with `pip check`.
Runtime updates also need a successful Docker build and its smoke checks.

Record the tested versions and run links in the PR. If a required capability is
not covered, add a focused regression or keep that update pending with the exact
gap. Check open PR state live rather than treating an old queue count as current.
Do not merge all updates together merely to empty the dependency queue.

## Reporting vulnerabilities

Do **not** open a public issue for a suspected vulnerability. Follow the process
in [SECURITY.md](SECURITY.md).
