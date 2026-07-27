"""Report output must stay inside reports/.

CodeQL `py/path-injection`, severity high: `out_path` reaches this function
from an authenticated API request body, so it is caller-controlled. The
confinement is what stops an incident report being written anywhere on the
filesystem.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.nids.services.report_service import _confine_report_path, _reports_root


# --------------------------------------------------------------------------
# rejected
# --------------------------------------------------------------------------


# The allowlist rejects traversal, home references, absolute paths and
# backslashes through one code path, so these all surface the same message.
# The assertion that matters is that they are refused at all.
@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "../../secrets.md",
        "sub/../../escape.md",
        "a/b/../../../out.md",
        "/etc/passwd",
        "/tmp/out.md",
        "~/owned.md",
        "~root/.ssh/authorized_keys",
        r"..\..\windows\system32\out.md",
        "reports\\..\\..\\out.md",
        "sub//../out.md",
        "  /etc/passwd",
        "out.md ",
        "café.md",
        "out;rm -rf.md",
        "out\nmd",
    ],
)
def test_paths_that_could_escape_are_rejected(bad):
    with pytest.raises(ValueError):
        _confine_report_path(bad)


def test_null_byte_is_rejected():
    with pytest.raises(ValueError, match="(?i)null byte"):
        _confine_report_path("report\x00.md")


# --------------------------------------------------------------------------
# accepted
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good",
    [
        "summary.md",
        "incident.md",
        "nested/incident.md",
        "./summary.md",
    ],
)
def test_relative_paths_resolve_under_reports_root(good):
    resolved = _confine_report_path(good)

    # The whole guarantee, stated once: whatever comes back is under reports/.
    assert resolved.is_relative_to(_reports_root())


def test_returned_path_is_absolute_and_resolved():
    resolved = _confine_report_path("summary.md")

    assert resolved.is_absolute()
    assert resolved.name == "summary.md"


def test_windows_drive_qualified_path_is_rejected_on_every_platform():
    """A drive letter must not slip through, POSIX or Windows.

    Worth pinning cross-platform: on POSIX ``Path('C:/x').is_absolute()`` is
    False, so a check relying only on that would let it past. The allowlist
    refuses the colon regardless of host.
    """
    with pytest.raises(ValueError):
        _confine_report_path("C:/Windows/Temp/out.md")


def test_unvalidated_input_is_not_carried_into_the_resolved_path():
    """The returned path is rebuilt from validated parts, not the raw string."""
    resolved = _confine_report_path("nested/incident.md")

    assert resolved.is_relative_to(_reports_root())
    assert resolved.parts[-2:] == ("nested", "incident.md")
