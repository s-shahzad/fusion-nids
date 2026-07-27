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


@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "../../secrets.md",
        "sub/../../escape.md",
        "a/b/../../../out.md",
    ],
)
def test_parent_traversal_is_rejected(bad):
    with pytest.raises(ValueError, match="(?i)parent-directory|within"):
        _confine_report_path(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",
        "/tmp/out.md",
    ],
)
def test_absolute_posix_path_is_rejected(bad):
    with pytest.raises(ValueError, match="(?i)relative"):
        _confine_report_path(bad)


def test_home_directory_reference_is_rejected():
    """`~` had been expanded for the caller, widening what had to be caught later."""
    with pytest.raises(ValueError, match="(?i)home directory"):
        _confine_report_path("~/owned.md")


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


def test_windows_style_absolute_is_rejected_where_recognised():
    """On Windows a drive-qualified path must not slip through as 'relative'."""
    candidate = Path("C:/Windows/Temp/out.md")
    if not (candidate.is_absolute() or candidate.drive):
        pytest.skip("POSIX host does not treat a drive letter as absolute")
    with pytest.raises(ValueError, match="(?i)relative"):
        _confine_report_path("C:/Windows/Temp/out.md")
