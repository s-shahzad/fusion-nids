from __future__ import annotations

from pathlib import Path

from src.NIDS.artifacts.analyzer import analyze_artifact


def test_analyze_artifact_flags_exe_with_suspicious_strings_as_high(tmp_path: Path) -> None:
    sample = tmp_path / "loader.exe"
    sample.write_bytes(
        b"MZ\npowershell\ncmd.exe\nhttp://example.invalid/payload\nwininet.dll\n"
    )

    record = analyze_artifact(sample)

    assert record["risk_level"] == "high"
    assert "executable_contains_suspicious_strings" in record["reasons"]
    assert "executable_with_suspicious_strings" in record["reasons"]


def test_analyze_artifact_flags_bin_with_suspicious_strings_as_medium(tmp_path: Path) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(
        b"MZ\nshellcode\nhttp://example.invalid/payload.bin\nws2_32.dll\n"
    )

    record = analyze_artifact(sample)

    assert record["risk_level"] == "medium"
    assert "executable_contains_suspicious_strings" in record["reasons"]
    assert "binary_with_suspicious_strings" in record["reasons"]
