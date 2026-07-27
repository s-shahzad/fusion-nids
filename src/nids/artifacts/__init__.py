"""Artifact intake and static analysis package for Universal NIDS."""

from .intake import run_artifact_scan, run_artifact_watch
from .report import generate_artifact_report

__all__ = ["run_artifact_scan", "run_artifact_watch", "generate_artifact_report"]
