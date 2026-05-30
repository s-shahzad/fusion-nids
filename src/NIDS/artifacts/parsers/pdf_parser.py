from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_pdf(path: Path, text_limit: int = 20000) -> dict[str, Any]:
    """Extract lightweight PDF metadata and text without executing content."""
    metadata: dict[str, Any] = {}
    text_parts: list[str] = []
    reasons: list[str] = []

    try:
        from pypdf import PdfReader
    except Exception as exc:
        return {
            "metadata": {"error": f"pypdf unavailable: {exc}"},
            "text": "",
            "tags": ["pdf", "parse_error"],
            "reasons": ["pdf_parser_unavailable"],
        }

    try:
        reader = PdfReader(str(path))
        if reader.metadata:
            metadata = {str(k): str(v) for k, v in reader.metadata.items()}
        metadata["pages"] = len(reader.pages)

        for page in reader.pages[:10]:
            if sum(len(chunk) for chunk in text_parts) >= text_limit:
                break
            page_text = page.extract_text() or ""
            if page_text:
                text_parts.append(page_text)

        if metadata.get("/JS") or metadata.get("/JavaScript"):
            reasons.append("pdf_contains_javascript_metadata")
    except Exception as exc:
        return {
            "metadata": {"error": f"pdf_parse_failed: {exc}"},
            "text": "",
            "tags": ["pdf", "parse_error"],
            "reasons": ["pdf_parse_failed"],
        }

    text = "\n".join(text_parts)[:text_limit]
    return {
        "metadata": metadata,
        "text": text,
        "tags": ["pdf"],
        "reasons": reasons,
    }
