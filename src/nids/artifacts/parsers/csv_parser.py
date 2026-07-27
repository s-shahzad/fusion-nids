from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def parse_csv(path: Path, sample_rows: int = 10, sample_chars: int = 8192) -> dict[str, Any]:
    """Extract CSV dialect, shape estimate, and sample rows."""
    metadata: dict[str, Any] = {}
    rows: list[list[str]] = []

    try:
        sample = path.read_text(encoding="utf-8", errors="ignore")[:sample_chars]
        delimiter = ","
        has_header = False

        try:
            dialect = csv.Sniffer().sniff(sample)
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ","

        try:
            has_header = csv.Sniffer().has_header(sample)
        except Exception:
            has_header = False

        total_rows = 0
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            for row in reader:
                total_rows += 1
                if len(rows) < sample_rows:
                    rows.append([str(cell) for cell in row])

        column_count = max((len(row) for row in rows), default=0)
        metadata = {
            "delimiter": delimiter,
            "has_header": has_header,
            "rows": total_rows,
            "cols": column_count,
            "sample_rows": rows,
        }

        text = "\n".join(",".join(row) for row in rows)[:20000]
        return {
            "metadata": metadata,
            "text": text,
            "tags": ["csv"],
            "reasons": [],
        }
    except Exception as exc:
        return {
            "metadata": {"error": f"csv_parse_failed: {exc}"},
            "text": "",
            "tags": ["csv", "parse_error"],
            "reasons": ["csv_parse_failed"],
        }
