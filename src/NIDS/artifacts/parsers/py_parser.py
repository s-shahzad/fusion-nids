from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

SUSPICIOUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        chain = []
        current: ast.AST | None = node
        while isinstance(current, ast.Attribute):
            chain.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            chain.append(current.id)
        return ".".join(reversed(chain))
    return ""


def parse_python(path: Path, text_limit: int = 20000) -> dict[str, Any]:
    """Parse Python file with AST only (no execution)."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)

        imports: set[str] = set()
        suspicious_calls: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
            elif isinstance(node, ast.Call):
                call = _call_name(node.func)
                if call in SUSPICIOUS_CALLS:
                    suspicious_calls.add(call)

        reasons: list[str] = []
        if suspicious_calls:
            reasons.append("python_contains_suspicious_function_calls")

        return {
            "metadata": {
                "imports": sorted(list(imports))[:200],
                "suspicious_calls": sorted(list(suspicious_calls)),
                "line_count": source.count("\n") + 1,
            },
            "text": source[:text_limit],
            "tags": ["python"],
            "reasons": reasons,
        }
    except Exception as exc:
        return {
            "metadata": {"error": f"python_parse_failed: {exc}"},
            "text": "",
            "tags": ["python", "parse_error"],
            "reasons": ["python_parse_failed"],
        }
