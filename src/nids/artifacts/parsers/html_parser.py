from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SUSPICIOUS_DOMAIN_TOKENS = [
    "pastebin",
    "bit.ly",
    "tinyurl",
    "ngrok",
    "onion",
    "duckdns",
]


def parse_html(path: Path, text_limit: int = 20000) -> dict[str, Any]:
    """Parse HTML for static indicators: title, links, scripts, and inline scripts."""
    try:
        from bs4 import BeautifulSoup
    except Exception as exc:
        return {
            "metadata": {"error": f"beautifulsoup4 unavailable: {exc}"},
            "text": "",
            "tags": ["html", "parse_error"],
            "reasons": ["html_parser_unavailable"],
        }

    reasons: list[str] = []
    suspicious_domains: set[str] = set()

    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
        soup = BeautifulSoup(raw, "lxml")

        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        script_tags = soup.find_all("script")
        inline_scripts = [tag for tag in script_tags if not tag.get("src")]

        links = []
        for tag in soup.find_all(["a", "script", "img", "link"]):
            href = tag.get("href") or tag.get("src")
            if href:
                links.append(str(href))

        for link in links:
            lower = link.lower()
            host = urlparse(link).netloc.lower()
            for token in SUSPICIOUS_DOMAIN_TOKENS:
                if token in lower or token in host:
                    suspicious_domains.add(host or lower)

        if len(inline_scripts) >= 4:
            reasons.append("html_many_inline_scripts")
        if suspicious_domains:
            reasons.append("html_suspicious_domains")

        visible_text = " ".join(soup.stripped_strings)[:text_limit]

        metadata = {
            "title": title,
            "links": len(links),
            "scripts": len(script_tags),
            "inline_scripts": len(inline_scripts),
            "suspicious_domains": sorted([domain for domain in suspicious_domains if domain])[:50],
        }

        return {
            "metadata": metadata,
            "text": visible_text,
            "tags": ["html"],
            "reasons": reasons,
        }
    except Exception as exc:
        return {
            "metadata": {"error": f"html_parse_failed: {exc}"},
            "text": "",
            "tags": ["html", "parse_error"],
            "reasons": ["html_parse_failed"],
        }
