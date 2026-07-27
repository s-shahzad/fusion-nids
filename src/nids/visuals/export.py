from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .charts import ChartSpec, build_all_figures
from .queries import build_analytics


@dataclass
class ExportedChart:
    slug: str
    title: str
    html_file: str
    png_file: str


def export_fig(fig, html_path: Path, png_path: Path) -> tuple[Path, Path | None]:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    png_path.parent.mkdir(parents=True, exist_ok=True)

    fig.write_html(str(html_path), include_plotlyjs="cdn", full_html=True)

    png_written: Path | None = None
    try:
        fig.write_image(str(png_path))
        png_written = png_path
    except Exception:
        png_written = None

    return html_path, png_written


def generate_index_page(output_dir: Path, charts: Iterable[ExportedChart]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    items = list(charts)

    card_blocks = []
    for chart in items:
        png_link = chart.png_file if chart.png_file else ""
        png_anchor = (
            f'<a class="link" href="{png_link}">PNG</a>' if png_link else '<span class="muted">PNG unavailable</span>'
        )

        card_blocks.append(
            f"""
            <section class="card" id="{chart.slug}">
              <div class="card-head">
                <h2>{chart.title}</h2>
                <div class="actions">
                  <a class="link" href="{chart.html_file}">HTML</a>
                  {png_anchor}
                </div>
              </div>
              <iframe src="{chart.html_file}" title="{chart.title}"></iframe>
            </section>
            """
        )

    rendered_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NIDS Graphical Analytics</title>
  <style>
    .nids-analytics-root {{
      --bg: #f6f8fb;
      --panel: #ffffff;
      --line: #d7dfea;
      --text: #1f2937;
      --muted: #64748b;
      --link: #1d4ed8;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      font-family: "Segoe UI", Arial, sans-serif;
      padding: 1rem;
    }}
    .nids-analytics-root .wrap {{
      max-width: 1280px;
      margin: 0 auto;
      display: grid;
      gap: 1rem;
    }}
    .nids-analytics-root .hero {{
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 14px;
      padding: 1rem;
    }}
    .nids-analytics-root h1 {{
      margin: 0 0 0.4rem;
      font-size: 1.5rem;
    }}
    .nids-analytics-root p {{
      margin: 0;
      color: var(--muted);
    }}
    .nids-analytics-root .card {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--panel);
      padding: 0.8rem;
      display: grid;
      gap: 0.7rem;
    }}
    .nids-analytics-root .card-head {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 1rem;
      flex-wrap: wrap;
    }}
    .nids-analytics-root .card-head h2 {{
      margin: 0;
      font-size: 1rem;
    }}
    .nids-analytics-root .actions {{
      display: flex;
      gap: 0.6rem;
      align-items: center;
      font-size: 0.86rem;
    }}
    .nids-analytics-root .link {{
      color: var(--link);
      text-decoration: none;
    }}
    .nids-analytics-root .muted {{
      color: var(--muted);
    }}
    .nids-analytics-root iframe {{
      width: 100%;
      min-height: 560px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
    }}
  </style>
</head>
<body>
  <main class="nids-analytics-root">
    <div class="wrap">
      <header class="hero">
        <h1>Universal NIDS Graphical Analytics</h1>
        <p>Generated: {rendered_at}</p>
      </header>
      {''.join(card_blocks)}
    </div>
  </main>
</body>
</html>
"""

    index_path = output_dir / "index.html"
    index_path.write_text(html, encoding="utf-8")
    return index_path


def run_visual_export(db_path: str | Path, output_dir: str | Path) -> tuple[Path, list[ExportedChart]]:
    db = Path(db_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    analytics = build_analytics(db)
    figures = build_all_figures(analytics)

    exports: list[ExportedChart] = []
    for spec in figures:
        html_path = out / f"{spec.slug}.html"
        png_path = out / f"{spec.slug}.png"
        _, png_written = export_fig(spec.figure, html_path, png_path)
        exports.append(
            ExportedChart(
                slug=spec.slug,
                title=spec.title,
                html_file=html_path.name,
                png_file=png_written.name if png_written else "",
            )
        )

    index_path = generate_index_page(out, exports)
    return index_path, exports
