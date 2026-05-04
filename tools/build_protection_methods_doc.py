from __future__ import annotations

import html
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = PROJECT_ROOT / "docs"
SOURCE_MD = DOCS_DIR / "protection_methods_analysis.md"
REPORT_HTML = DOCS_DIR / "protection_methods_analysis.html"
REPORT_DOCX = DOCS_DIR / "protection_methods_analysis.docx"

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_simple_docx import build_docx


def inline_markup(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text


def markdown_to_html(markdown_text: str) -> str:
    blocks: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append(f"<p>{inline_markup(' '.join(paragraph))}</p>")
            paragraph.clear()

    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            continue

        if stripped.startswith("# "):
            flush_paragraph()
            blocks.append(f"<h1>{inline_markup(stripped[2:].strip())}</h1>")
            continue

        if stripped.startswith("## "):
            flush_paragraph()
            blocks.append(f"<h2>{inline_markup(stripped[3:].strip())}</h2>")
            continue

        if stripped.startswith("### "):
            flush_paragraph()
            blocks.append(f"<h3>{inline_markup(stripped[4:].strip())}</h3>")
            continue

        if stripped.startswith("- "):
            flush_paragraph()
            blocks.append(f"<p>• {inline_markup(stripped[2:].strip())}</p>")
            continue

        numbered = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if numbered:
            flush_paragraph()
            blocks.append(f"<p>{numbered.group(1)}. {inline_markup(numbered.group(2))}</p>")
            continue

        if stripped.startswith("|"):
            flush_paragraph()
            if set(stripped.replace("|", "").replace(" ", "")) <= {"-", ":"}:
                continue
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            blocks.append(f"<p>{inline_markup(' | '.join(cells))}</p>")
            continue

        paragraph.append(stripped)

    flush_paragraph()
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ru">',
            "<head><meta charset=\"utf-8\"><title>Анализ методов защиты</title></head>",
            "<body>",
            *blocks,
            "</body>",
            "</html>",
        ]
    )


def main() -> None:
    html_text = markdown_to_html(SOURCE_MD.read_text(encoding="utf-8"))
    REPORT_HTML.write_text(html_text, encoding="utf-8")
    build_docx(REPORT_HTML, REPORT_DOCX)
    print(REPORT_HTML)
    print(REPORT_DOCX)


if __name__ == "__main__":
    main()
