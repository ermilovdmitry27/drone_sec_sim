from __future__ import annotations

from pathlib import Path

from build_simple_docx import ReportHtmlParser, build_docx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_OBJECT = PROJECT_ROOT / "docs" / "object_and_attack_report.html"
SOURCE_COVERAGE = PROJECT_ROOT / "docs" / "threat_coverage_report.html"
TARGET_HTML = PROJECT_ROOT / "docs" / "diploma_text_combined.html"
TARGET_DOCX = PROJECT_ROOT / "docs" / "diploma_text_combined.docx"


STYLE_BLOCK = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Текст для диплома: объект исследования, сценарии атак и покрытие угроз</title>
  <style>
    body {
      font-family: "Times New Roman", serif;
      font-size: 14pt;
      line-height: 1.35;
      margin: 2.2cm;
      color: #111;
    }
    h1, h2, h3 {
      font-weight: bold;
      margin-top: 1.1em;
      margin-bottom: 0.45em;
    }
    h1 {
      text-align: center;
      font-size: 18pt;
    }
    h2 {
      font-size: 16pt;
    }
    h3 {
      font-size: 14pt;
    }
    p {
      margin: 0 0 0.7em 0;
      text-align: justify;
    }
    .source {
      font-size: 11pt;
      color: #333;
      margin-top: -0.2em;
    }
  </style>
</head>
<body>
"""


def parse_blocks(path: Path) -> list[dict[str, str]]:
    parser = ReportHtmlParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.blocks


def render_block(block: dict[str, str]) -> str:
    tag = block["tag"]
    text = block["text"]
    css_class = block["class"]
    class_attr = f' class="{css_class}"' if css_class else ""
    return f"  <{tag}{class_attr}>{text}</{tag}>"


def transform_coverage_blocks(blocks: list[dict[str, str]]) -> list[dict[str, str]]:
    heading_map = {
        "1. Основание и границы реализации": "3.1.5 Реализация полного покрытия угроз из файла сопоставления",
        "2. Что добавлено в проект": "3.1.6 Архитектура каталогового покрытия",
        "3. Подтвержденный результат полного прогона": "3.1.7 Подтвержденный результат полного прогона",
        "3.1 Распределение по профилям эмуляции": "3.1.7.1 Распределение по профилям эмуляции",
        "3.2 Распределение по режимам покрытия": "3.1.7.2 Распределение по режимам покрытия",
        "3.3 Правила детектора, реально сработавшие в полном прогоне": "3.1.7.3 Срабатывания правил детектора в полном прогоне",
        "4. Таблица сопоставления угроз, профилей, правил и логов": "3.1.8 Таблица сопоставления угроз, профилей, правил и логов",
        "5. Ограничения": "3.1.9 Ограничения и границы интерпретации",
    }

    transformed: list[dict[str, str]] = []
    for block in blocks:
        if block["tag"] == "h1":
            continue
        updated = block.copy()
        if updated["tag"] in {"h2", "h3"} and updated["text"] in heading_map:
            updated["text"] = heading_map[updated["text"]]
        transformed.append(updated)
    return transformed


def build_html() -> str:
    object_blocks = parse_blocks(SOURCE_OBJECT)
    coverage_blocks = transform_coverage_blocks(parse_blocks(SOURCE_COVERAGE))

    merged_blocks: list[dict[str, str]] = [
        {"tag": "h1", "class": "", "text": "Текст для диплома: объект исследования, сценарии атак и покрытие угроз"},
        {
            "tag": "p",
            "class": "",
            "text": (
                "Документ объединяет подтвержденные по файлам проекта разделы об объекте "
                "исследования, выборе архитектуры стенда, реализованных сценариях атак и "
                "полном каталоговом покрытии угроз из файла сопоставления."
            ),
        },
        {
            "tag": "p",
            "class": "source",
            "text": (
                "Источники: docs/object_and_attack_report.html:1; "
                "docs/threat_coverage_report.html:1."
            ),
        },
    ]

    for block in object_blocks:
        if block["tag"] == "h1":
            continue
        merged_blocks.append(block)

    merged_blocks.extend(coverage_blocks)

    body = "\n".join(render_block(block) for block in merged_blocks)
    return STYLE_BLOCK + body + "\n</body>\n</html>\n"


def main() -> None:
    TARGET_HTML.write_text(build_html(), encoding="utf-8")
    build_docx(TARGET_HTML, TARGET_DOCX)
    print(TARGET_DOCX)


if __name__ == "__main__":
    main()
