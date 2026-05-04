from __future__ import annotations

import html
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from xml.sax.saxutils import escape


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


class ReportHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.blocks: list[dict[str, str]] = []
        self._tag_stack: list[str] = []
        self._current_tag: str | None = None
        self._current_class: str = ""
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        self._tag_stack.append(tag)
        if tag in {"h1", "h2", "h3", "p"}:
            self._current_tag = tag
            self._current_class = attrs_map.get("class") or ""
            self._buffer = []

    def handle_endtag(self, tag: str) -> None:
        if tag == self._current_tag:
            text = html.unescape("".join(self._buffer)).strip()
            if text:
                self.blocks.append(
                    {"tag": self._current_tag or "p", "class": self._current_class, "text": text}
                )
            self._current_tag = None
            self._current_class = ""
            self._buffer = []
        if self._tag_stack:
            self._tag_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._current_tag is not None:
            self._buffer.append(data)


def style_for(block: dict[str, str]) -> str:
    tag = block["tag"]
    if tag == "h1":
        return "TitleDoc"
    if tag == "h2":
        return "Heading1"
    if tag == "h3":
        return "Heading2"
    if block["class"] == "source":
        return "Source"
    return "BodyText"


def paragraph_xml(text: str, style: str) -> str:
    safe_text = escape(text)
    return (
        f'<w:p>'
        f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>'
        f'<w:r><w:t xml:space="preserve">{safe_text}</w:t></w:r>'
        f'</w:p>'
    )


def build_document_xml(blocks: list[dict[str, str]]) -> str:
    paragraphs = "\n".join(paragraph_xml(block["text"], style_for(block)) for block in blocks)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="{W_NS}">
  <w:body>
    {paragraphs}
    <w:sectPr>
      <w:pgSz w:w="11906" w:h="16838"/>
      <w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>
"""


def build_styles_xml() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="{W_NS}">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman"/>
        <w:sz w:val="28"/>
        <w:szCs w:val="28"/>
        <w:lang w:val="ru-RU"/>
      </w:rPr>
    </w:rPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
  </w:style>
  <w:style w:type="paragraph" w:styleId="TitleDoc">
    <w:name w:val="TitleDoc"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:jc w:val="center"/>
      <w:spacing w:before="0" w:after="200"/>
    </w:pPr>
    <w:rPr>
      <w:b/>
      <w:sz w:val="36"/>
      <w:szCs w:val="36"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="Heading1"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:spacing w:before="240" w:after="120"/>
    </w:pPr>
    <w:rPr>
      <w:b/>
      <w:sz w:val="32"/>
      <w:szCs w:val="32"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="Heading2"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:spacing w:before="180" w:after="100"/>
    </w:pPr>
    <w:rPr>
      <w:b/>
      <w:sz w:val="28"/>
      <w:szCs w:val="28"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="BodyText">
    <w:name w:val="BodyText"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:jc w:val="both"/>
      <w:spacing w:after="120"/>
    </w:pPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Source">
    <w:name w:val="Source"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:jc w:val="both"/>
      <w:spacing w:after="120"/>
    </w:pPr>
    <w:rPr>
      <w:i/>
      <w:sz w:val="22"/>
      <w:szCs w:val="22"/>
      <w:color w:val="444444"/>
    </w:rPr>
  </w:style>
</w:styles>
"""


def content_types_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""


def root_rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""


def document_rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"""


def core_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:dcmitype="http://purl.org/dc/dcmitype/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Объект исследования и подтвержденные сценарии атак</dc:title>
  <dc:creator>Codex</dc:creator>
</cp:coreProperties>
"""


def app_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
  xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Codex</Application>
</Properties>
"""


def build_docx(html_path: Path, out_path: Path) -> None:
    parser = ReportHtmlParser()
    parser.feed(html_path.read_text(encoding="utf-8"))
    document_xml = build_document_xml(parser.blocks)
    styles_xml = build_styles_xml()

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml())
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("word/document.xml", document_xml)
        zf.writestr("word/styles.xml", styles_xml)
        zf.writestr("word/_rels/document.xml.rels", document_rels_xml())
        zf.writestr("docProps/core.xml", core_xml())
        zf.writestr("docProps/app.xml", app_xml())


def main() -> None:
    html_path = Path("docs/object_and_attack_report.html")
    out_path = Path("docs/object_and_attack_report.docx")
    build_docx(html_path, out_path)
    print(out_path)


if __name__ == "__main__":
    main()
