"""Malworn H3: render a human-readable HTML or PDF report from aggregated JSON.

Input: `aggregated_report.json`, produced by `malworn_aggregator.py`.
Output: HTML and/or PDF. The program does not analyze, run, or upload files.

All findings are displayed as returned by the tools. Any agent explanation is
clearly distinguished from tool evidence. No malware verdict is created here.

Requires only Python's standard library for HTML output. For PDF:
    pip install reportlab

Usage:
    python report_generator.py --input examples/aggregated_report.json --format both \
        --output examples/malworn_analysis_report

From another Python module:
    from report_generator import render_html, render_pdf
    render_html(aggregated_report_dict, "analysis.html")
    render_pdf(aggregated_report_dict, "analysis.pdf")
"""
from __future__ import annotations

import argparse
from html import escape
import json
from pathlib import Path
from typing import Any, Mapping

MAX_INPUT_BYTES = 10 * 1024 * 1024  # JSON only, never raw executable samples
MAX_DISPLAY_ROWS_PER_TOOL = 10000

TOOL_NAMES = {
    "hashes": "File hashes",
    "file_type": "File type",
    "sections": "PE sections",
    "imports": "Imported libraries and APIs",
    "extra_checks": "Additional PE checks",
    "packing_indicators": "Packing and obfuscation indicators",
    "packer_signatures": "Packer signatures",
    "virustotal": "VirusTotal hash intelligence",
}
FIELD_NAMES = {
    "sha256": "SHA-256", "md5": "MD5", "sha1": "SHA-1",
    "is_pe": "PE format detected", "architecture": "Architecture",
    "detected_type": "Detected type", "section_count": "Section count",
    "entry_point_section": "Entry-point section", "raw_size": "Raw size (bytes)",
    "virtual_size": "Virtual size (bytes)", "size_bytes": "Size (bytes)",
    "import_count": "Import count", "total_imports": "Total imports",
    "present": "Present", "count": "Count", "types": "Types",
    "found": "VirusTotal record found", "detections": "Engines flagging file",
    "engines_total": "Total engines", "first_seen": "First seen",
    "last_analysis_date": "Last analysis date", "threat_label": "Reported threat label",
    "permalink": "VirusTotal report URL", "imphash": "Import hash",
    "product": "Product", "company": "Company", "source": "Source",
}
ORDER = ["hashes", "file_type", "sections", "imports", "extra_checks",
         "packing_indicators", "packer_signatures", "virustotal"]


class ReportFormatError(ValueError):
    """The aggregated report does not have the minimum expected structure."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportFormatError(f"{label} must be a JSON object")
    return value


def validate_report(report: Mapping[str, Any]) -> None:
    """Validate enough to render safely without redefining the team's contract."""
    if not isinstance(report, dict):
        raise ReportFormatError("Report must be a Python dict")
    _object(report.get("file"), "file")
    summary = _object(report.get("execution_summary"), "execution_summary")
    for list_key in ("selected_tools", "not_selected_tools", "missing_results", "failed_calls"):
        if list_key in summary and not isinstance(summary[list_key], list):
            raise ReportFormatError(f"execution_summary.{list_key} must be a list")
    results = report.get("tool_results")
    if not isinstance(results, list):
        raise ReportFormatError("tool_results must be a list")
    for index, result in enumerate(results):
        item = _object(result, f"tool_results[{index}]")
        if not isinstance(item.get("tool"), str):
            raise ReportFormatError(f"tool_results[{index}].tool must be a string")
        if item.get("execution_status") not in ("success", "failure", "skipped"):
            raise ReportFormatError(f"tool_results[{index}].execution_status is not supported")
        if not isinstance(item.get("data", {}), (dict, list)):
            raise ReportFormatError(f"tool_results[{index}].data must be an object or list")
        if not isinstance(item.get("warnings", []), list):
            raise ReportFormatError(f"tool_results[{index}].warnings must be a list")


def load_report(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ReportFormatError("JSON input exceeds the 10 MB display limit")
    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    validate_report(report)
    return report


def _label(field: str) -> str:
    return FIELD_NAMES.get(field, field.replace("_", " ").strip().capitalize())


def _display(value: Any) -> str:
    if value is None:
        return "Not available"
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value if value else "(empty)"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _iter_leaves(value: Any, prefix: str = "", depth: int = 0):
    """Yield human-readable (field, value) rows without making inferences."""
    if depth > 32:
        yield (prefix or "value", "[display depth exceeded]")
    elif isinstance(value, dict):
        if not value:
            yield (prefix or "data", "(empty object)")
        for key, child in value.items():
            segment = _label(str(key))
            yield from _iter_leaves(child, f"{prefix} / {segment}" if prefix else segment, depth + 1)
    elif isinstance(value, list):
        if not value:
            yield (prefix or "data", "(empty list)")
        for i, child in enumerate(value, 1):
            yield from _iter_leaves(child, f"{prefix} / item {i}" if prefix else f"Item {i}", depth + 1)
    else:
        yield (prefix or "value", _display(value))


def _generic_tables(data: Any) -> list[dict[str, Any]]:
    rows = list(_iter_leaves(data))[:MAX_DISPLAY_ROWS_PER_TOOL]
    return [{"title": "Reported fields", "headers": ["Field", "Reported value"], "rows": rows}]


def _sections_tables(data: dict[str, Any], name: str) -> list[dict[str, Any]]:
    collection_key = "sections" if name == "sections" else "per_section"
    items = data.get(collection_key)
    tables: list[dict[str, Any]] = []
    ordinary = {key: value for key, value in data.items() if key != collection_key}
    if ordinary:
        tables.extend(_generic_tables(ordinary))
    if isinstance(items, list):
        section_rows = []
        for item in items:
            if not isinstance(item, dict):
                section_rows.append([_display(item), "-", "-", "-"])
            else:
                section_rows.append([
                    _display(item.get("name")), _display(item.get("raw_size")),
                    _display(item.get("virtual_size")), _display(item.get("entropy")),
                ])
        tables.append({"title": "Sections", "headers": ["Section", "Raw bytes", "Virtual bytes", "Entropy"], "rows": section_rows})
        # Retain any additional section fields not covered by columns.
        more = [{k: v for k, v in item.items() if k not in ("name", "raw_size", "virtual_size", "entropy")}
                if isinstance(item, dict) else {} for item in items]
        if any(more):
            tables.append({"title": "Additional section fields", "headers": ["Field", "Reported value"],
                           "rows": list(_iter_leaves(more))[:MAX_DISPLAY_ROWS_PER_TOOL]})
    return tables or _generic_tables(data)


def _imports_tables(data: dict[str, Any]) -> list[dict[str, Any]]:
    tables: list[dict[str, Any]] = []
    metadata = {k: v for k, v in data.items() if k != "dlls"}
    if metadata:
        tables.extend(_generic_tables(metadata))
    dlls = data.get("dlls")
    if isinstance(dlls, list):
        rows = []
        for item in dlls:
            if isinstance(item, dict):
                funcs = item.get("functions", [])
                rows.append((str(item.get("dll", "Not available")),
                             ", ".join(str(x) for x in funcs) if isinstance(funcs, list) else _display(funcs)))
            else:
                rows.append((_display(item), ""))
        tables.append({"title": "Imports by DLL", "headers": ["DLL", "Imported functions"], "rows": rows})
        extras = [{k: v for k, v in d.items() if k not in ("dll", "functions")}
                  if isinstance(d, dict) else {} for d in dlls]
        if any(extras):
            tables.append({"title": "Additional import fields", "headers": ["Field", "Reported value"],
                           "rows": list(_iter_leaves(extras))[:MAX_DISPLAY_ROWS_PER_TOOL]})
    return tables or _generic_tables(data)


def _tool_tables(tool: str, data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return _generic_tables(data)
    if tool in ("sections", "packing_indicators"):
        return _sections_tables(data, tool)
    if tool == "imports":
        return _imports_tables(data)
    return _generic_tables(data)


def _sort_key(result: Mapping[str, Any]) -> tuple[int, str]:
    name = str(result.get("tool", ""))
    return (ORDER.index(name) if name in ORDER else len(ORDER), name)


def build_view(report: Mapping[str, Any]) -> dict[str, Any]:
    """One presentation model shared by the HTML and PDF exporters."""
    validate_report(report)
    file_data = report["file"]
    summary = report["execution_summary"]
    results = report["tool_results"]
    sections = []
    for r in sorted(results, key=_sort_key):
        status = r["execution_status"]
        sections.append({
            "title": TOOL_NAMES.get(r["tool"], _label(r["tool"])),
            "tool": r["tool"], "call_id": str(r.get("call_id", "Unknown")),
            "status": status,
            "status_label": "Not available" if status == "failure" else status.capitalize(),
            "tables": _tool_tables(r["tool"], r.get("data", {})) if status == "success" else [],
            "warnings": [str(x) for x in r.get("warnings", [])],
            "error": str(r.get("error")) if r.get("error") else None,
            "provenance": r.get("provenance", {}) if isinstance(r.get("provenance"), dict) else {},
        })
    agent = report.get("agent_commentary")
    if not isinstance(agent, dict):
        agent = {}
    file_note = str(file_data.get("note", ""))
    mock_sources = [s["tool"] for s in sections if s["provenance"].get("source") == "mock"]
    return {
        "title": "Static Analysis Report",
        "analysis_id": str(report.get("analysis_id", "Not available")),
        "generated_at": str(report.get("generated_at", "Not available")),
        "schema_version": str(report.get("schema_version", "Not available")),
        "scope": str(report.get("analysis_scope", "static_only")),
        "file_name": str(file_data.get("filename", "Not available")),
        "file_sha256": str(file_data.get("sha256", "Not available")),
        "file_size": _display(file_data.get("size_bytes")),
        "file_note": file_note,
        "synthetic_sample": "SYNTHETIC" in file_note.upper() or "MOCK ONLY" in file_note.upper(),
        "mock_sources": mock_sources,
        "selected": list(summary.get("selected_tools", [])),
        "unselected": list(summary.get("not_selected_tools", [])),
        "missing": list(summary.get("missing_results", [])),
        "successful_calls": int(summary.get("successful_calls", 0)),
        "failed_call_count": int(summary.get("failed_call_count", 0)),
        "skipped_call_count": int(summary.get("skipped_call_count", 0)),
        "total_facts": int(summary.get("total_facts", 0)),
        "sections": sections,
        "commentary": agent.get("text") if isinstance(agent.get("text"), str) else None,
        "commentary_origin": str(agent.get("origin", "not_supplied")),
        "notice": str(report.get("notice", "No malware verdict is issued by this report builder.")),
    }


CSS = """
:root{font-family:Inter,'Segoe UI',Arial,sans-serif;color:#172b42;background:#eef3f7}
*{box-sizing:border-box} body{margin:0} .page{max-width:970px;margin:34px auto;background:white;
box-shadow:0 12px 50px rgba(14,36,62,.1);border-radius:12px;overflow:hidden}
.cover{background:#132e47;color:#fff;padding:46px 52px 42px;position:relative}
.eyebrow{font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:#8cddcb}
h1{margin:14px 0 10px;font-size:37px;line-height:1.1;letter-spacing:-.025em}
.cover p{color:#cad8e3;max-width:750px;line-height:1.65}
.band{height:6px;background:#26a891}
.content{padding:30px 52px 54px}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:26px}
.meta .cell{background:rgba(255,255,255,.075);padding:12px 14px;border-radius:8px;min-width:0}
.meta .key{font-size:10px;font-weight:700;text-transform:uppercase;color:#acc3d2;letter-spacing:.08em}
.meta .value{font-size:13px;margin-top:4px;overflow-wrap:anywhere;color:#fff}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 24px}
.metric{border:1px solid #dbe5ea;border-radius:9px;padding:15px 12px}
.metric strong{font-size:27px;color:#18394d;display:block}.metric small{color:#64768a}
h2{font-size:21px;letter-spacing:-.015em;margin:33px 0 15px;border-bottom:1px solid #dce6eb;padding-bottom:10px}
h3{font-size:16px;margin:0 0 8px;color:#15394d}
.subtle{font-size:12px;color:#6b7c8d}.callid{font-family:ui-monospace,Consolas,monospace}
.lead{line-height:1.6;color:#485d72}
.notice{background:#edf8f5;border-left:4px solid #279b86;padding:12px 15px;border-radius:4px;margin:15px 0;font-size:13px;line-height:1.55}
.mock{background:#fff5e8;border-left-color:#bb7b2d}
.tool{border:1px solid #dce5ea;border-radius:10px;padding:20px;margin:16px 0;break-inside:avoid-page}
.toolhead{display:flex;justify-content:space-between;align-items:start;gap:12px}
.status{font-size:11px;font-weight:700;border-radius:20px;padding:6px 10px;white-space:nowrap;background:#e9f4f1;color:#177968}
.status.failure{background:#f7ebeb;color:#983e43}.status.skipped{background:#f0f0f0;color:#565e64}
.tabletitle{font-size:11px;text-transform:uppercase;font-weight:800;letter-spacing:.075em;color:#617587;margin:20px 0 8px}
table{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed}
th{background:#edf3f6;color:#244458;font-weight:800;text-align:left;padding:10px 11px}
td{border-bottom:1px solid #e5ecef;padding:10px 11px;vertical-align:top;overflow-wrap:anywhere;line-height:1.45}
tr:nth-child(even) td{background:#fbfcfd}
th:first-child{width:35%}table.wide th:first-child{width:25%}
.warn{margin:9px 0;color:#74531f;font-size:12px;line-height:1.55}
.error{margin:9px 0;color:#973e43;font-size:12px;line-height:1.55}
.tags{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0 16px}
.tag{font-size:11px;background:#edf2f5;border-radius:7px;padding:6px 9px;color:#38556a}
pre{background:#f4f7f9;padding:15px;border-radius:7px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.65}
.footer{border-top:1px solid #e4ecef;color:#6d7e8f;font-size:11px;margin-top:38px;padding-top:16px}
@media(max-width:640px){.page{margin:0;border-radius:0}.cover{padding:30px 22px}.content{padding:20px 22px}.meta{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}h1{font-size:30px}}
@media print{@page{size:A4;margin:13mm}.page{margin:0;box-shadow:none;max-width:none;border-radius:0}
.cover{print-color-adjust:exact;-webkit-print-color-adjust:exact}.metric,.tool,th{print-color-adjust:exact;-webkit-print-color-adjust:exact}
.tool{break-inside:auto}table{break-inside:auto}tr{break-inside:avoid}h2,h3{break-after:avoid}}
"""


def _html_table(table: Mapping[str, Any]) -> str:
    headers = list(table.get("headers", []))
    rows = list(table.get("rows", []))
    if not rows:
        return '<p class="subtle">No fields returned.</p>'
    wide = "wide" if len(headers) > 2 else ""
    out = [f'<div class="tabletitle">{escape(str(table.get("title", "")))}</div>',
           f'<table class="{wide}"><thead><tr>']
    out.extend(f"<th>{escape(str(h))}</th>" for h in headers)
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>" + "".join(f"<td>{escape(_display(v))}</td>" for v in row) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _tag_list(values: list[str], *, empty: str) -> str:
    if not values:
        return f'<span class="subtle">{escape(empty)}</span>'
    return '<div class="tags">' + ''.join(f'<span class="tag">{escape(str(t))}</span>' for t in values) + '</div>'


def html_document(report: Mapping[str, Any]) -> str:
    """Produce a complete standalone HTML string. All data is escaped."""
    v = build_view(report)
    h = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<title>Malworn | Static Analysis Report</title>',
        f'<style>{CSS}</style></head><body><main class="page">',
        '<header class="cover"><div class="eyebrow">Malworn / Malware Analysis Assistant</div>',
        '<h1>Static Analysis Report</h1>',
        '<p>Tool-attributed evidence collected during a static-only analysis. This document does not constitute a malware verdict.</p>',
        '<div class="meta">',
    ]
    for label, value in [
        ("Filename", v["file_name"]), ("SHA-256", v["file_sha256"]),
        ("File size (bytes)", v["file_size"]), ("Generated at (UTC / offset)", v["generated_at"]),
        ("Analysis ID", v["analysis_id"]), ("Scope", v["scope"]),
    ]:
        h.append(f'<div class="cell"><div class="key">{escape(label)}</div><div class="value">{escape(value)}</div></div>')
    h.append('</div></header><div class="band"></div><div class="content">')
    if v["synthetic_sample"]:
        h.append('<p class="notice mock"><strong>Synthetic demonstration:</strong> These values do not describe an actual scanned sample.</p>')
    if v["mock_sources"]:
        h.append('<p class="notice mock"><strong>Mock tool output:</strong> '
                 + escape(", ".join(v["mock_sources"])) + '. These values are not live intelligence.</p>')
    h.append('<h2>1. Execution overview</h2>')
    h.append('<div class="metrics">')
    for number, label in [
        (len(v["selected"]), "Tools selected"), (v["successful_calls"], "Successful calls"),
        (v["failed_call_count"], "Failed calls"), (v["total_facts"], "Recorded facts")
    ]:
        h.append(f'<div class="metric"><strong>{number}</strong><small>{escape(label)}</small></div>')
    h.append('</div>')
    h.append('<p class="lead">Only tools selected by the agent are represented as executed. Not-selected tools are not failures. '
             'A failed tool is marked unavailable rather than silently omitted.</p>')
    h.append('<div class="tabletitle">Agent-selected tools</div>' + _tag_list(v["selected"], empty="None"))
    h.append('<div class="tabletitle">Not selected</div>' + _tag_list(v["unselected"], empty="None"))
    h.append('<div class="tabletitle">Selected but missing a result</div>' + _tag_list(v["missing"], empty="None"))
    h.append('<h2>2. Tool evidence</h2>')
    if not v["sections"]:
        h.append('<p class="notice">No tool output was supplied. The report contains no analysis findings.</p>')
    for s in v["sections"]:
        status = s["status"]
        h.append('<section class="tool">')
        h.append('<div class="toolhead"><div><h3>' + escape(s["title"]) + '</h3><div class="subtle">'
                 + 'Source tool: <code>' + escape(s["tool"]) + '</code> &nbsp; / &nbsp; Call ID: <span class="callid">'
                 + escape(s["call_id"]) + '</span></div></div>')
        h.append(f'<span class="status {escape(status)}">{escape(s["status_label"])}</span></div>')
        if status == 'failure':
            h.append('<p class="notice">Tool result not available; no factual findings were generated for this call.</p>')
        elif status == 'skipped':
            h.append('<p class="notice">The tool call was skipped; no factual findings are shown.</p>')
        else:
            for table in s["tables"]:
                h.append(_html_table(table))
        for warning in s["warnings"]:
            h.append('<p class="warn"><strong>Tool warning:</strong> ' + escape(warning) + '</p>')
        if s["error"]:
            h.append('<p class="error"><strong>Tool error:</strong> ' + escape(s["error"]) + '</p>')
        if s["provenance"]:
            h.append('<p class="subtle">Tool execution metadata: ' + escape(json.dumps(s["provenance"], ensure_ascii=False)) + '</p>')
        h.append('</section>')
    h.append('<h2>3. AI explanation (separate from tool evidence)</h2>')
    if v["commentary"]:
        h.append('<p class="notice"><strong>Model-generated commentary:</strong> Not a verified tool finding. '
                 'Any factual statement must be checked against the source tool evidence above.</p>')
        h.append('<pre>' + escape(v["commentary"]) + '</pre>')
    else:
        h.append('<p class="subtle">No AI commentary supplied.</p>')
    h.append('<h2>4. Limitations and audit note</h2>')
    h.append('<p class="lead">This is static-only evidence. Missing VirusTotal records or zero reported detections '
             'do not establish that a file is safe. Packing indicators alone do not establish maliciousness. '
             'The report generator does not execute samples, make threat classifications, or change tool evidence.</p>')
    h.append('<p class="subtle">Contract: ' + escape(v["schema_version"]) + '</p>')
    h.append('<p class="notice">' + escape(v["notice"]) + '</p>')
    h.append('<div class="footer">Malworn • Evidence-first static analysis • Auto-generated document</div>')
    h.append('</div></main></body></html>')
    return "".join(h)


def render_html(report: Mapping[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html_document(report), encoding="utf-8")
    return target


def render_pdf(report: Mapping[str, Any], path: str | Path) -> Path:
    """Create a print-ready PDF with ReportLab (optional dependency)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, CondPageBreak,
        )
    except ImportError as exc:
        raise ReportFormatError("PDF export requires reportlab: pip install reportlab") from exc

    v = build_view(report)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    navy = colors.HexColor('#18354C')
    teal = colors.HexColor('#208D7B')
    pale = colors.HexColor('#ECF3F6')
    gray = colors.HexColor('#667B8C')
    paper = colors.HexColor('#FFFFFF')

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Brand', fontName='Helvetica-Bold', fontSize=10, textColor=teal,
                              spaceAfter=13, leading=13))
    styles.add(ParagraphStyle(name='CoverHeading', fontName='Helvetica-Bold', fontSize=27, leading=32,
                              textColor=navy, spaceAfter=10))
    styles.add(ParagraphStyle(name='Summary', fontName='Helvetica', fontSize=9.2, leading=14,
                              textColor=gray, spaceAfter=12))
    styles.add(ParagraphStyle(name='Sec', fontName='Helvetica-Bold', fontSize=14, leading=18,
                              textColor=navy, spaceBefore=18, spaceAfter=10, keepWithNext=True))
    styles.add(ParagraphStyle(name='Tool', fontName='Helvetica-Bold', fontSize=11, leading=14,
                              textColor=navy, spaceBefore=13, spaceAfter=6, keepWithNext=True))
    styles.add(ParagraphStyle(name='Micro', fontName='Helvetica', fontSize=8, leading=11.5,
                              textColor=gray, spaceAfter=7))
    styles.add(ParagraphStyle(name='BodyNew', fontName='Helvetica', fontSize=9, leading=13,
                              textColor=navy, spaceAfter=8))
    styles.add(ParagraphStyle(name='CellNew', fontName='Helvetica', fontSize=7.8, leading=11,
                              textColor=navy, splitLongWords=True))
    styles.add(ParagraphStyle(name='CellHead', fontName='Helvetica-Bold', fontSize=7.5, leading=10,
                              textColor=navy))
    styles.add(ParagraphStyle(name='Agent', fontName='Helvetica', fontSize=9, leading=14,
                              textColor=navy, spaceAfter=12))

    doc = SimpleDocTemplate(str(target), pagesize=A4, leftMargin=19*mm, rightMargin=19*mm,
                            topMargin=19*mm, bottomMargin=19*mm, title="Malworn Static Analysis Report",
                            author="Malworn", subject="Evidence-attributed static analysis")
    width = A4[0] - 38 * mm

    def P(text: Any, style: str = 'CellNew'):
        # HTML-escape untrusted values, and convert newlines only after escaping.
        safe = escape(str(text)).replace('\n', '<br/>')
        return Paragraph(safe, styles[style])

    def data_table(headers: list[str], rows: list[Any], col_widths=None):
        if not rows:
            return P('No fields returned.', 'Micro')
        n = len(headers)
        if col_widths is None:
            col_widths = [width * .33, width * .67] if n == 2 else [width/n] * n
        # All cells are Paragraphs so long text wraps rather than overlapping.
        matrix = [[P(h, 'CellHead') for h in headers]]
        for row in rows:
            matrix.append([P(_display(x)) for x in row])
        t = Table(matrix, colWidths=col_widths, repeatRows=1, hAlign='LEFT', splitByRow=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), pale),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [paper, colors.HexColor('#F9FBFC')]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('TOPPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING', (0,0), (-1,-1), 9),
            ('RIGHTPADDING', (0,0), (-1,-1), 9),
            ('LINEBELOW', (0,0), (-1,0), 0.7, colors.HexColor('#D9E5EB')),
            ('LINEBELOW', (0,1), (-1,-1), 0.3, colors.HexColor('#EDF2F5')),
        ]))
        return t

    story = [P('MALWORN  /  ANALYST EVIDENCE REPORT', 'Brand'),
             P('Static Analysis Report', 'CoverHeading'),
             P('Results are attributed to the tools that produced them. This document makes no malicious/benign verdict.', 'Summary'),
             HRFlowable(width='100%', thickness=2.0, color=teal), Spacer(1, 12)]
    metadata = [
        ('File', v['file_name']), ('SHA-256', v['file_sha256']),
        ('Size (bytes)', v['file_size']), ('Generated', v['generated_at']),
        ('Analysis ID', v['analysis_id']), ('Scope', v['scope']),
    ]
    story.append(data_table(['FILE METADATA', 'VALUE'], metadata))
    if v['synthetic_sample']:
        story.extend([Spacer(1, 12), P('SYNTHETIC DEMONSTRATION: These values do not describe an actual scanned sample.', 'BodyNew')])
    if v['mock_sources']:
        story.append(P('MOCK DATA SOURCES: ' + ', '.join(v['mock_sources']), 'BodyNew'))
    story.append(P('1. Execution overview', 'Sec'))
    story.append(data_table(['METRIC', 'VALUE'], [
        ('Tools selected', len(v['selected'])), ('Successful calls', v['successful_calls']),
        ('Failed calls', v['failed_call_count']), ('Skipped calls', v['skipped_call_count']),
        ('Attributed facts', v['total_facts']),
    ]))
    story.append(Spacer(1, 7))
    for label, values in [
        ('Selected tools', v['selected']), ('Not selected', v['unselected']),
        ('Selected but missing results', v['missing'])
    ]:
        story.append(P(label + ': ' + (', '.join(map(str, values)) if values else 'None'), 'Micro'))
    story.append(P('2. Tool evidence', 'Sec'))
    if not v['sections']:
        story.append(P('No tool results were supplied.', 'BodyNew'))
    for s in v['sections']:
        story.append(CondPageBreak(100))
        story.append(P(s['title'] + '  |  ' + s['status_label'], 'Tool'))
        story.append(P('Source: ' + s['tool'] + '   /   Call ID: ' + s['call_id'], 'Micro'))
        if s['status'] == 'failure':
            story.append(P('Not available: tool returned a failure. No findings are shown for this call.', 'BodyNew'))
        elif s['status'] == 'skipped':
            story.append(P('Tool call was skipped; no findings are shown.', 'BodyNew'))
        else:
            for block in s['tables']:
                story.append(P(block['title'], 'Micro'))
                widths = ([width * .21, width * .26, width * .26, width * .27]
                          if len(block['headers']) == 4 else None)
                story.append(data_table(block['headers'], block['rows'], widths))
                story.append(Spacer(1, 8))
        for warning in s['warnings']:
            story.append(P('Tool warning: ' + warning, 'Micro'))
        if s['error']:
            story.append(P('Tool error: ' + s['error'], 'Micro'))
        if s['provenance']:
            story.append(P('Execution metadata: ' + json.dumps(s['provenance'], ensure_ascii=False), 'Micro'))
        story.append(Spacer(1, 5))
    story.append(P('3. AI explanation', 'Sec'))
    story.append(P('Model commentary is not verified tool evidence. Check factual claims against the source tool results.', 'Summary'))
    if v['commentary']:
        story.append(P(v['commentary'], 'Agent'))
    else:
        story.append(P('No AI commentary supplied.', 'Micro'))
    story.append(P('4. Analysis limitations', 'Sec'))
    story.append(P('Static-only evidence. A missing VirusTotal record or zero detections is not proof of safety. '
                   'Packing indicators alone do not prove maliciousness. No threat verdict is generated by this report.', 'BodyNew'))
    story.append(P('JSON contract: ' + v['schema_version'], 'Micro'))
    story.append(P(v['notice'], 'Micro'))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor('#DBE6EB'))
        canvas.line(document.leftMargin, 16*mm, A4[0]-document.rightMargin, 16*mm)
        canvas.setFillColor(gray)
        canvas.setFont('Helvetica', 8)
        canvas.drawString(document.leftMargin, 12*mm, 'MALWORN / STATIC ANALYSIS / EVIDENCE ONLY')
        canvas.drawRightString(A4[0]-document.rightMargin, 12*mm, f'Page {document.page}')
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Render the aggregated Malworn JSON as HTML and/or PDF')
    parser.add_argument('--input', required=True, help='Path to aggregated_report.json')
    parser.add_argument('--output', required=True, help='Output basename (extension optional)')
    parser.add_argument('--format', choices=['html','pdf','both'], default='both')
    args = parser.parse_args(argv)
    try:
        report = load_report(args.input)
        base = Path(args.output)
        if base.suffix.lower() in ('.html','.pdf'):
            base = base.with_suffix('')
        if args.format in ('html','both'):
            print('Wrote HTML:', render_html(report, base.with_suffix('.html')))
        if args.format in ('pdf','both'):
            print('Wrote PDF:', render_pdf(report, base.with_suffix('.pdf')))
    except (ReportFormatError, OSError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f'Report generation failed: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
