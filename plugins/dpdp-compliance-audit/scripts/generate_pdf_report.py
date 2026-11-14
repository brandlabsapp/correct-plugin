#!/usr/bin/env python3
"""
DPDPA Compliance Report — PDF renderer

Renders a properly formatted PDF *directly from the scanner's JSON report*
(the object dpdp_scanner.py produces with --json) — not from the flattened
Markdown text. Markdown throws away the structure (which row is CRITICAL,
which block is a remediation step) that this renderer needs to produce real
bordered tables, severity color coding, and callout boxes. Use md-to-pdf.py
for arbitrary Markdown files; use this specifically for the DPDPA report.

Deps: fpdf2>=2.7.4 (pip install --user fpdf2)
Usage:
  python3 generate_pdf_report.py <report.json> [output.pdf] \
      [--company-name NAME] [--company-uuid UUID]
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Palette — kept in one place so severity/status colors are consistent
# across the score matrix, finding cards, and penalty table.
# ---------------------------------------------------------------------------

WHITE = (255, 255, 255)
DARK = (33, 37, 41)
MUTED = (108, 117, 125)
BORDER = (222, 226, 230)
PAGE_BG = (250, 250, 251)
BRAND = (30, 64, 175)  # Correct brand blue — swap for the exact hex if provided

CRITICAL = (217, 48, 37)
HIGH = (217, 119, 6)
MEDIUM = (202, 138, 4)
LOW = (100, 116, 139)
INFO = (37, 99, 235)
GOOD = (21, 128, 61)

SEVERITY_FILL = {
    "CRITICAL": (250, 219, 216),
    "HIGH": (254, 235, 200),
    "MEDIUM": (254, 243, 199),
    "LOW": (226, 232, 240),
    "INFO": (219, 234, 254),
}
SEVERITY_TEXT = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
    "INFO": INFO,
}

STATUS_FILL = {
    "PASS": (215, 245, 227),
    "GOOD": (223, 240, 216),
    "NEEDS_ATTENTION": (254, 243, 199),
    "WARNING": (254, 226, 189),
    "CRITICAL": (250, 219, 216),
}
STATUS_TEXT = {
    "PASS": GOOD,
    "GOOD": GOOD,
    "NEEDS_ATTENTION": MEDIUM,
    "WARNING": HIGH,
    "CRITICAL": CRITICAL,
}

OVERALL_COLOR = {
    "COMPLIANT": GOOD,
    "MOSTLY_COMPLIANT": (22, 163, 120),
    "NEEDS_ATTENTION": (202, 138, 4),
    "AT_RISK": HIGH,
    "NON_COMPLIANT": CRITICAL,
}


def clean(value) -> str:
    """Make any value latin-1 safe for the built-in Helvetica/Courier fonts."""
    if value is None:
        return ""
    text = str(value)
    text = (
        text.replace("—", "-")
        .replace("–", "-")
        .replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("…", "...")
    )
    text = text.replace("₹", "Rs. ")
    text = (
        text.replace("✅", "[OK]")
        .replace("🟢", "[OK]")
        .replace("🟡", "[!]")
        .replace("🟠", "[!]")
        .replace("🔴", "[!!]")
        .replace("⚠️", "[!]")
        .replace("❓", "?")
    )
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        text = text.encode("latin-1", "replace").decode("latin-1")
    # Soft-break only pathologically long unbroken tokens (e.g. long URLs) so
    # cells never overflow — threshold set above typical file-path lengths so
    # ordinary paths don't get a space forced into the middle of a filename.
    text = re.sub(r"(\S{90})(?=\S)", r"\1 ", text)
    return text


def _import_fpdf():
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
        from fpdf.fonts import FontFace

        return FPDF, XPos, YPos, FontFace
    except ImportError as e:
        die(f"fpdf2>=2.7.4 required: pip3 install --user fpdf2 ({e})")


def build_pdf(report: dict, company_name: str | None, company_uuid: str | None):
    FPDF, XPos, YPos, FontFace = _import_fpdf()

    class ReportPDF(FPDF):
        def header(self):
            if self.page_no() == 1:
                return
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*MUTED)
            self.set_xy(self.l_margin, 8)
            self.cell(0, 6, clean("DPDPA Compliance Audit"), align="L")
            self.ln(10)

        def footer(self):
            self.set_y(-14)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(*MUTED)
            self.cell(
                0,
                8,
                clean(f"Correct - DPDPA Compliance Audit - Page {self.page_no()}"),
                align="C",
            )

    pdf = ReportPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(left=16, top=16, right=16)
    pdf.add_page()
    usable_w = pdf.w - pdf.l_margin - pdf.r_margin

    def h_rule(gap_before=2, gap_after=3, color=BORDER):
        pdf.ln(gap_before)
        pdf.set_draw_color(*color)
        y = pdf.get_y()
        pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
        pdf.ln(gap_after)

    def heading(text, size=13, color=DARK, gap_before=4, gap_after=2):
        pdf.ln(gap_before)
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(*color)
        pdf.cell(0, 8, clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(gap_after)

    def body(text, size=10, style="", color=DARK, line_h=5.2):
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", style, size)
        pdf.set_text_color(*color)
        pdf.multi_cell(usable_w, line_h, clean(text))

    def callout(text, fill, border, text_color=DARK, icon="i", size=9):
        pdf.set_x(pdf.l_margin)
        x0, y0 = pdf.get_x(), pdf.get_y()
        pdf.set_font("Helvetica", "", size)
        line_h = 5
        full_text = clean(f"[{icon}] {text}")
        # dry_run measures wrapped height without drawing, so the box behind
        # the text is sized correctly with a single real draw of the text.
        text_h = pdf.multi_cell(usable_w - 8, line_h, full_text, dry_run=True, output="HEIGHT")
        box_h = text_h + 6
        pdf.set_fill_color(*fill)
        pdf.set_draw_color(*border)
        pdf.rect(x0, y0, usable_w, box_h, style="DF")
        pdf.set_xy(x0 + 4, y0 + 3)
        pdf.set_text_color(*text_color)
        pdf.multi_cell(usable_w - 8, line_h, full_text)
        pdf.set_xy(x0, y0 + box_h + 4)

    # ------------------------------------------------------------------
    # Cover / header block
    # ------------------------------------------------------------------
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*DARK)
    pdf.cell(0, 12, clean("DPDPA Compliance Audit Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*MUTED)
    meta_line = f"Project: {Path(report['workspace']).name}"
    if company_name:
        meta_line += f"  |  Organisation: {company_name}"
    if company_uuid:
        meta_line += f" ({company_uuid})"
    pdf.cell(0, 6, clean(meta_line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(
        0,
        6,
        clean(
            f"Date: {report['scan_timestamp']}  |  Target type: {report['target_type']}  |  "
            f"Files scanned: {report['total_files_scanned']}"
        ),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )

    sector = report.get("sector", {})
    sector_name = sector.get("sector", "general").replace("_", " ").title()
    pdf.cell(
        0,
        6,
        clean(f"Detected Sector: {sector_name} ({sector.get('confidence', 'low')} confidence)"),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.ln(3)

    # Overall score banner
    score_color = OVERALL_COLOR.get(report["overall_status"], LOW)
    banner_h = 18
    x0, y0 = pdf.l_margin, pdf.get_y()
    pdf.set_fill_color(*score_color)
    pdf.rect(x0, y0, usable_w, banner_h, style="F")
    pdf.set_xy(x0, y0)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(
        usable_w,
        banner_h,
        clean(f"Overall Compliance Score: {report['overall_score']} / 100  -  {report['overall_status']}"),
        align="C",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_y(y0 + banner_h + 4)

    callout(
        "Penalty figures cite the DPDPA Schedule (Section 33) as reproduced by dpdpa.com, a "
        "secondary legal-reference source, not the official Gazette. This report is not legal "
        "advice; verify exact figures before relying on them for a real compliance decision.",
        fill=(219, 234, 254),
        border=(191, 219, 254),
        text_color=(30, 58, 138),
        icon="i",
        size=8,
    )

    if sector.get("advisory"):
        callout(
            sector["advisory"],
            fill=(254, 243, 199),
            border=(253, 224, 71),
            text_color=(113, 63, 18),
            icon="sector",
            size=8,
        )

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------
    s = report["summary"]
    heading("1. Executive Summary", gap_before=2)
    pillars = report["pillar_scores"]
    sorted_pillars = sorted(pillars.items(), key=lambda x: x[1]["score"])
    weakest_id, weakest = sorted_pillars[0]
    strongest_id, strongest = sorted_pillars[-1]
    body(
        f"This audit scanned {report['total_files_scanned']} files. Strongest area: "
        f"{strongest['name']} ({strongest['score']}%). Weakest area: {weakest['name']} "
        f"({weakest['score']}%)."
    )
    pdf.ln(1)

    # Severity summary strip — small colored count chips
    chip_order = [("CRITICAL", s["CRITICAL"]), ("HIGH", s["HIGH"]), ("MEDIUM", s["MEDIUM"]), ("LOW", s["LOW"])]
    chip_w = usable_w / len(chip_order)
    x0 = pdf.l_margin
    y0 = pdf.get_y()
    for sev, count in chip_order:
        pdf.set_xy(x0, y0)
        pdf.set_fill_color(*SEVERITY_FILL[sev])
        pdf.set_draw_color(*BORDER)
        pdf.rect(x0, y0, chip_w - 2, 14, style="DF")
        pdf.set_xy(x0, y0 + 2)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*SEVERITY_TEXT[sev])
        pdf.cell(chip_w - 2, 6, clean(str(count)), align="C")
        pdf.set_xy(x0, y0 + 8)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*MUTED)
        pdf.cell(chip_w - 2, 5, clean(sev), align="C")
        x0 += chip_w
    pdf.set_xy(pdf.l_margin, y0 + 17)

    # ------------------------------------------------------------------
    # Compliance score matrix
    # ------------------------------------------------------------------
    heading("2. Compliance Score Matrix")
    col_w = (usable_w * 0.28, usable_w * 0.1, usable_w * 0.17, usable_w * 0.1, usable_w * 0.35)
    with pdf.table(
        col_widths=col_w,
        text_align=("LEFT", "CENTER", "CENTER", "CENTER", "LEFT"),
        line_height=5.5,
        first_row_as_headings=True,
        headings_style=FontFace(emphasis="BOLD", fill_color=(241, 245, 249), color=DARK, size_pt=9),
        borders_layout="ALL",
    ) as table:
        header_row = table.row()
        for col in ("Pillar", "Score", "Status", "Findings", "Max Penalty"):
            header_row.cell(clean(col))
        for pid, pdata in pillars.items():
            row = table.row()
            row.cell(clean(pdata["name"]), style=FontFace(size_pt=9))
            row.cell(clean(f"{pdata['score']}%"), style=FontFace(size_pt=9))
            row.cell(
                clean(pdata["status"]),
                style=FontFace(
                    fill_color=STATUS_FILL.get(pdata["status"], WHITE),
                    color=STATUS_TEXT.get(pdata["status"], DARK),
                    emphasis="BOLD",
                    size_pt=8,
                ),
            )
            row.cell(clean(str(pdata["findings_count"])), style=FontFace(size_pt=9))
            row.cell(clean(pdata["max_penalty"]), style=FontFace(size_pt=7.5))

    # ------------------------------------------------------------------
    # Critical & High findings — grouped by finding type, not repeated
    # per-instance, so recurring issues read as one problem + one fix
    # instead of N nearly-identical cards.
    # ------------------------------------------------------------------
    ch_findings = [f for f in report["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
    ch_warnings = [w for w in report["global_warnings"] if w["severity"] in ("CRITICAL", "HIGH")]

    grouped = defaultdict(list)
    for f in ch_findings:
        grouped[f["id"]].append(f)

    heading("3. Critical & High Severity Findings")
    if not grouped and not ch_warnings:
        body("No critical or high severity findings were detected.", color=GOOD)
    else:
        for fid, items in sorted(grouped.items(), key=lambda kv: (kv[1][0]["severity"] != "CRITICAL",)):
            first = items[0]
            sev = first["severity"]
            _finding_card(
                pdf, XPos, YPos,
                title=f"{fid}",
                severity=sev,
                pillar=pillars.get(first["pillar"], {}).get("name", first["pillar"]),
                section=first["dpdpa_section"],
                penalty=first["penalty"],
                description=first["description"],
                remediation=first["remediation"],
                locations=[f"{Path(f['file']).as_posix()}:{f['line']}" for f in items],
                usable_w=usable_w,
                clean=clean,
            )
        for w in ch_warnings:
            _finding_card(
                pdf, XPos, YPos,
                title=f"{w['id']} (architectural)",
                severity=w["severity"],
                pillar=pillars.get(w["pillar"], {}).get("name", w["pillar"]),
                section=w["dpdpa_section"],
                penalty=w["penalty"],
                description=w["description"],
                remediation=w["remediation"],
                locations=["Project-wide / architecture"],
                usable_w=usable_w,
                clean=clean,
            )

    # ------------------------------------------------------------------
    # Penalty risk matrix — grouped the same way, with an occurrence count
    # ------------------------------------------------------------------
    heading("4. Penalty Risk Matrix")
    all_groups = []
    for fid, items in grouped.items():
        first = items[0]
        all_groups.append(
            {
                "id": fid,
                "severity": first["severity"],
                "section": first["dpdpa_section"],
                "penalty": first["penalty"],
                "occurrences": len(items),
            }
        )
    for w in report["global_warnings"]:
        all_groups.append(
            {
                "id": w["id"],
                "severity": w["severity"],
                "section": w["dpdpa_section"],
                "penalty": w["penalty"],
                "occurrences": 1,
            }
        )
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_groups.sort(key=lambda g: severity_rank.get(g["severity"], 9))

    if not all_groups:
        body("No compliance risks or potential penalties detected.", color=GOOD)
    else:
        col_w = (usable_w * 0.28, usable_w * 0.12, usable_w * 0.12, usable_w * 0.3, usable_w * 0.18)
        with pdf.table(
            col_widths=col_w,
            line_height=5.5,
            first_row_as_headings=True,
            headings_style=FontFace(emphasis="BOLD", fill_color=(241, 245, 249), color=DARK, size_pt=9),
            borders_layout="ALL",
        ) as table:
            header_row = table.row()
            for col in ("Finding", "Severity", "Occurrences", "DPDPA Section", "Max Penalty"):
                header_row.cell(clean(col))
            for g in all_groups:
                row = table.row()
                row.cell(clean(g["id"]), style=FontFace(size_pt=8.5))
                row.cell(
                    clean(g["severity"]),
                    style=FontFace(
                        fill_color=SEVERITY_FILL.get(g["severity"], WHITE),
                        color=SEVERITY_TEXT.get(g["severity"], DARK),
                        emphasis="BOLD",
                        size_pt=8,
                    ),
                )
                row.cell(clean(str(g["occurrences"])), style=FontFace(size_pt=8.5))
                row.cell(clean(g["section"]), style=FontFace(size_pt=7.5))
                row.cell(clean(g["penalty"]), style=FontFace(size_pt=7))

    # ------------------------------------------------------------------
    # Remediation roadmap
    # ------------------------------------------------------------------
    heading("5. Remediation Roadmap")
    _roadmap_section(
        pdf, XPos, YPos, clean,
        title="Immediate (0-72 hours) - Critical issues",
        color=CRITICAL,
        fill=SEVERITY_FILL["CRITICAL"],
        items=[g for g in all_groups if g["severity"] == "CRITICAL"],
        usable_w=usable_w,
    )
    _roadmap_section(
        pdf, XPos, YPos, clean,
        title="Short-Term (1-2 weeks) - High severity issues",
        color=HIGH,
        fill=SEVERITY_FILL["HIGH"],
        items=[g for g in all_groups if g["severity"] == "HIGH"],
        usable_w=usable_w,
    )
    medium_items = [
        f for f in report["findings"] if f["severity"] in ("MEDIUM", "LOW")
    ] + [w for w in report["global_warnings"] if w["severity"] in ("MEDIUM", "LOW")]
    medium_grouped = defaultdict(int)
    medium_meta = {}
    for item in medium_items:
        medium_grouped[item["id"]] += 1
        medium_meta[item["id"]] = item
    _roadmap_section(
        pdf, XPos, YPos, clean,
        title="Medium-Term (1 month) - Medium/low severity & architecture gaps",
        color=MEDIUM,
        fill=SEVERITY_FILL["MEDIUM"],
        items=[
            {"id": fid, "severity": "MEDIUM", "occurrences": count}
            for fid, count in medium_grouped.items()
        ],
        usable_w=usable_w,
    )

    heading("Ongoing - Governance & Monitoring", size=11, gap_before=3)
    for line in [
        "Schedule quarterly DPDPA compliance scans",
        "Conduct an annual independent security audit (if Significant Data Fiduciary-designated)",
        "Maintain immutable consent telemetry logs",
        "Run a DPIA before each major feature release",
    ]:
        body(f"- {line}", size=9.5)

    return pdf


def _finding_card(pdf, XPos, YPos, *, title, severity, pillar, section, penalty, description, remediation, locations, usable_w, clean):
    sev_color = SEVERITY_TEXT.get(severity, DARK)
    sev_fill = SEVERITY_FILL.get(severity, WHITE)

    # rect() (used for the severity bar/badge/remediation box) is NOT
    # page-break-aware the way cell()/multi_cell() are, so mid-card auto
    # breaks tear a card's header away from its body, leaving orphaned
    # fragments alone on otherwise-blank pages. Pre-measure the whole card
    # and force a page break *before* it starts if it won't fit whole.
    body_w = usable_w - 3 - 2
    meta_h = pdf.multi_cell(body_w, 4.5, clean(f"Pillar: {pillar}  |  {section}  |  Penalty: {penalty}"), dry_run=True, output="HEIGHT")
    desc_h = pdf.multi_cell(body_w, 4.8, clean(description), dry_run=True, output="HEIGHT")
    shown = locations[:6]
    loc_text = "; ".join(shown)
    if len(locations) > 6:
        loc_text += f"; and {len(locations) - 6} more"
    loc_h = pdf.multi_cell(body_w, 4.3, clean(f"Locations: {loc_text}"), dry_run=True, output="HEIGHT")
    fix_h = pdf.multi_cell(body_w - 6, 4.3, clean(f"Fix: {remediation}"), dry_run=True, output="HEIGHT")
    card_h = 2 + 7 + meta_h + desc_h + loc_h + (fix_h + 4) + 5 + 8

    if pdf.get_y() + card_h > pdf.page_break_trigger and pdf.get_y() > pdf.t_margin + 5:
        pdf.add_page()

    pdf.ln(2)
    x0 = pdf.l_margin
    y0 = pdf.get_y()

    # Severity bar + title
    bar_w = 3
    pdf.set_fill_color(*sev_color)
    pdf.rect(x0, y0, bar_w, 7, style="F")
    pdf.set_xy(x0 + bar_w + 2, y0)
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*DARK)
    pdf.cell(usable_w - bar_w - 2 - 22, 7, clean(title))
    pdf.set_xy(pdf.w - pdf.r_margin - 20, y0)
    pdf.set_fill_color(*sev_fill)
    pdf.set_text_color(*sev_color)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(20, 7, clean(severity), align="C", fill=True)
    pdf.set_xy(x0 + bar_w + 2, y0 + 7)

    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(usable_w - bar_w - 2, 4.5, clean(f"Pillar: {pillar}  |  {section}  |  Penalty: {penalty}"))

    pdf.set_x(x0 + bar_w + 2)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*DARK)
    pdf.multi_cell(usable_w - bar_w - 2, 4.8, clean(description))

    pdf.set_x(x0 + bar_w + 2)
    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(usable_w - bar_w - 2, 4.3, clean(f"Locations: {loc_text}"))

    # Remediation callout
    pdf.set_x(x0 + bar_w + 2)
    rx, ry = pdf.get_x(), pdf.get_y()
    pdf.set_font("Helvetica", "", 8.7)
    box_w = usable_w - bar_w - 2
    fix_text = clean(f"Fix: {remediation}")
    text_h = pdf.multi_cell(box_w - 6, 4.3, fix_text, dry_run=True, output="HEIGHT")
    box_h = text_h + 4
    pdf.set_fill_color(223, 240, 216)
    pdf.rect(rx, ry, box_w, box_h, style="F")
    pdf.set_xy(rx + 3, ry + 2)
    pdf.set_text_color(21, 87, 36)
    pdf.multi_cell(box_w - 6, 4.3, fix_text)
    pdf.set_xy(x0, ry + box_h + 5)

    pdf.set_draw_color(*BORDER)
    pdf.line(x0, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)


def _roadmap_section(pdf, XPos, YPos, clean, *, title, color, fill, items, usable_w):
    pdf.ln(2)
    x0, y0 = pdf.l_margin, pdf.get_y()
    pdf.set_fill_color(*fill)
    pdf.rect(x0, y0, usable_w, 7, style="F")
    pdf.set_xy(x0 + 2, y0)
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*color)
    pdf.cell(usable_w - 4, 7, clean(title))
    pdf.set_xy(x0, y0 + 9)

    if not items:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*GOOD)
        pdf.cell(0, 5, clean("[x] Nothing outstanding at this priority."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        return

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*DARK)
    for item in items:
        occ = item.get("occurrences", 1)
        suffix = f" ({occ} occurrence{'s' if occ != 1 else ''})" if occ else ""
        pdf.set_x(x0 + 2)
        pdf.multi_cell(usable_w - 2, 5, clean(f"[ ] Fix {item['id']}{suffix}"))


def convert(json_path: Path, pdf_path: Path, company_name: str | None, company_uuid: str | None) -> None:
    with open(json_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    pdf = build_pdf(report, company_name, company_uuid)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(pdf_path))
    print(f"pdf: {pdf_path}")
    print(f"bytes: {pdf_path.stat().st_size}")


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        raise SystemExit(0 if args else 1)

    positional = []
    company_name = None
    company_uuid = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--company-name" and i + 1 < len(args):
            i += 1
            company_name = args[i]
        elif a == "--company-uuid" and i + 1 < len(args):
            i += 1
            company_uuid = args[i]
        else:
            positional.append(a)
        i += 1

    if not positional:
        die("usage: generate_pdf_report.py <report.json> [output.pdf]")

    json_path = Path(positional[0]).expanduser().resolve()
    if not json_path.is_file():
        die(f"file not found: {json_path}")

    if len(positional) >= 2:
        out = Path(positional[1]).expanduser().resolve()
    else:
        out = json_path.with_suffix(".pdf")

    convert(json_path, out, company_name, company_uuid)


if __name__ == "__main__":
    main()
