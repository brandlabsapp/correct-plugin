#!/usr/bin/env python3
"""Convert Markdown report → PDF (offline, no browser).

Deps: fpdf2 (pip install fpdf2). Falls back to plain-text layout if unavailable.
Usage:
  python3 md-to-pdf.py <input.md> [output.pdf]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def strip_md_inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text


def clean_pdf_text(text: str) -> str:
    """Replace non-latin-1 characters and emojis with safe equivalents to avoid '?' rendering."""
    # Standardise dashes
    text = text.replace("—", "-").replace("–", "-")
    
    # Replace Indian Rupee symbol
    text = text.replace("₹", "INR ")
    
    # Replace status emojis
    text = text.replace("✅", "[PASS]").replace("🟢", "[GOOD]").replace("🟡", "[NEEDS ATTENTION]").replace("🟠", "[WARNING]").replace("🔴", "[CRITICAL]").replace("ℹ️", "[INFO]").replace("⚠️", "[WARNING]")
    
    # Remove styling/bullet emojis
    text = text.replace("📊", "").replace("📋", "").replace("⚖️", "").replace("⏳", "")
    
    return text


def convert(md_path: Path, pdf_path: Path) -> None:
    try:
        from fpdf import FPDF
    except ImportError as e:
        die(f"fpdf2 required: pip3 install --user fpdf2 ({e})")

    raw = md_path.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(left=18, top=18, right=18)
    pdf.add_page()
    usable_w = pdf.w - pdf.l_margin - pdf.r_margin

    def write_body(text: str, size: int = 10, style: str = "") -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", style, size)
        cleaned = clean_pdf_text(text)
        safe = strip_md_inline(cleaned).encode("latin-1", "replace").decode("latin-1")
        # Soft-break very long tokens so Helvetica never overflows
        safe = re.sub(r"(\S{80})", r"\1 ", safe)
        if not safe.strip():
            pdf.ln(3)
            return
        pdf.multi_cell(usable_w, 5, safe)

    for line in lines:
        s = line.rstrip()
        if not s.strip():
            pdf.ln(3)
            continue
        if s.startswith("# "):
            pdf.ln(4)
            write_body(s[2:].strip(), size=16, style="B")
            pdf.ln(2)
            continue
        if s.startswith("## "):
            pdf.ln(3)
            write_body(s[3:].strip(), size=13, style="B")
            pdf.ln(1)
            continue
        if s.startswith("### "):
            pdf.ln(2)
            write_body(s[4:].strip(), size=11, style="B")
            continue
        if s.startswith("---"):
            pdf.ln(1)
            pdf.set_draw_color(180, 180, 180)
            y = pdf.get_y()
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(3)
            continue
        if s.startswith("|") and "|" in s[1:]:
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c or "") for c in cells):
                continue
            write_body("  |  ".join(cells), size=8)
            continue
        if s.lstrip().startswith("- ") or s.lstrip().startswith("* "):
            bullet = s.lstrip()[2:].strip()
            write_body(f"  - {bullet}", size=10)
            continue
        if re.match(r"^\d+\.\s", s.lstrip()):
            write_body(s.strip(), size=10)
            continue
        if s.startswith("```"):
            continue
        write_body(s, size=10)

    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(pdf_path))
    print(f"pdf: {pdf_path}")
    print(f"bytes: {pdf_path.stat().st_size}")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        raise SystemExit(0 if len(sys.argv) > 1 else 1)
    md = Path(sys.argv[1]).expanduser().resolve()
    if not md.is_file():
        die(f"file not found: {md}")
    if len(sys.argv) >= 3:
        out = Path(sys.argv[2]).expanduser().resolve()
    else:
        out = md.with_suffix(".pdf")
    convert(md, out)


if __name__ == "__main__":
    main()
