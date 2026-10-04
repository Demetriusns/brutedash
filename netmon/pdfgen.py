"""netmon/pdfgen.py -- a minimal pure-Python PDF 1.4 writer (stdlib only).

No reportlab, no weasyprint, no new dependencies: this module writes a
small, well-formed PDF 1.4 document using only the standard library.
Helvetica (a PDF base-14 font, present in every reader) is used so no
font embedding is needed.

What it CAN do (the honest boundary, documented here):
  - one-column text layout: headings, body paragraphs, bullet lists
  - simple tables with wrapped cells and fixed column widths
  - multiple pages, page numbers, a small brutedash header/footer
  - incident briefs and weekly summaries (assembled by reporting.py)

What it can NOT do (deliberately out of scope):
  - images, charts, or graphs -- text and tables only
  - rich typography (one font, three sizes, no bold/italic variants --
    "bold" is faked with a slightly larger size on headings)
  - right-to-left or complex scripts; non-Latin-1 characters are
    replaced with "?" so a stray emoji can never corrupt the file

Robustness rules (council-mandated):
  - every string that reaches the PDF goes through _pdf_escape(): "(",
    ")", and "\\" are escaped and non-Latin-1 chars become "?" -- alert
    text with parens/backslashes/unicode can never break the file
  - CR/LF inside a string become spaces (PDF strings are single-line)
  - the xref table is built from real byte offsets measured as the file
    is assembled, so it is always consistent

The output opens in any real reader (Acrobat, Preview, Chrome, Evince).
tests/test_reporting.py validates: %PDF-1.4 header, a parseable xref
table, the declared page count, and text extractable from the content
streams.
"""
import re
import time
from datetime import datetime

PAGE_W, PAGE_H = 612.0, 792.0      # US Letter
MARGIN = 72.0
USABLE_W = PAGE_W - 2 * MARGIN
TOP_Y = PAGE_H - MARGIN
BOTTOM_Y = MARGIN + 24             # leave room for the footer

# Helvetica (base-14) advance widths, units per 1000 em, for ASCII 32..126.
# Used only for word-wrapping; the PDF itself needs no metrics.
_CHARS = "".join(chr(c) for c in range(32, 127))
_WIDTHS = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333,
    278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278,
    584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
    500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944,
    667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
    278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
    278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
)
_WIDTH_MAP = dict(zip(_CHARS, _WIDTHS))
assert len(_WIDTH_MAP) == 95, "width table must cover ASCII 32..126"


def _pdf_escape(text):
    """Make a string safe for a PDF literal string: escape \\ ( ) and
    collapse CR/LF; anything outside Latin-1 becomes '?'. Never raises."""
    try:
        s = str(text or "")
    except Exception:
        s = ""
    s = s.replace("\r", " ").replace("\n", " ")
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "(":
            out.append("\\(")
        elif ch == ")":
            out.append("\\)")
        elif ord(ch) < 32:
            out.append(" ")  # control chars have no business in a PDF string
        elif ord(ch) > 255:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _text_width(text, size):
    """Width of text in points at the given font size."""
    total = 0
    for ch in text:
        total += _WIDTH_MAP.get(ch, 600)
    return total * size / 1000.0


def _wrap(text, max_width, size):
    """Greedy word wrap of one paragraph into lines fitting max_width.
    Never raises; a word longer than the line is hard-broken."""
    words = str(text or "").split()
    lines, current = [], ""
    for word in words:
        trial = word if not current else current + " " + word
        if _text_width(trial, size) <= max_width or not current:
            if _text_width(word, size) > max_width:
                # hard-break an overlong word (e.g. a long URL/hash)
                chunk = ""
                for ch in word:
                    if _text_width(chunk + ch, size) > max_width and chunk:
                        lines.append(chunk)
                        chunk = ch
                    else:
                        chunk += ch
                current = chunk if not current else current + " " + chunk
                if _text_width(current, size) > max_width:
                    lines.append(current)
                    current = ""
            else:
                current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


class PdfDoc:
    """Assemble a simple text-layout PDF. Call the content methods, then
    build() -> bytes."""

    def __init__(self, title, subtitle=""):
        self.title = title
        self.subtitle = subtitle
        # pages: list of pages; each page is a list of drawing ops:
        # ("text", x, y, size, text) or ("rule", x1, y1, x2, y2, gray)
        self._pages = [[]]
        self._y = TOP_Y - 40  # room for the header band
        self._first_content = True

    # -- content API --------------------------------------------------------

    def heading(self, text):
        self._ensure_space(52)
        for line in _wrap(text, USABLE_W, 16):
            self._emit(line, 16)
        self._y -= 6

    def subheading(self, text):
        self._ensure_space(40)
        for line in _wrap(text, USABLE_W, 13):
            self._emit(line, 13)
        self._y -= 4

    def body(self, text):
        self._ensure_space(30)
        for line in _wrap(text, USABLE_W, 11):
            self._emit(line, 11)
        self._y -= 4

    def bullet(self, text):
        self._ensure_space(30)
        for i, line in enumerate(_wrap(text, USABLE_W - 18, 11)):
            prefix = "- " if i == 0 else "  "
            self._emit(prefix + line, 11, indent=0 if i == 0 else 0,
                       x_off=18 if i > 0 else 0)
        self._y -= 2

    def spacer(self, points=10):
        self._ensure_space(points + 12)
        self._y -= points

    def table(self, headers, rows, widths=None):
        """Simple table. widths: list of point widths summing to <=
        USABLE_W; defaults to equal columns. Cells wrap; row height fits
        the tallest cell. Never raises on ragged rows (missing cells
        render empty, extras are dropped)."""
        n = len(headers)
        if n == 0:
            return
        if not widths:
            widths = [USABLE_W / n] * n
        widths = [float(w) for w in widths[:n]]
        while len(widths) < n:
            widths.append(USABLE_W / n)
        size = 10
        leading = size * 1.35

        def _cell_lines(cell, w):
            return _wrap(cell, w - 8, size) or [""]

        # header
        header_lines = [_cell_lines(h, w) for h, w in zip(headers, widths)]
        self._emit_row(header_lines, widths, size, leading, header=True)
        # rows
        for row in rows or []:
            cells = list(row)[:n] + [""] * max(0, n - len(row))
            lines = [_cell_lines(c, w) for c, w in zip(cells, widths)]
            self._emit_row(lines, widths, size, leading, header=False)

    def page_break(self):
        self._pages.append([])
        self._y = TOP_Y - 40

    # -- internals ----------------------------------------------------------

    def _emit(self, text, size, indent=0, x_off=0):
        self._pages[-1].append(
            ("text", MARGIN + indent + x_off, self._y, size, text))
        self._y -= size * 1.35

    def _emit_row(self, cell_lines, widths, size, leading, header):
        height = max(len(c) for c in cell_lines) * leading + 6
        self._ensure_space(height + 8)
        x = MARGIN
        for lines, w in zip(cell_lines, widths):
            yy = self._y
            for line in lines:
                self._pages[-1].append(("text", x + 4, yy, size, line))
                yy -= leading
            x += w
        if header:
            self._pages[-1].append(
                ("rule", MARGIN, self._y - height + 4,
                 MARGIN + sum(widths), self._y - height + 4, 0.6))
        self._y -= height + (4 if not header else 6)

    def _ensure_space(self, needed):
        if self._y - needed < BOTTOM_Y:
            self.page_break()

    # -- serialization ------------------------------------------------------

    def _render_page(self, ops, page_no, page_count):
        """One content stream's text for a page, incl. header/footer."""
        parts = []
        stamp = datetime.now().strftime("%b %d, %Y")
        header = "brutedash -- your network, explained"
        parts.append(
            f"BT /F1 9 Tf 11 TL {MARGIN:.1f} {PAGE_H - 48:.1f} Td"
            f" 0.55 g ({_pdf_escape(header)}) Tj ET")
        parts.append(
            f"BT /F1 9 Tf 11 TL {MARGIN:.1f} {PAGE_H - 60:.1f} Td"
            f" 0.55 g ({_pdf_escape(self.title)}) Tj ET")
        parts.append(
            f"0.8 g 0.5 w {MARGIN:.1f} {PAGE_H - 66:.1f} m"
            f" {PAGE_W - MARGIN:.1f} {PAGE_H - 66:.1f} l S 0 g")
        for op in ops:
            if op[0] == "text":
                _, x, y, size, text = op
                if y < BOTTOM_Y - 10:
                    continue  # safety: never draw into the footer
                parts.append(
                    f"BT /F1 {size} Tf {size * 1.35:.1f} TL"
                    f" {x:.1f} {y:.1f} Td ({_pdf_escape(text)}) Tj ET")
            elif op[0] == "rule":
                _, x1, y1, x2, y2, gray = op
                parts.append(
                    f"{gray} g 0.5 w {x1:.1f} {y1:.1f} m"
                    f" {x2:.1f} {y2:.1f} l S 0 g")
        footer = (f"Generated {stamp} by brutedash"
                  f" -- page {page_no} of {page_count}")
        parts.append(
            f"BT /F1 9 Tf 11 TL {MARGIN:.1f} {MARGIN - 16:.1f} Td"
            f" 0.55 g ({_pdf_escape(footer)}) Tj ET")
        return "\n".join(parts).encode("latin-1")

    def build(self):
        """Assemble and return the complete PDF as bytes."""
        if self.subtitle:
            self._pages[0].insert(
                0, ("text", MARGIN, TOP_Y - 40 + 16, 11, self.subtitle))
        page_count = len(self._pages)
        objects = []  # (objnum, bytes)

        def _add(body):
            objects.append((len(objects) + 1, body))
            return len(objects)

        catalog_n = _add(b"<< /Type /Catalog /Pages 2 0 R >>")
        assert catalog_n == 1
        # placeholder for the Pages object; filled after pages are known
        pages_n = _add(b"")
        assert pages_n == 2
        font_n = _add(b"<< /Type /Font /Subtype /Type1"
                      b" /BaseFont /Helvetica >>")
        assert font_n == 3
        page_refs = []
        for i, ops in enumerate(self._pages, start=1):
            content = self._render_page(ops, i, page_count)
            content_n = _add(b"<< /Length %d >>\nstream\n" % len(content)
                             + content + b"\nendstream")
            page_n = _add(
                ("<< /Type /Page /Parent 2 0 R"
                 " /MediaBox [0 0 612 792]"
                 f" /Contents {content_n} 0 R"
                 " /Resources << /Font << /F1 3 0 R >> >> >>").encode(
                     "latin-1"))
            page_refs.append(f"{page_n} 0 R")
        # now fill the Pages object
        objects[1] = (2, ("<< /Type /Pages /Kids [%s] /Count %d >>" % (
            " ".join(page_refs), page_count)).encode("latin-1"))

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}
        for num, body in objects:
            offsets[num] = len(out)
            out += f"{num} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
        out += b"0000000000 65535 f \n"
        for num in range(1, len(objects) + 1):
            out += f"{offsets[num]:010d} 00000 n \n".encode("ascii")
        out += (f"trailer\n<< /Size {len(objects) + 1}"
                f" /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n").encode(
                    "ascii")
        return bytes(out)


def extract_text(pdf_bytes):
    """Pull the text back out of content streams (for tests): finds every
    ( ... ) Tj, unescapes it, and joins the pieces. Not a general PDF
    parser -- just enough to prove our own writer's text is readable."""
    try:
        text = pdf_bytes.decode("latin-1")
    except Exception:
        return ""
    pieces = []
    for m in re.finditer(r"\((?:[^()\\]|\\.)*\)\s*Tj", text):
        raw = m.group(0)
        inner = raw[1:raw.rindex(")")]
        inner = inner.replace("\\\\", "\x00").replace("\\(", "(").replace(
            "\\)", ")").replace("\x00", "\\")
        pieces.append(inner)
    return "\n".join(pieces)
