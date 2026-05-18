#!/usr/bin/env python3
"""Render docs/proof-coverage.md — collapsible per-package tree of
SPARK proof status, straight from `gnatprove/gnatprove.out`.

One status column per subprogram (no source-annotation cross-
check): every row is what gnatprove discharged at --level=4,
nothing else.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parent.parent
GNATPROVE_OUT = ROOT / "gnatprove" / "gnatprove.out"
COVERAGE_MD = ROOT / "docs" / "proof-coverage.md"

DETAIL_RE = re.compile(
    r"^\s+(?P<qual>[A-Z][A-Za-z0-9_.]+)\s+at\s+(?P<file>\S+):(?P<line>\d+)"
    r"(?:,\s+instantiated\s+at\s+\S+)?\s+(?P<rest>.*)$"
)
PROVED_RE    = re.compile(r"and proved \((?P<n>\d+) checks\)")
NOTPROVED_RE = re.compile(r"and not proved, (?P<p>\d+) checks out of (?P<t>\d+) proved")
SKIPPED_RE   = re.compile(r"skipped; body is SPARK_Mode")


@dataclass
class Subprog:
    qual: str
    file: str
    line: int
    proved: int
    total: int
    skipped: bool = False

    @property
    def crate(self) -> str:
        parts = self.file.replace("\\", "/").split("/")
        if "crates" in parts:
            return parts[parts.index("crates") + 1]
        return self.qual.split(".", 1)[0].lower()

    @property
    def package(self) -> str:
        return self.qual.rsplit(".", 1)[0] if "." in self.qual else self.qual

    @property
    def name(self) -> str:
        return self.qual.rsplit(".", 1)[-1]

    @property
    def status(self) -> str:
        if self.skipped or self.total == 0:
            return "skipped"
        if self.proved == self.total:
            return "proved"
        return "partial"

    @property
    def glyph(self) -> str:
        return {"proved": "🟢", "partial": "🟡", "skipped": "⚪"}[self.status]


def parse_subprograms() -> list[Subprog]:
    text = GNATPROVE_OUT.read_text()
    subs: list[Subprog] = []
    in_detail = False
    for line in text.splitlines():
        if line.startswith("Detailed analysis report"):
            in_detail = True
            continue
        if not in_detail:
            continue
        m = DETAIL_RE.match(line)
        if not m:
            continue
        qual, file, ln, rest = m.group("qual"), m.group("file"), int(m.group("line")), m.group("rest")
        if SKIPPED_RE.search(rest):
            subs.append(Subprog(qual, file, ln, 0, 0, skipped=True))
            continue
        if pm := PROVED_RE.search(rest):
            n = int(pm.group("n"))
            if n == 0:
                continue  # package-level decl, no VCs
            subs.append(Subprog(qual, file, ln, n, n))
            continue
        if nm := NOTPROVED_RE.search(rest):
            subs.append(Subprog(qual, file, ln, int(nm.group("p")), int(nm.group("t"))))
    return subs


def package_glyph(subs: list[Subprog]) -> str:
    """A package's glyph: green if every member fully proved, yellow if
    any has a gap, white if nothing analysed."""
    if not subs:
        return "⚪"
    if any(s.status == "partial" for s in subs):
        return "🟡"
    if all(s.status == "skipped" for s in subs):
        return "⚪"
    return "🟢"


def render_legend() -> str:
    return (
        "## Legend\n\n"
        "Status comes directly from `gnatprove/gnatprove.out` at\n"
        "`--level=4` — no source-annotation cross-check, no claim layer.\n\n"
        "| Symbol | Meaning |\n"
        "|---|---|\n"
        "| 🟢 | All VCs in this subprogram / package are proved |\n"
        "| 🟡 | Partial — at least one VC unproved |\n"
        "| ⚪ | Not analysed (skipped, `SPARK_Mode (Off)`, or zero VCs) |\n"
    )


def render_subprog_row(s: Subprog) -> str:
    vc_cell = f"{s.proved}/{s.total}" if s.total > 0 else "—"
    return f"| {s.glyph} | `{s.name}` | {vc_cell} |"


def render_package_block(pkg: str, subs: list[Subprog]) -> str:
    subs_sorted = sorted(subs, key=lambda s: (s.status != "proved", s.qual))
    vp = sum(s.proved for s in subs)
    vt = sum(s.total for s in subs)
    pct = round(100 * vp / vt) if vt else 0
    sp = sum(1 for s in subs if s.status == "proved")
    n = len(subs)
    pglyph = package_glyph(subs)
    summary = (
        f"<summary>{pglyph} <code>{pkg}</code> — "
        f"{sp}/{n} subprograms · {vp:,}/{vt:,} VCs ({pct}%)</summary>"
    )
    lines = [
        "<details>",
        summary,
        "",
        "| | Subprogram | VCs |",
        "|---|---|---:|",
    ]
    for s in subs_sorted:
        lines.append(render_subprog_row(s))
    lines.append("")
    lines.append("</details>")
    return "\n".join(lines)


def render_crate_block(crate: str, subs: list[Subprog]) -> str:
    by_pkg: dict[str, list[Subprog]] = defaultdict(list)
    for s in subs:
        by_pkg[s.package].append(s)
    n = len(subs)
    sp = sum(1 for s in subs if s.status == "proved")
    vp = sum(s.proved for s in subs)
    vt = sum(s.total for s in subs)
    pct = round(100 * vp / vt) if vt else 0
    cglyph = package_glyph(subs)
    summary = (
        f"<summary>{cglyph} <b>{crate}</b> — "
        f"{sp}/{n} subprograms · {vp:,}/{vt:,} VCs ({pct}%)</summary>"
    )
    blocks = [render_package_block(p, by_pkg[p]) for p in sorted(by_pkg)]
    return (
        "<details>\n"
        + summary + "\n\n"
        + "\n\n".join(blocks)
        + "\n\n</details>"
    )


CRATE_ORDER = [
    "tls_core",
    "http2_core",
    "mqtt_core",
    "grpc_core",
    "http1_core",
    "protobuf_core",
    "tls_transport",
    "rflx_runtime",
    "logger",
]


def main() -> int:
    if not GNATPROVE_OUT.exists():
        print(f"error: {GNATPROVE_OUT} not found — run `make prove` first",
              file=sys.stderr)
        return 1

    subs = parse_subprograms()
    by_crate: dict[str, list[Subprog]] = defaultdict(list)
    for s in subs:
        by_crate[s.crate].append(s)

    blocks = []
    for crate in CRATE_ORDER:
        if crate in by_crate:
            blocks.append(render_crate_block(crate, by_crate[crate]))
    for crate in sorted(by_crate):
        if crate not in CRATE_ORDER:
            blocks.append(render_crate_block(crate, by_crate[crate]))

    total = len(subs)
    proved = sum(1 for s in subs if s.status == "proved")
    vp = sum(s.proved for s in subs)
    vt = sum(s.total for s in subs)
    pct = round(100 * vp / vt) if vt else 0

    header = "\n".join([
        "# Proof coverage",
        "",
        "Per-subprogram SPARK proof status across the workspace,",
        "rendered straight from `gnatprove/gnatprove.out` (workspace",
        "umbrella `transports_spark.gpr` + `gnatprove -U --level=4",
        "--proof-warnings=on`). Refresh with",
        "`make prove && make prove-coverage`.",
        "",
        f"**Workspace totals:** {proved} / {total} subprograms fully "
        f"proved · {vp:,} / {vt:,} VCs ({pct}%).",
        "",
    ])
    legend = render_legend()
    tree = "\n\n".join(blocks)
    COVERAGE_MD.write_text(header + "\n" + legend + "\n\n" + tree + "\n")
    print(f"# wrote {COVERAGE_MD.relative_to(ROOT)}")
    print(f"#   {proved}/{total} subprograms fully proved")
    print(f"#   {vp:,}/{vt:,} VCs ({pct}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
