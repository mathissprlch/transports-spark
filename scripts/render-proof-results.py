#!/usr/bin/env python3
"""Render the workspace gnatprove output into:

  1. docs/proof-results.txt — committable headline + per-package
     table + the gnatprove Summary block verbatim.

  2. Markdown on stdout, ready to paste into the README's
     "Proof results" section.

Reads gnatprove/gnatprove.out at the repo root, produced by
`make prove` (which runs gnatprove via the workspace umbrella
transports_spark.gpr with -U).

Per top-level Ada package family (Tls_Core, RFLX, Mqtt_Core,
etc.) the renderer sums VCs from gnatprove's per-subprogram
"Detailed analysis report" lines.

Usage: scripts/render-proof-results.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

ROOT = Path(__file__).resolve().parent.parent
IN_FILE = ROOT / "gnatprove" / "gnatprove.out"
RAW_OUT = ROOT / "docs" / "proof-results.txt"

# Top-level Ada package prefix → display label.
GROUPS = [
    ("Tls_Core",       "TLS 1.3 — crypto, key schedule, wire, driver"),
    ("Http2_Core",     "HTTP/2 — frame layer, HPACK, multi-stream server"),
    ("Mqtt_Core",      "MQTT 3.1.1 — client, broker, wire"),
    ("Grpc_Core",      "gRPC framing on top of HTTP/2"),
    ("Http1_Core",     "minimal HTTP/1.1"),
    ("Protobuf_Core",  "protobuf wire codec"),
    ("Tls_Transport",  "TLS adapter (Connect/Send/Receive/Close)"),
    ("RFLX",           "RecordFlux-generated parsers + state machines"),
    ("Logger",         "shared structured logger"),
]


# Detailed-report line shape:
#   "  Qualified.Name at file:line flow analyzed (...) and proved (N checks)"
#   "  Qualified.Name at file:line ... and not proved, X checks out of Y proved"
#   "  Qualified.Name at file:line skipped; body is SPARK_Mode => Off"
DETAIL_RE = re.compile(
    r"^\s+(?P<qual>[A-Z][A-Za-z0-9_.]+)\s+at\s+\S+:\d+(?:,\s+instantiated\s+at\s+\S+)?\s+(?P<rest>.*)$"
)
PROVED_RE   = re.compile(r"and proved \((?P<n>\d+) checks\)")
NOTPROVED_RE = re.compile(r"and not proved, (?P<p>\d+) checks out of (?P<t>\d+) proved")
SKIPPED_RE  = re.compile(r"skipped; body is SPARK_Mode")


@dataclass
class Subprog:
    qual: str
    proved: int   # 0 if skipped
    total:  int   # 0 if skipped
    skipped: bool = False

    @property
    def fully_proved(self) -> bool:
        return not self.skipped and self.total > 0 and self.proved == self.total


def parse_total(text: str) -> tuple[int, int, int]:
    """Return (total, proved, unproved) from the gnatprove 'Total' line."""
    m = re.search(r"^Total\s+(\d+)\s+(.*)$", text, flags=re.M)
    if not m:
        return (0, 0, 0)
    total = int(m.group(1))
    nums = re.findall(r"(\d+)(?:\s*\(\d+%\))?", m.group(2))
    unproved = int(nums[-1]) if nums else 0
    return total, total - unproved, unproved


def extract_summary_block(text: str) -> str:
    m = re.search(
        r"^=+\nSummary of SPARK analysis\n=+\n.*?(?=\n=+\n|\Z)",
        text, flags=re.S | re.M,
    )
    return m.group(0).strip() if m else ""


def parse_subprograms(text: str) -> list[Subprog]:
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
        qual, rest = m.group("qual"), m.group("rest")
        if SKIPPED_RE.search(rest):
            subs.append(Subprog(qual=qual, proved=0, total=0, skipped=True))
            continue
        if pm := PROVED_RE.search(rest):
            n = int(pm.group("n"))
            if n == 0:
                continue  # package-level decl, no VCs to count
            subs.append(Subprog(qual=qual, proved=n, total=n))
            continue
        if nm := NOTPROVED_RE.search(rest):
            subs.append(Subprog(qual=qual, proved=int(nm.group("p")), total=int(nm.group("t"))))
            continue
    return subs


def top_level(qual: str) -> str:
    return qual.split(".", 1)[0]


def render_group_table(subs: list[Subprog]) -> str:
    by_group: dict[str, list[Subprog]] = defaultdict(list)
    for s in subs:
        by_group[top_level(s.qual)].append(s)

    lines = [
        "| Package family | Subprograms (proved / total) | VCs (proved / total) | %  |",
        "|---|---:|---:|---:|",
    ]
    g_sp = g_st = g_vp = g_vt = 0
    for prefix, label in GROUPS:
        group = by_group.get(prefix, [])
        if not group:
            continue
        sp = sum(1 for s in group if s.fully_proved)
        st = len(group)  # include skipped subprograms in the denominator
        vp = sum(s.proved for s in group)
        vt = sum(s.total for s in group)
        pct = round(100 * vp / vt) if vt else 0
        lines.append(
            f"| **`{prefix}.*`** — {label} | {sp} / {st} | "
            f"{vp:,} / {vt:,} | {pct}% |"
        )
        g_sp += sp; g_st += st; g_vp += vp; g_vt += vt
    pct = round(100 * g_vp / g_vt) if g_vt else 0
    lines.append(
        f"| **Total** | **{g_sp} / {g_st}** | "
        f"**{g_vp:,} / {g_vt:,}** | **{pct}%** |"
    )
    return "\n".join(lines)


def render_topgap_table(subs: list[Subprog], n: int = 12) -> str:
    pkgs: dict[str, list[Subprog]] = defaultdict(list)
    for s in subs:
        if s.skipped:
            continue
        parent = s.qual.rsplit(".", 1)[0] if "." in s.qual else s.qual
        pkgs[parent].append(s)
    rows = []
    for pkg, members in pkgs.items():
        vp = sum(s.proved for s in members)
        vt = sum(s.total for s in members)
        if vt > vp:
            rows.append((pkg, vp, vt, vt - vp))
    rows.sort(key=lambda r: r[3], reverse=True)
    if not rows:
        return "_(every package fully proved at gnatprove --level=4)_"
    lines = ["| Package | VCs (proved / total) | Gap |", "|---|---:|---:|"]
    for pkg, vp, vt, gap in rows[:n]:
        lines.append(f"| `{pkg}` | {vp:,} / {vt:,} | {gap} |")
    return "\n".join(lines)


def main() -> int:
    if not IN_FILE.exists():
        print(f"error: {IN_FILE} not found — run `make prove` first", file=sys.stderr)
        return 1
    text = IN_FILE.read_text()
    total, proved, unproved = parse_total(text)
    subs = parse_subprograms(text)

    group_table = render_group_table(subs)
    topgap_table = render_topgap_table(subs)
    summary_block = extract_summary_block(text)

    RAW_OUT.parent.mkdir(parents=True, exist_ok=True)
    with RAW_OUT.open("w") as f:
        f.write("transports-spark — gnatprove --level=4 sweep\n")
        f.write("=" * 60 + "\n\n")
        f.write(
            "Headline aggregation. Per-subprogram detail is in\n"
            "gnatprove/gnatprove.out (the raw workspace-level output).\n\n"
        )
        f.write(group_table + "\n\n")
        f.write("Where unproved VCs live (top packages by gap):\n\n")
        f.write(topgap_table + "\n\n")
        f.write("gnatprove summary block:\n\n")
        f.write(summary_block + "\n")

    print(f"# wrote {RAW_OUT.relative_to(ROOT)}\n")
    print("# === Per-package rollup ===\n")
    print(group_table)
    print()
    print("# === Packages with unproved-VC gaps ===\n")
    print(topgap_table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
