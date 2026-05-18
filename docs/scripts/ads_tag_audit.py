#!/usr/bin/env python3
"""
Walks every public .ads in the crate set and reports public
procedures / functions that lack a [VERIFIED — …] tag header.

Usage:
    python3 docs/scripts/ads_tag_audit.py [crate1 crate2 ...]
With no args: scans all major crates.
"""
import re, os, sys

TAG_RE = re.compile(
    r"\[VERIFIED — (?:PLATINUM|AoRTE)\]"
    r"|\[OUTSIDE SPARK\]|\[NOT VERIFIED\]")
DECL_RE = re.compile(r"^   (procedure|function)\s+(\S+)")

DEFAULT_CRATES = [
    "tls_core", "http2_core", "mqtt_core", "grpc_core",
    "protobuf_core", "http1_core", "tls_transport",
]

def scan(crate):
    root = f"crates/{crate}/src"
    files = []
    for r, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".ads"):
                files.append(os.path.join(r, f))
    counts = {"total": 0, "tagged": 0}
    untagged_by_file = {}
    for path in sorted(files):
        with open(path, errors="replace") as fp:
            lines = fp.read().splitlines()
        in_private = False
        decls = []
        for i, ln in enumerate(lines):
            if ln.strip() == "private":
                in_private = True
                continue
            if in_private:
                continue
            m = DECL_RE.match(ln)
            if not m:
                continue
            start = max(0, i - 40)
            window = "\n".join(lines[start:i])
            prev = list(DECL_RE.finditer(window))
            if prev:
                window = window[prev[-1].end():]
            tagged = bool(TAG_RE.search(window))
            decls.append((i + 1, m.group(1), m.group(2), tagged))
        if not decls:
            continue
        counts["total"] += len(decls)
        counts["tagged"] += sum(1 for d in decls if d[3])
        ut = [d for d in decls if not d[3]]
        if ut:
            untagged_by_file[path] = ut
    return counts, untagged_by_file

def main():
    crates = sys.argv[1:] or DEFAULT_CRATES
    grand = {"total": 0, "tagged": 0}
    print("# API tag audit — progress\n")
    for crate in crates:
        counts, untagged = scan(crate)
        grand["total"] += counts["total"]
        grand["tagged"] += counts["tagged"]
        coverage = (counts["tagged"] / counts["total"] * 100
                    if counts["total"] else 0.0)
        print(f"## {crate}: {counts['tagged']}/{counts['total']} "
              f"tagged ({coverage:.0f} %)")
        for path, ut in untagged.items():
            rel = path.replace(f"crates/{crate}/src/", "")
            print(f"\n### `{rel}` — {len(ut)} untagged:")
            for line, kind, name, _ in ut[:30]:
                print(f"  - L{line}: `{kind} {name}`")
            if len(ut) > 30:
                print(f"  - … and {len(ut) - 30} more")
        print()
    pct = (grand["tagged"] / grand["total"] * 100
           if grand["total"] else 0.0)
    print(f"## Total: {grand['tagged']}/{grand['total']} "
          f"tagged ({pct:.1f} %)")

if __name__ == "__main__":
    main()
