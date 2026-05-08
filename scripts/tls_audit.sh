#!/usr/bin/env bash
# scripts/tls_audit.sh — CLAUDE.md §0d static audit for tls_core.
#
# Reports the four bypass-detection greps the platinum claim checklist
# requires.  A platinum claim is rejected on the first non-empty result.
# Tcp_Transport / Transport SPARK_Mode (Off) are the documented
# exception (GNAT.Sockets boundary, §0d.2 clause).

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO/crates/tls_core/src"
fail=0

step() { printf '\n=== %s ===\n' "$*"; }

# Filter helper: drop matches that are inside an Ada comment.
# `grep -n` output is `file:line:content`; comments start with optional
# whitespace then `--`. Discard them.
not_a_comment='[^:]+:[0-9]+:[[:space:]]*[^-[:space:]]'

step "1. SPARK_Mode (Off) — only Tcp_Transport / Transport allowed"
hits="$(grep -rnE 'SPARK_Mode\s*\(\s*Off|SPARK_Mode\s*=>\s*Off' "$SRC" \
        | grep -E "$not_a_comment" \
        | grep -vE 'tls_core-tcp_transport\.(adb|ads)|tls_core-transport\.(adb|ads)')"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "FAIL: unexpected SPARK_Mode (Off) bodies"
    fail=1
else
    echo "ok — only Tcp_Transport / Transport (the documented boundary)"
fi

step "2. pragma Assume in production code — must be zero"
hits="$(grep -rn 'pragma Assume' "$SRC" | grep -E "$not_a_comment")"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "FAIL: pragma Assume leaked into production"
    fail=1
else
    echo "ok"
fi

step "3. pragma Annotate (GNATprove …) justifications — must be zero"
hits="$(grep -rnE 'pragma Annotate\s*\(\s*GNATprove' "$SRC" \
        | grep -E "$not_a_comment")"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "FAIL: GNATprove justification annotation present"
    fail=1
else
    echo "ok"
fi

step "4. Stub Spec_* ghost functions whose body returns a constant"
# A real stub looks like:
#    function Spec_X (...) return Boolean is
#       pragma Unreferenced (...);
#    begin
#       return False;
#    end Spec_X;
# We require the function body to have a single `return False;` or
# `return True;` statement (constant Boolean stubs); array stubs like
# `(others => 0)` are too prone to false positives because legitimate
# locals initialise that way.
hits="$(grep -rE '^\s*function Spec_.* return .* is\s*$' "$SRC"/*.adb -A6 \
        2>/dev/null | grep -B1 -E '^[^:]+-\s*return (False|True);')"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "FAIL: stub Spec_* ghost (return constant) detected"
    fail=1
else
    echo "ok (constant-return stubs only — array stubs require manual review)"
fi

step "5. gnatprove headline (latest run)"
out="$REPO/crates/tls_core/obj/gnatprove/gnatprove.out"
if [ -f "$out" ]; then
    grep -A 1 '^Total' "$out" | head -2
    grep -E '^Functional Contracts' "$out" | head -1
else
    echo "(no gnatprove run yet — run 'make tls-prove')"
fi

if [ $fail -ne 0 ]; then
    echo
    echo "AUDIT FAILED — at least one platinum-bypass check tripped."
    exit 1
fi

echo
echo "AUDIT OK — no bypass mechanisms detected."
exit 0
