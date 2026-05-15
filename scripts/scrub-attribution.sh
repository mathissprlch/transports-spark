#!/usr/bin/env bash
#
# scrub-attribution.sh — find tool/assistant attribution in the tree.
#
# Per docs/conventions.md §13, the following must not appear in
# committed source, build files, public docs, or commit messages:
#
#   * literal tool / assistant names (Claude, claude.com, claude-code,
#     Anthropic, ChatGPT, Copilot, Cursor, Codex, Aider, GPT-4, ...)
#   * "Co-Authored-By:" trailers pointing at any of the above
#   * "Generated with <tool>" / "AI-generated" / "AI-authored" phrasing
#   * citations to private CLAUDE.md (use docs/conventions.md instead)
#
# Exit status:
#    0 — tree is clean
#    1 — banned strings found (output lists each hit)
#    2 — script error
#
# Run from the repo root:
#    scripts/scrub-attribution.sh         # check only
#    scripts/scrub-attribution.sh --quiet # exit-status only, no output

set -euo pipefail

QUIET=0
if [ "${1-}" = "--quiet" ]; then
   QUIET=1
fi

BANNED_REGEX='[Cc]laude[-. ]?[Cc]ode|claude\.com|[Aa]nthropic|Co-Authored-By:[[:space:]]*Claude|Co-Authored-By:[[:space:]]*AI|[Gg]enerated[[:space:]]+with[[:space:]]+Claude|[Gg]enerated[[:space:]]+by[[:space:]]+AI|AI-generated|AI-authored|\bCLAUDE\.md\b|\bChatGPT\b|\bGitHub Copilot\b|\bCodex\b|\bAider\b|\bCursor AI\b'

# Surfaces to scan. Exclude vendored / generated / build trees.
EXCLUDES=(
   --exclude-dir=.git
   --exclude-dir=obj
   --exclude-dir=lib
   --exclude-dir=bin
   --exclude-dir=vendor
   --exclude-dir=node_modules
   --exclude-dir=.claude
   --exclude="CLAUDE.md"             # the assistant contract itself
   --exclude=".gitignore"            # may reference the ignored filename
   --exclude="scrub-attribution.sh"  # this script
   --exclude="*.json"
   --exclude="*.log"
   --exclude="*.pcap"
   --exclude="*.tar.gz"
)

hits=$(grep -rnE "${BANNED_REGEX}" "${EXCLUDES[@]}" . 2>/dev/null || true)

# Commit message scan — covers staged commit message during pre-commit.
if [ -n "${GIT_COMMIT_MSG_FILE-}" ] && [ -f "$GIT_COMMIT_MSG_FILE" ]; then
   msg_hits=$(grep -nE "${BANNED_REGEX}" "$GIT_COMMIT_MSG_FILE" 2>/dev/null || true)
   if [ -n "$msg_hits" ]; then
      hits="${hits}"$'\n'"COMMIT_MSG:${msg_hits}"
   fi
fi

if [ -z "$hits" ]; then
   [ $QUIET -eq 0 ] && echo "scrub-attribution.sh: clean"
   exit 0
else
   if [ $QUIET -eq 0 ]; then
      echo "scrub-attribution.sh: banned strings found (see docs/conventions.md §13):" >&2
      echo "$hits" >&2
   fi
   exit 1
fi
