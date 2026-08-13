#!/bin/bash
# Monolith + slop detection pre-commit hook.
#
# Monolith: fails when a staged source file exceeds MAX_FILE_LINES.
# Slop:     fails on copy-paste evidence — a non-trivial line (>= MIN_DUP_LINE_LEN
#           chars) repeated >= MIN_DUP_COUNT times within one file. This is a
#           dependency-free proxy for jscpd; jscpd is used instead when present.
#
# Overrides: a repo may set monolith-slop.allow (space-separated globs) via
# `git config monolith-slop.allow "*.gen.rs **/vendor/**"` to exempt generated or
# vendored files. This hook never blocks when there are no staged source files.

set -u

MAX_FILE_LINES="${MONOLITH_MAX_LINES:-800}"
MIN_DUP_LINE_LEN="${SLOP_MIN_LINE_LEN:-40}"
MIN_DUP_COUNT="${SLOP_MIN_DUP_COUNT:-3}"

# Source file extensions we police.
SOURCE_RE='\.(rs|cpp|hpp|cc|hh|c|h|py|ts|js|go|sh)$'

files=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep -E "$SOURCE_RE" || true)
if [ -z "$files" ]; then
    exit 0
fi

allow=$(git config --get monolith-slop.allow 2>/dev/null || true)
is_allowed() {
    local f="$1"
    local g
    if [ -n "$allow" ]; then
        for g in $allow; do
            case "$f" in
                $g) return 0 ;;
            esac
        done
    fi
    return 1
}

# Test files legitimately repeat setup; the duplicate-line heuristic is too
# aggressive for them, so the slop check is skipped (monolith still applies).
is_test() {
    case "$1" in
        tests/*|test/*|*/tests/*|*/test/*|test_*|*_test.*|*_tests.*|*Test.*|*Tests.*) return 0 ;;
        *) return 1 ;;
    esac
}

monoliths=""
slop=""
for f in $files; do
    [ -f "$f" ] || continue
    is_allowed "$f" && continue

    lines=$(wc -l < "$f" | tr -d ' ')
    if [ "$lines" -gt "$MAX_FILE_LINES" ]; then
        monoliths="${monoliths}\n  $f (${lines} lines, limit ${MAX_FILE_LINES})"
    fi

    # Copy-paste proxy: non-trivial lines repeated MIN_DUP_COUNT+ times.
    # Skipped for test files (their setup boilerplate legitimately repeats).
    if is_test "$f"; then
        :
    elif command -v jscpd >/dev/null 2>&1; then
        # Prefer real copy-paste detection when available.
        out=$(jscpd --silent --min-lines 5 --min-tokens 40 "$f" 2>/dev/null || true)
        if [ -n "$out" ]; then
            slop="${slop}\n  $f (jscpd: copy-paste detected)"
        fi
    else
        dupes=$(awk -v L="$MIN_DUP_LINE_LEN" -v N="$MIN_DUP_COUNT" \
            '{ if (length($0) >= L) c[$0]++ } END { for (k in c) if (c[k] >= N) print k }' "$f" | head -5)
        if [ -n "$dupes" ]; then
            slop="${slop}\n  $f (repeated non-trivial lines):$(echo "$dupes" | sed 's/^/    /')"
        fi
    fi
done

status=0
if [ -n "$monoliths" ]; then
    echo "❌ monolith detection: staged file(s) exceed ${MAX_FILE_LINES} lines:"
    printf "%b\n" "$monoliths"
    echo "   Split these into focused modules before committing."
    status=1
fi
if [ -n "$slop" ]; then
    echo "⚠️  slop detection: copy-paste / duplicated code in staged file(s):"
    printf "%b\n" "$slop"
    echo "   Deduplicate or factor the repeated code before committing."
    status=1
fi

exit "$status"
