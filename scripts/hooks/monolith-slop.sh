#!/bin/bash
# Monolith + slop detection pre-commit hook.
#
# Monolith: fails when a newly-added staged source file exceeds MAX_FILE_LINES
# (pre-existing monoliths are tracked separately, so modifying them is allowed).
# Slop:     copy-paste detection via jscpd when available (block-level, accurate).
#           There is deliberately no single-line duplicate heuristic — it was
#           too noisy (flagging legitimate logging targets and test setup).
#
# Overrides: a repo may set monolith-slop.allow (space-separated globs) via
# `git config monolith-slop.allow "*.gen.rs **/vendor/**"` to exempt generated or
# vendored files. This hook never blocks when there are no staged source files.

set -u

MAX_FILE_LINES="${MONOLITH_MAX_LINES:-800}"

# Source file extensions we police.
SOURCE_RE='\.(rs|cpp|hpp|cc|hh|c|h|py|ts|js|go|sh)$'

all_files=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep -E "$SOURCE_RE" || true)
added_files=$(git diff --cached --name-only --diff-filter=A 2>/dev/null | grep -E "$SOURCE_RE" || true)
if [ -z "$all_files" ]; then
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
	tests/* | test/* | */tests/* | */test/* | test_* | *_test.* | *_tests.* | *Test.* | *Tests.*) return 0 ;;
	esac
	# In-file test modules (Rust `#[cfg(test)]`) legitimately repeat setup; skip
	# the duplicate-line heuristic for them (the monolith limit still applies).
	if [ -f "$1" ] && grep -q '#\[cfg(test)\]' "$1" 2>/dev/null; then
		return 0
	fi
	return 1
}

monoliths=""
for f in $added_files; do
	[ -f "$f" ] || continue
	is_allowed "$f" && continue

	lines=$(wc -l <"$f" | tr -d ' ')
	if [ "$lines" -gt "$MAX_FILE_LINES" ]; then
		monoliths="${monoliths}\n  $f (${lines} lines, limit ${MAX_FILE_LINES})"
	fi
done

slop=""
if command -v jscpd >/dev/null 2>&1; then
	for f in $all_files; do
		[ -f "$f" ] || continue
		is_allowed "$f" && continue
		is_test "$f" && continue
		out=$(jscpd --silent --min-lines 5 --min-tokens 40 "$f" 2>/dev/null || true)
		if [ -n "$out" ]; then
			slop="${slop}\n  $f (jscpd: copy-paste detected)"
		fi
	done
fi

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
