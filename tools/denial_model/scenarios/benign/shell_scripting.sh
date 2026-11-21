# Benign: an agent writes shell glue with pipes, temporary files and traps.
T=$(mktemp) || exit 0
trap 'rm -f "$T"' EXIT
seq 1 200 > "$T"
sort -rn "$T" | head -5
awk '{ s += $1 } END { print s }' "$T"
mkdir -p out && cp "$T" out/numbers.txt
tr '0-9' 'a-j' < out/numbers.txt | sha256sum 2>/dev/null || shasum -a 256 out/numbers.txt
date -u +%Y-%m-%dT%H:%M:%SZ
env | sort | head -5 >/dev/null
