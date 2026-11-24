# Benign: generates a 500 KB source tree in workspace and searches/aggregates it.
mkdir -p repo
i=0
while [ "$i" -lt 100 ]; do
    d="repo/pkg$((i % 10))"
    mkdir -p "$d"
    j=0
    while [ "$j" -lt 40 ]; do
        printf 'func_%d_%d: value=%d tag=OK\n' "$i" "$j" $((i + j))
        j=$((j + 1))
    done > "$d/mod_$i.txt"
    i=$((i + 1))
done
find repo -type f | sort | wc -l >/dev/null
grep -rn "tag=OK" repo | wc -l >/dev/null
sort repo/pkg0/mod_0.txt | uniq | wc -l >/dev/null
