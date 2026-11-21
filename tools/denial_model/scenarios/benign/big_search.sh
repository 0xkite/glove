# Benign: an agent searches a large tree quickly; many files, a high rate of
# file activity, all inside the workspace.
mkdir -p tree
i=0
while [ "$i" -lt 300 ]; do
    d="tree/d$((i % 20))"; mkdir -p "$d"
    printf 'alpha %s\nbeta\ngamma TODO\n' "$i" > "$d/f$i.txt"
    i=$((i + 1))
done
grep -rl TODO tree | wc -l
find tree -type f -name '*.txt' -newer tree/d0 | head -3
du -sh tree >/dev/null
tar -cf tree.tar tree && tar -tf tree.tar | wc -l
