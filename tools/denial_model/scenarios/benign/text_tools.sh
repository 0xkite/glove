# Benign: an agent searches and rewrites files with standard tools.
mkdir -p src docs
for i in 1 2 3 4 5; do printf 'line %s TODO fix\nother %s\n' "$i" "$i" > "src/f$i.txt"; done
grep -rn TODO src | head
find . -name '*.txt' | sort
sed -i '' 's/TODO/DONE/' src/f1.txt
awk '{ print $1 }' src/f2.txt | sort | uniq -c
wc -l src/*.txt
