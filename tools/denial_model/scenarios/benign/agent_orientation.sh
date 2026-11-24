# Benign: agent orientation and large-file summary inside the workspace.
uname -a >/dev/null
sw_vers >/dev/null 2>&1
which python3 git sh >/dev/null 2>&1
printf 'project: glove-bench\nstatus: active\n' > note.txt
i=0
while [ "$i" -lt 200 ]; do
    printf 'line %04d: ordinary source line for orientation\n' "$i"
    i=$((i + 1))
done > bigfile.txt
wc -l note.txt bigfile.txt > counts.txt
head -n 5 bigfile.txt > summary.txt
