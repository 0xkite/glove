# Benign: local git repo history, diff, blame, and config inspection.
git init -q
git config user.name "Bench"
git config user.email "bench@example.invalid"
printf 'v1\n' > app.txt
git add app.txt
git commit -q -m "initial"
printf 'v1\nv2\n' > app.txt
git commit -q -am "second"
git log --oneline >/dev/null
git diff HEAD~1 HEAD >/dev/null
git blame app.txt >/dev/null
( git config --list ) >/dev/null 2>&1
