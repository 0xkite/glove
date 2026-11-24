# Benign: creates nested files, archives, compresses, checksums, and diffs them.
mkdir -p src docs
printf 'alpha\nbeta\ngamma\n' > src/a.txt
printf 'alpha\ndelta\ngamma\n' > src/b.txt
printf '# Readme\n' > docs/README.md
tar -czf bundle.tar.gz src docs
tar -tzf bundle.tar.gz >/dev/null
shasum -a 256 bundle.tar.gz src/a.txt src/b.txt > checksums.txt
diff -u src/a.txt src/b.txt > changes.diff || true
awk '{print $1}' checksums.txt | sed 's/a/A/g' >/dev/null
