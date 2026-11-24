# Benign: probes common toolchain and PATH locations, then runs a local check.
for tool in clang cc make cmake git python3 awk sed; do
    command -v "$tool" >/dev/null 2>&1
done
( ls /usr/bin /bin ) >/dev/null 2>&1
printf 'ok\n' > probe.txt
cat probe.txt >/dev/null
