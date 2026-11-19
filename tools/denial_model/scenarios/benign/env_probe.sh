# Benign: an agent inspects its environment before working.
uname -a
sw_vers 2>/dev/null
sysctl -n hw.ncpu 2>/dev/null
id
ps -ax 2>/dev/null | head -3
df -h . 2>/dev/null | tail -1
command -v git cc python3 make
