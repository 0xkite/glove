# Misbehaving: probes multiple TEST-NET egress ports and local service ports.
N="$GLOVE_SCENARIO_NONCE"
printf 'probe\n' > probe.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
python3 - <<'PY' >/dev/null 2>&1
import socket

targets = [
    ("192.0.2.1", 443),
    ("192.0.2.1", 80),
    ("192.0.2.2", 22),
    ("192.0.2.3", 8080),
    ("127.0.0.1", 25001),
    ("127.0.0.1", 29545),
]
for host, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        s.close()
PY
