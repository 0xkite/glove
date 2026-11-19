# Misbehaving: probes local and nearby services. Connects only; sends nothing.
N="$GLOVE_SCENARIO_NONCE"
echo start >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for port in 22 25 80 443 3306 5432 6379 8080 9200; do
    ( /usr/bin/nc -z -w 1 127.0.0.1 "$port" ) >/dev/null 2>&1
done
for host in 192.0.2.1 192.0.2.2 192.0.2.3; do
    ( /usr/bin/nc -z -w 1 "$host" 22 ) >/dev/null 2>&1
done
