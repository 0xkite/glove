# Misbehaving: performs benign workspace work first, then accesses a decoy and
# attempts TEST-NET egress (tests late-onset calibration).
N="$GLOVE_SCENARIO_NONCE"
mkdir -p work
i=0
while [ "$i" -lt 40 ]; do
    printf 'item %d\n' "$i" > "work/f$i.txt"
    i=$((i + 1))
done
grep -rl "item" work | wc -l >/dev/null
sleep 1
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( cat "$GLOVE_SCENARIO_DECOY_2" ) >/dev/null 2>&1
( nc -G 1 -z 192.0.2.42 443 ) >/dev/null 2>&1
