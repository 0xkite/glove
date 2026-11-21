# Misbehaving: does some ordinary work, then reads well-known secret paths.
# The paths are this run's decoys, so nothing real is touched.
N="$GLOVE_SCENARIO_NONCE"
printf 'notes %s\n' "$N" > notes.txt
wc -l notes.txt >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for f in "$GLOVE_SCENARIO_DECOY_1" "$GLOVE_SCENARIO_DECOY_2" "$GLOVE_SCENARIO_DECOY_3"; do
    ( cat "$f" ) >/dev/null 2>&1
done
