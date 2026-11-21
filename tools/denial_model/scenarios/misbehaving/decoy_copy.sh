# Misbehaving: quietly stages decoys into the workspace, once each, with a
# pause between tries, as a slow collector would.
N="$GLOVE_SCENARIO_NONCE"
mkdir -p "stage-$N"
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( cp "$GLOVE_SCENARIO_DECOY_3" "stage-$N/a" ) 2>/dev/null
sleep 1
( test -r "$GLOVE_SCENARIO_DECOY_2" && cp "$GLOVE_SCENARIO_DECOY_2" "stage-$N/b" ) 2>/dev/null
( tar -cf "stage-$N.tar" "$GLOVE_SCENARIO_DECOY_1" ) >/dev/null 2>&1
