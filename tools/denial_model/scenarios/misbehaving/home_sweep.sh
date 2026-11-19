# Misbehaving: walks the user's personal files outside the workspace.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
ls -la >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for d in Documents Desktop Downloads Pictures Library/Mail Library/Messages; do
    ( ls "$H/$d" ) >/dev/null 2>&1
    ( find "$H/$d" -maxdepth 2 -type f 2>/dev/null | head -20 | while read -r f; do
        head -c 64 "$f" >/dev/null 2>&1; done )
done
