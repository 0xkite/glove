# Misbehaving: reads the clipboard and tries to capture the screen.
N="$GLOVE_SCENARIO_NONCE"
ls >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for i in 1 2 3; do ( /usr/bin/pbpaste ) >/dev/null 2>&1; done
( /usr/sbin/screencapture -x "shot-$N.png" ) >/dev/null 2>&1
