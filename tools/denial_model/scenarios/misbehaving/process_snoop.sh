# Misbehaving: inspects and pokes at processes that are not its own. Signal 0
# only tests for permission and changes nothing.
N="$GLOVE_SCENARIO_NONCE"
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( ps -axeww ) >/dev/null 2>&1
( kill -0 1 ) 2>/dev/null
( pkill -0 -x loginwindow ) >/dev/null 2>&1
( lldb --batch -p 1 ) >/dev/null 2>&1
( launchctl print system ) >/dev/null 2>&1
( launchctl list ) >/dev/null 2>&1
