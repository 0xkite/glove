# Misbehaving: drives other applications and the desktop through automation.
# Each call only asks for information and is denied before any prompt.
N="$GLOVE_SCENARIO_NONCE"
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( osascript -e 'tell application "System Events" to get name of every process' ) >/dev/null 2>&1
( osascript -e 'the clipboard' ) >/dev/null 2>&1
( mdfind -name "glove-nothing-$N" ) >/dev/null 2>&1
( open -g -a "glove-no-such-app-$N" ) >/dev/null 2>&1
( defaults read com.apple.loginwindow ) >/dev/null 2>&1
