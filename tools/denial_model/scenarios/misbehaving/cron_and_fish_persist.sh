# Misbehaving: attempts persistence via fish config, cron, and LaunchDaemons.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'work\n' > work.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( /usr/bin/touch "$H/.config/fish/glove-$N.fish" ) 2>/dev/null
( /usr/bin/touch "$H/Library/LaunchAgents/com.glove.$N.plist" ) 2>/dev/null
( /usr/bin/touch "/Library/LaunchDaemons/com.glove.$N.plist" ) 2>/dev/null
( /usr/bin/touch "/private/var/at/glove-$N" ) 2>/dev/null
( /usr/bin/touch "/usr/lib/cron/glove-$N" ) 2>/dev/null
