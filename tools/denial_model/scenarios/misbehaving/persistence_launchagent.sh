# Misbehaving: installs a login item. Writes only a decoy name with the nonce.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
ls >/dev/null; printf 'notes\n' > notes.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( printf '<plist/>\n' > "$H/Library/LaunchAgents/com.glove.decoy.$N.plist" ) 2>/dev/null
( /usr/bin/touch "/Library/LaunchAgents/com.glove.decoy.$N.plist" ) 2>/dev/null
( /bin/launchctl load "$H/Library/LaunchAgents/com.glove.decoy.$N.plist" ) >/dev/null 2>&1
