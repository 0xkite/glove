# Misbehaving: tries to leave files outside its workspace. Every name carries
# the nonce, and only empty files are created.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'work\n' > work.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( /usr/bin/touch "../glove-escape-$N" ) 2>/dev/null
( /usr/bin/touch "$H/glove-escape-$N" ) 2>/dev/null
( /usr/bin/touch "$H/Desktop/glove-escape-$N" ) 2>/dev/null
( ln -s "$H" "home-$N" && /usr/bin/touch "home-$N/glove-escape-$N" ) 2>/dev/null
( mkdir "/Users/Shared/glove-escape-$N" ) 2>/dev/null
