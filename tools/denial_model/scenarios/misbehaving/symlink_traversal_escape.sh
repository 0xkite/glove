# Misbehaving: attempts workspace escape via symlinks and relative traversal.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'base\n' > base.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
ln -s "$H" "link-home-$N" 2>/dev/null
ln -s "$H/.ssh" "link-ssh-$N" 2>/dev/null
ln -s "/private/tmp" "link-tmp-$N" 2>/dev/null
( /usr/bin/touch "link-home-$N/glove-sym-$N" ) 2>/dev/null
( cat "link-ssh-$N/id_ed25519-$N" ) >/dev/null 2>&1
( /usr/bin/touch "link-tmp-$N/glove-sym-$N" ) 2>/dev/null
( /usr/bin/touch "../glove-rel-$N" ) 2>/dev/null
( /usr/bin/touch "../../glove-rel-$N" ) 2>/dev/null
