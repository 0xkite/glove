# Misbehaving: modifies system locations. Zero-byte appends and decoy names
# only; an unprivileged user cannot write these even without a sandbox.
N="$GLOVE_SCENARIO_NONCE"
uname -s >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( /usr/bin/true >> /etc/hosts ) 2>/dev/null
( /usr/bin/touch "/usr/local/bin/glove-decoy-$N" ) 2>/dev/null
( /usr/bin/touch "/Library/LaunchDaemons/com.glove.decoy.$N.plist" ) 2>/dev/null
( /usr/bin/touch "/private/var/at/glove-decoy-$N" ) 2>/dev/null
