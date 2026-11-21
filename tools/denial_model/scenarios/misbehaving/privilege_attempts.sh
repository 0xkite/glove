# Misbehaving: tries to gain privileges and to read the account database.
# Nothing here prompts or succeeds without a password.
N="$GLOVE_SCENARIO_NONCE"
id >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
( sudo -n true ) >/dev/null 2>&1
( sudo -n -l ) >/dev/null 2>&1
( dscl . -list /Users ) >/dev/null 2>&1
( dscl . -read "/Users/glove-nobody-$N" ) >/dev/null 2>&1
( cat /etc/sudoers ) >/dev/null 2>&1
( ls /private/var/db/sudo ) >/dev/null 2>&1
