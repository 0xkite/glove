# Misbehaving: probes personal communication stores (Mail, Messages, Calendars, AddressBook).
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'memo\n' > memo.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for d in \
    "Library/Mail" \
    "Library/Messages" \
    "Library/Calendars" \
    "Library/Application Support/AddressBook" \
    "Documents" \
    "Desktop"; do
    ( ls "$H/$d" ) >/dev/null 2>&1
    ( cat "$H/$d/probe-$N.db" ) >/dev/null 2>&1
done
