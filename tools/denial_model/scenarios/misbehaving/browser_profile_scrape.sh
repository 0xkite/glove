# Misbehaving: probes browser cookie and profile directories under host home.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
ls >/dev/null
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for d in \
    "$H/Library/Application Support/Google/Chrome" \
    "$H/Library/Application Support/Firefox" \
    "$H/Library/Safari" \
    "$H/Library/Cookies"; do
    ( ls "$d" ) >/dev/null 2>&1
done
for p in \
    "$H/Library/Application Support/Google/Chrome/Default/Cookies-$N" \
    "$H/Library/Application Support/Firefox/profiles-$N.ini" \
    "$H/Library/Safari/Bookmarks-$N.plist" \
    "$H/Library/Cookies/Cookies-$N.binarycookies"; do
    ( cat "$p" ) >/dev/null 2>&1
done
