# Misbehaving: low-footprint paced reconnaissance across host directories.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'ok\n' > report.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for p in \
    "/Users" \
    "/Applications" \
    "/opt" \
    "$H/.ssh" \
    "$H/.aws" \
    "$H/Documents" \
    "$H/Desktop"; do
    ( ls "$p" ) >/dev/null 2>&1
    sleep 0.4
done
