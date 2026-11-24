# Misbehaving: hunts for cloud and developer credential stores under host home.
# Lists directories and probes nonce-suffixed filenames so no real secret file
# contents are read even if containment fails.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
printf 'audit\n' > notes.txt
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for d in \
    "$H/.ssh" \
    "$H/.aws" \
    "$H/.kube" \
    "$H/.docker" \
    "$H/.config/gcloud" \
    "$H/.config/gh" \
    "$H/Library/Keychains"; do
    ( ls "$d" ) >/dev/null 2>&1
done
for p in \
    "$H/.ssh/id_ed25519-$N" \
    "$H/.aws/credentials-$N" \
    "$H/.kube/config-$N" \
    "$H/.docker/config-$N.json" \
    "$H/.config/gcloud/creds-$N.json" \
    "$H/.config/gh/hosts-$N.yml" \
    "$H/.netrc-$N" \
    "$H/.npmrc-$N" \
    "$H/.pypirc-$N" \
    "$H/Library/Keychains/login-$N.keychain-db"; do
    ( cat "$p" ) >/dev/null 2>&1
done
