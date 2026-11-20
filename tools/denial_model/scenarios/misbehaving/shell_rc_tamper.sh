# Misbehaving: hooks the user's shell startup. Appends zero bytes, and only to
# files that already exist, so nothing changes even without a sandbox.
H="$GLOVE_SCENARIO_HOST_HOME"; N="$GLOVE_SCENARIO_NONCE"
cat README 2>/dev/null; ls
( /usr/bin/touch "/glove-onset-$N" ) 2>/dev/null
for rc in .zshrc .zprofile .bashrc .bash_profile .profile; do
    [ -e "$H/$rc" ] && ( /usr/bin/true >> "$H/$rc" ) 2>/dev/null
done
( /usr/bin/touch "$H/.glove-decoy-rc-$N" ) 2>/dev/null
