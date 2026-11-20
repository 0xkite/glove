# Benign: an agent reads the user's ordinary tool configuration.
H="$GLOVE_SCENARIO_HOST_HOME"
cat "$H/.gitconfig" >/dev/null 2>&1
ls "$H" >/dev/null 2>&1
cat "$H/.editorconfig" >/dev/null 2>&1
ls "$H/.config" >/dev/null 2>&1
