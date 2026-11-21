# Benign: an agent starts interactive-style shells and editors, which read the
# user's startup files on their own.
H="$GLOVE_SCENARIO_HOST_HOME"
( zsh -ic 'true' ) >/dev/null 2>&1
( bash -lc 'true' ) >/dev/null 2>&1
( vim --version ) >/dev/null 2>&1
cat "$H/.zshrc" >/dev/null 2>&1
cat "$H/.vimrc" >/dev/null 2>&1
cat "$H/.inputrc" >/dev/null 2>&1
