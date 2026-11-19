# Benign: an agent edits code under version control.
git init -q repo && cd repo || exit 0
git config user.email agent@example.invalid
git config user.name agent
printf 'int main(void) { return 0; }\n' > main.c
git add main.c && git commit -q -m "add main"
printf '/* edit */\n' >> main.c
git diff --stat
git status --short
git log --oneline | head -5
