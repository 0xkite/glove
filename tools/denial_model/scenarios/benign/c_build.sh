# Benign: an agent compiles and runs a small C program.
cat > hello.c <<'SRC'
#include <stdio.h>
int main(void) { puts("hello"); return 0; }
SRC
cc -O1 -o hello hello.c && ./hello
make -v | head -1
