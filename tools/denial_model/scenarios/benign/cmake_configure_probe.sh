# Benign: probes build tools and compiles a small C program in the workspace.
( clang --version ) >/dev/null 2>&1
( make --version ) >/dev/null 2>&1
( xcrun --show-sdk-path ) >/dev/null 2>&1
cat > hello.c <<'SRC'
#include <stdio.h>
int main(void) {
    puts("ok");
    return 0;
}
SRC
( cc -O1 -o hello hello.c && ./hello ) >/dev/null 2>&1
