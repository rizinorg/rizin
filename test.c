#include <stdio.h>

void foo() { printf("foo\n"); }
void bar() { printf("bar\n"); }

int main() {
    foo();
    bar();
    if (1) {
        foo();
    }
    return 0;
}