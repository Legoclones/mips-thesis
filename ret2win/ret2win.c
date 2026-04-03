#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win() {
    system("/bin/sh");
}

void vuln() {
    char buf[0x20];
    read(0, buf, 0x60);
}

int main(int argc, char* argv[]) {
    printf("%p\n", win);
    vuln();
    return 0;
}