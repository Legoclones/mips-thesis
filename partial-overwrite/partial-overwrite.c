#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void vuln() {
    char buf[0x20];
    read(0, buf, 0x60);
}

void win() {
    system("echo '[+] win() function called'");
    system("/bin/sh");
}

int main(int argc, char* argv[]) {
    char str[0x40];
    read(0, str, 0x40-1);

    vuln();
    return strcmp(str, "asdf");
}