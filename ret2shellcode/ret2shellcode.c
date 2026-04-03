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

int main(int argc, char* argv[]) {
    char shellcode[0x100];
    read(0, shellcode, 0x100);
    
    printf("%p\n", &shellcode);
    vuln();
    return 0;
}