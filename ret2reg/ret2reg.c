#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char * pointer;

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void * vuln() {
    char buf[0x20];
    read(0, buf, 0x60);

    // every MIPS binary has a ret2v0 gadget, so as long as we return the pointer
    // to shellcode, we can use that gadget
    return memcpy(pointer, pointer, 0x0);
}

int main(int argc, char* argv[]) {
    char shellcode[0x100];
    read(0, shellcode, 0x100);
    
    // ELF leak needed for location of ret2reg gadget
    printf("%p\n", &vuln);

    pointer = shellcode;
    vuln();
    return 0;
}