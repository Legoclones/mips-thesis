#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int vuln() {
    char buf[0x20];
    read(0, buf, 0x60);
    return strcmp("/bin/sh", buf);              // put our buf into first argument for system
}

int main(int argc, char* argv[]) {
    system("id");

    // print address of system and vuln
    #ifdef STATIC
    printf("%p\n", &system);                    // if statically-linked, just print the address
    #else
    void *addr = dlsym(RTLD_NEXT, "system");    // otherwise, resolve the symbol and print that
    printf("%p\n", addr);
    #endif
    printf("%p\n", &vuln);

    vuln();
    return 0;
}