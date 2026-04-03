#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

char* str = NULL;

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void verify_win() {
    // if this string is printed, process continuation works
    puts("You win!");
    exit(0);
}

int vuln() {
    char buf[0x20];
    read(0, buf, 0x60);

    // place str in first argument register
    return strlen(str);
}

int main(int argc, char* argv[]) {
    // technique assumes they know ELF base address
    printf("%p\n", vuln);

    // print out the address of puts JUST FOR VERIFICATION
    void *addr = dlsym(RTLD_NEXT, "puts");
    printf("%p\n", addr);

    // get address for str
    puts("str addr:");
    scanf("%p", &str);

    return vuln();
}