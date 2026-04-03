#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char binsh[] = "/bin/sh";
int retval = 0;

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void helper() {
    __asm__ volatile (
        "syscall"
    );
}

// sets execve syscall arguments correctly
int set_args(char * exe, int argv, int envp) {
    return retval;
}

void vuln() {
    char buf[0x20];
    read(0, buf, 0x60);
    scanf("%d", &retval);
    set_args(binsh, 0, 0);
}

int main(int argc, char* argv[]) {
    printf("%p\n", helper);
    vuln();
    return 0;
}