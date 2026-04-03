#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char bin_sh[] = "/bin/sh";

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void syscall_inst() {
    __asm__ volatile (
        "syscall"
    );
}

int vuln() {
    char buf[0x20];
    read(0, buf, 0x400);

    // atoi allows us to put arbitrary values in the first argument register
    return atoi(buf);
}

int main(int argc, char* argv[]) {
    // ensure enough space for an entire sigreturn frame
    char stack_space[0x300]; 
    
    printf("%p\n", &syscall_inst);

    // to not optimize out functions
    return vuln()+strlen(stack_space);
}