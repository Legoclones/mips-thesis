#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char* bin_sh = "/bin/sh";
char global_buf[0x40];

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win() {
    // if attacker controls the stack, they can populate all needed registers here and exec "/bin/sh"
    #if defined(MIPS32)
    __asm__ volatile (
        "lw $a0,0($sp)\n"
        "lw $a1,4($sp)\n"
        "lw $a2,8($sp)\n"
        "lw $v0,12($sp)\n"
        "addiu $sp, $sp, 16\n"
        "syscall"
    );
    #elif defined(MIPS64)
    __asm__ volatile (
        "ld $a0,0($sp)\n"
        "ld $a1,8($sp)\n"
        "ld $a2,16($sp)\n"
        "ld $v0,24($sp)\n"
        "addiu $sp, $sp, 32\n"
        "syscall"
    );
    #elif defined(x86)
    __asm__ volatile (
        "pop %rdi\n"
        "pop %rsi\n"
        "pop %rdx\n"
        "pop %rax\n"
        "syscall"
    );
    #else
    #error "Unsupported architecture"
    #endif
}

void vuln() {
    char buf[0x20];
    read(0, buf, 0x60);
}

int main(int argc, char* argv[]) {
    // leak
    printf("%p\n", win);

    // fill psuedo-stack "global_buf"
    read(0, global_buf, 0x40);

    // stack overflow
    vuln();
    return 0;
}