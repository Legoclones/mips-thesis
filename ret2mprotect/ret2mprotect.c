#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>

#define MMAP_ADDR 0x1337000

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void set_args(void *addr, size_t len, int prot) {
    // prevent optimizing out the function
    volatile int i = 0;
    return;
}

void vuln() {
    char buf[0x20];
    read(0, buf, 0x60);

    set_args((void *)MMAP_ADDR, 0x1000, 0x7);           // this should set the proper registers for mprotect
}

int main(int argc, char* argv[]) {
    // print address of mprotect
    #ifdef STATIC
    printf("%p\n", &mprotect);                  // if statically-linked, just print the address
    #else
    void *addr = dlsym(RTLD_NEXT, "mprotect");  // otherwise, resolve the symbol and print that
    printf("%p\n", addr);
    #endif

    // create new RW-only section
    void* rw_section = mmap((void*)MMAP_ADDR, 0x1000, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (rw_section == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // write 0x80 bytes of shellcode to the new section
    int out = read(0, rw_section, 0x80);
    if (out < 0) {
        perror("read");
        exit(1);
    }
    
    // sleep for 1 second to allow cache flush
    sleep(1);

    vuln();
    return 0;
}